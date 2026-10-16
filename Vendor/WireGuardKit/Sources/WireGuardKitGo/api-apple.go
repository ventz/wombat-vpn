/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Modified for Wombat: buffered signal channel, bounds-safe stack dump, a lock
 * around the handle table, and the device (not just the fd) is closed when
 * configuration fails or the device can't come up. A second engine,
 * amneziawg-go, serves AmneziaWG tunnels (awgTurnOn); every other call works on
 * a handle from either engine.
 */

package main

// #include <stdlib.h>
// #include <sys/types.h>
// static void callLogger(void *func, void *ctx, int64_t token, int level, const char *msg)
// {
// 	((void(*)(void *, int64_t, int, const char *))func)(ctx, token, level, msg);
// }
import "C"

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	awgdevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	awgtun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Wombat: the logger is read by every goroutine and set from Swift, so both halves are
// loaded and stored atomically, as one pair (audits WOM-03, S2-L4). Swift sets it once.
type loggerPair struct {
	fn, ctx unsafe.Pointer
}

var logger atomic.Pointer[loggerPair]

// CLogger sends one tunnel's lines to Swift. Wombat: each carries the token Swift gave that
// tunnel's adapter, so a line reaches only that tunnel's log view. Several tunnels (possibly of
// different macOS users) share this process; one global destination mixed their lines.
// Token 0 is the process itself (the SIGUSR2 stack dump).
type CLogger struct {
	level C.int
	token C.int64_t
}

func cstring(s string) *C.char {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		b := [1]C.char{}
		return &b[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func (l CLogger) Printf(format string, args ...interface{}) {
	pair := logger.Load()
	if pair == nil || pair.fn == nil {
		return
	}
	C.callLogger(pair.fn, pair.ctx, l.token, l.level, cstring(fmt.Sprintf(format, args...)))
}

// engine is what both device types (wireguard-go and amneziawg-go) offer, so one handle
// table and one set of exported calls serve both.
type engine interface {
	Up() error
	Close()
	IpcSet(string) error
	IpcGet() (string, error)
	BindUpdate() error
	SendKeepalivesToPeersWithCurrentKeypair()
	DisableSomeRoamingForBrokenMobileSemantics()
}

type tunnelHandle struct {
	engine
	errorf func(format string, args ...any)
}

func (h tunnelHandle) Errorf(format string, args ...any) { h.errorf(format, args...) }

var (
	tunnelHandlesMu sync.Mutex
	tunnelHandles   = make(map[int32]tunnelHandle)
)

func lookup(h int32) (tunnelHandle, bool) {
	tunnelHandlesMu.Lock()
	defer tunnelHandlesMu.Unlock()
	dev, ok := tunnelHandles[h]
	return dev, ok
}

func init() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize()+1)
		for range signals {
			n := runtime.Stack(buf[:len(buf)-1], true)
			buf[n] = 0
			if pair := logger.Load(); pair != nil && pair.fn != nil {
				C.callLogger(pair.fn, pair.ctx, 0, 0, (*C.char)(unsafe.Pointer(&buf[0])))
			}
		}
	}()
}

//export wgSetLogger
func wgSetLogger(context, loggerFn unsafe.Pointer) {
	logger.Store(&loggerPair{fn: loggerFn, ctx: context})
}

// withoutEmptyPackets drops packets with no bytes after offset. wireguard-go (used unmodified)
// can hand one to the TUN when an authenticated IPv6 packet's payload length makes its uint16
// sum wrap to 0, and the macOS TUN write reads the version byte past the end and panics the
// whole extension (audit 4b-H1). Both engines get this guard; amneziawg-go is also fixed at the
// root (its WOMBAT.md, patch 8).
//
// It also drops packets shorter than their IP header (20 bytes for IPv4, 40 for IPv6), which
// the same wrap produces for lengths just above 65496; the kernel would drop them anyway.
func withoutEmptyPackets(bufs [][]byte, offset int) [][]byte {
	valid := func(b []byte) bool {
		if len(b) <= offset {
			return false
		}
		n := len(b) - offset
		return n >= 20 && (b[offset]>>4 != 6 || n >= 40)
	}
	for i, b := range bufs {
		if valid(b) {
			continue
		}
		kept := append([][]byte{}, bufs[:i]...)
		for _, b := range bufs[i+1:] {
			if valid(b) {
				kept = append(kept, b)
			}
		}
		return kept
	}
	return bufs
}

// guardedWrite passes a batch through unchanged when every packet is valid, keeping the
// engine's own count and error. Otherwise it writes the valid ones; the dropped packets count
// as handled. (Neither engine reads the count today, and macOS batches are one packet.)
func guardedWrite(write func([][]byte, int) (int, error), bufs [][]byte, offset int) (int, error) {
	kept := withoutEmptyPackets(bufs, offset)
	if len(kept) == len(bufs) {
		return write(bufs, offset)
	}
	if len(kept) == 0 {
		return len(bufs), nil
	}
	n, err := write(kept, offset)
	if err != nil {
		return n, err
	}
	return len(bufs), nil
}

type guardedTUN struct{ tun.Device }

func (t guardedTUN) Write(bufs [][]byte, offset int) (int, error) {
	return guardedWrite(t.Device.Write, bufs, offset)
}

type guardedAWGTUN struct{ awgtun.Device }

func (t guardedAWGTUN) Write(bufs [][]byte, offset int) (int, error) {
	return guardedWrite(t.Device.Write, bufs, offset)
}

// dupTunFile duplicates the tunnel fd for an engine, which takes ownership of the copy.
func dupTunFile(tunFd int32, errorf func(string, ...any)) *os.File {
	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		errorf("Unable to dup tun fd: %v", err)
		return nil
	}
	if err := unix.SetNonblock(dupTunFd, true); err != nil {
		errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return nil
	}
	return os.NewFile(uintptr(dupTunFd), "/dev/tun")
}

// startEngine configures and brings up a new device, then stores it in the handle table.
// On any failure the device is closed, which also closes its tun file.
func startEngine(dev engine, settings *C.char, errorf, verbosef func(string, ...any)) int32 {
	if err := dev.IpcSet(C.GoString(settings)); err != nil {
		errorf("Unable to set IPC settings: %v", err)
		dev.Close()
		return -1
	}
	if err := dev.Up(); err != nil {
		errorf("Unable to bring up device: %v", err)
		dev.Close()
		return -1
	}
	verbosef("Device started")

	tunnelHandlesMu.Lock()
	defer tunnelHandlesMu.Unlock()
	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		dev.Close()
		return -1
	}
	tunnelHandles[i] = tunnelHandle{dev, errorf}
	return i
}

//export wgTurnOn
func wgTurnOn(settings *C.char, tunFd int32, logToken int64) int32 {
	logger := &device.Logger{
		Verbosef: CLogger{0, C.int64_t(logToken)}.Printf,
		Errorf:   CLogger{1, C.int64_t(logToken)}.Printf,
	}
	file := dupTunFile(tunFd, logger.Errorf)
	if file == nil {
		return -1
	}
	tun, err := tun.CreateTUNFromFile(file, 0)
	if err != nil {
		logger.Errorf("Unable to create new tun device from fd: %v", err)
		file.Close()
		return -1
	}
	logger.Verbosef("Attaching to interface")
	return startEngine(device.NewDevice(guardedTUN{tun}, conn.NewStdNetBind(), logger), settings, logger.Errorf, logger.Verbosef)
}

// awgTurnOn starts an AmneziaWG tunnel on the amneziawg-go engine. The settings are the
// same UAPI text plus AmneziaWG's device keys (jc, s1, h1, i1, ...).
//
//export awgTurnOn
func awgTurnOn(settings *C.char, tunFd int32, logToken int64) int32 {
	logger := &awgdevice.Logger{
		Verbosef: CLogger{0, C.int64_t(logToken)}.Printf,
		Errorf:   CLogger{1, C.int64_t(logToken)}.Printf,
	}
	file := dupTunFile(tunFd, logger.Errorf)
	if file == nil {
		return -1
	}
	tun, err := awgtun.CreateTUNFromFile(file, 0)
	if err != nil {
		logger.Errorf("Unable to create new tun device from fd: %v", err)
		file.Close()
		return -1
	}
	logger.Verbosef("Attaching to interface (AmneziaWG)")
	return startEngine(awgdevice.NewDevice(guardedAWGTUN{tun}, awgconn.NewStdNetBind(), logger), settings, logger.Errorf, logger.Verbosef)
}

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	tunnelHandlesMu.Lock()
	dev, ok := tunnelHandles[tunnelHandle]
	delete(tunnelHandles, tunnelHandle)
	tunnelHandlesMu.Unlock()
	if ok {
		dev.Close()
	}
}

//export wgSetConfig
func wgSetConfig(tunnelHandle int32, settings *C.char) int64 {
	dev, ok := lookup(tunnelHandle)
	if !ok {
		return 0
	}
	err := dev.IpcSet(C.GoString(settings))
	if err != nil {
		dev.Errorf("Unable to set IPC settings: %v", err)
		// Both engines' IPCError types have ErrorCode.
		var ipcErr interface{ ErrorCode() int64 }
		if errors.As(err, &ipcErr) {
			return ipcErr.ErrorCode()
		}
		return -1
	}
	return 0
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	dev, ok := lookup(tunnelHandle)
	if !ok {
		return nil
	}
	settings, err := dev.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export wgBumpSockets
func wgBumpSockets(tunnelHandle int32) {
	dev, ok := lookup(tunnelHandle)
	if !ok {
		return
	}
	go func() {
		for i := 0; i < 10; i++ {
			err := dev.BindUpdate()
			if err == nil {
				dev.SendKeepalivesToPeersWithCurrentKeypair()
				return
			}
			dev.Errorf("Unable to update bind, try %d: %v", i+1, err)
			time.Sleep(time.Second / 2)
		}
		dev.Errorf("Gave up trying to update bind; tunnel is likely dysfunctional")
	}()
}

//export wgDisableSomeRoamingForBrokenMobileSemantics
func wgDisableSomeRoamingForBrokenMobileSemantics(tunnelHandle int32) {
	dev, ok := lookup(tunnelHandle)
	if !ok {
		return
	}
	dev.DisableSomeRoamingForBrokenMobileSemantics()
}

// depVersion is a module's version from the build info, shortened to the commit for
// pseudo-versions.
func depVersion(path string) *C.char {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return C.CString("unknown")
	}
	for _, dep := range info.Deps {
		if dep.Path == path {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return C.CString(parts[2][:7])
			}
			return C.CString(dep.Version)
		}
	}
	return C.CString("unknown")
}

//export wgVersion
func wgVersion() *C.char {
	return depVersion("golang.zx2c4.com/wireguard")
}

//export awgVersion
func awgVersion() *C.char {
	return depVersion("github.com/amnezia-vpn/amneziawg-go/v3")
}

func main() {}
