// The C ABI of Wombat's tailnet engine (tailnet.h). All logic lives in package node; this file
// only marshals strings and handles.
package main

// #include <stdlib.h>
// #include <stdint.h>
// #include <stdbool.h>
// static void callLine(void *fn, void *ctx, int64_t token, const char *s)
// {
// 	((void (*)(void *, int64_t, const char *))fn)(ctx, token, s);
// }
import "C"

import (
	"errors"
	"log"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"tailscale.com/hostinfo"
	"tailscale.com/version"
	"wombat.local/tailscale-bridge/node"
)

type callbacks struct {
	ctx, log, plan unsafe.Pointer
}

var cb atomic.Pointer[callbacks]

func send(fn func(*callbacks) unsafe.Pointer, token int64, s string) {
	c := cb.Load()
	if c == nil || fn(c) == nil {
		return
	}
	cs := C.CString(s)
	defer C.free(unsafe.Pointer(cs))
	C.callLine(fn(c), c.ctx, C.int64_t(token), cs)
}

func logLine(token int64, s string) {
	send(func(c *callbacks) unsafe.Pointer { return c.log }, token, s)
}

var (
	handlesMu sync.Mutex
	handles   = map[int32]*node.Node{}
	nextID    int32
)

func lookup(h C.int32_t) *node.Node {
	handlesMu.Lock()
	defer handlesMu.Unlock()
	return handles[int32(h)]
}

func setError(out **C.char, err error) {
	if out != nil {
		*out = C.CString(err.Error())
	}
}

func init() {
	// A Go panic prints goroutine stacks with argument words, which may hold key bytes; print
	// none (security-9-fable note 3).
	debug.SetTraceback("none")
	hostinfo.SetPackage("wombat")
	// Libraries that use the standard logger go through the same redaction, as the process.
	log.SetFlags(0)
	log.SetOutput(node.NewLineWriter(func(s string) { logLine(0, s) }))
}

//export tsSetCallbacks
func tsSetCallbacks(ctx unsafe.Pointer, logFn, planFn unsafe.Pointer) {
	cb.Store(&callbacks{ctx: ctx, log: logFn, plan: planFn})
}

//export tsStart
func tsStart(stateDir, controlURL, hostname *C.char, acceptDNS C.bool, tunFD C.int32_t, token C.int64_t, errOut **C.char) C.int32_t {
	fd := int(tunFD)
	if fd < 0 {
		setError(errOut, errors.New("no tunnel interface"))
		return -1
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		setError(errOut, err)
		return -1
	}
	tok := int64(token)
	n, err := node.Start(node.Config{
		StateDir:   C.GoString(stateDir),
		ControlURL: C.GoString(controlURL),
		Hostname:   C.GoString(hostname),
		AcceptDNS:  bool(acceptDNS),
		TunFile:    os.NewFile(uintptr(fd), "/dev/tun"),
		Log:        func(s string) { logLine(tok, s) },
		OnPlan: func(p []byte) {
			send(func(c *callbacks) unsafe.Pointer { return c.plan }, tok, string(p))
		},
	})
	if err != nil {
		// node.Start closed the file (it owns it from here on): never close fd again.
		setError(errOut, err)
		return -1
	}
	handlesMu.Lock()
	defer handlesMu.Unlock()
	for {
		nextID++
		if nextID <= 0 {
			nextID = 1
		}
		if _, used := handles[nextID]; !used {
			break
		}
	}
	handles[nextID] = n
	return C.int32_t(nextID)
}

//export tsStop
func tsStop(h C.int32_t) {
	handlesMu.Lock()
	n := handles[int32(h)]
	delete(handles, int32(h))
	handlesMu.Unlock()
	if n != nil {
		n.Stop()
	}
}

//export tsStatus
func tsStatus(h C.int32_t) *C.char {
	n := lookup(h)
	if n == nil {
		return nil
	}
	return C.CString(string(n.Status()))
}

//export tsLogin
func tsLogin(h C.int32_t, errOut **C.char) C.int32_t {
	n := lookup(h)
	if n == nil {
		setError(errOut, errors.New("the tailnet isn't running"))
		return -1
	}
	if err := n.Login(); err != nil {
		setError(errOut, err)
		return -1
	}
	return 0
}

//export tsLogout
func tsLogout(h C.int32_t, timeoutMS C.int32_t, errOut **C.char) C.int32_t {
	n := lookup(h)
	if n == nil {
		setError(errOut, errors.New("the tailnet isn't running"))
		return -1
	}
	if err := n.Logout(time.Duration(timeoutMS) * time.Millisecond); err != nil {
		setError(errOut, err)
		return -1
	}
	return 0
}

//export tsRebind
func tsRebind(h C.int32_t) {
	if n := lookup(h); n != nil {
		n.Rebind()
	}
}

//export tsVersion
func tsVersion() *C.char { return C.CString(version.Long()) }

func main() {}
