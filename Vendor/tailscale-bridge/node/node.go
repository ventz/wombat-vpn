package node

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsdial"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/opt"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
)

// Config describes one node. Every field comes from the profile Swift checked; the rules are
// applied again here because this is the code that dials.
type Config struct {
	// StateDir holds state.json (node and machine keys). It must exist and be private to its
	// owner (no group or other bits); Swift creates it under the extension's root-only container.
	StateDir   string
	ControlURL string // empty = Tailscale's coordination server
	Hostname   string // empty = the OS host name
	AcceptDNS  bool   // MagicDNS
	// TunFile is the claimed utun. Nil runs the node on netstack alone (the command-line probe).
	// Start owns it: on failure it is closed exactly once, here, never by the caller
	// (security-7 M2: a second close could hit a reused descriptor number).
	TunFile *os.File
	Log     func(line string) // receives redacted lines only
	OnPlan  func(planJSON []byte)
}

// Node is one running Tailscale node.
type Node struct {
	control string
	lb      *ipnlocal.LocalBackend
	ns      *netstack.Impl
	netMon  *netmon.Monitor
	dialer  *tsdial.Dialer
	sys     *tsd.System
	logf    logger.Logf
	stop    sync.Once

	authMu      sync.Mutex
	refusedAuth string // the last sign-in URL ValidLoginURL refused (logged once)
}

// One node per process: Tailscale keeps process-wide state (netns, the interface props, the
// default logger), and macOS runs one VPN at a time anyway.
var (
	runningMu sync.Mutex
	running   *Node
)

// ErrBusy means another node is running in this process.
var ErrBusy = errors.New("another tailnet is already running")

// Start brings a node up. It signs in only with saved keys; a new node waits in NeedsLogin
// until the owner asks for a sign-in page (Login).
func Start(cfg Config) (n *Node, err error) {
	// Until the TUN device owns the file, a failure closes it here.
	tunOwned := false
	defer func() {
		if err != nil && cfg.TunFile != nil && !tunOwned {
			cfg.TunFile.Close()
		}
	}()
	runningMu.Lock()
	defer runningMu.Unlock()
	if running != nil {
		return nil, ErrBusy
	}
	control, err := CanonicalControlURL(cfg.ControlURL)
	if err != nil {
		return nil, err
	}
	if err := checkStateDir(cfg.StateDir); err != nil {
		return nil, err
	}
	// Each server has its own directory, named by ControlKey: one server's keys can't be
	// started against another, even if the Swift side passed the wrong directory.
	if filepath.Base(cfg.StateDir) != ControlKey(control) {
		return nil, errors.New("the state directory doesn't belong to this coordination server")
	}
	w := NewLineWriter(func(s string) {
		if cfg.Log != nil {
			cfg.Log(s)
		}
	})
	logf := logger.Logf(func(format string, args ...any) {
		fmt.Fprintf(w, format+"\n", args...)
	})
	if devBuild != "" {
		logf("%s", devBuild)
	}

	// Everything made below is released on failure, newest first, in tsnet's order (netstack,
	// backend or engine or TUN, dialer, network monitor, event bus); each owner replaces the
	// cleanup of what it took over. The extension lives across tunnels, so a leak here grows
	// with every failed start (quality-9 M2).
	var cleanups []func()
	push := func(f func()) int { cleanups = append(cleanups, f); return len(cleanups) - 1 }
	defer func() {
		if err != nil {
			for i := len(cleanups) - 1; i >= 0; i-- {
				cleanups[i]()
			}
		}
	}()

	sys := tsd.NewSystem()
	push(func() { sys.Bus.Get().Close() })
	st, err := store.NewFileStore(logf, filepath.Join(cfg.StateDir, "state.json"))
	if err != nil {
		return nil, fmt.Errorf("state store: %w", err)
	}
	sys.Set(st)
	netMon, err := netmon.New(sys.Bus.Get(), logf)
	if err != nil {
		return nil, fmt.Errorf("network monitor: %w", err)
	}
	push(func() { netMon.Close() })
	sys.Set(netMon)
	dialer := &tsdial.Dialer{Logf: logf}
	dialer.SetBus(sys.Bus.Get())
	push(func() { dialer.Close() })
	sys.Set(dialer)
	// The engine slot: the TUN until the engine owns it, then the engine until the backend does.
	engineSlot := push(func() {})

	onlyNetstack := cfg.TunFile == nil
	var dev tun.Device
	if !onlyNetstack {
		native, err := tun.CreateTUNFromFile(cfg.TunFile, 0)
		tunOwned = true // CreateTUNFromFile closes the file itself when it fails
		if err != nil {
			return nil, fmt.Errorf("tun: %w", err)
		}
		cleanups[engineSlot] = func() { native.Close() }
		name, _ := native.Name()
		// The ts_macext dialers and the MagicDNS forwarder bind to this interface by index.
		netmon.SetTailscaleInterfaceProps(name, 0)
		dev = guardedTUN{native}
	}
	// Outbound control, DERP and STUN sockets are bound to the physical default interface
	// (netns_darwin), which keeps them out of our own utun. The probe has no utun.
	netns.SetEnabled(!onlyNetstack)

	f := newFacade(cfg.OnPlan)
	e, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Tun:            dev,
		Router:         f,
		DNS:            f,
		ReconfigureVPN: f.ReconfigureVPN,
		NetMon:         netMon,
		HealthTracker:  sys.HealthTracker.Get(),
		Metrics:        sys.UserMetricsRegistry(),
		Dialer:         dialer,
		SetSubsystem:   sys.Set,
		ControlKnobs:   sys.ControlKnobs(),
		EventBus:       sys.Bus.Get(),
	})
	if err != nil {
		return nil, fmt.Errorf("engine: %w", err)
	}
	cleanups[engineSlot] = func() { e.Close() }
	sys.Set(e)
	sys.NetstackRouter.Set(onlyNetstack)

	ns, err := netstack.Create(logf, sys.Tun.Get(), e, sys.MagicSock.Get(), dialer, sys.DNSManager.Get(), sys.ProxyMapper())
	if err != nil {
		return nil, fmt.Errorf("netstack: %w", err)
	}
	push(func() { ns.Close() })
	sys.Set(ns)
	// With a utun the kernel owns this node's addresses; netstack only answers quad100
	// (MagicDNS) and TSMP. No subnet routing either way.
	ns.ProcessLocalIPs = onlyNetstack
	ns.ProcessSubnets = false
	if w, ok := sys.Tun.GetOK(); ok {
		w.Start()
	}

	// No logtail (ts_omit_logtail), so no log id: nothing is uploaded to log.tailscale.com.
	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		return nil, fmt.Errorf("backend: %w", err)
	}
	cleanups[engineSlot] = lb.Shutdown // the backend closes the engine and the TUN
	// Tailnet Lock (TKA) state lives under the state directory (tka-profiles/). Without a var
	// root it was memory-only, so a compromised coordination server could disable or replace
	// the lock on every connect (security-9-opus M1). The directory is per tunnel and per
	// server, root-only, 0700.
	lb.SetVarRoot(cfg.StateDir)
	if err := ns.Start(lb); err != nil {
		return nil, fmt.Errorf("netstack start: %w", err)
	}

	if err := lb.Start(ipn.Options{UpdatePrefs: prefsFor(control, cfg)}); err != nil {
		return nil, fmt.Errorf("backend start: %w", err)
	}
	n = &Node{control: control, lb: lb, ns: ns, netMon: netMon, dialer: dialer, sys: sys, logf: logf}
	running = n
	return n, nil
}

// prefsFor fixes every preference the spike allows (design 2.6). Nothing else can change them:
// there is no LocalAPI, and c2n, syspolicy and remoteconfig are compiled out.
func prefsFor(control string, cfg Config) *ipn.Prefs {
	p := ipn.NewPrefs()
	p.ControlURL = control
	p.WantRunning = true
	p.RouteAll = false // no subnet routes from peers
	p.ExitNodeID = ""  // no exit node: 0/0 is never routed
	p.ExitNodeIP = netip.Addr{}
	p.ShieldsUp = true // no inbound connections from peers
	p.NoStatefulFiltering = opt.NewBool(false)
	p.CorpDNS = cfg.AcceptDNS
	p.Hostname = cfg.Hostname
	return p
}

// Login asks the coordination server for a sign-in page; its URL appears in Status.
func (n *Node) Login() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return n.lb.StartLoginInteractive(ctx)
}

// Logout expires the node key at the coordination server, so the saved keys become worthless
// there, and forgets them locally.
func (n *Node) Logout(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return n.lb.Logout(ctx, ipnauth.Self)
}

// Rebind re-probes paths at once after a wake or network change.
func (n *Node) Rebind() { _ = n.lb.DebugRebind() }

// Stop shuts the node down in tsnet's order; the backend closes the engine and the utun. The
// dialer and the event bus go too, or each connect leaves goroutines behind (quality-9 M2).
func (n *Node) Stop() {
	n.stop.Do(func() {
		n.ns.Close() // the gVisor stack isn't closed by the backend (quality-7)
		n.lb.Shutdown()
		n.netMon.Close()
		n.dialer.Close()
		n.sys.Bus.Get().Close()
		runningMu.Lock()
		if running == n {
			running = nil
		}
		runningMu.Unlock()
	})
}

func checkStateDir(dir string) error {
	if dir == "" || !filepath.IsAbs(dir) {
		return errors.New("the state directory must be an absolute path")
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("state directory: %w", err)
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("the state directory isn't a directory")
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return errors.New("the state directory must not be readable by others")
	}
	return nil
}
