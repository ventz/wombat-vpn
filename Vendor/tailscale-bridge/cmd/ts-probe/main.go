//go:build wombat_devprobe

// ts-probe runs the tailnet node on netstack alone (no utun, no Network Extension) against a
// throwaway Headscale (scripts/dev/headscale-peer.sh), to test sign-in, saved keys, the network
// plan, a TSMP ping and sign-out without a signed system extension. Dev only: built with the
// wombat_devprobe tag, which also allows plain http on loopback (node/devprobe.go).
//
//	go run -tags wombat_devprobe ./cmd/ts-probe -control http://127.0.0.1:18080 -peer 100.64.0.1
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"wombat.local/tailscale-bridge/node"
)

func main() {
	control := flag.String("control", "http://127.0.0.1:18080", "coordination server")
	peer := flag.String("peer", "100.64.0.1", "tailnet address to ping")
	approve := flag.String("approve", "", "command that registers the sign-in key (gets the key as its last argument)")
	flag.Parse()

	base, err := os.MkdirTemp("", "ts-probe-")
	check(err)
	defer os.RemoveAll(base)
	// node.Start wants the per-server directory the extension makes: <base>/<ControlKey>, 0700.
	canonical, err := node.CanonicalControlURL(*control)
	check(err)
	dir := filepath.Join(base, node.ControlKey(canonical))
	check(os.Mkdir(dir, 0o700))

	var lastPlan string
	cfg := node.Config{
		StateDir: dir, ControlURL: *control, Hostname: "wombat-probe", AcceptDNS: true,
		Log:    func(s string) { fmt.Fprintln(os.Stderr, "  log:", s) },
		OnPlan: func(p []byte) { lastPlan = string(p) },
	}

	step("start (new node)")
	n, err := node.Start(cfg)
	check(err)
	st := waitState(n, "NeedsLogin", 30*time.Second)
	check(n.Login())
	st = waitFor(n, 30*time.Second, func(s node.Status) bool { return s.AuthURL != "" })
	fmt.Println("  sign-in URL host ok:", st.AuthURL[:strings.Index(st.AuthURL, "/register/")+10]+"…")
	if *approve != "" {
		key := st.AuthURL[strings.LastIndex(st.AuthURL, "/")+1:]
		parts := strings.Fields(*approve)
		out, err := exec.Command(parts[0], append(parts[1:], key)...).CombinedOutput()
		if err != nil {
			fail("approve: %v: %s", err, out)
		}
	} else {
		fmt.Println("  approve it, e.g. scripts/dev/headscale-peer.sh approve <key>")
	}
	st = waitState(n, "Running", 120*time.Second)
	fmt.Printf("  running as %s %v, tailnet %q, MagicDNS %q, %d peers\n", st.Self.Name, st.Self.Addresses, st.Tailnet, st.MagicDNSSuffix, len(st.Peers))
	time.Sleep(2 * time.Second)
	fmt.Println("  plan:", lastPlan)
	var plan node.Plan
	check(json.Unmarshal([]byte(lastPlan), &plan))

	step("TSMP ping " + *peer)
	ping(n, *peer)

	step("restart from saved keys")
	n.Stop()
	fi, err := os.Stat(filepath.Join(dir, "state.json"))
	check(err)
	fmt.Printf("  state.json mode %v\n", fi.Mode().Perm())
	if fi.Mode().Perm() != 0o600 {
		fail("state.json is %v, want 0600", fi.Mode().Perm())
	}
	n, err = node.Start(cfg)
	check(err)
	waitState(n, "Running", 60*time.Second)
	fmt.Println("  running again without a sign-in")
	ping(n, *peer)

	step("logout")
	check(n.Logout(10 * time.Second))
	st = waitFor(n, 30*time.Second, func(s node.Status) bool { return s.State != "Running" })
	fmt.Println("  state after logout:", st.State)
	n.Stop()
	fmt.Println("\nts-probe: all steps passed")
}

func ping(n *node.Node, peer string) {
	ip := netip.MustParseAddr(peer)
	var err error
	for i := 0; i < 10; i++ {
		r, e := n.Ping(ip, 10*time.Second)
		if e == nil && r.Err == "" {
			fmt.Printf("  pong from %s via %s in %.1f ms\n", r.NodeName, cmpStr(r.Endpoint, "DERP "+fmt.Sprint(r.DERPRegionCode)), r.LatencySeconds*1000)
			return
		}
		err = e
		if e == nil {
			err = fmt.Errorf("%s", r.Err)
		}
		time.Sleep(time.Second)
	}
	fail("ping %s: %v", peer, err)
}

func cmpStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func status(n *node.Node) node.Status {
	var s node.Status
	check(json.Unmarshal(n.Status(), &s))
	return s
}

func waitState(n *node.Node, state string, d time.Duration) node.Status {
	return waitFor(n, d, func(s node.Status) bool { return s.State == state })
}

func waitFor(n *node.Node, d time.Duration, ok func(node.Status) bool) node.Status {
	deadline := time.Now().Add(d)
	for {
		s := status(n)
		if ok(s) {
			fmt.Println("  state:", s.State)
			return s
		}
		if time.Now().After(deadline) {
			fail("timed out in state %s (health %v)", s.State, s.Health)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func step(s string) { fmt.Println("==>", s) }

func check(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ts-probe: "+format+"\n", args...)
	os.Exit(1)
}
