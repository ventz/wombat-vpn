package node

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/types/key"
	"tailscale.com/types/persist"
)

// The filter keys on text prefixes and 64-hex/base64 runs; the check below looks for the raw
// key bytes in other encodings (design 2.8: verify by a different route than the fix).
func TestRedactKeys(t *testing.T) {
	node := key.NewNode()
	machine := key.NewMachine()
	nodeRaw := node.Raw32()
	secrets := [][]byte{nodeRaw[:], machine.UntypedBytes()}

	var sink []string
	w := NewLineWriter(func(s string) { sink = append(sink, s) })
	logger := log.New(w, "", 0)

	nodeText, _ := node.MarshalText()
	machineText, _ := machine.MarshalText()
	prefs := ipn.NewPrefs()
	prefs.Persist = &persist.Persist{PrivateNodeKey: node}
	prefsJSON, _ := json.Marshal(prefs)

	logger.Printf("node key %s", nodeText)
	logger.Printf("machine key %s", machineText)
	logger.Printf("untyped %s", node.UntypedHexString())
	logger.Printf("upper %s", strings.ToUpper(hex.EncodeToString(nodeRaw[:])))
	logger.Printf("b64 %s.", base64.StdEncoding.EncodeToString(nodeRaw[:]))
	logger.Printf("b64raw %s", base64.RawURLEncoding.EncodeToString(nodeRaw[:]))
	logger.Printf("prefs %s", prefsJSON)
	logger.Printf("%v", fmt.Sprint(prefs))
	logger.Printf("Received auth URL: https://login.tailscale.com/a/123abc")
	logger.Printf("ok line peer [AbCdE] 100.64.0.1")
	w.Write([]byte("split " + string(nodeText[:20])))
	w.Write([]byte(string(nodeText[20:]) + "\n"))

	all := strings.Join(sink, "\n")
	for _, s := range secrets {
		for _, enc := range []string{
			hex.EncodeToString(s), strings.ToUpper(hex.EncodeToString(s)),
			base64.StdEncoding.EncodeToString(s), base64.RawStdEncoding.EncodeToString(s),
			base64.URLEncoding.EncodeToString(s), base64.RawURLEncoding.EncodeToString(s),
		} {
			if strings.Contains(all, enc) {
				t.Fatalf("a key reached the sink as %q:\n%s", enc, all)
			}
		}
	}
	if strings.Contains(all, "/a/123abc") {
		t.Fatalf("an auth URL reached the sink:\n%s", all)
	}
	if !strings.Contains(all, "ok line peer [AbCdE] 100.64.0.1") {
		t.Fatalf("an ordinary line was lost:\n%s", all)
	}
}

func TestLineWriterBounds(t *testing.T) {
	var sink []string
	w := NewLineWriter(func(s string) { sink = append(sink, s) })
	w.Write([]byte(strings.Repeat("x", 5000)))
	w.Write([]byte(strings.Repeat("y", 2000) + "\n"))
	for _, s := range sink {
		if len(s) > 1024 {
			t.Fatalf("line of %d bytes", len(s))
		}
	}
}

func TestLineWriterStripsControlCharacters(t *testing.T) {
	var sink []string
	w := NewLineWriter(func(s string) { sink = append(sink, s) })
	w.Write([]byte("[v\x00JSON]1{\"a\":1}\x1b[31m\n"))
	if len(sink) != 1 || strings.ContainsAny(sink[0], "\x00\x1b") {
		t.Fatalf("got %q", sink)
	}
}

// security-9 L3: a sign-in link is a bearer URL whatever its path, and upstream logs some
// without any marker word. Only scheme and host remain.
func TestRedactURLPaths(t *testing.T) {
	cases := map[string]string{
		"netmap: control says to open URL https://hs.example.com/auth/abc123def":  "netmap: control says to open URL https://hs.example.com/[path]",
		"[v1] TryLogout control response: newURL=https://hs.example.com:8443/x/y": "[v1] TryLogout control response: newURL=https://hs.example.com:8443/[path]",
		"control: https://hs.example.com connected":                               "control: https://hs.example.com connected",
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}
