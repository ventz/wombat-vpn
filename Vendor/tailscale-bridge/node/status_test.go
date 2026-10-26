package node

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A hostile server's peer names can't push the status past what Swift accepts (256 KB), and
// the state and sign-in URL always arrive (security-9 L2, astra S9-2).
func TestStatusStaysUnderBudget(t *testing.T) {
	out := Status{State: "NeedsLogin", AuthURL: "https://hs.example.com/register/x", Control: "https://hs.example.com",
		Health: []string{}, Peers: []Peer{}}
	now := time.Now()
	for i := 0; i < maxPeers; i++ {
		out.Peers = append(out.Peers, Peer{
			Name: clip(strings.Repeat("<&>", 100), maxText), DNSName: clip(strings.Repeat("<", 300), 253),
			OS: clip(strings.Repeat("&", 200), maxText), Relay: clip(strings.Repeat(">", 200), maxText),
			Addresses: []string{"100.64.0.1", "fd7a:115c:a1e0::1"}, LastSeen: &now,
		})
	}
	data := encodeStatus(out)
	if len(data) > maxJSONSize {
		t.Fatalf("status is %d bytes", len(data))
	}
	var back Status
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.State != "NeedsLogin" || back.AuthURL == "" || !back.PeersTruncated || len(back.Peers) == 0 {
		t.Fatalf("state %q, auth %q, truncated %v, %d peers", back.State, back.AuthURL, back.PeersTruncated, len(back.Peers))
	}
}

// Bidi overrides, zero-width and C1 characters can't make one name render as another.
func TestClipDropsFormatCharacters(t *testing.T) {
	if got := clip("nas‮gpj.exe​\u0085x", maxText); got != "nasgpj.exex" {
		t.Fatalf("clip kept format characters: %q", got)
	}
}

// Design 2.2: nothing key-like ever reaches the app through the status, whatever a future
// field adds. The struct is built by hand from public fields; this keeps it that way.
func TestStatusCarriesNoKeys(t *testing.T) {
	now := time.Now()
	out := Status{State: "Running", Control: "https://hs.example.com", Health: []string{"ok"},
		Self:  &Peer{Name: "mac", Addresses: []string{"100.64.0.2"}, LastSeen: &now},
		Peers: []Peer{{Name: "peer", DNSName: "peer.example", OS: "linux", Addresses: []string{"100.64.0.1"}}}}
	data := string(encodeStatus(out))
	if regexp.MustCompile(`privkey:|nlpriv:|nodekey:|[0-9a-f]{64}|(?i)persist`).MatchString(data) {
		t.Fatalf("status carries key-like text: %s", data)
	}
}
