package node

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// The status is bounded whatever the coordination server sends (security-7 L7). Swift refuses
// JSON over 256 KB, so the encoded size has its own budget (security-9 L2, quality-9 L10).
const (
	maxPeers    = 256
	maxText     = 128 // names, OS, relay
	maxHealth   = 16
	maxHealthN  = 300
	maxJSONSize = 192 << 10
)

// clip drops control characters (C0, DEL, C1) and format characters (bidi overrides,
// zero-width), so a server or peer can't make one name render as another (security-9 L2).
func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		s = s[:n]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// Status is what the app may know about the node: no keys, no Persist, no netmap.
type Status struct {
	State          string   `json:"state"`
	AuthURL        string   `json:"authURL,omitempty"` // only when ValidLoginURL accepts it
	Control        string   `json:"control"`
	Self           *Peer    `json:"self,omitempty"`
	MagicDNSSuffix string   `json:"magicDNSSuffix,omitempty"`
	Tailnet        string   `json:"tailnet,omitempty"`
	Health         []string `json:"health"`
	Peers          []Peer   `json:"peers"`
	PeersTruncated bool     `json:"peersTruncated,omitempty"`
}

type Peer struct {
	Name      string     `json:"name"`
	DNSName   string     `json:"dnsName,omitempty"`
	OS        string     `json:"os,omitempty"`
	Addresses []string   `json:"addresses"`
	Online    bool       `json:"online"`
	Active    bool       `json:"active"`
	Relay     string     `json:"relay,omitempty"`
	Direct    bool       `json:"direct"`
	RxBytes   int64      `json:"rxBytes"`
	TxBytes   int64      `json:"txBytes"`
	LastSeen  *time.Time `json:"lastSeen,omitempty"`
}

// Status returns the node's state as JSON.
func (n *Node) Status() []byte {
	st := n.lb.Status()
	out := Status{State: st.BackendState, Control: n.control, MagicDNSSuffix: clip(strings.TrimSuffix(st.MagicDNSSuffix, "."), 253),
		Health: []string{}, Peers: []Peer{}}
	for _, h := range st.Health {
		if len(out.Health) < maxHealth {
			out.Health = append(out.Health, clip(h, maxHealthN))
		}
	}
	if ValidLoginURL(st.AuthURL, n.control) {
		out.AuthURL = st.AuthURL
	} else if st.AuthURL != "" {
		n.noteRefusedAuthURL(st.AuthURL)
	}
	if st.CurrentTailnet != nil {
		out.Tailnet = clip(st.CurrentTailnet.Name, maxText)
	}
	if st.Self != nil {
		p := peerOf(st.Self)
		out.Self = &p
	}
	for _, ps := range st.Peer {
		out.Peers = append(out.Peers, peerOf(ps))
	}
	slices.SortFunc(out.Peers, func(a, b Peer) int { return cmp.Compare(a.Name, b.Name) })
	if len(out.Peers) > maxPeers {
		out.Peers, out.PeersTruncated = out.Peers[:maxPeers], true
	}
	return encodeStatus(out)
}

// encodeStatus keeps the JSON under maxJSONSize by halving the peer list: the state, the
// sign-in URL and this node always arrive, so the card keeps its controls.
func encodeStatus(out Status) []byte {
	for {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false) // "<" stays 1 byte, not 6
		_ = enc.Encode(out)
		if buf.Len() <= maxJSONSize || len(out.Peers) == 0 {
			return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
		}
		out.Peers, out.PeersTruncated = out.Peers[:len(out.Peers)/2], true
	}
}

// noteRefusedAuthURL logs once per URL that a sign-in page was withheld, without the URL
// (it is a bearer link): otherwise "Sign In…" just does nothing (quality-9 M1).
func (n *Node) noteRefusedAuthURL(u string) {
	n.authMu.Lock()
	defer n.authMu.Unlock()
	if n.refusedAuth == u {
		return
	}
	n.refusedAuth = u
	n.logf("the coordination server's sign-in page is on another host, port or scheme than the server itself; not shown")
}

func peerOf(ps *ipnstate.PeerStatus) Peer {
	p := Peer{Name: clip(ps.HostName, maxText), DNSName: clip(strings.TrimSuffix(ps.DNSName, "."), 253), OS: clip(ps.OS, maxText),
		Addresses: []string{}, Online: ps.Online, Active: ps.Active, Relay: clip(ps.Relay, maxText), Direct: ps.CurAddr != "",
		RxBytes: ps.RxBytes, TxBytes: ps.TxBytes}
	for _, a := range ps.TailscaleIPs[:min(len(ps.TailscaleIPs), 4)] {
		p.Addresses = append(p.Addresses, a.String())
	}
	if !ps.LastSeen.IsZero() {
		t := ps.LastSeen
		p.LastSeen = &t
	}
	return p
}

// Ping sends a TSMP ping through the tailnet (the probe's data-path check).
func (n *Node) Ping(ip netip.Addr, timeout time.Duration) (*ipnstate.PingResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return n.lb.Ping(ctx, ip, tailcfg.PingTSMP, 0)
}
