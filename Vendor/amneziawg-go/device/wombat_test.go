/* SPDX-License-Identifier: MIT
 *
 * Tests for Wombat's changes to amneziawg-go (see WOMBAT.md).
 */

package device

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// A real AmneziaWG 2.0 shape (values changed): no I-packets, H ranges, S1-S4 all set.
// Upstream lost the first transport packet whenever S4 was set (stale TUN read offset).
func TestWombatAWG2Ping(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, true,
		"jc", "4", "jmin", "8", "jmax", "80",
		"s1", "97", "s2", "24", "s3", "136", "s4", "8",
		"h1", "52817304-98112577", "h2", "203946611-260118845",
		"h3", "811402277-1390655104", "h4", "1602337918-1849120473",
		// The same UAPI Wombat's TunnelCore writes, signature packet included.
		"i1", "<b 0xc70000000108><r 16><t>",
	)
	t.Run("ping", func(t *testing.T) { pair.Send(t, Ping, nil) })
	t.Run("pong", func(t *testing.T) { pair.Send(t, Pong, nil) })
}

func TestWombatPaddingBounds(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()
	for _, line := range []string{"s1=65360", "s2=65416", "s3=65444", "s4=1025", "s4=65000"} {
		if err := dev.IpcSet(line + "\n"); err == nil {
			t.Errorf("%s: accepted", line)
		}
	}
	for _, line := range []string{"s1=1132", "s4=1024", "s4=32"} {
		if err := dev.IpcSet(line + "\n"); err != nil {
			t.Errorf("%s: %v", line, err)
		}
	}
}

// Jc = 0 sends nothing and logs nothing, whatever Jmin and Jmax say (a config with Jmin but
// no Jmax used to log an error with the values on every handshake).
func TestWombatNoJunkWhenCountIsZero(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()
	dev.junk.count.Store(0)
	dev.junk.min.Store(50)
	dev.junk.max.Store(0)
	if got := dev.JunkPackets(); got != nil {
		t.Errorf("%d junk packets with jc=0", len(got))
	}
}

// The most buffers one handshake can send: 128 junk packets, five I-packets and the initiation.
// One bind Send of more than conn.IdealBatchSize (128) panicked the whole process (patch 6).
func TestWombatMaxJunkPing(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, true,
		"jc", "128", "jmin", "8", "jmax", "80",
		"i1", "<r 8>", "i2", "<r 8>", "i3", "<r 8>", "i4", "<r 8>", "i5", "<r 8>",
	)
	t.Run("ping", func(t *testing.T) { pair.Send(t, Ping, nil) })
	t.Run("pong", func(t *testing.T) { pair.Send(t, Pong, nil) })
}

func TestWombatS4OnlyPing(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, true, "s4", "25")
	t.Run("ping", func(t *testing.T) { pair.Send(t, Ping, nil) })
	t.Run("pong", func(t *testing.T) { pair.Send(t, Pong, nil) })
}

func TestWombatObfLengthBounds(t *testing.T) {
	for _, spec := range []string{
		"<r -1>", "<rc -5>", "<rd -1>", "<dz -1>",
		"<r 65508>", "<rc 99999999999>", "<rd 1000000>",
		"<r 40000><r 40000>", // each fits, together longer than a datagram
		"<b 0x" + strings.Repeat("ab", maxObfLen+1) + ">",
	} {
		if chain, err := newObfChain(spec); err == nil {
			t.Errorf("%.40q: accepted (length %d)", spec, chain.ObfuscatedLen(0))
		}
	}
	for _, spec := range []string{"<r 0>", "<r 65507>", "<b 0xc0ffee><t><r 16><rc 8><rd 4>"} {
		if _, err := newObfChain(spec); err != nil {
			t.Errorf("%q: %v", spec, err)
		}
	}
}

func TestWombatJunkGuard(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()
	for _, c := range []struct{ count, min, max uint32 }{
		{4, 100, 50},              // jmax < jmin wrapped to a ~4 GB size upstream
		{4, 10, maxObfLen + 1},    // larger than a datagram
		{maxJunkCount + 1, 8, 80}, // too many
	} {
		dev.junk.count.Store(c.count)
		dev.junk.min.Store(c.min)
		dev.junk.max.Store(c.max)
		if got := dev.JunkPackets(); got != nil {
			t.Errorf("jc=%d jmin=%d jmax=%d: %d packets, want none", c.count, c.min, c.max, len(got))
		}
	}
	dev.junk.count.Store(4)
	dev.junk.min.Store(8)
	dev.junk.max.Store(80)
	got := dev.JunkPackets()
	if len(got) != 4 {
		t.Fatalf("got %d junk packets, want 4", len(got))
	}
	for _, p := range got {
		if len(p) < 8 || len(p) >= 80 {
			t.Errorf("junk packet of %d bytes, want 8..79", len(p))
		}
	}
}

// The tag parser takes text from a config file; no spec may panic it or yield a chain longer
// than a datagram. Run longer with: go test ./device -run '^$' -fuzz FuzzWombatObfChain
func FuzzWombatObfChain(f *testing.F) {
	for _, seed := range []string{"<b 0xc0ffee><t><r 16>", "<rc 8> <rd 4>", "<r -1>", "<dz 99999>", "<b 0x>", "<", "<>>", "<r 40000><r 40000>"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		chain, err := newObfChain(spec)
		if err != nil || chain == nil {
			return
		}
		n := chain.ObfuscatedLen(0)
		if n < 0 || n > maxObfLen {
			t.Fatalf("%q: length %d", spec, n)
		}
		buf := make([]byte, n)
		chain.Obfuscate(buf, nil)
	})
}

// An authenticated IPv6 packet whose payload length field is 65496 made `length + 40` wrap to 0
// in a uint16, so a zero-length packet reached the TUN. On macOS, NativeTun.Write then read
// past the end of the buffer and panicked the process (round-4 security audit; upstream
// wireguard-go has the same code). Patch 8.
func TestWombatIPv6LengthWrap(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, true)
	src := netip.MustParseAddr("fd00::2")
	dst := netip.MustParseAddr("fd00::1")
	// Route fd00::/64 to the other device on both sides, as an IPv6 tunnel would.
	for _, dev := range []*Device{pair[0].dev, pair[1].dev} {
		dev.peers.RLock()
		for _, peer := range dev.peers.keyMap {
			dev.allowedips.Insert(netip.MustParsePrefix("fd00::/64"), peer)
		}
		dev.peers.RUnlock()
	}

	packet := make([]byte, 48)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 65496) // + 40 header bytes wraps a uint16 to 0
	packet[6] = 59                                 // no next header
	packet[7] = 64
	copy(packet[8:24], src.AsSlice())
	copy(packet[24:40], dst.AsSlice())

	pair[1].tun.Outbound <- packet
	select {
	case got := <-pair[0].tun.Inbound:
		t.Fatalf("delivered a %d-byte packet to the TUN; want it dropped", len(got))
	case <-time.After(2 * time.Second):
	}
}

// Cookie replies larger than their request are capped per second; others are not (patch 9).
func TestWombatCookieReplyBudget(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()

	// Plain WireGuard sizes: a 64-byte reply never amplifies.
	for i := 0; i < 100; i++ {
		if !dev.allowCookieReply(MessageResponseType) {
			t.Fatal("non-amplifying cookie reply was limited")
		}
	}

	// The shape of a real AmneziaWG 2.0 config: a 116-byte response-shaped packet would get a
	// 200-byte reply.
	if err := dev.IpcSet("s1=97\ns2=24\ns3=136\n"); err != nil {
		t.Fatal(err)
	}
	if !dev.allowCookieReply(MessageInitiationType) { // 245 bytes in, 200 out: not amplifying
		t.Fatal("non-amplifying initiation reply was limited")
	}
	allowed := 0
	for i := 0; i < 100; i++ {
		if dev.allowCookieReply(MessageResponseType) {
			allowed++
		}
	}
	if allowed != maxAmplifyingReplies {
		t.Fatalf("%d amplifying replies allowed in one second, want %d", allowed, maxAmplifyingReplies)
	}
}

// A handshake response larger than the initiation shares the same budget (patch 9).
func TestWombatResponseBudget(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()
	peer := &Peer{}
	for i := 0; i < 100; i++ { // 148 in, 92 out
		if !dev.allowHandshakeResponse(peer) {
			t.Fatal("non-amplifying response was limited")
		}
	}
	if err := dev.IpcSet("s1=0\ns2=1188\n"); err != nil { // 148 in, 1280 out
		t.Fatal(err)
	}
	allowed := 0
	for i := 0; i < 100; i++ {
		if dev.allowHandshakeResponse(peer) {
			allowed++
		}
	}
	if allowed != maxAmplifyingReplies {
		t.Fatalf("%d amplifying responses allowed in one second, want %d", allowed, maxAmplifyingReplies)
	}
	// The cookie budget is separate: spending all responses leaves cookie replies available.
	if err := dev.IpcSet("s3=1216\n"); err != nil {
		t.Fatal(err)
	}
	if !dev.allowCookieReply(MessageInitiationType) {
		t.Fatal("cookie reply blocked by the response budget")
	}
}

// Unauthenticated cookie requests can't use up the budget that real handshakes need: a
// flood of MAC1-only initiations spends the cookie budget, not the response one (S4d M1).
func TestWombatCookieFloodLeavesResponses(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()
	peer := &Peer{}
	if err := dev.IpcSet("s1=0\ns2=1188\ns3=1216\n"); err != nil { // both kinds amplify
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		dev.allowCookieReply(MessageInitiationType)
	}
	if !dev.allowHandshakeResponse(peer) {
		t.Fatal("a cookie flood blocked a handshake response")
	}
}

// One peer's amplifying responses don't use up another's (S4e Info 2).
func TestWombatResponseBudgetIsPerPeer(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()
	if err := dev.IpcSet("s1=0\ns2=1188\n"); err != nil {
		t.Fatal(err)
	}
	busy, other := &Peer{}, &Peer{}
	for i := 0; i < 100; i++ {
		dev.allowHandshakeResponse(busy)
	}
	if !dev.allowHandshakeResponse(other) {
		t.Fatal("one peer's responses blocked another's")
	}
}
