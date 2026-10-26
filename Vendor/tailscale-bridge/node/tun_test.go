package node

import (
	"testing"

	"github.com/tailscale/wireguard-go/tun"
)

type recordingTUN struct {
	tun.Device
	got [][]byte
}

func (r *recordingTUN) Write(bufs [][]byte, offset int) (int, error) {
	r.got = append(r.got, bufs...)
	return len(bufs), nil
}

func TestGuardedTUNDropsShortPackets(t *testing.T) {
	const off = 16
	pkt := func(version byte, n int) []byte {
		b := make([]byte, off+n)
		if n > 0 {
			b[off] = version << 4
		}
		return b
	}
	rec := &recordingTUN{}
	g := guardedTUN{rec}
	bufs := [][]byte{pkt(4, 0), pkt(4, 20), pkt(6, 39), pkt(6, 40), pkt(4, 19), make([]byte, 3)}
	n, err := g.Write(bufs, off)
	if err != nil || n != len(bufs) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if len(rec.got) != 2 || len(rec.got[0]) != off+20 || len(rec.got[1]) != off+40 {
		t.Fatalf("passed %d packets", len(rec.got))
	}
}
