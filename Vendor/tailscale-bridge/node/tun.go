package node

import "github.com/tailscale/wireguard-go/tun"

// guardedTUN drops packets the macOS TUN write can't take. Tailscale's wireguard-go fork has
// the same darwin Write as upstream: it reads the version byte at buf[offset] with no length
// check, so an empty packet after offset panics the whole extension (Wombat audit 4b-H1, the
// IPv6 payload-length wrap). Packets shorter than their IP header are dropped too; the kernel
// would drop them anyway. Same rule as withoutEmptyPackets in WireGuardKitGo/api-apple.go.
type guardedTUN struct{ tun.Device }

func validPacket(b []byte, offset int) bool {
	if len(b) <= offset {
		return false
	}
	n := len(b) - offset
	return n >= 20 && (b[offset]>>4 != 6 || n >= 40)
}

func (t guardedTUN) Write(bufs [][]byte, offset int) (int, error) {
	kept := bufs[:0:0]
	for _, b := range bufs {
		if validPacket(b, offset) {
			kept = append(kept, b)
		}
	}
	if len(kept) == len(bufs) {
		return t.Device.Write(bufs, offset)
	}
	if len(kept) == 0 {
		return len(bufs), nil
	}
	if n, err := t.Device.Write(kept, offset); err != nil {
		return n, err
	}
	return len(bufs), nil
}
