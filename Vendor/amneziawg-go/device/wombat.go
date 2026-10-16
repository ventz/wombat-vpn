/* SPDX-License-Identifier: MIT
 *
 * Wombat's additions to amneziawg-go (see WOMBAT.md).
 */

package device

import (
	"sync"
	"time"
)

// maxAmplifyingReplies caps, per second and per device, replies larger than the datagram that
// triggered them (patch 9). WireGuard never replies with more than it received: a cookie reply
// (64 bytes) and a handshake response (92) are both smaller than an initiation (148). S2 and S3
// can change that: with S2 = 20 and S3 = 144 (a real AmneziaWG 2.0 config) a 112-byte packet
// gets a 208-byte cookie reply, and S1 = 0 with S2 = 1188 turns a 148-byte initiation into a
// 1280-byte response. A reply goes to the datagram's source address, which can be spoofed:
// cookie replies need only the tunnel's public key (MAC1), responses the peer's private key.
// Non-amplifying replies are not limited, as upstream. Cookie replies (which need no peer key)
// have one budget per device; handshake responses have one per peer, so neither an
// unauthenticated flood nor one peer can delay another peer's handshakes.
const maxAmplifyingReplies = 20

type amplifyingReplyBudget struct {
	sync.Mutex
	window time.Time
	sent   int
}

// allowReply reports whether a reply of replySize bytes may answer a request of requestSize,
// charging budget b when it amplifies.
func (b *amplifyingReplyBudget) allowReply(requestSize, replySize int) bool {
	if replySize <= requestSize {
		return true
	}
	b.Lock()
	defer b.Unlock()
	if now := time.Now(); now.Sub(b.window) >= time.Second {
		b.window, b.sent = now, 0
	}
	if b.sent >= maxAmplifyingReplies {
		return false
	}
	b.sent++
	return true
}

// allowCookieReply reports whether a cookie reply may answer a handshake message of msgType.
func (device *Device) allowCookieReply(msgType uint32) bool {
	request := int(device.paddings.init.Load()) + MessageInitiationSize
	if msgType == MessageResponseType {
		request = int(device.paddings.response.Load()) + MessageResponseSize
	}
	return device.amplifyingReplies.cookies.allowReply(request, int(device.paddings.cookie.Load())+MessageCookieReplySize)
}

// allowHandshakeResponse reports whether peer's initiation may be answered now.
func (device *Device) allowHandshakeResponse(peer *Peer) bool {
	return peer.amplifyingResponses.allowReply(int(device.paddings.init.Load())+MessageInitiationSize,
		int(device.paddings.response.Load())+MessageResponseSize)
}
