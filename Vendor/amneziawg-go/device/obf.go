package device

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Wombat: every generated length is bounded. Upstream took any int, so a negative <r -1>
// panicked the sending goroutine and a huge one allocated without limit on every handshake.
// One obfuscated packet can never be larger than a UDP datagram.
const maxObfLen = 65507

// Wombat: junk packets sent before each handshake initiation (Jc).
const maxJunkCount = 128

// Wombat: S1-S4 bounds. Upstream took any uint16: an S4 near 65535 moved the TUN read offset
// past the end of the buffer and panicked the reader, taking down every tunnel in the
// process. Handshake paddings keep the message within a datagram; transport padding leaves
// room for a full-size packet behind it.
var maxPadding = [4]uint64{
	maxObfLen - MessageInitiationSize,
	maxObfLen - MessageResponseSize,
	maxObfLen - MessageCookieReplySize,
	1024,
}

func parseObfLength(val string) (int, error) {
	length, err := strconv.Atoi(val)
	if err != nil {
		return 0, err
	}
	if length < 0 || length > maxObfLen {
		return 0, fmt.Errorf("length %d is outside 0...%d", length, maxObfLen)
	}
	return length, nil
}

type obfBuilder func(val string) (obf, error)

var obfBuilders = map[string]obfBuilder{
	"b":  newBytesObf,
	"t":  newTimestampObf,
	"r":  newRandObf,
	"rc": newRandCharObf,
	"rd": newRandDigitsObf,
	"d":  newDataObf,
	"ds": newDataStringObf,
	"dz": newDataSizeObf,
}

type obf interface {
	Obfuscate(dst, src []byte)
	Deobfuscate(dst, src []byte) bool
	ObfuscatedLen(srcLen int) int
	DeobfuscatedLen(srcLen int) int
}

type obfChain struct {
	Spec string
	obfs []obf
}

func newObfChain(spec string) (*obfChain, error) {
	var (
		obfs []obf
		errs []error
	)

	remaining := spec[:]
	for {
		start := strings.IndexByte(remaining, '<')
		if start == -1 {
			break
		}

		end := strings.IndexByte(remaining[start:], '>')
		if end == -1 {
			return nil, errors.New("missing enclosing >")
		}
		end += start

		tag := remaining[start+1 : end]
		parts := strings.Fields(tag)
		if len(parts) == 0 {
			errs = append(errs, errors.New("empty tag"))
			remaining = remaining[end+1:]
			continue
		}

		key := parts[0]
		builder, ok := obfBuilders[key]
		if !ok {
			errs = append(errs, fmt.Errorf("unknown tag <%s>", key))
			remaining = remaining[end+1:]
			continue
		}

		val := ""
		if len(parts) > 1 {
			val = parts[1]
		}

		o, err := builder(val)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to build <%s>: %w", key, err))
			remaining = remaining[end+1:]
			continue
		}

		obfs = append(obfs, o)
		remaining = remaining[end+1:]
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if len(obfs) == 0 {
		return nil, nil
	}

	chain := &obfChain{Spec: spec, obfs: obfs}
	if chain.ObfuscatedLen(0) > maxObfLen {
		return nil, fmt.Errorf("packet is longer than %d bytes", maxObfLen)
	}
	return chain, nil
}

func (c *obfChain) Obfuscate(dst, src []byte) {
	written := 0
	for _, o := range c.obfs {
		obfLen := o.ObfuscatedLen(len(src))
		o.Obfuscate(dst[written:written+obfLen], src)
		written += obfLen
	}
}

func (c *obfChain) Deobfuscate(dst, src []byte) bool {
	dynamicLen := len(src) - c.ObfuscatedLen(0)

	written, read := 0, 0

	for _, o := range c.obfs {
		deobfLen := o.DeobfuscatedLen(dynamicLen)
		obfLen := o.ObfuscatedLen(deobfLen)

		if !o.Deobfuscate(dst[written:written+deobfLen], src[read:read+obfLen]) {
			return false
		}

		written += deobfLen
		read += obfLen
	}

	return true
}

func (c *obfChain) ObfuscatedLen(n int) int {
	total := 0
	for _, o := range c.obfs {
		total += o.ObfuscatedLen(n)
	}
	return total
}

func (c *obfChain) DeobfuscatedLen(n int) int {
	dynamicLen := n - c.ObfuscatedLen(0)

	total := 0
	for _, o := range c.obfs {
		total += o.DeobfuscatedLen(dynamicLen)
	}
	return total
}
