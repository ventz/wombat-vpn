/* SPDX-License-Identifier: MIT
 *
 * Tests for Wombat's bridge (api-apple.go).
 */

package main

import (
	"errors"
	"testing"
)

func TestWithoutEmptyPackets(t *testing.T) {
	const offset = 16
	good := make([]byte, offset+40)
	good[offset] = 0x60
	empty := make([]byte, offset)
	shortV6 := make([]byte, offset+39)
	shortV6[offset] = 0x60
	v4 := make([]byte, offset+20)
	v4[offset] = 0x45
	for _, c := range []struct {
		in   [][]byte
		want int
	}{
		{[][]byte{good, good}, 2},
		{[][]byte{empty}, 0},
		{[][]byte{good, empty, good}, 2},
		{[][]byte{empty, good}, 1},
		{[][]byte{make([]byte, offset-1)}, 0},
		{[][]byte{shortV6, v4}, 1},
		{[][]byte{make([]byte, offset+19)}, 0},
	} {
		got := withoutEmptyPackets(c.in, offset)
		if len(got) != c.want {
			t.Errorf("%d packets in, %d kept, want %d", len(c.in), len(got), c.want)
		}
		for _, b := range got {
			if len(b) <= offset {
				t.Errorf("kept a packet of %d bytes", len(b))
			}
		}
	}
}

// A clean batch reaches the engine's writer untouched, with its count and error passed back.
func TestGuardedWritePassThrough(t *testing.T) {
	const offset = 16
	v4 := make([]byte, offset+20)
	v4[offset] = 0x45
	failure := errors.New("write failed")
	var got int
	write := func(bufs [][]byte, _ int) (int, error) { got = len(bufs); return 1, failure }

	if n, err := guardedWrite(write, [][]byte{v4, v4}, offset); n != 1 || err != failure || got != 2 {
		t.Errorf("clean batch: n=%d err=%v wrote %d, want 1, the writer's error, 2", n, err, got)
	}
	got = 0
	if n, err := guardedWrite(write, [][]byte{make([]byte, offset)}, offset); n != 1 || err != nil || got != 0 {
		t.Errorf("all dropped: n=%d err=%v wrote %d, want 1, nil, 0", n, err, got)
	}
	if n, err := guardedWrite(write, [][]byte{v4, make([]byte, offset)}, offset); err != failure || got != 1 || n != 1 {
		t.Errorf("mixed: n=%d err=%v wrote %d, want the writer's count and error after 1 packet", n, err, got)
	}
}
