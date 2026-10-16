/* SPDX-License-Identifier: MIT
 *
 * Tests for Wombat's changes to amneziawg-go (see WOMBAT.md).
 */

package tun

import "testing"

// A packet shorter than one byte must be refused, not read past: Write looks at the IP version
// in buf[offset] (patch 8).
func TestWombatWriteShortPacket(t *testing.T) {
	tun := &NativeTun{}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Write panicked: %v", r)
		}
	}()
	buf := make([]byte, 16)
	if _, err := tun.Write([][]byte{buf}, 16); err == nil {
		t.Fatal("Write accepted a packet with no bytes")
	}
}
