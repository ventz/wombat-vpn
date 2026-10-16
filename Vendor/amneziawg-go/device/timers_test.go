/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"testing"
	"time"
)

// TestTimerExpiryRace asks whether a timer is pending while it expires, then
// arms it again. Under the race detector it fails if the expiry changes the
// state of the timer outside modifyingLock, where IsPending and Mod do not
// see the change in order.
func TestTimerExpiryRace(t *testing.T) {
	var peer Peer
	timer := peer.NewTimer(func(*Peer, time.Duration) {})
	defer timer.DelSync()

	deadline := time.Now().Add(5 * time.Second)
	for i := 0; i < 100; i++ {
		timer.Mod(time.Microsecond)
		for timer.IsPending() {
			if time.Now().After(deadline) {
				t.Fatal("the timer did not expire")
			}
		}
	}
}
