# amneziawg-go in Wombat

Upstream: https://github.com/amnezia-vpn/amneziawg-go, tag `v3.1.20260828`
(commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`), MIT (see `LICENSE`).

Wombat links this engine only for AmneziaWG tunnels. Plain WireGuard tunnels run upstream
wireguard-go. Both are built into one `libwg-go.a` by `scripts/build-wg-go.sh`, which points
`WireGuardKitGo/go.mod` here with a `replace` directive.

## What was left out

Only the packages Wombat links, plus what their tests need, are vendored: `conn`, `device`,
`ipc`, `ratelimiter`, `replay`, `rwcancel`, `tai64n`, `tun` (without `netstack`). The
`outline` package, the integration tests, the command-line `main`, `version.go` and the
Docker/Make files were dropped, and `go mod tidy` pruned `go.mod` to match. This removes the
Outline SDK, QUIC and YAML dependencies from the module graph. gVisor and `go.uber.org/atomic`
stay in `go.mod` because upstream's tests use them; nothing Wombat links imports them.

## Wombat patches

Grep for `Wombat:` to find each one (patch 1 too).

1. **Upstream wireguard-go `2631ce9`** (2026-10-06) backported to `device/noise-protocol.go`:
   reject a handshake response consumed after an intermediate initiation.
2. **Bounded obfuscation lengths** (`device/obf.go`, `obf_rand*.go`, `obf_datasize.go`):
   `<r N>`, `<rc N>`, `<rd N>` and `<dz N>` must be 0...65507, and a whole I-packet chain
   no longer than one UDP datagram. Upstream accepted any int: a negative length panicked
   the sending goroutine, a huge one allocated without limit on every handshake.
3. **Junk packet guard** (`device/noise-protocol.go`, `JunkPackets`): `jmax < jmin`, a
   `jmax` larger than a datagram, or `jc > 128` sends no junk and logs an error (without the
   values, which fingerprint the server); `jc = 0` returns before any check. Upstream's
   `max-min` wrapped around to a ~4 GB allocation.
4. **Stale S4 offset** (`device/send.go`, `RoutineReadFromTUN`): the TUN reader starts with
   the device and blocks in `Read` with the offset computed before it, so a packet read across
   a change of S4 (the first one after configuration, when the reader got there first) went
   out with the old padding and the peer dropped it. It's a scheduling race: upstream's own
   `TestAWGDevicePing` failed 5 of 5 runs on macOS and 22 of 30 on Linux (0 of 30 with
   `-cpu 1`) at v3.1.20260828. The packet is now moved to the current offset. Upstream
   issue [#168](https://github.com/amnezia-vpn/amneziawg-go/issues/168) and PR
   [#169](https://github.com/amnezia-vpn/amneziawg-go/pull/169) (open, unreviewed as of
   2026-10-15) found the same cause and the same fix independently; drop this patch once #169
   (or an equivalent) is in a tag.
5. **S1-S4 bounds** (`device/uapi.go`, `maxPadding` in `device/obf.go`): handshake paddings
   keep their message within a datagram, S4 is at most 1024. Upstream took any uint16; an S4
   near 65535 moved the TUN read offset past the buffer and panicked the reader, which takes
   down every tunnel in the process.
6. **Handshake batches** (`device/peer.go`, `SendBuffers`), from upstream PR
   [#202](https://github.com/amnezia-vpn/amneziawg-go/pull/202) (open as of 2026-10-15, fixes
   #111): the I-packets, Jc junk packets and initiation went to the bind in one `Send`, and more
   than 128 buffers (Jc = 128, or Jc >= 123 with all five I-packets) panicked it with an index
   out of range, killing every tunnel. They are now sent in batches of the bind's size. Found by
   the round-4 security audit; drop once #202 is in a tag.
7. **Timer race** (`device/timers.go`), from upstream PR
   [#205](https://github.com/amnezia-vpn/amneziawg-go/pull/205) (open as of 2026-10-15): the
   fork cleared a firing timer's `duration` after releasing `modifyingLock`, a data race with
   `Mod`/`IsPending` that could drop a just-armed retry or keepalive. wireguard-go clears its
   flag under the lock. `device/timers_test.go` (from #205) reports the race under `-race`
   before the fix. Found in the round-4 security audit. Of PR #194's other wireguard-go
   backports, the exact unmarshal length checks are already in `receive.go`, and the rest are
   Linux-only or performance work.
8. **IPv6 length wrap** (`device/receive.go`, `tun/tun_darwin.go`): the IPv6 payload length
   plus the 40-byte header was summed in a `uint16`, so 65496 wrapped to 0 and an
   authenticated peer could deliver a zero-length packet, whose macOS TUN write read the
   version byte past the end and panicked the process. The sum is now an `int`, and `Write`
   refuses a packet with no bytes. Upstream wireguard-go has the same code (as of `2631ce9`);
   Wombat guards that engine in its bridge instead (`api-apple.go`, `withoutEmptyPackets`).
   Found in a round-4 security re-scan.
9. **Amplifying reply budget** (`device/wombat.go`, `device/receive.go`): a cookie reply or
   handshake response larger than the datagram that triggered it (S2 and S3 can make it so; a
   real 2.0 config does for cookies) is limited to 20 a second: cookie replies per device,
   handshake responses per peer. Replies go to a source address that can be spoofed.
   Non-amplifying replies are not limited.

`device/s4_startup_race_test.go` is the race test from PR #169 (its padding-bound test, which
expects looser limits than patch 5, was left out). It checks patch 4 by holding the first TUN
read until S4 is configured.

Tests in `device/wombat_test.go`: patch 2 (`TestWombatObfLengthBounds`, `FuzzWombatObfChain`),
3 (`TestWombatJunkGuard`, `TestWombatNoJunkWhenCountIsZero`), 4 (`TestWombatS4OnlyPing`,
`TestWombatAWG2Ping`, and upstream's `TestAWGDevicePing`, which fails without it) and 5
(`TestWombatPaddingBounds`), 6 (`TestWombatMaxJunkPing`), 7 (`TestTimerExpiryRace`, run with
`-race`), 8 (`TestWombatIPv6LengthWrap`, and `TestWombatWriteShortPacket` in `tun/`), 9
(`TestWombatCookieReplyBudget`, `TestWombatResponseBudget`, `TestWombatResponseBudgetIsPerPeer`,
`TestWombatCookieFloodLeavesResponses`). Patch 1 is a race with no deterministic test; it is identical to
upstream wireguard-go's commit.

## Updating

1. `scripts/check-amneziawg-vendor.sh` clones the pinned tag, checks its commit and prints our
   differences, which must be exactly the patches above. For a new tag, clone it, diff it
   against this directory the same way, and read every change in `device/`; then update the
   tag and commit in that script.
2. Re-apply the patches above and check upstream wireguard-go for fixes this fork lacks.
3. `go mod tidy`, `go test ./...` here, then `scripts/build-wg-go.sh` and `govulncheck`.
