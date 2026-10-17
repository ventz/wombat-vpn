# OpenConnect in Wombat

Wombat's Cisco AnyConnect support runs the tunnel on **libopenconnect 9.21** (LGPL-2.1,
© David Woodhouse and contributors, <https://www.infradead.org/openconnect/>) with
**OpenSSL 3.5 LTS** (Apache-2.0). Neither source tree is checked in: `scripts/build-openconnect.sh`
downloads the release tarballs, checks them against SHA-256 pins, and builds universal static
libraries into `build/openconnect/`.

## What Wombat changes

Eleven security patches, applied by `scripts/patch-openconnect.py` as checked substitutions (the
build fails if an anchor moves), all found in Wombat's audits (round 5b, 2026-10-16):

1. `cstp.c`: the gateway's MTU (`X-CSTP-MTU`, `X-DTLS-MTU`) must be 1-16384. Unbounded, a value
   near 2^31 wrapped `alloc_pkt`'s `int` size to a 2 KB buffer that the CSTP read could then fill
   with up to 2 GB: a heap overwrite any hostile gateway could trigger in upstream 9.21.
2. `cstp.c`: `X-CSTP-Base-MTU` bounded the same way.
3. `cstp.c`: at most 4096 `X-CSTP-`/`X-DTLS-` headers per CONNECT reply (memory exhaustion).
4. `openconnect-internal.h`: `alloc_pkt` refuses a negative or larger-than-1 MiB length, so no
   path can wrap the packet size.
5. `cstp.c`: a compression the client didn't request is refused (Wombat requests none), so the
   gateway can't switch on a C decompressor it feeds.
6. `cstp.c`: deflate payloads shorter than their 4-byte checksum are refused (`avail_in` underflow).
7. `cstp.c`: the server-disconnect message is terminated inside its buffer (off-by-one write).
8. `cstp.c`: the CSTP incoming queue is bounded like DTLS's (`max_qlen`).
9. `cstp.c`: the HTTP 503 header loop stops on read errors (it could spin forever).
10. `cstp.c`: the decoded STRAP private key is wiped (`OPENSSL_cleanse`) and freed after use.
11. `cstp.c`: LZS/LZ4 are never told the destination is larger than `deflate_pkt_size` (defense
    in depth; unreachable while we request no compression, patch 5).

Patch 3 also caps the headers at 1 MiB in total.

Re-check each on every version bump. Apart from these, at compile time every process-spawning call
(`fork`, the `exec` family, `posix_spawn`, `system`) is renamed to a stub in `noexec.c` that
fails with `ENOSYS`, and the build fails if a reference to a real one remains. That keeps
vpnc-script, CSD/HostScan wrappers, the NTLM helper and the external browser from ever running.
`scripts/build-signed.sh` checks the linked extension binary again.

Only the tunnel phase uses libopenconnect: sign-in is Wombat's own Swift code
(`Packages/TunnelCore/Sources/TunnelCore/AnyConnect*.swift`), modeled on OpenConnect's
`auth.c`. libopenconnect is linked only into the OpenConnect system extension, never into the
app or the WireGuard extension.

## LGPL-2.1

libopenconnect is linked statically. Wombat's complete source, including the scripts that build
and link libopenconnect, is public under the MIT license, so anyone can relink the extension
against a modified libopenconnect: change `OPENCONNECT_VERSION`/`OPENCONNECT_SHA256` (or point
the script at your own tarball), run `scripts/build-openconnect.sh`, and build. The license texts
ship in the extension bundle (`Contents/Resources/COPYING.LGPL`, `LICENSE.openssl`).

## Bumping

Change the version and SHA-256 together in `scripts/build-openconnect.sh` (verify the tarball's
GPG signature, key `BE07D9FD54809AB2C4B0FF5F63762CDA67E2F359`, or compare with Homebrew's
formula), keep `AnyConnectXML.clientVersion`/`defaultUserAgent` in step with the new version,
then run `scripts/dev/ocserv-peer.sh up`, `scripts/dev/oc-probe.sh` and the live tests.
