#!/usr/bin/env bash
# Patch 12 proof: builds scripts/dev/dtls-stray-record.c against Wombat's patched libopenconnect
# and runs it (no gateway, VPN profile or keychain needed). See Vendor/openconnect/WOMBAT.md.
# The first run downloads the pinned openconnect/OpenSSL sources and builds them (minutes).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/build/dtls-stray-record"
OC="$ROOT/build/openconnect"
"$ROOT/scripts/build-openconnect.sh" >/dev/null
ARCH="$(uname -m)"
# The harness reaches into libopenconnect's internals, so it needs this arch's configured tree.
VERSION="$(sed -n 's/^readonly OPENCONNECT_VERSION=//p' "$ROOT/scripts/build-openconnect.sh")"
TREE="$OC/work/$ARCH/openconnect-$VERSION"
[[ -f "$TREE/config.h" ]] || { echo "no configured openconnect tree for $ARCH under $OC/work" >&2; exit 1; }
mkdir -p "$OUT"
# A failed build must never run the previous binary.
command rm -f "$OUT/dtls-stray-record"
SDK="$(xcrun --sdk macosx --show-sdk-path)"
clang -isysroot "$SDK" -arch "$ARCH" -Wall -DHAVE_CONFIG_H -I"$TREE" -I"$TREE/json" \
    -I"$OC/work/$ARCH/prefix/include" -I"$SDK/usr/include/libxml2" \
    "$ROOT/scripts/dev/dtls-stray-record.c" \
    "$OC/lib/libopenconnect.a" "$OC/lib/libssl.a" "$OC/lib/libcrypto.a" -lxml2 -lz -liconv \
    -o "$OUT/dtls-stray-record"
exec "$OUT/dtls-stray-record"
