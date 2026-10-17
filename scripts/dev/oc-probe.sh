#!/usr/bin/env bash
# Builds and runs scripts/dev/oc-probe (see main.swift there) against the ocserv test gateway.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/build/oc-probe"
OC="$ROOT/build/openconnect"
"$ROOT/scripts/build-openconnect.sh" >/dev/null
mkdir -p "$OUT"
# A failed build must never run the previous binary.
command rm -f "$OUT/oc-probe"
SDK="$(xcrun --sdk macosx --show-sdk-path)"
clang -isysroot "$SDK" -I"$OC/include/openconnect" -c "$ROOT/OpenConnect/OCBridge.c" -o "$OUT/OCBridge.o"
xcrun swiftc -swift-version 5 -module-name WombatProbe -sdk "$SDK" \
    -import-objc-header "$ROOT/OpenConnect/OCBridge.h" -Xcc -I"$OC/include/openconnect" \
    "$ROOT"/Packages/TunnelCore/Sources/TunnelCore/*.swift "$ROOT/OpenConnect/OpenConnectEngine.swift" "$ROOT/OpenConnect/TunnelDevice.swift" "$ROOT/scripts/dev/oc-probe/main.swift" \
    "$OUT/OCBridge.o" "$OC/lib/libopenconnect.a" "$OC/lib/libssl.a" "$OC/lib/libcrypto.a" -lxml2 -lz -liconv \
    -o "$OUT/oc-probe"
exec "$OUT/oc-probe" "$ROOT"
