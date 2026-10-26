#!/usr/bin/env bash
# Builds build/wg-go/libwg-go.a (universal) from Vendor/WireGuardKit/Sources/WireGuardKitGo,
# against the patched Go runtime (mach_continuous_time; see lib-go-runtime.sh).
set -euo pipefail
trap 'echo "build-wg-go: line $LINENO failed (exit $?): $BASH_COMMAND" >&2' ERR

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/scripts/lib-go-runtime.sh"
SRC="$ROOT/Vendor/WireGuardKit/Sources/WireGuardKitGo"
# The AmneziaWG engine, linked into the same archive (go.mod replace; see its WOMBAT.md).
AWG="$ROOT/Vendor/amneziawg-go"
OUT="$ROOT/build/wg-go"
WORK="$OUT/work"
ARCHS="${ARCHS:-arm64 x86_64}"
MACOS_MIN="${MACOSX_DEPLOYMENT_TARGET:-14.0}"
STAMP="$OUT/.stamp"

go_runtime_prepare build-wg-go "$ROOT/build/go-runtime"

# Skip the rebuild when nothing that feeds the archive changed.
inputs_hash() {
    { echo "$GO_VERSION $ARCHS $MACOS_MIN"; cat "$SRC"/*.go "$SRC/go.mod" "$SRC/go.sum" "$0" "$ROOT/scripts/lib-go-runtime.sh"
      find "$AWG" -type f \( -name '*.go' -o -name go.mod -o -name go.sum \) ! -name '*_test.go' | LC_ALL=C sort | xargs cat; } \
        | shasum -a 256 | cut -d' ' -f1
}
HASH="$(inputs_hash)"
if [[ -f "$OUT/libwg-go.a" && -f "$STAMP" && "$(cat "$STAMP")" == "$HASH" ]]; then
    echo "build-wg-go: up to date"
    exit 0
fi

export CGO_ENABLED=1 GOOS=darwin GOFLAGS=-mod=readonly GOTOOLCHAIN=local
mkdir -p "$OUT" "$WORK"
parts=()
for arch in $ARCHS; do
    goarch="$(go_runtime_goarch "$arch")" || { echo "build-wg-go: unknown arch $arch" >&2; exit 1; }
    flags="-isysroot $SDK -arch $arch -mmacosx-version-min=$MACOS_MIN"
    echo "build-wg-go: building $arch"
    (cd "$SRC" && CGO_CFLAGS="$flags" CGO_LDFLAGS="$flags" GOARCH="$goarch" \
        go build -ldflags=-w -trimpath -buildmode c-archive -o "$WORK/libwg-go-$arch.a" .)
    command rm -f "$WORK/libwg-go-$arch.h"
    parts+=("$WORK/libwg-go-$arch.a")
done
lipo -create -output "$OUT/libwg-go.a" "${parts[@]}"
go_runtime_check_clock build-wg-go "$OUT/libwg-go.a"
echo "$HASH" > "$STAMP"
echo "build-wg-go: $OUT/libwg-go.a ($(lipo -archs "$OUT/libwg-go.a"))"
