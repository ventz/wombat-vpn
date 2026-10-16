#!/usr/bin/env bash
# Builds build/wg-go/libwg-go.a (universal) from Vendor/WireGuardKit/Sources/WireGuardKitGo.
#
# Go's runtime measures time with mach_absolute_time, which stops while the Mac sleeps, so
# WireGuard's handshake and rekey timers would think no time passed across a sleep. Like the
# official app, we build against a private copy of GOROOT patched to mach_continuous_time.
# The patch is a checked substitution rather than a diff so it survives Go releases; the
# script fails if the expected call sites move.
set -euo pipefail
trap 'echo "build-wg-go: line $LINENO failed (exit $?): $BASH_COMMAND" >&2' ERR

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/Vendor/WireGuardKit/Sources/WireGuardKitGo"
# The AmneziaWG engine, linked into the same archive (go.mod replace; see its WOMBAT.md).
AWG="$ROOT/Vendor/amneziawg-go"
OUT="$ROOT/build/wg-go"
WORK="$OUT/work"
ARCHS="${ARCHS:-arm64 x86_64}"
MACOS_MIN="${MACOSX_DEPLOYMENT_TARGET:-14.0}"

export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
command -v go >/dev/null || { echo "build-wg-go: Go is required (brew install go)" >&2; exit 1; }

REAL_GOROOT="$(go env GOROOT)"
GO_VERSION="$(go env GOVERSION)"
# The runtime patch is checked against this toolchain line; a different minor version must be a
# deliberate bump (audit F-16). WOMBAT_GO_VERSION overrides for testing a new release.
readonly EXPECTED_GO="${WOMBAT_GO_VERSION:-go1.27}"
[[ "$GO_VERSION" == "$EXPECTED_GO" || "$GO_VERSION" == "$EXPECTED_GO".* ]] \
    || { echo "build-wg-go: Go $GO_VERSION, expected $EXPECTED_GO.x (set WOMBAT_GO_VERSION to try another)" >&2; exit 1; }
SDK="$(xcrun --sdk macosx --show-sdk-path)"
PATCHED="$WORK/goroot-$GO_VERSION"
STAMP="$OUT/.stamp"

# Skip the rebuild when nothing that feeds the archive changed.
inputs_hash() {
    { echo "$GO_VERSION $ARCHS $MACOS_MIN"; cat "$SRC"/*.go "$SRC/go.mod" "$SRC/go.sum" "$0"
      find "$AWG" -type f \( -name '*.go' -o -name go.mod -o -name go.sum \) ! -name '*_test.go' | LC_ALL=C sort | xargs cat; } \
        | shasum -a 256 | cut -d' ' -f1
}
HASH="$(inputs_hash)"
if [[ -f "$OUT/libwg-go.a" && -f "$STAMP" && "$(cat "$STAMP")" == "$HASH" ]]; then
    echo "build-wg-go: up to date"
    exit 0
fi

if [[ ! -f "$PATCHED/.prepared" ]]; then
    echo "build-wg-go: preparing patched GOROOT ($GO_VERSION)"
    mkdir -p "$PATCHED"
    rsync -a --delete --exclude=pkg/obj/go-build "$REAL_GOROOT/" "$PATCHED/"
    chmod -R u+w "$PATCHED/src/runtime"
    for f in sys_darwin.go sys_darwin_amd64.s sys_darwin_arm64.s; do
        file="$PATCHED/src/runtime/$f"
        before="$(/usr/bin/grep -c 'libc_mach_absolute_time' "$file" || true)"
        [[ "$before" == "1" ]] || { echo "build-wg-go: expected one mach_absolute_time call in $f, found '${before:-0}'" >&2; exit 1; }
        /usr/bin/sed -i '' -e 's/libc_mach_absolute_time mach_absolute_time/libc_mach_continuous_time mach_continuous_time/' \
            -e 's/libc_mach_absolute_time(SB)/libc_mach_continuous_time(SB)/' "$file"
        after="$(/usr/bin/grep -c 'libc_mach_continuous_time' "$file" || true)"
        [[ "$after" == "1" ]] || { echo "build-wg-go: patch did not apply to $f" >&2; exit 1; }
    done
    touch "$PATCHED/.prepared"
fi

export GOROOT="$PATCHED"
export CGO_ENABLED=1 GOOS=darwin GOFLAGS=-mod=readonly GOTOOLCHAIN=local
mkdir -p "$OUT"
parts=()
for arch in $ARCHS; do
    case "$arch" in
        arm64) goarch=arm64 ;;
        x86_64) goarch=amd64 ;;
        *) echo "build-wg-go: unknown arch $arch" >&2; exit 1 ;;
    esac
    flags="-isysroot $SDK -arch $arch -mmacosx-version-min=$MACOS_MIN"
    echo "build-wg-go: building $arch"
    (cd "$SRC" && CGO_CFLAGS="$flags" CGO_LDFLAGS="$flags" GOARCH="$goarch" \
        go build -ldflags=-w -trimpath -buildmode c-archive -o "$WORK/libwg-go-$arch.a" .)
    command rm -f "$WORK/libwg-go-$arch.h"
    parts+=("$WORK/libwg-go-$arch.a")
done
lipo -create -output "$OUT/libwg-go.a" "${parts[@]}"
# The clock patch must have taken: no mach_absolute_time may remain in the archive.
symbols="$(nm "$OUT/libwg-go.a" 2>/dev/null || true)"
if [[ "$symbols" == *mach_absolute_time* || "$symbols" != *mach_continuous_time* ]]; then
    command rm -f "$OUT/libwg-go.a"
    echo "build-wg-go: the archive still uses mach_absolute_time; the runtime patch did not apply" >&2
    exit 1
fi
echo "$HASH" > "$STAMP"
echo "build-wg-go: $OUT/libwg-go.a ($(lipo -archs "$OUT/libwg-go.a"))"
