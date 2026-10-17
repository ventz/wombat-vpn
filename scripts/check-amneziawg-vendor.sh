#!/usr/bin/env bash
# Verifies Vendor/amneziawg-go against upstream: clones the pinned tag, checks it is the pinned
# commit, and prints every difference from our copy. The output must be exactly the patches in
# Vendor/amneziawg-go/WOMBAT.md (plus the trimmed go.mod/go.sum and our test file).
#
#   scripts/check-amneziawg-vendor.sh            # diff to stdout
#   scripts/check-amneziawg-vendor.sh --stat     # files only
#
# The vendored tree has no checksum of its own (go.mod's replace points at a directory), so this
# is how a reviewer confirms nothing else changed.
set -euo pipefail
trap 'echo "check-amneziawg-vendor: line $LINENO failed (exit $?): $BASH_COMMAND" >&2' ERR

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$ROOT/Vendor/amneziawg-go"
TAG="v3.1.20260828"
COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"

mkdir -p "$ROOT/build"
WORK="$(mktemp -d "$ROOT/build/awg-upstream.XXXXXX")"
trap 'command rm -rf "$WORK"' EXIT

git clone -q --depth 1 --branch "$TAG" https://github.com/amnezia-vpn/amneziawg-go "$WORK/upstream" 2>/dev/null
actual="$(git -C "$WORK/upstream" rev-parse HEAD)"
[[ "$actual" == "$COMMIT" ]] || { echo "check-amneziawg-vendor: $TAG is $actual, expected $COMMIT (tag moved?)" >&2; exit 1; }

# The paths deliberately left out of the vendored copy (WOMBAT.md, "What was left out"),
# removed from the clone by exact path. diff -x matches a base name at every depth, so a new
# device/version.go would have been skipped silently (review SEC-11).
for p in .github outline tests tun/netstack Dockerfile Makefile main.go main_windows.go format_test.go version.go; do
    [[ -e "$WORK/upstream/$p" ]] || { echo "check-amneziawg-vendor: upstream has no $p any more; update this list" >&2; exit 1; }
    command rm -rf "$WORK/upstream/$p"
done
excludes=(-x .git)
if [[ "${1:-}" == "--stat" ]]; then
    diff -rq "${excludes[@]}" "$WORK/upstream" "$VENDOR" | sed "s|$WORK/upstream|upstream|; s|$VENDOR|vendored|" || true
else
    diff -ru "${excludes[@]}" "$WORK/upstream" "$VENDOR" | sed "s|$WORK/upstream|upstream|; s|$VENDOR|vendored|" || true
fi
