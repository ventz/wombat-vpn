#!/bin/bash
#
# Point the Homebrew cask (ventz/homebrew-tap, Casks/wombat-wireguard.rb) at a published release
# and push it. release.sh runs this after "Published", so the DMG the cask names is already live.
#
# Usage: scripts/update-tap.sh <version> <dmg>
#   WOMBAT_TAP_DIR   local checkout of the tap (default ~/git/homebrew-tap)

set -euo pipefail
trap 'echo "update-tap.sh: line $LINENO failed (exit $?): $BASH_COMMAND" >&2' ERR

[[ $# -eq 2 ]] || { echo "usage: $0 <version> <dmg>" >&2; exit 2; }
version="$1"
dmg="$2"
tap_dir="${WOMBAT_TAP_DIR:-$HOME/git/homebrew-tap}"
cask="$tap_dir/Casks/wombat-wireguard.rb"
feed_host="${WOMBAT_FEED_HOST:-https://wombat.vpetkov.net}"

[[ -f "$cask" ]] || { echo "no cask at $cask (set WOMBAT_TAP_DIR)" >&2; exit 1; }
[[ "$version" =~ ^[0-9]+(\.[0-9]+)+$ ]] || { echo "not a version: $version" >&2; exit 1; }

sha=$(shasum -a 256 "$dmg"); sha=${sha%% *}
# Users download the published copy, not ours: refuse to point the cask at a file that differs.
published=$(command curl -fsSL "$feed_host/Wombat-$version.dmg?cb=$(date +%s)" | shasum -a 256)
[[ "${published%% *}" == "$sha" ]] \
    || { echo "$feed_host/Wombat-$version.dmg doesn't match $dmg -- not updating the cask" >&2; exit 1; }

git -C "$tap_dir" pull --ff-only --quiet
sed -i '' -E \
    -e "s/^  version \"[^\"]*\"/  version \"$version\"/" \
    -e "s/^  sha256 \"[0-9a-f]*\"/  sha256 \"$sha\"/" "$cask"
grep -q "version \"$version\"" "$cask" && grep -q "sha256 \"$sha\"" "$cask" \
    || { echo "could not update $cask" >&2; exit 1; }

if git -C "$tap_dir" diff --quiet; then
    echo "  tap:      already at $version"
    exit 0
fi
git -C "$tap_dir" commit --quiet -am "wombat-wireguard $version"
git -C "$tap_dir" push --quiet
echo "  tap:      wombat-wireguard $version (brew install --cask ventz/tap/wombat-wireguard)"
