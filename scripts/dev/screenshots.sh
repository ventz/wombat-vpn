#!/usr/bin/env bash
# Captures the website/README screenshots from the Debug app's demo mode (example tunnels,
# documentation addresses, throwaway keys: nothing of yours), then scales them to 1600 px and
# converts them to WebP for site/screenshots/ (published by scripts/publish-site.sh).
#
# Usage: scripts/dev/screenshots.sh   (build the Debug app first; see docs/DEVELOPING.md)
set -euo pipefail
trap 'echo "screenshots: line $LINENO failed (exit $?): $BASH_COMMAND" >&2' ERR

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP="$ROOT/build/DerivedData/Build/Products/Debug/Wombat Debug.app"
# The app is sandboxed, so it writes inside its own container; copied out below.
CONTAINER_DIR="$HOME/Library/Containers/net.vpetkov.wombat.debug/Data/tmp/screenshots"
RAW="$ROOT/build/screenshots/raw"
SITE="$ROOT/site/screenshots"

[[ -d "$APP" ]] || { echo "screenshots: build the Debug app first" >&2; exit 1; }
command -v cwebp >/dev/null || { echo "screenshots: brew install webp" >&2; exit 1; }

command rm -rf "$CONTAINER_DIR"
osascript -e 'quit app "Wombat Debug"' >/dev/null 2>&1 || true
# Through LaunchServices, so the app may take focus: an inactive window renders gray traffic
# lights and gray switches. -W waits until the app quits when the captures are done.
# One launch per appearance: a fresh launch gets the focus; a second pass in the same launch
# often rendered inactive (gray traffic lights) while the Mac was in use.
for appearance in dark light; do
    open -W -n --env WOMBAT_DEMO=1 --env WOMBAT_CAPTURE=1 --env WOMBAT_CAPTURE_APPEARANCE=$appearance "$APP"
done

mkdir -p "$RAW" "$SITE"
shopt -s nullglob
shots=("$CONTAINER_DIR"/*.png)
(( ${#shots[@]} > 0 )) || { echo "screenshots: the app captured nothing" >&2; exit 1; }
for f in "${shots[@]}"; do
    name="$(basename "$f" .png)"
    command cp -f "$f" "$RAW/$name.png"
    tmp="$(mktemp "${TMPDIR:-/tmp}/wombat-shot.XXXXXX").png"
    command cp -f "$f" "$tmp"
    width="$(sips -g pixelWidth "$tmp" | awk '/pixelWidth/ {print $2}')"
    # Window shots are scaled to 1600 px wide; small ones (menu bar) keep their size.
    if (( width > 1600 )); then sips --resampleWidth 1600 "$tmp" >/dev/null; fi
    cwebp -quiet -q 84 -alpha_q 90 -m 6 "$tmp" -o "$SITE/$name.webp"
    command rm -f "$tmp"
    echo "  $name.webp"
done
