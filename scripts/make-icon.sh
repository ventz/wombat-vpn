#!/bin/bash
#
# Build Resources/AppIcon.icns and docs/images/icon.png from a square
# source PNG (1024 px or larger, transparent outside a rounded tile).
#
# Usage: scripts/make-icon.sh path/to/icon.png

set -euo pipefail

[[ $# -eq 1 && -f "$1" ]] || { echo "Usage: $0 SOURCE.png" >&2; exit 64; }

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/icon.XXXXXX")
trap 'command rm -rf "$work"' EXIT

# Clip onto Apple's exact tile shape; macOS 26 jails anything else on a gray plate
"$repo_root/scripts/compose-icon.py" "$1" "$work/icon-1024.png"

iconset="$work/AppIcon.iconset"
mkdir -p "$iconset"
for size in 16 32 128 256 512; do
    sips -z $size $size "$work/icon-1024.png" --out "$iconset/icon_${size}x${size}.png" >/dev/null
    double=$((size * 2))
    sips -z $double $double "$work/icon-1024.png" --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$repo_root/Resources/AppIcon.icns"

# README and website image, lossless. 448 px keeps it under ~200 KB (512 px is
# ~240 KB; palette quantizing gets smaller but bands the tile's gradient)
mkdir -p "$repo_root/docs/images"
sips -z 448 448 "$work/icon-1024.png" --out "$repo_root/docs/images/icon.png" >/dev/null

echo "wrote Resources/AppIcon.icns and docs/images/icon.png"
