#!/bin/bash

# Builds a drag-to-install DMG: the app on the left, an Applications alias on
# the right, an arrow between them on a background image that says what to do.

set -euo pipefail
trap 'echo "create-dmg.sh: line $LINENO failed (exit $?): $BASH_COMMAND" >&2' ERR

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "Usage: $0 APP_PATH OUTPUT_DMG [VOLUME_NAME]" >&2
    exit 64
fi

app_path="$1"
output_path="$2"
volume_name="${3:-Wombat}"
script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
background_source="$script_directory/dmg/background.tiff"

if [[ ! -d "$app_path" || "$app_path" != *.app ]]; then
    echo "The app path is not an application bundle: $app_path" >&2
    exit 66
fi

if [[ "$output_path" != *.dmg ]]; then
    echo "The output path must end in .dmg: $output_path" >&2
    exit 64
fi

# Build under a unique volume name and rename it at the end. With the final name,
# any open copy of an earlier image (someone installing a previous build) pushed
# this one onto a "Wombat 1" mount while Finder laid out the wrong window -- a
# release failed that way.
build_volume="$volume_name-build-$$"

app_name="$(basename "$app_path")"
output_directory="$(dirname "$output_path")"
mkdir -p "$output_directory"
output_directory="$(cd "$output_directory" && pwd)"
output_path="$output_directory/$(basename "$output_path")"

staging_directory="$(mktemp -d "$output_directory/wombat-dmg.XXXXXX")"
temp_dmg="$staging_directory/rw.dmg"
device=""
cleanup() {
    if [[ -n "$device" ]]; then
        hdiutil detach "$device" -quiet -force 2>/dev/null || true
    fi
    rm -rf "$staging_directory"
}
trap cleanup EXIT

payload="$staging_directory/payload"
mkdir -p "$payload"
ditto "$app_path" "$payload/$app_name"

has_background=0
if [[ -f "$background_source" ]]; then
    mkdir -p "$payload/.background"
    cp "$background_source" "$payload/.background/background.tiff"
    has_background=1
fi

# A read/write image first, so the Finder window layout can be set and saved
# into the volume's .DS_Store, then converted to the image that ships.
size_kb=$(du -sk "$payload" | awk '{print $1}')
hdiutil create -srcfolder "$payload" -volname "$build_volume" \
    -fs HFS+ -format UDRW -size $((size_kb + 65536))k -quiet "$temp_dmg"

# The attach output is captured whole and parsed afterwards. Piping it into
# an awk that exits on the first match kills hdiutil with SIGPIPE while it is
# still writing, and under `set -o pipefail` that failure propagates out of
# the command substitution and ends the script with no message at all. It is a
# race, so it looked like the DMG step failing at random.
attach_output=$(hdiutil attach "$temp_dmg" -readwrite -noverify -noautoopen)
# awk keeps only the first match itself: piping into `head -1` let head exit
# early, awk die of SIGPIPE and pipefail end the script silently -- at random,
# since hdiutil prints several /dev/disk lines (it failed a real release run).
device=$(printf '%s\n' "$attach_output" | awk '/^\/dev\/disk/ && !found {print $1; found = 1}')
[[ -n "$device" ]] || {
    echo "hdiutil attach returned no device:" >&2
    printf '%s\n' "$attach_output" >&2
    exit 70
}
mount_point="/Volumes/$build_volume"

# Attach returns before the volume is necessarily in /Volumes.
for _ in $(seq 1 50); do
    [[ -d "$mount_point" ]] && break
    sleep 0.2
done
[[ -d "$mount_point" ]] || { echo "volume never appeared at $mount_point" >&2; exit 70; }

# The Applications alias is made inside the mounted volume rather than in the
# source folder. Both produce a working drag-to-install link, but creating it
# here lets the Finder index it and cache its folder icon into the volume's
# .DS_Store; made beforehand it renders as an empty dashed placeholder.
ln -s /Applications "$mount_point/Applications"

# The Finder needs a moment after attach before it accepts scripting.
sleep 2

background_clause=""
if [[ $has_background -eq 1 ]]; then
    background_clause="set background picture of theViewOptions to file \".background:background.tiff\""
fi

osascript <<APPLESCRIPT || echo "note: could not set the window layout; the DMG is still valid" >&2
tell application "Finder"
    tell disk "$build_volume"
        open
        set current view of container window to icon view
        set toolbar visible of container window to false
        set statusbar visible of container window to false
        set the bounds of container window to {200, 120, 860, 568}
        set theViewOptions to the icon view options of container window
        set arrangement of theViewOptions to not arranged
        set icon size of theViewOptions to 160
        set text size of theViewOptions to 14
        $background_clause
        set position of item "$app_name" of container window to {170, 190}
        set position of item "Applications" of container window to {490, 190}
        close
        open
        update without registering applications
        delay 2
        close
    end tell
end tell
APPLESCRIPT

sync
diskutil rename "$mount_point" "$volume_name" >/dev/null

# Finder can hold the volume for a moment after closing its window
for attempt in 1 2 3 4 5; do
    if hdiutil detach "$device" -quiet; then
        device=""
        break
    fi
    sleep 2
done
[[ -z "$device" ]] || hdiutil detach "$device" -force -quiet
device=""

hdiutil convert "$temp_dmg" -format UDZO -imagekey zlib-level=9 -ov -quiet -o "$output_path"
echo "created: $output_path"
