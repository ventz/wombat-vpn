#!/bin/bash
#
# Build a Developer ID signed, notarized Wombat.app: the only kind that can run tunnels.
#
# A Network Extension system extension needs the packet-tunnel-provider-systemextension
# entitlement, which only Developer ID provisioning profiles grant; a development-signed build
# installs, but macOS rejects its extension ("NetworkExtension key must be a non-empty
# dictionary"). So the app is archived with the development value and exported as Developer ID,
# which re-signs everything and rewrites the entitlement.
#
# Usage:
#   scripts/build-signed.sh             # build/signed/Wombat.app, notarized and stapled
#   scripts/build-signed.sh --install   # ...and replace /Applications/Wombat.app, then open it
#   scripts/build-signed.sh --no-notarize
#
# Requires Xcode signed in to the team (Settings › Accounts), the Developer ID Application
# certificate in the login keychain, and the notarytool profile (WOMBAT_NOTARY_PROFILE).

set -euo pipefail
trap 'echo "build-signed.sh: line $LINENO failed (exit $?): $BASH_COMMAND" >&2' ERR

readonly IDENTITY="${WOMBAT_SIGNING_IDENTITY:-Developer ID Application: Ventzislav Petkov (8J9W3ZG4ZN)}"
readonly NOTARY_PROFILE="${WOMBAT_NOTARY_PROFILE:-ventz-notary}"

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

install=0
notarize=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install) install=1; shift ;;
        --no-notarize) notarize=0; shift ;;
        -h|--help) sed -n '2,18p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

say() { printf '\n==> %s\n' "$*"; }

out="$repo_root/build/signed"
archive="$out/Wombat.xcarchive"
app="$out/export/Wombat.app"
developer_dir=$(xcode-select -p)

identities=$(security find-identity -v -p codesigning)
[[ "$identities" == *"$IDENTITY"* ]] || { echo "missing signing identity: $IDENTITY" >&2; exit 1; }

command rm -rf "$out"
mkdir -p "$out"

say "Archiving (Release, universal)"
xcodegen generate >/dev/null
# Output goes to a log: xcodebuild is very verbose and the errors are what matter.
if ! xcodebuild archive -project Wombat.xcodeproj -scheme Wombat -configuration Release \
        -destination "generic/platform=macOS" -derivedDataPath build/DerivedDataRelease \
        -archivePath "$archive" -allowProvisioningUpdates \
        NE_PACKET_TUNNEL=packet-tunnel-provider >"$out/archive.log" 2>&1; then
    grep -E ' error: |error: ' "$out/archive.log" >&2 || tail -20 "$out/archive.log" >&2
    echo "archive failed; full log: $out/archive.log" >&2
    echo "(\"Unable to log in with account\": sign out and back in under Xcode › Settings › Accounts)" >&2
    exit 1
fi

say "Exporting with Developer ID"
xcodebuild -exportArchive -archivePath "$archive" -exportPath "$out/export" \
    -exportOptionsPlist scripts/ExportOptions.plist -allowProvisioningUpdates >"$out/export.log" 2>&1 \
    || { tail -20 "$out/export.log" >&2; exit 1; }

say "Auditing signatures"
# Outputs are read into variables, never piped to grep -q: under pipefail an early grep exit
# kills the writer with SIGPIPE and a passing check fails at random (see Moo's release.sh).
# Two system extensions: WireGuard (.tunnel) and OpenConnect (.openconnect), each its own process.
extensions=()
while IFS= read -r ext; do extensions+=("$ext"); done < <(ls -d "$app/Contents/Library/SystemExtensions/"*.systemextension)
[[ ${#extensions[@]} -eq 2 ]] || { echo "expected 2 system extensions, found ${#extensions[@]}" >&2; exit 1; }
for code in "$app" "${extensions[@]}" "$app/Contents/Helpers/wombat"; do
    signature=$(codesign -dvv "$code" 2>&1)
    [[ "$signature" == *"Authority=Developer ID Application"* ]] \
        || { echo "not Developer ID signed: $code" >&2; exit 1; }
    [[ "$signature" == *"(runtime)"* ]] || { echo "hardened runtime is off: $code" >&2; exit 1; }
    entitlements=$(codesign -d --entitlements - --xml "$code" 2>/dev/null || true)
    [[ "$entitlements" != *get-task-allow* ]] || { echo "carries get-task-allow: $code" >&2; exit 1; }
    # Hardened-runtime exceptions (JIT, unsigned memory, library validation off, DYLD
    # variables) would undo what the runtime protects; nothing here needs them.
    [[ "$entitlements" != *com.apple.security.cs.* ]] || { echo "carries a hardened-runtime exception: $code" >&2; exit 1; }
done
for code in "$app" "${extensions[@]}"; do
    entitlements=$(codesign -d --entitlements - --xml "$code" 2>/dev/null)
    [[ "$entitlements" == *packet-tunnel-provider-systemextension* ]] \
        || { echo "missing packet-tunnel-provider-systemextension: $code" >&2; exit 1; }
done
# Sparkle's nested code (Autoupdate, Updater.app, its XPC services) must be Developer ID signed
# with the hardened runtime too: --deep --strict ignores a bare executable like Autoupdate, and
# notarization rejects it (Moo hit this).
nested=$(find "$app/Contents/Frameworks" -type f -perm +111 2>/dev/null || true)
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    description=$(file "$f")
    [[ "$description" == *Mach-O* ]] || continue
    signature=$(codesign -dvv "$f" 2>&1 || true)
    [[ "$signature" == *"Authority=Developer ID Application"* && "$signature" == *"(runtime)"* ]] \
        || { echo "nested code not Developer ID signed with the hardened runtime: $f" >&2; exit 1; }
done <<< "$nested"
codesign --verify --deep --strict "$app"
# Release builds authenticate each other with this requirement (Shared/CodeSigning.swift); if a
# binary didn't satisfy it, the app, extension and CLI would refuse to talk at run time.
readonly DEVELOPER_ID_REQ='anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
# The OpenConnect extension never starts processes: its libopenconnect calls stubs instead
# (scripts/build-openconnect.sh), so no exec-family symbol may be imported.
for ext in "${extensions[@]}"; do
    [[ "$ext" == *.openconnect.systemextension ]] || continue
    binary="$ext/Contents/MacOS/$(basename "$ext" .systemextension)"
    [[ -x "$binary" ]] || { echo "no OpenConnect extension binary at $binary" >&2; exit 1; }
    imports=$(nm -u "$binary")  # a failing nm fails the build, never an empty (passing) list
    # Sanity: the list is real only if it has imports the extension certainly uses.
    [[ "$imports" == *_SecTrustEvaluateWithError* && "$imports" == *_getaddrinfo* ]] \
        || { echo "unexpected import list for $binary" >&2; exit 1; }
    while IFS= read -r symbol; do
        case "$symbol" in
            _posix_spawn_file_actions_*|_posix_spawnattr_*) ;;  # building blocks only, harmless alone
            _fork|_fork\$*|_vfork*|_exec*|_posix_spawn*|_system|_system\$*|_popen*|*OBJC_CLASS_\$_NSTask*)
                echo "the OpenConnect extension imports $symbol: $binary" >&2; exit 1 ;;
        esac
    done <<< "$imports"
    # LGPL and OpenSSL license texts must ship with the library (Vendor/openconnect/WOMBAT.md), and
    # the library must be Wombat's patched build: these messages exist only in the patches
    # (scripts/patch-openconnect.py; quality-6 L11).
    for license in COPYING.LGPL LICENSE.openssl; do
        [[ -s "$ext/Contents/Resources/$license" ]] || { echo "missing $license in $ext" >&2; exit 1; }
    done
    marks=$(strings "$binary")
    for mark in "Gateway sent an invalid MTU" "Gateway sent too many headers" "Gateway chose a compression that wasn't requested"; do
        [[ "$marks" == *"$mark"* ]] || { echo "libopenconnect in $binary lacks the patch message: $mark" >&2; exit 1; }
    done
done
for code in "$app" "${extensions[@]}" "$app/Contents/Helpers/wombat"; do
    codesign --verify -R="$DEVELOPER_ID_REQ" "$code" || { echo "does not satisfy the Developer ID requirement: $code" >&2; exit 1; }
done
echo "app, both extensions and CLI: Developer ID, hardened runtime, no get-task-allow or runtime exceptions, NE entitlement for system extensions"

say "Checking bundle contents"
# XcodeGen copies every file in a source folder into the bundle, gitignored ones included, so a
# stray profile, key or CLAUDE.md would be signed and notarized in (review NEW-5). Only these
# files may ship; Sparkle.framework is SwiftPM's and is checked by its own signature above.
# Symlinks count too, and each extension's files are matched by exact path (a case pattern's
# `*` would also match "/").
contents=$(cd "$app" && find . \( -type f -o -type l \) -not -path './Contents/Frameworks/Sparkle.framework/*' | sed 's|^\./||')
[[ "$contents" == *Contents/MacOS/Wombat* ]] || { echo "no file list for $app" >&2; exit 1; }
allowed=$'Contents/Info.plist\nContents/PkgInfo\nContents/CodeResources\nContents/_CodeSignature/CodeResources\nContents/embedded.provisionprofile\nContents/MacOS/Wombat\nContents/Helpers/wombat\nContents/Resources/AppIcon.icns\nContents/Resources/MenuBarW.tiff\nContents/Resources/completions/_wombat\nContents/Resources/completions/wombat.bash\nContents/Resources/completions/wombat.fish'
for ext in "${extensions[@]}"; do
    name=$(basename "$ext")
    base="Contents/Library/SystemExtensions/$name/Contents"
    allowed+=$'\n'"$base/Info.plist"$'\n'"$base/embedded.provisionprofile"$'\n'"$base/_CodeSignature/CodeResources"$'\n'"$base/MacOS/${name%.systemextension}"
    if [[ "$name" == *.openconnect.systemextension ]]; then
        allowed+=$'\n'"$base/Resources/COPYING.LGPL"$'\n'"$base/Resources/LICENSE.openssl"
    fi
done
while IFS= read -r f; do
    found=0
    while IFS= read -r a; do [[ "$f" == "$a" ]] && { found=1; break; }; done <<< "$allowed"
    [[ $found -eq 1 ]] || { echo "unexpected file in the bundle (add it to this list only if it belongs): $f" >&2; exit 1; }
done <<< "$contents"
echo "bundle holds only the expected files"

if [[ $notarize -eq 1 ]]; then
    say "Notarizing (a few minutes at Apple)"
    ditto -c -k --keepParent "$app" "$out/Wombat.zip"
    # notarytool exits 0 even when the status is Invalid, so the status is checked.
    result=$("$developer_dir/usr/bin/notarytool" submit "$out/Wombat.zip" \
        --keychain-profile "$NOTARY_PROFILE" --wait --output-format json)
    status=$(printf '%s' "$result" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))')
    if [[ "$status" != "Accepted" ]]; then
        id=$(printf '%s' "$result" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')
        echo "notarization finished as '$status'" >&2
        "$developer_dir/usr/bin/notarytool" log "$id" --keychain-profile "$NOTARY_PROFILE" >&2 || true
        exit 1
    fi
    "$developer_dir/usr/bin/stapler" staple "$app"
    command rm -f "$out/Wombat.zip"
    spctl --assess --type execute -vv "$app"
fi

if [[ $install -eq 1 ]]; then
    say "Installing to /Applications"
    osascript -e 'quit app "Wombat"' >/dev/null 2>&1 || true
    command rm -rf /Applications/Wombat.app
    ditto "$app" /Applications/Wombat.app
    open /Applications/Wombat.app
fi

say "Built $app"
