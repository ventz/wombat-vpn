#!/bin/bash
#
# Cut a Wombat release: build (Developer ID, notarized, stapled), package a DMG, notarize it,
# publish the signed Sparkle appcast so installed copies update themselves, refresh the stable
# /Wombat.dmg download, and (when origin is on GitHub) create the GitHub release.
#
# Usage:
#   scripts/release.sh                     # version from project.yml
#   scripts/release.sh --notes notes.html  # release notes shown in the updater (HTML only)
#   scripts/release.sh --dry-run           # build and package, publish nothing
#
# Requires, one time each (see docs/DEVELOPING.md):
#   - Xcode signed in to the team, the Developer ID Application certificate (scripts/build-signed.sh)
#   - the notarytool profile (WOMBAT_NOTARY_PROFILE, default moo-notary)
#   - Wombat's Sparkle EdDSA key in the login keychain, account "wombat"
#     (generate_keys --account wombat); never Moo's or Tardy's
#   - ~/.config/cloudflare/.env with CLOUDFLARE_ADMIN_TOKEN (loaded only for wrangler)
#   - a logged-in gh, when origin is a GitHub repository
#
# Adapted from Moo's release.sh; its guards (signed-feed checks, never overwriting a published
# archive, cache-busting before first publish) are kept with their reasons.

set -euo pipefail
trap 'echo "release.sh: line $LINENO failed (exit $?): $BASH_COMMAND" >&2' ERR

readonly IDENTITY="${WOMBAT_SIGNING_IDENTITY:-Developer ID Application: Ventzislav Petkov (8J9W3ZG4ZN)}"
readonly NOTARY_PROFILE="${WOMBAT_NOTARY_PROFILE:-moo-notary}"
readonly BUCKET="${WOMBAT_BUCKET:-wombat-mac-wireguard-autoupdate}"
readonly FEED_HOST="${WOMBAT_FEED_HOST:-https://wombat.vpetkov.net}"
readonly SPARKLE_ACCOUNT="wombat"
readonly WRANGLER_VERSION="${WOMBAT_WRANGLER_VERSION:-4.133.0}"
readonly CF_ENV="${WOMBAT_CLOUDFLARE_ENV:-$HOME/.config/cloudflare/.env}"

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

# Past archives live outside the repo: generate_appcast needs earlier releases on hand to keep
# their entries in the feed, and they are large.
release_dir="${WOMBAT_RELEASE_DIR:-$HOME/wombat-releases}"
notes_file=""
dry_run=0
# generate_appcast lists every archive in the release directory, so a dry run's unsigned DMG
# must never land there (quality-3): dry runs package into the build folder instead.

while [[ $# -gt 0 ]]; do
    case "$1" in
        --notes) [[ $# -ge 2 ]] || { echo "--notes needs an .html file" >&2; exit 2; }
                 notes_file="$2"; shift 2 ;;
        --dry-run) dry_run=1; shift ;;
        -h|--help) sed -n '2,22p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

say() { printf '\n==> %s\n' "$*"; }

# The highest <sparkle:version> in a feed's text, or nothing. `sort -n` reads all its input
# before `tail` sees any, so no reader exits early under pipefail; `|| true` covers a feed with
# no versions.
highest_build_in() {
    printf '%s' "$1" | grep -oE '<sparkle:version>[0-9]+' | grep -oE '[0-9]+' | sort -n | tail -1 || true
}

# A URL not published yet must never be requested plainly: Cloudflare caches the 404 for hours
# and the release then serves it (Moo 0.1.7). A unique query string gets its own cache entry.
fresh() { printf '%s?cb=%s' "$1" "$(date +%s)"; }

# Pinned, npm install scripts off, and only the token reaches it: this runs on the machine holding
# the Developer ID key, the notary profile and the Sparkle key.
wrangler() {
    (
        set -a
        # shellcheck disable=SC1090
        source "$CF_ENV"
        set +a
        env -i HOME="$HOME" PATH="$PATH" TMPDIR="${TMPDIR:-/tmp}" \
            CLOUDFLARE_API_TOKEN="$CLOUDFLARE_ADMIN_TOKEN" ${CLOUDFLARE_ACCOUNT_ID:+CLOUDFLARE_ACCOUNT_ID="$CLOUDFLARE_ACCOUNT_ID"} \
            CI=1 WRANGLER_SEND_METRICS=false npm_config_ignore_scripts=true \
            npx --yes "wrangler@$WRANGLER_VERSION" "$@"
    )
}

# --- Preflight ----------------------------------------------------------------------------------
# Every check here fails a release long before notarizing would.

say "Checking prerequisites"

# generate_appcast embeds HTML notes in the feed but only *links* any other format, and only the
# DMG and the feed are uploaded: Markdown notes would ship a feed whose notes link 404s (Moo 0.1.3).
if [[ -n "$notes_file" ]]; then
    [[ -f "$notes_file" ]] || { echo "notes file not found: $notes_file" >&2; exit 1; }
    case "${notes_file##*.}" in
        html|htm) ;;
        *) echo "notes must be .html so they are embedded in the feed, not linked: $notes_file" >&2; exit 1 ;;
    esac
fi

identities=$(security find-identity -v -p codesigning)
[[ "$identities" == *"$IDENTITY"* ]] || { echo "missing signing identity: $IDENTITY" >&2; exit 1; }

# Real paths, not xcrun: xcrun refuses to run until the Xcode license is accepted, which would
# only show up at the very last step.
developer_dir=$(xcode-select -p)
notarytool="$developer_dir/usr/bin/notarytool"
stapler="$developer_dir/usr/bin/stapler"
for tool in "$notarytool" "$stapler"; do
    [[ -x "$tool" ]] || { echo "not found: $tool" >&2; exit 1; }
done
"$notarytool" history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1 \
    || { echo "notarytool profile '$NOTARY_PROFILE' is missing or invalid" >&2; exit 1; }

sparkle_bin="$repo_root/build/DerivedDataRelease/SourcePackages/artifacts/sparkle/Sparkle/bin"
if [[ ! -x "$sparkle_bin/generate_appcast" ]]; then
    say "Resolving package dependencies (Sparkle tools not unpacked yet)"
    xcodegen generate >/dev/null
    xcodebuild -resolvePackageDependencies -project Wombat.xcodeproj -scheme Wombat \
        -derivedDataPath build/DerivedDataRelease >/dev/null
fi
[[ -x "$sparkle_bin/generate_appcast" ]] || { echo "generate_appcast not found under $sparkle_bin" >&2; exit 1; }

if [[ $dry_run -eq 0 ]]; then
    [[ -f "$CF_ENV" ]] || { echo "$CF_ENV not found (CLOUDFLARE_ADMIN_TOKEN)" >&2; exit 1; }
    wrangler whoami >/dev/null 2>&1 || { echo "wrangler can't authenticate with the token in $CF_ENV" >&2; exit 1; }
fi

# A release is built from a commit, so it can be traced and tagged: a real one needs a repository
# with a commit and a clean tree. Untracked files count too: XcodeGen compiles every source file
# it finds, committed or not (quality-3). No GitHub remote: the GitHub release is skipped.
build_commit=""
github_repo=""
if [[ $dry_run -eq 0 ]]; then
    build_commit=$(git rev-parse --verify --quiet HEAD 2>/dev/null || true)
    [[ -n "$build_commit" ]] || { echo "no commit to release from -- commit first" >&2; exit 1; }
    changes=$(git status --porcelain)
    [[ -z "$changes" ]] || { echo "uncommitted or untracked changes -- commit them so the release matches its commit:" >&2; echo "$changes" >&2; exit 1; }
    origin_url=$(git remote get-url origin 2>/dev/null || true)
    if [[ "$origin_url" == *github.com* ]]; then
        gh auth status >/dev/null 2>&1 || { echo "gh is not logged in -- run: gh auth login" >&2; exit 1; }
        github_repo=$(gh repo view "$origin_url" --json nameWithOwner --jq .nameWithOwner)
        git fetch --quiet origin
        pushed=$(git branch -r --contains "$build_commit")
        [[ -n "$pushed" ]] || { echo "$build_commit is not on origin -- push it before releasing" >&2; exit 1; }
    fi
fi

# --- Build --------------------------------------------------------------------------------------
# build-signed.sh archives, exports with Developer ID (which signs the nested Sparkle code and
# grants the system-extension entitlement), audits every signature, notarizes and staples the app.

say "Building (Developer ID, notarized)"
scripts/build-signed.sh
app="$repo_root/build/signed/export/Wombat.app"
[[ -d "$app" ]] || { echo "build produced no app at $app" >&2; exit 1; }

version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$app/Contents/Info.plist")
build_number=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$app/Contents/Info.plist")

if [[ -n "$github_repo" ]]; then
    existing=$(git ls-remote --tags origin "refs/tags/v$version")
    [[ -z "$existing" ]] || { echo "v$version is already tagged on origin -- bump MARKETING_VERSION" >&2; exit 1; }
fi
# Sparkle orders updates by CFBundleVersion: a release that bumps only the marketing version is
# never offered to anyone.
published_feed=$(curl -fsS "$(fresh "$FEED_HOST/appcast.xml")" 2>/dev/null || true)
highest_build=$(highest_build_in "$published_feed")
if [[ -n "$highest_build" ]] && (( build_number <= highest_build )); then
    echo "build $build_number is not above the published build $highest_build -- bump CURRENT_PROJECT_VERSION" >&2
    exit 1
fi

say "Version $version (build $build_number), architectures: $(lipo -archs "$app/Contents/MacOS/Wombat")"

# Installed copies verify with the SUPublicEDKey built into them; sign_update --verify uses the
# keychain's key, so it can't catch the two differing. Compared now, before notarizing the DMG.
plist_key=$(/usr/libexec/PlistBuddy -c "Print :SUPublicEDKey" "$app/Contents/Info.plist" 2>/dev/null || true)
keychain_key=$("$sparkle_bin/generate_keys" --account "$SPARKLE_ACCOUNT" -p 2>/dev/null || true)
keychain_key=${keychain_key//[[:space:]]/}
if [[ -z "$plist_key" || -z "$keychain_key" || "$plist_key" != "$keychain_key" ]]; then
    echo "the Sparkle key in the keychain (account $SPARKLE_ACCOUNT) does not match SUPublicEDKey --" \
        "updates signed with it would be refused by every installed copy" >&2
    echo "  app:      ${plist_key:-<none>}" >&2
    echo "  keychain: ${keychain_key:-<none>}" >&2
    exit 1
fi

# --- Package ------------------------------------------------------------------------------------

[[ $dry_run -eq 1 ]] && release_dir="$repo_root/build/release-dry-run"
mkdir -p "$release_dir"
dmg="$release_dir/Wombat-$version.dmg"

say "Building $dmg"
command rm -f "$dmg"
scripts/create-dmg.sh "$app" "$dmg" "Wombat"

if [[ -n "$notes_file" ]]; then
    # generate_appcast attaches notes whose name matches the archive.
    notes_dest="$release_dir/Wombat-$version.${notes_file##*.}"
    [[ "$notes_file" -ef "$notes_dest" ]] || command cp -f "$notes_file" "$notes_dest"
fi

if [[ $dry_run -eq 1 ]]; then
    say "Dry run -- skipping DMG notarization and publish"
    echo "built: $dmg"
    exit 0
fi

# The image needs its own signature: notarizing and stapling an unsigned one both succeed, and
# only spctl then rejects it, which reads like a problem with the app inside.
say "Signing and notarizing the disk image"
codesign --force --sign "$IDENTITY" --timestamp "$dmg"
"$notarytool" submit "$dmg" --keychain-profile "$NOTARY_PROFILE" --wait
"$stapler" staple "$dmg"
spctl --assess --type open --context context:primary-signature -vv "$dmg"

# --- Appcast ------------------------------------------------------------------------------------
# Start from the published feed so earlier releases keep their entries. generate_appcast re-signs
# whatever it is given, so a tampered live feed would come back validly signed: it must verify
# first. A 404 means there is no feed yet; anything else stops.

say "Generating appcast"
remote_dir=$(mktemp -d "${TMPDIR:-/tmp}/wombat-remote-feed.XXXXXX")
remote_feed="$remote_dir/appcast.xml"
feed_status=$(curl -s -o "$remote_feed" -w '%{http_code}' "$(fresh "$FEED_HOST/appcast.xml")" || true)
case "$feed_status" in
    200)
        "$sparkle_bin/sign_update" --account "$SPARKLE_ACCOUNT" --verify "$remote_feed" \
            || { echo "the published feed's signature does not verify -- not building on it" >&2; exit 1; }
        command mv -f "$remote_feed" "$release_dir/appcast.xml" ;;
    404) ;;
    *) echo "could not download the published feed (HTTP $feed_status) -- not building on a local copy" >&2; exit 1 ;;
esac
command rm -rf "$remote_dir"

"$sparkle_bin/generate_appcast" --account "$SPARKLE_ACCOUNT" \
    --download-url-prefix "$FEED_HOST/" \
    --maximum-versions 5 \
    "$release_dir"

feed=$(cat "$release_dir/appcast.xml")
if [[ "$feed" == *"<sparkle:releaseNotesLink>"* ]]; then
    echo "the generated feed links release notes that are never uploaded -- write them as .html" >&2
    exit 1
fi
# The app sets SURequireSignedFeed: an unsigned or edited feed strands every copy.
[[ "$feed" == *"sparkle-signatures:"* ]] || { echo "generate_appcast did not sign the feed -- not publishing" >&2; exit 1; }
"$sparkle_bin/sign_update" --account "$SPARKLE_ACCOUNT" --verify "$release_dir/appcast.xml" \
    || { echo "the feed's signature does not verify -- not publishing" >&2; exit 1; }
[[ "$feed" == *"<sparkle:version>$build_number</sparkle:version>"* ]] \
    || { echo "the generated feed does not list build $build_number -- not publishing" >&2; exit 1; }

# Every file the feed points at (the DMG, delta updates) must be on the host before the feed is,
# or the updater follows a link to a 404 (Moo shipped three releases of 404 deltas that way).
feed_files=()
while IFS= read -r name; do
    [[ -z "$name" || "$name" == "appcast.xml" ]] && continue
    feed_files+=("$name")
done < <(grep -oE "${FEED_HOST//./\\.}/[A-Za-z0-9._-]+" "$release_dir/appcast.xml" | sed "s|^$FEED_HOST/||" | sort -u)
for name in ${feed_files[@]+"${feed_files[@]}"}; do
    [[ -f "$release_dir/$name" ]] || { echo "the feed references $name, which is not in $release_dir" >&2; exit 1; }
done

# --- Publish ------------------------------------------------------------------------------------

say "Publishing to R2 ($BUCKET)"

# The versioned DMG is what the feed points at and must never be overwritten: Sparkle checks the
# signature recorded for that exact file, and R2 replaces objects without a word. One already
# there (a re-run) is left alone only if it is byte for byte this file.
dmg_name=$(basename "$dmg")
dmg_status=$(curl -s -o /dev/null -I -w '%{http_code}' "$(fresh "$FEED_HOST/$dmg_name")" || true)
case "$dmg_status" in
    404)
        wrangler r2 object put "$BUCKET/$dmg_name" --file "$dmg" --content-type application/x-apple-diskimage --remote ;;
    200)
        published_dir=$(mktemp -d "${TMPDIR:-/tmp}/wombat-published-dmg.XXXXXX")
        curl -fsS -o "$published_dir/$dmg_name" "$(fresh "$FEED_HOST/$dmg_name")"
        published_sum=$(shasum -a 256 "$published_dir/$dmg_name")
        local_sum=$(shasum -a 256 "$dmg")
        command rm -rf "$published_dir"
        [[ "${published_sum%% *}" == "${local_sum%% *}" ]] \
            || { echo "$FEED_HOST/$dmg_name is already published with different contents -- refusing to overwrite it" >&2; exit 1; }
        echo "$dmg_name is already published, byte for byte -- not uploading it again" ;;
    *) echo "could not tell whether $dmg_name is already published (HTTP $dmg_status)" >&2; exit 1 ;;
esac

# Everything else the feed references (deltas). Status compared explicitly: with -I, curl --fail
# doesn't turn a 404 into a failing exit.
for name in ${feed_files[@]+"${feed_files[@]}"}; do
    [[ "$name" == "$dmg_name" ]] && continue
    http_status=$(curl -s -o /dev/null -I -w '%{http_code}' "$(fresh "$FEED_HOST/$name")" || true)
    [[ "$http_status" == "200" ]] && continue
    wrangler r2 object put "$BUCKET/$name" --file "$release_dir/$name" --content-type application/octet-stream --remote
done

# The feed goes after everything it references.
wrangler r2 object put "$BUCKET/appcast.xml" --file "$release_dir/appcast.xml" \
    --content-type application/xml --cache-control "max-age=300" --remote

say "Verifying the published feed"
live_dir=$(mktemp -d "${TMPDIR:-/tmp}/wombat-live-feed.XXXXXX")
curl -fsS -o "$live_dir/appcast.xml" "$(fresh "$FEED_HOST/appcast.xml")" \
    || { echo "could not download the feed just published -- CHECK $FEED_HOST/appcast.xml NOW" >&2; exit 1; }
"$sparkle_bin/sign_update" --account "$SPARKLE_ACCOUNT" --verify "$live_dir/appcast.xml" \
    || { echo "THE PUBLISHED FEED DOES NOT VERIFY -- republish $release_dir/appcast.xml" >&2; exit 1; }
live_feed=$(cat "$live_dir/appcast.xml")
command rm -rf "$live_dir"
[[ "$live_feed" == *"<sparkle:version>$build_number</sparkle:version>"* ]] \
    || { echo "the published feed does not list build $build_number -- check $FEED_HOST/appcast.xml" >&2; exit 1; }

# Wombat.dmg: a copy of the newest release for the website's Download button and links that don't
# go stale. Nothing in the update path reads it; it goes last so it is never newer than the feed.
wrangler r2 object put "$BUCKET/Wombat.dmg" --file "$dmg" --content-type application/x-apple-diskimage \
    --cache-control "max-age=300" --remote

say "Published"
echo "  download: $FEED_HOST/Wombat.dmg   (always the newest release)"
echo "  this one: $FEED_HOST/$dmg_name"
echo "  appcast:  $FEED_HOST/appcast.xml"
echo "  local:    $dmg"

# --- GitHub release -----------------------------------------------------------------------------

if [[ -z "$github_repo" ]]; then
    say "No GitHub remote -- skipping the GitHub release"
    exit 0
fi

tag="v$version"
say "Creating GitHub release $tag ($github_repo)"
checksum=$(shasum -a 256 "$dmg")
checksum=${checksum%% *}
github_notes=$(mktemp "${TMPDIR:-/tmp}/wombat-github-notes.XXXXXX")
{
    if [[ -n "$notes_file" ]]; then cat "$notes_file"; printf '\n'; fi
    cat <<NOTES
## Install

Download **$dmg_name** below, open it, and drag Wombat to Applications (network extensions only
run from there). On first launch, allow the extension in System Settings › General › Login Items
& Extensions. It is signed with a Developer ID, notarized by Apple, and updates itself.

## Verify

\`\`\`
spctl --assess --type open --context context:primary-signature -vv $dmg_name
shasum -a 256 $dmg_name
# $checksum
\`\`\`
NOTES
} > "$github_notes"

gh release create "$tag" "$dmg" --repo "$github_repo" --target "$build_commit" \
    --title "Wombat $version" --notes-file "$github_notes" --latest
command rm -f "$github_notes"
echo "  github:   https://github.com/$github_repo/releases/tag/$tag"
