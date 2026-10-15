#!/usr/bin/env bash
# Publishes the landing page at https://wombat.vpetkov.net to the R2 bucket that also serves
# releases and the Sparkle appcast. Separate from releases on purpose: editing copy shouldn't need
# a build, and a build shouldn't silently republish the site.
#
# Credentials: the account admin token in ~/.config/cloudflare/.env (CLOUDFLARE_ADMIN_TOKEN),
# loaded only for wrangler's environment, never exported to the shell.
set -euo pipefail
trap 'echo "publish-site: line $LINENO failed (exit $?): $BASH_COMMAND" >&2' ERR

readonly BUCKET="${WOMBAT_BUCKET:-wombat-mac-wireguard-autoupdate}"
readonly SITE_HOST="${WOMBAT_FEED_HOST:-https://wombat.vpetkov.net}"
readonly WRANGLER_VERSION="${WOMBAT_WRANGLER_VERSION:-4.133.0}"
readonly CF_ENV="${WOMBAT_CLOUDFLARE_ENV:-$HOME/.config/cloudflare/.env}"

cd "$(dirname "$0")/.."
[[ -f "$CF_ENV" ]] || { echo "publish-site: $CF_ENV not found" >&2; exit 1; }

# Pinned, npm install scripts off: this runs on the machine holding the signing keys.
wrangler() {
    (
        set -a
        # shellcheck disable=SC1090
        source "$CF_ENV"
        set +a
        # Only what wrangler needs reaches it, not the rest of the .env (R2 keys and the like;
        # audit S2-L6).
        env -i HOME="$HOME" PATH="$PATH" TMPDIR="${TMPDIR:-/tmp}" \
            CLOUDFLARE_API_TOKEN="$CLOUDFLARE_ADMIN_TOKEN" ${CLOUDFLARE_ACCOUNT_ID:+CLOUDFLARE_ACCOUNT_ID="$CLOUDFLARE_ACCOUNT_ID"} \
            CI=1 WRANGLER_SEND_METRICS=false npm_config_ignore_scripts=true \
            npx --yes "wrangler@$WRANGLER_VERSION" "$@"
    )
}

put() { # put <key> <file> <content-type> <cache-control>; content types without charset (wrangler hangs)
    wrangler r2 object put "$BUCKET/$1" --file "$2" --content-type "$3" --cache-control "$4" --remote >/dev/null
    echo "  $1"
}

echo "==> Publishing site to $BUCKET"
put index.html site/index.html text/html "max-age=300"
put icon.png docs/images/icon.png image/png "max-age=86400"
put og.png site/og.png image/png "max-age=86400"   # link-preview card (scripts/make-og-image.py)
if [[ -d site/screenshots ]]; then
    for f in site/screenshots/*.webp site/screenshots/*.png; do
        [[ -f "$f" ]] || continue
        case "$f" in *.webp) type=image/webp ;; *) type=image/png ;; esac
        put "screenshots/$(basename "$f")" "$f" "$type" "max-age=86400"
    done
fi

echo "==> Published to $SITE_HOST (index.html max-age 5 min; the root is served by the zone rule \"Wombat site: serve index.html at the root\")"
