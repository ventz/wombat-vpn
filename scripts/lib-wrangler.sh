# Sourced by release.sh and publish-site.sh. Needs CF_ENV set.
#
# wrangler comes from scripts/tools: an exact version with a committed lockfile (every package's
# integrity hash), installed by `npm ci` with install scripts off into build/tools. `npx
# wrangler@x` resolved wrangler's own dependencies fresh on every release, on the machine holding
# the Developer ID key, the notary profile and the Sparkle key (review SEC-8).
#
# Token: WOMBAT_R2_TOKEN from the .env when it's set (a token limited to the R2 bucket, made in
# the dashboard), else the account admin token. Only that token reaches wrangler.

wombat_tools_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

wrangler_install() {
    local src="$wombat_tools_root/scripts/tools" dst="$wombat_tools_root/build/tools"
    mkdir -p "$dst"
    if ! cmp -s "$src/package-lock.json" "$dst/package-lock.json" || [[ ! -x "$dst/node_modules/.bin/wrangler" ]]; then
        command cp -f "$src/package.json" "$src/package-lock.json" "$dst/"
        (cd "$dst" && env -i HOME="$HOME" PATH="$PATH" TMPDIR="${TMPDIR:-/tmp}" \
            npm ci --ignore-scripts --no-audit --no-fund --loglevel=error >/dev/null) \
            || { echo "wrangler: npm ci failed in $dst" >&2; return 1; }
    fi
}

wrangler() {
    wrangler_install || return 1
    (
        set -a
        # shellcheck disable=SC1090
        source "$CF_ENV"
        set +a
        # Only what wrangler needs reaches it, not the rest of the .env (audit S2-L6).
        env -i HOME="$HOME" PATH="$PATH" TMPDIR="${TMPDIR:-/tmp}" \
            CLOUDFLARE_API_TOKEN="${WOMBAT_R2_TOKEN:-$CLOUDFLARE_ADMIN_TOKEN}" \
            ${CLOUDFLARE_ACCOUNT_ID:+CLOUDFLARE_ACCOUNT_ID="$CLOUDFLARE_ACCOUNT_ID"} \
            CI=1 WRANGLER_SEND_METRICS=false npm_config_ignore_scripts=true \
            "$wombat_tools_root/build/tools/node_modules/.bin/wrangler" "$@"
    )
}
