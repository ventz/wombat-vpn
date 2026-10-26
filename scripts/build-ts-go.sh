#!/usr/bin/env bash
# Builds build/ts-go/libts-go.a (universal) from Vendor/tailscale-bridge: the tailnet engine for
# the Wombat Tailnet system extension, against the patched Go runtime (lib-go-runtime.sh).
#
# Tailscale's optional features are compiled out by ts_omit_* tags (design: build/audits/
# spike-tailscale-design.md 2.1). Go ignores a tag it doesn't know, so a renamed feature would
# silently come back: every tag is checked against tailscale.com's feature/buildfeatures first.
set -euo pipefail
# The gates below use bracket ranges; their meaning must not depend on the locale (security-8 L4).
export LC_ALL=C
trap 'echo "build-ts-go: line $LINENO failed (exit $?): $BASH_COMMAND" >&2' ERR

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/scripts/lib-go-runtime.sh"
SRC="$ROOT/Vendor/tailscale-bridge"
OUT="$ROOT/build/ts-go"
WORK="$OUT/work"
ARCHS="${ARCHS:-arm64 x86_64}"
MACOS_MIN="${MACOSX_DEPLOYMENT_TARGET:-14.0}"
STAMP="$OUT/.stamp"

# Compiled out: anything that runs programs, listens, uploads, takes remote orders, or turns this
# Mac into a router. Kept: dns, netstack, gro, nattraversal, udptransport, health, bakedroots,
# tailnetlock, ipnbus.
OMIT=(
    ssh taildrop serve webclient drive aws kube cloud relayserver tap
    c2n clientupdate remoteconfig syspolicy posture portlist capture netlog logtail captiveportal
    debug debugeventbus connreject routecheck
    advertiseexitnode advertiseroutes bird appconnectors useexitnode useroutes peerapiclient
    peerapiserver outboundproxy useproxy acme webbrowser wakeonlan favorites conn25 ace
    identityfederation oauthkey serviceclientprefs doctor qrcodes flashappliance hujsonconf
    completion completion_scripts desktop_sessions colorable cliconndiag unixsocketidentity
    osrouter cachenetmap dnsresolvecache portmapper debugportmapper
    iptables dbus networkmanager resolved linuxdnsfight linkspeed tundevstats sdnotify syslog
    synology systray androidbin androiddns listenrawdisco tpm runtimemetrics usermetrics
    clientmetrics
)

go_runtime_prepare build-ts-go "$ROOT/build/go-runtime"
export CGO_ENABLED=1 GOOS=darwin GOFLAGS=-mod=readonly GOTOOLCHAIN=local

TS_DIR="$(cd "$SRC" && go list -m -f '{{.Dir}}' tailscale.com)"
TS_VERSION="$(cd "$SRC" && go list -m -f '{{.Version}}' tailscale.com)"
TS_VERSION="${TS_VERSION#v}"
# build-signed.sh finds a linked logtail by this text; a Tailscale upgrade that renames it would
# silently disable that check (security-8 L5).
logtail_marker="$(cat "$TS_DIR"/logtail/*.go)"
[[ "$logtail_marker" == *TS_DEBUG_LOGTAIL_FLUSHDELAY* ]] \
    || { echo "build-ts-go: logtail's TS_DEBUG_LOGTAIL_FLUSHDELAY moved; update the check in build-signed.sh" >&2; exit 1; }
tags="ts_macext"
for feature in "${OMIT[@]}"; do
    [[ -f "$TS_DIR/feature/buildfeatures/feature_${feature}_disabled.go" ]] \
        || { echo "build-ts-go: tailscale.com $TS_VERSION has no omittable feature '$feature'" >&2; exit 1; }
    tags+=",ts_omit_$feature"
done
# The probe's plain-http loopback allowance must never reach the extension.
[[ "$tags" != *wombat_devprobe* ]] || { echo "build-ts-go: wombat_devprobe is for ts-probe only" >&2; exit 1; }

inputs_hash() {
    { echo "$GO_VERSION $ARCHS $MACOS_MIN $tags"; cat "$0" "$ROOT/scripts/lib-go-runtime.sh" "$SRC/go.mod" "$SRC/go.sum"
      find "$SRC" -type f -name '*.go' ! -name '*_test.go' | LC_ALL=C sort | xargs cat; } \
        | shasum -a 256 | cut -d' ' -f1
}
HASH="$(inputs_hash)"
if [[ -f "$OUT/libts-go.a" && -f "$STAMP" && "$(cat "$STAMP")" == "$HASH" ]]; then
    echo "build-ts-go: up to date"
    exit 0
fi

# Checked patches to Tailscale's control client. Go refuses build overlays of module-cache files,
# so the build runs from a work copy of the bridge with its dependencies vendored (from the
# go.sum-verified module cache; nothing is downloaded) and the vendored file patched. Each substitution must match exactly once, or the build stops: an
# upgrade that moves the code needs the patch re-checked, like lib-go-runtime.sh's.
#  1. A coordination server's PingRequest is answered only over the Noise connection to that
#     server. Upstream sends a HEAD, or a POST of the result, to any URL with a plain HTTP
#     client: blind requests from root to this Mac's loopback and LAN (security-9 M2).
#  2. A server's Debug.Exit is ignored: upstream calls os.Exit, ending the one extension
#     process that serves every tunnel (security-9 L1; constraint 12).
BUILD_SRC="$WORK/src"
command rm -rf "${BUILD_SRC:?}"
mkdir -p "$BUILD_SRC"
rsync -a --exclude vendor "$SRC/" "$BUILD_SRC/"
(cd "$BUILD_SRC" && GOFLAGS= GOPROXY=off go mod vendor) || { echo "build-ts-go: go mod vendor failed" >&2; exit 1; }
direct_src="$BUILD_SRC/vendor/tailscale.com/control/controlclient/direct.go"
direct_dst="$direct_src"
python3 -I - "$direct_src" "$direct_dst" <<'PY' || { echo "build-ts-go: the control client patch did not apply" >&2; exit 1; }
import sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src).read()
patches = [
    ('\tuseNoise := pr.URLIsNoise || pr.Types == "c2n"\n',
     '\tuseNoise := pr.URLIsNoise || pr.Types == "c2n"\n'
     '\tif !useNoise {\n'
     '\t\tc.logf("wombat: ignored a ping request outside the control connection")\n'
     '\t\treturn\n'
     '\t}\n'),
    ('\t\tc.logf("exiting process with status %v per controlplane", *code)\n\t\tos.Exit(*code)\n',
     '\t\tc.logf("wombat: ignored a control request to exit with status %v", *code)\n'),
    # os.Exit was the file's only use of os.
    ('\t"os"\n', '\t_ "os"\n'),
]
for old, new in patches:
    if s.count(old) != 1:
        sys.exit("expected one match for: " + old.splitlines()[0])
    s = s.replace(old, new)
open(dst, "w").write(s)
PY

ldflags="-w -X tailscale.com/version.longStamp=$TS_VERSION-wombat -X tailscale.com/version.shortStamp=$TS_VERSION"
mkdir -p "$OUT" "$WORK"
parts=()
for arch in $ARCHS; do
    goarch="$(go_runtime_goarch "$arch")" || { echo "build-ts-go: unknown arch $arch" >&2; exit 1; }
    flags="-isysroot $SDK -arch $arch -mmacosx-version-min=$MACOS_MIN"
    echo "build-ts-go: building $arch"
    (cd "$BUILD_SRC" && GOFLAGS=-mod=vendor CGO_CFLAGS="$flags" CGO_LDFLAGS="$flags" GOARCH="$goarch" \
        go build -tags "$tags" -ldflags="$ldflags" -trimpath -buildmode c-archive -o "$WORK/libts-go-$arch.a" .)
    command rm -f "$WORK/libts-go-$arch.h"
    parts+=("$WORK/libts-go-$arch.a")
done
lipo -create -output "$OUT/libts-go.a" "${parts[@]}"
go_runtime_check_clock build-ts-go "$OUT/libts-go.a"
# Outputs are read into a variable, never piped to grep -q: under pipefail grep's early exit
# kills strings with SIGPIPE and the check never fires (quality-7; see build-signed.sh).
texts="$(strings "$OUT/libts-go.a")"
symbols="$(nm "$OUT/libts-go.a" 2>/dev/null || true)"
# An empty or broken listing would pass every symbol gate (security-8 L4).
if [[ "$symbols" != *"_syscall.Syscall"* || "$symbols" != *"_tailscale.com/"* ]]; then
    command rm -f "$OUT/libts-go.a"
    echo "build-ts-go: nm gave no usable symbol list" >&2
    exit 1
fi
logtail_gate='[tT]\ _tailscale\.com/logtail\.(NewLogger|\(\*Logger\)\.upload)'
exec_gate='[tT]\ _syscall\.(Exec|forkExec|ForkExec)[^A-Za-z0-9_]'
# Nothing that serves: the sandbox allows listening since the device test (network.server, for
# magicsock's UDP), so this gate is what keeps LocalAPI, proxies and peerAPI out
# (security-9-fable L2). safesocket's client helpers are linked; its listeners must not be.
listen_gate='[tT]\ _tailscale\.com/(ipn/localapi\.|ipn/ipnserver\.|net/socks5\.|net/proxymux\.|tsnet\.|safesocket\.[Ll]isten|ipn/ipnlocal\.\(\*peerAPIServer\))'
# The gates themselves must still match what they're for (positive controls).
[[ $'0 t _tailscale.com/logtail.(*Logger).uploading\n' =~ $logtail_gate && $'0 t _syscall.forkExec\n' =~ $exec_gate \
    && ! $'0 t _syscall.execveLibc\n' =~ $exec_gate \
    && $'0 t _tailscale.com/ipn/localapi.(*Handler).ServeHTTP\n' =~ $listen_gate && $'0 t _tailscale.com/safesocket.Listen\n' =~ $listen_gate \
    && ! $'0 t _tailscale.com/safesocket.localTCPPortAndToken\n' =~ $listen_gate ]] || { echo "build-ts-go: a symbol gate no longer matches its control" >&2; exit 1; }
# No log upload code may be linked (ts_omit_logtail; nothing here builds a logtail.Logger). The
# test is the uploader's own functions, not the host name: net/tlsdial compares a dialed host
# with "log.tailscale.com", so that text is in every build (x86_64 keeps it as a string, arm64
# as immediates). Verified 2026-10-26 against a copy that calls logtail.NewLogger: 3 symbols
# there on both architectures, 0 here.
if [[ "$symbols" =~ $logtail_gate ]]; then
    command rm -f "$OUT/libts-go.a"
    echo "build-ts-go: the archive links logtail's uploader" >&2
    exit 1
fi
# Nothing may be able to replace or fork the process (security-7 L4): os.StartProcess is the
# stub, and syscall.Exec/ForkExec must not be linked at all. Go's functions are local symbols in
# a c-archive ("t", not "T"; an uppercase-only test never fired, found 2026-10-26).
if [[ "$symbols" =~ $listen_gate ]]; then
    command rm -f "$OUT/libts-go.a"
    echo "build-ts-go: the archive links a listener package (${BASH_REMATCH[0]})" >&2
    exit 1
fi
# Recorded, not refused: with a var root (Tailnet Lock state), ipn/auditlog would write there.
[[ "$symbols" != *"_tailscale.com/ipn/auditlog."* ]] || echo "build-ts-go: note: ipn/auditlog is linked"
if [[ "$symbols"$'\n' =~ $exec_gate ]]; then
    command rm -f "$OUT/libts-go.a"
    echo "build-ts-go: the archive links syscall.Exec or forkExec" >&2
    exit 1
fi
# The control client patches must be in (security-9 M2, L1).
if [[ "$texts" != *"wombat: ignored a ping request outside the control connection"* || "$texts" != *"wombat: ignored a control request to exit"* ]]; then
    command rm -f "$OUT/libts-go.a"
    echo "build-ts-go: the archive lacks the control client patches" >&2
    exit 1
fi
# The probe's plain-http allowance must not be in the archive (its marker text; security-7 L5).
if [[ "$texts" == *"wombat_devprobe build"* ]]; then
    command rm -f "$OUT/libts-go.a"
    echo "build-ts-go: the archive contains the dev-probe build" >&2
    exit 1
fi
# For the record (design 2.9): which linked packages import os/exec.
(cd "$SRC" && GOARCH=arm64 go list -deps -tags "$tags" -f '{{.ImportPath}}{{range .Imports}}{{if eq . "os/exec"}} imports os/exec{{end}}{{end}}' . \
    | /usr/bin/grep 'imports os/exec' > "$OUT/os-exec-importers.txt" || true)
echo "$HASH" > "$STAMP"
echo "build-ts-go: $OUT/libts-go.a ($(lipo -archs "$OUT/libts-go.a"), $(du -h "$OUT/libts-go.a" | cut -f1)); os/exec importers: $(wc -l < "$OUT/os-exec-importers.txt" | tr -d ' ')"
