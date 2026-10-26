# Sourced by the Go engine builds (build-wg-go.sh, build-ts-go.sh). Not executable on its own.
#
# Go's runtime measures time with mach_absolute_time, which stops while the Mac sleeps, so
# WireGuard's handshake and rekey timers would think no time passed across a sleep. Like the
# official app, we build against a private copy of GOROOT patched to mach_continuous_time.
#
# The same copy also stubs os.StartProcess (which os/exec funnels into) to fail with
# errWombatNoExec: the extensions never run programs (constraints 2 and 5), and Tailscale's core
# still links six packages that import os/exec (spike design 2.9).
#
# Both patches are checked substitutions rather than diffs so they survive Go releases; they fail
# if the expected code moves.

# go_runtime_prepare <tag> <work dir>: checks the toolchain, prepares the patched GOROOT and
# exports GOROOT, GO_VERSION and SDK. <tag> prefixes error messages.
go_runtime_prepare() {
    local tag="$1" work="$2"
    export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
    command -v go >/dev/null || { echo "$tag: Go is required (brew install go)" >&2; return 1; }

    local real_goroot
    real_goroot="$(go env GOROOT)"
    GO_VERSION="$(go env GOVERSION)"
    # The exact toolchain release: the compiler builds code that runs as root, so a new one is a
    # deliberate bump (audit F-16; security-9-astra S9-6). WOMBAT_GO_VERSION overrides for
    # testing a new release. The build prints the toolchain's own checksum for the record.
    local expected="${WOMBAT_GO_VERSION:-go1.27.3}"
    [[ "$GO_VERSION" == "$expected" ]] \
        || { echo "$tag: Go $GO_VERSION, expected $expected (set WOMBAT_GO_VERSION to try another)" >&2; return 1; }
    SDK="$(xcrun --sdk macosx --show-sdk-path)"
    local patched="$work/goroot-$GO_VERSION"

    # Two Xcode targets may build at once: one prepares, the other waits (security-7 L6). A lock
    # older than 10 minutes is a dead build's and is taken over.
    mkdir -p "$work"
    # The holder's PID is in the lock: a lock left by a cancelled or killed build is taken over
    # at once instead of after 10 minutes of silence (quality-9 L5).
    local lock="$work/.prepare.lock" waited=0 holder
    until mkdir "$lock" 2>/dev/null; do
        holder="$(cat "$lock/pid" 2>/dev/null || true)"
        if [[ -n "$holder" ]] && ! kill -0 "$holder" 2>/dev/null; then
            echo "$tag: taking over a GOROOT lock left by process $holder"
            command rm -f "$lock/pid"; rmdir "$lock" 2>/dev/null || true; continue
        fi
        if (( waited >= 600 )); then command rm -f "$lock/pid"; rmdir "$lock" 2>/dev/null || true; waited=0; continue; fi
        (( waited % 15 == 0 )) && echo "$tag: waiting for another build to prepare the Go runtime"
        sleep 1; waited=$((waited + 1))
    done
    echo $$ > "$lock/pid"
    # Bump the marker when a patch is added, so existing copies are prepared again. A failed
    # preparation releases the lock too.
    if [[ ! -f "$patched/.prepared-2" ]]; then
        go_runtime_patch "$tag" "$real_goroot" "$patched" || { command rm -f "$lock/pid"; rmdir "$lock"; return 1; }
    fi
    command rm -f "$lock/pid"; rmdir "$lock"
    echo "$tag: toolchain $GO_VERSION, go binary sha256 $(shasum -a 256 "$(command -v go)" | cut -d' ' -f1)"
    export GOROOT="$patched"
}

# go_runtime_patch <tag> <real GOROOT> <copy>: copies GOROOT and applies both patches. Every
# step is checked explicitly: the caller runs it in a condition, where errexit doesn't apply.
go_runtime_patch() {
    local tag="$1" real_goroot="$2" patched="$3" f file before after
    echo "$tag: preparing patched GOROOT ($GO_VERSION)"
    mkdir -p "$patched" || return 1
    rsync -a --delete --exclude=pkg/obj/go-build "$real_goroot/" "$patched/" || return 1
    chmod -R u+w "$patched/src/runtime" || return 1
    for f in sys_darwin.go sys_darwin_amd64.s sys_darwin_arm64.s; do
        file="$patched/src/runtime/$f"
        before="$(/usr/bin/grep -c 'libc_mach_absolute_time' "$file" || true)"
        [[ "$before" == "1" ]] || { echo "$tag: expected one mach_absolute_time call in $f, found '${before:-0}'" >&2; return 1; }
        /usr/bin/sed -i '' -e 's/libc_mach_absolute_time mach_absolute_time/libc_mach_continuous_time mach_continuous_time/' \
            -e 's/libc_mach_absolute_time(SB)/libc_mach_continuous_time(SB)/' "$file" || return 1
        after="$(/usr/bin/grep -c 'libc_mach_continuous_time' "$file" || true)"
        [[ "$after" == "1" ]] || { echo "$tag: patch did not apply to $f" >&2; return 1; }
    done
    file="$patched/src/os/exec.go"
    chmod u+w "$file" "$patched/src/os" || return 1
    before="$(/usr/bin/grep -c '^	return startProcess(name, argv, attr)$' "$file" || true)"
    [[ "$before" == "1" ]] || { echo "$tag: expected one startProcess call in os/exec.go, found '${before:-0}'" >&2; return 1; }
    /usr/bin/sed -i '' 's/^	return startProcess(name, argv, attr)$/	return nil, \&PathError{Op: "fork\/exec", Path: name, Err: errWombatNoExec}/' "$file" || return 1
    after="$(/usr/bin/grep -c 'errWombatNoExec' "$file" || true)"
    [[ "$after" == "1" ]] || { echo "$tag: the exec stub did not apply to os/exec.go" >&2; return 1; }
    cat > "$patched/src/os/wombat_noexec.go" <<'GO' || return 1
package os

import "errors"

// Wombat: the network extensions never run programs. build-signed.sh looks for this text.
var errWombatNoExec = errors.New("wombat: this process never runs programs")

// startProcess stays referenced so the platform code still compiles unchanged.
var _ = startProcess
GO
    touch "$patched/.prepared-2"
}

# go_runtime_goarch <xcode arch>: prints the GOARCH for an Xcode architecture name.
go_runtime_goarch() {
    case "$1" in
        arm64) echo arm64 ;;
        x86_64) echo amd64 ;;
        *) return 1 ;;
    esac
}

# go_runtime_check_clock <tag> <archive>: the clock patch must have taken: no mach_absolute_time
# may remain in the archive. Deletes the archive and fails otherwise.
go_runtime_check_clock() {
    local tag="$1" archive="$2" symbols
    symbols="$(nm "$archive" 2>/dev/null || true)"
    if [[ "$symbols" == *mach_absolute_time* || "$symbols" != *mach_continuous_time* ]]; then
        command rm -f "$archive"
        echo "$tag: the archive still uses mach_absolute_time; the runtime patch did not apply" >&2
        return 1
    fi
}
