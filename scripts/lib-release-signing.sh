# shellcheck shell=bash
# Sourced by release.sh. Needs sparkle_bin and SPARKLE_ACCOUNT set.
# shellcheck disable=SC2154 # sparkle_bin and SPARKLE_ACCOUNT come from release.sh
#
# Wombat's Sparkle EdDSA private key is read ONCE per release from the login keychain, from the
# item generate_keys made (generic password, service https://sparkle-project.org, account
# SPARKLE_ACCOUNT), with /usr/bin/security: one keychain prompt. It is then handed to each
# Sparkle tool on stdin (`--ed-key-file -`), so no tool asks the keychain again. Letting the tools
# read the keychain themselves meant one prompt per run, about four per release.
#
# The key lives only in the unexported shell variable sparkle_key. It is never put in argv (a
# builtin printf feeds the tool's stdin, and builtins aren't exec'd), never in a file, and never
# traced. Here-strings are avoided on purpose: /bin/bash 3.2 writes them to a temporary file;
# process substitution is a /dev/fd pipe. No =~ on the key either: BASH_REMATCH would keep a copy.
# The guards stop accidental leaks (`bash -x`, a PS4 from the environment). They don't defend
# against a hostile environment (BASH_ENV, imported functions, DEBUG traps): that is trusted.

# Drops an export attribute inherited from the environment along with any value.
unset sparkle_key
sparkle_key=""
# The keychain to read; empty means the user's search list (the login keychain). Only the test
# harness sets it, to a throwaway keychain.
sparkle_keychain=""
readonly SPARKLE_KEYCHAIN_SERVICE="https://sparkle-project.org"

# Every function that reads sparkle_key starts with
#     { local xtrace=$-; set +x; } 2>/dev/null
# and restores tracing with `sparkle_key_xtrace_restore "$xtrace"` before it returns, so even
# `bash -x scripts/release.sh` never traces the key (release.sh pins PS4, which bash would
# otherwise take from the environment). The state is kept per call, so nesting works.
sparkle_key_xtrace_restore() {
    case $1 in *x*) set -x ;; esac
}

# Reads the key from the keychain into sparkle_key.
sparkle_key_load() {
    { local xtrace=$-; set +x; } 2>/dev/null
    local status=0
    local -a keychain=()
    # Base64 spelled out, not A-Za-z: bash 3.2 ranges follow the locale's collation order.
    local b64='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    [[ -n "$sparkle_keychain" ]] && keychain=("$sparkle_keychain")
    # An export attribute set after this file was sourced (allexport on at that time, or a later
    # declare -x) would hand the key to every child: dropped before the key is assigned.
    builtin export -n sparkle_key 2>/dev/null || true
    if [[ $- == *a* ]]; then
        # allexport would hand the key to every later child (build, notarytool, curl, gh).
        echo "refusing to load the Sparkle key with allexport (set -a) on" >&2
        status=1
    elif ! sparkle_key=$(/usr/bin/security find-generic-password -s "$SPARKLE_KEYCHAIN_SERVICE" \
            -a "$SPARKLE_ACCOUNT" -w ${keychain[@]+"${keychain[@]}"} </dev/null); then
        sparkle_key=""
        echo "could not read the Sparkle key from the keychain (service $SPARKLE_KEYCHAIN_SERVICE," \
            "account $SPARKLE_ACCOUNT) -- missing, or the prompt was denied" >&2
        status=1
    else
        sparkle_key=${sparkle_key//[[:space:]]/}
        # generate_keys stores base64: a 32-byte seed (44 characters, the last data character
        # carrying 2 zero bits, then one "="), or, for a key made by Sparkle 1, 64 private + 32
        # public bytes (128 characters, no padding). Checked with globs in bash: nothing decodes
        # it, and nothing copies it.
        if ! { [[ ${#sparkle_key} -eq 44 && "${sparkle_key:0:43}" != *[!$b64]* \
                  && "${sparkle_key:42:1}" == [AEIMQUYcgkosw048] && "${sparkle_key:43}" == "=" ]] \
               || [[ ${#sparkle_key} -eq 128 && "$sparkle_key" != *[!$b64]* ]]; }; then
            echo "the keychain item (account $SPARKLE_ACCOUNT) does not hold a Sparkle EdDSA private key" \
                "(got ${#sparkle_key} characters)" >&2
            sparkle_key=""
            status=1
        fi
    fi
    sparkle_key_xtrace_restore "$xtrace"
    return "$status"
}

# Runs a Sparkle tool (sign_update, generate_appcast) with the key on stdin. Without a loaded
# key it fails rather than let the tool read the keychain (another prompt, and a key nobody
# compared with SUPublicEDKey).
sparkle_tool() {
    { local xtrace=$-; set +x; } 2>/dev/null
    local tool="$sparkle_bin/${1-}" status=0
    # Only the tools that take the key on stdin; generate_keys would read the keychain itself.
    case ${1-} in
        sign_update|generate_appcast) ;;
        *) echo "sparkle_tool: '${1-}' is not a Sparkle signing tool" >&2
           sparkle_key_xtrace_restore "$xtrace"
           return 1 ;;
    esac
    shift
    if [[ -n "${sparkle_key:-}" ]]; then
        # Process substitution, not a pipe: only the tool's status counts under pipefail.
        "$tool" --ed-key-file - "$@" < <(builtin printf '%s\n' "$sparkle_key") || status=$?
    else
        echo "the Sparkle key is not loaded (or already cleared)" >&2
        status=1
    fi
    sparkle_key_xtrace_restore "$xtrace"
    return "$status"
}

# Succeeds when the loaded key's public half is $1 (SUPublicEDKey); returns 1 when it isn't and
# 2 when the check couldn't run (the cause is printed). generate_keys -p only reads
# the keychain, so this proves it by use: sign_update signs a random probe with the key, and
# CryptoKit, independently of Sparkle, verifies that signature against $1. That works for both
# export formats, and catches a Sparkle 1 export whose stored public half is wrong.
sparkle_key_matches() {
    { local xtrace=$-; set +x; } 2>/dev/null
    local public_key="${1-}" probe_dir signature status=0
    if [[ -z "${sparkle_key:-}" || -z "$public_key" ]]; then
        echo "the Sparkle key is not loaded, or no public key was given" >&2
        sparkle_key_xtrace_restore "$xtrace"
        return 2
    fi
    if ! probe_dir=$(mktemp -d "${TMPDIR:-/tmp}/wombat-key-probe.XXXXXX") \
        || ! /bin/dd if=/dev/urandom of="$probe_dir/probe" bs=64 count=1 2>/dev/null; then
        echo "could not write a probe file to check the Sparkle key" >&2
        [[ -n "${probe_dir:-}" ]] && command rm -rf "$probe_dir"
        sparkle_key_xtrace_restore "$xtrace"
        return 2
    fi
    # sign_update's errors stay visible (they never contain the key), so a key Sparkle rejects
    # isn't reported as a mismatch.
    if ! signature=$(sparkle_tool sign_update -p "$probe_dir/probe"); then
        echo "sign_update could not sign a probe with the Sparkle key" >&2
        status=2
    elif signature=${signature//[[:space:]]/}; [[ -z "$signature" ]]; then
        # Empty output isn't a wrong key: the check didn't run.
        echo "sign_update printed no signature for the probe" >&2
        status=2
    else
        # Only public data reaches swift: the public key, the signature and the probe. Its errors
        # stay visible too, so a broken toolchain isn't mistaken for a wrong key.
        /usr/bin/swift - "$public_key" "$signature" "$probe_dir/probe" >/dev/null <<'SWIFT' || status=$?
import CryptoKit
import Foundation
func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(2)
}
let args = CommandLine.arguments
guard args.count == 4 else { fail("internal: expected 3 arguments") }
guard let raw = Data(base64Encoded: args[1]), raw.count == 32 else {
    fail("SUPublicEDKey is not a base64 32-byte Ed25519 public key")
}
guard let signature = Data(base64Encoded: args[2]) else {
    fail("sign_update's probe signature is not base64")
}
guard let message = FileManager.default.contents(atPath: args[3]) else {
    fail("could not read the probe file")
}
guard
      let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw),
      key.isValidSignature(signature, for: message)
else { exit(3) }
SWIFT
    fi
    command rm -rf "$probe_dir"
    # swift exits 3 for a signature that doesn't verify; anything else that isn't 0 (2 for bad
    # input, 1 for a toolchain or compile error) means the check didn't run.
    case $status in 0|2) ;; 3) status=1 ;; *) status=2 ;; esac
    sparkle_key_xtrace_restore "$xtrace"
    return "$status"
}

# Hygiene, not a scrub: unset frees the string but bash doesn't zero the memory. sparkle_tool
# fails afterwards instead of reaching for the keychain.
sparkle_key_clear() {
    { local xtrace=$-; set +x; } 2>/dev/null
    sparkle_key=""
    unset sparkle_key
    sparkle_key_xtrace_restore "$xtrace"
}
