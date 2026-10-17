#!/usr/bin/env bash
# Builds build/openconnect/ (static libraries + headers) for the OpenConnect engine:
# libopenconnect (LGPL-2.1) on OpenSSL 3.5 LTS (Apache-2.0), with libxml2, zlib and iconv from
# the macOS SDK. Linked into the OpenConnect system extension only, never into the app or the
# WireGuard extension (sign-in is Swift, in the app).
#
# Sources are downloaded once into build/openconnect/downloads and must match the SHA-256 pins
# below (openconnect's also matches Homebrew's formula; OpenSSL's matches the .sha256 file on
# its GitHub release). Bump a version by changing both lines together, on purpose.
#
# Every process-spawning call in the library (fork, exec*, posix_spawn, system) is renamed at
# compile time to a stub in Vendor/openconnect/noexec.c that fails with ENOSYS, and the build
# fails if any reference to the real functions is left in the archive: a server must never make
# Wombat run a vpnc-script, HostScan/CSD wrapper or helper (CLAUDE.md constraint 2).
set -euo pipefail
trap 'echo "build-openconnect: line $LINENO failed (exit $?): $BASH_COMMAND" >&2' ERR

readonly OPENCONNECT_VERSION=9.21
readonly OPENCONNECT_SHA256=5b32369467db6e5f317aa1ed12cfcbb81ed00bdbc765450b6bfcbdc300944a58
readonly OPENSSL_VERSION=3.5.9
readonly OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build/openconnect"
DOWNLOADS="$OUT/downloads"
WORK="$OUT/work"
# Always both: Debug (one arch) and Release (universal) then share one output instead of
# rebuilding it for each other (Q5-L13); linking a universal archive into one arch is fine.
ARCHS="arm64 x86_64"
MACOS_MIN="${MACOSX_DEPLOYMENT_TARGET:-15.0}"
SDK="$(xcrun --sdk macosx --show-sdk-path)"
STAMP="$OUT/.stamp"
JOBS="$(sysctl -n hw.ncpu)"

# Skip the rebuild when nothing that feeds the archives changed.
HASH="$( { echo "$OPENCONNECT_VERSION $OPENSSL_VERSION $ARCHS $MACOS_MIN $SDK"; cat "$0" "$ROOT/Vendor/openconnect/noexec.c" "$ROOT/scripts/patch-openconnect.py"; } | shasum -a 256 | cut -d' ' -f1)"
if [[ -f "$OUT/lib/libopenconnect.a" && -f "$STAMP" && "$(cat "$STAMP")" == "$HASH" ]]; then
    echo "build-openconnect: up to date"
    exit 0
fi

fetch() {  # url sha256 file
    local url="$1" sum="$2" file="$DOWNLOADS/$3"
    if [[ ! -f "$file" ]]; then
        echo "build-openconnect: downloading $3"
        curl -sSfL --proto '=https' --tlsv1.2 -o "$file.part" "$url"
        command mv -f "$file.part" "$file"
    fi
    local got
    got="$(shasum -a 256 "$file" | cut -d' ' -f1)"
    if [[ "$got" != "$sum" ]]; then
        command rm -f "$file"
        echo "build-openconnect: $3 has SHA-256 $got, expected $sum (deleted; rerun to download again)" >&2
        exit 1
    fi
}

mkdir -p "$DOWNLOADS" "$WORK"
fetch "https://www.infradead.org/openconnect/download/openconnect-$OPENCONNECT_VERSION.tar.gz" \
    "$OPENCONNECT_SHA256" "openconnect-$OPENCONNECT_VERSION.tar.gz"
fetch "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" \
    "$OPENSSL_SHA256" "openssl-$OPENSSL_VERSION.tar.gz"

# configure insists on pkg-config but must not find anything (Homebrew's GnuTLS, lz4, ...): a
# stand-in that knows no packages, so only the *_CFLAGS/*_LIBS given below are used.
FAKE_PKG_CONFIG="$WORK/pkg-config"
printf '#!/bin/sh\ncase "$1" in --version) echo 0.29.2; exit 0 ;; --atleast-pkgconfig-version) exit 0 ;; esac\nexit 1\n' > "$FAKE_PKG_CONFIG"
chmod +x "$FAKE_PKG_CONFIG"

# The renames: every way the library could start a process goes to a stub that fails.
NOEXEC_DEFINES=""
for fn in fork execv execvp execve execl execlp posix_spawn posix_spawnp system; do
    NOEXEC_DEFINES+=" -D$fn=wombat_noexec_$fn"
done

for arch in $ARCHS; do
    case "$arch" in
        arm64) ossl_target=darwin64-arm64-cc; host=aarch64-apple-darwin ;;
        x86_64) ossl_target=darwin64-x86_64-cc; host=x86_64-apple-darwin ;;
        *) echo "build-openconnect: unknown arch $arch" >&2; exit 1 ;;
    esac
    flags="-isysroot $SDK -arch $arch -mmacosx-version-min=$MACOS_MIN"
    dir="$WORK/$arch"
    # OpenSSL takes most of the time and changes least: rebuilt only when its inputs change.
    ossl_stamp="$(echo "$OPENSSL_VERSION $flags" | shasum -a 256 | cut -d' ' -f1)"
    if [[ -f "$dir/prefix/lib/libcrypto.a" && "$(cat "$dir/.openssl-stamp" 2>/dev/null)" == "$ossl_stamp" ]]; then
        command rm -rf "$dir/openconnect-$OPENCONNECT_VERSION"
    else
    command rm -rf "$dir"
    mkdir -p "$dir"

    echo "build-openconnect: OpenSSL $OPENSSL_VERSION ($arch)"
    tar -xzf "$DOWNLOADS/openssl-$OPENSSL_VERSION.tar.gz" -C "$dir"
    ossl="$dir/openssl-$OPENSSL_VERSION"
    # No engines, dynamic modules, legacy provider, apps or docs: openconnect needs none of them,
    # and a static library can't load modules anyway.
    (cd "$ossl" && CC=clang CFLAGS="$flags -O2" ./Configure "$ossl_target" no-shared no-module no-dso \
        no-engine no-legacy no-apps no-docs no-tests no-ui-console no-comp \
        --prefix="$dir/prefix" --openssldir=/nonexistent/openssl >"$dir/openssl-configure.log" 2>&1 \
        && make -j"$JOBS" build_libs >"$dir/openssl-build.log" 2>&1 \
        && make install_dev >"$dir/openssl-install.log" 2>&1) \
        || { tail -30 "$dir"/openssl-*.log >&2; exit 1; }
    echo "$ossl_stamp" > "$dir/.openssl-stamp"
    fi

    echo "build-openconnect: libopenconnect $OPENCONNECT_VERSION ($arch)"
    tar -xzf "$DOWNLOADS/openconnect-$OPENCONNECT_VERSION.tar.gz" -C "$dir"
    oc="$dir/openconnect-$OPENCONNECT_VERSION"
    # Wombat's security patches (bounded gateway MTU and header count, no packet size wrap).
    /usr/bin/python3 -I "$ROOT/scripts/patch-openconnect.py" "$oc" >/dev/null
    # The external browser and vpnc-script paths point nowhere (and could not run anyway: see the
    # renames). Every optional dependency that would pull in more C is off.
    (cd "$oc" && CC=clang CFLAGS="$flags -O2 $NOEXEC_DEFINES" LDFLAGS="$flags" \
        PKG_CONFIG="$FAKE_PKG_CONFIG" \
        OPENSSL_CFLAGS="-I$dir/prefix/include" OPENSSL_LIBS="$dir/prefix/lib/libssl.a $dir/prefix/lib/libcrypto.a" \
        LIBXML2_CFLAGS="-I$SDK/usr/include/libxml2" LIBXML2_LIBS="-lxml2" \
        ZLIB_CFLAGS="" ZLIB_LIBS="-lz" \
        ./configure --host="$host" --prefix="$dir/prefix" --enable-static --disable-shared \
            --disable-nls --without-gnutls --with-openssl --without-lz4 \
            --without-libproxy --without-stoken --without-libpcsclite --without-libpskc --without-gssapi \
            --with-builtin-json --with-vpnc-script=/nonexistent/vpnc-script \
            --with-external-browser=no --disable-docs \
            >"$dir/openconnect-configure.log" 2>&1 \
        && make -j"$JOBS" libopenconnect.la >"$dir/openconnect-build.log" 2>&1) \
        || { tail -40 "$dir"/openconnect-*.log >&2; exit 1; }
    clang $flags -O2 -c "$ROOT/Vendor/openconnect/noexec.c" -o "$dir/noexec.o"
    # libtool's static archive comes out empty when the OpenSSL libraries are given as .a paths,
    # so the archive is made here from the exact object list in the Makefile.
    objects="$(cd "$oc" && printf 'wombat-print-objects:\n\t@echo $(libopenconnect_la_OBJECTS)\n' \
        | make -s -f Makefile -f - wombat-print-objects)"
    members=()
    for lo in $objects; do members+=("$oc/${lo%.lo}.o"); done
    [[ ${#members[@]} -gt 30 ]] || { echo "build-openconnect: only ${#members[@]} objects in libopenconnect" >&2; exit 1; }
    command rm -f "$dir/libopenconnect.a"
    ar rcs "$dir/libopenconnect.a" "${members[@]}" "$dir/noexec.o"
done

command rm -rf "$OUT/lib" "$OUT/include"
mkdir -p "$OUT/lib" "$OUT/include/openconnect"
first="$(echo "$ARCHS" | awk '{print $1}')"
for lib in libopenconnect libssl libcrypto; do
    parts=()
    for arch in $ARCHS; do
        if [[ "$lib" == libopenconnect ]]; then parts+=("$WORK/$arch/libopenconnect.a"); else parts+=("$WORK/$arch/prefix/lib/$lib.a"); fi
    done
    lipo -create -output "$OUT/lib/$lib.a" "${parts[@]}"
done
command cp -f "$WORK/$first/openconnect-$OPENCONNECT_VERSION/openconnect.h" "$OUT/include/openconnect/"
command cp -f "$WORK/$first/openconnect-$OPENCONNECT_VERSION/COPYING.LGPL" "$OUT/COPYING.LGPL"
command cp -f "$WORK/$first/openssl-$OPENSSL_VERSION/LICENSE.txt" "$OUT/LICENSE.openssl"

# No reference to a real process-spawning function may remain, and the stubs must be what the
# library calls (or the renames silently stopped applying).
undefined="$(nm -u "$OUT/lib/libopenconnect.a" 2>/dev/null | sort -u)"
for fn in fork vfork execv execvp execve execl execlp execle posix_spawn posix_spawnp system popen; do
    # Matched in a variable, not piped to grep -q (SIGPIPE under pipefail; see build-signed.sh).
    if [[ $'\n'"$undefined"$'\n' == *$'\n'"_$fn"$'\n'* ]]; then
        command rm -f "$OUT/lib/libopenconnect.a"
        echo "build-openconnect: libopenconnect still calls $fn(); the no-exec renames did not apply" >&2
        exit 1
    fi
done
defined="$(nm -g "$OUT/lib/libopenconnect.a" 2>/dev/null)"
[[ "$defined" == *wombat_noexec_fork* ]] || { echo "build-openconnect: the no-exec stubs are missing" >&2; exit 1; }
# ...and the library itself, so an empty archive can't pass the checks above.
for fn in openconnect_vpninfo_new openconnect_obtain_cookie openconnect_make_cstp_connection openconnect_mainloop; do
    [[ "$defined" == *" T _$fn"* ]] || { echo "build-openconnect: $fn is missing from libopenconnect.a" >&2; exit 1; }
done
# Calls to the stubs prove the renames reached the code that spawns (not just that they exist).
calls="$(nm -u "$OUT/lib/libopenconnect.a" 2>/dev/null)"
[[ "$calls" == *_wombat_noexec_fork* && "$calls" == *_wombat_noexec_posix_spawn* ]] \
    || { echo "build-openconnect: nothing calls the no-exec stubs; the renames did not apply" >&2; exit 1; }

echo "$HASH" > "$STAMP"
echo "build-openconnect: $OUT/lib ($(lipo -archs "$OUT/lib/libopenconnect.a"); openconnect $OPENCONNECT_VERSION, OpenSSL $OPENSSL_VERSION)"
