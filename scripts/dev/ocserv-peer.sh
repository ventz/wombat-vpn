#!/usr/bin/env bash
# Starts a throwaway Cisco AnyConnect-compatible gateway (ocserv) in Docker (OrbStack or Docker
# Desktop) and writes a matching Wombat profile, for testing the OpenConnect engine end to end.
#
#   scripts/dev/ocserv-peer.sh up          # password, then a one-time code (stands in for Duo)
#   scripts/dev/ocserv-peer.sh up --cert   # client certificate plus password
#   scripts/dev/ocserv-peer.sh down
#
# Writes build/ocserv-peer/: wombat-ocserv.anyconnect (import it in Wombat), test.env (the
# values the live tests read), client.p12 (password "wombat"; import into the login keychain
# for the --cert mode) and the test CA. User "test", password "test-password". The one-time
# code is TOTP over the RFC 4226 test secret: `scripts/dev/ocserv-peer.sh otp` prints the
# current one. The tunnel routes only 10.98.0.0/24; ping 10.98.0.1 once connected.
set -euo pipefail
trap 'echo "ocserv-peer: line $LINENO failed (exit $?): $BASH_COMMAND" >&2' ERR

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/build/ocserv-peer"
NAME="wombat-ocserv-peer"
PORT="${WOMBAT_OCSERV_PORT:-4443}"
# RFC 4226 / 6238 test secret ("12345678901234567890"): protects nothing.
readonly OTP_SECRET_HEX=3132333435363738393031323334353637383930
DOCKER=(env -u DOCKER_HOST docker)

otp() {
    /usr/bin/python3 -I -c '
import hmac, hashlib, struct, time, sys
key = bytes.fromhex(sys.argv[1]); counter = int(time.time()) // 30
h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
o = h[-1] & 15
print("%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000))' "$OTP_SECRET_HEX"
}

case "${1:-up}" in
down) "${DOCKER[@]}" rm -f "$NAME" >/dev/null 2>&1 || true; echo "ocserv-peer: removed"; exit 0 ;;
otp) otp; exit 0 ;;
up) ;;
*) echo "usage: $0 up [--cert] | down | otp" >&2; exit 64 ;;
esac
MODE=password
[[ "${2:-}" == "--cert" ]] && MODE=cert

"${DOCKER[@]}" rm -f "$NAME" >/dev/null 2>&1 || true
mkdir -p "$OUT"
chmod 700 "$OUT"
"${DOCKER[@]}" build -q -t wombat-ocserv-peer "$ROOT/scripts/dev/ocserv-peer" >/dev/null

if [[ ! -f "$OUT/server.pem" ]]; then
    echo "ocserv-peer: making test certificates"
    "${DOCKER[@]}" run --rm -v "$OUT:/out" wombat-ocserv-peer sh -c '
set -e
cd /out
umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 -subj "/CN=Wombat Test CA" \
    -keyout ca.key -out ca.pem -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=localhost" -keyout server.key -out server.csr 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 -extfile server.ext -out server.pem 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=test" -keyout client.key -out client.csr 2>/dev/null
printf "extendedKeyUsage=clientAuth\n" > client.ext
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 -extfile client.ext -out client.pem 2>/dev/null
openssl pkcs12 -export -legacy -inkey client.key -in client.pem -name "Wombat test client" -passout pass:wombat -out client.p12 2>/dev/null \
  || openssl pkcs12 -export -inkey client.key -in client.pem -name "Wombat test client" -passout pass:wombat -out client.p12
rm -f server.csr client.csr server.ext client.ext ca.srl
chmod 644 *.pem
'
fi
# ocpasswd format: user:group:crypt hash.
hash="$("${DOCKER[@]}" run --rm wombat-ocserv-peer openssl passwd -6 test-password)"
printf 'test:*:%s\n' "$hash" > "$OUT/passwd"
printf 'HOTP/T30 test - %s\n' "$OTP_SECRET_HEX" > "$OUT/users.oath"
chmod 644 "$OUT/passwd" "$OUT/users.oath" "$OUT"/*.pem
chmod 644 "$OUT/server.key"  # read by ocserv in the container; a test key that protects nothing

# The same port inside and out: ocserv tells clients its DTLS port (X-DTLS-Port), so a mapped
# 4443→443 sent DTLS to 127.0.0.1:443 and it always fell back to TLS.
"${DOCKER[@]}" run -d --name "$NAME" --cap-add NET_ADMIN --device /dev/net/tun -e MODE="$MODE" -e PORT="$PORT" \
    -v "$OUT:/etc/ocserv/test:ro" -p "127.0.0.1:$PORT:$PORT/tcp" -p "127.0.0.1:$PORT:$PORT/udp" wombat-ocserv-peer >/dev/null
for _ in $(seq 1 30); do
    if "${DOCKER[@]}" logs "$NAME" 2>&1 | /usr/bin/grep -q 'listening (TCP)'; then break; fi
    sleep 1
done

pin="$(openssl x509 -in "$OUT/server.pem" -outform DER | shasum -a 256 | cut -d' ' -f1)"
client="$(openssl x509 -in "$OUT/client.pem" -outform DER | shasum -a 256 | cut -d' ' -f1)"
{
    echo "[AnyConnect]"
    echo "Server = https://localhost:$PORT/"
    echo "Username = test"
    echo "ServerCertificate = sha256:$pin"
    [[ "$MODE" == cert ]] && echo "ClientCertificate = sha256:$client"
} > "$OUT/wombat-ocserv.anyconnect"
cat > "$OUT/test.env" <<ENV
WOMBAT_OCSERV_URL=https://localhost:$PORT/
WOMBAT_OCSERV_MODE=$MODE
WOMBAT_OCSERV_USER=test
WOMBAT_OCSERV_PASSWORD=test-password
WOMBAT_OCSERV_OTP_SECRET=$OTP_SECRET_HEX
WOMBAT_OCSERV_PIN=$pin
WOMBAT_OCSERV_CLIENT_P12=$OUT/client.p12
WOMBAT_OCSERV_CLIENT_P12_PASSWORD=wombat
ENV
echo "ocserv-peer: gateway running ($NAME, $MODE mode, tcp+udp $PORT); profile: $OUT/wombat-ocserv.anyconnect"
echo "ocserv-peer: user test / test-password; one-time code: $0 otp; logs: docker logs -f $NAME"
