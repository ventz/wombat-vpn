#!/usr/bin/env bash
# Starts a throwaway WireGuard peer in a Docker container (OrbStack or Docker Desktop) and writes
# a matching split-tunnel client config, for testing Wombat end to end without a real server.
#
#   scripts/dev/test-peer.sh up         # start the peer, write build/test-peer/wombat-test.conf
#   scripts/dev/test-peer.sh up --awg   # an AmneziaWG 2.0 peer instead (upstream amneziawg-go,
#                                       # built from scripts/dev/awg-peer); writes wombat-awg.conf
#   scripts/dev/test-peer.sh down       # remove the container
#
# The client routes only 10.99.0.0/24, so the rest of the Mac's traffic is untouched. Then:
#   wombat import build/test-peer/wombat-test.conf && wombat up wombat-test && ping 10.99.0.1
# The keys are generated on the first run of each kind and kept in build/test-peer/*.keys (0600),
# so an imported test tunnel keeps working across restarts. They protect nothing; delete the
# .keys file for fresh ones.
set -euo pipefail
trap 'echo "test-peer: line $LINENO failed (exit $?): $BASH_COMMAND" >&2' ERR

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/build/test-peer"
NAME="wombat-test-peer"
PORT="${WOMBAT_TEST_PORT:-51820}"
IMAGE="alpine:3.22"
AWG=0
[[ "${2:-}" == "--awg" ]] && AWG=1

case "${1:-up}" in
down)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    echo "test-peer: removed"
    exit 0
    ;;
up) ;;
*) echo "usage: $0 up|down" >&2; exit 64 ;;
esac

docker rm -f "$NAME" >/dev/null 2>&1 || true
mkdir -p "$OUT"
chmod 700 "$OUT"

# keys <file> <keytool>: sets server_priv/server_pub/client_priv/client_pub, reusing <file>.
keys() {
    local file="$1" tool="$2"
    if [[ -f "$file" ]]; then
        # shellcheck disable=SC1090
        source "$file"
    else
        server_priv="$(docker exec "$NAME" "$tool" genkey)"
        client_priv="$(docker exec "$NAME" "$tool" genkey)"
        (umask 077; printf 'server_priv=%q\nclient_priv=%q\n' "$server_priv" "$client_priv" > "$file")
    fi
    server_pub="$(printf '%s' "$server_priv" | docker exec -i "$NAME" "$tool" pubkey)"
    client_pub="$(printf '%s' "$client_priv" | docker exec -i "$NAME" "$tool" pubkey)"
}

if (( AWG )); then
    docker build -q -t wombat-awg-peer "$ROOT/scripts/dev/awg-peer" >/dev/null
    docker run -d --name "$NAME" --cap-add NET_ADMIN --device /dev/net/tun -p "$PORT:51820/udp" \
        wombat-awg-peer sleep infinity >/dev/null
    keys "$OUT/awg.keys" awg
    # The shape of a real AmneziaWG 2.0 export (S1-S4, H ranges), plus one signature packet.
    obfuscation="Jc = 4
Jmin = 8
Jmax = 80
S1 = 97
S2 = 24
S3 = 136
S4 = 8
H1 = 52817304-98112577
H2 = 203946611-260118845
H3 = 811402277-1390655104
H4 = 1602337918-1849120473
I1 = <b 0xc70000000108><r 16><t>"
    docker exec -i "$NAME" sh -s <<SERVER
set -e
umask 077
mkdir -p /var/run/amneziawg
amneziawg-go awg0 >/tmp/awg.log 2>&1
cat > /tmp/awg0.conf <<CONF
[Interface]
PrivateKey = $server_priv
ListenPort = 51820
$obfuscation

[Peer]
PublicKey = $client_pub
AllowedIPs = 10.99.0.2/32
CONF
awg setconf awg0 /tmp/awg0.conf
ip address add 10.99.0.1/24 dev awg0
ip link set awg0 up
SERVER
    umask 077
    cat > "$OUT/wombat-awg.conf" <<CLIENT
[Interface]
PrivateKey = $client_priv
Address = 10.99.0.2/32
$obfuscation

[Peer]
PublicKey = $server_pub
AllowedIPs = 10.99.0.0/24
Endpoint = 127.0.0.1:$PORT
PersistentKeepalive = 25
CLIENT
    echo "test-peer: AmneziaWG peer running ($NAME, udp $PORT); client config: $OUT/wombat-awg.conf"
    echo "test-peer: server view: docker exec $NAME awg show"
    exit 0
fi

docker run -d --name "$NAME" --cap-add NET_ADMIN -p "$PORT:51820/udp" "$IMAGE" \
    sh -c 'apk add --no-cache wireguard-tools-wg iproute2 >/dev/null && sleep infinity' >/dev/null
for _ in $(seq 1 60); do
    if docker exec "$NAME" sh -c 'command -v wg' >/dev/null 2>&1; then break; fi
    sleep 1
done

keys "$OUT/wireguard.keys" wg

docker exec -i "$NAME" sh -s <<EOF
set -e
umask 077
printf '%s' '$server_priv' > /tmp/server.key
ip link add wg0 type wireguard
wg set wg0 listen-port 51820 private-key /tmp/server.key peer '$client_pub' allowed-ips 10.99.0.2/32
ip address add 10.99.0.1/24 dev wg0
ip link set wg0 up
EOF

umask 077
cat > "$OUT/wombat-test.conf" <<EOF
[Interface]
PrivateKey = $client_priv
Address = 10.99.0.2/32

[Peer]
PublicKey = $server_pub
AllowedIPs = 10.99.0.0/24
Endpoint = 127.0.0.1:$PORT
PersistentKeepalive = 25
EOF
echo "test-peer: running ($NAME, udp $PORT); client config: $OUT/wombat-test.conf"
echo "test-peer: server view: docker exec $NAME wg show"
