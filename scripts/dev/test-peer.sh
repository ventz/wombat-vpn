#!/usr/bin/env bash
# Starts a throwaway WireGuard peer in a Docker container (OrbStack or Docker Desktop) and writes
# a matching split-tunnel client config, for testing Wombat end to end without a real server.
#
#   scripts/dev/test-peer.sh up     # start the peer, write build/test-peer/wombat-test.conf
#   scripts/dev/test-peer.sh down   # remove the container
#
# The client routes only 10.99.0.0/24, so the rest of the Mac's traffic is untouched. Then:
#   wombat import build/test-peer/wombat-test.conf && wombat up wombat-test && ping 10.99.0.1
# The keys are generated fresh each run and protect nothing.
set -euo pipefail
trap 'echo "test-peer: line $LINENO failed (exit $?): $BASH_COMMAND" >&2' ERR

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/build/test-peer"
NAME="wombat-test-peer"
PORT="${WOMBAT_TEST_PORT:-51820}"
IMAGE="alpine:3.22"

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

docker run -d --name "$NAME" --cap-add NET_ADMIN -p "$PORT:51820/udp" "$IMAGE" \
    sh -c 'apk add --no-cache wireguard-tools-wg iproute2 >/dev/null && sleep infinity' >/dev/null
for _ in $(seq 1 60); do
    if docker exec "$NAME" sh -c 'command -v wg' >/dev/null 2>&1; then break; fi
    sleep 1
done

server_priv="$(docker exec "$NAME" wg genkey)"
server_pub="$(printf '%s' "$server_priv" | docker exec -i "$NAME" wg pubkey)"
client_priv="$(docker exec "$NAME" wg genkey)"
client_pub="$(printf '%s' "$client_priv" | docker exec -i "$NAME" wg pubkey)"

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
