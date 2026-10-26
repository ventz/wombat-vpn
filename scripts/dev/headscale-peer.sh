#!/usr/bin/env bash
# Starts a throwaway Headscale control server plus one tailnet node in Docker (OrbStack or Docker
# Desktop), for testing Wombat's tailnet engine without a Tailscale account. Plain http on
# loopback works only for the dev probe (Vendor/tailscale-bridge/cmd/ts-probe): the extension
# requires https, refuses loopback and shows no sign-in page on an IP-literal host, so
# `up --https` serves https://headscale.wombat.test:8443 from this Mac's LAN address.
#
#   scripts/dev/headscale-peer.sh up               # control server on http://127.0.0.1:18080 + node "peer"
#   scripts/dev/headscale-peer.sh up --https       # https://headscale.wombat.test:8443, for the extension
#   scripts/dev/headscale-peer.sh untrust          # how to remove the test CA and the hosts line
#   scripts/dev/headscale-peer.sh approve <id>     # register the Mac (auth id from its login page)
#   scripts/dev/headscale-peer.sh nodes            # list nodes (100.x addresses, online state)
#   scripts/dev/headscale-peer.sh down             # remove both containers
#
# The node shares the server's network namespace, so it reaches the control server on the same
# 127.0.0.1:<port> the Mac uses. Traffic between the Mac and the node goes direct when OrbStack's
# NAT allows it and through Tailscale's public DERP relays otherwise. MagicDNS names end in
# .wombat-test.internal: ping peer.wombat-test.internal once the Mac is registered.
# Plain http is fine on loopback: the control protocol is Noise-encrypted on its own.
#
# --https: the extension binds its sockets to the default-route interface (Tailscale's netns), so
# it can't reach a container network such as OrbStack's bridge; it can reach this Mac's own en0
# address, where the server is published. The name (.test never resolves publicly) maps to that
# address in /etc/hosts. The certificate comes from a CA made for this run: name-constrained to
# that one name, and its private key is deleted once it has signed the server's certificate, so
# trusting it lets nothing else pass. The extension runs as root and uses the system's trust,
# hence one sudo command (printed below) for the trust and the hosts line. The server is
# reachable from the LAN while it runs; registering a node still needs `approve`.
set -euo pipefail
trap 'echo "headscale-peer: line $LINENO failed (exit $?): $BASH_COMMAND" >&2' ERR

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/build/headscale-peer"
SERVER="wombat-headscale"
NODE="wombat-tailnet-peer"
PORT="${WOMBAT_HEADSCALE_PORT:-18080}"
HEADSCALE_IMAGE="headscale/headscale:0.29.6"
TAILSCALE_IMAGE="tailscale/tailscale:v1.104.2"
USER_NAME="wombat"

# A stale DOCKER_HOST (e.g. a removed Colima socket) would override the OrbStack context.
docker() { env -u DOCKER_HOST docker "$@"; }
hs() { docker exec "$SERVER" headscale "$@"; }
CA_NAME="Wombat Headscale test CA"
HS_NAME="headscale.wombat.test"

case "${1:-up}" in
down)
    docker rm -f "$NODE" "$SERVER" >/dev/null 2>&1 || true
    echo "headscale-peer: removed"
    echo "headscale-peer: if you trusted a test CA, '$0 untrust' prints how to remove it and the hosts line"
    exit 0
    ;;
approve)
    [[ -n "${2:-}" ]] || { echo "usage: $0 approve <auth id from the login page, hskey-authreq-...>" >&2; exit 64; }
    # Headscale 0.29 names it an auth id (`nodes register --key` is gone).
    hs auth register --user "$USER_NAME" --auth-id "$2"
    exit 0
    ;;
nodes)
    hs nodes list
    exit 0
    ;;
untrust)
    # Every run makes a CA with the same name: remove each by its hash, trust settings too
    # (-t), plus the hosts line. Reading the System keychain needs no sudo.
    hashes="$(security find-certificate -a -Z -c "$CA_NAME" /Library/Keychains/System.keychain 2>/dev/null | awk '/^SHA-1 hash:/ {print $3}')"
    removals=""
    for h in $hashes; do removals+="security delete-certificate -Z $h -t /Library/Keychains/System.keychain; "; done
    [[ -n "$removals" ]] || echo "headscale-peer: no test CA in the System keychain"
    echo "Run: sudo sh -c '${removals}sed -i \"\" \"/# wombat-headscale-test\$/d\" /etc/hosts'"
    exit 0
    ;;
up) ;;
*) echo "usage: $0 up [--https]|approve <key>|nodes|down|untrust" >&2; exit 64 ;;
esac
HTTPS=0
[[ "${2:-}" == "--https" ]] && HTTPS=1

docker rm -f "$NODE" "$SERVER" >/dev/null 2>&1 || true
mkdir -p "$OUT"
chmod 700 "$OUT"

publish="127.0.0.1:$PORT:$PORT"
server_url="http://127.0.0.1:$PORT"
tls_lines=""
peer_env=()
tls_mount=()
if (( HTTPS )); then
    HOST_IP="$(ipconfig getifaddr en0)" || { echo "headscale-peer: en0 has no IPv4 address" >&2; exit 1; }
    PORT=8443
    publish="$HOST_IP:$PORT:$PORT"
    server_url="https://$HS_NAME:$PORT"
    tls="$OUT/tls"
    mkdir -p "$tls"
    # The path goes into a root shell command below: plain characters only.
    [[ "$tls" =~ ^[A-Za-z0-9/._-]+$ ]] || { echo "headscale-peer: move the checkout to a path without spaces or quotes" >&2; exit 1; }
    # The CA key never outlives this run, even a failed one (security-8 L6).
    trap 'command rm -f "${tls:?}/ca-key.pem"' EXIT
    chmod 700 "$tls"
    command rm -f "${tls:?}"/*.pem "${tls:?}"/*.cnf "${tls:?}"/*.srl
    cat > "$tls/ca.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = ca
prompt = no
[dn]
CN = $CA_NAME
[ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
nameConstraints = critical, permitted;DNS:$HS_NAME, excluded;IP:0.0.0.0/0.0.0.0, excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0
subjectKeyIdentifier = hash
[leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:$HS_NAME
authorityKeyIdentifier = keyid
EOF
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
        -keyout "$tls/ca-key.pem" -out "$tls/ca.pem" -config "$tls/ca.cnf" 2>/dev/null
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$tls/server-key.pem" -out "$tls/server-csr.pem" -subj "/CN=$HS_NAME" 2>/dev/null
    openssl x509 -req -in "$tls/server-csr.pem" -CA "$tls/ca.pem" -CAkey "$tls/ca-key.pem" \
        -CAcreateserial -days 30 -extfile "$tls/ca.cnf" -extensions leaf -out "$tls/server.pem" 2>/dev/null
    # The CA signs nothing else, ever.
    command rm -f "${tls:?}/ca-key.pem" "${tls:?}/server-csr.pem" "${tls:?}"/*.srl
    openssl verify -CAfile "$tls/ca.pem" "$tls/server.pem" >/dev/null
    chmod 644 "$tls/server-key.pem"  # read by the container's user; the directory stays 0700
    tls_lines="tls_cert_path: /etc/headscale/tls/server.pem
tls_key_path: /etc/headscale/tls/server-key.pem"
    # The node shares the server's network namespace, so the name goes on the server container.
    tls_mount=(-v "$tls:/etc/headscale/tls:ro" --add-host "$HS_NAME:$HOST_IP")
    peer_env=(-e SSL_CERT_FILE=/etc/wombat-ca.pem -v "$tls/ca.pem:/etc/wombat-ca.pem:ro")
fi

cat > "$OUT/config.yaml" <<EOF
server_url: $server_url
listen_addr: 0.0.0.0:$PORT
$tls_lines
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
noise:
  private_key_path: /var/lib/headscale/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: false
  urls:
    - https://controlplane.tailscale.com/derpmap/default
  auto_update_enabled: false
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
log:
  level: info
policy:
  mode: file
  path: ""
dns:
  magic_dns: true
  base_domain: wombat-test.internal
  override_local_dns: false
  nameservers:
    global: []
unix_socket: /var/run/headscale/headscale.sock
unix_socket_permission: "0770"
logtail:
  enabled: false
taildrop:
  enabled: false
EOF

docker run -d --name "$SERVER" -p "$publish" \
    -v "$OUT/config.yaml:/etc/headscale/config.yaml:ro" ${tls_mount[@]+"${tls_mount[@]}"} \
    "$HEADSCALE_IMAGE" serve >/dev/null
for _ in $(seq 1 30); do
    if hs users list >/dev/null 2>&1; then break; fi
    sleep 1
done
hs users create "$USER_NAME" >/dev/null
user_id="$(hs users list --output json | python3 -c 'import json,sys; print(next(u["id"] for u in json.load(sys.stdin) if u["name"] == "'"$USER_NAME"'"))')"
# A single-use key for the container node only; the Mac signs in through the browser.
node_key="$(hs preauthkeys create --user "$user_id" --expiration 10m)"

# Over https the node dials the published address like the Mac does, trusting only the test CA.
docker run -d --name "$NODE" --network "container:$SERVER" ${peer_env[@]+"${peer_env[@]}"} \
    -e TS_USERSPACE=true -e TS_HOSTNAME=peer -e TS_AUTHKEY="$node_key" \
    -e TS_EXTRA_ARGS="--login-server=$server_url" \
    "$TAILSCALE_IMAGE" >/dev/null
for _ in $(seq 1 30); do
    if docker exec "$NODE" tailscale ip -4 >/dev/null 2>&1; then break; fi
    sleep 1
done

echo "headscale-peer: control server $server_url (user $USER_NAME)"
if (( HTTPS )); then
    echo "headscale-peer: once per run, trust this run's CA and name the server (the extension runs as root):"
    echo "  sudo sh -c 'security add-trusted-cert -d -r trustRoot -p ssl -k /Library/Keychains/System.keychain \"$tls/ca.pem\" && sed -i \"\" \"/# wombat-headscale-test\$/d\" /etc/hosts && echo \"$HOST_IP $HS_NAME # wombat-headscale-test\" >> /etc/hosts'"
    echo "headscale-peer: when done: $0 untrust"
fi
echo "headscale-peer: node peer at $(docker exec "$NODE" tailscale ip -4), peer.wombat-test.internal"
echo "headscale-peer: after the Mac opens the login page, run: $0 approve <auth id>"
