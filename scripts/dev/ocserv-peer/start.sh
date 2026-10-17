#!/bin/sh
# Runs inside the container. /etc/ocserv/test is the host's build/ocserv-peer (certificates,
# password and OTP files made by ocserv-peer.sh). MODE: password (password, then a one-time
# code, like Duo) or cert (client certificate and password).
set -e
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
T=/etc/ocserv/test
# liboath records the last code used (no replays), so its file must be writable.
cp "$T/users.oath" /run/users.oath
case "${MODE:-password}" in
cert) AUTH='auth = "certificate"
auth = "plain[passwd=/etc/ocserv/test/passwd]"' ;;
*) AUTH='auth = "plain[passwd=/etc/ocserv/test/passwd,otp=/run/users.oath]"' ;;
esac
cat > /etc/ocserv/ocserv.conf <<CONF
$AUTH
tcp-port = ${PORT:-4443}
udp-port = ${PORT:-4443}
run-as-user = nobody
run-as-group = nogroup
socket-file = /run/ocserv.socket
server-cert = $T/server.pem
server-key = $T/server.key
ca-cert = $T/ca.pem
cert-user-oid = 2.5.4.3
isolate-workers = false
max-clients = 16
max-same-clients = 8
keepalive = 32400
dpd = 90
mobile-dpd = 1800
switch-to-tcp-timeout = 25
try-mtu-discovery = false
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1"
auth-timeout = 240
idle-timeout = 1200
mobile-idle-timeout = 1800
min-reauth-time = 1
max-ban-score = 0
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = true
pid-file = /run/ocserv.pid
device = vpns
predictable-ips = true
default-domain = wombat.test
ipv4-network = 10.98.0.0
ipv4-netmask = 255.255.255.0
dns = 10.98.0.1
route = 10.98.0.0/255.255.255.0
cisco-client-compat = true
dtls-legacy = true
banner = "Wombat test gateway: authorized testing only"
CONF
exec ocserv --foreground --config /etc/ocserv/ocserv.conf --log-stderr
