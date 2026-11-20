"""Wombat's patches to libopenconnect, applied by scripts/build-openconnect.sh to a freshly
extracted source tree. Each is a checked substitution: the anchor must occur exactly once, or
the build fails (so a version bump can't silently drop a patch). Listed in
Vendor/openconnect/WOMBAT.md.

    python3 -I scripts/patch-openconnect.py <openconnect-source-dir>
"""
import pathlib
import sys

ROOT = pathlib.Path(sys.argv[1])

PATCHES = [
    # 1. The gateway's MTU (X-CSTP-MTU, X-DTLS-MTU) was unbounded: near 2^31 it wraps
    #    alloc_pkt's int size to a 2 KB buffer that the CSTP read then fills with up to 2 GB
    #    (heap overwrite in the root extension; audit S5B-H1). Reject anything outside 1-16384.
    ("cstp.c",
     "\tif (!mtu) {\n",
     "\t/* Wombat: a gateway-chosen MTU is bounded before any buffer is sized from it. */\n"
     "\tif (mtu < 0 || mtu > 16384) {\n"
     "\t\tvpn_progress(vpninfo, PRG_ERR, _(\"Gateway sent an invalid MTU (%d). Aborting\\n\"), mtu);\n"
     "\t\tret = -EINVAL;\n"
     "\t\tgoto err;\n"
     "\t}\n"
     "\tif (!mtu) {\n"),
    # 2. X-CSTP-Base-MTU, the same way (it feeds the DTLS MTU calculation).
    ("cstp.c",
     "vpninfo->cstp_basemtu = atol(colon);",
     "{ long base = atol(colon); /* Wombat: bounded */ vpninfo->cstp_basemtu = (base > 0 && base <= 16384) ? (int)base : 0; }"),
    # 3. Every X-CSTP-/X-DTLS- header was kept with no limit on how many (memory exhaustion of
    #    the extension; S5B-M6). Real gateways send a few dozen to a few hundred.
    ("cstp.c",
     "\tint ret = 0;\n\n\twhile ((ret = vpninfo->ssl_gets(vpninfo, buf, sizeof(buf)))) {\n",
     "\tint ret = 0;\n\tint wombat_options = 0; long wombat_bytes = 0; /* Wombat: bounded headers */\n\n"
     "\twhile ((ret = vpninfo->ssl_gets(vpninfo, buf, sizeof(buf)))) {\n"
     "\t\tif (++wombat_options > 4096 || (ret > 0 && (wombat_bytes += ret) > (1 << 20))) {\n"
     "\t\t\tvpn_progress(vpninfo, PRG_ERR, _(\"Gateway sent too many headers. Aborting\\n\"));\n"
     "\t\t\tret = -EINVAL;\n"
     "\t\t\tgoto err;\n"
     "\t\t}\n"),
    # 5. A compression the client never asked for (Wombat asks for none) was honored when the
    #    gateway announced it; its decompressor is then gateway-fed C (S5C: an inflate underflow).
    ("cstp.c",
     "\t/* Wombat: a gateway-chosen MTU is bounded before any buffer is sized from it. */\n",
     "\t/* Wombat: only compressions this client requested. */\n"
     "\tif ((vpninfo->cstp_compr && !(vpninfo->cstp_compr & vpninfo->req_compr)) ||\n"
     "\t    (vpninfo->dtls_compr && !(vpninfo->dtls_compr & vpninfo->req_compr))) {\n"
     "\t\tvpn_progress(vpninfo, PRG_ERR, _(\"Gateway chose a compression that wasn't requested. Aborting\\n\"));\n"
     "\t\tret = -EINVAL;\n"
     "\t\tgoto err;\n"
     "\t}\n"
     "\t/* Wombat: a gateway-chosen MTU is bounded before any buffer is sized from it. */\n"),
    # 6. The deflate payload carries a 4-byte checksum: shorter ones underflowed avail_in.
    ("cstp.c",
     "\t\tvpninfo->inflate_strm.next_in = buf;\n\t\tvpninfo->inflate_strm.avail_in = len - 4;\n",
     "\t\tif (len < 4) { /* Wombat: no underflow */\n"
     "\t\t\tfree_pkt(vpninfo, new);\n"
     "\t\t\treturn -EINVAL;\n"
     "\t\t}\n"
     "\t\tvpninfo->inflate_strm.next_in = buf;\n\t\tvpninfo->inflate_strm.avail_in = len - 4;\n"),
    # 7. The server-disconnect message was NUL-terminated at data[payload_len]; payload_len can
    #    equal receive_mtu, the size of data[], so that write lands one byte past the allocation.
    ("cstp.c",
     "\t\t\t\tvpninfo->cstp_pkt->data[payload_len] = 0;\n",
     "\t\t\t\tvpninfo->cstp_pkt->data[payload_len < receive_mtu ? payload_len : receive_mtu - 1] = 0; /* Wombat: in bounds */\n"),
    # 8. CSTP reads had no limit on the incoming queue (DTLS has one): a gateway could fill memory.
    ("cstp.c",
     "\twhile (readable) {\n",
     "\twhile (readable) {\n"
     "\t\tif (vpninfo->incoming_queue.count >= vpninfo->max_qlen) { /* Wombat: as DTLS does */\n"
     "\t\t\twork_done = 1;\n"
     "\t\t\tbreak;\n"
     "\t\t}\n"),
    # 9. On HTTP 503 the header loop treated a read error (< 0) as a line and could spin forever.
    ("cstp.c",
     "\t\t\twhile ((vpninfo->ssl_gets(vpninfo, buf, sizeof(buf)))) {\n\t\t\t\tif (!strncmp(buf, \"X-Reason: \", 10)) {\n",
     "\t\t\twhile (vpninfo->ssl_gets(vpninfo, buf, sizeof(buf)) > 0) { /* Wombat: stop on errors */\n\t\t\t\tif (!strncmp(buf, \"X-Reason: \", 10)) {\n"),
    # 10. The decoded STRAP private key was never freed: wiped and freed once ingested.
    ("cstp.c",
     "\t\t\t\tif (der && !ingest_strap_privkey(vpninfo, der, derlen)) {\n",
     "\t\t\t\tint wombat_ingested = der && !ingest_strap_privkey(vpninfo, der, derlen);\n"
     "\t\t\t\tif (der) { OPENSSL_cleanse(der, derlen > 0 ? derlen : 0); free(der); } /* Wombat */\n"
     "\t\t\t\tif (wombat_ingested) {\n"),
    # 11. LZS/LZ4 are given this->len as the output capacity, which a queued packet from a
    #     larger-MTU epoch could make exceed the real deflate_pkt buffer. Unreachable while we
    #     request no compression (patch 5), but make the bound local and obvious.
    ("cstp.c",
     "\t} else if (compr_type == COMPR_LZS) {\n\t\tif (this->len < 40)\n",
     "\t} else if (compr_type == COMPR_LZS) {\n"
     "\t\tif (this->len > vpninfo->deflate_pkt_size) /* Wombat: never exceed the buffer */\n"
     "\t\t\treturn -EFBIG;\n"
     "\t\tif (this->len < 40)\n"),
    ("cstp.c",
     "\t} else if (compr_type == COMPR_LZ4) {\n\t\tif (this->len < 40)\n",
     "\t} else if (compr_type == COMPR_LZ4) {\n"
     "\t\tif (this->len > vpninfo->deflate_pkt_size) /* Wombat: never exceed the buffer */\n"
     "\t\t\treturn -EFBIG;\n"
     "\t\tif (this->len < 40)\n"),
    # 12. A DTLS record typed 0x08 (compressed) when no compression was negotiated ended the whole
    #     session ("Unknown packet received", then a BYE), while every other unknown type is dropped
    #     as possible OpenSSL garbage (upstream's comment in the default case). One such record
    #     killed a 6-hour session on a gateway that announced no compression (patch 5 didn't trip;
    #     2026-11-20). Now it is dropped too, never decompressed (patch 5's rule holds), and logged
    #     at PRG_INFO with its length and first 4 bytes so the next one is diagnosable. 3 drops in
    #     one 60 s window (a fixed window; it also restarts if the clock steps back) mean something
    #     is really wrong with the DTLS channel: close it and carry on over TLS for the rest of the
    #     session (upstream's "Disabling DTLS" steps in openssl-dtls.c, minus freeing dtls_ctx,
    #     which goes with vpninfo). The strings skip _() on purpose: DTLSDiagnosticLine (Swift)
    #     matches them exactly, and a translation must not change them. Upstream's unknown_pkt
    #     label is left unreferenced (one -Wunused-label warning, expected).
    ("openconnect-internal.h",
     "\tint dtls_attempt_period;\n",
     "\tint dtls_attempt_period;\n"
     "\ttime_t wombat_dtls_compr_since; /* Wombat: patch 12 */\n"
     "\tint wombat_dtls_compr_drops;\n"),
    ("dtls.c",
     "\t\t\tif (!vpninfo->dtls_compr) {\n"
     "\t\t\t\tvpn_progress(vpninfo, PRG_ERR,\n"
     "\t\t\t\t\t     _(\"Compressed DTLS packet received when compression not enabled\\n\"));\n"
     "\t\t\t\tgoto unknown_pkt;\n"
     "\t\t\t}\n",
     "\t\t\tif (!vpninfo->dtls_compr) {\n"
     "\t\t\t\t/* Wombat: drop it like other unknown types (no quit, no BYE), never\n"
     "\t\t\t\t * decompress it; repeats fall back to TLS for the session. */\n"
     "\t\t\t\ttime_t wombat_now = time(NULL);\n"
     "\n"
     "\t\t\t\tif (wombat_now < vpninfo->wombat_dtls_compr_since ||\n"
     "\t\t\t\t    wombat_now - vpninfo->wombat_dtls_compr_since >= 60) {\n"
     "\t\t\t\t\tvpninfo->wombat_dtls_compr_since = wombat_now;\n"
     "\t\t\t\t\tvpninfo->wombat_dtls_compr_drops = 0;\n"
     "\t\t\t\t}\n"
     "\t\t\t\tvpninfo->wombat_dtls_compr_drops++;\n"
     "\t\t\t\tvpn_progress(vpninfo, PRG_INFO,\n"
     "\t\t\t\t\t     \"Dropped an unexpected compressed DTLS packet (%d bytes, starts %02x %02x %02x %02x; %d within 60 s)\\n\",\n"
     "\t\t\t\t\t     len, buf[0], len > 1 ? buf[1] : 0, len > 2 ? buf[2] : 0,\n"
     "\t\t\t\t\t     len > 3 ? buf[3] : 0, vpninfo->wombat_dtls_compr_drops);\n"
     "\t\t\t\tif (vpninfo->wombat_dtls_compr_drops >= 3) {\n"
     "\t\t\t\t\tvpn_progress(vpninfo, PRG_INFO,\n"
     "\t\t\t\t\t\t     \"Unexpected compressed DTLS packets keep arriving; using TLS only for this session\\n\");\n"
     "\t\t\t\t\tdtls_close(vpninfo);\n"
     "\t\t\t\t\tvpninfo->dtls_attempt_period = 0;\n"
     "\t\t\t\t\tvpninfo->dtls_state = DTLS_DISABLED;\n"
     "\t\t\t\t\treturn 1;\n"
     "\t\t\t\t}\n"
     "\t\t\t\tbreak;\n"
     "\t\t\t}\n"),
    # 4. Defense in depth for every packet buffer: a negative or absurd length can no longer
    #    wrap the int size (alloc_pkt is the one allocator for CSTP, DTLS and ESP packets).
    ("openconnect-internal.h",
     "\tint alloc_len = sizeof(struct pkt) + len;\n",
     "\tif (len < 0 || len > (1 << 20)) /* Wombat: no size wrap */\n"
     "\t\treturn NULL;\n"
     "\tint alloc_len = sizeof(struct pkt) + len;\n"),
]

for name, old, new in PATCHES:
    path = ROOT / name
    text = path.read_text()
    count = text.count(old)
    if count != 1:
        sys.exit(f"patch-openconnect: expected one anchor in {name}, found {count}: {old[:60]!r}")
    path.write_text(text.replace(old, new))
print(f"patch-openconnect: applied {len(PATCHES)} substitutions")
