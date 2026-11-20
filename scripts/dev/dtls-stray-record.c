/* Patch 12 proof (Vendor/openconnect/WOMBAT.md), built and run by scripts/dev/dtls-stray-record.sh.
 * Feeds real DTLS records (an in-process OpenSSL DTLS server over loopback UDP) through Wombat's
 * patched libopenconnect dtls_mainloop() and checks that a record typed 0x08 (compressed) with no
 * compression negotiated:
 *  - is dropped and logged, never fatal (no quit_reason, so no BYE), and later data still arrives;
 *  - logs a 1-byte record as "starts 08 00 00 00" (no stale bytes);
 *  - counts per 60 s window, which restarts after 60 s and when the clock steps back;
 *  - on the 3rd in one window closes DTLS (DTLS_DISABLED) and the session goes on.
 * Test only: a throwaway self-signed key, no gateway, no VPN profile, no keychain. */
#include <config.h>
#include "openconnect-internal.h"
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdarg.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The exact lines patch 12 prints. DTLSDiagnosticLine (LogScrubber.swift) makes only these
 * public, and only at PRG_INFO; LogScrubberTests.swift uses the same text: change both together. */
#define DROP_PREFIX "Dropped an unexpected compressed DTLS packet ("
#define FALLBACK_LINE "Unexpected compressed DTLS packets keep arriving; using TLS only for this session\n"

static char last_line[512];
static int drops_logged, fallback_logged, fatal_logged, wrong_level;

static void progress(void *privdata, int level, const char *fmt, ...)
{
	va_list ap;
	(void)privdata;
	va_start(ap, fmt);
	vsnprintf(last_line, sizeof(last_line), fmt, ap);
	va_end(ap);
	printf("[libopenconnect level %d] %s", level, last_line);
	if (!strncmp(last_line, DROP_PREFIX, strlen(DROP_PREFIX))) {
		drops_logged++;
		wrong_level += level != PRG_INFO;
	}
	if (!strcmp(last_line, FALLBACK_LINE)) {
		fallback_logged++;
		wrong_level += level != PRG_INFO;
	}
	if (strstr(last_line, "compression not enabled")) fatal_logged++;
}

static int udp_socket(struct sockaddr_in *me)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	socklen_t len = sizeof(*me);

	memset(me, 0, sizeof(*me));
	me->sin_family = AF_INET;
	me->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (fd < 0 || bind(fd, (struct sockaddr *)me, sizeof(*me)) || getsockname(fd, (struct sockaddr *)me, &len)) {
		perror("socket");
		exit(2);
	}
	fcntl(fd, F_SETFL, O_NONBLOCK);
	return fd;
}

static SSL *wire(SSL_CTX *ctx, int fd, struct sockaddr_in *peer)
{
	SSL *ssl = SSL_new(ctx);
	BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);

	connect(fd, (struct sockaddr *)peer, sizeof(*peer));
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, peer);
	SSL_set_bio(ssl, bio, bio);
	return ssl;
}

static SSL *server;
static int client_fd;

/* One record from the "gateway", then a moment for loopback UDP to deliver it. */
static void send_record(const unsigned char *rec, int len)
{
	if (SSL_write(server, rec, len) != len) {
		fprintf(stderr, "server write failed\n");
		exit(2);
	}
	struct pollfd pfd = { .fd = client_fd, .events = POLLIN };
	if (poll(&pfd, 1, 1000) != 1) {
		fprintf(stderr, "the record didn't arrive within 1 s\n");
		exit(2);
	}
}

static int failures;
#define CHECK(c, msg) do { printf("%s: %s\n", (c) ? "ok" : "FAIL", msg); if (!(c)) failures++; } while (0)

int main(void)
{
	struct sockaddr_in client_addr, server_addr;
	int server_fd = udp_socket(&server_addr);
	int timeout = 1000, ret, i, client_done = 0, server_done = 0;
	EVP_PKEY *key = EVP_EC_gen("P-256");
	X509 *cert = X509_new();

	client_fd = udp_socket(&client_addr);
	if (!key || !cert) {
		fprintf(stderr, "OpenSSL could not make a test key\n");
		return 2;
	}

	X509_set_version(cert, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
	X509_gmtime_adj(X509_getm_notBefore(cert), 0);
	X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
	X509_set_pubkey(cert, key);
	X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC, (const unsigned char *)"dtls-stray-record", -1, -1, 0);
	X509_set_issuer_name(cert, X509_get_subject_name(cert));
	X509_sign(cert, key, EVP_sha256());

	SSL_CTX *server_ctx = SSL_CTX_new(DTLS_server_method()), *client_ctx = SSL_CTX_new(DTLS_client_method());
	if (!server_ctx || !client_ctx) {
		fprintf(stderr, "OpenSSL could not make DTLS contexts\n");
		return 2;
	}
	SSL_CTX_use_certificate(server_ctx, cert);
	SSL_CTX_use_PrivateKey(server_ctx, key);
	SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, NULL);
	server = wire(server_ctx, server_fd, &client_addr);
	SSL *client = wire(client_ctx, client_fd, &server_addr);
	SSL_set_accept_state(server);
	SSL_set_connect_state(client);
	for (i = 0; i < 2000 && !(client_done && server_done); i++) {
		if (!client_done) client_done = SSL_do_handshake(client) == 1;
		if (!server_done) server_done = SSL_do_handshake(server) == 1;
	}
	if (!(client_done && server_done)) {
		printf("FAIL: in-process DTLS handshake\n");
		return 1;
	}

	/* What the engine has once DTLS is up and no compression was negotiated. */
	struct openconnect_info *v = openconnect_vpninfo_new("dtls-stray-record", NULL, NULL, NULL, progress, NULL);
	openconnect_set_loglevel(v, PRG_INFO);  /* Wombat's default level */
	v->dtls_ssl = client;
	v->dtls_fd = client_fd;
	v->dtls_state = DTLS_ESTABLISHED;
	v->ip_info.mtu = 1400;
	v->dtls_compr = 0;
	v->dtls_attempt_period = 60;

	const unsigned char compressed[] = { AC_PKT_COMPRESSED, 0x22, 0x80, 0x00, 0x11, 0x22 };
	const unsigned char data[] = { AC_PKT_DATA, 0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2 };

	send_record(compressed, sizeof(compressed));
	send_record(data, sizeof(data));
	ret = dtls_mainloop(v, &timeout, 1);
	CHECK(!v->quit_reason && fatal_logged == 0, "0x08 record: session not ended (no quit_reason, no BYE)");
	CHECK(drops_logged == 1 && !strcmp(last_line, DROP_PREFIX "6 bytes, starts 08 22 80 00; 1 within 60 s)\n"),
	      "0x08 record: dropped and logged with its length and first 4 bytes");
	CHECK(v->incoming_queue.count == 1, "data record after it still delivered");
	CHECK(v->dtls_state == DTLS_ESTABLISHED, "DTLS still up after one drop");

	send_record(compressed, 1);
	ret = dtls_mainloop(v, &timeout, 1);
	CHECK(!v->quit_reason && !strcmp(last_line, DROP_PREFIX "1 bytes, starts 08 00 00 00; 2 within 60 s)\n"),
	      "1-byte 0x08 record: logged as 08 00 00 00, 2nd in the window");
	CHECK(v->dtls_state == DTLS_ESTABLISHED, "DTLS still up after two drops");

	v->wombat_dtls_compr_since -= 61;  /* the window opened over 60 s ago */
	send_record(compressed, sizeof(compressed));
	ret = dtls_mainloop(v, &timeout, 1);
	CHECK(v->wombat_dtls_compr_drops == 1 && v->dtls_state == DTLS_ESTABLISHED, "drop after 60 s: new window, DTLS still up");

	v->wombat_dtls_compr_since += 1000;  /* the clock stepped back */
	send_record(compressed, sizeof(compressed));
	ret = dtls_mainloop(v, &timeout, 1);
	CHECK(v->wombat_dtls_compr_drops == 1 && v->dtls_state == DTLS_ESTABLISHED, "clock stepped back: new window, DTLS still up");

	send_record(compressed, sizeof(compressed));
	ret = dtls_mainloop(v, &timeout, 1);
	CHECK(v->wombat_dtls_compr_drops == 2 && v->dtls_state == DTLS_ESTABLISHED, "2nd in the window: DTLS still up");

	send_record(compressed, sizeof(compressed));
	ret = dtls_mainloop(v, &timeout, 1);
	CHECK(ret == 1 && !v->quit_reason, "3rd in one window: session not ended");
	CHECK(drops_logged == 6 && fallback_logged == 1, "3rd in one window: drop and TLS fallback logged");
	CHECK(wrong_level == 0, "patch-12 lines are PRG_INFO (Wombat's default level; DTLSDiagnosticLine's gate)");
	CHECK(v->dtls_state == DTLS_DISABLED && v->dtls_ssl == NULL && v->dtls_fd == -1 && v->dtls_attempt_period == 0,
	      "DTLS closed and disabled for the session (traffic goes on over TLS)");

	printf(failures ? "FAILED: %d check(s)\n" : "PASS\n", failures);
	return failures ? 1 : 0;
}
