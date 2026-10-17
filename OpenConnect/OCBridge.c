// Wombat: see OCBridge.h.

#include "OCBridge.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static wombat_oc_log_fn wombat_logger;

void wombat_oc_set_logger(wombat_oc_log_fn fn) { wombat_logger = fn; }

static void wombat_oc_progress(void *privdata, int level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

static void wombat_oc_progress(void *privdata, int level, const char *fmt, ...) {
    if (!wombat_logger) return;
    /* Large enough for any token (≤ 4 KB) to be scrubbed whole by the Swift side. */
    char line[8192];
    va_list args;
    va_start(args, fmt);
    vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);
    size_t n = strlen(line);
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
    if (n > 0) wombat_logger(privdata, level, line);
}

struct openconnect_info *wombat_oc_vpninfo_new(const char *useragent,
                                               openconnect_validate_peer_cert_vfn validate,
                                               openconnect_process_auth_form_vfn form,
                                               void *privdata) {
    return openconnect_vpninfo_new(useragent, validate, NULL, form, wombat_oc_progress, privdata);
}
