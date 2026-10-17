// Wombat: the small C layer between libopenconnect and Swift. libopenconnect's logging
// callback is variadic, which Swift can't implement, so the library is created here with a C
// logger that formats each line and hands it to Swift.

#ifndef WOMBAT_OC_BRIDGE_H
#define WOMBAT_OC_BRIDGE_H

#include <openconnect.h>

typedef void (*wombat_oc_log_fn)(void *privdata, int level, const char *message);

/// Sets the Swift logger (once, before the first wombat_oc_vpninfo_new).
void wombat_oc_set_logger(wombat_oc_log_fn fn);

/// openconnect_vpninfo_new with the C logger. No write_new_config callback: Wombat never
/// saves the gateway's XML profile.
struct openconnect_info *wombat_oc_vpninfo_new(const char *useragent,
                                               openconnect_validate_peer_cert_vfn validate,
                                               openconnect_process_auth_form_vfn form,
                                               void *privdata);

/* From <sys/kern_control.h> (as in WireGuardKitC, MIT): for finding the utun descriptor. */
#include <sys/types.h>
#define CTLIOCGINFO 0xc0644e03UL
struct ctl_info {
    u_int32_t   ctl_id;
    char        ctl_name[96];
};
struct sockaddr_ctl {
    u_char      sc_len;
    u_char      sc_family;
    u_int16_t   ss_sysaddr;
    u_int32_t   sc_id;
    u_int32_t   sc_unit;
    u_int32_t   sc_reserved[5];
};

/// The command bytes (character macros don't import into Swift).
static const unsigned char WOMBAT_OC_CMD_CANCEL = OC_CMD_CANCEL;
static const unsigned char WOMBAT_OC_CMD_STATS = OC_CMD_STATS;
static const unsigned char WOMBAT_OC_CMD_PAUSE = OC_CMD_PAUSE;

#endif
