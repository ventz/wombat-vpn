/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2023 WireGuard LLC. All Rights Reserved.
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

/* Wombat: token is the value passed to wgTurnOn/awgTurnOn for that tunnel; 0 is the process. */
typedef void(*logger_fn_t)(void *context, int64_t token, int level, const char *msg);
extern void wgSetLogger(void *context, logger_fn_t logger_fn);
extern int wgTurnOn(const char *settings, int32_t tun_fd, int64_t log_token);
/* Wombat: an AmneziaWG tunnel on the amneziawg-go engine. The handle works with every call below. */
extern int awgTurnOn(const char *settings, int32_t tun_fd, int64_t log_token);
extern void wgTurnOff(int handle);
extern int64_t wgSetConfig(int handle, const char *settings);
extern char *wgGetConfig(int handle);
extern void wgBumpSockets(int handle);
extern void wgDisableSomeRoamingForBrokenMobileSemantics(int handle);
extern const char *wgVersion();
extern const char *awgVersion();

#endif
