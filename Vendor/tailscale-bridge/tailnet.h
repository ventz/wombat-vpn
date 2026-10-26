/* SPDX-License-Identifier: MIT
 *
 * Wombat's tailnet engine: one Tailscale node (tailscale.com, BSD-3-Clause) per extension
 * process. Strings passed in are copied; strings returned are malloc'd and freed by the caller.
 */

#ifndef WOMBAT_TAILNET_H
#define WOMBAT_TAILNET_H

#include <stdbool.h>
#include <stdint.h>

/* token is the value given to tsStart; 0 is the process itself. Lines are already redacted. */
typedef void (*ts_log_fn)(void *context, int64_t token, const char *line);
/* A network plan (JSON) for Swift's TailnetNetworkPlan gate, never applied as is. */
typedef void (*ts_plan_fn)(void *context, int64_t token, const char *json);

extern void tsSetCallbacks(void *context, ts_log_fn log_fn, ts_plan_fn plan_fn);
/* Takes ownership of tun_fd. Returns a handle > 0, or -1 with *error_out set. */
extern int32_t tsStart(const char *state_dir, const char *control_url, const char *hostname,
                       bool accept_dns, int32_t tun_fd, int64_t token, char **error_out);
extern void tsStop(int32_t handle);
/* Status JSON (no keys), or NULL for an unknown handle. */
extern char *tsStatus(int32_t handle);
extern int32_t tsLogin(int32_t handle, char **error_out);
extern int32_t tsLogout(int32_t handle, int32_t timeout_ms, char **error_out);
extern void tsRebind(int32_t handle);
extern char *tsVersion(void);

#endif
