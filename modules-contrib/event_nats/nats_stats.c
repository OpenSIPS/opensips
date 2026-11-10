/*
 * Copyright (C) 2025 OpenSIPS Solutions
 * Copyright (C) 2025 Norm Brandinger <n.brandinger@gmail.com>
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

/*
 * nats_stats.c -- NATS publish statistics and MI command handlers
 *
 * Manages a shared-memory statistics block (nats_stats_t) that tracks
 * publish counts, failure counts, and JetStream ack results across all
 * OpenSIPS worker processes.  Exposes three MI commands:
 *
 *   nats_status    -- returns connection state and server info
 *   nats_stats     -- returns all publish/fail/ack counters
 *   nats_reconnect -- informational (auto-reconnect is always active)
 *
 * The stats block is allocated in shared memory during mod_init() and
 * freed during mod_destroy().
 */

#include <stddef.h>

#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../mi/mi.h"
#include "nats_stats.h"
#include "event_nats_sub.h"
#include "../nats/nats_bind.h"
#include "../nats/nats_pool.h"

/* module parameters (defined in event_nats.c) */
extern int nats_jetstream;

nats_stats_t *nats_stats = NULL;

/**
 * nats_stats_init() -- Allocate the per-process counter table.
 *
 * Called from mod_init() before forking.  The table is sized once
 * for NATS_STATS_MAX_PROCS slots; each running worker process bumps
 * exclusively into its own slot indexed by process_no.  This keeps
 * the publish hot path off any other worker's cacheline.
 */
int nats_stats_init(void)
{
    size_t bytes = (size_t)NATS_STATS_MAX_PROCS * sizeof(nats_stats_t);
    nats_stats = shm_malloc(bytes);
    if (!nats_stats) {
        LM_ERR("oom for per-process stats table (%zu bytes)\n", bytes);
        return -1;
    }
    memset(nats_stats, 0, bytes);
    return 0;
}

/**
 * nats_stats_destroy() -- Free the shared stats block.
 *
 * Called from mod_destroy() during shutdown.
 */
void nats_stats_destroy(void)
{
    if (nats_stats) {
        shm_free(nats_stats);
        nats_stats = NULL;
    }
}

/**
 * nats_stats_sum() -- Sum a counter across every per-process slot.
 *
 * Used by the MI handler to expose a single aggregate number per
 * counter despite the per-process write fan-out.  Reads use relaxed
 * atomic loads — torn reads on a 64-bit field are unlikely on the
 * supported architectures (aarch64 / x86_64 both guarantee atomic
 * 64-bit aligned loads), but the explicit load makes it explicit.
 */
unsigned long nats_stats_sum(size_t field_offset)
{
    unsigned long total = 0;
    int i;

    if (!nats_stats) return 0;
    for (i = 0; i < NATS_STATS_MAX_PROCS; i++) {
        _Atomic unsigned long *slot =
            (_Atomic unsigned long *)
            ((char *)&nats_stats[i] + field_offset);
        total += atomic_load_explicit(slot, memory_order_relaxed);
    }
    return total;
}

/**
 * mi_nats_status() -- MI handler for "nats_status".
 *
 * Returns a JSON object with the NATS server URL, connection state
 * (yes/no), and JetStream mode (enabled/disabled).
 *
 * @param params    MI parameters (unused).
 * @param async_hdl MI async handler (unused).
 * @return          MI response object, or NULL on error.
 */
mi_response_t *mi_nats_status(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
    mi_response_t *resp;
    mi_item_t *resp_obj;

    resp = init_mi_result_object(&resp_obj);
    if (!resp) return NULL;

    {
        const char *server_info = nats_pool_get_server_info();
        if (add_mi_string(resp_obj, MI_SSTR("server"),
                server_info, strlen(server_info)) < 0)
            goto error;
    }
    if (nats_pool_is_connected()) {
        if (add_mi_string(resp_obj, MI_SSTR("connected"), MI_SSTR("yes")) < 0)
            goto error;
    } else {
        if (add_mi_string(resp_obj, MI_SSTR("connected"), MI_SSTR("no")) < 0)
            goto error;
    }
    if (nats_jetstream) {
        if (add_mi_string(resp_obj, MI_SSTR("jetstream"), MI_SSTR("enabled")) < 0)
            goto error;
    } else {
        if (add_mi_string(resp_obj, MI_SSTR("jetstream"), MI_SSTR("disabled")) < 0)
            goto error;
    }

    return resp;
error:
    free_mi_response(resp);
    return NULL;
}

/**
 * mi_nats_stats() -- MI handler for "nats_stats".
 *
 * Returns a JSON object with all publish/fail counters: published,
 * evi_published, script_published, failed, reconnects, js_ack_ok,
 * js_ack_failed, js_retried, js_duplicate, reconnect_buf_dropped and
 * js_pending_dropped.
 *
 * @param params    MI parameters (unused).
 * @param async_hdl MI async handler (unused).
 * @return          MI response object, or NULL on error.
 */
mi_response_t *mi_nats_stats(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
    mi_response_t *resp;
    mi_item_t *resp_obj;

    resp = init_mi_result_object(&resp_obj);
    if (!resp) return NULL;

    if (!nats_stats) {
        if (add_mi_string(resp_obj, MI_SSTR("error"), MI_SSTR("stats not initialized")) < 0)
            goto error;
        return resp;
    }

    if (add_mi_number(resp_obj, MI_SSTR("published"),
            NATS_STATS_SUM(published)) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("evi_published"),
            NATS_STATS_SUM(evi_published)) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("script_published"),
            NATS_STATS_SUM(script_published)) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("failed"),
            NATS_STATS_SUM(failed)) < 0)
        goto error;
    /* The per-process `reconnects` counter was never incremented
     * anywhere; the authoritative reconnect count is the shared pool's
     * reconnect epoch (bumped in _pool_reconnected_cb). */
    if (add_mi_number(resp_obj, MI_SSTR("reconnects"),
            (unsigned long)nats_pool_get_reconnect_epoch()) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("js_ack_ok"),
            NATS_STATS_SUM(js_ack_ok)) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("js_ack_failed"),
            NATS_STATS_SUM(js_ack_failed)) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("js_retried"),
            NATS_STATS_SUM(js_retried)) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("js_duplicate"),
            NATS_STATS_SUM(js_duplicate)) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("reconnect_buf_dropped"),
            NATS_STATS_SUM(reconnect_buf_dropped)) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("js_pending_dropped"),
            NATS_STATS_SUM(js_pending_dropped)) < 0)
        goto error;

    /* Inbound (subscribe-side) backpressure: events shed under a publish
     * flood, plus the live in-flight gauge.  Counters live in the consumer
     * module's SHM control block (read via getters). */
    if (add_mi_number(resp_obj, MI_SSTR("inbound_dropped_oversize"),
            nats_inbound_dropped_oversize()) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("inbound_dropped_backpressure"),
            nats_inbound_dropped_backpressure()) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("inbound_inflight"),
            (unsigned long)nats_inbound_inflight()) < 0)
        goto error;

    return resp;
error:
    free_mi_response(resp);
    return NULL;
}

/**
 * mi_nats_reconnect() -- MI handler for "nats_reconnect".
 *
 * Informational endpoint.  NATS auto-reconnect is always active via
 * nats.c's built-in reconnection logic; this MI command confirms that
 * status.  A true manual reconnect would require IPC to the worker
 * process, which is not implemented.
 *
 * @param params    MI parameters (unused).
 * @param async_hdl MI async handler (unused).
 * @return          MI response object, or NULL on error.
 */
mi_response_t *mi_nats_reconnect(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
    mi_response_t *resp;
    mi_item_t *resp_obj;

    resp = init_mi_result_object(&resp_obj);
    if (!resp) return NULL;

    /* Note: actual reconnect requires signaling the worker process.
     * For now, nats.c handles reconnection automatically. */
    if (add_mi_string(resp_obj, MI_SSTR("status"),
            MI_SSTR("NATS auto-reconnect is active")) < 0) {
        free_mi_response(resp);
        return NULL;
    }

    return resp;
}
