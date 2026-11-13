/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
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
 */

/*
 * cachedb_nats_stats.c — counter storage + nats_cdb_stats MI handler.
 *
 * Mirrors event_nats/nats_stats.c. Allocated in mod_init pre-fork via
 * shm_malloc, zero-initialized; readers/writers use C11 atomic ops.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"

#include "cachedb_nats_stats.h"

nats_cdb_stats_t *nats_cdb_stats = NULL;

int nats_cdb_stats_init(void)
{
	size_t bytes = (size_t)NATS_CDB_STATS_MAX_PROCS *
		sizeof(nats_cdb_stats_t);
	nats_cdb_stats = shm_malloc(bytes);
	if (!nats_cdb_stats) {
		LM_ERR("oom for per-process cdb stats table (%zu bytes)\n",
			bytes);
		return -1;
	}
	memset(nats_cdb_stats, 0, bytes);
	return 0;
}

unsigned long nats_cdb_stats_sum(size_t field_offset)
{
	unsigned long total = 0;
	int i;

	if (!nats_cdb_stats) return 0;
	for (i = 0; i < NATS_CDB_STATS_MAX_PROCS; i++) {
		_Atomic unsigned long *slot =
			(_Atomic unsigned long *)
			((char *)&nats_cdb_stats[i] + field_offset);
		total += atomic_load_explicit(slot, memory_order_relaxed);
	}
	return total;
}

void nats_cdb_stats_destroy(void)
{
	if (nats_cdb_stats) {
		shm_free(nats_cdb_stats);
		nats_cdb_stats = NULL;
	}
}

mi_response_t *mi_nats_cdb_stats(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;

	(void)params;
	(void)async_hdl;

	resp = init_mi_result_object(&resp_obj);
	if (!resp) return NULL;

	if (!nats_cdb_stats) {
		if (add_mi_string(resp_obj, MI_SSTR("error"),
			MI_SSTR("stats not initialized")) < 0)
			goto error;
		return resp;
	}

	if (add_mi_number(resp_obj, MI_SSTR("cas_retry"),
		NATS_CDB_STATS_SUM(cas_retry)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("cas_exhausted"),
		NATS_CDB_STATS_SUM(cas_exhausted)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("create_doc"),
		NATS_CDB_STATS_SUM(create_doc)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("index_miss_kv"),
		NATS_CDB_STATS_SUM(index_miss_kv)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("fastfail_rejected"),
		NATS_CDB_STATS_SUM(fastfail_rejected)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("op_failed"),
		NATS_CDB_STATS_SUM(op_failed)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("watcher_restarts"),
		NATS_CDB_STATS_SUM(watcher_restarts)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("watcher_handle_leaks"),
		NATS_CDB_STATS_SUM(watcher_handle_leaks)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("nul_fields_rejected"),
		NATS_CDB_STATS_SUM(nul_fields_rejected)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("poison_values_rejected"),
		NATS_CDB_STATS_SUM(poison_values_rejected)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("value_oversize_rejected"),
		NATS_CDB_STATS_SUM(value_oversize_rejected)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("rows_reaped"),
		NATS_CDB_STATS_SUM(rows_reaped)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("contacts_pruned"),
		NATS_CDB_STATS_SUM(contacts_pruned)) < 0)
		goto error;
	/* last-reap-pass gauges: a free registration time series
	 * refreshed every nats_reap_interval seconds (0s across the board until
	 * the first pass). */
	if (add_mi_number(resp_obj, MI_SSTR("reap_last_run"),
		NATS_CDB_STATS_SUM(reap_last_run)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("reap_last_ms"),
		NATS_CDB_STATS_SUM(reap_last_ms)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("reap_last_keys"),
		NATS_CDB_STATS_SUM(reap_last_keys)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("reap_last_aors"),
		NATS_CDB_STATS_SUM(reap_last_aors)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("reap_last_contacts"),
		NATS_CDB_STATS_SUM(reap_last_contacts)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("reap_last_active"),
		NATS_CDB_STATS_SUM(reap_last_active)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("reap_last_permanent"),
		NATS_CDB_STATS_SUM(reap_last_permanent)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("reap_last_due"),
		NATS_CDB_STATS_SUM(reap_last_due)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("reap_enum_failures"),
		NATS_CDB_STATS_SUM(reap_enum_failures)) < 0)
		goto error;

	return resp;

error:
	free_mi_response(resp);
	return NULL;
}

unsigned long nats_cas_backoff_max_us(int attempt)
{
	unsigned long us;

	if (attempt <= 0)
		return 0;
	/* Clamp shift count so very large attempts cannot UB the shift;
	 * the cap is what bounds the value above modest attempt counts. */
	if (attempt > 16)
		attempt = 16;
	us = NATS_CAS_BACKOFF_BASE_US << (attempt - 1);
	if (us > NATS_CAS_BACKOFF_CAP_US)
		us = NATS_CAS_BACKOFF_CAP_US;
	return us;
}

void nats_cas_backoff_sleep(int attempt)
{
	unsigned long max_us = nats_cas_backoff_max_us(attempt);
	unsigned long us;

	if (max_us == 0)
		return;
	/* Full jitter — pick a random interval in [0, max_us] so concurrent
	 * losers do not all retry at the same instant. rand() resolution is
	 * fine here; we don't need cryptographic randomness. */
	us = ((unsigned long)rand()) % (max_us + 1);
	if (us > 0)
		usleep((useconds_t)us);
}
