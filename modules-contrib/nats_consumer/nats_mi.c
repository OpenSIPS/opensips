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
 * nats_mi.c -- MI command handlers for the consumer-handle registry.
 *
 *   nats_consumer_bind   {config}         201 OK / 400 parse / 409 dup / 500 oom
 *   nats_consumer_unbind {id}             200 OK / 404 missing
 *   nats_consumer_list                    JSON array of handles
 */

#include <string.h>

#include "../../dprint.h"
#include "../../mi/item.h"
#include "../../mi/mi.h"

#include "nats_handle_registry.h"
#include "nats_handle_parse.h"
#include "nats_mi.h"
#include "nats_consumer_proc.h"
#include "nats_ring.h"
#include "nats_ack_ipc.h"
#include "nats_rpc_ipc.h"
#include "nats_rpc_consumer.h"
#include "nats_rpc_slot.h"

#include <stdatomic.h>
#include <time.h>

/* ── enum -> string helpers ───────────────────────────────────── */

static const char *type_str(nats_consumer_type_e t)
{
	switch (t) {
		case NATS_CONSUMER_DURABLE:   return "durable";
		case NATS_CONSUMER_EPHEMERAL: return "ephemeral";
		case NATS_CONSUMER_ORDERED:   return "ordered";
	}
	return "unknown";
}

static const char *deliver_str(nats_deliver_policy_e d)
{
	switch (d) {
		case NATS_DELIVER_ALL:               return "all";
		case NATS_DELIVER_LAST:              return "last";
		case NATS_DELIVER_NEW:               return "new";
		case NATS_DELIVER_LAST_PER_SUBJECT:  return "last_per_subject";
		case NATS_DELIVER_BY_START_SEQ:      return "by_start_seq";
		case NATS_DELIVER_BY_START_TIME:     return "by_start_time";
	}
	return "unknown";
}

static const char *ack_str(nats_ack_policy_e a)
{
	switch (a) {
		case NATS_ACK_EXPLICIT: return "explicit";
		case NATS_ACK_NONE:     return "none";
		case NATS_ACK_ALL:      return "all";
	}
	return "unknown";
}

/* ── bind ─────────────────────────────────────────────────────── */

mi_response_t *mi_consumer_bind(const mi_params_t *params,
		struct mi_handler *async)
{
	str config;
	const char *err = NULL;
	nats_handle_t *h;
	int rc;
	(void)async;

	if (get_mi_string_param(params, "config", &config.s, &config.len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'config' parameter"));

	h = nats_handle_parse(&config, &err);
	if (!h) {
		if (!err) err = "parse error";
		return init_mi_error(400, (char *)err, (int)strlen(err));
	}

	rc = nats_registry_bind(h);
	if (rc == -1) {
		nats_handle_free(h);
		return init_mi_error(409, MI_SSTR("duplicate id"));
	}
	if (rc == -2) {
		nats_handle_free(h);
		return init_mi_error(500, MI_SSTR("registry internal error"));
	}
	if (rc == -3) {
		nats_handle_free(h);
		return init_mi_error(507, MI_SSTR("handle count limit reached"));
	}
	if (rc != 0) {
		nats_handle_free(h);
		return init_mi_error(500, MI_SSTR("registry bind failed"));
	}

	LM_INFO("nats_consumer: bound handle id=%.*s stream=%.*s\n",
		h->id.len, h->id.s, h->stream.len, h->stream.s);
	return init_mi_result_ok();
}

/* ── unbind ───────────────────────────────────────────────────── */

mi_response_t *mi_consumer_unbind(const mi_params_t *params,
		struct mi_handler *async)
{
	str id;
	(void)async;

	if (get_mi_string_param(params, "id", &id.s, &id.len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'id' parameter"));

	if (nats_registry_unbind(&id) < 0)
		return init_mi_error(404, MI_SSTR("no such handle"));

	LM_INFO("nats_consumer: unbound handle id=%.*s\n", id.len, id.s);
	return init_mi_result_ok();
}

/* ── list ─────────────────────────────────────────────────────── */

struct list_ctx {
	mi_item_t *arr;
	int err;
};

static int list_cb(nats_handle_t *h, void *user)
{
	struct list_ctx *c = (struct list_ctx *)user;
	mi_item_t *obj;

	obj = add_mi_object(c->arr, NULL, 0);
	if (!obj) { c->err = 1; return -1; }

	#define ADD_S(name, sp) do { \
		if ((sp)->len > 0 && \
				add_mi_string(obj, MI_SSTR(name), (sp)->s, (sp)->len) < 0) { \
			c->err = 1; return -1; \
		} \
	} while (0)
	#define ADD_S_ALWAYS(name, sp) do { \
		if (add_mi_string(obj, MI_SSTR(name), \
				(sp)->s ? (sp)->s : "", (sp)->len) < 0) { \
			c->err = 1; return -1; \
		} \
	} while (0)
	#define ADD_N(name, v) do { \
		if (add_mi_number(obj, MI_SSTR(name), (double)(v)) < 0) { \
			c->err = 1; return -1; \
		} \
	} while (0)
	#define ADD_STATIC_STR(name, cstr) do { \
		const char *_s = (cstr); \
		if (add_mi_string(obj, MI_SSTR(name), _s, (int)strlen(_s)) < 0) { \
			c->err = 1; return -1; \
		} \
	} while (0)

	ADD_S_ALWAYS("id", &h->id);
	ADD_S_ALWAYS("stream", &h->stream);
	ADD_S_ALWAYS("durable", &h->durable);
	ADD_STATIC_STR("type", type_str(h->type));
	ADD_S_ALWAYS("filter", &h->filter);
	ADD_S_ALWAYS("filters", &h->filters_csv);
	ADD_STATIC_STR("deliver_policy", deliver_str(h->deliver_policy));
	ADD_STATIC_STR("ack_policy", ack_str(h->ack_policy));
	ADD_N("ack_wait_ms", h->ack_wait_ms);
	ADD_N("max_deliver", h->max_deliver);
	ADD_N("max_ack_pending", h->max_ack_pending);

	/* runtime counters -- take the per-handle read lock */
	lock_start_read(h->rlock);
	ADD_N("created_at",     (double)h->created_at);
	ADD_N("last_used_at",   (double)h->last_used_at);
	ADD_N("pulls_requested", h->pulls_requested);
	ADD_N("msgs_delivered",  h->msgs_delivered);
	ADD_N("acks",            h->acks);
	ADD_N("naks",            h->naks);
	ADD_N("terms",           h->terms);
	ADD_N("redeliveries",    h->redeliveries);
	ADD_N("poisoned",        h->poisoned);
	ADD_N("fetch_skips_full",   h->fetch_skips_full);
	ADD_N("backpressure_drops", h->backpressure_drops);
	ADD_N("fetch_errors",       h->fetch_errors);
	if (h->ring) {
		ADD_N("ring_depth",  nats_ring_depth(h->ring));
		ADD_N("ring_forced_unwedges",
			nats_ring_forced_unwedges(h->ring));
	}
	lock_stop_read(h->rlock);

	/* Backoff state for ensure_subscription_for_handle() retries.
	 * Written only by the consumer process from reconcile_subs_cb()
	 * without taking the rlock -- consistent with the existing
	 * pulls_requested / msgs_delivered counters above, which are
	 * also writer-side lockless.  Worst case MI sees a tear/stale
	 * read; ensure_failures is a small counter and ensure_next_retry_at
	 * is monotonically nondecreasing within a single failure run, so
	 * either field is operator-actionable even when slightly stale.
	 *
	 * Non-zero ensure_failures means the handle is currently failing;
	 * ensure_failures >= 7 means the backoff has saturated at the 60 s
	 * cap (mirrors the WARN threshold in reconcile_subs_cb).  The same
	 * value reported as 0 means the handle is healthy. */
	ADD_N("ensure_failures",      h->ensure_failures);
	ADD_N("ensure_next_retry_at", (double)h->ensure_next_retry_at);

	#undef ADD_S
	#undef ADD_S_ALWAYS
	#undef ADD_N
	#undef ADD_STATIC_STR
	return 0;
}

mi_response_t *mi_consumer_list(const mi_params_t *params,
		struct mi_handler *async)
{
	mi_response_t *resp;
	mi_item_t *arr;
	struct list_ctx ctx;
	(void)params;
	(void)async;

	resp = init_mi_result_array(&arr);
	if (!resp)
		return NULL;

	ctx.arr = arr;
	ctx.err = 0;

	nats_registry_foreach(list_cb, &ctx);

	if (ctx.err) {
		free_mi_response(resp);
		return init_mi_error(500, MI_SSTR("list internal error"));
	}

	return resp;
}

/* ── consumer_stats ───────────────────────────────────────────── */

/* Aggregate of the per-handle SHM counters, summed across the registry.
 * Read under the same per-handle read lock as list_cb (writer side is the
 * consumer process via relaxed atomics; a torn read is acceptable for
 * telemetry). */
struct stats_ctx {
	unsigned long handles;
	unsigned long ring_depth;
	unsigned long ring_capacity;
	unsigned long pulls_requested;
	unsigned long msgs_delivered;
	unsigned long acks;
	unsigned long naks;
	unsigned long terms;
	unsigned long redeliveries;
	unsigned long poisoned;
	unsigned long fetch_skips_full;
	unsigned long backpressure_drops;
	unsigned long fetch_errors;
};

static int stats_cb(nats_handle_t *h, void *user)
{
	struct stats_ctx *c = (struct stats_ctx *)user;

	c->handles++;
	if (h->ring) {
		c->ring_depth    += nats_ring_depth(h->ring);
		c->ring_capacity += nats_ring_capacity(h->ring);
	}

	lock_start_read(h->rlock);
	c->pulls_requested    += h->pulls_requested;
	c->msgs_delivered     += h->msgs_delivered;
	c->acks               += h->acks;
	c->naks               += h->naks;
	c->terms              += h->terms;
	c->redeliveries       += h->redeliveries;
	c->poisoned           += h->poisoned;
	c->fetch_skips_full   += h->fetch_skips_full;
	c->backpressure_drops += h->backpressure_drops;
	c->fetch_errors       += h->fetch_errors;
	lock_stop_read(h->rlock);
	return 0;
}

/*
 * nats_consumer_stats -- one flat object aggregating the observability
 * counters an operator needs to spot back-pressure and IPC saturation:
 *
 *   handles, ring_depth/ring_capacity (summed across handles)
 *   msgs_delivered, pulls_requested, acks, naks, terms, redeliveries
 *   fetch_skips_full   -- Fetches skipped because the ring was full (flow
 *                         control; no data loss)
 *   backpressure_drops -- messages fetched but deferred (broker redelivers)
 *   fetch_errors       -- Fetch calls that returned a hard error
 *   ack_ipc_*          -- worker->consumer ack queue: depth + lifetime
 *                         enqueued/drained/dropped
 *   rpc_ipc_*          -- worker->consumer async-RPC queue (same fields)
 *   rpc_slots_inflight / rpc_slots_total -- async-RPC slot-pool occupancy
 *
 * Safe to call from the attendant/MI process: the per-handle counters and
 * ring live in SHM, and the ack/RPC IPC queues + slot pool are allocated
 * pre-fork (mod_init) so their getters return shared state in any process.
 */
mi_response_t *mi_consumer_stats(const mi_params_t *params,
		struct mi_handler *async)
{
	mi_response_t *resp;
	mi_item_t *obj;
	struct stats_ctx s;
	(void)params;
	(void)async;

	memset(&s, 0, sizeof(s));

	resp = init_mi_result_object(&obj);
	if (!resp)
		return NULL;

	nats_registry_foreach(stats_cb, &s);

	#define SN(name, v) do { \
		if (add_mi_number(obj, MI_SSTR(name), (double)(v)) < 0) \
			goto err; \
	} while (0)

	SN("handles",            s.handles);
	SN("ring_depth",         s.ring_depth);
	SN("ring_capacity",      s.ring_capacity);
	SN("msgs_delivered",     s.msgs_delivered);
	SN("pulls_requested",    s.pulls_requested);
	SN("acks",               s.acks);
	SN("naks",               s.naks);
	SN("terms",              s.terms);
	SN("redeliveries",       s.redeliveries);
	SN("poisoned",           s.poisoned);
	SN("fetch_skips_full",   s.fetch_skips_full);
	SN("backpressure_drops", s.backpressure_drops);
	SN("fetch_errors",       s.fetch_errors);

	/* worker -> consumer ack IPC */
	SN("ack_ipc_depth",      nats_ack_ipc_depth());
	SN("ack_ipc_enqueued",   nats_ack_ipc_enqueued_total());
	SN("ack_ipc_drained",    nats_ack_ipc_drained_total());
	SN("ack_ipc_dropped",    nats_ack_ipc_dropped_total());

	/* worker -> consumer async-RPC IPC */
	SN("rpc_ipc_depth",      nats_rpc_ipc_depth());
	SN("rpc_ipc_enqueued",   nats_rpc_ipc_enqueued_total());
	SN("rpc_ipc_drained",    nats_rpc_ipc_drained_total());
	SN("rpc_ipc_dropped",    nats_rpc_ipc_dropped_total());
	SN("rpc_slot_orphans_reaped", nats_rpc_slot_orphans_reaped_total());

	/* async-RPC slot pool */
	SN("rpc_slots_inflight", nats_rpc_slot_inflight_count());
	SN("rpc_slots_total",    nats_rpc_slot_total_count());

	#undef SN
	return resp;

err:
	free_mi_response(resp);
	return NULL;
}

/* nats_consumer_health -- consumer-process liveness snapshot.
 *
 * Returns a JSON object:
 *   { "tick": N,
 *     "consumer_pid": PID,
 *     "last_tick_ms_ago": MS,    // monotonic ms since last tick
 *     "stale": true|false        // last_tick_ms_ago > 5000 (>5x loop tick)
 *   }
 *
 * Operators / external watchdogs poll this and treat stale=true as
 * "consumer process wedged or crashed" -- since the SHM ring's
 * eventfd-blocked workers cannot raise the alarm themselves. */
mi_response_t *mi_consumer_health(const mi_params_t *params,
		struct mi_handler *async)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	(void)params; (void)async;

	resp = init_mi_result_object(&resp_obj);
	if (!resp) return NULL;

	if (!nats_consumer_hb) {
		if (add_mi_string(resp_obj, MI_SSTR("error"),
				MI_SSTR("heartbeat block not initialized")) < 0)
			goto err;
		return resp;
	}

	{
		unsigned long tick = atomic_load_explicit(&nats_consumer_hb->tick,
			memory_order_relaxed);
		long long last_us = atomic_load_explicit(
			&nats_consumer_hb->last_tick_us, memory_order_relaxed);
		int pid = atomic_load_explicit(&nats_consumer_hb->consumer_pid,
			memory_order_relaxed);
		struct timespec ts;
		long long now_us = 0;
		long long ms_ago;
		int stale;

		if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
			now_us = (long long)ts.tv_sec * 1000000LL +
			         (long long)ts.tv_nsec / 1000LL;
		ms_ago = (last_us > 0 && now_us >= last_us) ?
		         (now_us - last_us) / 1000LL : -1;
		stale = (ms_ago < 0 || ms_ago > 5000);

		if (add_mi_number(resp_obj, MI_SSTR("tick"), (double)tick) < 0) goto err;
		if (add_mi_number(resp_obj, MI_SSTR("consumer_pid"),
				(double)pid) < 0) goto err;
		if (add_mi_number(resp_obj, MI_SSTR("last_tick_ms_ago"),
				(double)ms_ago) < 0) goto err;
		if (stale) {
			if (add_mi_string(resp_obj, MI_SSTR("stale"),
					MI_SSTR("true")) < 0) goto err;
		} else {
			if (add_mi_string(resp_obj, MI_SSTR("stale"),
					MI_SSTR("false")) < 0) goto err;
		}
	}
	return resp;
err:
	free_mi_response(resp);
	return NULL;
}

/* ── MI export table ──────────────────────────────────────────── */

const mi_export_t nats_consumer_mi_cmds[] = {
	{ "nats_consumer_bind",
	  "bind or update a consumer handle", 0, 0, {
		{ mi_consumer_bind, {"config", 0} },
		{ EMPTY_MI_RECIPE }
	  }, { 0 }
	},
	{ "nats_consumer_unbind",
	  "remove a consumer handle", 0, 0, {
		{ mi_consumer_unbind, {"id", 0} },
		{ EMPTY_MI_RECIPE }
	  }, { 0 }
	},
	{ "nats_consumer_list",
	  "list all registered handles", 0, 0, {
		{ mi_consumer_list, {0} },
		{ EMPTY_MI_RECIPE }
	  }, { 0 }
	},
	{ "nats_consumer_stats",
	  "aggregate ring/IPC/slot counters for back-pressure monitoring", 0, 0, {
		{ mi_consumer_stats, {0} },
		{ EMPTY_MI_RECIPE }
	  }, { 0 }
	},
	{ "nats_consumer_health",
	  "consumer-process heartbeat snapshot for watchdog use",
	  0, 0, {
		{ mi_consumer_health, {0} },
		{ EMPTY_MI_RECIPE }
	  }, { 0 }
	},
	{ EMPTY_MI_EXPORT }
};
