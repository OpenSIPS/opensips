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
 */

/*
 * event_nats_sub.c — NATS subscription consumer process
 *
 * Follows the rabbitmq_consumer pattern:
 *   1. Dedicated process (proc_export_t) subscribes to NATS
 *   2. nats.c async callbacks fire on received messages
 *   3. Message data is copied to SHM and dispatched via ipc_dispatch_rpc()
 *   4. SIP worker receives IPC, calls evi_raise_event() → event_route[E_*]
 *
 * Parameters accessible in event_route:
 *   $param(subject) — NATS subject the message arrived on
 *   $param(data)    — message payload (string)
 */

#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdatomic.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../ipc.h"
#include "../../evi/evi.h"
#include "../../evi/evi_params.h"
#include "../nats/nats_bind.h"
#include "../nats/nats_pool.h"
#include "event_nats_sub.h"

/* ── Global subscription list ────────────────────────────────────── */

nats_subscription_t nats_subscriptions[NATS_MAX_SUBSCRIPTIONS];
int nats_subscription_count = 0;

/* ── EVI parameter names ─────────────────────────────────────────── */

static str evi_subject_name = str_init("subject");
static str evi_data_name = str_init("data");

/* ── IPC event structure (allocated in SHM) ──────────────────────── */

typedef struct nats_ipc_event {
	event_id_t event_id;
	char *subject;     /* points INTO this struct's combined SHM block */
	int subject_len;
	char *data;        /* points INTO this struct's combined SHM block */
	int data_len;
} nats_ipc_event_t;

/* Inbound-event backpressure.  A publish flood must not exhaust SHM or
 * saturate the worker IPC queue.  NATS_EVENT_MAX_DATA caps per-message
 * payload; NATS_EVENT_MAX_INFLIGHT caps the number of events dispatched
 * but not yet processed. */
#define NATS_EVENT_MAX_DATA      (1 * 1024 * 1024)   /* 1 MiB (NATS default max_payload) */
#define NATS_EVENT_MAX_INFLIGHT  4096

/* Shared (SHM) backpressure state: the cnats I/O thread (consumer process)
 * increments `inflight` and the SIP workers decrement it after raising the
 * event, so it must live in shared memory.  Allocated in
 * nats_consumer_register_events() at mod_init (pre-fork) so every process
 * inherits the pointer. */
typedef struct nats_inbound_ctl {
	_Atomic int            inflight;
	_Atomic unsigned long  dropped_backpressure;
	_Atomic unsigned long  dropped_oversize;
} nats_inbound_ctl_t;

static nats_inbound_ctl_t *g_inbound = NULL;

/* Observability getters for the inbound backpressure counters.  g_inbound
 * is a single SHM struct allocated pre-fork, so these are safe to call from
 * the attendant/MI process (which never touches the I/O-thread writers).
 * Return 0 before the block is allocated. */
unsigned long nats_inbound_dropped_oversize(void)
{
	return g_inbound ? atomic_load_explicit(&g_inbound->dropped_oversize,
		memory_order_relaxed) : 0;
}

unsigned long nats_inbound_dropped_backpressure(void)
{
	return g_inbound ? atomic_load_explicit(&g_inbound->dropped_backpressure,
		memory_order_relaxed) : 0;
}

int nats_inbound_inflight(void)
{
	return g_inbound ? atomic_load_explicit(&g_inbound->inflight,
		memory_order_relaxed) : 0;
}

/* ── Forward declarations ────────────────────────────────────────── */

static void nats_msg_handler(natsConnection *nc, natsSubscription *sub,
	natsMsg *msg, void *closure);
static void nats_ipc_raise_event(int sender, void *param);

/* Create the natsSubscription for one configured subscription, wiring
 * nats_msg_handler.  Queue-subscribes when a queue group is set (load-
 * balanced across members), plain-subscribes otherwise.  Returns the
 * natsStatus; the handle lands in sub->sub. */
static natsStatus subscribe_one(nats_subscription_t *sub, natsConnection *nc)
{
	if (sub->queue_group[0])
		return nats_dl.natsConnection_QueueSubscribe(&sub->sub, nc,
			sub->subject, sub->queue_group, nats_msg_handler, sub);
	return nats_dl.natsConnection_Subscribe(&sub->sub, nc,
		sub->subject, nats_msg_handler, sub);
}

/*
 * The reconnect check of the consumer process, once per loop turn: when
 * the pool's reconnect epoch has moved since @sub_epoch, walk every
 * subscription, and if cnats has marked it invalid (server-side state
 * was lost across the reconnect), destroy it and re-subscribe.
 * Subscriptions that survived the reconnect on the broker side report
 * nats_dl.natsSubscription_IsValid()=true and are left alone.  The epoch
 * adopted is the one read BEFORE the walk (nats_epoch.h): a reconnect
 * landing during it is seen by the next call.  Returns 1 if a reconnect
 * was seen, 0 if not.
 */
static int resubscribe_pass(natsConnection *nc, nats_epoch_t *sub_epoch)
{
	int cur_epoch = nats_epoch_snapshot();
	natsStatus s;
	int i;

	if (nats_epoch_current(sub_epoch))
		return 0;

	LM_INFO("NATS consumer: reconnect detected (epoch "
		"%d -> %d); checking subscriptions\n",
		sub_epoch->seen, cur_epoch);
	for (i = 0; i < nats_subscription_count; i++) {
		nats_subscription_t *sub = &nats_subscriptions[i];

		if (sub->sub && nats_dl.natsSubscription_IsValid(sub->sub))
			continue;
		if (sub->sub) {
			nats_dl.natsSubscription_Destroy(sub->sub);
			sub->sub = NULL;
		}
		s = subscribe_one(sub, nc);
		if (s == NATS_OK) {
			LM_INFO("NATS consumer: re-subscribed to '%s'\n",
				sub->subject);
		} else {
			LM_ERR("NATS consumer: resubscribe to '%s' failed: %s\n",
				sub->subject, nats_dl.natsStatus_GetText(s));
		}
	}
	nats_epoch_adopt(sub_epoch, cur_epoch);
	return 1;
}

/* ── Modparam parser ─────────────────────────────────────────────── */

int nats_consumer_parse_subscribe(modparam_t type, void *val)
{
	char *str_val = (char *)val;
	char *p, *tok;
	char buf[512];
	nats_subscription_t *s;

	if (!str_val || !str_val[0]) {
		LM_ERR("empty subscribe parameter\n");
		return -1;
	}

	if (nats_subscription_count >= NATS_MAX_SUBSCRIPTIONS) {
		LM_ERR("too many subscriptions (max %d)\n",
			NATS_MAX_SUBSCRIPTIONS);
		return -1;
	}

	s = &nats_subscriptions[nats_subscription_count];
	memset(s, 0, sizeof(*s));

	/* Copy to writable buffer for strsep */
	if (strlen(str_val) >= sizeof(buf)) {
		LM_ERR("subscribe value too long\n");
		return -1;
	}
	strcpy(buf, str_val);

	/* Parse key=value pairs separated by semicolons */
	p = buf;
	while ((tok = strsep(&p, ";")) != NULL) {
		char *eq = strchr(tok, '=');
		if (!eq) continue;
		*eq = '\0';

		/* Trim leading spaces */
		while (*tok == ' ') tok++;
		char *val_str = eq + 1;
		while (*val_str == ' ') val_str++;

		if (strcmp(tok, "subject") == 0) {
			if (s->subject[0]) {
				LM_ERR("duplicate 'subject=' in subscribe\n");
				return -1;
			}
			if (strlen(val_str) >= sizeof(s->subject)) {
				LM_ERR("subject too long: %s\n", val_str);
				return -1;
			}
			strcpy(s->subject, val_str);
		} else if (strcmp(tok, "event") == 0) {
			if (s->event_name[0]) {
				LM_ERR("duplicate 'event=' in subscribe\n");
				return -1;
			}
			if (strlen(val_str) >= sizeof(s->event_name)) {
				LM_ERR("event name too long: %s\n", val_str);
				return -1;
			}
			strcpy(s->event_name, val_str);
		} else if (strcmp(tok, "queue") == 0) {
			if (s->queue_group[0]) {
				LM_ERR("duplicate 'queue=' in subscribe\n");
				return -1;
			}
			if (strlen(val_str) >= sizeof(s->queue_group)) {
				LM_ERR("queue group too long: %s\n", val_str);
				return -1;
			}
			strcpy(s->queue_group, val_str);
		} else {
			LM_WARN("unknown subscribe key: %s\n", tok);
		}
	}

	/* Validate required fields */
	if (!s->subject[0]) {
		LM_ERR("subscribe param missing 'subject' field\n");
		return -1;
	}
	if (!s->event_name[0]) {
		LM_ERR("subscribe param missing 'event' field\n");
		return -1;
	}

	LM_INFO("parsed subscribe: subject=%s event=%s queue=%s\n",
		s->subject, s->event_name,
		s->queue_group[0] ? s->queue_group : "(none)");

	nats_subscription_count++;
	return 0;
}

/* ── Event registration ──────────────────────────────────────────── */

int nats_consumer_register_events(void)
{
	int i;
	str event_name;

	/* Allocate the shared inbound-backpressure gauge once, pre-fork. */
	if (!g_inbound) {
		g_inbound = shm_malloc(sizeof(*g_inbound));
		if (!g_inbound) {
			LM_ERR("cannot allocate inbound backpressure state\n");
			return -1;
		}
		memset(g_inbound, 0, sizeof(*g_inbound));
	}

	for (i = 0; i < nats_subscription_count; i++) {
		event_name.s = nats_subscriptions[i].event_name;
		event_name.len = strlen(nats_subscriptions[i].event_name);

		nats_subscriptions[i].event_id =
			evi_publish_event(event_name);
		if (nats_subscriptions[i].event_id == EVI_ERROR) {
			LM_ERR("cannot register event '%s'\n",
				nats_subscriptions[i].event_name);
			return -1;
		}

		LM_INFO("registered event '%s' (id=%d) for subject '%s'\n",
			nats_subscriptions[i].event_name,
			nats_subscriptions[i].event_id,
			nats_subscriptions[i].subject);
	}

	return 0;
}

/* ── Consumer process main loop ──────────────────────────────────── */

void nats_consumer_process(int rank)
{
	natsConnection *nc;
	natsStatus s;
	int i;

	LM_INFO("NATS consumer process starting (pid=%d)\n", getpid());

	/* No subscriptions configured: block forever on pause() rather
	 * than returning.  Returning from a proc_export entry triggers
	 * SIGCHLD in the attendant, which OpenSIPS treats as a fatal
	 * child exit and shuts the whole instance down.  pause() blocks
	 * until any signal is delivered; if the signal terminates the
	 * process, control never returns to us, and if it's caught and
	 * the handler returns we just loop and pause() again. */
	if (nats_subscription_count == 0) {
		for (;;)
			pause();
	}

	/* Get NATS connection from shared pool.  If the broker is down at
	 * startup, nats_pool_get() exhausts its max_reconnect attempts and
	 * returns NULL.  We MUST NOT return from this proc_export entry on
	 * that path: returning raises SIGCHLD in the attendant, which
	 * OpenSIPS treats as a fatal child exit and shuts the whole instance
	 * down (the same hazard the no-subscriptions branch above guards
	 * against).  Instead, stay alive and keep retrying — cnats
	 * establishes the connection on its background thread and a later
	 * nats_pool_get() succeeds once the broker becomes reachable. */
	nc = nats_pool_get();
	while (!nc) {
		LM_WARN("NATS consumer: connection unavailable (broker "
			"down?); staying alive, retrying in 5s\n");
		sleep(5);
		nc = nats_pool_get();
	}

	/* Subscribe to all configured subjects */
	for (i = 0; i < nats_subscription_count; i++) {
		nats_subscription_t *sub = &nats_subscriptions[i];

		s = subscribe_one(sub, nc);

		if (s != NATS_OK) {
			LM_ERR("subscribe to '%s' failed: %s\n",
				sub->subject, nats_dl.natsStatus_GetText(s));
			continue;
		}

		LM_INFO("subscribed to '%s' %s→ event '%s'\n",
			sub->subject,
			sub->queue_group[0] ? "(queue) " : "",
			sub->event_name);
	}

	/* Block forever -- nats.c fires the per-subscription callbacks on
	 * its internal threads, so this process just needs to stay alive
	 * AND react to reconnects.
	 *
	 * Loop cadence: 5 s.  cnats handles the actual reconnect on a
	 * background thread; we poll the pool's atomic reconnect epoch.
	 * When it advances, walk every subscription, and if cnats has
	 * marked it invalid (server-side state was lost across the
	 * reconnect), destroy it and re-subscribe.  Subscriptions that
	 * survived the reconnect on the broker side report
	 * nats_dl.natsSubscription_IsValid()=true and are left alone. */
	{
		nats_epoch_t sub_epoch;   /* tag of the live sub set */
		int prev_connected = nats_pool_is_connected();

		nats_epoch_save(&sub_epoch);
		for (;;) {
			sleep(5);

			int cur_connected = nats_pool_is_connected();

			resubscribe_pass(nc, &sub_epoch);

			if (prev_connected && !cur_connected) {
				LM_WARN("NATS consumer: connection lost, "
					"awaiting reconnect...\n");
			} else if (!prev_connected && cur_connected) {
				LM_INFO("NATS consumer: connection restored\n");
			}
			prev_connected = cur_connected;
		}
	}
}

/* ── nats.c message callback ─────────────────────────────────────── */

/*
 * Rate-limited drop warning, safe for the nats.c I/O thread.
 * The two admission-control branches below used to drop SILENTLY
 * (only the MI counters moved); but this callback may not call LM_*
 * (dprint is not warranted reentrant against the worker thread's
 * logging -- the same rule the modules-contrib/nats pool callbacks follow), so
 * the warning rides a raw write(2) to stderr, once per 30s per drop
 * class.  The authoritative signal remains the MI counters
 * (inbound_dropped_oversize / inbound_dropped_backpressure).
 */
/* last time each drop warning was written */
static time_t rl_oversize, rl_backpressure;

static void drop_warn_unsafe(time_t *rl_slot, const char *line, size_t len)
{
	time_t now = time(NULL);

	/* benign race: two library threads may both pass right at the
	 * boundary and emit one extra line */
	if (*rl_slot != 0 && now >= *rl_slot && now - *rl_slot < 30)
		return;
	*rl_slot = now;
	if (write(STDERR_FILENO, line, len) < 0) {
		/* stderr may be closed under a daemonized start; the MI
		 * counters still carry the signal */
	}
}


/*
 * Called by nats.c on its internal I/O thread when a message arrives.
 * MUST NOT call OpenSIPS APIs (LM_*, pkg_malloc, etc.) — only SHM
 * operations and ipc_dispatch_rpc().
 *
 * Pattern: copy message to SHM → ipc_dispatch_rpc() → worker handles it.
 */
static void nats_msg_handler(natsConnection *nc, natsSubscription *sub,
	natsMsg *msg, void *closure)
{
	nats_subscription_t *nsub = (nats_subscription_t *)closure;
	nats_ipc_event_t *evt;
	const char *subject;
	const char *data;
	int subject_len, data_len;

	char  *p;
	size_t need;

	subject = nats_dl.natsMsg_GetSubject(msg);
	data = nats_dl.natsMsg_GetData(msg);
	data_len = nats_dl.natsMsg_GetDataLength(msg);
	if (data_len < 0) data_len = 0;
	subject_len = subject ? strlen(subject) : 0;

	/* Reject oversized payloads: a flood of huge messages would otherwise
	 * exhaust SHM. */
	if (data_len > NATS_EVENT_MAX_DATA) {
		static const char warn[] = "WARNING: event_nats: dropping "
			"oversize NATS event(s) (see MI inbound_dropped_oversize; "
			"repeats suppressed for 30s)\n";

		if (g_inbound)
			atomic_fetch_add_explicit(&g_inbound->dropped_oversize, 1,
				memory_order_relaxed);
		drop_warn_unsafe(&rl_oversize, warn, sizeof(warn) - 1);
		nats_dl.natsMsg_Destroy(msg);
		return;
	}

	/* Bound in-flight events: a publish flood must not queue unbounded
	 * SHM + IPC jobs faster than the workers drain them. */
	if (g_inbound && atomic_load_explicit(&g_inbound->inflight,
			memory_order_relaxed) >= NATS_EVENT_MAX_INFLIGHT) {
		static const char warn[] = "WARNING: event_nats: dropping NATS "
			"event(s) under backpressure (workers not draining; see MI "
			"inbound_dropped_backpressure; repeats suppressed for 30s)\n";

		atomic_fetch_add_explicit(&g_inbound->dropped_backpressure, 1,
			memory_order_relaxed);
		drop_warn_unsafe(&rl_backpressure, warn, sizeof(warn) - 1);
		nats_dl.natsMsg_Destroy(msg);
		return;
	}

	/* ONE combined SHM allocation: event struct + subject + data laid out
	 * back-to-back.  Per-field mallocs tripled the SHM allocator lock
	 * traffic, which profiling shows is the dominant cost at high rates;
	 * the whole event is freed with a single shm_free. */
	need = sizeof(nats_ipc_event_t) + (size_t)subject_len + 1 +
		(size_t)data_len + 1;
	evt = shm_malloc(need);
	if (!evt) {
		nats_dl.natsMsg_Destroy(msg);
		return;
	}
	memset(evt, 0, sizeof(*evt));
	evt->event_id = nsub->event_id;

	p = (char *)evt + sizeof(nats_ipc_event_t);
	evt->subject = p;
	if (subject_len > 0)
		memcpy(evt->subject, subject, subject_len);
	evt->subject[subject_len] = '\0';
	evt->subject_len = subject_len;

	p += subject_len + 1;
	evt->data = p;
	if (data && data_len > 0)
		memcpy(evt->data, data, data_len);
	evt->data[data_len] = '\0';
	evt->data_len = data_len;

	nats_dl.natsMsg_Destroy(msg);

	if (g_inbound)
		atomic_fetch_add_explicit(&g_inbound->inflight, 1,
			memory_order_relaxed);

	/* Dispatch to next available SIP worker */
	if (ipc_dispatch_rpc(nats_ipc_raise_event, evt) < 0) {
		/* IPC dispatch failed — single free, undo the in-flight bump. */
		if (g_inbound)
			atomic_fetch_sub_explicit(&g_inbound->inflight, 1,
				memory_order_relaxed);
		shm_free(evt);
	}
}

/* ── IPC handler (runs in SIP worker process) ────────────────────── */

/*
 * Called by a SIP worker via IPC. This is in OpenSIPS process context,
 * so all OpenSIPS APIs are available.
 *
 * Builds EVI params and calls evi_raise_event() which triggers
 * event_route[E_*] handlers in the routing script.
 */
static void nats_ipc_raise_event(int sender, void *param)
{
	nats_ipc_event_t *evt = (nats_ipc_event_t *)param;
	evi_params_p evi_params = NULL;

	if (!evt) return;

	/* Build EVI parameters */
	evi_params = evi_get_params();
	if (!evi_params) {
		LM_ERR("cannot create EVI params\n");
		goto cleanup;
	}

	/* $param(subject) */
	if (evt->subject && evt->subject_len > 0) {
		str subject_str = {evt->subject, evt->subject_len};
		if (evi_param_add_str(evi_params, &evi_subject_name,
				&subject_str) < 0) {
			LM_ERR("cannot add 'subject' param\n");
			goto cleanup;
		}
	}

	/* $param(data) */
	if (evt->data && evt->data_len > 0) {
		str data_str = {evt->data, evt->data_len};
		if (evi_param_add_str(evi_params, &evi_data_name,
				&data_str) < 0) {
			LM_ERR("cannot add 'data' param\n");
			goto cleanup;
		}
	}

	/* Raise the event — this triggers event_route[E_*] */
	if (evi_raise_event(evt->event_id, evi_params) < 0) {
		LM_ERR("cannot raise event %d\n", evt->event_id);
	}

	/* evi_raise_event takes ownership of params — don't free them */
	evi_params = NULL;

cleanup:
	if (evi_params)
		evi_free_params(evi_params);
	/* Single free: subject/data live inside evt's combined block. */
	shm_free(evt);
	if (g_inbound)
		atomic_fetch_sub_explicit(&g_inbound->inflight, 1,
			memory_order_relaxed);
}

#ifdef UNIT_TESTS
void event_nats_test_msg_handler(natsMsg *msg, nats_subscription_t *sub)
{
	nats_msg_handler(NULL, NULL, msg, sub);
}

natsStatus event_nats_test_subscribe_one(nats_subscription_t *sub,
	natsConnection *nc)
{
	return subscribe_one(sub, nc);
}

int event_nats_test_resubscribe_pass(natsConnection *nc, int *epoch_seen)
{
	nats_epoch_t e;
	int rc;

	e.seen = *epoch_seen;
	rc = resubscribe_pass(nc, &e);
	*epoch_seen = e.seen;
	return rc;
}

void event_nats_test_set_inflight(int value)
{
	if (g_inbound)
		atomic_store(&g_inbound->inflight, value);
}

void event_nats_test_reset_drop_warnings(void)
{
	rl_oversize = rl_backpressure = 0;
}
#endif
