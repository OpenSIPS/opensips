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
 * event_nats.c -- EVI transport module for NATS messaging
 *
 * This module registers a "nats" EVI (Event Virtual Interface) transport
 * with OpenSIPS, allowing any OpenSIPS event to be published to a NATS
 * subject.  It also exports a script function nats_publish() for direct
 * NATS publishing from opensips.cfg routing scripts.
 *
 * Transport registration:
 *   mod_init() registers the transport callbacks (parse, raise, match,
 *   free, print) with the EVI subsystem via register_event_mod().  Once
 *   registered, scripts can subscribe events to NATS destinations using
 *   the "nats:<subject>" socket syntax.
 *
 * Connection management:
 *   child_init() obtains a NATS connection (and optional JetStream context)
 *   from the shared nats_pool.  Connections are per-process; the pool
 *   handles reconnection automatically.
 *
 * Rank filtering:
 *   NATS initializes in SIP workers (UDP and TCP, rank >= 1), the
 *   HTTPD/MI process (PROC_MODULE), and the timer process (PROC_TIMER).
 *   The timer raises a large class of subscribable events in-process
 *   (usrloc/dialog EXPIRY, tm/dialog timeouts) and the raise callback
 *   runs in whatever process fires the event, so the timer MUST have a
 *   connection or those publishes are dropped.  Only the attendant
 *   (PROC_MAIN) and TCP-main (PROC_TCP_MAIN) skip initialization -- they
 *   do not handle SIP routing and TCP-main holds TLS/OpenSSL state in
 *   isolation.  Module-exported processes (negative rank)
 *   self-initialize and are not driven by child_init().
 *
 *   The admission rule is centralized in modules-contrib/nats/nats_pool_should_init().
 *
 * MI commands:
 *   nats_status  -- connection state and server info
 *   nats_stats   -- publish/fail counters
 *   nats_reconnect -- informational (auto-reconnect is always active)
 */

#include <string.h>
#include <time.h>

#include "../../sr_module.h"
#include "../../globals.h"
#include "../../evi/evi_transport.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../mod_fix.h"
#include <nats/nats.h>
#include "event_nats.h"
#include "nats_producer.h"
#include "nats_stats.h"
#include "event_nats_sub.h"
#include "nats_jetstream.h"
#include "../nats/nats_bind_mod.h"
#include "../nats/nats_pool.h"
#include "../nats/nats_redact.h"
#include "../nats/nats_validate.h"
#include "../nats/nats_js_retry.h"
#include "../nats/nats_rl.h"
#include "nats_msg_id.h"

/* module lifecycle */
static int mod_init(void);
static int child_init(int rank);
static void mod_destroy(void);

/* EVI transport callbacks */
static evi_reply_sock *nats_evi_parse(str socket);
static int nats_evi_raise(struct sip_msg *msg, str *ev_name,
	evi_reply_sock *sock, evi_params_t *params, evi_async_ctx_t *async_ctx);
static int nats_evi_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
static void nats_evi_free(evi_reply_sock *sock);
static str nats_evi_print(evi_reply_sock *sock);

/* script function */
static int w_nats_publish(struct sip_msg *msg, str *subject, str *payload,
	str *msg_id);
static void nats_evi_js_ack_cb(int outcome);

/* msg_id modparam: which event parameters form the Nats-Msg-Id of an
 * event's JetStream publishes (one rule per event, set pre-fork). */
static int nats_msg_id_param(modparam_t type, void *val);
static nats_msg_id_rule msg_id_rules[NATS_MSG_ID_MAX_RULES];
static int msg_id_rule_cnt = 0;

/* module parameters (non-static, accessed by nats_stats.c) */
char *nats_url = NULL;   /* unset: NATS_DEFAULT_URL, unless another
                          * NATS module configures servers */
int nats_jetstream = 0;
int nats_reconnect_wait = 2000;   /* ms */
int nats_max_reconnect = 60;

/* TLS configuration is sourced from the tls_mgm "nats" client domain
 * at connect time (see modules-contrib/nats/nats_pool.c: apply_tls_from_mgm).
 * The user module just binds tls_mgm and hands the bind table to
 * modules-contrib/nats; cert/CA/key/verify/cipher all come from the domain. */

/* the nats module API (nats_bind_mod.h), bound in mod_init */
struct nats_binds nats_api;
/* settings of the shared connection, forwarded to the nats module */
NATS_ALIAS_SETTER(creds_file)
NATS_ALIAS_SETTER(drain_timeout_ms)
NATS_ALIAS_SETTER(js_ack_timeout_ms)
NATS_ALIAS_SETTER(js_publish_retries)
NATS_ALIAS_SETTER(nkey)
NATS_ALIAS_SETTER(nkey_seed_file)
NATS_ALIAS_SETTER(no_randomize)
NATS_ALIAS_SETTER(password)
NATS_ALIAS_SETTER(reconnect_buf_size)
NATS_ALIAS_SETTER(token)
NATS_ALIAS_SETTER(user)

static const param_export_t mod_params[] = {
	{"nats_url",            STR_PARAM, &nats_url},
	{"jetstream",           INT_PARAM, &nats_jetstream},
	{"reconnect_wait_ms",   INT_PARAM, &nats_reconnect_wait},
	{"max_reconnect",       INT_PARAM, &nats_max_reconnect},
	/* Tunable shutdown drain timeout, ms (ONE pool value shared with
	 * cachedb_nats; see nats_pool_drain_timeout_decide for the merge
	 * contract). */
	{"drain_timeout_ms",      INT_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_drain_timeout_ms},
	/* Server order of the shared connection (ONE pool value; see
	 * nats_pool_no_randomize_decide for the merge contract). */
	{"no_randomize",        INT_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_no_randomize},
	/* Reconnect buffer of the shared connection (ONE pool value; see
	 * nats_pool_reconnect_buf_size_decide for the merge contract). */
	{"reconnect_buf_size",  INT_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_reconnect_buf_size},
	/* JetStream publishes: message ids, ack wait and resends (the
	 * pool's ack handler reads the two ints; nats_js_retry.h). */
	{"msg_id",              STR_PARAM|USE_FUNC_PARAM,
	      (void *)nats_msg_id_param},
	{"js_ack_timeout_ms",   INT_PARAM|USE_FUNC_PARAM, (void *)nats_alias_js_ack_timeout_ms},
	{"js_publish_retries",  INT_PARAM|USE_FUNC_PARAM, (void *)nats_alias_js_publish_retries},
	/* Credentials of the shared connection (ONE pool value each; see
	 * modules-contrib/nats/nats_auth.h), so no secret has to be inside a URL. */
	{"user",                 STR_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_user},
	{"password",             STR_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_password},
	{"token",                STR_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_token},
	{"creds_file",           STR_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_creds_file},
	{"nkey",                 STR_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_nkey},
	{"nkey_seed_file",       STR_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_nkey_seed_file},
	{"subscribe",           STR_PARAM|USE_FUNC_PARAM,
	                        (void *)nats_consumer_parse_subscribe},
	{0,0,0}
};

/* tls_mgm is required only when the operator wants TLS (URL begins
 * with tls://).  DEP_SILENT lets plaintext-only deployments load
 * event_nats without tls_mgm; the tls:// path checks at connect time
 * and errors with operator-friendly guidance if tls_mgm is missing. */
static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "nats", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "tls_mgm", DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/* MI commands */
static const mi_export_t mi_cmds[] = {
	{ "nats_status", 0, 0, 0, {
		{mi_nats_status, {0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "nats_stats", 0, 0, 0, {
		{mi_nats_stats, {0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "nats_reconnect", 0, 0, 0, {
		{mi_nats_reconnect, {0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	/* JetStream management MI commands */
	{ "nats_account_info", 0, 0, 0, {
		{mi_nats_account_info, {0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	/* The read-only JS observability commands (nats_stream_list,
	 * nats_stream_info) are owned by cachedb_nats (richer variants:
	 * filter/pagination/format support) -- registering them here too
	 * made whichever module loaded first silently win.  This
	 * module keeps only the MUTATING JetStream admin commands below. */
	{ "nats_stream_create", 0, 0, 0, {
		{mi_nats_stream_create, {"name", "subjects", 0}},
		{mi_nats_stream_create, {"name", "subjects", "replicas", 0}},
		{mi_nats_stream_create, {"name", "subjects", "replicas",
			"max_msgs", "max_bytes", "max_age", "retention", "storage", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "nats_stream_delete", 0, 0, 0, {
		{mi_nats_stream_delete, {"stream", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "nats_stream_purge", 0, 0, 0, {
		{mi_nats_stream_purge, {"stream", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	/* JetStream consumer-admin commands.  Named nats_js_consumer_* (not
	 * nats_consumer_*) so they do not collide with the nats_consumer
	 * module's own nats_consumer_* handle-management commands when both
	 * modules are loaded; mirrors this module's nats_stream_* family. */
	{ "nats_js_consumer_list", 0, 0, 0, {
		{mi_nats_consumer_list, {"stream", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "nats_js_consumer_info", 0, 0, 0, {
		{mi_nats_consumer_info, {"stream", "consumer", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "nats_js_consumer_create", 0, 0, 0, {
		{mi_nats_consumer_create, {"stream", "name", 0}},
		{mi_nats_consumer_create, {"stream", "name", "filter_subject", 0}},
		{mi_nats_consumer_create, {"stream", "name", "filter_subject",
			"deliver_policy", "ack_policy", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "nats_js_consumer_delete", 0, 0, 0, {
		{mi_nats_consumer_delete, {"stream", "consumer", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "nats_msg_get", 0, 0, 0, {
		{mi_nats_msg_get, {"stream", "seq", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "nats_msg_delete", 0, 0, 0, {
		{mi_nats_msg_delete, {"stream", "seq", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{EMPTY_MI_EXPORT}
};

static const cmd_export_t cmds[] = {
	{"nats_publish", (cmd_function)w_nats_publish, {
		{CMD_PARAM_STR, 0, 0},  /* subject (required) */
		{CMD_PARAM_STR, 0, 0},  /* payload (required) */
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},  /* JetStream msg id */
		{0,0,0}},
	ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

/* Consumer process — always spawned, but the main loop returns
 * immediately when no `subscribe` modparams were configured (see
 * nats_consumer_process()).  We don't mutate `no` here because the
 * proc_export_t table is consumed before mod_init runs. */
static const proc_export_t procs[] = {
	/* "event consumer" to disambiguate from the standalone nats_consumer
	 * module's "NATS consumer" proc when both are loaded. */
	{"NATS event consumer", 0, 0, nats_consumer_process, 1, 0},
	{0, 0, 0, 0, 0, 0}
};

struct module_exports exports = {
	"event_nats",               /* module name */
	MOD_TYPE_DEFAULT,           /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	0,                          /* load function */
	&deps,                      /* OpenSIPS module dependencies */
	cmds,                       /* exported functions */
	0,                          /* exported async functions */
	mod_params,                 /* exported parameters */
	0,                          /* exported statistics */
	mi_cmds,                    /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,                          /* exported transformations */
	procs,                      /* extra processes — NATS consumer */
	0,                          /* module pre-initialization function */
	mod_init,                   /* module initialization function */
	0,                          /* response handling function */
	mod_destroy,                /* destroy function */
	child_init,                 /* per-child init function */
	0                           /* reload confirm function */
};

/* EVI transport export -- registers the callback table with the EVI
 * subsystem so that "nats:<subject>" sockets are recognized. */
static const evi_export_t trans_export_nats = {
	NATS_STR,                   /* transport module name */
	nats_evi_raise,             /* raise function */
	nats_evi_parse,             /* parse function */
	nats_evi_match,             /* sockets match function */
	nats_evi_free,              /* free function */
	nats_evi_print,             /* print socket */
	NATS_FLAG                   /* flags */
};

/**
 * mod_init() -- Module initialization (pre-fork).
 *
 * Initializes publish statistics, registers the NATS EVI transport with
 * the OpenSIPS event subsystem, and registers this module with the
 * shared NATS connection pool (including TLS configuration).
 *
 * Called once in the main (attendant) process before forking workers.
 *
 * @return  0 on success, -1 on error (aborts module loading).
 */
static int mod_init(void)
{
	LM_NOTICE("initializing event_nats module ...\n");

	if (nats_bind_api("event_nats") < 0)
		return -1;

	if (nats_pool_js_ack_timeout_ms < NATS_JS_ACK_TIMEOUT_MS_MIN ||
	    nats_pool_js_ack_timeout_ms > NATS_JS_ACK_TIMEOUT_MS_MAX) {
		LM_ERR("js_ack_timeout_ms=%d is outside %d..%d\n",
			nats_pool_js_ack_timeout_ms, NATS_JS_ACK_TIMEOUT_MS_MIN,
			NATS_JS_ACK_TIMEOUT_MS_MAX);
		return -1;
	}
	if (nats_pool_js_publish_retries < 0 ||
	    nats_pool_js_publish_retries > NATS_JS_PUBLISH_RETRIES_MAX) {
		LM_ERR("js_publish_retries=%d is outside 0..%d\n",
			nats_pool_js_publish_retries, NATS_JS_PUBLISH_RETRIES_MAX);
		return -1;
	}
	if (nats_jetstream &&
	    (long)(nats_pool_js_publish_retries + 1) * nats_pool_js_ack_timeout_ms
	    > NATS_JS_DEFAULT_DUPLICATE_WINDOW_MS)
		LM_WARN("js_publish_retries=%d with js_ack_timeout_ms=%d can resend "
			"a message up to %ld ms after its first publish: the "
			"duplicate window of the target streams must be at least "
			"that long (the stream default is %d ms), or a resend can "
			"be stored twice\n", nats_pool_js_publish_retries,
			nats_pool_js_ack_timeout_ms,
			(long)(nats_pool_js_publish_retries + 1) *
			nats_pool_js_ack_timeout_ms,
			NATS_JS_DEFAULT_DUPLICATE_WINDOW_MS);
	if (msg_id_rule_cnt > 0 && !nats_jetstream)
		LM_WARN("msg_id is set but jetstream=0: message ids are only "
			"sent with JetStream publishes\n");

	if (nats_stats_init() < 0) {
		LM_ERR("cannot init stats\n");
		return -1;
	}

	/* Register the NATS transport callback table with EVI so that
	 * event subscriptions using "nats:<subject>" are handled by us */
	if (register_event_mod(&trans_export_nats)) {
		LM_ERR("cannot register transport functions for NATS\n");
		return -1;
	}

	/* Bind tls_mgm if loaded; hand the bind table to modules-contrib/nats so the
	 * pool's connect path can look up the "nats" client domain.  No
	 * effect on plaintext (nats://) URLs; tls:// URLs error at
	 * connect time if tls_mgm isn't bound or the "nats" domain
	 * isn't defined. */
	nats_pool_bind_tls("event_nats");

	if ((nats_url ?
			nats_pool_register(nats_url, "event_nats",
				nats_reconnect_wait, nats_max_reconnect) :
			nats_pool_register_default(NATS_DEFAULT_URL, "event_nats",
				nats_reconnect_wait, nats_max_reconnect)) < 0) {
		LM_ERR("cannot register with NATS connection pool\n");
		return -1;
	}

	/* Register the JS publish-ack callback so the pool's cnats-thread
	 * AckHandler bumps our shared ack counters (js_ack_ok,
	 * js_ack_failed, js_retried, js_duplicate, ...) via
	 * atomic_fetch_add. */
	nats_pool_set_pub_ack_cb(nats_evi_js_ack_cb);

	if (nats_url) {
		char redacted[512];
		nats_redact_url(nats_url, redacted, sizeof(redacted));
		LM_INFO("NATS URL: %s, JetStream: %s\n",
			redacted,
			nats_jetstream ? "enabled" : "disabled");
	} else {
		LM_INFO("NATS URL: not set (%s unless another NATS module "
			"configures servers), JetStream: %s\n", NATS_DEFAULT_URL,
			nats_jetstream ? "enabled" : "disabled");
	}

	/* Register EVI events for all configured subscriptions */
	if (nats_subscription_count > 0) {
		if (nats_consumer_register_events() < 0) {
			LM_ERR("cannot register NATS consumer events\n");
			return -1;
		}
		LM_INFO("NATS consumer: %d subscription(s) configured\n",
			nats_subscription_count);
	}

	return 0;
}

/**
 * child_init() -- Per-child process initialization (post-fork).
 *
 * Obtains a NATS connection from the shared pool and optionally a
 * JetStream context, then registers them with the producer module.
 *
 * Rank filtering is delegated to modules-contrib/nats/nats_pool_should_init();
 * see that function's documentation for the admission set.
 *
 * @param rank  OpenSIPS process rank (1-based for SIP workers).
 * @return      Always 0.  A NATS connection that cannot be established at
 *              boot (broker down) must NOT abort the worker: returning -1
 *              here is fatal to the whole OpenSIPS instance, turning an
 *              eventing-sidecar outage into a total call-processing
 *              outage.  We degrade instead -- the producer's publish path
 *              fails cleanly on a NULL connection (nats_producer.c's `!_nc`
 *              guard bumps the `failed` stat and returns -1), so the SIP
 *              server boots and routes calls while NATS publishing is
 *              unavailable.
 */
static int child_init(int rank)
{
	natsConnection *nc;
	jsCtx *js;

	if (!nats_pool_should_init(rank)) {
		LM_DBG("skipping NATS init for process rank=%d\n", rank);
		return 0;
	}

	LM_INFO("initializing NATS for process rank=%d pid=%d\n",
		rank, getpid());
	nc = nats_pool_get();
	if (!nc) {
		LM_WARN("cannot get NATS connection from pool (broker down?) — "
			"event_nats starting degraded; publishes will fail until "
			"the broker is reachable\n");
		return 0;
	}
	nats_producer_set_connection(nc);

	if (nats_jetstream) {
		js = nats_pool_get_js();
		if (!js) {
			LM_WARN("cannot get JetStream context from pool — "
				"event_nats starting degraded; JetStream publishes "
				"will fail until it is available\n");
			return 0;
		}
		nats_producer_set_js(js);
	}

	return 0;
}

/**
 * mod_destroy() -- Module cleanup on OpenSIPS shutdown.
 *
 * Frees publish statistics and tears down the NATS connection pool.
 */
static void mod_destroy(void)
{
	LM_NOTICE("destroying event_nats module ...\n");
	/* Stop the cnats ack callback from reaching our stats table, then
	 * drop our pool reference (the pool tears down on the last module's
	 * unregister), and only THEN free the stats -- otherwise a late ack
	 * on the cnats thread could bump freed stats memory. */
	nats_pool_set_pub_ack_cb(NULL);
	nats_pool_unregister();
	nats_stats_destroy();
}

/**
 * nats_evi_parse() -- Parse a NATS EVI socket string.
 *
 * Accepts a socket in the format "nats:<subject_prefix>" and allocates
 * an evi_reply_sock with the subject prefix stored in sock->address.
 * The socket is allocated in shared memory so it persists across
 * process boundaries.
 *
 * @param socket  The socket string (subject prefix) to parse.
 * @return        Allocated evi_reply_sock on success, NULL on error.
 */
static evi_reply_sock *nats_evi_parse(str socket)
{
	evi_reply_sock *sock = NULL;

	if (!socket.len || !socket.s) {
		LM_ERR("no socket specified\n");
		return NULL;
	}

	LM_DBG("parsing NATS socket: %.*s\n", socket.len, socket.s);

	sock = shm_malloc(sizeof(evi_reply_sock) + socket.len);
	if (!sock) {
		LM_ERR("evi parse: shm_malloc for evi_reply_sock failed "
			"(socket spec '%.*s', %zu bytes incl. address tail)\n",
			socket.len, socket.s,
			sizeof(evi_reply_sock) + socket.len);
		return NULL;
	}
	memset(sock, 0, sizeof(evi_reply_sock) + socket.len);

	/* store subject prefix in address */
	sock->address.s = (char *)(sock + 1);
	memcpy(sock->address.s, socket.s, socket.len);
	sock->address.len = socket.len;

	sock->flags |= EVI_ADDRESS | EVI_EXPIRE | EVI_ASYNC_STATUS;

	return sock;
}

/* Max NATS subject length (including the NUL) handled on the publish hot
 * path; a longer subject is rejected rather than truncated. */
#define NATS_MAX_SUBJECT_LEN  512

/* Validate a subject and publish (subject + payload).  @ctx is a short
 * label used in log messages.  The subject is NUL-terminated into a stack
 * buffer (rejected if too long) and validated before publish.  While the
 * connection is down, libnats keeps the message in its reconnect buffer
 * and sends it after the reconnect; a full buffer refuses it and the
 * producer counts it (failed, reconnect_buf_dropped).  @msg_id is the
 * JetStream Nats-Msg-Id (NUL-terminated), or NULL for a generated one;
 * core publishes carry none.  Shared by nats_evi_raise() (EVI transport)
 * and w_nats_publish() (script).  Returns 0 on publish success, -1
 * otherwise; the caller bumps the per-type success counter. */
static int nats_publish_checked(const char *subj, int subj_len,
		const char *payload, int payload_len, const char *msg_id,
		const char *ctx)
{
	char subj_buf[NATS_MAX_SUBJECT_LEN];

	if (subj_len >= (int)sizeof(subj_buf)) {
		LM_ERR("%s: NATS subject too long (%d bytes, max %d): %.*s\n",
			ctx, subj_len, (int)sizeof(subj_buf) - 1, subj_len, subj);
		return -1;
	}
	if (nats_validate_publish_subject(subj, subj_len) < 0) {
		LM_ERR("%s: NATS subject rejected (wildcard / control char / "
			"empty token / leading-trailing dot): %.*s\n",
			ctx, subj_len, subj);
		return -1;
	}
	memcpy(subj_buf, subj, subj_len);
	subj_buf[subj_len] = '\0';

	if (nats_jetstream)
		return nats_js_publish_async(subj_buf, payload, payload_len, msg_id);
	return nats_publish(subj_buf, payload, payload_len);
}

/* The msg_id rule of @ev_name, or NULL. */
static const nats_msg_id_rule *msg_id_rule_of(const str *ev_name)
{
	int i;

	if (!ev_name)
		return NULL;
	for (i = 0; i < msg_id_rule_cnt; i++)
		if (msg_id_rules[i].event.len == ev_name->len &&
		    memcmp(msg_id_rules[i].event.s, ev_name->s, ev_name->len) == 0)
			return &msg_id_rules[i];
	return NULL;
}

/* msg_id modparam: "EVENT: param, param, ..." -- one rule per event. */
static int nats_msg_id_param(modparam_t type, void *val)
{
	nats_msg_id_rule r;
	const char *spec = (const char *)val;

	if (msg_id_rule_cnt >= NATS_MSG_ID_MAX_RULES) {
		LM_ERR("msg_id: at most %d rules\n", NATS_MSG_ID_MAX_RULES);
		return -1;
	}
	if (!spec || nats_msg_id_rule_parse(spec, strlen(spec), &r) < 0) {
		LM_ERR("msg_id: '%s' is not \"EVENT: param, param, ...\" (an "
			"event name, then 1 to %d distinct parameter names)\n",
			spec ? spec : "", NATS_MSG_ID_MAX_PARAMS);
		return -1;
	}
	if (msg_id_rule_of(&r.event)) {
		LM_ERR("msg_id: a second rule for event %.*s\n",
			r.event.len, r.event.s);
		return -1;
	}
	msg_id_rules[msg_id_rule_cnt++] = r;
	return 0;
}

/**
 * nats_evi_raise() -- Publish an EVI event to a NATS subject.
 *
 * Builds a JSON payload from the EVI parameters, copies the subject
 * into a null-terminated stack buffer, and publishes via the pool
 * connection.  If the subject exceeds the 511-byte buffer, the publish
 * is rejected with an error (not silently truncated).
 *
 * Supports both core NATS publish and JetStream async publish depending
 * on the nats_jetstream module parameter.
 *
 * @param msg        Current SIP message (unused by NATS transport).
 * @param ev_name    Event name (included in the JSON payload).
 * @param sock       EVI socket containing the NATS subject prefix.
 * @param params     EVI parameter list to serialize as JSON.
 * @param async_ctx  Async status callback context (may be NULL).
 * @return           0 on success, -1 on error.
 */
static int nats_evi_raise(struct sip_msg *msg, str *ev_name,
	evi_reply_sock *sock, evi_params_t *params, evi_async_ctx_t *async_ctx)
{
	char *payload = NULL;
	int payload_len;
	int rc = -1;
	char id_buf[NATS_MSG_ID_BUF];
	const char *msg_id = NULL;
	const nats_msg_id_rule *rule;

	if (!sock) {
		LM_ERR("invalid evi socket\n");
		goto out;
	}

	/* the event's Nats-Msg-Id from its msg_id rule; without a rule, or
	 * if the event lacks a rule parameter, a generated one (NULL) */
	if (nats_jetstream && (rule = msg_id_rule_of(ev_name)) != NULL) {
		int n = nats_msg_id_build(rule, params, id_buf, sizeof id_buf);
		if (n > 0) {
			msg_id = id_buf;
		} else {
			static time_t rl;
			if (nats_rl_pass(&rl, time(NULL), 30))
				LM_WARN("msg_id of %.*s: %s; publishing it with a "
					"generated id (repeats suppressed for 30s)\n",
					ev_name->len, ev_name->s,
					n == NATS_MSG_ID_EMISSING ?
					"the event lacks a parameter of the rule" :
					"the id is longer than 255 bytes");
		}
	}

	payload = evi_build_payload(params, ev_name, 0, NULL, NULL);
	if (!payload) {
		LM_ERR("failed to build event payload\n");
		goto out;
	}
	payload_len = strlen(payload);

	rc = nats_publish_checked(sock->address.s, sock->address.len,
		payload, payload_len, msg_id, "nats_evi_raise");
	if (rc == 0)
		NATS_STATS_BUMP(evi_published);

out:
	if (payload)
		evi_free_payload(payload);

	/* report async status -- non-blocking publish, report immediately.
	 * Must run on every exit path so subscribers waiting on async
	 * status don't hang on early-failure returns. */
	if (async_ctx && async_ctx->status_cb) {
		async_ctx->status_cb(async_ctx->cb_param,
			rc == 0 ? EVI_STATUS_SUCCESS : EVI_STATUS_FAIL);
	}

	return rc;
}

/**
 * nats_evi_match() -- Compare two NATS EVI sockets for equality.
 *
 * Two sockets match if they have the same subject prefix (byte-exact
 * comparison).  Used by the EVI subsystem to deduplicate subscriptions.
 *
 * @param sock1  First socket to compare.
 * @param sock2  Second socket to compare.
 * @return       1 if sockets match, 0 otherwise.
 */
static int nats_evi_match(evi_reply_sock *sock1, evi_reply_sock *sock2)
{
	if (!sock1 || !sock2)
		return 0;

	if (!(sock1->flags & EVI_ADDRESS) || !(sock2->flags & EVI_ADDRESS))
		return 0;

	if (sock1->address.len != sock2->address.len)
		return 0;

	if (memcmp(sock1->address.s, sock2->address.s, sock1->address.len) != 0)
		return 0;

	return 1;
}

/**
 * nats_evi_free() -- Free a NATS EVI socket.
 *
 * Releases the shared-memory allocation for the socket.  The address
 * string is embedded in the same allocation, so a single shm_free
 * releases everything.
 *
 * @param sock  Socket to free (may be NULL).
 */
static void nats_evi_free(evi_reply_sock *sock)
{
	if (!sock)
		return;

	LM_DBG("freeing NATS socket: %.*s\n",
		sock->address.len, sock->address.s);

	shm_free(sock);
}

/**
 * nats_evi_print() -- Return a printable representation of a NATS EVI socket.
 *
 * Returns the subject prefix stored in sock->address.  Used by the EVI
 * subsystem for logging and MI output.
 *
 * @param sock  Socket to print.
 * @return      str containing the subject prefix.
 */
static str nats_evi_print(evi_reply_sock *sock)
{
	/* address.s is embedded right after the sock struct */
	return sock->address;
}

/**
 * w_nats_publish() -- Script function: nats_publish(subject, payload[, msg_id]).
 *
 * Publishes a message to a NATS subject directly from an opensips.cfg
 * routing script.  The subject is copied into a null-terminated stack
 * buffer; if it exceeds the 511-byte limit, the publish is rejected
 * with an error (not silently truncated).
 *
 * Uses JetStream async publish when the jetstream module parameter is
 * enabled, otherwise uses core NATS publish.
 *
 * @param msg      Current SIP message context.
 * @param subject  NATS subject to publish to.
 * @param payload  Message payload (typically JSON).
 * @param msg_id   Optional JetStream Nats-Msg-Id (NULL: generated).
 * @return         1 on success, -1 on error (OpenSIPS script convention).
 */
static int w_nats_publish(struct sip_msg *msg, str *subject, str *payload,
	str *msg_id)
{
	char id_buf[NATS_MSG_ID_BUF];
	const char *id = NULL;
	int rc;

	if (!subject || !subject->len || !subject->s) {
		LM_ERR("missing NATS subject\n");
		return -1;
	}
	if (!payload || !payload->len || !payload->s) {
		LM_ERR("missing NATS payload\n");
		return -1;
	}
	if (msg_id) {
		if (nats_msg_id_check(msg_id->s, msg_id->len) < 0) {
			LM_ERR("nats_publish: msg_id must be 1 to %d printable "
				"characters without spaces\n", NATS_MSG_ID_MAX);
			return -1;
		}
		memcpy(id_buf, msg_id->s, msg_id->len);
		id_buf[msg_id->len] = '\0';
		id = id_buf;
	}

	rc = nats_publish_checked(subject->s, subject->len,
		payload->s, payload->len, id, "nats_publish");
	if (rc == 0)
		NATS_STATS_BUMP(script_published);

	return rc == 0 ? 1 : -1;
}

/*
 * nats_evi_js_ack_cb -- registered with the pool, invoked from a
 * cnats-internal I/O thread when a JetStream publish-ack arrives.
 *
 * MUST stay free of OpenSIPS APIs.  Only atomic ops on shared SHM
 * counters are safe here.  See modules-contrib/nats/nats_pool.h for the full
 * thread-safety contract.
 */
static void nats_evi_js_ack_cb(int outcome)
{
	switch (outcome) {
	case NATS_PUB_ACK_OK:
		NATS_STATS_BUMP(js_ack_ok);
		break;
	case NATS_PUB_ACK_DUPLICATE:
		/* stored once: an earlier copy (a resend's original, or the
		 * same id published again) is in the stream */
		NATS_STATS_BUMP(js_ack_ok);
		NATS_STATS_BUMP(js_duplicate);
		break;
	case NATS_PUB_ACK_RETRIED:
		NATS_STATS_BUMP(js_retried);
		break;
	case NATS_PUB_ACK_FAILED_BUFFER_FULL:
		NATS_STATS_BUMP(js_ack_failed);
		NATS_STATS_BUMP(reconnect_buf_dropped);
		break;
	case NATS_PUB_ACK_FAILED_PENDING_FULL:
		NATS_STATS_BUMP(js_ack_failed);
		NATS_STATS_BUMP(js_pending_dropped);
		break;
	default:
		NATS_STATS_BUMP(js_ack_failed);
		break;
	}
}

#ifdef UNIT_TESTS
int event_nats_test_child_init(int rank)
{
	return child_init(rank);
}

void event_nats_test_mod_destroy(void)
{
	mod_destroy();
}

void event_nats_test_js_ack_cb(int outcome)
{
	nats_evi_js_ack_cb(outcome);
}

const evi_export_t *event_nats_test_transport(void)
{
	return &trans_export_nats;
}
#endif
