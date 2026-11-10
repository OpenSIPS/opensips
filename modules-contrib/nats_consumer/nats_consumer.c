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
 * nats_consumer.c -- module lifecycle + registrations.
 *
 * Script-surface exports:
 *   - sync  cmd:   nats_fetch(id, timeout_ms),
 *                  nats_fetch_batch(id, opts), nats_batch_select(i),
 *                  nats_ack(), nats_ack_next(), nats_ack_progress(),
 *                  nats_nak(), nats_nak_delay(delay_ms),
 *                  nats_term(), nats_in_progress(),
 *                  nats_hdr_set(name, value),
 *                  nats_reply(payload),
 *                  nats_request(subject, payload, timeout_ms)
 *   - async acmd:  nats_fetch(id, timeout_ms),
 *                  nats_fetch_batch(id, opts)
 *   - pvars:       $nats_subject, $nats_data, $nats_reply_to,
 *                  $nats_seq, $nats_consumer_seq, $nats_delivered,
 *                  $nats_pending, $nats_token, $nats_hdr(Name)
 *
 * IMPORTANT: nats_request() is SYNC-ONLY -- it blocks the calling
 * worker for up to timeout_ms.  Restrict callsites to timer_route /
 * startup_route until an async variant is added.  See nats_rpc.c /
 * nats_rpc.h for the full rationale.
 */

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../nats/nats_bind_mod.h"
#include "../nats/nats_pool.h"
#include "nats_consumer.h"
#include "nats_handle_parse.h"
#include "nats_handle_registry.h"
#include "nats_mi.h"
#include "nats_ack_ipc.h"
#include "nats_consumer_proc.h"
#include "nats_fetch.h"
#include "nats_ack.h"
#include "nats_rpc.h"
#include "nats_rpc_async.h"
#include "nats_rpc_slot.h"
#include "nats_rpc_ipc.h"
#include "nats_rpc_consumer.h"

static int  mod_init(void);
static int  child_init(int rank);
static void mod_destroy(void);

/* w_nats_consumer_bind() -- script wrapper for the bind API.
 *
 * Same parse + register sequence as the MI command's mi_consumer_bind
 * (nats_mi.c), expressed as a cmd_export so operators can write the
 * canonical OpenSIPS pattern:
 *
 *     startup_route {
 *         nats_consumer_bind("id=jobs;stream=jobs;subject=jobs.>");
 *         nats_consumer_bind("id=audit;stream=audit;subject=audit.>");
 *     }
 *
 * Restricted to STARTUP_ROUTE: bindings define the consumer-process's
 * fetch handles, which the consumer process reads at child_init.
 * Calling from request_route would mean "modify the registry mid-flight"
 * which is doable via the MI path but isn't what the script API is
 * documented to express.
 *
 * Returns 1 on success, -1 on parse/registry/duplicate-id error.  The
 * specific error reason is logged at LM_ERR; script callers can branch
 * on $retcode.  Mirrors the MI handler's error mapping (parse -> 400,
 * dup -> 409, OOM -> 500) but collapses to a single -1 since cmd_export
 * doesn't carry status codes.
 */
/* One bind core shared by the script function, the declarative `bind`
 * modparam loop in mod_init and (indirectly, same shape) the MI
 * handler: parse the config string, bind into the registry, log.
 * Returns 0 on success; on failure logs with @who context and returns
 * -1 (the handle is freed). */
static int bind_one_config(const str *config_str, const char *who)
{
	const char    *err = NULL;
	nats_handle_t *h;
	int            rc;

	if (!config_str || config_str->len <= 0 || !config_str->s) {
		LM_ERR("%s: empty/null config string\n", who);
		return -1;
	}

	h = nats_handle_parse(config_str, &err);
	if (!h) {
		if (!err) err = "parse error";
		LM_ERR("%s: parse failed: %s (config '%.*s')\n", who, err,
			config_str->len, config_str->s);
		return -1;
	}

	rc = nats_registry_bind(h);
	if (rc != 0) {
		LM_ERR("%s: bind failed for id '%.*s': %s\n", who,
			h->id.len, h->id.s,
			rc == -1 ? "duplicate id" :
			rc == -3 ? "handle count limit reached" :
			           "registry full or OOM");
		nats_handle_free(h);
		return -1;
	}

	LM_INFO("nats_consumer: bound handle id=%.*s stream=%.*s (%s)\n",
		h->id.len, h->id.s, h->stream.len, h->stream.s, who);
	return 0;
}

static int w_nats_consumer_bind(struct sip_msg *msg, str *config_str)
{
	(void)msg;
	return bind_one_config(config_str, "nats_consumer_bind") == 0 ? 1 : -1;
}

/* ── script-callable commands ────────────────────────────────── */

/* NOT `const` -- the allow_sync_anywhere modparam setter
 * widens the nats_request entry's route mask in-place when an
 * operator opts into worker-blocking sync calls from the SIP
 * worker contexts (REQUEST/FAILURE/BRANCH/ERROR routes).  See
 * nats_request_allow_sync_setter(). */
static cmd_export_t cmds[] = {
	{ "nats_fetch", (cmd_function)w_nats_fetch, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_fetch_batch", (cmd_function)w_nats_fetch_batch, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_batch_select", (cmd_function)w_nats_batch_select, {
		{CMD_PARAM_INT, 0, 0},
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_ack", (cmd_function)w_nats_ack, {
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_ack_next", (cmd_function)w_nats_ack_next, {
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_ack_progress", (cmd_function)w_nats_ack_progress, {
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_nak", (cmd_function)w_nats_nak, {
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_nak_delay", (cmd_function)w_nats_nak_delay, {
		{CMD_PARAM_INT, 0, 0},
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_term", (cmd_function)w_nats_term, {
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_in_progress", (cmd_function)w_nats_in_progress, {
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_hdr_set", (cmd_function)w_nats_hdr_set, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{0, 0, 0}},
		ALL_ROUTES },
	{ "nats_reply", (cmd_function)w_nats_reply, {
		{CMD_PARAM_STR, 0, 0},
		{0, 0, 0}},
		ALL_ROUTES },
	/* The sync `nats_request` blocks the calling worker on
	 * natsConnection_RequestMsg for up to timeout_ms.  By default
	 * we restrict the route mask so the engine refuses the call
	 * from contexts where blocking a SIP UDP/TCP worker would
	 * stall request processing (REQUEST_ROUTE, FAILURE_ROUTE,
	 * BRANCH_ROUTE, ERROR_ROUTE).  Allowed from STARTUP / TIMER /
	 * LOCAL / EVENT / ONREPLY routes, which either don't own a
	 * SIP worker (startup, timer, event) or already accept
	 * synchronous semantics (local, onreply).
	 *
	 * Operators who want the sync ergonomics from a worker route
	 * (low-RPS deployments, a thin SIP gateway in front, etc.)
	 * opt in via `modparam("nats_consumer",
	 * "allow_sync_anywhere", 1)`; the setter widens this entry's
	 * flags to ALL_ROUTES in place and emits an LM_WARN listing
	 * the per-route blocking consequences so the operator cannot
	 * miss them.  Most deployments should leave the safer default
	 * and use `async(nats_request(...), rt)` from worker contexts
	 * instead -- it yields to the reactor on a per-call eventfd
	 * rather than blocking. */
	{ "nats_request", (cmd_function)w_nats_request, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{0, 0, 0}},
		ONREPLY_ROUTE | LOCAL_ROUTE | STARTUP_ROUTE |
		TIMER_ROUTE | EVENT_ROUTE },
	/* Script wrapper for the registry bind API.  STARTUP_ROUTE only:
	 * binds define the consumer-process's pull handles, which are
	 * read at child_init.  Mid-flight binds belong on the MI path. */
	{ "nats_consumer_bind", (cmd_function)w_nats_consumer_bind, {
		{CMD_PARAM_STR, 0, 0},
		{0, 0, 0}},
		STARTUP_ROUTE },
	{ 0, 0, {{0, 0, 0}}, 0 }
};

static const acmd_export_t acmds[] = {
	{ "nats_fetch", (acmd_function)w_nats_fetch_async, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{0, 0, 0}} },
	{ "nats_fetch_batch", (acmd_function)w_nats_fetch_batch_async, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{0, 0, 0}} },
	/* `nats_request` is also registered above as a sync cmd with a
	 * restrictive route mask.  The dispatch between sync and async is
	 * driven by call-site syntax: `nats_request(...)` resolves to the
	 * sync entry, `async(nats_request(...), rt)` resolves here. */
	{ "nats_request", (acmd_function)w_nats_request_async, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{0, 0, 0}} },
	{ 0, 0, {{0, 0, 0}} }
};

/* ── modparams ───────────────────────────────────────────────── */

/* Declarative handle binds.  Each `bind` modparam
 * value uses the same config grammar as nats_consumer_bind(); values
 * are queued at cfg-parse time and bound in mod_init right after the
 * registry comes up.  A bad or duplicate declarative bind FAILS
 * mod_init.  (The former file-persistence layer was deleted: with
 * binds declarative in the .cfg there is nothing to rehydrate.
 * Runtime MI binds remain available but are ephemeral.) */
struct bind_cfg {
	str s;
	struct bind_cfg *next;
};
static struct bind_cfg *bind_cfg_head = NULL;
static struct bind_cfg **bind_cfg_tail = &bind_cfg_head;

static int set_bind_param(modparam_t type, void *val)
{
	struct bind_cfg *bc;
	char *v = (char *)val;

	(void)type;
	if (!v || !*v) {
		LM_ERR("nats_consumer: empty bind modparam\n");
		return -1;
	}
	bc = pkg_malloc(sizeof(*bc));
	if (!bc)
		return -1;
	bc->s.s = v;                 /* cfg-parser-owned, process lifetime */
	bc->s.len = (int)strlen(v);
	bc->next = NULL;
	*bind_cfg_tail = bc;
	bind_cfg_tail = &bc->next;
	return 0;
}

/* Module-global Fetch tuning.  Per-handle bind keys (`fetch_batch=`,
 * `fetch_timeout_ms=`) override these for a single handle; the
 * consumer process resolves the effective values at every Fetch call.
 * Defaults stay conservative (10 msgs / 1 s) so the module behaves
 * the same after upgrade for operators who do not set anything. */
int nats_consumer_fetch_batch      = 10;
int nats_consumer_fetch_timeout_ms = 1000;

/* Consumer-side poison-message cap.  With max_deliver=0 (the JetStream
 * default) the broker redelivers a message that always fails processing
 * forever, with no dead-letter -- one poison message can wedge a handle.
 * When this is > 0 the consumer Terms any message whose NumDelivered
 * exceeds it (a dead-letter backstop) and bumps the per-handle `poisoned`
 * counter.  0 disables the backstop (unlimited redelivery). */
int nats_consumer_poison_max_deliver = 20;

/* Outbound header name used to carry the per-call UUIDv7
 * correlation id auto-minted by both the sync and async
 * `nats_request` start paths.  Default `X-Request-Id`, following
 * the most-common cross-system convention.  An empty string
 * disables auto-staging entirely: the id is still minted and
 * readable as $nats_request_id, just not put on the wire.
 *
 * A script that manually stages the same header via
 * nats_hdr_set("X-Request-Id", $var(my_id)) BEFORE calling
 * nats_request wins -- the auto-stager only sets the header when
 * no entry with the same (case-insensitive) name is already on
 * the worker's outbound buffer. */
char *nats_request_id_header = "X-Request-Id";

/* strlen(nats_request_id_header), computed ONCE at mod_init --
 * the modparam is immutable after startup, yet both RPC start paths
 * used to re-measure it per request.  0 when auto-staging is off. */
int nats_request_id_header_len;

/* NATS connection parameters.  nats_consumer registers its own pool so it
 * works when loaded WITHOUT event_nats / cachedb_nats; the modules-contrib/nats pool
 * merges registrations when several NATS modules are loaded.  When nats_url
 * is unset the default localhost is registered only if no other module
 * already registered (see mod_init), to avoid injecting a spurious server
 * into a co-loaded module's pool. */
static char *nats_url = NULL;
static int   nats_reconnect_wait_ms = 0;   /* 0 = modules-contrib/nats default */
static int   nats_max_reconnect     = 0;   /* 0 = modules-contrib/nats default */
/* Set iff this module's own nats_pool_register() succeeded, so mod_destroy
 * unregisters exactly once (registration is conditional). */
static int   _pool_registered = 0;

/*
 * USE_FUNC_PARAM setter for `allow_sync_anywhere`.
 *
 * Runs at config-parse time, the moment OpenSIPS sees the
 * `modparam("nats_consumer", "allow_sync_anywhere", 1)`
 * directive.  Because modparam directives are processed strictly
 * before route blocks are parsed (and the route-mask validation
 * happens at route-block parse time), this setter is in a position
 * to widen the cmds[]'s nats_request entry's flag word before any
 * call site is checked against it.
 *
 * Setting val=0 (or omitting the modparam entirely) leaves the
 * default restrictive mask.  Setting val=1 widens to ALL_ROUTES so
 * sync nats_request is callable from every worker context --
 * REQUEST_ROUTE, FAILURE_ROUTE, BRANCH_ROUTE, ERROR_ROUTE -- in
 * addition to the always-permitted STARTUP/TIMER/LOCAL/EVENT/
 * ONREPLY contexts.  Setting anything else is reported as a parse
 * error so a typo cannot silently disarm the safety guard.
 *
 * A multi-line LM_WARN spells out the per-route blocking
 * consequences so the operator who opts in cannot miss them.
 */
static int nats_request_allow_sync_setter(modparam_t type, void *val)
{
	int       want;
	unsigned  i;

	if ((type & PARAM_TYPE_MASK(INT_PARAM)) == 0) {
		LM_ERR("allow_sync_anywhere: must be an integer\n");
		return -1;
	}
	want = (int)(long)val;
	if (want != 0 && want != 1) {
		LM_ERR("allow_sync_anywhere: expected 0 or 1, got %d\n",
			want);
		return -1;
	}
	if (want == 0)
		return 0;   /* default behaviour; no mutation needed */

	for (i = 0; cmds[i].name; i++) {
		if (strcmp(cmds[i].name, "nats_request") == 0) {
			cmds[i].flags = ALL_ROUTES;
			LM_WARN(
"================================================================\n"
"  allow_sync_anywhere=1\n"
"  nats_request route mask widened to ALL_ROUTES.\n"
"\n"
"  Sync calls to nats_request(...) from these routes will BLOCK\n"
"  the executing process for up to timeout_ms while the libnats\n"
"  request/reply round-trip is in flight.  Per-route blast\n"
"  radius (verified against the OpenSIPS source paths):\n"
"\n"
"    REQUEST_ROUTE  Runs on the SIP worker that received the\n"
"                   request (receive.c run_top_route).  The\n"
"                   worker cannot read its next SIP packet for\n"
"                   the duration; under load the recv backlog\n"
"                   grows on this worker's interface.\n"
"\n"
"    FAILURE_ROUTE  Two invocation paths with DIFFERENT blast\n"
"                   radius:\n"
"                   * Negative-reply trigger -- runs on the SIP\n"
"                     worker that received the reply\n"
"                     (tm/t_reply.c run_failure_handlers).\n"
"                     Same blast radius as REQUEST_ROUTE\n"
"                     blocking on that worker; async()\n"
"                     IS available from this trigger path.\n"
"                   * fr_timer / fr_inv_timer expiry -- runs\n"
"                     inline on the single-threaded TIMER\n"
"                     TICKER process (timer.c run_timer_process,\n"
"                     forked by start_timer_processes).  This\n"
"                     process is a bare select(0,0,0,0,&tv)\n"
"                     loop with NO reactor; it just fires C-\n"
"                     level callbacks registered via\n"
"                     register_timer().  Blocking it queues\n"
"                     every other transaction's fr_timer fire,\n"
"                     every other module's tick callback\n"
"                     (retransmissions, watchdogs, etc.) until\n"
"                     the block clears.  Worse blast radius\n"
"                     than blocking a single SIP worker, AND\n"
"                     async() is NOT available from this\n"
"                     trigger path because the ticker has no\n"
"                     reactor -- there is no non-blocking\n"
"                     option in this module for fr_timer-\n"
"                     triggered failure_route today.\n"
"\n"
"    BRANCH_ROUTE   Runs on the SIP worker that is fanning out\n"
"                   the transaction's outbound branches\n"
"                   (tm/t_fwd.c pre_print_uac_request).  The\n"
"                   per-branch INVITE/REGISTER send is delayed\n"
"                   by up to timeout_ms; subsequent branches in\n"
"                   the same transaction also wait.\n"
"\n"
"    ERROR_ROUTE    Runs on the SIP worker that hit a parse\n"
"                   error on an inbound request (receive.c) or\n"
"                   that tripped an in-action error\n"
"                   (action.c).  Blocking delays the error\n"
"                   response back to the peer.\n"
"\n"
"  Note that timer_route { ... } blocks (NOT to be confused\n"
"  with the C-level timer callbacks above) run on a separate\n"
"  Timer handler process that DOES have a full reactor and\n"
"  DOES support async() -- they are unaffected by this\n"
"  limitation.\n"
"\n"
"  Strongly recommended for any worker route:\n"
"      async(nats_request(subj, payload, tmo), reply_route)\n"
"  -- yields to the reactor instead of blocking, and is\n"
"  accepted regardless of this modparam.  Use it from every\n"
"  reactor-backed context (request_route, branch_route,\n"
"  error_route, timer_route, event_route, onreply_route,\n"
"  failure_route via reply trigger).  Only fr_timer-triggered\n"
"  failure_route has no non-blocking option today; an\n"
"  upstream TM change to dispatch fr_timer expiry through a\n"
"  Timer handler instead of running it inline on the ticker\n"
"  would lift that restriction.\n"
"================================================================\n"
			);
			return 0;
		}
	}
	LM_ERR("allow_sync_anywhere: nats_request entry not "
		"found in cmds[] -- module table layout drift?\n");
	return -1;
}

/* the nats module API (nats_bind_mod.h), bound in mod_init */
struct nats_binds nats_api;
/* settings of the shared connection, forwarded to the nats module */
NATS_ALIAS_SETTER(creds_file)
NATS_ALIAS_SETTER(nkey)
NATS_ALIAS_SETTER(nkey_seed_file)
NATS_ALIAS_SETTER(no_randomize)
NATS_ALIAS_SETTER(password)
NATS_ALIAS_SETTER(reconnect_buf_size)
NATS_ALIAS_SETTER(token)
NATS_ALIAS_SETTER(user)

static const param_export_t params[] = {
	{ "nats_url",          STR_PARAM, &nats_url },
	{ "reconnect_wait_ms", INT_PARAM, &nats_reconnect_wait_ms },
	{ "max_reconnect",     INT_PARAM, &nats_max_reconnect },
	/* server order of the shared connection (ONE pool value; see
	 * nats_pool_no_randomize_decide for the merge contract) */
	{ "no_randomize",      INT_PARAM|USE_FUNC_PARAM,
	                       (void *)nats_alias_no_randomize },
	/* reconnect buffer of the shared connection (ONE pool value; see
	 * nats_pool_reconnect_buf_size_decide for the merge contract) */
	{ "reconnect_buf_size", INT_PARAM|USE_FUNC_PARAM,
	                       (void *)nats_alias_reconnect_buf_size },
	/* Credentials of the shared connection (ONE pool value each; see
	 * modules-contrib/nats/nats_auth.h), so no secret has to be inside a URL. */
	{ "user",             STR_PARAM|USE_FUNC_PARAM,
	                       (void *)nats_alias_user },
	{ "password",         STR_PARAM|USE_FUNC_PARAM,
	                       (void *)nats_alias_password },
	{ "token",            STR_PARAM|USE_FUNC_PARAM,
	                       (void *)nats_alias_token },
	{ "creds_file",       STR_PARAM|USE_FUNC_PARAM,
	                       (void *)nats_alias_creds_file },
	{ "nkey",             STR_PARAM|USE_FUNC_PARAM,
	                       (void *)nats_alias_nkey },
	{ "nkey_seed_file",   STR_PARAM|USE_FUNC_PARAM,
	                       (void *)nats_alias_nkey_seed_file },
	{ "bind",              STR_PARAM|USE_FUNC_PARAM,
	                       (void *)set_bind_param },
	{ "fetch_batch",       INT_PARAM, &nats_consumer_fetch_batch       },
	{ "fetch_timeout_ms",  INT_PARAM, &nats_consumer_fetch_timeout_ms  },
	{ "poison_max_deliver",INT_PARAM, &nats_consumer_poison_max_deliver },
	{ "allow_sync_anywhere",
	      INT_PARAM | USE_FUNC_PARAM,
	      (void *)nats_request_allow_sync_setter },
	{ "request_id_header", STR_PARAM, &nats_request_id_header },
	{ "async_rpc_slots",   INT_PARAM, &nats_rpc_slot_count },
	{ "async_rpc_poll_ms", INT_PARAM, &nats_rpc_async_poll_ms },
	{ 0, 0, 0 }
};

/* ── pseudo-variables ────────────────────────────────────────── */

static const pv_export_t mod_pvars[] = {
	{ str_const_init("nats_subject"),      1000, pv_get_nats_subject,
		0, 0, 0, 0, 0 },
	{ str_const_init("nats_data"),         1000, pv_get_nats_data,
		0, 0, 0, 0, 0 },
	{ str_const_init("nats_reply_to"),     1000, pv_get_nats_reply_to,
		0, 0, 0, 0, 0 },
	{ str_const_init("nats_seq"),          1000, pv_get_nats_seq,
		0, 0, 0, 0, 0 },
	{ str_const_init("nats_consumer_seq"), 1000, pv_get_nats_consumer_seq,
		0, 0, 0, 0, 0 },
	{ str_const_init("nats_delivered"),    1000, pv_get_nats_delivered,
		0, 0, 0, 0, 0 },
	{ str_const_init("nats_pending"),      1000, pv_get_nats_pending,
		0, 0, 0, 0, 0 },
	{ str_const_init("nats_token"),        1000, pv_get_nats_token,
		0, 0, 0, 0, 0 },
	{ str_const_init("nats_hdr"),          1000, pv_get_nats_hdr,
		0, pv_parse_nats_hdr_name, 0, 0, 0 },
	{ str_const_init("nats_request_id"),   1000, pv_get_nats_request_id,
		pv_set_nats_request_id, 0, 0, 0, 0 },
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

/* Dedicated JetStream pull consumer process.
 * One instance -- there is a single process for the module. */
static const proc_export_t procs[] = {
	{ "NATS consumer", 0, 0, nats_consumer_proc_main, 1,
		PROC_FLAG_HAS_IPC /* receives worker ack/RPC jobs */ },
	{ 0, 0, 0, 0, 0, 0 }
};

/* tls_mgm bind table -- handed to modules-contrib/nats so the pool's connect path
 * can look up the "nats" client domain for tls:// URLs.  DEP_SILENT
 * lets plaintext-only deployments load nats_consumer without tls_mgm. */

static const dep_export_t deps = {
	{
		{ MOD_TYPE_DEFAULT, "nats", DEP_ABORT },
		{MOD_TYPE_DEFAULT, "tls_mgm", DEP_SILENT},
		{MOD_TYPE_NULL, NULL, 0},
	},
	{
		{NULL, NULL},
	},
};

struct module_exports exports = {
	"nats_consumer",            /* module name */
	MOD_TYPE_DEFAULT,           /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	0,                          /* load function */
	&deps,                      /* OpenSIPS module dependencies */
	cmds,                       /* exported functions */
	acmds,                      /* exported async functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	nats_consumer_mi_cmds,      /* exported MI functions */
	mod_pvars,                  /* exported pseudo-variables */
	0,                          /* exported transformations */
	procs,                      /* extra processes -- NATS consumer */
	0,                          /* module pre-initialization function */
	mod_init,                   /* module initialization function */
	0,                          /* response handling function */
	mod_destroy,                /* destroy function */
	child_init,                 /* per-child init function */
	0                           /* reload confirm function */
};

static int mod_init(void)
{
	LM_INFO("nats_consumer %s initializing\n", NATS_CONSUMER_VERSION);

	if (nats_bind_api("nats_consumer") < 0)
		return -1;

	/* cache the request-id header length (config constant;
	 * the RPC start paths consume it per request). */
	nats_request_id_header_len = nats_request_id_header
		? (int)strlen(nats_request_id_header) : 0;

	/* Bind tls_mgm if loaded; hand the bind table to modules-contrib/nats so the
	 * pool's connect path can look up the "nats" client domain.  No
	 * effect on plaintext (nats://) URLs; tls:// URLs error at
	 * connect time if tls_mgm isn't bound or the "nats" domain
	 * isn't defined.
	 *
	 * Bind tls_mgm before registering the pool so the "nats" client
	 * domain is available to the connect path for tls:// URLs. */
	nats_pool_bind_tls("nats_consumer");

	/* Register our own pool so nats_consumer works when loaded WITHOUT
	 * event_nats / cachedb_nats (those previously had to register first;
	 * loaded alone the consumer process aborted at nats_pool_get()).  The
	 * modules-contrib/nats pool merges registrations, so this is safe alongside them.
	 * When nats_url is unset, register the localhost default: the pool
	 * uses it only if no module configures servers, whatever the module
	 * load order. */
	if (nats_url) {
		if (nats_pool_register(nats_url, "nats_consumer",
				nats_reconnect_wait_ms, nats_max_reconnect) < 0) {
			LM_ERR("nats_consumer: NATS pool registration failed\n");
			return -1;
		}
		_pool_registered = 1;
	} else {
		if (!nats_pool_is_registered())
			LM_WARN("nats_consumer: no nats_url set; defaulting to "
				"nats://localhost:4222 unless another NATS module "
				"configures servers\n");
		if (nats_pool_register_default("nats://localhost:4222", "nats_consumer",
				nats_reconnect_wait_ms, nats_max_reconnect) < 0) {
			LM_ERR("nats_consumer: NATS pool registration failed\n");
			return -1;
		}
		_pool_registered = 1;
	}

	if (nats_registry_init(NATS_CONSUMER_REGISTRY_BUCKETS) < 0) {
		LM_ERR("nats_consumer: registry init failed\n");
		return -1;
	}
#ifdef UNIT_TESTS
	if (nc_ut_hold_init() < 0) {
		LM_ERR("nats_consumer: unit test hold init failed\n");
		return -1;
	}
#endif
	LM_DBG("nats_consumer: registry ready (%d buckets)\n",
		NATS_CONSUMER_REGISTRY_BUCKETS);

	/* Worker acks ride core IPC; only the SHM stat counters
	 * need setup.  Non-fatal: if SHM is short, stats read as zero. */
	if (nats_ack_ipc_stats_init() < 0) {
		LM_WARN("nats_consumer: ack IPC stats init failed; "
			"ack_ipc_* MI stats will read as zero\n");
	}

	/* Allocate the SHM slot pool + eventfd pool for the
	 * consumer-process-routed async nats_request transport.
	 * Must happen pre-fork so every child inherits the
	 * eventfds at the same numeric fd values.  Tolerant to
	 * failure (slot allocation requires NATS_RPC_SLOT_COUNT
	 * fds, which may exceed ulimit on small deployments) --
	 * we log and continue with the sync fall-through. */
	if (nats_rpc_slot_init() < 0) {
		LM_WARN("nats_consumer: rpc slot pool init failed; "
			"async nats_request will fall back to the sync "
			"path until the slot pool is available\n");
		/* deliberately non-fatal */
	}

	/* Worker -> consumer-process publish hop for the async transport
	 * rides core IPC; only its SHM stat counters need setup.
	 * Non-fatal: if SHM is short, stats read as zero. */
	if (nats_rpc_ipc_stats_init() < 0) {
		LM_WARN("nats_consumer: rpc IPC stats init failed; "
			"rpc_ipc_* MI stats will read as zero\n");
	}

	if (nats_consumer_hb_init() < 0) {
		LM_ERR("nats_consumer: heartbeat SHM alloc failed\n");
		nats_ack_ipc_stats_destroy();
		nats_registry_destroy();
		return -1;
	}

	/* Declarative binds: bind every queued `bind`
	 * modparam config now that the registry + rings + IPC are up.  A
	 * failure here is a config error and fails the boot. */
	{
		struct bind_cfg *bc;
		for (bc = bind_cfg_head; bc; bc = bc->next) {
			if (bind_one_config(&bc->s, "bind modparam") < 0) {
				nats_rpc_slot_destroy();
				nats_rpc_ipc_stats_destroy();
				nats_ack_ipc_stats_destroy();
				nats_registry_destroy();
				return -1;
			}
		}
	}

	return 0;
}

static int child_init(int rank)
{
	if (!nats_pool_should_init(rank)) {
		LM_DBG("nats_consumer: skipping rank=%d\n", rank);
		return 0;
	}
	LM_DBG("nats_consumer: child_init rank=%d\n", rank);
	/* Bring up this process's pool connection now, as event_nats does:
	 * nats_request() / nats_fetch() fast-fail while the process is not
	 * connected, and nothing else connects a SIP worker when
	 * nats_consumer is the only NATS module loaded.  A broker that is
	 * down only means a degraded start (the pool keeps connecting). */
	if (!nats_pool_get())
		LM_WARN("nats_consumer: no NATS connection yet (broker down?) -- "
			"starting degraded; requests fail until it is reachable\n");
	return 0;
}

static void mod_destroy(void)
{
	LM_INFO("nats_consumer: shutting down\n");
	/* Order matters: ack IPC before the registry (so any future drain
	 * path can flush before the registry disappears underneath it). */
	nats_ack_ipc_stats_destroy();
	nats_rpc_ipc_stats_destroy();
	nats_rpc_slot_destroy();
	nats_consumer_hb_destroy();
	nats_registry_destroy();
	/* Drop our pool reference iff we registered one (registration is
	 * conditional -- when another NATS module owns the pool we inherit
	 * it and must not unregister it). */
	if (_pool_registered)
		nats_pool_unregister();
}

#ifdef UNIT_TESTS
/* Whether this module's own pool registration succeeded in mod_init. */
int nc_ut_pool_registered(void)
{
	return _pool_registered;
}
#endif
