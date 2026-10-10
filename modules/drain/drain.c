/*
 * Graceful traffic drain support for OpenSIPS
 *
 * Copyright (C) 2026 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#include <string.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../atomic.h"
#include "../../locking.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"
#include "../../parser/parse_to.h"
#include "../../script_cb.h"
#include "../../statistics.h"
#include "../../status_report.h"
#include "../../timer.h"
#include "../../evi/evi_modules.h"
#include "../../evi/evi_params.h"
#include "../sl/sl_api.h"
#include "../tm/tm_load.h"

#define DRAIN_EVENT_STATE_NAME "E_DRAIN_STATE_CHANGED"
#define DRAIN_EVENT_COMPLETE_NAME "E_DRAIN_COMPLETE"

static int mod_init(void);
static void mod_destroy(void);
static int drain_pre_request(struct sip_msg *msg, void *param);
static int w_drain_enabled(struct sip_msg *msg);
static int w_drain_reject(struct sip_msg *msg);
static mi_response_t *mi_drain_enable(const mi_params_t *params,
		struct mi_handler *async_hdl);
static mi_response_t *mi_drain_status(const mi_params_t *params,
		struct mi_handler *async_hdl);
static void drain_timer(unsigned int ticks, void *param);

static int drain_initial_state = 0;
static int drain_auto_reject = 1;
static int drain_reject_invites = 1;
static int drain_reject_registers = 1;
static int drain_wait_transactions = 1;
static int drain_reply_code = 503;
static str drain_reply_reason = str_init("Service Unavailable");

static atomic_t *drain_state;
static atomic_t *drain_complete_emitted;
static gen_lock_t *drain_lock;
static void *drain_srg;
static struct sl_binds slb;
static struct tm_binds tmb;

static stat_var *rejected_requests;
static stat_var *dialog_active_stat;
static stat_var *dialog_early_stat;
static stat_var *tm_inuse_stat;

static str dialog_module_name = str_init("dialog");
static str tm_module_name = str_init("tm");
static str active_dialogs_name = str_init("active_dialogs");
static str early_dialogs_name = str_init("early_dialogs");
static str inuse_transactions_name = str_init("inuse_transactions");

static str drain_state_event_name = str_init(DRAIN_EVENT_STATE_NAME);
static str drain_complete_event_name = str_init(DRAIN_EVENT_COMPLETE_NAME);
static event_id_t drain_state_event = EVI_ERROR;
static event_id_t drain_complete_event = EVI_ERROR;

static stat_var *get_module_stat(str *module_name, str *stat_name)
{
	module_stats *mod;

	mod = get_stat_module(module_name);
	if (!mod)
		return NULL;
	return __get_stat(stat_name, mod->idx);
}

static unsigned long drain_stat_state(void *unused)
{
	(void)unused;
	return drain_state && atomic_load(drain_state) ? 1 : 0;
}

/*
 * The dialog/tm statistics are resolved once in mod_init() (both modules
 * are initialized before us thanks to the DEP_ABORT dependencies), so the
 * pointers are inherited by all the worker processes.
 */
static int drain_resolve_stats(void)
{
	dialog_active_stat = get_module_stat(&dialog_module_name,
		&active_dialogs_name);
	dialog_early_stat = get_module_stat(&dialog_module_name,
		&early_dialogs_name);
	if (!dialog_active_stat || !dialog_early_stat) {
		LM_ERR("dialog statistics are not available, but they are required "
			"to track the remaining calls - make sure the dialog module "
			"is loaded with \"enable_stats\" turned on\n");
		return -1;
	}

	tm_inuse_stat = get_module_stat(&tm_module_name,
		&inuse_transactions_name);
	if (!tm_inuse_stat) {
		if (drain_wait_transactions) {
			LM_ERR("tm statistics are not available, but they are required "
				"by \"wait_transactions\" - make sure the tm module is "
				"loaded with \"enable_stats\" turned on\n");
			return -1;
		}
		LM_WARN("tm statistics are not available, the "
			"\"inuse_transactions\" gauge will always report 0\n");
	}

	return 0;
}

static unsigned long drain_stat_active_dialogs(void *unused)
{
	return dialog_active_stat ? get_stat_val(dialog_active_stat) : 0;
}

static unsigned long drain_stat_early_dialogs(void *unused)
{
	return dialog_early_stat ? get_stat_val(dialog_early_stat) : 0;
}

static unsigned long drain_stat_inuse_transactions(void *unused)
{
	return tm_inuse_stat ? get_stat_val(tm_inuse_stat) : 0;
}

static unsigned long drain_stat_remaining(void *unused)
{
	/*
	 * dialog:active_dialogs only counts confirmed dialogs; a dialog moves
	 * from early_dialogs to active_dialogs when it gets answered, so both
	 * gauges must be summed to cover every established or ringing call.
	 */
	unsigned long remaining = drain_stat_active_dialogs(NULL) +
		drain_stat_early_dialogs(NULL);

	if (drain_wait_transactions)
		remaining += drain_stat_inuse_transactions(NULL);
	return remaining;
}

static const stat_export_t mod_stats[] = {
	{"draining", STAT_IS_FUNC, (stat_var **)drain_stat_state},
	{"rejected_requests", 0, &rejected_requests},
	{"active_dialogs", STAT_IS_FUNC, (stat_var **)drain_stat_active_dialogs},
	{"early_dialogs", STAT_IS_FUNC, (stat_var **)drain_stat_early_dialogs},
	{"inuse_transactions", STAT_IS_FUNC, (stat_var **)drain_stat_inuse_transactions},
	{"remaining", STAT_IS_FUNC, (stat_var **)drain_stat_remaining},
	{0, 0, 0}
};

static const cmd_export_t cmds[] = {
	{"drain_enabled", (cmd_function)w_drain_enabled, {{0, 0, 0}}, ALL_ROUTES},
	{"drain_reject", (cmd_function)w_drain_reject, {{0, 0, 0}}, REQUEST_ROUTE},
	{0, 0, {{0, 0, 0}}, 0}
};

static const param_export_t params[] = {
	{"initial_state", INT_PARAM, &drain_initial_state},
	{"auto_reject", INT_PARAM, &drain_auto_reject},
	{"reject_invites", INT_PARAM, &drain_reject_invites},
	{"reject_registers", INT_PARAM, &drain_reject_registers},
	{"wait_transactions", INT_PARAM, &drain_wait_transactions},
	{"reply_code", INT_PARAM, &drain_reply_code},
	{"reply_reason", STR_PARAM, &drain_reply_reason.s},
	{0, 0, 0}
};

static const mi_export_t mi_cmds[] = {
	{"enable", 0, 0, 0, {
		{mi_drain_enable, {"enable", 0}},
		{EMPTY_MI_RECIPE}}, {0}},
	{"status", 0, 0, 0, {
		{mi_drain_status, {0}},
		{EMPTY_MI_RECIPE}}, {0}},
	{EMPTY_MI_EXPORT}
};

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "sl", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "tm", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "dialog", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"drain",
	MOD_TYPE_DEFAULT,
	MODULE_VERSION,
	DEFAULT_DLFLAGS,
	NULL,
	&deps,
	cmds,
	NULL,
	params,
	mod_stats,
	mi_cmds,
	NULL,
	NULL,
	NULL,
	NULL,
	mod_init,
	0,
	mod_destroy,
	0,
	0
};

static void drain_raise_event(event_id_t event)
{
	if (event == EVI_ERROR || !evi_probe_event(event))
		return;
	if (evi_raise_event(event, NULL) < 0)
		LM_ERR("failed to raise drain event %d\n", event);
}

static void drain_set_state(int enabled)
{
	int old_state, new_state;

	if (!drain_state || !drain_lock)
		return;

	new_state = enabled ? 1 : 0;

	/* MI commands may run concurrently in several processes (FIFO, HTTP,
	 * ...) and the timer may be completing the drain at the same time, so
	 * the read-modify-write of the shared state must be serialized */
	lock_get(drain_lock);

	old_state = atomic_load(drain_state);
	if (old_state == new_state) {
		lock_release(drain_lock);
		return;
	}

	atomic_store(drain_state, new_state);
	atomic_store(drain_complete_emitted, 0);

	if (drain_srg) {
		if (new_state)
			sr_set_status(drain_srg, CHAR_INT_NULL, SR_STATUS_NOT_READY,
				CHAR_INT("draining traffic"), 0);
		else
			sr_set_status(drain_srg, CHAR_INT_NULL, SR_STATUS_READY,
				CHAR_INT("accepting new traffic"), 0);
	}

	lock_release(drain_lock);

	drain_raise_event(drain_state_event);
}

static int drain_is_initial_invite(struct sip_msg *msg)
{
	if (!msg || msg->first_line.type != SIP_REQUEST ||
		msg->REQ_METHOD != METHOD_INVITE)
		return 0;

	if (parse_headers(msg, HDR_TO_F, 0) < 0 || !msg->to ||
		parse_to_header(msg) < 0 || !get_to(msg)) {
		LM_DBG("cannot determine To-tag while evaluating drain policy\n");
		return 0;
	}

	return get_to(msg)->tag_value.len == 0;
}

static int drain_should_reject(struct sip_msg *msg)
{
	if (!drain_state || !atomic_load(drain_state) || !msg ||
		msg->first_line.type != SIP_REQUEST)
		return 0;

	if (drain_reject_invites && drain_is_initial_invite(msg))
		return 1;

	if (drain_reject_registers && msg->REQ_METHOD == METHOD_REGISTER)
		return 1;

	return 0;
}

static int drain_send_reject(struct sip_msg *msg)
{
	if (slb.reply(msg, drain_reply_code, &drain_reply_reason, NULL) < 0) {
		LM_ERR("failed to send drain rejection reply\n");
		return -1;
	}

	if (rejected_requests)
		update_stat(rejected_requests, 1);
	return 1;
}

/*
 * Applies the drain admission policy to a request.
 * Returns 1 if the request was consumed (either rejected, or absorbed by TM
 * as a retransmission), 0 if it must be processed normally and -1 if the
 * rejection reply could not be sent.
 */
static int drain_handle_request(struct sip_msg *msg)
{
	int rc;

	if (!drain_should_reject(msg))
		return 0;

	/*
	 * Drain may be enabled after an initial request already created a TM
	 * transaction.  Do not turn a retransmission of that request into a new
	 * stateless 503: let TM retransmit the transaction's existing reply.
	 * t_check_trans() returns 0 after handling a normal retransmission, >0
	 * when a transaction is already associated and <0 for a new request.
	 */
	rc = tmb.t_check_trans(msg);
	if (rc == 0)
		return 1;
	if (rc > 0)
		return 0;

	return drain_send_reject(msg);
}

static int drain_pre_request(struct sip_msg *msg, void *param)
{
	if (!drain_auto_reject)
		return SCB_RUN_ALL;

	return drain_handle_request(msg) > 0 ? SCB_DROP_MSG : SCB_RUN_ALL;
}

static int w_drain_enabled(struct sip_msg *msg)
{
	return drain_state && atomic_load(drain_state) ? 1 : -1;
}

static int w_drain_reject(struct sip_msg *msg)
{
	return drain_handle_request(msg) > 0 ? 1 : -1;
}

static mi_response_t *build_status_response(void)
{
	mi_response_t *resp;
	mi_item_t *obj;

	resp = init_mi_result_object(&obj);
	if (!resp)
		return NULL;

	if (add_mi_number(obj, MI_SSTR("draining"), drain_stat_state(NULL)) < 0 ||
		add_mi_number(obj, MI_SSTR("active_dialogs"),
			drain_stat_active_dialogs(NULL)) < 0 ||
		add_mi_number(obj, MI_SSTR("early_dialogs"),
			drain_stat_early_dialogs(NULL)) < 0 ||
		add_mi_number(obj, MI_SSTR("inuse_transactions"),
			drain_stat_inuse_transactions(NULL)) < 0 ||
		add_mi_number(obj, MI_SSTR("remaining"),
			drain_stat_remaining(NULL)) < 0 ||
		add_mi_bool(obj, MI_SSTR("wait_transactions"),
			drain_wait_transactions != 0) < 0 ||
		add_mi_number(obj, MI_SSTR("rejected_requests"),
			rejected_requests ? get_stat_val(rejected_requests) : 0) < 0) {
		free_mi_response(resp);
		return NULL;
	}

	return resp;
}

static mi_response_t *mi_drain_enable(const mi_params_t *params,
		struct mi_handler *async_hdl)
{
	int enable;

	if (get_mi_int_param(params, "enable", &enable) < 0)
		return init_mi_param_error();
	if (enable != 0 && enable != 1)
		return init_mi_error(400, MI_SSTR("enable must be 0 or 1"));

	drain_set_state(enable);
	return build_status_response();
}

static mi_response_t *mi_drain_status(const mi_params_t *params,
		struct mi_handler *async_hdl)
{
	return build_status_response();
}

static void drain_timer(unsigned int ticks, void *param)
{
	(void)ticks;
	(void)param;

	int complete = 0;

	if (!drain_state || !atomic_load(drain_state) ||
		atomic_load(drain_complete_emitted))
		return;

	if (drain_stat_remaining(NULL) != 0)
		return;

	/* re-check under lock, so we never report the completion of a drain
	 * which was meanwhile cancelled (or cancelled and restarted) over MI */
	lock_get(drain_lock);
	if (atomic_load(drain_state) && !atomic_load(drain_complete_emitted)) {
		atomic_store(drain_complete_emitted, 1);
		complete = 1;
	}
	lock_release(drain_lock);

	if (!complete)
		return;

	LM_NOTICE("traffic drain complete\n");
	drain_raise_event(drain_complete_event);
}

#ifdef UNIT_TESTS
int drain_test_should_reject(struct sip_msg *msg, int draining,
	int reject_invites, int reject_registers)
{
	int old_invites = drain_reject_invites;
	int old_registers = drain_reject_registers;
	int old_state;
	int rc;

	if (!drain_state)
		return -1;

	old_state = atomic_load(drain_state);
	drain_reject_invites = reject_invites;
	drain_reject_registers = reject_registers;
	atomic_store(drain_state, draining ? 1 : 0);

	rc = drain_should_reject(msg);

	atomic_store(drain_state, old_state);
	drain_reject_invites = old_invites;
	drain_reject_registers = old_registers;
	return rc;
}
#endif

static int mod_init(void)
{
	drain_reply_reason.len = strlen(drain_reply_reason.s);

	if (drain_reply_code < 300 || drain_reply_code > 699) {
		LM_ERR("invalid reply_code %d\n", drain_reply_code);
		return -1;
	}

	if (load_sl_api(&slb) != 0) {
		LM_ERR("cannot load sl API\n");
		return -1;
	}

	if (load_tm_api(&tmb) != 0 || !tmb.t_check_trans) {
		LM_ERR("cannot load tm API for retransmission-safe draining\n");
		return -1;
	}

	if (drain_resolve_stats() != 0)
		return -1;

	drain_state = shm_malloc(sizeof(*drain_state));
	drain_complete_emitted = shm_malloc(sizeof(*drain_complete_emitted));
	if (!drain_state || !drain_complete_emitted) {
		LM_ERR("no shared memory for drain state\n");
		goto error;
	}
	atomic_init(drain_state, drain_initial_state ? 1 : 0);
	atomic_init(drain_complete_emitted, 0);

	drain_lock = lock_alloc();
	if (!drain_lock || !lock_init(drain_lock)) {
		LM_ERR("failed to create the drain lock\n");
		goto error;
	}

	/*
	 * Readiness is derived from drain state, so generic public SR setters
	 * must not be able to mutate this group independently.
	 */
	if (atomic_load(drain_state))
		drain_srg = sr_register_group_with_identifier(CHAR_INT("drain"),
			0, CHAR_INT_NULL, SR_STATUS_NOT_READY,
			CHAR_INT("draining traffic"), 20);
	else
		drain_srg = sr_register_group_with_identifier(CHAR_INT("drain"),
			0, CHAR_INT_NULL, SR_STATUS_READY,
			CHAR_INT("accepting new traffic"), 20);
	if (!drain_srg) {
		LM_ERR("failed to register drain status/report group\n");
		goto error;
	}

	drain_state_event = evi_publish_event(drain_state_event_name);
	if (drain_state_event == EVI_ERROR) {
		LM_ERR("cannot publish %s\n", DRAIN_EVENT_STATE_NAME);
		goto error;
	}
	drain_complete_event = evi_publish_event(drain_complete_event_name);
	if (drain_complete_event == EVI_ERROR) {
		LM_ERR("cannot publish %s\n", DRAIN_EVENT_COMPLETE_NAME);
		goto error;
	}

	if (drain_auto_reject &&
		register_script_cb(drain_pre_request, PRE_SCRIPT_CB|REQ_TYPE_CB,
			NULL) != 0) {
		LM_ERR("cannot register drain pre-request callback\n");
		goto error;
	}

	if (register_timer("drain-monitor", drain_timer, NULL, 1,
		TIMER_FLAG_SKIP_ON_DELAY) < 0) {
		LM_ERR("cannot register drain monitor timer\n");
		goto error;
	}

	return 0;

error:
	if (drain_lock) {
		lock_dealloc(drain_lock);
		drain_lock = NULL;
	}
	if (drain_state) {
		shm_free(drain_state);
		drain_state = NULL;
	}
	if (drain_complete_emitted) {
		shm_free(drain_complete_emitted);
		drain_complete_emitted = NULL;
	}
	return -1;
}

static void mod_destroy(void)
{
	if (drain_lock) {
		lock_destroy(drain_lock);
		lock_dealloc(drain_lock);
		drain_lock = NULL;
	}
	if (drain_state)
		shm_free(drain_state);
	if (drain_complete_emitted)
		shm_free(drain_complete_emitted);
	drain_state = NULL;
	drain_complete_emitted = NULL;
}
