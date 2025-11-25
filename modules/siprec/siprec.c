/*
 * Copyright (C) 2017 OpenSIPS Project
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
 *
 * History:
 * ---------
 *  2017-06-20  created (razvanc)
 */

#include "../../mem/shm_mem.h"
#include "../../sr_module.h"
#include "../../mod_fix.h"
#include "../../dprint.h"
#include "../../lib/list.h"
#include "../../ut.h"

#include "siprec_sess.h"
#include "siprec_logic.h"
#include "siprec_var.h"
#include "../rtp_relay/rtp_relay_load.h"

#define srec_inst list_head

static int mod_preinit(void);
static int mod_init(void);
static int child_init(int);
static void mod_destroy(void);

static int siprec_start_rec(struct sip_msg *msg, str *srs, str *instance);
static int siprec_pause_rec(struct sip_msg *msg, str *instance);
static int siprec_resume_rec(struct sip_msg *msg, str *instance);
static int siprec_stop_rec(struct sip_msg *msg, str *instance);
static int siprec_send_indialog(struct sip_msg *msg, str *hdrs, str *body,
		str *instance);

/* modules dependencies */
static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "dialog", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "b2b_entities", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "rtp_relay", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "db_url", get_deps_sqldb_url },
		{ NULL, NULL },
	},
};

/* exported commands */
static const cmd_export_t cmds[] = {
	{"siprec_start_recording",(cmd_function)siprec_start_rec, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE},
	{"siprec_pause_recording",(cmd_function)siprec_pause_rec, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{0,0,0}},
		ALL_ROUTES},
	{"siprec_resume_recording",(cmd_function)siprec_resume_rec, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{0,0,0}},
		ALL_ROUTES},
	{"siprec_stop_recording",(cmd_function)siprec_stop_rec, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{0,0,0}},
		ALL_ROUTES},
	{"siprec_send_indialog",(cmd_function)siprec_send_indialog, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{0,0,0}},
		ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

/* exported parameters */
static const param_export_t params[] = {
	{"skip_failover_codes",	STR_PARAM, &skip_failover_codes.s },
	{0, 0, 0}
};

static const pv_export_t vars[] = {
	{ str_const_init("siprec"), 1000,
		pv_get_siprec, pv_set_siprec, pv_parse_siprec,
		pv_parse_siprec_instance, 0, 0 },
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

/* module exports */
struct module_exports exports = {
	"siprec",						/* module name */
	MOD_TYPE_DEFAULT,				/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,				/* dlopen flags */
	0,								/* load function */
	&deps,							/* OpenSIPS module dependencies */
	cmds,							/* exported functions */
	0,								/* exported async functions */
	params,							/* exported parameters */
	0,								/* exported statistics */
	0,								/* exported MI functions */
	vars,							/* exported pseudo-variables */
	0,								/* extra processes */
	0,								/* extra transformations */
	mod_preinit,					/* module pre-initialization function */
	mod_init,						/* module initialization function */
	(response_function) 0,			/* response handling function */
	(destroy_function)mod_destroy,	/* destroy function */
	child_init,						/* per-child init function */
	0								/* reload confirm function */
};

/**
 * pre-init module function
 */
static int mod_preinit(void)
{
	if (load_dlg_api(&srec_dlg) != 0) {
		LM_ERR("dialog module not loaded! Cannot use siprec module\n");
		return -1;
	}

	if (load_tm_api(&srec_tm) != 0) {
		LM_ERR("tm module not loaded! Cannot use siprec module\n");
		return -1;
	}

	if (load_b2b_api(&srec_b2b) != 0) {
		LM_ERR("b2b_entities module not loaded! Cannot use siprec module\n");
		return -1;
	}

	if (load_rtp_relay(&srec_rtp) != 0) {
		LM_ERR("rtp_relay module not loaded! Cannot use siprec module\n");
		return -1;
	}

	srec_dlg_idx = srec_dlg.dlg_ctx_register_ptr(NULL);

	if (init_srec_var() < 0) {
		LM_ERR("cannot initialize siprec variable!\n");
		return -1;
	}

	return 0;
}

/**
 * init module function
 */
static int mod_init(void)
{
	LM_DBG("initializing siprec module ...\n");

	if (src_init() < 0) {
		LM_ERR("cannot initialize src structures!\n");
		return -1;
	}

	if (srec_dlg.register_dlgcb(NULL, DLGCB_LOADED, srec_loaded_callback,
			NULL, NULL) < 0)
		LM_WARN("cannot register callback for loaded dialogs - will not be "
				"able to terminate siprec sessions after a restart!\n");

	return 0;
}

/*
 * function called when a child process starts
 */
static int child_init(int rank)
{
	return 0;
}

/*
 * function called after OpenSIPS has been stopped to cleanup resources
 */
static void mod_destroy(void)
{
}

static void tm_src_unref_session(void *p)
{
	struct src_sess *ss = (struct src_sess *)p;
	srec_dlg.dlg_unref(ss->ctx->dlg, 1); /* release the dialog */
	srec_hlog(ss, SREC_UNREF, "start recording unref");
	SIPREC_UNREF(ss);
}

/*
 * function that simply prints the parameters passed
 */
static int siprec_start_rec(struct sip_msg *msg, str *srs, str *instance)
{
	int ret = -2;
	str *aor, *display, *xml_val;
	struct src_ctx *ctx;
	struct src_sess *ss;
	struct dlg_cell *dlg;
	struct srec_var *var;
	struct cell *t;
	str body;

	if (!instance)
		instance = &siprec_default_instance;

	/* create the dialog, if does not exist yet */
	dlg = srec_dlg.get_dlg();
	if (!dlg) {
		if (!msg) {
			LM_ERR("no message or dialog available\n");
			return -2;
		}
		if (srec_dlg.create_dlg(msg, 0) < 0) {
			LM_ERR("cannot create dialog!\n");
			return -2;
		}
		dlg = srec_dlg.get_dlg();
	}
	ctx = src_get_ctx(dlg);
	if (!ctx) {
		ctx = src_new_ctx(dlg);
		if (!ctx) {
			LM_ERR("could not create new ctx\n");
			return -2;
		}
	}
	SIPREC_LOCK(ctx);
	ss = src_get_session(ctx, instance);
	if (ss) {
		LM_DBG("session %p already exists!\n", ss);
		if (ss->flags & SIPREC_STARTED) {
			LM_WARN("session already started!\n");
			goto release;
		}
		srs_add_nodes(ss, srs);
		goto start_recording;
	}
	var = get_srec_var(instance);
	if (!(ss = src_new_session(srs, ctx, var, instance))) {
		LM_ERR("cannot create siprec session!\n");
		goto release;
	}

	/* we ref the dialog to make sure it does not dissapear until we receive
	 * the reply from the SRS */
	srec_dlg.dlg_ref(dlg, 1);

	/* caller info */
	if (var && var->caller.len) {
		xml_val = &var->caller;
		display = aor = NULL;
	} else {
		if (parse_from_header(msg) < 0) {
			LM_ERR("cannot parse from header!\n");
			goto session_cleanup;
		}
		aor = &get_from(msg)->uri;
		display = (get_from(msg)->display.s ? &get_from(msg)->display : NULL);
		xml_val = NULL;
	}

	if (src_add_participant(ss, aor, display, xml_val, NULL, NULL) < 0) {
		LM_ERR("cannot add caller participant!\n");
		goto session_cleanup;
	}
	/* caller info */
	if (var && var->callee.len) {
		xml_val = &var->callee;
	} else {
		if ((!msg->to && parse_headers(msg, HDR_TO_F, 0) < 0) || !msg->to) {
			LM_ERR("inexisting or invalid to header!\n");
			goto session_cleanup;
		}
		aor = &get_to(msg)->uri;
		display = (get_to(msg)->display.s ? &get_to(msg)->display : NULL);
		xml_val = NULL;
	}

	if (src_add_participant(ss, aor, display, xml_val, NULL, NULL) < 0) {
		LM_ERR("cannot add callee pariticipant!\n");
		goto session_cleanup;
	}

	if (dlg->state > DLG_STATE_CONFIRMED_NA)
		goto start_recording;

	/* if we are in the context of a reply, but we're dealing with a late-negotiation
	 * we need to postpone the 'copy-offer' command until we have both SDPs */
	t = srec_tm.t_gett();
	if (t && t != T_UNDEFINED && t->uas.request) {
		if (get_body(t->uas.request, &body) >= 0 && body.len == 0) {
			ret = srec_late_recording(ss);
			goto release;
		}
	}

	SIPREC_REF_UNSAFE(ss);
	srec_hlog(ss, SREC_REF, "starting recording");
	if (srec_tm.register_tmcb(msg, 0, TMCB_RESPONSE_OUT, tm_start_recording,
			ss, tm_src_unref_session) <= 0) {
		LM_ERR("cannot register tm callbacks\n");
		srec_hlog(ss, SREC_UNREF, "error starting recording");
		SIPREC_UNREF_UNSAFE(ss);
		srec_dlg.dlg_unref(dlg, 1);
	}
	else {
		ret = 1;
	}
	goto release;

session_cleanup:
	srec_dlg.dlg_unref(dlg, 1);
	SIPREC_UNLOCK(ctx);
	src_free_session(ss);
	return ret;
start_recording:
	if (dlg->state >= DLG_STATE_DELETED) {
		LM_WARN("call already terminated!\n");
		ret = -1;
		goto release;
	}
	ret = src_start_recording(msg, ss);
	if (ret < 0)
		LM_ERR("cannot start recording!\n");
release:
	SIPREC_UNLOCK(ctx);
	return ret;
}

static int siprec_pause_rec(struct sip_msg *msg, str *instance)
{
	if (!instance)
		instance = &siprec_default_instance;

	return (src_pause_recording(instance) < 0 ? -1: 1);
}

static int siprec_resume_rec(struct sip_msg *msg, str *instance)
{
	if (!instance)
		instance = &siprec_default_instance;

	return (src_resume_recording(instance) < 0 ? -1: 1);
}

static int siprec_stop_rec(struct sip_msg *msg, str *instance)
{
	if (!instance)
		instance = &siprec_default_instance;

	return (src_stop_recording(instance) < 0 ? -1: 1);
}

static int siprec_send_indialog(struct sip_msg *msg, str *hdrs, str *body,
		str *instance)
{
	if (!instance)
		instance = &siprec_default_instance;

	return (src_send_indialog(msg, hdrs, body, instance) < 0 ? -1: 1);
}
