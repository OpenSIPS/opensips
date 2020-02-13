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
#include "../../ut.h"

#include "siprec_sess.h"
#include "siprec_logic.h"

static int mod_init(void);
static int child_init(int);
static void mod_destroy(void);

static int siprec_start_rec(struct sip_msg *msg, str *srs, str *group,
		str *_cA, str *_cB, str *rtp, str *m_ip, str *_hdrs);

/* modules dependencies */
static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "dialog", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "b2b_entities", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "rtpproxy", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "db_url", get_deps_sqldb_url },
		{ NULL, NULL },
	},
};

/* exported commands */
static cmd_export_t cmds[] = {
	{"siprec_start_recording",(cmd_function)siprec_start_rec, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE},
	{0,0,{{0,0,0}},0}
};

/* exported parameters */
static param_export_t params[] = {
	{"media_port_min",		INT_PARAM, &siprec_port_min },
	{"media_port_max",		INT_PARAM, &siprec_port_max },
	{"skip_failover_codes",	STR_PARAM, &skip_failover_codes.s },
	{0, 0, 0}
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
	0,								/* exported pseudo-variables */
	0,								/* extra processes */
	0,								/* extra transformations */
	0,								/* module pre-initialization function */
	mod_init,						/* module initialization function */
	(response_function) 0,			/* response handling function */
	(destroy_function)mod_destroy,	/* destroy function */
	child_init,						/* per-child init function */
	0								/* reload confirm function */
};

/**
 * init module function
 */
static int mod_init(void)
{
	LM_DBG("initializing siprec module ...\n");

	if (srs_init() < 0) {
		LM_ERR("cannot initialize srs structures!\n");
		return -1;
	}

	if (src_init() < 0) {
		LM_ERR("cannot initialize src structures!\n");
		return -1;
	}

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

	if (load_rtpproxy_api(&srec_rtp) != 0) {
		LM_ERR("rtpproxy module not loaded! Cannot use siprec module\n");
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

/*
 * function that simply prints the parameters passed
 */
static int siprec_start_rec(struct sip_msg *msg, str *srs, str *group,
		str *_cA, str *_cB, str *rtp, str *m_ip, str *_hdrs)
{
	int ret;
	str *aor, *display, *xml_val;
	struct src_sess *ss;
	struct dlg_cell *dlg;

	/* create the dialog, if does not exist yet */
	dlg = srec_dlg.get_dlg();
	if (!dlg) {
		if (srec_dlg.create_dlg(msg, 0) < 0) {
			LM_ERR("cannot create dialog!\n");
			return -2;
		}
		dlg = srec_dlg.get_dlg();
	}

	/* XXX: if there is a forced send socket in the message, use it
	 * this is the only way to provide a different socket for SRS, but
	 * we might need to take a different approach */
	/* check if the current dialog has a siprec session ongoing */
	if (!(ss = src_new_session(srs, rtp, m_ip, group, _hdrs, msg->force_send_socket))) {
		LM_ERR("cannot create siprec session!\n");
		return -2;
	}

	/* we ref the dialog to make sure it does not dissapear until we receive
	 * the reply from the SRS */
	srec_dlg.dlg_ref(dlg, 1);
	ss->dlg = dlg;

	ret = -2;

	/* caller info */
	if (_cA) {
		xml_val = _cA;
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
	if (srs_fill_sdp_stream(msg, ss, &ss->participants[0], 0) < 0) {
		LM_ERR("cannot add SDP for caller!\n");
		goto session_cleanup;
	}
	/* caller info */
	if (_cB) {
		xml_val = _cB;
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

	SIPREC_REF_UNSAFE(ss);
	if (srec_tm.register_tmcb(msg, 0, TMCB_RESPONSE_OUT, tm_start_recording,
			ss, src_unref_session) <= 0) {
		LM_ERR("cannot register tm callbacks\n");
		SIPREC_UNREF_UNSAFE(ss);
		goto session_cleanup;
	}
	return 1;

session_cleanup:
	src_free_session(ss);
	return ret;
}
