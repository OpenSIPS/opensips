/*
 * presence_callinfo module - Presence Handling of call-info events
 *
 * Copyright (C) 2010 Ovidiu Sas
 * Copyright (C) 2013 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2010-03-11  initial version (osas)
 *  2010-07-13  added support for SCA Broadsoft with dialog module (bogdan)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../str.h"
#include "../../mod_fix.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_from.h"
#include "../../mem/mem.h"
#include "../presence/bind_presence.h"
#include "presence_callinfo.h"
#include "add_events.h"
#include "sca_hash.h"
#include "sca_dialog.h"

int call_info_timeout_notification = 1;
int line_seize_timeout_notification = 0;
int no_dialog_support = 0;
static int hash_size = 64;
int sca_log_level_ = L_ALERT, *sca_log_level;

static str caller_spec_param;
static str callee_spec_param;
static pv_spec_t caller_spec;
static pv_spec_t callee_spec;

/* external API's */
presence_api_t pres;

/* module functions */
static int mod_init(void);
static int child_init(int);
static void destroy(void);
static int sca_init_globals(void);
static void sca_tm_sendpublish(struct cell *t, int type, struct tmcb_params *_params);
static void free_cb_param(void *param);

/* script functions */
int sca_engage(struct sip_msg *msg, str *parties);
int sca_set_called_line(struct sip_msg *msg, str *line);
int sca_mute_branch(struct sip_msg* msg, str *parties);

/* MI functions */
mi_response_t *sca_mi_list_lines(const mi_params_t *params,
		struct mi_handler *async_hdl);
mi_response_t *sca_mi_release_line(const mi_params_t *params,
		struct mi_handler *async_hdl);
mi_response_t *sca_mi_set_log_level(const mi_params_t *params,
		struct mi_handler *async_hdl);

extern struct sca_hash *sca_table;

/* module exported commands */
static const cmd_export_t cmds[] ={
	{"sca_engage", (cmd_function)sca_engage, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE},
	{"sca_set_called_line",  (cmd_function)sca_set_called_line, {
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE},
	{"sca_mute_branch", (cmd_function)sca_mute_branch, {
		{CMD_PARAM_STR,0,0}, {0,0,0},
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, {0,0,0}},
		BRANCH_ROUTE},
	{0,0,{{0,0,0}},0}
};

/* module exported parameters */
static const param_export_t params[] = {
	{"line_hash_size",                  INT_PARAM, &hash_size},
	{"disable_dialog_support_for_sca",  INT_PARAM, &no_dialog_support},
	{"call_info_timeout_notification",  INT_PARAM, &call_info_timeout_notification},
	{"line_seize_timeout_notification", INT_PARAM, &line_seize_timeout_notification},
	{"caller_spec_param",   STR_PARAM, &caller_spec_param.s },
	{"callee_spec_param",   STR_PARAM, &callee_spec_param.s },
	{"log_level",           INT_PARAM, &sca_log_level_ },
	{0, 0, 0}
};

static module_dependency_t *get_deps_dialog_support(const param_export_t *param)
{
	int no_dialog_support = *(int *)param->param_pointer;

	if (no_dialog_support)
		return NULL;

	return alloc_module_dep(MOD_TYPE_DEFAULT, "dialog", DEP_ABORT);
}

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "presence", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "disable_dialog_support_for_sca", get_deps_dialog_support },
		{ NULL, NULL },
	},
};

static const mi_export_t mi_cmds[] = {
	{ "list_lines", 0, 0, 0, {
		{sca_mi_list_lines, {0}},
		{sca_mi_list_lines, {"sca_line", 0}},
		{EMPTY_MI_RECIPE}}, {"sca_list_lines", 0}
	},
	{ "release_line", 0, 0, 0, {
		{sca_mi_release_line, {"sca_line", 0}},
		{sca_mi_release_line, {"sca_line", "sca_index", 0}},
		{EMPTY_MI_RECIPE}}, {"sca_release_line", 0}
	},
	{ "set_log_level", 0, 0, 0, {
		{sca_mi_set_log_level, {0}},
		{sca_mi_set_log_level, {"log_level", 0}},
		{EMPTY_MI_RECIPE}}, {"sca_set_log_level", 0}
	},
	{EMPTY_MI_EXPORT}
};

/* module exports */
struct module_exports exports= {
	"presence_callinfo",	/* module name */
	MOD_TYPE_DEFAULT,       /* class of this module */
	MODULE_VERSION,			/* module version */
	DEFAULT_DLFLAGS,		/* dlopen flags */
	0,						/* load function */
	&deps,                  /* OpenSIPS module dependencies */
	cmds,					/* exported functions */
	0,						/* exported async functions */
	params,					/* exported parameters */
	0,						/* exported statistics */
	mi_cmds,				/* exported MI functions */
	0,						/* exported pseudo-variables */
	0,			 			/* exported transformations */
	0,						/* extra processes */
	0,						/* module pre-initialization function */
	mod_init,				/* module initialization function */
	(response_function) 0,	/* response handling function */
	destroy,				/* destroy function */
	child_init,				/* per-child init function */
	0						/* reload confirm function */
};


/*
 * init module function
 */
static int mod_init(void)
{
	bind_presence_t bind_presence;

	LM_INFO("initializing...\n");

	/* bind to presence module */
	bind_presence= (bind_presence_t)find_export("bind_presence",0);
	if (!bind_presence) {
		LM_ERR("can't bind presence\n");
		return -1;
	}
	if (bind_presence(&pres) < 0) {
		LM_ERR("can't bind pua\n");
		return -1;
	}

	if (sca_init_globals() != 0) {
		LM_ERR("failed to init globals\n");
		return -1;
	}

	if (pres.add_event == NULL) {
		LM_ERR("could not import add_event\n");
		return -1;
	}
	if(callinfo_add_events() < 0) {
		LM_ERR("failed to add call-info events\n");
		return -1;
	}

	if (no_dialog_support==0) {
		/* bind to the tm/dialog APIs */
		if (init_module_apis()<0 ) {
			LM_ERR("failed to enable the dialog support\n");
			return -1;
		}

		/* init internal hash table to keep the SCA/lines status */
		if ( init_sca_hash(hash_size) < 0 ) {
			LM_ERR("failed to init hash table for SCA lines\n");
			return -1;
		}
	}

	return 0;
}


static int child_init(int rank)
{
	return 0;
}


static void destroy(void)
{
	LM_DBG("destroying module ...\n");
	if (no_dialog_support==0)
		destroy_sca_hash();
	return;
}


static inline int sca_parse_parties_flag(str *parties)
{
	int i, flags = 0;

	if (parties) {
		for( i=0 ; i<parties->len ; i++) {
			switch (parties->s[i]) {
				case SCA_PUB_A_CHAR:
					flags |= SCA_PUB_A;
					break;
				case SCA_PUB_B_CHAR:
					flags |= SCA_PUB_B;
					break;
				default:
					LM_ERR("unsupported party flag [%c], ignoring\n", parties->s[i]);
			}
		}
	}

	if (flags==0)
		flags = SCA_PUB_A | SCA_PUB_B;

	return flags;
}


static int sca_init_globals(void)
{
	sca_log_level = shm_malloc(sizeof *sca_log_level);
	if (!sca_log_level) {
		LM_ERR("oom\n");
		return -1;
	}
	*sca_log_level = sca_log_level_;

	if (caller_spec_param.s) {
		caller_spec_param.len = strlen(caller_spec_param.s);
		if (!pv_parse_spec(&caller_spec_param, &caller_spec)) {
			LM_ERR("failed to parse caller spec\n");
			return -2;
		}

		switch (caller_spec.type) {
			case PVT_NONE:
			case PVT_EMPTY:
			case PVT_NULL:
			case PVT_MARKER:
			case PVT_COLOR:
				LM_ERR("invalid caller spec\n");
				return -3;
			default: ;
		}
	}

	if (callee_spec_param.s) {
		callee_spec_param.len = strlen(callee_spec_param.s);
		if (!pv_parse_spec(&callee_spec_param, &callee_spec)) {
			LM_ERR("failed to parse callee spec\n");
			return -2;
		}

		switch(callee_spec.type) {
			case PVT_NONE:
			case PVT_EMPTY:
			case PVT_NULL:
			case PVT_MARKER:
			case PVT_COLOR:
				LM_ERR("invalid callee spec\n");
				return -3;
			default: ;
		}
	}

	return 0;
}

static struct sca_cb_params * sca_build_cb_param(
				struct to_body *entity_p, struct to_body *peer_p)
{
	struct sca_cb_params *param;
	char *p;

	param = shm_malloc(sizeof *param +
		entity_p->display.len + entity_p->uri.len +
		peer_p->display.len + peer_p->uri.len);
	if (!param) {
		LM_ERR("failed to allocate a param pack\n");
		return NULL;
	}
	memset(param, 0, sizeof *param);

	p = (char *)(param + 1);

	memcpy( p, entity_p->uri.s, entity_p->uri.len);
	param->entity.uri.s = p;
	param->entity.uri.len = entity_p->uri.len;
	p+= entity_p->uri.len;

	if (entity_p->display.len) {
		memcpy( p, entity_p->display.s, entity_p->display.len);
		param->entity.display.s = p;
		param->entity.display.len = entity_p->display.len;
		p+= entity_p->display.len;
	}

	memcpy( p, peer_p->uri.s, peer_p->uri.len);
	param->peer.uri.s = p;
	param->peer.uri.len = peer_p->uri.len;
	p+= peer_p->uri.len;

	if (peer_p->display.len) {
		memcpy( p, peer_p->display.s, peer_p->display.len);
		param->peer.display.s = p;
		param->peer.display.len = peer_p->display.len;
		p+= peer_p->display.len;
	}

	return param;
}


static int sca_pack_cb_params(struct sip_msg *msg,
		struct sca_cb_params **param1, struct sca_cb_params **param2)
{
	struct to_body entity, peer;
	struct to_body *entity_p, *peer_p;
	pv_value_t tok;
	char *c_buf = NULL;
	char *p_buf = NULL;
	int len;
	str *ruri;
	int ret;

	ret = -1;

	/* do we have a spec override? */
	if (caller_spec.type && pv_get_spec_value(msg, &caller_spec, &tok) >= 0
			&& pvv_is_str(&tok)) {

		trim(&tok.rs);
		c_buf = pkg_malloc(tok.rs.len + CRLF_LEN + 1);
		if (!c_buf) {
			LM_ERR("no more pkg memeory\n");
			goto error1;
		}

		len = sprintf(c_buf, "%.*s%s", tok.rs.len, tok.rs.s, CRLF);
		parse_to(c_buf, c_buf+len, &entity);

		if (entity.error != PARSE_OK) {
			LM_ERR("Failed to parse entity nameaddr [%.*s]\n", len, c_buf);
			goto error1;
		}
		entity_p = &entity;

	} else {
		entity_p = get_from(msg);
	}

	/* do we have a spec override? */
	if (callee_spec.type && pv_get_spec_value(msg, &callee_spec, &tok) >= 0
			&& pvv_is_str(&tok)) {

		trim(&tok.rs);
		p_buf = pkg_malloc(tok.rs.len + CRLF_LEN + 1);
		if (!p_buf) {
			LM_ERR("no more pkg memeory\n");
			goto error2;
		}
		len = sprintf(p_buf, "%.*s%s", tok.rs.len, tok.rs.s, CRLF);
		LM_DBG("extracted peer nameaddr is [%.*s]\n", len, p_buf);

	} else {

		ruri = GET_RURI(msg);
		peer_p = get_to(msg);
		len = peer_p->display.len + 2 + ruri->len + CRLF_LEN;
		p_buf = pkg_malloc(len + 1);
		if (!p_buf) {
			LM_ERR("no more pkg memeory\n");
			goto error2;
		}
		len = 0;
		if (peer_p->display.len) {
			memcpy(p_buf, peer_p->display.s, peer_p->display.len);
			len = peer_p->display.len;
			p_buf[len++]='<';
		}
		memcpy(p_buf + len, ruri->s, ruri->len);
		len+= ruri->len;
		if (peer_p->display.len)
			p_buf[len++]='>';
		memcpy(p_buf + len, CRLF, CRLF_LEN);
		len+= CRLF_LEN;
		LM_DBG("computed peer nameaddr is [%.*s]\n", len, p_buf);

	}

	parse_to( p_buf, p_buf+len , &peer);
	if (peer.error != PARSE_OK) {
		LM_ERR("Failed to parse peer nameaddr [%.*s]\n", len, p_buf);
		goto error2;
	}
	peer_p = &peer;

	/* now finally pack everything */
	*param1 = sca_build_cb_param(entity_p, peer_p);
	if (!*param1)
		goto error2;

	*param2 = sca_build_cb_param(entity_p, peer_p);
	if (!*param2) {
		shm_free(*param1);
		goto error2;
	}

	LM_DBG("packed callinfo data: entity [%.*s]/[%.*s],"
		" peer [%.*s]/[%.*s]\n",
		(*param1)->entity.display.len, (*param1)->entity.display.s,
		(*param1)->entity.uri.len, (*param1)->entity.uri.s,
		(*param1)->peer.display.len, (*param1)->peer.display.s,
		(*param1)->peer.uri.len, (*param1)->peer.uri.s
		);

	ret = 0;

error2:
	if (p_buf) {
		pkg_free(p_buf);
		free_to_params( &peer );
	}
error1:
	if (c_buf) {
		pkg_free(c_buf);
		free_to_params( &entity );
	}
	return ret;
}


static int sca_validate_call_out(struct sip_msg *msg, str *line_s)
{
	struct sca_line *line;
	unsigned int idx;

	/* extract the index from the call-info line */
	if (parse_call_info_header(msg) != 0) {
		LM_ERR("missing or bogus Call-Info header in INVITE\n");
		return -5;
	}

	idx = get_appearance_index(msg);
	if (!idx) {
		LM_ERR("failed to extract line index from Call-Info hdr\n");
		return -6;
	}

	LM_SCA("looking for line <%.*s>, idx %d\n", line_s->len, line_s->s, idx);

	/* search for the line (with no creation) */
	line = get_sca_line(line_s, 0);
	if (!line) {
		LM_ERR("used line <%.*s> not found in hash. Using without seizing?\n",
			line_s->len, line_s->s);
		return -2;
	}

	if (line->seize_state == 0) {
		LM_ERR("line <%.*s> not seized at the moment\n",
			line_s->len, line_s->s);
		unlock_sca_line(line);
		return -3;
	}

	if (line->seize_state != idx) {
		LM_ERR("line <%.*s> seized for diff index! (idx=%d,seized_for=%d)\n",
			line_s->len, line_s->s, idx, line->seize_state);
		unlock_sca_line(line);
		return -4;
	}

	/* still locked here! */
	unlock_sca_line(line);

	// TODO -- find the best way to integrate this line-seize terminated NOTY
	//terminate_line_sieze(line);

	return 1;
}


int sca_engage(struct sip_msg *msg, str *parties)
{
	struct sca_cb_params *param_dlg = NULL, *param_tm = NULL;
	struct dlg_cell * dlg;
	int rc, flags, val_type;
	int_str sca_engaged;

	if (no_dialog_support) {
		LM_ERR("dialog support is disabled, cannot use this function\n");
		return -1;
	}

	if (msg->REQ_METHOD != METHOD_INVITE)
		return 1;

	flags = sca_parse_parties_flag(parties);

	dlg = dlgf.get_dlg();
	if (!dlg && (dlgf.create_dlg(msg, 0) < 0 || !(dlg = dlgf.get_dlg()))) {
		LM_ERR("Failed to create dialog\n");
		return -1;
	}

	LM_SCA("sca_engage('%.*s') called, flags: %d\n",
			parties->len, parties->s, flags);

	if (sca_pack_cb_params( msg, &param_dlg, &param_tm) < 0) {
		LM_ERR("Failed to allocate parameters\n");
		return -1;
	}

	/* do some extra checks for outbound, ensure line is seized */
	if (flags & SCA_PUB_A
	        && (rc = sca_validate_call_out(msg, &param_dlg->entity.uri)) < 0) {
		LM_SCA("call out attempt not validated, rc: %d\n", rc);
		free_cb_param(param_tm); free_cb_param(param_dlg);
		return rc;
	}

	if (dlgf.fetch_dlg_value(dlg, &sca_engaged_Dvar, &val_type,
		&sca_engaged, 0) < 0 || val_type != DLG_VAL_TYPE_INT) {
		LM_DBG("sca_engaged not found in dlg\n");

		sca_engaged.n = flags;
		if (dlgf.store_dlg_value(dlg, &sca_engaged_Dvar, &sca_engaged,
		        DLG_VAL_TYPE_INT) < 0) {
			LM_ERR("Failed to store sca_engaged Dvar!\n");
			goto err_cleanup;
		}
	} else {
		/* repeat sca_engage() call, check if flags require updating */
		if (sca_engaged.n != flags) {
			sca_engaged.n = flags;
			if (dlgf.store_dlg_value(dlg, &sca_engaged_Dvar, &sca_engaged,
			        DLG_VAL_TYPE_INT) < 0) {
				LM_ERR("Failed to update sca_engaged Dvar!\n");
				goto err_cleanup;
			}
		}

		/* callbacks were already registered previously */
		free_cb_param(param_tm); free_cb_param(param_dlg);
		return 1;
	}

	/* register TM callback to get access to received replies */
	if (tmf.register_tmcb(msg, NULL, TMCB_RESPONSE_IN,
		sca_tm_sendpublish, (void *)param_tm, free_cb_param) != 1) {
		LM_ERR("cannot register TM callback for incoming replies\n");
		goto err_cleanup;
	}

	/* register dialog callbacks which triggers sending PUBLISH */
	if (dlgf.register_dlgcb(dlg,
	        DLGCB_FAILED | DLGCB_EARLY |DLGCB_CONFIRMED | DLGCB_TERMINATED
	        | DLGCB_EXPIRED | DLGCB_REQ_WITHIN ,
		sca_dialog_sendpublish, (void *)param_dlg, free_cb_param) != 0) {
		LM_ERR("cannot register callback for interested dialog types\n");
		free_cb_param(param_dlg);
		return -1;
	}

	return 1;

err_cleanup:
	free_cb_param(param_tm);
	free_cb_param(param_dlg);
	return -1;
}


int sca_set_called_line(struct sip_msg *msg, str *callee)
{
	struct dlg_cell *dlg;
	struct to_body to_b;
	int branch, len;
	str name_u;
	char *c_buf;
	int_str isval;

	if (no_dialog_support) {
		LM_ERR("dialog support is disabled, cannot use this function\n");
		return -1;
	}

	if (msg->REQ_METHOD != METHOD_INVITE) {
		LM_SCA("not an INVITE, skipping\n");
		return 1;
	}

	dlg = dlgf.get_dlg();
	if (!dlg)
		return -1;

	branch = tmf.get_branch_index();

	/* build var name */
	build_branch_callee_var_names( branch, &name_u );

	/* no callee -- just store NULL */
	if (ZSTRP(callee)) {
		if (dlgf.store_dlg_value(dlg, &name_u, NULL, DLG_VAL_TYPE_NONE)< 0) {
			LM_ERR("Failed to remove URI for branch %d\n", branch);
			return -1;
		}

		return 1;
	}

	/* parse input as nameaddr */
	trim( callee );

	c_buf = pkg_malloc(callee->len + CRLF_LEN + 1);
	if (!c_buf) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memcpy(c_buf, callee->s, callee->len);
	len = callee->len;

	memcpy(c_buf + len, CRLF, CRLF_LEN);
	len += CRLF_LEN;

	parse_to( c_buf, c_buf+len , &to_b);
	if (to_b.error != PARSE_OK) {
		LM_ERR("Failed to parse entity nameaddr [%.*s]\n", len, c_buf);
		goto error;
	}

	LM_DBG("storing callee URI in dlg: [%.*s]->[%.*s]\n",
		name_u.len, name_u.s, to_b.uri.len, to_b.uri.s);

	isval.s = to_b.uri;
	if (dlgf.store_dlg_value(dlg, &name_u, &isval, DLG_VAL_TYPE_STR) < 0) {
		LM_ERR("Failed to store display for branch %d\n", branch);
		goto error;
	}

	pkg_free(c_buf);
	free_to_params(&to_b);
	return 1;

error:
	pkg_free(c_buf);
	free_to_params(&to_b);
	return -1;
}


int sca_mute_branch(struct sip_msg *msg, str *parties)
{
	struct dlg_cell * dlg;
	int branch, flags;
	str mute_var;
	char buf[2];
	str val = {buf,2};
	int_str isval;

	dlg = dlgf.get_dlg();
	if (!dlg)
		return -1;

	branch = tmf.get_branch_index();

	/* build var name */
	build_branch_mute_var_name( branch, &mute_var );

	/* parse the parties to be muted  */
	flags = sca_parse_parties_flag(parties);
	val.s[0] = (flags&SCA_PUB_A) ? 'Y':'N';
	val.s[1] = (flags&SCA_PUB_B) ? 'Y':'N';

	LM_DBG("storing muting setting [%.*s]->[%.*s]\n",
		mute_var.len, mute_var.s, val.len, val.s);

	isval.s = val;
	if (dlgf.store_dlg_value(dlg, &mute_var, &isval, DLG_VAL_TYPE_STR) < 0) {
		LM_ERR("Failed to store mute flags for branch %d\n",branch);
		return -1;
	}

	return 1;
}


static int sca_mi_print_line(mi_item_t *line_obj, struct sca_line *ln)
{
	mi_item_t *idx_arr, *idx_obj;
	struct sca_idx *idx;
	unsigned int ticks;
	char *state;
	time_t now;
	int diff;
	double expires_ts;

	if (add_mi_string(line_obj, MI_SSTR("line"), ln->line.s, ln->line.len) < 0)
		goto error;

	if (add_mi_number(line_obj, MI_SSTR("seize_state"), ln->seize_state) < 0)
		goto error;

	now = time(NULL);
	ticks = get_ticks();
	if (!ln->seize_expires) {
		diff = 0;
		expires_ts = 0;
	} else {
		diff = (int)ln->seize_expires - (int)ticks;
		expires_ts = now + ln->seize_expires - ticks;
	}

	if (add_mi_number(line_obj, MI_SSTR("seize_expires"), diff) < 0)
		goto error;

	if (add_mi_number(line_obj, MI_SSTR("seize_expires_ts"), expires_ts) < 0)
		goto error;

	idx_arr = add_mi_array(line_obj, MI_SSTR("indexes"));
	if (!idx_arr)
		goto error;

	for (idx = ln->indexes; idx; idx = idx->next) {
		idx_obj = add_mi_object(idx_arr, NULL, 0);
		if (!idx_obj)
			goto error;

		if (add_mi_number(idx_obj, MI_SSTR("index"), idx->idx) < 0)
			goto error;

		state = sca_line_state_to_str(idx->state);
		if (add_mi_string(idx_obj, MI_SSTR("state"), state, strlen(state)) < 0)
			goto error;
	}

	return 0;

error:
	return -1;
}


mi_response_t *sca_mi_list_lines(const mi_params_t *params,
		struct mi_handler *_)
{
	mi_response_t *resp;
	mi_item_t *resp_obj, *lines_arr, *line;
	struct sca_line *ln;
	struct sca_idx *idx;
	double cnt = 0, cnt_idx = 0;
	str match_line = STR_NULL;
	int i;

	try_get_mi_string_param(params, "sca_line", &match_line.s, &match_line.len);

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	lines_arr = add_mi_array(resp_obj, MI_SSTR("lines"));
	if (!lines_arr)
		goto error;

	for (i = 0; i < sca_table->size; i++) {
		sca_lock(i);

		for (ln = sca_table->entries[i].first; ln; ln = ln->next) {
			if (match_line.s && str_strcmp(&match_line, &ln->line))
				continue;

			line = add_mi_object(lines_arr, NULL, 0);
			if (!line)
				goto error_unlock;

			if (sca_mi_print_line(line, ln) != 0)
				goto error_unlock;

			for (idx = ln->indexes; idx; idx = idx->next)
				cnt_idx++;

			cnt++;
		}

		sca_unlock(i);
	}

	add_mi_number(resp_obj, MI_SSTR("num_lines"), cnt);
	add_mi_number(resp_obj, MI_SSTR("num_indexes"), cnt_idx);
	return resp;

error_unlock:
	sca_unlock(i);
error:
	LM_ERR("failed to print SCA lines\n");
	free_mi_response(resp);
	return NULL;
}


mi_response_t *sca_mi_release_line(const mi_params_t *params,
		struct mi_handler *_)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	struct sca_line *ln, *ln_next;
	struct sca_idx *prev, *cur, *cur_next;
	str match_line = STR_NULL;
	int release_all = 0, cnt = 0, cnt_idx = 0, match_index = -1, i;

	get_mi_string_param(params, "sca_line", &match_line.s, &match_line.len);
	try_get_mi_int_param(params, "sca_index", &match_index);

	if (!str_strcasecmp(&match_line, str_static("ALL")))
		release_all = 1;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	for (i = 0; i < sca_table->size; i++) {
		sca_lock(i);

		for (ln = sca_table->entries[i].first; ln; ln = ln_next) {
			ln_next = ln->next;

			if (!release_all && str_strcmp(&match_line, &ln->line))
				continue;

			for (prev = NULL, cur = ln->indexes; cur; prev = cur, cur = cur_next) {
				cur_next = cur->next;
				if (match_index > 0 && cur->idx != match_index)
					continue;

				/* detach */
				if (!prev)
					ln->indexes = cur_next;
				else
					prev->next = cur_next;

				shm_free(cur);
				cur = prev;

				cnt_idx++;
			}

			if (match_index < 0 || !ln->indexes) {
				/* detach */
				if (ln->prev)
					ln->prev->next = ln_next;
				else
					sca_table->entries[i].first = ln_next;

				if (ln_next)
					ln_next->prev = ln->prev;

				free_sca_line(ln);
				cnt++;
			}
		}

		sca_unlock(i);
	}

	add_mi_number(resp_obj, MI_SSTR("released_lines"), cnt);
	add_mi_number(resp_obj, MI_SSTR("released_indexes"), cnt_idx);
	return resp;
}


mi_response_t *sca_mi_set_log_level(const mi_params_t *params,
		struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	int sll;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	if (try_get_mi_int_param(params, "log_level", &sll) < 0) {
		add_mi_number(resp_obj, MI_SSTR("log_level"), *sca_log_level);
	} else {
		add_mi_number(resp_obj, MI_SSTR("log_level_before"), *sca_log_level);
		add_mi_number(resp_obj, MI_SSTR("log_level_after"), sll);
		*sca_log_level = sll;
	}

	return resp;
}


static void sca_tm_sendpublish(struct cell *t, int type, struct tmcb_params *_params)
{
	struct sip_msg *req = _params->req; //, *rpl = _params->rpl;
	struct sca_cb_params *param;
	struct sca_party *entity;
	struct dlg_cell *dlg;
	str *peer, custom = STR_NULL, name_u;
	int n, branch;
	int_str isval;
	int val_type, idx = 0;

	isval.s = STR_NULL;

	param = (struct sca_cb_params *)(*_params->param);
	peer = &param->peer.uri;
	entity = &(param->entity);

	/* this is triggered only for TMCB_RESPONSE_IN */
	branch = tmf.get_branch_index();

	LM_SCA("TM event %d [%d/%d] received, entity [%.*s], peer [%.*s]\n", type,
	    _params->code, branch, entity->uri.len, entity->uri.s,
	    peer->len, peer->s);

	dlg = dlgf.get_dlg();
	if (!dlg) {
		LM_ERR("dialog not found\n");
		return;
	}

	/* try to see if there is any custom callee per branch */
	build_branch_callee_var_names( branch, &name_u);
	if (dlgf.fetch_dlg_value(dlg, &name_u, &val_type, &isval, 1)== 0) {
		custom = isval.s;
		isval.s = STR_NULL;
		peer = &custom;
		LM_SCA("peer line override with [%.*s]\n", peer->len, peer->s);
	}

	/* catch all early dialog replies and publish call-info accordingly */
	if (_params->code >= 180 && _params->code < 200) {
		//expire = t->uac[branch].request.fr_timer.time_out - get_ticks();

		/* ringing/early state - is it the first ringing on this branch ? */
		lock_get(&t->reply_mutex);
		if ( param->bitmask_early & (1ULL << branch)) {
			n = 0;
		} else {
			param->bitmask_early |= (1ULL << branch);
			n = 1;
		}
		lock_release(&t->reply_mutex);

		if (n) {
			/* best-effort search for ";appearance-index" in Call-INFO hdr */
			if (parse_call_info_header(req) == 0)
				idx = get_appearance_index(req);

			sca_sendpublish(dlg, branch, &entity->uri, peer, idx, -1);
		}
	}

	pkg_free(custom.s);
}


static void free_cb_param(void *param)
{
	shm_free(param);
}
