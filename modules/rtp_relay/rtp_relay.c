/*
 * Copyright (C) 2021 OpenSIPS Solutions
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

#include "../../dprint.h"
#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../ut.h"

#include "rtp_relay_ctx.h"
#include "rtp_relay.h"

#define RTP_RELAY_PV_PEER 0x1
#define RTP_RELAY_PV_VAR 0x2

static int pv_parse_rtp_relay_var(pv_spec_p sp, const str *in);
static int pv_get_rtp_relay_var(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val);
static int pv_set_rtp_relay_var(struct sip_msg *msg, pv_param_t *param,
		int op, pv_value_t *val);
static int pv_init_rtp_relay_var(pv_spec_p sp, int param);
static int rtp_relay_engage(struct sip_msg *msg, struct rtp_relay *relay, int *set);
static int fixup_rtp_relay(void **param);

static int mod_preinit(void);
static int mod_init(void);

static dep_export_t mod_deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "dialog", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
	},
};

static cmd_export_t mod_cmds[] = {
	{"rtp_relay_engage", (cmd_function)rtp_relay_engage, {
		{CMD_PARAM_STR, fixup_rtp_relay, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE},
	{"register_rtp_relay", (cmd_function)rtp_relay_reg,
		{{0,0,0}},0},
	{0,0,{{0,0,0}},0}
};

static mi_export_t mi_cmds[] = {
	{ "rtp_relay_list", 0, 0, 0, {
		{mi_rtp_relay_list, {0}},
		{mi_rtp_relay_list, {"engine", 0}},
		{mi_rtp_relay_list, {"engine", "set", 0}},
		{mi_rtp_relay_list, {"engine", "node", 0}},
		{mi_rtp_relay_list, {"engine", "set", "node", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "rtp_relay_update",
		"updates an ongoing RTP relay session",
			MI_ASYNC_RPL_FLAG, 0, {
		{mi_rtp_relay_update, {0}},
		{mi_rtp_relay_update, {"engine", 0}},
		{mi_rtp_relay_update, {"engine", "set", 0}},
		{mi_rtp_relay_update, {"engine", "set", "node", 0}},
		{mi_rtp_relay_update, {"engine", "set", "new_set", 0}},
		{mi_rtp_relay_update, {"engine", "set", "new_node", 0}},
		{mi_rtp_relay_update, {"engine", "set", "new_set", "new_node", 0}},
		{mi_rtp_relay_update, {"engine", "set", "node", "new_set", 0}},
		{mi_rtp_relay_update, {"engine", "set", "node", "new_node", 0}},
		{mi_rtp_relay_update, {"engine", "set", "node", "new_set", "new_node", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "rtp_relay_update_callid",
		"updates an ongoing RTP relay session identified by its Call-ID",
			MI_ASYNC_RPL_FLAG, 0, {
		{mi_rtp_relay_update_callid, {"callid", 0}},
		{mi_rtp_relay_update_callid, {"callid", "flags", 0}},
		{mi_rtp_relay_update_callid, {"callid", "engine", 0}},
		{mi_rtp_relay_update_callid, {"callid", "engine", "flags", 0}},
		{mi_rtp_relay_update_callid, {"callid", "engine", "set", 0}},
		{mi_rtp_relay_update_callid, {"callid", "engine", "set", "flags", 0}},
		{mi_rtp_relay_update_callid, {"callid", "engine", "set", "node", 0}},
		{mi_rtp_relay_update_callid, {"callid", "engine", "set", "node", "flags", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};


static param_export_t mod_params[] = {
	{0, 0, 0}
};

static pv_export_t mod_pvars[] = {
	{ str_init("rtp_relay"), 2004, pv_get_rtp_relay_var, pv_set_rtp_relay_var,
		pv_parse_rtp_relay_var, pv_parse_index, 0, 0},
	{ str_init("rtp_relay_peer"), 2005, pv_get_rtp_relay_var,
		pv_set_rtp_relay_var, pv_parse_rtp_relay_var,
		pv_parse_index, pv_init_rtp_relay_var, RTP_RELAY_PV_PEER},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

struct module_exports exports = {
	"rtp_relay",
	MOD_TYPE_DEFAULT,	/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,	/* dlopen flags */
	0,					/* load function */
	&mod_deps,			/* OpenSIPS module dependencies */
	mod_cmds,
	0,
	mod_params,
	0,					/* exported statistics */
	mi_cmds,
	mod_pvars,			/* exported pseudo-variables */
	0,					/* exported transformations */
	0,					/* extra processes */
	mod_preinit,
	mod_init,
	0,					/* reply processing */
	0,					/* destroy function */
	0,
	0					/* reload confirm function */
};

static int mod_preinit(void)
{
	if (rtp_relay_ctx_preinit() < 0) {
		LM_ERR("could not pre-initialize rtp_relay ctx\n");
		return -1;
	}
	return 0;
}

static int mod_init(void)
{
	if (rtp_relay_ctx_init() < 0) {
		LM_ERR("could not initialize rtp_relay ctx\n");
		return -1;
	}
	return 0;
}

static int pv_init_rtp_relay_var(pv_spec_p sp, int param)
{
	if(sp==NULL)
		return -1;
	sp->pvp.pvn.type = param;
	return 0;
}

static int pv_parse_rtp_relay_var(pv_spec_p sp, const str *in)
{
	enum rtp_relay_var_flags flag;
	pv_spec_t *pv;
	if (!in || !in->s || in->len < 1) {
		LM_ERR("invalid RTP relay var name!\n");
		return -1;
	}
	if (in->s[0] == PV_MARKER) {
		pv = pkg_malloc(sizeof(pv_spec_t));
		if (!pv) {
			LM_ERR("Out of mem!\n");
			return -1;
		}
		if (!pv_parse_spec(in, pv)) {
			LM_ERR("cannot parse PVAR [%.*s]\n",
					in->len, in->s);
			return -1;
		}
		sp->pvp.pvn.type |= RTP_RELAY_PV_VAR;
		sp->pvp.pvn.u.dname = pv;
	} else {
		flag = rtp_relay_flags_get(in);
		if (flag == RTP_RELAY_FLAGS_UNKNOWN) {
			LM_ERR("invalid RTP relay name %.*s\n", in->len, in->s);
			return -1;
		}
		sp->pvp.pvn.u.isname.name.n = flag;
	}
	return 0;
}

static inline enum rtp_relay_type rtp_relay_get_seq_type(
		struct sip_msg *msg, int req, int type)
{
	if (type & RTP_RELAY_PV_PEER)
		req = !req;

	if (rtp_relay_ctx_upstream())
		return req?RTP_RELAY_ANSWER:RTP_RELAY_OFFER;
	else
		return req?RTP_RELAY_OFFER:RTP_RELAY_ANSWER;
}

static struct rtp_relay_sess *pv_get_rtp_relay_sess(struct sip_msg *msg,
		pv_param_t *param, struct rtp_relay_ctx *ctx, enum rtp_relay_var_flags *flag,
		enum rtp_relay_type *type, int set)
{
	int idx = RTP_RELAY_ALL_BRANCHES;
	int idxf = 0;
	pv_value_t flags_name;
	struct rtp_relay_sess *sess = NULL;

	*flag = RTP_RELAY_FLAGS_UNKNOWN;

	if (param->pvi.type != 0) {
		if (pv_get_spec_index(msg, param, &idx, &idxf)!=0) {
			LM_ERR("invalid branch index\n");
			return NULL;
		}
		if ((idxf != PV_IDX_ALL && idxf != PV_IDX_INT) || idx < 0) {
			LM_WARN("only positive integer RTP relay branches or '*' are allowed "
					"(%d/%d)! ignoring...\n", idxf, idx);
			idx = RTP_RELAY_ALL_BRANCHES;
		}
		if (idxf == PV_IDX_ALL)
			idx = RTP_RELAY_ALL_BRANCHES;
	} else if (route_type == BRANCH_ROUTE) {
		idx = rtp_relay_ctx_branch();
	}

	sess = rtp_relay_get_sess(ctx, idx);
	if (!sess) {
		if (set) {
			sess = rtp_relay_new_sess(ctx, idx);
			if (!sess) {
				LM_ERR("could not create new RTP relay session!\n");
				return NULL;
			}
		} else {
			return NULL;
		}
	}

	*type = rtp_relay_get_seq_type(msg,
			(msg->first_line.type == SIP_REQUEST), param->pvn.type);

	if (param->pvn.type & RTP_RELAY_PV_VAR) {
		if (pv_get_spec_value(msg, (pv_spec_p)param->pvi.u.dval, &flags_name) < 0)
			LM_ERR("cannot get the name of the RTP relay variable\n");
		else if (pvv_is_str(&flags_name))
			*flag = rtp_relay_flags_get(&flags_name.rs);
		if (*flag == RTP_RELAY_FLAGS_UNKNOWN) {
			*flag = RTP_RELAY_FLAGS_SELF;
			flags_name.rs = *rtp_relay_flags_get_str(*flag);
			LM_WARN("unknown/bad RTP relay variable/type! using default (%.*s)...\n",
					flags_name.rs.len, flags_name.rs.s);
		}
	} else {
		*flag = param->pvn.u.isname.name.n;
	}
	return sess;
}

static int pv_get_rtp_relay_var(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val)
{
	struct rtp_relay_ctx *ctx;
	struct rtp_relay_sess *sess;
	enum rtp_relay_var_flags flag;
	enum rtp_relay_type type;

	if (!param) {
		LM_ERR("invalid parameter or value to set\n");
		return -1;
	}

	if (!(ctx = rtp_relay_try_get_ctx()))
		return pv_get_null(msg, param, val);

	RTP_RELAY_CTX_LOCK(ctx);

	sess = pv_get_rtp_relay_sess(msg, param, ctx, &flag, &type, 0);
	if (!sess) {
		pv_get_null(msg, param, val);
		goto end;
	}

	if (flag != RTP_RELAY_FLAGS_DISABLED) {
		val->rs = sess->flags[type][flag];
	} else if (rtp_sess_disabled(sess)) {
		init_str(&val->rs, "disabled");
	} else {
		init_str(&val->rs, "enabled");
	}
	val->flags = PV_VAL_STR;
end:
	RTP_RELAY_CTX_UNLOCK(ctx);
	return 0;
}

static int pv_set_rtp_relay_var(struct sip_msg *msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	enum rtp_relay_var_flags flag;
	enum rtp_relay_type type;
	struct rtp_relay_ctx *ctx;
	struct rtp_relay_sess *sess;
	int ret = 0;
	int disabled;
	str s = {NULL, 0};

	if (!(ctx = rtp_relay_get_ctx())) {
		LM_ERR("could not get/create context!\n");
		return -2;
	}
	RTP_RELAY_CTX_LOCK(ctx);

	sess = pv_get_rtp_relay_sess(msg, param, ctx, &flag, &type, 1);
	if (!sess) {
		LM_ERR("could not get context session!\n");
		ret = -2;
		goto end;
	}
	if (flag == RTP_RELAY_FLAGS_DISABLED) {
		/* disabled is treated differently */
		if (val->flags & PV_VAL_NULL)
			disabled = 0;
		else if (pvv_is_int(val))
			disabled = val->ri;
		else if (val->rs.len != 0)
			disabled = 1;
		else
			disabled = 0;
		rtp_sess_set_disabled(sess, disabled);
		goto end;
	}
	if (!(val->flags & PV_VAL_NULL)) {
		if (pvv_is_int(val))
			s.s = int2str(val->ri, &s.len);
		else
			s = val->rs;
	}
	if (shm_str_sync(&sess->flags[type][flag], &s) >= 0)
		goto end;
	ret = -1;
end:
	RTP_RELAY_CTX_UNLOCK(ctx);
	return ret;
}

static int fixup_rtp_relay(void **param)
{
	str *s = (str *)*param;
	struct rtp_relay *relay = rtp_relay_get(s);
	if (!relay) {
		LM_ERR("no '%.*s' relay module registered to handle RTP relay engage\n", s->len, s->s);
		return E_INVALID_PARAMS;
	}
	*param = relay;
	return 0;
}

static int rtp_relay_engage(struct sip_msg *msg, struct rtp_relay *relay, int *set)
{
	struct rtp_relay_ctx *ctx;
	int ret = -2;

	/* figure out the context we're in */
	if (msg->REQ_METHOD != METHOD_INVITE || get_to(msg)->tag_value.len != 0) {
		LM_WARN("rtp_relay_engage() can only be called on initial INVITEs\n");
		return -2;
	}

	ctx = rtp_relay_get_ctx();
	if (!ctx) {
		LM_ERR("could not get RTP relay ctx!\n");
		return -2;
	}
	RTP_RELAY_CTX_LOCK(ctx);
	ret = rtp_relay_ctx_engage(msg, ctx, relay, set);
	RTP_RELAY_CTX_UNLOCK(ctx);
	return ret;
}
