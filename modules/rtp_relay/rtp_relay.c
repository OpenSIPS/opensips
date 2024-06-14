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
#include "../../parser/parse_from.h"

#include "rtp_relay_load.h"
#include "rtp_relay_ctx.h"
#include "rtp_relay.h"

#define RTP_RELAY_PV_PEER 0x1
#define RTP_RELAY_PV_VAR 0x2

static int pv_parse_rtp_relay_var(pv_spec_p sp, const str *in);
static int pv_get_rtp_relay_var(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val);
static int pv_parse_rtp_relay_index(pv_spec_p sp, const str *in);
static int pv_get_rtp_relay_ctx(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val);
static int pv_set_rtp_relay_var(struct sip_msg *msg, pv_param_t *param,
		int op, pv_value_t *val);
static int pv_set_rtp_relay_ctx(struct sip_msg *msg, pv_param_t *param,
		int op, pv_value_t *val);
static int pv_parse_rtp_relay_ctx(pv_spec_p sp, const str *in);
static int pv_init_rtp_relay_var(pv_spec_p sp, int param);
static int rtp_relay_engage(struct sip_msg *msg, struct rtp_relay *relay, int *set);
static int fixup_rtp_relay(void **param);

static int mod_preinit(void);
static int mod_init(void);

static const dep_export_t mod_deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "dialog", DEP_SILENT },
		{ MOD_TYPE_DEFAULT, "b2b_logic", DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
	},
};

static const cmd_export_t mod_cmds[] = {
	{"rtp_relay_engage", (cmd_function)rtp_relay_engage, {
		{CMD_PARAM_STR, fixup_rtp_relay, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE},
	{"register_rtp_relay", (cmd_function)rtp_relay_reg,
		{{0,0,0}},0},
	{"load_rtp_relay", (cmd_function)rtp_relay_load,
		{{0,0,0}},0},
	{0,0,{{0,0,0}},0}
};

static const mi_export_t mi_cmds[] = {
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

char *rtp_relay_route_offer_name = "rtp_relay_offer";
char *rtp_relay_route_answer_name = "rtp_relay_answer";
char *rtp_relay_route_delete_name = "rtp_relay_delete";
char *rtp_relay_route_copy_offer_name = "rtp_relay_copy_offer";
char *rtp_relay_route_copy_answer_name = "rtp_relay_copy_answer";
char *rtp_relay_route_copy_delete_name = "rtp_relay_copy_delete";

static const param_export_t mod_params[] = {
	{"route_offer",       STR_PARAM, &rtp_relay_route_offer_name},
	{"route_answer",      STR_PARAM, &rtp_relay_route_answer_name},
	{"route_delete",      STR_PARAM, &rtp_relay_route_delete_name},
	{"route_copy_offer",  STR_PARAM, &rtp_relay_route_copy_offer_name},
	{"route_copy_answer", STR_PARAM, &rtp_relay_route_copy_answer_name},
	{"route_copy_delete", STR_PARAM, &rtp_relay_route_copy_delete_name},
	{0, 0, 0}
};

static const pv_export_t mod_pvars[] = {
	{ str_const_init("rtp_relay"), 2004, pv_get_rtp_relay_var, pv_set_rtp_relay_var,
		pv_parse_rtp_relay_var, pv_parse_rtp_relay_index, 0, 0},
	{ str_const_init("rtp_relay_peer"), 2005, pv_get_rtp_relay_var,
		pv_set_rtp_relay_var, pv_parse_rtp_relay_var,
		pv_parse_rtp_relay_index, pv_init_rtp_relay_var, RTP_RELAY_PV_PEER},
	{ str_const_init("rtp_relay_ctx"), 2006, pv_get_rtp_relay_ctx,
		pv_set_rtp_relay_ctx, pv_parse_rtp_relay_ctx,
		NULL, NULL, 0},
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
	static struct rtp_relay_hooks rtp_relay;
	if (rtp_relay_ctx_preinit() < 0) {
		LM_ERR("could not pre-initialize rtp_relay ctx\n");
		return -1;
	}
	struct rtp_relay_funcs binds = {
		.offer = rtp_relay_route_offer,
		.answer = rtp_relay_route_answer,
		.delete = rtp_relay_route_delete,
		.copy_offer = rtp_relay_route_copy_offer,
		.copy_answer = rtp_relay_route_copy_answer,
		.copy_delete = rtp_relay_route_copy_delete,
	};
	register_rtp_relay("route", &binds, &rtp_relay);
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

struct rtp_relay_leg *rtp_relay_get_peer_leg(struct rtp_relay_ctx *ctx,
		struct rtp_relay_leg *peer)
{
	struct list_head *it;
	struct rtp_relay_leg *leg;

	list_for_each(it, &ctx->legs) {
		leg = list_entry(it, struct rtp_relay_leg, list);
		if (leg == peer)
			continue;
		if (!leg->tag.len) {
			if (peer->tag.len && leg->index == RTP_RELAY_ALL_BRANCHES)
				return leg;
		} else {
			return leg;
		}
	}

	return NULL;
}

struct rtp_relay_leg *rtp_relay_get_leg(struct rtp_relay_ctx *ctx,
		str *tag, int idx)
{
	struct list_head *it;
	struct rtp_relay_leg *leg;

	if (tag && !tag->len)
		tag = NULL;

	LM_RTP_DBG("searching for tag [%.*s] idx [%d]\n", tag?tag->len:0, tag?tag->s:"", idx);

	list_for_each(it, &ctx->legs) {
		leg = list_entry(it, struct rtp_relay_leg, list);
		if (tag) {
			/* match by tag */
			if (leg->tag.len) {
				if (str_match(tag, &leg->tag))
					return leg;
				continue;
			}
		}
		if (leg->index != RTP_RELAY_ALL_BRANCHES && leg->index == idx)
			return leg;
	}

	LM_RTP_DBG("no leg for tag [%.*s] idx [%d]\n", tag?tag->len:0, tag?tag->s:"", idx);
	return NULL;
}

struct rtp_relay_leg *rtp_relay_new_leg(struct rtp_relay_ctx *ctx,
		str *tag, int idx)
{
	struct rtp_relay_leg *leg = shm_malloc(sizeof(*leg));
	if (!leg) {
		LM_ERR("oom for new leg!\n");
		return NULL;
	}
	memset(leg, 0, sizeof(*leg));
	if (tag && tag->len)
		shm_str_dup(&leg->tag, tag);
	leg->index = idx;
	leg->ref = 1;
	list_add(&leg->list, &ctx->legs);
	LM_RTP_DBG("new leg=%p index=%d\n", leg, idx);
	return leg;
}

#define PV_RTP_RELAY_INDEX_NONE (0)
#define PV_RTP_RELAY_INDEX_PVAR (1<<0)
#define PV_RTP_RELAY_INDEX_INT  (1<<1)
#define PV_RTP_RELAY_INDEX_TAG  (1<<2)

static int pv_get_rtp_relay_index(struct sip_msg *msg,
		pv_param_p ip, int *idx, str *tag)
{
	pv_value_t tv;
	if(ip==NULL || idx==NULL)
		return -1;

	tag->s = NULL;
	tag->len = 0;
	*idx = RTP_RELAY_ALL_BRANCHES;
	switch (ip->pvi.type) {
		case PV_RTP_RELAY_INDEX_NONE:
			break;
		case PV_RTP_RELAY_INDEX_PVAR:
			if(pv_get_spec_value(msg,
					(const pv_spec_p)ip->pvi.u.dval, &tv)!=0) {
				LM_ERR("cannot get index value\n");
				return -1;
			}
			if(tv.flags & PV_VAL_INT) {
				if (tv.ri < 0) {
					LM_WARN("only positive integer RTP relay branches or "
							"'*' are allowed (%d)! ignoring...\n", tv.ri);
					return -1;
				}
				*idx = tv.ri;
				tag->s = int2str(*idx, &tag->len);
			} else {
				*tag = tv.rs;
			}
			break;
		case PV_RTP_RELAY_INDEX_INT:
			*idx = ip->pvi.u.ival;
			tag->s = int2str(*idx, &tag->len);
			break;
		case PV_RTP_RELAY_INDEX_TAG:
			*tag = *(str *)ip->pvi.u.dval;
			break;
		default:
			LM_BUG("unhandled index type %d\n", ip->pvi.type);
			return -1;
	}
	return 0;
}

static int pv_parse_rtp_relay_index(pv_spec_p sp, const str *in)
{
	char *p, *s;
	str *tag;
	pv_spec_p nsp = 0;

	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;
	p = in->s;
	if(*p==PV_MARKER)
	{
		nsp = (pv_spec_p)pkg_malloc(sizeof(pv_spec_t));
		if(nsp==NULL)
		{
			LM_ERR("no more memory\n");
			return -1;
		}
		memset(nsp, 0, sizeof(pv_spec_t));
		s = pv_parse_spec(in, nsp);
		if(s==NULL)
		{
			LM_ERR("invalid index [%.*s]\n", in->len, in->s);
			pv_spec_free(nsp);
			return -1;
		}
		sp->pvp.pvi.type = PV_RTP_RELAY_INDEX_PVAR;
		sp->pvp.pvi.u.dval = (void*)nsp;
		return 0;
	}
	if(*p=='*' && in->len==1) {
		sp->pvp.pvi.type = PV_RTP_RELAY_INDEX_NONE;
		return 0;
	}
	if (str2sint(in, &sp->pvp.pvi.u.ival) < 0) {
		tag = pkg_malloc(sizeof *tag + in->len);
		if (!tag) {
			LM_ERR("could not allocate tag\n");
			return -1;
		}
		tag->s = (char *)(tag + 1);
		tag->len = in->len;
		memcpy(tag->s, in->s, in->len);
		sp->pvp.pvi.type = PV_RTP_RELAY_INDEX_TAG;
	} else {
		sp->pvp.pvi.type = PV_RTP_RELAY_INDEX_INT;
	}
	return 0;
}


static struct rtp_relay_leg *pv_get_rtp_relay_leg(struct sip_msg *msg,
		pv_param_t *param, struct rtp_relay_ctx *ctx,
		enum rtp_relay_var_flags *flag, int set)
{
	struct rtp_relay_leg *leg, *peer;
	pv_value_t flags_name;
	int idx = RTP_RELAY_ALL_BRANCHES;
	str tag;

	*flag = RTP_RELAY_FLAGS_UNKNOWN;

	if (pv_get_rtp_relay_index(msg, param, &idx, &tag) != 0) {
		LM_ERR("invalid branch index\n");
		return NULL;
	}
	if (tag.len == 0 && idx == RTP_RELAY_ALL_BRANCHES) {
		/* nothing provisioned - lookup through the tag */
		if (parse_headers(msg, HDR_FROM_F|HDR_TO_F, 0) < 0 ||
				!msg->from || !msg->to) {
			LM_ERR("bad request or missing To and/or From headers\n");
			return NULL;
		}
		if (route_type == BRANCH_ROUTE || route_type == ONREPLY_ROUTE) {
			if (parse_to_header(msg) < 0) {
				LM_ERR("cannot parse To header!\n");
				return NULL;
			}
			if (get_to(msg)->tag_value.len)
				/* a sequential should always have a to_tag */
				tag = get_to(msg)->tag_value;
			idx = rtp_relay_ctx_branch();
		} else if (route_type == LOCAL_ROUTE) {
			/* we always force index 0 for local_route */
			idx = rtp_relay_get_last_branch(ctx, msg);
		} else {
			if (parse_from_header(msg) < 0) {
				LM_ERR("cannot parse From header!\n");
				return NULL;
			}
			tag = get_from(msg)->tag_value;
		}
	}
	/* identify the leg in question */
	leg = rtp_relay_get_leg(ctx, &tag, idx);
	if (param->pvn.type) { /* looking for its peer */
		if (ctx->established) {
			if (!leg)
				return NULL;
			if (!leg->peer) {
				LM_ERR("peer does not exist for established session\n");
				return NULL;
			}
			leg = leg->peer;
		} else if (!leg) {
			LM_ERR("no leg identified, so cannot figure out peer\n");
			return NULL;
		} else {
			peer = rtp_relay_get_peer_leg(ctx, leg);
			if (!peer) {
				if (!set)
					return NULL;
				peer = rtp_relay_new_leg(ctx, &get_from(msg)->tag_value, RTP_RELAY_ALL_BRANCHES);
				if (!peer) {
					LM_ERR("cannot create a new leg\n");
					return NULL;
				}
			}
			leg->peer = peer;
			leg = peer;
		}
	} else {
		if (!leg) {
			if (!set)
				return NULL;
			leg = rtp_relay_new_leg(ctx, &tag, idx);
			if (!leg) {
				LM_ERR("cannot create a new leg\n");
				return NULL;
			}
		}
	}

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

	return leg;
}

static int pv_get_rtp_relay_var(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val)
{
	struct rtp_relay_ctx *ctx;
	struct rtp_relay_leg *leg;
	enum rtp_relay_var_flags flag;

	if (!param) {
		LM_ERR("invalid parameter or value to set\n");
		return -1;
	}

	if (!(ctx = rtp_relay_try_get_ctx()))
		return pv_get_null(msg, param, val);

	RTP_RELAY_CTX_LOCK(ctx);

	leg = pv_get_rtp_relay_leg(msg, param, ctx, &flag, 0);
	if (!leg) {
		pv_get_null(msg, param, val);
		goto end;
	}

	if (flag != RTP_RELAY_FLAGS_DISABLED) {
		val->rs = leg->flags[flag];
	} else if (rtp_leg_disabled(leg)) {
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
	struct rtp_relay_ctx *ctx;
	struct rtp_relay_leg *leg;
	int ret = 0;
	int disabled;
	str s = {NULL, 0};

	if (!(ctx = rtp_relay_get_ctx())) {
		LM_ERR("could not get/create context!\n");
		return -2;
	}
	RTP_RELAY_CTX_LOCK(ctx);

	leg = pv_get_rtp_relay_leg(msg, param, ctx, &flag, 1);
	if (!leg) {
		LM_ERR("could not get context session!\n");
		ret = -2;
		goto end;
	}

	if (flag == RTP_RELAY_FLAGS_DISABLED) {
		/* disabled is treated differently */
		if (!val || (val->flags & PV_VAL_NULL))
			disabled = 0;
		else if (pvv_is_int(val))
			disabled = val->ri;
		else if (val->rs.len != 0)
			disabled = 1;
		else
			disabled = 0;
		rtp_leg_set_disabled(leg, disabled);
		goto end;
	}
	if (val && !(val->flags & PV_VAL_NULL)) {
		if (pvv_is_int(val))
			s.s = int2str(val->ri, &s.len);
		else
			s = val->rs;
	}
	if (shm_str_sync(&leg->flags[flag], &s) >= 0)
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

enum rtp_relay_ctx_flags {
	RTP_RELAY_CTX_CALLID,
	RTP_RELAY_CTX_FROM_TAG,
	RTP_RELAY_CTX_TO_TAG,
	RTP_RELAY_CTX_FLAGS,
	RTP_RELAY_CTX_DELETE,
	RTP_RELAY_CTX_UNKNOWN,
};

static enum rtp_relay_ctx_flags rtp_relay_ctx_flags_get(const str *in)
{
	if (str_casematch_nt(in, "call_id") ||
			str_casematch_nt(in, "call-id") ||
			str_casematch_nt(in, "callid"))
		return RTP_RELAY_CTX_CALLID;
	if (str_casematch_nt(in, "from_tag") ||
			str_casematch_nt(in, "from-tag") ||
			str_casematch_nt(in, "fromtag"))
		return RTP_RELAY_CTX_FROM_TAG;
	if (str_casematch_nt(in, "to_tag") ||
			str_casematch_nt(in, "to-tag") ||
			str_casematch_nt(in, "totag"))
		return RTP_RELAY_CTX_TO_TAG;
	if (str_casematch_nt(in, "flags"))
		return RTP_RELAY_CTX_FLAGS;
	if (str_casematch_nt(in, "delete"))
		return RTP_RELAY_CTX_DELETE;
	return RTP_RELAY_CTX_UNKNOWN;
}

static enum rtp_relay_ctx_flags
	rtp_relay_ctx_flags_resolve(struct sip_msg *msg, pv_param_t *param)
{
	pv_value_t flags_name;
	if (param->pvn.type & RTP_RELAY_PV_VAR) {
		if (pv_get_spec_value(msg, (pv_spec_p)param->pvi.u.dval, &flags_name) < 0)
			LM_ERR("cannot get the name of the RTP ctx flag\n");
		else if (pvv_is_str(&flags_name))
			return rtp_relay_ctx_flags_get(&flags_name.rs);
	} else {
		return param->pvn.u.isname.name.n;
	}
	return RTP_RELAY_CTX_UNKNOWN;
}

static int pv_get_rtp_relay_ctx(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val)
{
	str *sync = NULL;
	struct rtp_relay_ctx *ctx;
	enum rtp_relay_ctx_flags flag;

	flag = rtp_relay_ctx_flags_resolve(msg, param);
	if (flag == RTP_RELAY_CTX_UNKNOWN) {
		LM_ERR("could not resolve ctx flag!\n");
		return -1;
	}

	if (!(ctx = rtp_relay_try_get_ctx()))
		return pv_get_null(msg, param, val);

	RTP_RELAY_CTX_LOCK(ctx);
	switch (flag) {
		case RTP_RELAY_CTX_CALLID:
			sync = &ctx->callid;
			break;
		case RTP_RELAY_CTX_FROM_TAG:
			sync = &ctx->from_tag;
			break;
		case RTP_RELAY_CTX_TO_TAG:
			sync = &ctx->to_tag;
			break;
		case RTP_RELAY_CTX_FLAGS:
			sync = &ctx->flags;
			break;
		case RTP_RELAY_CTX_DELETE:
			sync = &ctx->delete;
			break;
		default:
			LM_BUG("unhandled flag %d\n", flag);
			break;
	}
	if (sync && sync->len) {
		val->rs = *sync;
		val->flags = PV_VAL_STR;
	} else {
		pv_get_null(msg, param, val);
	}
	RTP_RELAY_CTX_UNLOCK(ctx);
	return 0;
}

static int pv_set_rtp_relay_ctx(struct sip_msg *msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	int ret = -3;
	str *sync = NULL;
	struct rtp_relay_ctx *ctx;
	enum rtp_relay_ctx_flags flag;
	str s = {NULL, 0};

	flag = rtp_relay_ctx_flags_resolve(msg, param);
	if (flag == RTP_RELAY_CTX_UNKNOWN) {
		LM_ERR("could not resolve ctx flag!\n");
		return -1;
	}

	if (!(ctx = rtp_relay_get_ctx())) {
		LM_ERR("could not get/create context!\n");
		return -2;
	}
	RTP_RELAY_CTX_LOCK(ctx);
	switch (flag) {
		case RTP_RELAY_CTX_CALLID:
			sync = &ctx->callid;
			break;
		case RTP_RELAY_CTX_FROM_TAG:
			sync = &ctx->from_tag;
			break;
		case RTP_RELAY_CTX_TO_TAG:
			sync = &ctx->to_tag;
			break;
		case RTP_RELAY_CTX_FLAGS:
			sync = &ctx->flags;
			break;
		case RTP_RELAY_CTX_DELETE:
			sync = &ctx->delete;
			break;
		default:
			LM_BUG("unhandled flag %d\n", flag);
			break;
	}
	if (sync) {
		if (val && !(val->flags & PV_VAL_NULL)) {
			if (pvv_is_int(val))
				s.s = int2str(val->ri, &s.len);
			else
				s = val->rs;
		}
		if (s.s && s.len) {
			if (shm_str_sync(sync, &s) >=0)
				ret = 1;
		} else {
			if (sync->s) {
				shm_free(sync->s);
				sync->s = 0;
				sync->len = 0;
			}
		}
	}
	RTP_RELAY_CTX_UNLOCK(ctx);
	return ret;
}

static int pv_parse_rtp_relay_ctx(pv_spec_p sp, const str *in)
{
	enum rtp_relay_ctx_flags flag;
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
		flag = rtp_relay_ctx_flags_get(in);
		if (flag == RTP_RELAY_CTX_UNKNOWN) {
			LM_ERR("invalid RTP relay context flag %.*s\n", in->len, in->s);
			return -1;
		}
		sp->pvp.pvn.u.isname.name.n = flag;
	}
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
