/*
 * Copyright (C) 2017 Răzvan Crainea <razvan@opensips.org>
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
 */

/* TODO list:
 * engage per branch
 * drop accounting for all branches
 * drop accounting for a specific branch
 * add multi-leg values
 */

#include "../../dprint.h"
#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../db/db.h"
#include "../../mod_fix.h"
#include "../../lib/list.h"
#include "../../resolve.h"
#include "cgrates.h"
#include "cgrates_cmd.h"
#include "cgrates_acc.h"
#include "cgrates_auth.h"
#include "cgrates_common.h"
#include "cgrates_engine.h"

int cgre_retry_tout = CGR_DEFAULT_RETRY_TIMEOUT;
int cgrc_max_conns = CGR_DEFAULT_MAX_CONNS;
str cgre_bind_ip;

static int fixup_cgrates_auth(void ** param, int param_no);
static int fixup_cgrates_acc(void ** param, int param_no);
static int mod_init(void);
static void mod_destroy(void);
static int child_init(int rank);
static int cgrates_set_engine(modparam_t type, void * val);

int cgr_ctx_idx;
int cgr_ctx_local_idx;
int cgr_tm_ctx_idx = -1;

static int pv_set_cgr(struct sip_msg *msg, pv_param_t *param,
		int op, pv_value_t *val);
static int pv_get_cgr(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val);
static int pv_parse_cgr(pv_spec_p sp, str *in);
static int pv_parse_idx_cgr(pv_spec_p sp, str *in);
static int pv_get_cgr_reply(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val);

LIST_HEAD(cgrates_engines);

static cmd_export_t cmds[] = {
	{"cgrates_acc", (cmd_function)w_cgr_acc, 0, fixup_cgrates_acc, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"cgrates_acc", (cmd_function)w_cgr_acc, 1, fixup_cgrates_acc, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"cgrates_acc", (cmd_function)w_cgr_acc, 2, fixup_cgrates_acc, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"cgrates_acc", (cmd_function)w_cgr_acc, 3, fixup_cgrates_acc, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"cgrates_acc", (cmd_function)w_cgr_acc, 4, fixup_cgrates_acc, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"cgrates_auth", (cmd_function)w_cgr_auth, 0, fixup_cgrates_auth, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"cgrates_auth", (cmd_function)w_cgr_auth, 1, fixup_cgrates_auth, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"cgrates_auth", (cmd_function)w_cgr_auth, 2, fixup_cgrates_auth, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"cgrates_auth", (cmd_function)w_cgr_auth, 3, fixup_cgrates_auth, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"cgrates_cmd", (cmd_function)w_cgr_cmd, 1, fixup_spve_null, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"cgrates_cmd", (cmd_function)w_cgr_cmd, 2, fixup_spve_spve, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{0, 0, 0, 0, 0, 0}
};

static pv_export_t pvars[] = {
	{ str_init("cgr"), 2003, pv_get_cgr, pv_set_cgr,
		pv_parse_cgr, pv_parse_idx_cgr, 0, 0},
	{ str_init("cgrret"), 2004, pv_get_cgr_reply,
		0, 0, 0, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};


static acmd_export_t acmds[] = {
	{"cgrates_auth",  (acmd_function)w_acgr_auth, 0, fixup_cgrates_auth},
	{"cgrates_auth",  (acmd_function)w_acgr_auth, 1, fixup_cgrates_auth},
	{"cgrates_auth",  (acmd_function)w_acgr_auth, 2, fixup_cgrates_auth},
	{"cgrates_auth",  (acmd_function)w_acgr_auth, 3, fixup_cgrates_auth},
	{"cgrates_cmd",   (acmd_function)w_acgr_cmd,  1, fixup_spve_null},
	{"cgrates_cmd",   (acmd_function)w_acgr_cmd,  1, fixup_spve_null},
	{0, 0, 0, 0, }
};

static param_export_t params[] = {
	{"cgrates_engine", STR_PARAM|USE_FUNC_PARAM,
		(void*)cgrates_set_engine },
	{"bind_ip", STR_PARAM, &cgre_bind_ip.s },
	{"max_async_connections", INT_PARAM, &cgrc_max_conns },
	{"retry_timeout", INT_PARAM, &cgre_retry_tout },
	{0, 0, 0}
};

static mi_export_t mi_cmds[] = {
	{ 0, 0, 0, 0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "dialog", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
	},
};

struct module_exports exports = {
	"cgrates",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	&deps,           /* OpenSIPS module dependencies */
	cmds,
	acmds,
	params,
	0,           /* exported statistics */
	mi_cmds,     /* exported MI functions */
	pvars,       /* exported pseudo-variables */
	0,			 /* exported transformations */
	0,           /* extra processes */
	mod_init,
	0,           /* reply processing */
	mod_destroy, /* destroy function */
	child_init
};



static int fixup_cgrates_auth(void ** param, int param_no)
{
	if (param_no < 4)
		return fixup_spve(param);
	LM_CRIT("Unknown parameter number %d\n", param_no);
	return E_UNSPEC;
}

static int fixup_cgrates_acc(void ** param, int param_no)
{
	static int dlg_loaded = 0;
	unsigned flags = 0;
	char *p, *e;
	str s;

	if (!dlg_loaded) {
		dlg_loaded = 1;
		if (load_dlg_api(&cgr_dlgb)!=0)
			LM_DBG("failed to find dialog API - is dialog module loaded?\n");

		if (!cgr_dlgb.get_dlg) {
			LM_WARN("error loading dialog module - acc cannot be generated\n");
			return -1;
		}

		if (cgr_dlgb.register_dlgcb(NULL, DLGCB_LOADED, cgr_loaded_callback,
				NULL, NULL) < 0)
			LM_ERR("cannot register callback for dialog loaded - accounting "
					"for ongoing calls will be lost after restart\n");
		LM_DBG("loaded cgr_loaded_callback!\n");
	}

	if (param_no == 1) {
		/* parse flags */
		s.s = (char *)*param;
		e = s.s + strlen(s.s);
		while (s.s < e) {
			p = strchr(s.s, '|');
			s.len = (p ? (p - s.s) : strlen(s.s));
			str_trim_spaces_lr(s);
			if (!strncasecmp(s.s, "missed", 6))
				flags |= CGRF_DO_MISSED;
			else if (!strncasecmp(s.s, "cdr", 3))
				flags |= CGRF_DO_CDR;
			else
				LM_WARN("unknown flag [%.*s]\n", s.len, s.s);
			if (p)
				s.s = p + 1;
			else
				break;
		}
		if ((flags & (CGRF_DO_MISSED|CGRF_DO_CDR)) == CGRF_DO_MISSED) {
			LM_WARN("missed flag without cdr does not do anything; "
					"ignoring it...\n");
			flags &= ~CGRF_DO_MISSED;
		}
		*param = (unsigned long *)(unsigned long)flags;
		return 0;
	}
	if (param_no >= 2 && param_no <= 4)
		return fixup_spve(param);
	LM_CRIT("Unknown parameter number %d\n", param_no);
	return E_UNSPEC;
}

static int mod_init(void)
{
	if (cgre_retry_tout < 0) {
		LM_ERR("Invalid retry connection timeout\n");
		return -1;
	}

	if (cgrc_max_conns < 1) {
		LM_WARN("Invalid number of maximum async connections: %d! "
				"Async mode disabled!\n", cgrc_max_conns);
		cgrc_max_conns = 0;
	}

	/* load the TM API */
	if (load_tm_api(&cgr_tmb)!=0) {
		LM_INFO("TM not loaded- cannot store variables in transaction!\n");
	} else {
		cgr_tm_ctx_idx = cgr_tmb.t_ctx_register_ptr(cgr_free_ctx);
		/* register a routine to move the pointer in tm when the transaction
		 * is created! */
		if (cgr_tmb.register_tmcb(0, 0, TMCB_REQUEST_IN, cgr_move_ctx, 0, 0)<=0) {
			LM_ERR("cannot register tm callbacks\n");
			return -2;
		}
	}

	if (cgre_bind_ip.s)
		cgre_bind_ip.len = strlen(cgre_bind_ip.s);

	cgr_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, cgr_free_ctx);
	cgr_ctx_local_idx = context_register_ptr(CONTEXT_GLOBAL, cgr_free_local_ctx);

	return 0;
}

static int child_init(int rank)
{
	struct list_head *l;
	struct cgr_engine *e;
	struct cgr_conn *c;

	/* connect to all servers */
	/* go through each server and initialize a single connection */
	list_for_each(l, &cgrates_engines) {
		e = list_entry(l, struct cgr_engine, list);
		/* start a connection for everybody */
		if ((c = cgrc_new(e)) && cgrc_conn(c) >= 0) {
			/* but only non module processes have reactors */
			e->default_con = c;
			CGRC_SET_DEFAULT(c);
			if (rank != PROC_MODULE && rank != PROC_MAIN)
				cgrc_start_listen(c);
		}
	}
	return cgr_init_common();
}


static void mod_destroy(void)
{
	return;
}

static int cgrates_set_engine(modparam_t type, void * val)
{
	char *p;
	unsigned int port;
	str host;
	str port_s;
	struct cgr_engine *e;
	struct ip_addr *ip;
	char *s = (char *)val;

	if (!s)
		return 0;

	host.s = s;
	p = strchr(s, ':');
	if (p) {
		host.len = p - s;
		port_s.s = p + 1;
		port_s.len = strlen(s) - host.len - 1;
		str_trim_spaces_lr(port_s);
		if (str2int(&port_s, &port) < 0) {
			LM_ERR("Invalid engine port [%.*s]\n", port_s.len, port_s.s);
			return -1;
		}
		if (port > 65536) {
			LM_ERR("Invalid port number %u\n", port);
			return -1;
		}
	} else {
		host.len = strlen(s);
		port = CGR_DEFAULT_PORT;
	}
	str_trim_spaces_lr(host);
	if ((ip = str2ip(&host)) == NULL) {
		LM_ERR("invalid ip in cgr engine host: %.*s\n", host.len, host.s);
		return -1;
	}

	LM_DBG("Adding cgrates engine %.*s:%u\n", host.len, host.s, port);

	e = pkg_malloc(sizeof(*e) + host.len);
	if (!e) {
		LM_ERR("out of pkg mem!\n");
		return -1;
	}
	memset(e, 0, sizeof(*e));
	e->host.s = (char *)(e + 1);
	e->host.len = host.len;
	memcpy(e->host.s, host.s, host.len);

	e->port = port;
	init_su(&e->su, ip, port);

	INIT_LIST_HEAD(&e->conns);

	list_add_tail(&e->list, &cgrates_engines);

	return 0;
}

static inline str *pv_get_idx_value(struct sip_msg *msg, pv_param_t *param)
{
	static pv_value_t idx_val;

	if (param->pvi.u.dval) {
		if (param->pvi.type == PV_NAME_PVAR) {
			if (pv_get_spec_value(msg, (pv_spec_p)param->pvi.u.dval, &idx_val) != 0) {
				LM_WARN("cannot get the tag of the cgr variable! "
						"using default\n");
				return NULL;
			}
			if (idx_val.flags & PV_VAL_NULL ||
				!(idx_val.flags & PV_VAL_STR)) {
				LM_WARN("invalid tag for variable! using default\n");
				return NULL;
			}
			return &idx_val.rs;
		} else {
			return (str *)param->pvi.u.dval;
		}
	}
	return NULL;
}

static int pv_set_cgr(struct sip_msg *msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	pv_value_t name_val;
	struct cgr_session *s;
	struct cgr_ctx *ctx;
	struct cgr_kv *kv;
	int dup;

	if (!param || !val) {
		LM_ERR("invalid parameter or value to set\n");
		return -1;
	}

	/* first get the name of the field */
	if (param->pvn.type == PV_NAME_PVAR) {
		if (pv_get_spec_value(msg, (pv_spec_p)param->pvn.u.dname, &name_val) != 0) {
			LM_ERR("cannot get the name of the cgr variable\n");
			return -1;
		}
		if (name_val.flags & PV_VAL_NULL ||
			!(name_val.flags & PV_VAL_STR)) {
			LM_ERR("invalid name for variable!\n");
			return -1;
		}
		dup = 1;
	} else {
		name_val.rs = param->pvn.u.isname.name.s;
		dup = 0;
	}
	if (!name_val.rs.s || !name_val.rs.len) {
		LM_ERR("variable name not specified!\n");
		return -1;
	}

	if (!(ctx = cgr_get_ctx()))
		return -2;

	s = cgr_get_sess_new(ctx, pv_get_idx_value(msg, param));
	if (!s) {
		LM_ERR("cannot get a new dict!\n");
		return -2;
	}

	/* check if there already is a kv with that name */
	kv = cgr_get_kv(s, name_val.rs);
	if (kv) {
		/* replace the old value */
		cgr_free_kv_val(kv);
		if (val->flags & PV_VAL_NULL && op == COLONEQ_T) {
			/* destroy the value */
			cgr_free_kv(kv);
			return 0;
		}
	} else {
		kv = cgr_new_real_kv(name_val.rs.s, name_val.rs.len, dup);
		if (!kv) {
			LM_ERR("cannot allocate new key-value\n");
			return -1;
		}
		list_add(&kv->list, &s->kvs);
	}
	if (val->flags & PV_VAL_NULL) {
		kv->flags |= CGR_KVF_TYPE_NULL;
	} else if (val->flags & PV_VAL_INT) {
		kv->flags |= CGR_KVF_TYPE_INT;
		kv->value.n = val->ri;
	} else if (val->flags & PV_VAL_STR) {
		kv->value.s.s = shm_malloc(val->rs.len);
		if (!kv->value.s.s) {
			LM_ERR("out of shm mem!\n");
			goto free_kv;
		}
		memcpy(kv->value.s.s, val->rs.s, val->rs.len);
		kv->value.s.len = val->rs.len;
		kv->flags |= CGR_KVF_TYPE_STR;
	}
	LM_DBG("add cgr kv: %d %s in %p\n", kv->key.len, kv->key.s, s);

	return 0;
free_kv:
	cgr_free_kv(kv);
	return -1;
}

static int pv_get_cgr(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val)
{
	pv_value_t name_val;
	struct cgr_ctx *ctx;
	struct cgr_kv *kv;
	struct cgr_session *s;

	if (!param || !val) {
		LM_ERR("invalid parameter or value to set\n");
		return -1;
	}

	if (!(ctx = CGR_GET_CTX()))
		return pv_get_null(msg, param, val);

	s = cgr_get_sess(ctx, pv_get_idx_value(msg, param));
	if (!s)
		return pv_get_null(msg, param, val);

	/* first get the name of the field */
	if (param->pvn.type == PV_NAME_PVAR) {
		if (pv_get_spec_value(msg, (pv_spec_p)param->pvn.u.dname, &name_val) != 0) {
			LM_ERR("cannot get the name of the cgr variable\n");
			return -1;
		}
		if (name_val.flags & PV_VAL_NULL ||
			!(name_val.flags & PV_VAL_STR)) {
			LM_ERR("invalid name for variable!\n");
			return -1;
		}
	} else {
		name_val.rs = param->pvn.u.isname.name.s;
	}

	/* check if there already is a kv with that name */
	if (!(kv = cgr_get_kv(s, name_val.rs)) || \
			kv->flags & CGR_KVF_TYPE_NULL)
		return pv_get_null(msg, param, val);

	if (kv->flags & CGR_KVF_TYPE_INT) {
		val->rs.s = int2str(kv->value.n, &val->rs.len);
		val->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
	} else if (kv->flags & CGR_KVF_TYPE_STR) {
		val->rs = kv->value.s;
		val->flags = PV_VAL_STR;
	} else {
		LM_ERR("unknown type!\n");
		return -1;
	}
	return 0;
}

static int pv_get_cgr_reply(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val)
{
	struct cgr_local_ctx *ctx;

	if (!param || !val) {
		LM_ERR("invalid parameter or value to set\n");
		return -1;
	}

	if (!(ctx = CGR_GET_LOCAL_CTX()) || !ctx->reply)
		return pv_get_null(msg, param, val);

	if (ctx->reply_flags & CGR_KVF_TYPE_STR) {
		val->rs = ctx->reply->s;
		val->flags = PV_VAL_STR;
	} else {
		val->rs.s = int2str(ctx->reply->n, &val->rs.len);
		val->ri = ctx->reply->n;
		val->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
	}

	return 0;
}

static int pv_parse_cgr(pv_spec_p sp, str *in)
{
	char *s;
	pv_spec_t *pv;
	if (!in || !in->s || in->len < 1) {
		LM_ERR("invalid CGR var name!\n");
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
		sp->pvp.pvn.u.dname = sp;
		sp->pvp.pvn.type = PV_NAME_PVAR;
	} else {
		/* we need to add the null terminator */
		s = pkg_malloc(in->len + 1);
		if (!s) {
			LM_ERR("Out of mem!\n");
			return -1;
		}
		memcpy(s, in->s, in->len);
		s[in->len] = '\0';

		sp->pvp.pvn.u.isname.name.s.s = s;
		sp->pvp.pvn.u.isname.name.s.len = in->len;
		sp->pvp.pvn.type = PV_NAME_INTSTR;
	}
	return 0;
}

static int pv_parse_idx_cgr(pv_spec_p sp, str *in)
{
	str *s;
	pv_spec_t *pv;
	if (!in || !in->s || in->len < 1) {
		LM_ERR("invalid CGR var name!\n");
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
		sp->pvp.pvi.u.dval = sp;
		sp->pvp.pvi.type = PV_NAME_PVAR;
	} else {
		/* we need to add the null terminator */
		s = pkg_malloc(sizeof(str) + in->len);
		if (!s) {
			LM_ERR("Out of mem!\n");
			return -1;
		}
		s->s = (char *)s + sizeof(str);
		memcpy(s->s, in->s, in->len);
		s->len = in->len;

		sp->pvp.pvi.u.dval = s;
		sp->pvp.pvi.type = PV_NAME_INTSTR;
	}
	return 0;
}
