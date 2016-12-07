/*
 * Copyright (C) 2016 Razvan Crainea <razvan@opensips.org>
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
 * close call
 * generate CDR
 * add multi-leg values
 * raw commands
 */

#include "../../dprint.h"
#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../db/db.h"
#include "../../mod_fix.h"
#include "../../lib/list.h"
#include "../../resolve.h"
#include "../../reactor_defs.h"
#include "cgrates.h"
#include "cgrates_acc.h"
#include "cgrates_auth.h"
#include "cgrates_common.h"
#include "cgrates_engine.h"

int cgre_conn_tout = CGR_DEFAULT_CONN_TIMEOUT;
int cgrc_max_conns = CGR_DEFAULT_MAX_CONNS;
str cgre_bind_ip;

#if 0
static int w_async_cgr_engage(struct sip_msg* msg,
		async_resume_module **resume_f, void **resume_p,
		char* acc_c, char *dst_c);
#endif
static int fixup_cgrates(void ** param, int param_no);
static int mod_init(void);
static void mod_destroy(void);
static int child_init(int rank);
static int cgrates_set_engine(modparam_t type, void * val);

struct cgr_uac {
	struct list_head kv_store;
};

#define CGRB_ALL_BRANCHES ((unsigned int)-1)

struct cgr_param {
	int wait_for_reply;
	struct sip_msg *msg;
	struct cgr_conn *c;
};

#define CGRF_ENGAGED	0x1

int cgr_ctx_idx;
static int cgr_tm_ctx_idx;
// TODO static inline struct cgr_acc_ctx *cgr_get_acc_branch(void);

#define CGR_GET_SHM_CTX(_t) \
	(cgr_tmb.t_ctx_get_ptr(_t, cgr_tm_ctx_idx))
#define CGR_PUT_SHM_CTX(_t, _p) \
	cgr_tmb.t_ctx_put_ptr(_t, cgr_tm_ctx_idx, _p)

static int cgrates_async_resume_repl(int fd, struct sip_msg *msg, void *param);

static int pv_set_cgr(struct sip_msg *msg, pv_param_t *param,
		int op, pv_value_t *val);
static int pv_get_cgr(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val);
static int pv_parse_cgr(pv_spec_p sp, str *in);
static int pv_get_cgr_reply(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val);
static inline int cgr_replace_shm_kv(struct list_head *head,
		const char *key, int flags, int_str *val);

LIST_HEAD(cgrates_engines);

static cmd_export_t cmds[] = {
	{"cgrates_acc", (cmd_function)w_cgr_acc, 1, fixup_cgrates, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"cgrates_auth", (cmd_function)w_cgr_auth, 1, fixup_cgrates, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{0, 0, 0, 0, 0, 0}
};

static pv_export_t pvars[] = {
	{ str_init("cgr"), 2003, pv_get_cgr, pv_set_cgr,
		pv_parse_cgr, 0, 0, 0},
	{ str_init("cgrret"), 2004, pv_get_cgr_reply,
		0, 0, 0, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};


static acmd_export_t acmds[] = {
	/*
	{"cgrates_engage",  (acmd_function)w_async_cgr_engage, 1,
		fixup_cgrates},
		*/
	{0, 0, 0, 0, }
};

static param_export_t params[] = {
	{"cgrates_engine", STR_PARAM|USE_FUNC_PARAM,
		(void*)cgrates_set_engine },
	{"bind_ip", STR_PARAM, &cgre_bind_ip.s },
	{"max_async_connections", INT_PARAM, &cgrc_max_conns },
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
	0,           /* extra processes */
	mod_init,
	0,           /* reply processing */
	mod_destroy, /* destroy function */
	child_init
};



static int fixup_cgrates(void ** param, int param_no)
{
	if (param_no > 0 && param_no < 5)
		return fixup_spve(param);
	if (param_no == 5)
		return fixup_pvar(param);
	LM_CRIT("Unknown parameter number %d\n", param_no);
	return E_UNSPEC;
}

static int mod_init(void)
{
	if (cgre_conn_tout < 0) {
		LM_ERR("Invalid connection timeout to CGR engine\n");
		return -1;
	}

	if (cgrc_max_conns < 1) {
		LM_WARN("Invalid number of maximum async connections: %d! "
				"Async mode disabled!\n", cgrc_max_conns);
		cgrc_max_conns = 0;
	}

	/* load the TM API */
	if (load_tm_api(&cgr_tmb)!=0) {
		LM_ERR("can't load TM API\n");
		return -1;
	}

	if (load_dlg_api(&cgr_dlgb)!=0) {
		LM_ERR("failed to find dialog API - is dialog module loaded?\n");
		return -1;
	}
	
	/* TODO: register also for loaded dialogs */

	if (cgre_bind_ip.s)
		cgre_bind_ip.len = strlen(cgre_bind_ip.s);

	cgr_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, cgr_free_ctx);
	cgr_tm_ctx_idx = cgr_tmb.t_ctx_register_ptr(NULL);

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

	return 0;
}


static void mod_destroy(void)
{
	return;
}

/*
static json_object *cgr_get_start_msg(struct sip_msg *msg, str *acc, str *dst)
{
	struct dlg_cell *dlg = cgr_dlgb.get_dlg();
	if (!dlg) {
		LM_ERR("Cannot retrieve the dialog information\n");
		return NULL;
	}
	return cgr_get_generic_msg("SMGenericV1.InitiateSession", NULL, 1);
}
*/

#if 0
static json_object *cgr_get_auth_msg(struct sip_msg *msg, str *acc, str *dst)
{
	struct dlg_cell *dlg = cgr_dlgb.get_dlg();
	struct list_head *hlist, *l, *lt;
	struct cgr_kv *kv, *newkv;
	struct cgr_ctx *ctx;
	struct cell *t;
	int_str val;

	if (!dlg) {
		LM_ERR("Cannot retrieve the dialog information\n");
		return NULL;
	}
	if (!(t = cgr_tmb.t_gett())) {
		if (cgr_tmb.t_newtran(msg) < 0 || !(t = cgr_tmb.t_gett())) {
			LM_ERR("cannot create transaction!\n");
			return NULL;
		}
	}
	hlist = CGR_GET_SHM_CTX(t);
	if (!hlist) {
		hlist = shm_malloc(sizeof *hlist);
		if (!hlist) {
			LM_ERR("out of shm memory!\n");
			return NULL;
		}
		INIT_LIST_HEAD(hlist);
	}
	if ((ctx = CGR_GET_CTX()) != NULL) {
		list_for_each(l, &ctx->kv_store) {
			kv = list_entry(l, struct cgr_kv, list);
			newkv = cgr_dup_kvlist_shm_kv(kv);
			if (!newkv) {
				LM_ERR("cannot duplicate args list\n");
				goto error;
			}
			list_add(&newkv->list, hlist);
		}
	}

	/* OriginID */
	if(msg->callid==NULL && ((parse_headers(msg, HDR_CALLID_F, 0)==-1) ||
			(msg->callid==NULL)) ) {
		LM_ERR("Cannot get callid of the message!\n");
		goto error;
	}
	val.s = msg->callid->body;
	if (cgr_replace_shm_kv(hlist, "OriginID", CGR_KVF_TYPE_STR,
			&val) < 0) {
		LM_ERR("Cannot add OriginID header\n");
		goto error;
	}

	val.s = *acc;
	if (cgr_replace_shm_kv(hlist, "Account", CGR_KVF_TYPE_STR,
			&val) < 0) {
		LM_ERR("Cannot add Account header\n");
		goto error;
	}

	val.s = *dst;
	if (cgr_replace_shm_kv(hlist, "Destination", CGR_KVF_TYPE_STR,
			&val) < 0) {
		LM_ERR("Cannot add Destination header\n");
		goto error;
	}

#if 0
	val.n = dlg->h_entry;
	if (cgr_replace_shm_kv(hlist, "DialogEntry", CGR_KVF_TYPE_INT,
			&val) < 0) {
		LM_ERR("Cannot add DialogEntry header\n");
		goto error;
	}
	val.n = dlg->h_id;
	if (cgr_replace_shm_kv(hlist, "DialogId", CGR_KVF_TYPE_INT,
			&val) < 0) {
		LM_ERR("Cannot add DialogId header\n");
		goto error;
	}
	CGR_PUT_SHM_CTX(t, hlist);
#endif
	
	return cgr_get_generic_msg("SMGenericV1.MaxUsage", hlist, 0);
error:
	list_for_each_safe(l, lt, hlist)
		cgr_free_kv(list_entry(l, struct cgr_kv, list));
	shm_free(hlist);
	return NULL;
}
#endif


static inline int async_cgr_handle_cmd(struct sip_msg *msg,
		async_resume_module **resume_f, void **resume_p, str *smsg)
{
	struct list_head *l;
	struct cgr_engine *e;
	struct cgr_conn *c;
	struct cgr_param *cp = NULL;
	int ret = 1;
	cp = pkg_malloc(sizeof *cp);
	if (!cp) {
		LM_ERR("out of pkg memory\n");
		return -2;
	}
	memset(cp, 0, sizeof *cp);

	/* reset the error */
	CGR_RESET_REPLY_CTX();

	/* connect to all servers */
	/* go through each server and initialize the state */
	list_for_each(l, &cgrates_engines) {
		e = list_entry(l, struct cgr_engine, list);
		if (!(c = cgr_get_free_conn(e)))
			continue;
		/* found a free connection - build the buffer */
		cp->c = c;
		cp->wait_for_reply = 1;
		if (cgrc_send(c, smsg) < 0) {
			cgrc_close(c, CGRC_IS_LISTEN(c));
			continue;
		}
		/* message succesfully sent - now fetch the reply */
		if (CGRC_IS_DEFAULT(c)) {
			cp->msg = msg;
			do {
				ret = cgrc_async_read(c, NULL, cp);
			} while(async_status == ASYNC_CONTINUE);
			pkg_free(cp);
			if (async_status == ASYNC_DONE)
				/* do the reading in sync mode */
				async_status = ASYNC_SYNC;
			else
				return -3;
		} else {
			c->state = CGRC_USED;
			if (CGRC_IS_LISTEN(c)) {
				/* remove the fd from the reactor because it will be added at the end of
				 * this function */
				reactor_del_reader(c->fd, -1, 0);
				CGRC_UNSET_LISTEN(c);
			}
			async_status = c->fd;
			*resume_f = cgrates_async_resume_repl;
			*resume_p = cp;
		}
		return ret;
	}
	async_status = ASYNC_NO_IO;
	pkg_free(cp);
	return -3;
}

#if 0
static int w_async_cgr_engage(struct sip_msg* msg,
		async_resume_module **resume_f, void **resume_p,
		char* acc_c, char *dst_c)
{
	str acc_str;
	str dst;
	json_object *jmsg = NULL;
	str smsg;
	int ret;

	if (msg->REQ_METHOD != METHOD_INVITE || has_totag(msg)) {
		LM_DBG("cgrates not engaged on initial INVITE\n");
		return -4;
	}

	if (acc_c && fixup_get_svalue(msg, (gparam_p)acc_c, &acc_str) < 0) {
		LM_ERR("failed fo fetch account's name\n");
		return -2;
	}

	if (dst_c) {
		if (fixup_get_svalue(msg, (gparam_p)dst_c, &dst) < 0) {
			LM_ERR("failed fo fetch the destination\n");
			return -2;
		}
	} else if (get_request_user(msg) == 0) {
		LM_ERR("failed to get destination from R-URI\n");
		return -4;
	}

	/* create the dialog if does not exist yet */
	if (!cgr_dlgb.get_dlg() && cgr_dlgb.create_dlg(msg, 0) < 0) {
		LM_ERR("error creating new dialog\n");
		return -2;
	}

	if (cgr_tmb.register_tmcb( msg, 0, TMCB_ON_FAILURE|TMCB_RESPONSE_OUT,
			cgr_tmcb_func, 0, 0)<=0) {
		LM_ERR("cannot register tm callbacks\n");
		return -2;
	}

	jmsg = cgr_get_auth_msg(msg, &acc_str, &dst);
	if (!jmsg) {
		LM_ERR("cannot build the json to send to cgrates\n");
		return -2;
	}
	smsg.s = (char *)json_object_to_json_string(jmsg);
	smsg.len = strlen(smsg.s);

	ret = async_cgr_handle_cmd(msg, resume_f, resume_p, &smsg);
	json_object_put(jmsg);

	return ret;
}
#endif

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


static int cgrates_async_resume_repl(int fd,
		struct sip_msg *msg, void *param)
{
	int ret;
	struct cgr_param *cp = (struct cgr_param *)param;
	struct cgr_conn *c = cp->c;

	cp->msg = msg;

	ret = cgrc_async_read(c, NULL, cp);

	if (async_status == ASYNC_DONE) {
		/* processing done - remove the FD and replace the handler */
		async_status = ASYNC_DONE_NO_IO;
		reactor_del_reader(c->fd, -1, 0);
		if (cgrc_start_listen(c) < 0) {
			LM_CRIT("cannot re-register fd for cgrates events!\n");
			return -1;
		}
	}
	return ret;
}


static inline int cgr_replace_shm_kv(struct list_head *head,
		const char *key, int flags, int_str *val)
{
	struct cgr_kv *kv;
	int len;
	str n = { (char *)key, strlen(key) };
	kv = cgr_get_kv(head, n);
	flags |= CGR_KVF_TYPE_SHM;
	if (kv) {
		if (flags & CGR_KVF_TYPE_STR) {
			if ((kv->flags & CGR_KVF_TYPE_STR) &&
					val->s.len <= kv->value.s.len) {
				/* simply update the value */
				kv->value.s.len = val->s.len;
				memcpy(kv->value.s.s, val->s.s, val->s.len);
				return 0;
			} else {
				/* free it and remove it, because we need to add a new one */
				cgr_free_kv(kv);
			}
		} else {
			kv->flags = flags;
			kv->value.n = val->n;
			return 0;
		}
	}
	len = sizeof(*kv) + strlen(key) + 1;

	if (flags & CGR_KVF_TYPE_STR)
		len += val->s.len;
	kv = shm_malloc(len);
	if (!kv) {
		LM_ERR("cannot allocate memory for kv\n");
		return -1;
	}
	kv->key.s = (char *)(kv + 1);
	kv->key.len = strlen(key);
	memcpy(kv->key.s, key, kv->key.len + 1); /* also copy \0 */
	if (flags & CGR_KVF_TYPE_STR) {
		kv->value.s.s = kv->key.s + kv->key.len + 1;
		kv->value.s.len = val->s.len;
		memcpy(kv->value.s.s, val->s.s, val->s.len);
	} else if (flags & CGR_KVF_TYPE_INT)
		kv->value.n = val->n;
	kv->flags = flags;
	list_add(&kv->list, head);
	return 0;
}


static int pv_set_cgr(struct sip_msg *msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	pv_value_t name_val;
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

	if (!(ctx = cgr_get_ctx_new()))
		return -2;

	/* check if there already is a kv with that name */
	kv = cgr_get_kv(&ctx->kv_store, name_val.rs);
	if (kv) {
		/* replace the old value */
		cgr_free_kv_val(kv);
		if (val->flags & PV_VAL_NULL && op == COLONEQ_T) {
			/* destroy the value */
			cgr_free_kv(kv);
			return 0;
		}
	} else {
		kv = cgr_new_kv(name_val.rs, dup);
		if (!kv) {
			LM_ERR("cannot allocate new key-value\n");
			return -1;
		}
		list_add(&kv->list, &ctx->kv_store);
	}
	if (val->flags & PV_VAL_NULL) {
		kv->flags |= CGR_KVF_TYPE_NULL;
	} else if (val->flags & PV_VAL_INT) {
		kv->flags |= CGR_KVF_TYPE_INT;
		kv->value.n = val->ri;
	} else if (val->flags & PV_VAL_STR) {
		kv->value.s.s = pkg_malloc(val->rs.len);
		if (!kv->value.s.s) {
			LM_ERR("out of pkg mem!\n");
			goto free_kv;
		}
		memcpy(kv->value.s.s, val->rs.s, val->rs.len);
		kv->value.s.len = val->rs.len;
		kv->flags |= CGR_KVF_TYPE_STR;
	}
	LM_INFO("ADDED: %d %s\n", kv->key.len, kv->key.s);

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

	if (!param || !val) {
		LM_ERR("invalid parameter or value to set\n");
		return -1;
	}

	if (!(ctx = CGR_GET_CTX()))
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
	if (!(kv = cgr_get_kv(&ctx->kv_store, name_val.rs)) || \
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
	struct cgr_ctx *ctx;

	if (!param || !val) {
		LM_ERR("invalid parameter or value to set\n");
		return -1;
	}

	if (!(ctx = CGR_GET_CTX()) || !ctx->reply)
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
