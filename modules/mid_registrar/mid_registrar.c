/*
 * Support for:
 *  - REGISTER traffic throttling, optionally with contact aggregation
 *  - processing registrations upon receiving 200 OK replies
 *
 * This module is intended to be used as a middle layer SIP component in
 * environments where a large proportion of SIP UAs (e.g. mobile devices)
 * register at high enough frequencies that they actually degrade the
 * performance of their registrars.
 *
 * Copyright (C) 2016 OpenSIPS Solutions
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
 *  2016-07-06 initial version (liviu)
 */

#include "../../sr_module.h"
#include "../../ut.h"
#include "../../timer.h"
#include "../../data_lump.h"
#include "../../rw_locking.h"

#include "mid_registrar.h"
#include "save.h"
#include "lookup.h"
#include "encode.h"
#include "ulcb.h"

#include "../../lib/reg/rerrno.h"
#include "../../lib/reg/config.h"
#include "../../lib/reg/sip_msg.h"
#include "../../lib/reg/regtime.h"

#include "../../parser/contact/contact.h"
#include "../../parser/contact/parse_contact.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_expires.h"
#include "../../parser/parse_supported.h"
#include "../../parser/parse_uri.h"
#include "../../data_lump_rpl.h"
#include "../../net/trans.h"

str register_method = str_init("REGISTER");
str contact_hdr = str_init("Contact: ");
str expires_hdr = str_init("Expires: ");
str expires_param = str_init("expires");

struct usrloc_api ul_api;
struct tm_binds tm_api;
struct sig_binds sig_api;

/* specifically used to mutually exclude concurrent calls of the
 * TMCB_RESPONSE_IN callback, upon SIP 200 OK retransmissions */
rw_lock_t *tm_retrans_lk;

int default_expires = 3600; /*!< Default expires value in seconds */
int min_expires     = 10;   /*!< Minimum expires the phones are allowed to use
							  in seconds - use 0 to switch expires checking off */
int max_expires     = 3600;

int max_contacts = 0;		/*!< Maximum number of contacts per AOR
                                 (0=no checking) */
int max_username_len = USERNAME_MAX_SIZE;
int max_domain_len   = DOMAIN_MAX_SIZE;
int max_aor_len      = MAX_AOR_LEN;
int retry_after = 0;		/*!< The value of Retry-After HF in 5xx replies */

qvalue_t default_q  = Q_UNSPECIFIED; /*!< Default q value multiplied by 1000 */

char* rcv_avp_param = 0;
unsigned short rcv_avp_type = 0;
int rcv_avp_name;

int tcp_persistent_flag = -1;  /*!< if the TCP connection should be kept open */
char *tcp_persistent_flag_s = 0;

char* mct_avp_param = 0;
unsigned short mct_avp_type = 0;
int mct_avp_name;

char* attr_avp_param = 0;
unsigned short attr_avp_type = 0;
int attr_avp_name;

str extra_ct_params_str;
pv_spec_t extra_ct_params_avp;

static struct mid_reg_info *__info;

#define RCV_NAME "received"
str rcv_param = str_init(RCV_NAME);

int case_sensitive  = 1; /*!< If set to 0, username in aor will be case insensitive */
str gruu_secret = {0,0};
int disable_gruu = 1;
str realm_prefix = str_init("");
int reg_use_domain = 0;

static int mod_init(void);
static int cfg_validate(void);

static int domain_fixup(void** param);

int solve_avp_defs(void);

/* 
 * Working modes:
 *    0 = mirror
 *    1 = device throttling
 *    2 = user throttling
 */
enum mid_reg_mode reg_mode = MID_REG_MIRROR;

unsigned int outgoing_expires = 3600;

enum mid_reg_insertion_mode   ctid_insertion  = MR_REPLACE_USER;
char *mp_ctid_insertion = "ct-param";

str ctid_param = str_init("ctid");

static cmd_export_t cmds[] = {
	{"mid_registrar_save", (cmd_function)mid_reg_save, {
		{CMD_PARAM_STR|CMD_PARAM_STATIC, domain_fixup, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0 ,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{"mid_registrar_lookup", (cmd_function)mid_reg_lookup, {
		{CMD_PARAM_STR|CMD_PARAM_STATIC, domain_fixup, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0 ,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

static param_export_t mod_params[] = {
	{ "mode",                 INT_PARAM, &reg_mode },
	{ "default_expires",      INT_PARAM, &default_expires },
	{ "min_expires",          INT_PARAM, &min_expires },
	{ "max_expires",          INT_PARAM, &max_expires },
	{ "default_q",            INT_PARAM, &default_q },
	{ "tcp_persistent_flag",  STR_PARAM, &tcp_persistent_flag_s },
	{ "realm_prefix",         STR_PARAM, &realm_prefix.s },
	{ "case_sensitive",       INT_PARAM, &case_sensitive },
	{ "received_avp",         STR_PARAM, &rcv_avp_param },
	{ "received_param",       STR_PARAM, &rcv_param.s },
	{ "max_contacts",         INT_PARAM, &max_contacts },
	{ "max_username_len",     INT_PARAM, &max_username_len },
	{ "max_domain_len",       INT_PARAM, &max_domain_len },
	{ "max_aor_len",          INT_PARAM, &max_aor_len },
	{ "retry_after",          INT_PARAM, &retry_after },
	{ "gruu_secret",          STR_PARAM, &gruu_secret.s },
	{ "disable_gruu",         INT_PARAM, &disable_gruu },
	{ "outgoing_expires",     INT_PARAM, &outgoing_expires },
	{ "contact_id_insertion", STR_PARAM, &mp_ctid_insertion },
	{ "contact_id_param",     STR_PARAM, &ctid_param.s },
	{ "extra_contact_params_avp", STR_PARAM, &extra_ct_params_str.s },
	{ "attr_avp",             STR_PARAM, &attr_avp_param },
	{ 0,0,0 }
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "usrloc",    DEP_ABORT  },
		{ MOD_TYPE_DEFAULT, "signaling", DEP_ABORT  },
		{ MOD_TYPE_DEFAULT, "tm",        DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports= {
	"mid_registrar",        /* module's name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,            /* exported functions */
	NULL,               /* exported async functions */
	mod_params,      /* param exports */
	NULL,       /* exported statistics */
	NULL,         /* exported MI functions */
	NULL,       /* exported pseudo-variables */
	NULL,	    /* exported transformations */
	NULL,               /* extra processes */
	NULL,            /* module pre-initialization function */
	mod_init,        /* module initialization function */
	NULL,               /* reply processing function */
	NULL,
	NULL,       /* per-child init function */
	cfg_validate/* reload confirm function */
};

/*! \brief
 * Convert char* parameter to udomain_t* pointer
 */
static int domain_fixup(void** param)
{
	udomain_t* d;
	str dom_s;

	if (pkg_nt_str_dup(&dom_s, (str*)*param) < 0)
		return E_OUT_OF_MEM;

	if (ul_api.register_udomain(dom_s.s, &d) < 0) {
		LM_ERR("failed to register domain\n");
		pkg_free(dom_s.s);
		return E_UNSPEC;
	}

	pkg_free(dom_s.s);

	*param = (void*)d;
	return 0;
}

static int mid_reg_pre_script(struct sip_msg *foo, void *bar)
{
	set_ct(NULL);
	return SCB_RUN_ALL;
}


static int mid_reg_post_script(struct sip_msg *foo, void *bar)
{
	set_ct(NULL);
	return SCB_RUN_ALL;
}


static int mod_init(void)
{
	if (load_ul_api(&ul_api) < 0) {
		LM_ERR("failed to load user location API\n");
		return -1;
	}

	if (!ul_api.have_mem_storage()) {
		LM_ERR("no support for external-storage usrloc!\n");
		return -1;
	}

	if (load_tm_api(&tm_api) < 0) {
		LM_ERR("failed to load user location API\n");
		return -1;
	}

	if(load_sig_api(&sig_api)< 0) {
		LM_ERR("can't load signaling functions\n");
		return -1;
	}

	if (is_script_func_used("mid_registrar_save",5) && !ul_api.tags_in_use()) {
		LM_ERR("as per your current usrloc module configuration, "
				"mid_registrar_save() ownership tags "
				"will be completely ignored!\n");
		return -1;
	}

	if (!strncasecmp(mp_ctid_insertion, STR_L("ct-param"))) {
		ctid_insertion = MR_APPEND_PARAM;
	} else if (!strncasecmp(mp_ctid_insertion, STR_L("ct-user"))) {
		ctid_insertion = MR_REPLACE_USER;
	} else {
		LM_WARN("bad 'contact_id_insertion' (%s) - using 'ct-param' as a "
		        "default\n", mp_ctid_insertion);
		ctid_insertion = MR_APPEND_PARAM;
	}

	if (min_expires > default_expires) {
		LM_ERR("min_expires > default_expires! "
		       "Decreasing min_expires to %d...\n", default_expires);
		min_expires = default_expires;
	}

	if (max_expires < default_expires) {
		LM_ERR("max_expires < default_expires! "
		       "Increasing max_expires to %d...\n", default_expires);
		max_expires = default_expires;
	}

	/* Normalize default_q parameter */
	if (default_q != Q_UNSPECIFIED) {
		if (default_q > MAX_Q) {
			LM_DBG("default_q = %d, lowering to MAX_Q: %d\n", default_q, MAX_Q);
			default_q = MAX_Q;
		} else if (default_q < MIN_Q) {
			LM_DBG("default_q = %d, raising to MIN_Q: %d\n", default_q, MIN_Q);
			default_q = MIN_Q;
		}
	}

	/*
	 * Import use_domain parameter from usrloc
	 */
	reg_use_domain = ul_api.use_domain;

	rcv_param.len = strlen(rcv_param.s);

	if (solve_avp_defs() != 0) {
		LM_ERR("failed to parse one or more module AVPs\n");
		return -1;
	}

	realm_prefix.len = strlen(realm_prefix.s);

	if (gruu_secret.s)
		gruu_secret.len = strlen(gruu_secret.s);

	tcp_persistent_flag = get_flag_id_by_name(FLAG_TYPE_MSG, tcp_persistent_flag_s);
	tcp_persistent_flag = (tcp_persistent_flag != -1) ? (1 << tcp_persistent_flag) : 0;

	ctid_param.len = strlen(ctid_param.s);

	if (reg_mode != MID_REG_MIRROR) {
		if (ul_api.register_ulcb(
			UL_CONTACT_INSERT|UL_CONTACT_UPDATE|UL_CONTACT_DELETE|UL_CONTACT_EXPIRE,
			mid_reg_ct_event) < 0) {
			LM_ERR("cannot register usrloc contact callback\n");
			return -1;
		}

		if (reg_mode == MID_REG_THROTTLE_AOR) {
			if (ul_api.register_ulcb(UL_AOR_INSERT|UL_AOR_DELETE|UL_AOR_EXPIRE,
				mid_reg_aor_event) < 0) {
				LM_ERR("cannot register usrloc AoR callback\n");
				return -1;
			}
		}
	}

	if (register_script_cb(mid_reg_pre_script,
	                       PRE_SCRIPT_CB|REQ_TYPE_CB, NULL) < 0) {
		LM_ERR("failed to register pre script cb\n");
		return -1;
	}

	if (register_script_cb(mid_reg_post_script,
	                       POST_SCRIPT_CB|REQ_TYPE_CB, NULL) < 0) {
		LM_ERR("failed to register post script cb\n");
		return -1;
	}

	tm_retrans_lk = lock_init_rw();
	if (!tm_retrans_lk) {
		LM_ERR("oom\n");
		return -1;
	}

	return 0;
}


static int cfg_validate(void)
{
	if (is_script_func_used("mid_registrar_save", 5) && !ul_api.tags_in_use()){
		LM_ERR("mid_registrar_save() with sharing tag was found, but the "
			"module's configuration has no tag support, better restart\n");
		return 0;
	}
	return 1;
}


void set_ct(struct mid_reg_info *ct)
{
	__info = ct;
}

struct mid_reg_info *get_ct(void)
{
	return __info;
}

struct mid_reg_info *mri_alloc(void)
{
	struct mid_reg_info *new;

	new = shm_malloc(sizeof *new);
	if (!new) {
		LM_ERR("oom\n");
		return NULL;
	}
	memset(new, 0, sizeof *new);

	new->tm_lock = lock_init_rw();
	if (!new->tm_lock) {
		shm_free(new);
		LM_ERR("oom\n");
		return NULL;
	}

	INIT_LIST_HEAD(&new->ct_mappings);

	return new;
}

struct mid_reg_info *mri_dup(struct mid_reg_info *mri)
{
	struct mid_reg_info *new;

	new = mri_alloc();
	if (!new)
		return NULL;

	new->reg_flags = mri->reg_flags;
	new->last_cseq = mri->last_cseq;

	if (mri->aor.s)
		shm_str_dup(&new->aor, &mri->aor);

	if (mri->from.s)
		shm_str_dup(&new->from, &mri->from);

	if (mri->to.s)
		shm_str_dup(&new->to, &mri->to);

	if (mri->callid.s)
		shm_str_dup(&new->callid, &mri->callid);

	if (mri->ct_uri.s)
		shm_str_dup(&new->ct_uri, &mri->ct_uri);

	if (mri->main_reg_uri.s)
		shm_str_dup(&new->main_reg_uri, &mri->main_reg_uri);

	if (mri->main_reg_next_hop.s)
		shm_str_dup(&new->main_reg_next_hop, &mri->main_reg_next_hop);

	new->cmatch.mode = mri->cmatch.mode;
	if (mri->cmatch.match_params)
		new->cmatch.match_params = dup_shm_str_list(new->cmatch.match_params);

	return new;
}

extern void free_ct_mappings(struct list_head *mappings);
void mri_free(struct mid_reg_info *mri)
{
	if (!mri)
		return;

	LM_DBG("aor: '%.*s' %p\n", mri->aor.len, mri->aor.s, mri->aor.s);
	LM_DBG("from: '%.*s' %p\n", mri->from.len, mri->from.s, mri->from.s);
	LM_DBG("to: '%.*s' %p\n", mri->to.len, mri->to.s, mri->to.s);
	LM_DBG("callid: '%.*s' %p\n", mri->callid.len, mri->callid.s, mri->callid.s);
	LM_DBG("main reg: '%.*s' %p\n", mri->main_reg_uri.len, mri->main_reg_uri.s,
	       mri->main_reg_uri.s);
	LM_DBG("ct_uri: '%.*s' %p\n", mri->ct_uri.len, mri->ct_uri.s, mri->ct_uri.s);

	shm_free(mri->aor.s);
	shm_free(mri->from.s);
	shm_free(mri->to.s);
	shm_free(mri->callid.s);

	lock_destroy_rw(mri->tm_lock);

	if (mri->main_reg_uri.s)
		shm_free(mri->main_reg_uri.s);

	if (mri->main_reg_next_hop.s)
		shm_free(mri->main_reg_next_hop.s);

	if (mri->ct_uri.s)
		shm_free(mri->ct_uri.s);

	if (mri->user_agent.s)
		shm_free(mri->user_agent.s);

	if (mri->ownership_tag.s)
		shm_free(mri->ownership_tag.s);

	if (mri->cmatch.match_params)
		free_shm_str_list(mri->cmatch.match_params);

	free_ct_mappings(&mri->ct_mappings);

#ifdef EXTRA_DEBUG
	memset(mri, 0, sizeof *mri);
#endif
	shm_free(mri);
}

int get_expires_hf(struct sip_msg* _m)
{
	exp_body_t* p;

	if (_m->expires) {
		p = (exp_body_t*)_m->expires->parsed;
		if (p != NULL && p->valid) {
			if (p->val != 0) {
				return p->val;
			} else return 0;
		} else return default_expires;
	} else {
		return default_expires;
	}
}

int solve_avp_defs(void)
{
	str s;
	pv_spec_t avp_spec;

	if (rcv_avp_param && *rcv_avp_param) {
		s.s = rcv_avp_param; s.len = strlen(s.s);
		if (pv_parse_spec(&s, &avp_spec)==0
				|| avp_spec.type!=PVT_AVP) {
			LM_ERR("malformed or non AVP %s AVP definition\n", rcv_avp_param);
			return -1;
		}

		if(pv_get_avp_name(0, &avp_spec.pvp, &rcv_avp_name, &rcv_avp_type)!=0)
		{
			LM_ERR("[%s]- invalid AVP definition\n", rcv_avp_param);
			return -1;
		}
	} else {
		rcv_avp_name = -1;
		rcv_avp_type = 0;
	}

	if (extra_ct_params_str.s) {
		extra_ct_params_str.len = strlen(extra_ct_params_str.s);

		if (extra_ct_params_str.len) {
			if (!pv_parse_spec(&extra_ct_params_str, &extra_ct_params_avp) ||
			     extra_ct_params_avp.type != PVT_AVP) {
				LM_ERR("extra_ct_params_avp: malformed or non-AVP content!\n");
				return -1;
			}
		}
	}

	if (attr_avp_param && *attr_avp_param) {
		init_str(&s, attr_avp_param);

		if (!pv_parse_spec(&s, &avp_spec) || avp_spec.type != PVT_AVP) {
			LM_ERR("malformed or non AVP %s AVP definition\n", attr_avp_param);
			return -1;
		}

		if(pv_get_avp_name(0, &avp_spec.pvp, &attr_avp_name, &attr_avp_type)!=0)
		{
			LM_ERR("[%s]- invalid AVP definition\n", attr_avp_param);
			return -1;
		}
	} else {
		attr_avp_name = -1;
		attr_avp_type = 0;
	}

	return 0;
}

str get_extra_ct_params(struct sip_msg *msg)
{
	str null_str = {NULL, 0};
	pv_value_t extra_params;

	if (ZSTR(extra_ct_params_str))
		return null_str;

	if (pv_get_spec_value(msg, &extra_ct_params_avp, &extra_params) != 0) {
		LM_ERR("failed to get extra params\n");
		return null_str;
	}

	if (extra_params.flags & PV_VAL_NULL)
		return null_str;

	if (!(extra_params.flags & PV_VAL_STR)) {
		LM_ERR("skipping extra Contact params with int value (%d)\n",
		       extra_params.ri);
		return null_str;
	}

	return extra_params.rs;
}
