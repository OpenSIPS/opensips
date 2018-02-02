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
#include "../../mod_fix.h"
#include "../../data_lump.h"
#include "../../rw_locking.h"

#include "mid_registrar.h"
#include "save.h"
#include "lookup.h"
#include "encode.h"
#include "ulcb.h"

#include "../../lib/reg/rerrno.h"
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


static struct mid_reg_info *__info;
int ucontact_data_idx;
int urecord_data_idx;

#define RCV_NAME "received"
str rcv_param = str_init(RCV_NAME);

int case_sensitive  = 1; /*!< If set to 0, username in aor will be case insensitive */
str gruu_secret = {0,0};
int disable_gruu = 1;
char* realm_pref    = "";
str realm_prefix;
int reg_use_domain = 0;

#define is_insertion_mode(v) (v == INSERT_BY_CONTACT || v == INSERT_BY_PATH)
#define insertion_mode_str(v) (v == INSERT_BY_CONTACT ? "by Contact" : "by Path")

static int mod_init(void);

static int domain_fixup(void** param);
static int registrar_fixup(void** param, int param_no);

/* 
 * Working modes:
 *    0 = mirror
 *    1 = device throttling
 *    2 = user throttling
 */
enum mid_reg_mode reg_mode = MID_REG_MIRROR;

unsigned int outgoing_expires = 3600;

#define is_matching_mode(v) (v == MATCH_BY_PARAM || v == MATCH_BY_USER)
#define matching_mode_str(v) (v == MATCH_BY_PARAM ? "by uri param" : "by user")

enum mid_reg_insertion_mode   insertion_mode  = INSERT_BY_CONTACT;

//TODO: remove the Path-based mid-registrar logic starting with OpenSIPS 2.4
enum mid_reg_matching_mode  matching_mode = MATCH_BY_PARAM;

/*
 * Only used in INSERT_BY_CONTACT insertion mode
 * Allows us to match the request contact set with the reply contact set,
 * which contains rewritten Contact header field domains
 */
str matching_param = str_init("rid");

static cmd_export_t cmds[] = {
	{ "mid_registrar_save", (cmd_function)mid_reg_save, 1,
	  registrar_fixup, NULL, REQUEST_ROUTE },
	{ "mid_registrar_save", (cmd_function)mid_reg_save, 2,
	  registrar_fixup, NULL, REQUEST_ROUTE },
	{ "mid_registrar_save", (cmd_function)mid_reg_save, 3,
	  registrar_fixup, NULL, REQUEST_ROUTE },
	{ "mid_registrar_save", (cmd_function)mid_reg_save, 4,
	  registrar_fixup, NULL, REQUEST_ROUTE },
	{ "mid_registrar_lookup", (cmd_function)mid_reg_lookup, 1,
	  registrar_fixup, NULL, REQUEST_ROUTE },
	{ "mid_registrar_lookup", (cmd_function)mid_reg_lookup, 2,
	  registrar_fixup, NULL, REQUEST_ROUTE },
	{ "mid_registrar_lookup", (cmd_function)mid_reg_lookup, 3,
	  registrar_fixup, NULL, REQUEST_ROUTE },
	{ NULL, NULL, 0, NULL, NULL, 0 }
};

static param_export_t mod_params[] = {
	{ "mode",                 INT_PARAM, &reg_mode },
	{ "default_expires",      INT_PARAM, &default_expires },
	{ "min_expires",          INT_PARAM, &min_expires },
	{ "max_expires",          INT_PARAM, &max_expires },
	{ "default_q",            INT_PARAM, &default_q },
	{ "tcp_persistent_flag",  INT_PARAM, &tcp_persistent_flag },
	{ "tcp_persistent_flag",  STR_PARAM, &tcp_persistent_flag_s },
	{ "realm_prefix",         STR_PARAM, &realm_pref },
	{ "case_sensitive",       INT_PARAM, &case_sensitive },
	{ "received_avp",         STR_PARAM, &rcv_avp_param },
	{ "received_param",       STR_PARAM, &rcv_param.s },
	{ "max_contacts",         INT_PARAM, &max_contacts },
	{ "retry_after",          INT_PARAM, &retry_after },
	{ "gruu_secret",          STR_PARAM, &gruu_secret.s },
	{ "disable_gruu",         INT_PARAM, &disable_gruu },
	{ "outgoing_expires",     INT_PARAM, &outgoing_expires },
	{ "insertion_mode",       INT_PARAM, &insertion_mode },
	{ "contact_match_param",  STR_PARAM, &matching_param.s },
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
	&deps,           /* OpenSIPS module dependencies */
	cmds,            /* exported functions */
	NULL,               /* exported async functions */
	mod_params,      /* param exports */
	NULL,       /* exported statistics */
	NULL,         /* exported MI functions */
	NULL,       /* exported pseudo-variables */
	NULL,               /* extra processes */
	mod_init,        /* module initialization function */
	NULL,               /* reply processing function */
	NULL,
	NULL       /* per-child init function */
};

/*! \brief
 * Convert char* parameter to udomain_t* pointer
 */
static int domain_fixup(void** param)
{
	udomain_t* d;

	if (ul_api.register_udomain((char*)*param, &d) < 0) {
		LM_ERR("failed to register domain\n");
		return E_UNSPEC;
	}

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

/*! \brief
 * Fixup for "save"+"lookup" functions - domain, flags, AOR params
 */
static int registrar_fixup(void** param, int param_no)
{
	switch (param_no) {
	case 1:
		/* table name */
		return domain_fixup(param);
	case 2:
		/* flags */
		return fixup_spve(param);
	case 3:
		/* AoR */
		return fixup_sgp(param);
	case 4:
		/* outgoing registration interval */
		return fixup_igp(param);
	}

	return E_BUG;
}

static int mod_init(void)
{
	if (load_ul_api(&ul_api) < 0) {
		LM_ERR("failed to load user location API\n");
		return -1;
	}

	if (ul_api.db_mode != NO_DB) {
		LM_ERR("the 2.3 mid_registrar only works with usrloc 'db_mode = 0'!\n");
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

	if (!is_insertion_mode(insertion_mode)) {
		insertion_mode = INSERT_BY_PATH;
		LM_WARN("bad \"insertion_mode\" (%d) - using '%s' as a default\n",
		        insertion_mode, insertion_mode_str(insertion_mode));
	} else {
		LM_DBG("insertion mode: '%s'\n", insertion_mode_str(insertion_mode));
	}

	if (!is_matching_mode(matching_mode)) {
		matching_mode = MATCH_BY_PARAM;
		LM_WARN("bad \"matching_mode\" (%d) - using '%s' as a default\n",
		        matching_mode, matching_mode_str(matching_mode));
	} else {
		LM_DBG("contact matching mode: '%s'\n", matching_mode_str(matching_mode));
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

	realm_prefix.s = realm_pref;
	realm_prefix.len = strlen(realm_pref);

	if (gruu_secret.s)
		gruu_secret.len = strlen(gruu_secret.s);

	/* fix the flags */
	fix_flag_name(tcp_persistent_flag_s, tcp_persistent_flag);
	tcp_persistent_flag = get_flag_id_by_name(FLAG_TYPE_MSG, tcp_persistent_flag_s);
	tcp_persistent_flag = (tcp_persistent_flag != -1) ? (1 << tcp_persistent_flag) : 0;

	matching_param.len = strlen(matching_param.s);

	if (reg_mode != MID_REG_MIRROR) {
		if (ul_api.db_mode == DB_ONLY) {
			LM_ERR("mid_registrar traffic conversion cannot work with "
			       "usrloc \"db_mode\" = %d!\n", DB_ONLY);
			return -1;
		}

		if (ul_api.register_ulcb(
			UL_CONTACT_INSERT|UL_CONTACT_UPDATE|UL_CONTACT_DELETE|UL_CONTACT_EXPIRE,
			mid_reg_ct_event, &ucontact_data_idx) < 0) {
			LM_ERR("cannot register usrloc contact callback\n");
			return -1;
		}

		if (reg_mode == MID_REG_THROTTLE_AOR) {
			if (ul_api.register_ulcb(UL_AOR_INSERT|UL_AOR_DELETE|UL_AOR_EXPIRE,
				mid_reg_aor_event, &urecord_data_idx) < 0) {
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

	if (mri->path.s)
		shm_free(mri->path.s);

	if (mri->path_received.s)
		shm_free(mri->path_received.s);

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
