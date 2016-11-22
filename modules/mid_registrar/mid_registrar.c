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

#include "mid_registrar.h"
#include "uac_timer.h"
#include "save.h"
#include "lookup.h"
#include "encode.h"
#include "ulcb.h"

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


rerr_t rerrno;


static struct mid_reg_info *__info;
int ucontact_data_idx;
int urecord_data_idx;


#define PATH_MODE_STRICT	2
#define PATH_MODE_LAZY		1
#define PATH_MODE_OFF		0


str sock_hdr_name = {0,0};

#define RCV_NAME "received"
str rcv_param = str_init(RCV_NAME);

char uri_buf[MAX_URI_SIZE];


static time_t act_time;

inline void set_ct(struct mid_reg_info *ct)
{
	__info = ct;
}

inline struct mid_reg_info *get_ct(void)
{
	return __info;
}

/*! \brief
 * Get actual time and store
 * value in act_time
 */
void update_act_time(void)
{
	act_time = time(0);
}


time_t get_act_time(void)
{
	return act_time;
}

int calc_contact_q(param_t* _q, qvalue_t* _r)
{
	int rc;

	if (!_q || (_q->body.len == 0)) {
		*_r = default_q;
	} else {
		rc = str2q(_r, _q->body.s, _q->body.len);
		if (rc < 0) {
			rerrno = R_INV_Q; /* Invalid q parameter */
			LM_ERR("invalid qvalue (%.*s): %s\n",
					_q->body.len, _q->body.s, qverr2str(rc));
			return -1;
		}
	}
	return 0;
}

static struct hdr_field* act_contact;
contact_t* get_next_contact(contact_t* _c)
{
	struct hdr_field* p = NULL;
	if (_c->next == 0) {
		if (act_contact)
			p = act_contact->next;
		while(p) {
			if (p->type == HDR_CONTACT_T) {
				act_contact = p;
				return (((contact_body_t*)p->parsed)->contacts);
			}
			p = p->next;
		}
		return 0;
	} else {
		return _c->next;
	}
}
int case_sensitive  = 1;			/*!< If set to 0, username in aor will be case insensitive */
str gruu_secret = {0,0};
int disable_gruu = 1;
char* realm_pref    = "";
str realm_prefix;
int reg_use_domain = 0;

#define is_routing_mode(v) (v == ROUTE_BY_CONTACT || v == ROUTE_BY_PATH)
#define routing_mode_str(v) (v == ROUTE_BY_CONTACT ? "by Contact" : "by Path")

static int mod_init(void);

static int domain_fixup(void** param);
static int registrar_fixup(void** param, int param_no);

/* 
 * TODO
 * 0 = proxy mode
 * 1 = registration traffic throttling mode (by Contact)
 * 2 = registration traffic throttling mode (by AoR)
 */
enum mid_reg_mode reg_mode = MID_REG_MIRROR;

/*
 * Outbound expires
 *
 * min: 4 sec
 * max: 4294967295 sec
 *
 * default value: 0 (not set - all incoming traffic is mirrored)
 */
unsigned int outgoing_expires = 600;
unsigned int min_outgoing_expires = 4;

#define is_matching_mode(v) (v == MATCH_BY_PARAM || v == MATCH_BY_USER)
#define matching_mode_str(v) (v == MATCH_BY_PARAM ? "by uri param" : "by user")

enum mid_reg_routing_mode   routing_mode  = ROUTE_BY_CONTACT;
enum mid_reg_matching_mode  matching_mode = MATCH_BY_PARAM;

/*
 * Only used in ROUTE_BY_CONTACT routing mode
 * Allows us to match the request contact set with the reply contact set,
 * which contains rewritten Contact header field domains
 */
str matching_param = str_init("rinstance");

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
	{ "min_expires",          INT_PARAM, &min_expires },
	{ "default_q",            INT_PARAM, &default_q },
	{ "tcp_persistent_flag",  INT_PARAM, &tcp_persistent_flag },
	{ "tcp_persistent_flag",  STR_PARAM, &tcp_persistent_flag_s },
	{ "realm_prefix",         STR_PARAM, &realm_pref },
	{ "case_sensitive",       INT_PARAM, &case_sensitive },
	{ "received_avp",         STR_PARAM, &rcv_avp_param },
	{ "received_param",       STR_PARAM, &rcv_param.s },
	{ "max_contacts",         INT_PARAM, &max_contacts },
	{ "retry_after",          INT_PARAM, &retry_after },
	{ "sock_hdr_name",        STR_PARAM, &sock_hdr_name.s },
	{ "gruu_secret",          STR_PARAM, &gruu_secret.s },
	{ "disable_gruu",         INT_PARAM, &disable_gruu },
	{ "outgoing_expires",     INT_PARAM, &outgoing_expires },
	{ "contact_routing_mode", INT_PARAM, &routing_mode },
	{ "contact_match_mode",   INT_PARAM, &matching_mode },
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
		/* outbound registration interval */
		return fixup_igp(param);
	}

	return E_BUG;
}

static int mod_init(void)
{
	str s;
	pv_spec_t avp_spec;

	if (load_ul_api(&ul_api) < 0) {
		LM_ERR("failed to load user location API\n");
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

	if (!is_routing_mode(routing_mode)) {
		routing_mode = ROUTE_BY_PATH;
		LM_WARN("bad \"routing_mode\" (%d) - using '%s' as a default\n",
		        routing_mode, routing_mode_str(routing_mode));
	} else {
		LM_DBG("contact routing mode: '%s'\n", routing_mode_str(routing_mode));
	}

	if (!is_matching_mode(matching_mode)) {
		matching_mode = MATCH_BY_PARAM;
		LM_WARN("bad \"matching_mode\" (%d) - using '%s' as a default\n",
		        matching_mode, matching_mode_str(matching_mode));
	} else {
		LM_DBG("contact matching mode: '%s'\n", matching_mode_str(matching_mode));
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

	rcv_param.len = strlen(rcv_param.s);

	realm_prefix.s = realm_pref;
	realm_prefix.len = strlen(realm_pref);

	if (sock_hdr_name.s)
		sock_hdr_name.len = strlen(sock_hdr_name.s);

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
			UL_CONTACT_INSERT|UL_CONTACT_DELETE|UL_CONTACT_EXPIRE,
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

	return 0;
}

void mri_free(struct mid_reg_info *mri)
{
	LM_DBG("aor: '%.*s' %p\n", mri->aor.len, mri->aor.s, mri->aor.s);
	LM_DBG("from: '%.*s' %p\n", mri->from.len, mri->from.s, mri->from.s);
	LM_DBG("callid: '%.*s' %p\n", mri->callid.len, mri->callid.s, mri->callid.s);
	LM_DBG("ruri: '%.*s' %p\n", mri->ruri.len, mri->ruri.s, mri->ruri.s);
	LM_DBG("ct_uri: '%.*s' %p\n", mri->ct_uri.len, mri->ct_uri.s, mri->ct_uri.s);

	if (mri->aor.s)
		shm_free(mri->aor.s);

	if (mri->from.s)
		shm_free(mri->from.s);

	if (mri->callid.s)
		shm_free(mri->callid.s);

	if (mri->ruri.s)
		shm_free(mri->ruri.s);

	if (mri->next_hop.s)
		shm_free(mri->next_hop.s);

	if (mri->ct_uri.s)
		shm_free(mri->ct_uri.s);

	if (mri->ct_body.s)
		shm_free(mri->ct_body.s);

#ifdef EXTRA_DEBUG
	memset(mri, 0, sizeof *mri);
#endif
	shm_free(mri);
}

contact_t* get_first_contact(struct sip_msg* _m)
{
	if (_m->contact == 0) return 0;

	act_contact = _m->contact;
	return (((contact_body_t*)_m->contact->parsed)->contacts);
}

int parse_reg_headers(struct sip_msg* _m)
{
	struct hdr_field* ptr;

	if (parse_headers(_m, HDR_EOH_F, 0) == -1) {
		rerrno = R_PARSE;
		LM_ERR("failed to parse headers\n");
		return -1;
	}

	if (!_m->to) {
		rerrno = R_TO_MISS;
		LM_ERR("To not found\n");
		return -2;
	}

	if (!_m->callid) {
		rerrno = R_CID_MISS;
		LM_ERR("Call-ID not found\n");
		return -3;
	}

	if (!_m->cseq) {
		rerrno = R_CS_MISS;
		LM_ERR("CSeq not found\n");
		return -4;
	}

	if (_m->expires && !_m->expires->parsed && (parse_expires(_m->expires) < 0)) {
		rerrno = R_PARSE_EXP;
		LM_ERR("failed to parse expires body\n");
		return -5;
	}

	if (_m->contact) {
		ptr = _m->contact;
		while(ptr) {
			if (ptr->type == HDR_CONTACT_T) {
				if (!ptr->parsed && (parse_contact(ptr) < 0)) {
					rerrno = R_PARSE_CONT;
					LM_ERR("failed to parse Contact body\n");
					return -6;
				}
			}
			ptr = ptr->next;
		}
	}

	return 0;
}

#define EI_R_FINE       "No problem"                                /* R_FINE */
#define EI_R_UL_DEL_R   "usrloc_record_delete failed"               /* R_UL_DEL_R */
#define	EI_R_UL_GET_R   "usrloc_record_get failed"                  /* R_UL_GET */
#define	EI_R_UL_NEW_R   "usrloc_record_new failed"                  /* R_UL_NEW_R */
#define	EI_R_INV_CSEQ   "Invalid CSeq number"                       /* R_INV_CSEQ */
#define	EI_R_UL_INS_C   "usrloc_contact_insert failed"              /* R_UL_INS_C */
#define	EI_R_UL_INS_R   "usrloc_record_insert failed"               /* R_UL_INS_R */
#define	EI_R_UL_DEL_C   "usrloc_contact_delete failed"              /* R_UL_DEL_C */
#define	EI_R_UL_UPD_C   "usrloc_contact_update failed"              /* R_UL_UPD_C */
#define	EI_R_TO_USER    "No username in To URI"                     /* R_TO_USER */
#define	EI_R_AOR_LEN    "Address Of Record too long"                /* R_AOR_LEN */
#define	EI_R_AOR_PARSE  "Error while parsing AOR"                   /* R_AOR_PARSE */
#define	EI_R_INV_EXP    "Invalid expires param in contact"          /* R_INV_EXP */
#define	EI_R_INV_Q      "Invalid q param in contact"                /* R_INV_Q */
#define	EI_R_PARSE      "Message parse error"                       /* R_PARSE */
#define	EI_R_TO_MISS    "To header not found"                       /* R_TO_MISS */
#define	EI_R_CID_MISS   "Call-ID header not found"                  /* R_CID_MISS */
#define	EI_R_CS_MISS    "CSeq header not found"                     /* R_CS_MISS */
#define	EI_R_PARSE_EXP	"Expires parse error"                       /* R_PARSE_EXP */
#define	EI_R_PARSE_CONT	"Contact parse error"                       /* R_PARSE_CONT */
#define	EI_R_STAR_EXP	"* used in contact and expires is not zero" /* R_STAR__EXP */
#define	EI_R_STAR_CONT	"* used in contact and more than 1 contact" /* R_STAR_CONT */
#define	EI_R_OOO	"Out of order request"                      /* R_OOO */
#define	EI_R_RETRANS	"Retransmission"                            /* R_RETRANS */
#define EI_R_UNESCAPE   "Error while unescaping username"           /* R_UNESCAPE */
#define EI_R_TOO_MANY   "Too many registered contacts"              /* R_TOO_MANY */
#define EI_R_CONTACT_LEN  "Contact/received too long"               /* R_CONTACT_LEN */
#define EI_R_CALLID_LEN  "Callid too long"                          /* R_CALLID_LEN */
#define EI_R_PARSE_PATH  "Path parse error"                         /* R_PARSE_PATH */
#define EI_R_PATH_UNSUP  "No support for found Path indicated"      /* R_PATH_UNSUP */

str error_info[] = {
	{EI_R_FINE,       sizeof(EI_R_FINE) - 1},
	{EI_R_UL_DEL_R,   sizeof(EI_R_UL_DEL_R) - 1},
	{EI_R_UL_GET_R,   sizeof(EI_R_UL_GET_R) - 1},
	{EI_R_UL_NEW_R,   sizeof(EI_R_UL_NEW_R) - 1},
	{EI_R_INV_CSEQ,   sizeof(EI_R_INV_CSEQ) - 1},
	{EI_R_UL_INS_C,   sizeof(EI_R_UL_INS_C) - 1},
	{EI_R_UL_INS_R,   sizeof(EI_R_UL_INS_R) - 1},
	{EI_R_UL_DEL_C,   sizeof(EI_R_UL_DEL_C) - 1},
	{EI_R_UL_UPD_C,   sizeof(EI_R_UL_UPD_C) - 1},
	{EI_R_TO_USER,    sizeof(EI_R_TO_USER) - 1},
	{EI_R_AOR_LEN,    sizeof(EI_R_AOR_LEN) - 1},
	{EI_R_AOR_PARSE,  sizeof(EI_R_AOR_PARSE) - 1},
	{EI_R_INV_EXP,    sizeof(EI_R_INV_EXP) - 1},
	{EI_R_INV_Q,      sizeof(EI_R_INV_Q) - 1},
	{EI_R_PARSE,      sizeof(EI_R_PARSE) - 1},
	{EI_R_TO_MISS,    sizeof(EI_R_TO_MISS) - 1},
	{EI_R_CID_MISS,   sizeof(EI_R_CID_MISS) - 1},
	{EI_R_CS_MISS,    sizeof(EI_R_CS_MISS) - 1},
	{EI_R_PARSE_EXP,  sizeof(EI_R_PARSE_EXP) - 1},
	{EI_R_PARSE_CONT, sizeof(EI_R_PARSE_CONT) - 1},
	{EI_R_STAR_EXP,   sizeof(EI_R_STAR_EXP) - 1},
	{EI_R_STAR_CONT,  sizeof(EI_R_STAR_CONT) - 1},
	{EI_R_OOO,        sizeof(EI_R_OOO) - 1},
	{EI_R_RETRANS,    sizeof(EI_R_RETRANS) - 1},
	{EI_R_UNESCAPE,   sizeof(EI_R_UNESCAPE) - 1},
	{EI_R_TOO_MANY,   sizeof(EI_R_TOO_MANY) - 1},
	{EI_R_CONTACT_LEN,sizeof(EI_R_CONTACT_LEN) - 1},
	{EI_R_CALLID_LEN, sizeof(EI_R_CALLID_LEN) - 1},
	{EI_R_PARSE_PATH, sizeof(EI_R_PARSE_PATH) - 1},
	{EI_R_PATH_UNSUP, sizeof(EI_R_PATH_UNSUP) - 1}

};

int rerr_codes[] = {
	200, /* R_FINE */
	500, /* R_UL_DEL_R */
	500, /* R_UL_GET */
	500, /* R_UL_NEW_R */
	400, /* R_INV_CSEQ */
	500, /* R_UL_INS_C */
	500, /* R_UL_INS_R */
	500, /* R_UL_DEL_C */
	500, /* R_UL_UPD_C */
	400, /* R_TO_USER */
	500, /* R_AOR_LEN */
	400, /* R_AOR_PARSE */
	400, /* R_INV_EXP */
	400, /* R_INV_Q */
	400, /* R_PARSE */
	400, /* R_TO_MISS */
	400, /* R_CID_MISS */
	400, /* R_CS_MISS */
	400, /* R_PARSE_EXP */
	400, /* R_PARSE_CONT */
	400, /* R_STAR_EXP */
	400, /* R_STAR_CONT */
	200, /* R_OOO */
	200, /* R_RETRANS */
	400, /* R_UNESCAPE */
	503, /* R_TOO_MANY */
	400, /* R_CONTACT_LEN */
	400, /* R_CALLID_LEN */
	400, /* R_PARSE_PATH */
	420  /* R_PATH_UNSUP */

};

int get_expires_hf(struct sip_msg* _m)
{
	exp_body_t* p;

	if (_m->expires) {
		p = (exp_body_t*)_m->expires->parsed;
		if (p->valid) {
			if (p->val != 0) {
				return p->val;
			} else return 0;
		} else return default_expires;
	} else {
		return default_expires;
	}
}
