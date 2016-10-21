/*
 * Support for:
 *  - REGISTER traffic throttling, optionally with outbound contact aggregation
 *  - proxying REGISTER traffic while saving registration state
 *       (contact expirations are taken from the downstream UAS's 200 OK reply)
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
#include "../../lib/path.h"

#include "uac_timer.h"
//----------------------
#include "../../parser/contact/contact.h"
#include "../../parser/contact/parse_contact.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_methods.h"
#include "../../parser/parse_allow.h"
#include "../../parser/parse_supported.h"
#include "../../parser/parse_expires.h"
#include "../../parser/parse_uri.h"
#include "../../dset.h"
#include "../../trim.h"
#include "../../data_lump_rpl.h"
#include "../../net/trans.h"

#define allowed_method(_msg, _c, _f) \
	( !((_f)&REG_LOOKUP_METHODFILTER_FLAG) || \
		((_msg)->REQ_METHOD)&((_c)->methods) )

#define ua_re_check(return) \
	if (flags & REG_LOOKUP_UAFILTER_FLAG) { \
		if (regexec(&ua_re, ptr->user_agent.s, 1, &ua_match, 0)) { \
			return; \
		} \
	}

unsigned int nbranches;
static char urimem[MAX_BRANCHES-1][MAX_URI_SIZE];
static str branch_uris[MAX_BRANCHES-1];

static struct {
	char* buf;
	int buf_len;
	int data_len;
} contact = {0, 0, 0};

int default_expires = 3600; 			/*!< Default expires value in seconds */
int min_expires     = 10;			/*!< Minimum expires the phones are allowed to use in seconds
 						 * use 0 to switch expires checking off */
int max_expires     = 3600;

char* rcv_avp_param = 0;
unsigned short rcv_avp_type = 0;
int rcv_avp_name;

int tcp_persistent_flag = -1;			/*!< if the TCP connection should be kept open */
char *tcp_persistent_flag_s = 0;

char* mct_avp_param = 0;
unsigned short mct_avp_type = 0;
int mct_avp_name;

char* attr_avp_param = 0;
unsigned short attr_avp_type = 0;
int attr_avp_name;

typedef enum rerr {
	R_FINE = 0,   /*!< Everything went OK */
	R_UL_DEL_R,   /*!< Usrloc record delete failed */
	R_UL_GET_R,   /*!< Usrloc record get failed */
	R_UL_NEW_R,   /*!< Usrloc new record failed */
	R_INV_CSEQ,   /*!< Invalid CSeq value */
	R_UL_INS_C,   /*!< Usrloc insert contact failed */
	R_UL_INS_R,   /*!< Usrloc insert record failed */
	R_UL_DEL_C,   /*!< Usrloc contact delete failed */
	R_UL_UPD_C,   /*!< Usrloc contact update failed */
	R_TO_USER,    /*!< No username part in To URI */
	R_AOR_LEN,    /*!< Address Of Record too long */
	R_AOR_PARSE,  /*!< Error while parsing Address Of Record */
	R_INV_EXP,    /*!< Invalid expires parameter in contact */
	R_INV_Q,      /*!< Invalid q parameter in contact */
	R_PARSE,      /*!< Error while parsing message */
	R_TO_MISS,    /*!< Missing To header field */
	R_CID_MISS,   /*!< Missing Call-ID header field */
	R_CS_MISS,    /*!< Missing CSeq header field */
	R_PARSE_EXP,  /*!< Error while parsing Expires */
	R_PARSE_CONT, /*!< Error while parsing Contact */
	R_STAR_EXP,   /*!< star and expires != 0 */
	R_STAR_CONT,  /*!< star and more contacts */
	R_OOO,        /*!< Out-Of-Order request */
	R_RETRANS,    /*!< Request is retransmission */
	R_UNESCAPE,   /*!< Error while unescaping username */
	R_TOO_MANY,   /*!< Too many contacts */
	R_CONTACT_LEN,/*!< Contact URI or RECEIVED too long */
	R_CALLID_LEN, /*!< Callid too long */
	R_PARSE_PATH, /*!< Error while parsing Path */
	R_PATH_UNSUP  /*!< Path not supported by UAC */

} rerr_t;

static rerr_t rerrno;

#define MAX_AOR_LEN 256

#define RCV_NAME "received"
str rcv_param = str_init(RCV_NAME);
#define MAX_TGRUU_SIZE 255
#define GR_MAGIC 73
str gruu_secret = {0,0};
str default_gruu_secret=str_init("0p3nS1pS");
char tgruu_dec[MAX_TGRUU_SIZE];

#define CONTACT_MAX_SIZE       255
#define RECEIVED_MAX_SIZE      255
#define USERNAME_MAX_SIZE      64
#define DOMAIN_MAX_SIZE        64
#define CALLID_MAX_SIZE        255
#define UA_MAX_SIZE            255

#define PATH_MODE_STRICT	2
#define PATH_MODE_LAZY		1
#define PATH_MODE_OFF		0

#define REG_SAVE_MEMORY_FLAG           (1<<0)
#define REG_SAVE_NOREPLY_FLAG          (1<<1)
#define REG_SAVE_SOCKET_FLAG           (1<<2)
#define REG_SAVE_PATH_STRICT_FLAG      (1<<3)
#define REG_SAVE_PATH_LAZY_FLAG        (1<<4)
#define REG_SAVE_PATH_OFF_FLAG         (1<<5)
#define REG_SAVE_PATH_RECEIVED_FLAG    (1<<6)
#define REG_SAVE_FORCE_REG_FLAG        (1<<7)
#define REG_SAVE_PATH_FLAG   (REG_SAVE_PATH_STRICT_FLAG|\
			REG_SAVE_PATH_LAZY_FLAG|REG_SAVE_PATH_OFF_FLAG)

#define REG_LOOKUP_METHODFILTER_FLAG   (1<<0)
#define REG_LOOKUP_NOBRANCH_FLAG       (1<<1)
#define REG_LOOKUP_UAFILTER_FLAG       (1<<2)
#define REG_BRANCH_AOR_LOOKUP_FLAG     (1<<3)
str sock_hdr_name = {0,0};

#define MAX_CONTACT_BUFFER 1024

#define E_INFO "P-Registrar-Error: "
#define E_INFO_LEN (sizeof(E_INFO) - 1)

#define CONTACT_BEGIN "Contact: "
#define CONTACT_BEGIN_LEN (sizeof(CONTACT_BEGIN) - 1)

#define Q_PARAM ";q="
#define Q_PARAM_LEN (sizeof(Q_PARAM) - 1)

#define EXPIRES_PARAM ";expires="
#define EXPIRES_PARAM_LEN (sizeof(EXPIRES_PARAM) - 1)

#define SIP_PROTO "sip:"
#define SIP_PROTO_SIZE (sizeof(SIP_PROTO) - 1)

#define PUB_GRUU ";pub-gruu="
#define PUB_GRUU_SIZE (sizeof(PUB_GRUU) - 1)

#define TEMP_GRUU ";temp-gruu="
#define TEMP_GRUU_SIZE (sizeof(TEMP_GRUU) - 1)

#define SIP_INSTANCE ";+sip.instance="
#define SIP_INSTANCE_SIZE (sizeof(SIP_INSTANCE) - 1)

#define TEMP_GRUU_HEADER "tgruu."
#define TEMP_GRUU_HEADER_SIZE (sizeof(TEMP_GRUU_HEADER) - 1)

#define GR_PARAM ";gr="
#define GR_PARAM_SIZE (sizeof(GR_PARAM) - 1)

#define GR_NO_VAL ";gr"
#define GR_NO_VAL_SIZE (sizeof(GR_NO_VAL) - 1)

#define CONTACT_SEP ", "
#define CONTACT_SEP_LEN (sizeof(CONTACT_SEP) - 1)


time_t act_time;


/*! \brief
 * Get actual time and store
 * value in act_time
 */
void get_act_time(void)
{
	act_time = time(0);
}
qvalue_t default_q  = Q_UNSPECIFIED;	/*!< Default q value multiplied by 1000 */
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
int disable_gruu = 1;
char* realm_pref    = "";
str realm_prefix;
int reg_use_domain = 0;
//-------------------

enum mid_reg_mode {
	MID_REG_MIRROR,
	MID_REG_THROTTLE_CT,
	MID_REG_THROTTLE_AOR,
};

enum mid_reg_routing_mode {
	ROUTE_BY_CONTACT,
	ROUTE_BY_PATH,
};
#define is_routing_mode(v) (v == ROUTE_BY_CONTACT || v == ROUTE_BY_PATH)
#define routing_mode_str(v) (v == ROUTE_BY_CONTACT ? "by Contact" : "by Path")

static int mod_init(void);

static int domain_fixup(void** param);
static int registrar_fixup(void** param, int param_no);

static int w_mid_reg_save(struct sip_msg *msg, char *dom, char *flags_gp,
                          char *aor_gp, char *reg_itv_gp);

static int w_mid_reg_lookup(struct sip_msg* _m, char* _t, char* _f, char* _s);

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
unsigned int outbound_expires = 600;
unsigned int min_outbound_expires = 4;

enum mid_reg_matching_mode {
	MATCH_BY_PARAM,
	MATCH_BY_USER,
};
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

/*
 * MIN: 4 seconds
 * MAX: 4294967295 (max uint) seconds
 */
unsigned int min_reg_expire = 4;
unsigned int reg_expire = 30;

static cmd_export_t cmds[] = {
	{ "mid_registrar_save", (cmd_function)w_mid_reg_save, 1,
	  registrar_fixup, NULL, REQUEST_ROUTE },
	{ "mid_registrar_save", (cmd_function)w_mid_reg_save, 2,
	  registrar_fixup, NULL, REQUEST_ROUTE },
	{ "mid_registrar_save", (cmd_function)w_mid_reg_save, 3,
	  registrar_fixup, NULL, REQUEST_ROUTE },
	{ "mid_registrar_save", (cmd_function)w_mid_reg_save, 4,
	  registrar_fixup, NULL, REQUEST_ROUTE },
	{ "mid_registrar_lookup", (cmd_function)w_mid_reg_lookup, 1,
	  registrar_fixup, NULL, REQUEST_ROUTE },
	{ "mid_registrar_lookup", (cmd_function)w_mid_reg_lookup, 2,
	  registrar_fixup, NULL, REQUEST_ROUTE },
	{ "mid_registrar_lookup", (cmd_function)w_mid_reg_lookup, 3,
	  registrar_fixup, NULL, REQUEST_ROUTE },
	{ NULL, NULL, 0, NULL, NULL, 0 }
};

static param_export_t mod_params[] = {
	{ "mode", INT_PARAM, &reg_mode },
	{ "min_expires", INT_PARAM, &reg_expire },
	{ "outbound_expires", INT_PARAM, &outbound_expires },
	{ "contact_routing_mode", INT_PARAM, &routing_mode },
	{ "contact_match_mode", INT_PARAM, &matching_mode },
	{ "contact_match_param", STR_PARAM, &matching_param.s },
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
	int itv;

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

	if (reg_expire < min_reg_expire) {
		LM_WARN("\"min_expires\" value too low (%us), using default "
		        "minimum of %us\n", reg_expire, min_reg_expire);
		reg_expire = min_reg_expire;
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

	matching_param.len = strlen(matching_param.s);

	timer_queue_init();

	if (outbound_expires < min_outbound_expires) {
		LM_WARN("\"outbound_expires\" value too low (%us), using default "
		        "minimum of %us\n", outbound_expires, min_reg_expire);
		outbound_expires = min_outbound_expires;
	}

	if (reg_mode != MID_REG_MIRROR) {
		/* increase the routine's scheduling interval as much as possible */
		itv = min_outbound_expires / 2;
		if (itv < 1)
			itv = 1;

		if (register_timer("mid-reg-uac", mid_reg_uac, NULL, itv,
		                   TIMER_FLAG_DELAY_ON_DELAY) < 0) {
			LM_ERR("failed to register the 'mid-reg-uac' timer!\n");
			return -1;
		}
	}

	return 0;
}

struct save_ctx {
	unsigned int flags;
	str aor;
	unsigned int max_contacts;
	unsigned int expires;
	unsigned int expires_out;
};

contact_t* get_first_contact(struct sip_msg* _m)
{
	if (_m->contact == 0) return 0;

	act_contact = _m->contact;
	return (((contact_body_t*)_m->contact->parsed)->contacts);
}

struct mid_reg_queue_entry * mk_timer_queue_entry(unsigned int expires,
            unsigned int expires_out, udomain_t *dom, str *aor, urecord_t *rec, ucontact_t *con, str *to, str *from, str *callid)
{
	struct mid_reg_queue_entry *e;

	e = shm_malloc(sizeof *e);
	if (!e) {
		LM_ERR("out of mem!\n");
		return NULL;
	}
	memset(e, 0, sizeof *e);

	e->expires = expires;
	e->expires_out = expires_out;

	e->next_check_ts = act_time + expires;
	e->last_register_out_ts = act_time;

	e->rec = rec;
	e->con = con;

	/*
	 * domains are allocated 1 time only, in the fixup phase, before forking.
	 *
	 * this allows us to pass the same memory address to a different
	 * process, without duplicating underlying data into shared mem
	 */
	e->dom = dom;

	if (aor)
		shm_str_dup(&e->aor, aor);

	if (callid)
		shm_str_dup(&e->callid, callid);

	if (to)
		shm_str_dup(&e->to, to);

	if (from)
		shm_str_dup(&e->from, from);

	return e;
}

int parse_message(struct sip_msg* _m)
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

#define MAX_TEMP_GRUU_SIZE	255
static char temp_gruu_buf[MAX_TEMP_GRUU_SIZE];
char * build_temp_gruu(str *aor,str *instance,str *callid,int *len)
{
	int time_len,i;
	char *p;
	char *time_str = int2str((unsigned long)act_time,&time_len);
	str *magic;

	*len = time_len + aor->len + instance->len + callid->len + 3 - 2; /* +3 blank spaces, -2 discarded chars of instance in memcpy below */
	p = temp_gruu_buf;

	memcpy(p,time_str,time_len);
	p+=time_len;
	*p++=' ';

	memcpy(p,aor->s,aor->len);
	p+=aor->len;
	*p++=' ';

	memcpy(p,instance->s+1,instance->len-2);
	p+=instance->len-2;
	*p++=' ';

	memcpy(p,callid->s,callid->len);

	LM_DBG("build temp gruu [%.*s]\n",*len,temp_gruu_buf);
	if (gruu_secret.s != NULL)
		magic = &gruu_secret;
	else
		magic = &default_gruu_secret;

	for (i=0;i<*len;i++)
		temp_gruu_buf[i] ^= magic->s[i%magic->len];
	return temp_gruu_buf;
}

int extract_aor(str* _uri, str* _a,str *sip_instance,str *call_id)
{
	static char aor_buf[MAX_AOR_LEN];
	memset(aor_buf, 0, MAX_AOR_LEN);

	str tmp;
	struct sip_uri puri;
	int user_len,tgruu_len,dec_size,i;
	str *magic;

	if (parse_uri(_uri->s, _uri->len, &puri) < 0) {
		rerrno = R_AOR_PARSE;
		LM_ERR("failed to parse Address of Record\n");
		return -1;
	}

	/* if have ;gr param and func caller is interested in
	 * potentially extracting the sip instance */
	if ((puri.gr.s && puri.gr.len) && sip_instance)
	{
		LM_DBG("has gruu\n");

		/* ;gr param detected */
		if (memcmp(puri.user.s,TEMP_GRUU,TEMP_GRUU_SIZE) == 0)
		{
			LM_DBG("temp gruu\n");
			/* temp GRUU, decode and extract aor, sip_instance
			 * and call_id */
			tgruu_len = puri.user.len - TEMP_GRUU_SIZE;
			memcpy(tgruu_dec,puri.user.s+TEMP_GRUU_SIZE,tgruu_len);

			if (gruu_secret.s != NULL)
				magic = &gruu_secret;
			else
				magic = &default_gruu_secret;

			dec_size = base64decode((unsigned char *)tgruu_dec,
					(unsigned char *)tgruu_dec,tgruu_len);

			for (i=0;i<tgruu_len;i++)
				tgruu_dec[i] ^= magic->s[i%magic->len];

			LM_DBG("decoded [%.*s]\n",dec_size,tgruu_dec);
			/* extract aor - skip tgruu generation time at
			 * the beggining */
			_a->s = (char *)memchr(tgruu_dec,' ',dec_size) + 1;
			if (_a->s == NULL) {
				rerrno = R_AOR_PARSE;
				LM_ERR("failed to parse Address of Record\n");
				return -1;
			}
			_a->len = (char *)memchr(_a->s,' ',dec_size - (_a->s-tgruu_dec)) - _a->s;
			if (_a->len < 0) {
				rerrno = R_AOR_PARSE;
				LM_ERR("failed to parse Address of Record\n");
				return -1;
			}

			sip_instance->s = _a->s+_a->len+1; /* skip ' ' */
			if (sip_instance->s >= tgruu_dec + dec_size) {
				rerrno = R_AOR_PARSE;
				LM_ERR("failed to parse Address of Record\n");
				return -1;
			}
			sip_instance->len = (char *)memchr(sip_instance->s,' ',
					dec_size-(sip_instance->s-tgruu_dec)) - sip_instance->s;
			if (sip_instance->len < 0) {
				rerrno = R_AOR_PARSE;
				LM_ERR("failed to parse Address of Record\n");
				return -1;
			}

			call_id->s = sip_instance->s + sip_instance->len + 1;
			if (call_id->s >= tgruu_dec + dec_size) {
				rerrno = R_AOR_PARSE;
				LM_ERR("failed to parse Address of Record\n");
				return -1;
			}
			call_id->len = (tgruu_dec+dec_size) - call_id->s;

			LM_DBG("extracted aor [%.*s] and instance [%.*s] and callid [%.*s]\n",_a->len,_a->s,
					sip_instance->len,sip_instance->s,call_id->len,call_id->s);

			/* skip checks - done at save() */
			return 0;
		}
		else
		{
			LM_DBG("public gruu\n");
			*sip_instance = puri.gr_val;
		}
	}

	if ( (puri.user.len + puri.host.len + 1) > MAX_AOR_LEN
	|| puri.user.len > USERNAME_MAX_SIZE
	||  puri.host.len > DOMAIN_MAX_SIZE ) {
		rerrno = R_AOR_LEN;
		LM_ERR("Address Of Record too long\n");
		return -2;
	}

	_a->s = aor_buf;
	_a->len = puri.user.len;

	if (un_escape(&puri.user, _a) < 0) {
		rerrno = R_UNESCAPE;
		LM_ERR("failed to unescape username\n");
		return -3;
	}

	user_len = _a->len;

	if (reg_use_domain) {
		if (user_len)
			aor_buf[_a->len++] = '@';
		/* strip prefix (if defined) */
		if (realm_prefix.len && realm_prefix.len<puri.host.len &&
		(memcmp(realm_prefix.s, puri.host.s, realm_prefix.len)==0) ) {
			memcpy(aor_buf + _a->len, puri.host.s + realm_prefix.len,
					puri.host.len - realm_prefix.len);
			_a->len += puri.host.len - realm_prefix.len;
		} else {
			memcpy(aor_buf + _a->len, puri.host.s, puri.host.len);
			_a->len += puri.host.len;
		}
	}

	if (case_sensitive && user_len) {
		tmp.s = _a->s + user_len + 1;
		tmp.len = _a->s + _a->len - tmp.s;
		strlower(&tmp);
	} else {
		strlower(_a);
	}

	return 0;
}




#define MSG_200 "OK"
#define MSG_400 "Bad Request"
#define MSG_420 "Bad Extension"
#define MSG_500 "Server Internal Error"
#define MSG_503 "Service Unavailable"


int retry_after = 0;				/*!< The value of Retry-After HF in 5xx replies */

#define RETRY_AFTER "Retry-After: "
#define RETRY_AFTER_LEN (sizeof(RETRY_AFTER) - 1)

static int add_retry_after(struct sip_msg* _m)
{
	char* buf, *ra_s;
 	int ra_len;

 	ra_s = int2str(retry_after, &ra_len);
 	buf = (char*)pkg_malloc(RETRY_AFTER_LEN + ra_len + CRLF_LEN);
 	if (!buf) {
 		LM_ERR("no pkg memory left\n");
 		return -1;
 	}
 	memcpy(buf, RETRY_AFTER, RETRY_AFTER_LEN);
 	memcpy(buf + RETRY_AFTER_LEN, ra_s, ra_len);
 	memcpy(buf + RETRY_AFTER_LEN + ra_len, CRLF, CRLF_LEN);
 	add_lump_rpl(_m, buf, RETRY_AFTER_LEN + ra_len + CRLF_LEN,
 		     LUMP_RPL_HDR | LUMP_RPL_NODUP);
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

int codes[] = {
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

#define PATH "Path: "
#define PATH_LEN (sizeof(PATH) - 1)

static int add_path(struct sip_msg* _m, str* _p)
{
	char* buf;

 	buf = (char*)pkg_malloc(PATH_LEN + _p->len + CRLF_LEN);
 	if (!buf) {
 		LM_ERR("no pkg memory left\n");
 		return -1;
 	}
 	memcpy(buf, PATH, PATH_LEN);
 	memcpy(buf + PATH_LEN, _p->s, _p->len);
 	memcpy(buf + PATH_LEN + _p->len, CRLF, CRLF_LEN);
 	add_lump_rpl(_m, buf, PATH_LEN + _p->len + CRLF_LEN,
 		     LUMP_RPL_HDR | LUMP_RPL_NODUP);
 	return 0;
}

#define UNSUPPORTED "Unsupported: "
#define UNSUPPORTED_LEN (sizeof(UNSUPPORTED) - 1)
static int add_unsupported(struct sip_msg* _m, str* _p)
{
	char* buf;

 	buf = (char*)pkg_malloc(UNSUPPORTED_LEN + _p->len + CRLF_LEN);
 	if (!buf) {
 		LM_ERR("no pkg memory left\n");
 		return -1;
 	}
 	memcpy(buf, UNSUPPORTED, UNSUPPORTED_LEN);
 	memcpy(buf + UNSUPPORTED_LEN, _p->s, _p->len);
 	memcpy(buf + UNSUPPORTED_LEN + _p->len, CRLF, CRLF_LEN);
 	add_lump_rpl(_m, buf, UNSUPPORTED_LEN + _p->len + CRLF_LEN,
 		     LUMP_RPL_HDR | LUMP_RPL_NODUP);
 	return 0;
}



static inline int calc_temp_gruu_len(str* aor,str* instance,str *callid)
{
	int time_len,temp_gr_len;

	int2str((unsigned long)act_time,&time_len);
	temp_gr_len = time_len + aor->len + instance->len - 2 + callid->len + 3; /* <instance> and blank spaces */
	temp_gr_len = (temp_gr_len/3 + (temp_gr_len%3?1:0))*4; /* base64 encoding */
	return temp_gr_len;
}

static inline unsigned int calc_buf_len(ucontact_t* c,int build_gruu,
		struct sip_msg *_m)
{
	unsigned int len;
	int qlen;
	struct socket_info *sock;

	len = 0;
	while(c) {
		if (VALID_CONTACT(c, act_time)) {
			if (len) len += CONTACT_SEP_LEN;
			len += 2 /* < > */ + c->c.len;
			qlen = len_q(c->q);
			if (qlen) len += Q_PARAM_LEN + qlen;
			len += EXPIRES_PARAM_LEN + INT2STR_MAX_LEN;
			if (c->received.s) {
				len += 1 /* ; */
					+ rcv_param.len
					+ 1 /* = */
					+ 1 /* dquote */
					+ c->received.len
					+ 1 /* dquote */
					;
			}
			if (build_gruu && c->instance.s) {
				sock = (c->sock)?(c->sock):(_m->rcv.bind_address);
				/* pub gruu */
				len += PUB_GRUU_SIZE
					+ 1 /* quote */
					+ SIP_PROTO_SIZE
					+ c->aor->len
					+ (reg_use_domain ?0:(1 /* @ */ + sock->name.len + 1 /* : */ + sock->port_no_str.len))
					+ GR_PARAM_SIZE
					+ (c->instance.len - 2)
					+ 1 /* quote */
					;
				/* temp gruu */
				len += TEMP_GRUU_SIZE
					+ 1 /* quote */
					+ SIP_PROTO_SIZE
					+ TEMP_GRUU_HEADER_SIZE
					+ calc_temp_gruu_len(c->aor,&c->instance,&c->callid)
					+ 1 /* @ */
					+ sock->name.len
					+ 1 /* : */
					+ sock->port_no_str.len
					+ GR_NO_VAL_SIZE
					+ 1 /* quote */
					;
				/* sip.instance */
				len += SIP_INSTANCE_SIZE
					+ 1 /* quote */
					+ (c->instance.len - 2)
					+ 1 /* quote */
					;
			}
		}
		c = c->next;
	}

	if (len) len += CONTACT_BEGIN_LEN + CRLF_LEN;
	return len;
}
static inline int get_expires_hf(struct sip_msg* _m)
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

void calc_contact_expires(struct sip_msg* _m, param_t* _ep, int* _e, struct save_ctx *_sctx)
{
	if (!_ep || !_ep->body.len) {
		*_e = get_expires_hf(_m);
	} else {
		if (str2int(&_ep->body, (unsigned int*)_e) < 0) {
			*_e = default_expires;
		}
	}

	if ((*_e != 0) && ((*_e) < min_expires))
		*_e = min_expires;

	if ((*_e != 0) && max_expires && ((*_e) > max_expires))
		*_e = max_expires;
}

/* with the optionally added outbound timeout extension */
void calc_ob_contact_expires(struct sip_msg* _m, param_t* _ep, int* _e, struct save_ctx *_sctx)
{
	if (!_ep || !_ep->body.len) {
		*_e = get_expires_hf(_m);
	} else {
		if (str2int(&_ep->body, (unsigned int*)_e) < 0) {
			*_e = default_expires;
		}
	}

	/* extend outbound timeout, thus "throttling" heavy incoming traffic */
	if (*_e && *_e < outbound_expires)
		*_e = outbound_expires;

	/* Convert to absolute value */
	if (*_e != 0) *_e += act_time;

	/* TODO FIXME ceiling up to "min_expires" is bad! */
	if ((*_e != 0) && ((*_e - act_time) < min_expires)) {
		*_e = min_expires + act_time;
	}

	/* cutting timeout down to "max_expires" */
	if ((*_e != 0) && max_expires && ((*_e - act_time) > max_expires)) {
		*_e = max_expires + act_time;
	}
}

/*! \brief
 * Combines all Path HF bodies into one string.
 */
int build_path_vector(struct sip_msg *_m, str *path, str *received,
														unsigned int flags)
{
	static char buf[MAX_PATH_SIZE];
	char *p;
	struct hdr_field *hdr;
	struct sip_uri puri;

	rr_t *route = 0;

	path->len = 0;
	path->s = 0;
	received->s = 0;
	received->len = 0;

	if(parse_headers(_m, HDR_EOH_F, 0) < 0) {
		LM_ERR("failed to parse the message\n");
		goto error;
	}

	for( hdr=_m->path,p=buf ; hdr ; hdr=hdr->sibling) {
		/* check for max. Path length */
		if( p-buf+hdr->body.len+1 >= MAX_PATH_SIZE) {
			LM_ERR("Overall Path body exceeds max. length of %d\n",
					MAX_PATH_SIZE);
			goto error;
		}
		if(p!=buf)
			*(p++) = ',';
		memcpy( p, hdr->body.s, hdr->body.len);
		p +=  hdr->body.len;
	}

	if (p!=buf) {
		/* check if next hop is a loose router */
		if (parse_rr_body( buf, p-buf, &route) < 0) {
			LM_ERR("failed to parse Path body, no head found\n");
			goto error;
		}
		if (parse_uri(route->nameaddr.uri.s,route->nameaddr.uri.len,&puri)<0){
			LM_ERR("failed to parse the first Path URI\n");
			goto error;
		}
		if (!puri.lr.s) {
			LM_ERR("first Path URI is not a loose-router, not supported\n");
			goto error;
		}
		if ( flags&REG_SAVE_PATH_RECEIVED_FLAG ) {
			param_hooks_t hooks;
			param_t *params;

			if (parse_params(&(puri.params),CLASS_CONTACT,&hooks,&params)!=0){
				LM_ERR("failed to parse parameters of first hop\n");
				goto error;
			}
			if (hooks.contact.received)
				*received = hooks.contact.received->body;
			/*for (;params; params = params->next) {
				if (params->type == P_RECEIVED) {
					*received = hooks.contact.received->body;
					break;
				}
			}*/
			free_params(params);
		}
		free_rr(&route);
	}

	path->s = buf;
	path->len = p-buf;
	return 0;
error:
	if(route) free_rr(&route);
	return -1;
}

int build_contact(ucontact_t* c,struct sip_msg *_m)
{
	char *p, *cp, *tmpgr;
	int fl, len,grlen;
	int build_gruu = 0;
	struct socket_info *sock;

	LM_DBG("building contact ...\n");

	if (!disable_gruu && _m->supported && parse_supported(_m) == 0 &&
		(get_supported(_m) & F_SUPPORTED_GRUU))
		build_gruu=1;

	contact.data_len = calc_buf_len(c,build_gruu,_m);
	if (!contact.data_len) return 0;

	if (!contact.buf || (contact.buf_len < contact.data_len)) {
		if (contact.buf) pkg_free(contact.buf);
		contact.buf = (char*)pkg_malloc(contact.data_len);
		if (!contact.buf) {
			contact.data_len = 0;
			contact.buf_len = 0;
			LM_ERR("no pkg memory left\n");
			return -1;
		} else {
			contact.buf_len = contact.data_len;
		}
	}

	p = contact.buf;

	memcpy(p, CONTACT_BEGIN, CONTACT_BEGIN_LEN);
	p += CONTACT_BEGIN_LEN;

	fl = 0;
	while(c) {
		if (VALID_CONTACT(c, act_time)) {
			if (fl) {
				memcpy(p, CONTACT_SEP, CONTACT_SEP_LEN);
				p += CONTACT_SEP_LEN;
			} else {
				fl = 1;
			}

			*p++ = '<';
			memcpy(p, c->c.s, c->c.len);
			p += c->c.len;
			*p++ = '>';

			len = len_q(c->q);
			if (len) {
				memcpy(p, Q_PARAM, Q_PARAM_LEN);
				p += Q_PARAM_LEN;
				memcpy(p, q2str(c->q, 0), len);
				p += len;
			}

			memcpy(p, EXPIRES_PARAM, EXPIRES_PARAM_LEN);
			p += EXPIRES_PARAM_LEN;
			cp = int2str((int)(c->expires - act_time), &len);
			memcpy(p, cp, len);
			p += len;

			if (c->received.s) {
				*p++ = ';';
				memcpy(p, rcv_param.s, rcv_param.len);
				p += rcv_param.len;
				*p++ = '=';
				*p++ = '\"';
				memcpy(p, c->received.s, c->received.len);
				p += c->received.len;
				*p++ = '\"';
			}

			if (build_gruu && c->instance.s) {
				sock = (c->sock)?(c->sock):(_m->rcv.bind_address);
				/* build pub GRUU */
				memcpy(p,PUB_GRUU,PUB_GRUU_SIZE);
				p += PUB_GRUU_SIZE;
				*p++ = '\"';
				memcpy(p,SIP_PROTO,SIP_PROTO_SIZE);
				p += SIP_PROTO_SIZE;
				memcpy(p,c->aor->s,c->aor->len);
				p += c->aor->len;
				if (!reg_use_domain) {
					*p++ = '@';
					memcpy(p,sock->name.s,sock->name.len);
					p += sock->name.len;
					*p++ = ':';
					memcpy(p,sock->port_no_str.s,sock->port_no_str.len);
					p += sock->port_no_str.len;
				}
				memcpy(p,GR_PARAM,GR_PARAM_SIZE);
				p += GR_PARAM_SIZE;
				memcpy(p,c->instance.s+1,c->instance.len-2);
				p += c->instance.len-2;
				*p++ = '\"';

				/* build temp GRUU */
				memcpy(p,TEMP_GRUU,TEMP_GRUU_SIZE);
				p += TEMP_GRUU_SIZE;
				*p++ = '\"';
				memcpy(p,SIP_PROTO,SIP_PROTO_SIZE);
				p += SIP_PROTO_SIZE;
				memcpy(p,TEMP_GRUU_HEADER,TEMP_GRUU_HEADER_SIZE);
				p += TEMP_GRUU_HEADER_SIZE;

				tmpgr = build_temp_gruu(c->aor,&c->instance,&c->callid,&grlen);
				base64encode((unsigned char *)p,
						(unsigned char *)tmpgr,grlen);
				p += calc_temp_gruu_len(c->aor,&c->instance,&c->callid);
				*p++ = '@';
				memcpy(p,sock->name.s,sock->name.len);
				p += sock->name.len;
				*p++ = ':';
				memcpy(p,sock->port_no_str.s,sock->port_no_str.len);
				p += sock->port_no_str.len;
				memcpy(p,GR_NO_VAL,GR_NO_VAL_SIZE);
				p += GR_NO_VAL_SIZE;
				*p++ = '\"';

				/* build +sip.instance */
				memcpy(p,SIP_INSTANCE,SIP_INSTANCE_SIZE);
				p += SIP_INSTANCE_SIZE;
				*p++ = '\"';
				memcpy(p,c->instance.s+1,c->instance.len-2);
				p += c->instance.len-2;
				*p++ = '\"';
			}
		}

		c = c->next;
	}

	memcpy(p, CRLF, CRLF_LEN);
	p += CRLF_LEN;

	contact.data_len = p - contact.buf;

	LM_DBG("created Contact HF: %.*s\n", contact.data_len, contact.buf);
	return 0;
}

static struct socket_info *get_sock_hdr(struct sip_msg *msg)
{
	struct socket_info *sock;
	struct hdr_field *hf;
	str socks;
	str hosts;
	int port;
	int proto;

	if (parse_headers( msg, HDR_EOH_F, 0) == -1) {
		LM_ERR("failed to parse message\n");
		return 0;
	}

	hf = get_header_by_name( msg, sock_hdr_name.s, sock_hdr_name.len);
	if (hf==0)
		return 0;

	trim_len( socks.len, socks.s, hf->body );
	if (socks.len==0)
		return 0;

	if (parse_phostport( socks.s, socks.len, &hosts.s, &hosts.len,
	&port, &proto)!=0) {
		LM_ERR("bad socket <%.*s> in \n",
			socks.len, socks.s);
		return 0;
	}
	set_sip_defaults( port, proto);
	sock = grep_sock_info(&hosts,(unsigned short)port,(unsigned short)proto);
	if (sock==0) {
		LM_ERR("non-local socket <%.*s>\n",	socks.len, socks.s);
		return 0;
	}

	LM_DBG("%d:<%.*s>:%d -> p=%p\n", proto,socks.len,socks.s,port,sock );

	return sock;
}

/*! \brief
 * Fills the common part (for all contacts) of the info structure
 */
static inline ucontact_info_t* pack_ci( struct sip_msg* _m, contact_t* _c,
    unsigned int _e, unsigned int _e_out, unsigned int _f, unsigned int _flags)
{
	static ucontact_info_t ci;
	static str no_ua = str_init("n/a");
	static str callid;
	static str path_received = {0,0};
	static str path;
	static str received = {0,0};
	static int received_found;
	static unsigned int allowed, allow_parsed;
	static struct sip_msg *m = 0;
	static int_str attr_avp_value;
	static struct usr_avp *avp_attr;
	int_str val;

	if (_m!=0) {
		memset( &ci, 0, sizeof(ucontact_info_t));

		/* Get callid of the message */
		callid = _m->callid->body;
		trim_trailing(&callid);
		if (callid.len > CALLID_MAX_SIZE) {
			rerrno = R_CALLID_LEN;
			LM_ERR("callid too long\n");
			goto error;
		}
		ci.callid = &callid;

		/* Get CSeq number of the message */
		if (str2int(&get_cseq(_m)->number, (unsigned int*)&ci.cseq) < 0) {
			rerrno = R_INV_CSEQ;
			LM_ERR("failed to convert cseq number\n");
			goto error;
		}

		/* set received socket */
		if ( _flags&REG_SAVE_SOCKET_FLAG) {
			ci.sock = get_sock_hdr(_m);
			if (ci.sock==0)
				ci.sock = _m->rcv.bind_address;
		} else {
			ci.sock = _m->rcv.bind_address;
		}

		/* additional info from message */
		if (parse_headers(_m, HDR_USERAGENT_F, 0) != -1 && _m->user_agent &&
		_m->user_agent->body.len>0 && _m->user_agent->body.len<UA_MAX_SIZE) {
			ci.user_agent = &_m->user_agent->body;
		} else {
			ci.user_agent = &no_ua;
		}

		/* extract Path headers */
		if ( _flags&REG_SAVE_PATH_FLAG ) {
			if (build_path_vector(_m, &path, &path_received, _flags) < 0) {
				rerrno = R_PARSE_PATH;
				goto error;
			}
			if (path.len && path.s) {
				ci.path = &path;
				/* save in msg too for reply */
				if (set_path_vector(_m, &path) < 0) {
					rerrno = R_PARSE_PATH;
					goto error;
				}
			}
		}

		ci.last_modified = act_time;

		/* set flags */
		ci.flags  = _f;
		ci.cflags =  getb0flags(_m);

		/* get received */
		if (path_received.len && path_received.s) {
			ci.cflags |= ul_api.nat_flag;
			ci.received = path_received;
		}

		allow_parsed = 0; /* not parsed yet */
		received_found = 0; /* not found yet */
		m = _m; /* remember the message */
	}

	if(_c!=0) {
		/* Calculate q value of the contact */
		if (calc_contact_q(_c->q, &ci.q) < 0) {
			rerrno = R_INV_Q;
			LM_ERR("failed to calculate q\n");
			goto error;
		}

		/* set expire time */
		ci.expires = _e + act_time;
		ci.expires_out = _e_out;

		/* Get methods of contact */
		if (_c->methods) {
			if (parse_methods(&(_c->methods->body), &ci.methods) < 0) {
				rerrno = R_PARSE;
				LM_ERR("failed to parse contact methods\n");
				goto error;
			}
		} else {
			/* check on Allow hdr */
			if (allow_parsed == 0) {
				if (m && parse_allow( m ) != -1) {
					allowed = get_allow_methods(m);
				} else {
					allowed = ALL_METHODS;
				}
				allow_parsed = 1;
			}
			ci.methods = allowed;
		}

		if (_c->instance) {
			ci.instance = _c->instance->body;
		}

		/* get received */
		if (ci.received.len==0) {
			if (_c->received) {
				ci.received = _c->received->body;
			} else {
				if (received_found==0) {
					memset(&val, 0, sizeof(int_str));
					if (rcv_avp_name>=0
								&& search_first_avp(rcv_avp_type, rcv_avp_name, &val, 0)
								&& val.s.len > 0) {
						if (val.s.len>RECEIVED_MAX_SIZE) {
							rerrno = R_CONTACT_LEN;
							LM_ERR("received too long\n");
							goto error;
						}
						received = val.s;
					} else {
						received.s = 0;
						received.len = 0;
					}
					received_found = 1;
				}
				ci.received = received;
			}
		}

		/* additional information (script pvar) */
		if (attr_avp_name != -1) {
			avp_attr = search_first_avp(attr_avp_type, attr_avp_name,
										&attr_avp_value, NULL);
			if (avp_attr) {
				ci.attr = &attr_avp_value.s;

				LM_DBG("Attributes: %.*s\n", ci.attr->len, ci.attr->s);
			}
		}
	}

	return &ci;
error:
	return 0;
}

#define is_cflag_set(_name) ((sctx.flags)&(_name))

int send_reply(struct sip_msg* _m, unsigned int _flags)
{
	str unsup = str_init(SUPPORTED_PATH_STR);
	long code;
	str msg = str_init(MSG_200); /* makes gcc shut up */
	char* buf;

	LM_DBG("contact buf: %.*s\n", contact.data_len, contact.buf);

	if (contact.data_len > 0) {
		add_lump_rpl( _m, contact.buf, contact.data_len, LUMP_RPL_HDR|LUMP_RPL_NODUP|LUMP_RPL_NOFREE);
		contact.data_len = 0;
	}

	if (rerrno == R_FINE && (_flags&REG_SAVE_PATH_FLAG) && _m->path_vec.s) {
		if ( (_flags&REG_SAVE_PATH_OFF_FLAG)==0 ) {
			if (parse_supported(_m)<0 && (_flags&REG_SAVE_PATH_STRICT_FLAG)) {
				rerrno = R_PATH_UNSUP;
				if (add_unsupported(_m, &unsup) < 0)
					return -1;
				if (add_path(_m, &_m->path_vec) < 0)
					return -1;
			}
			else if (get_supported(_m) & F_SUPPORTED_PATH) {
				if (add_path(_m, &_m->path_vec) < 0)
					return -1;
			} else if ((_flags&REG_SAVE_PATH_STRICT_FLAG)) {
				rerrno = R_PATH_UNSUP;
				if (add_unsupported(_m, &unsup) < 0)
					return -1;
				if (add_path(_m, &_m->path_vec) < 0)
					return -1;
			}
		}
	}

	code = codes[rerrno];
	switch(code) {
	case 200: msg.s = MSG_200; msg.len = sizeof(MSG_200)-1; break;
	case 400: msg.s = MSG_400; msg.len = sizeof(MSG_400)-1;break;
	case 420: msg.s = MSG_420; msg.len = sizeof(MSG_420)-1;break;
	case 500: msg.s = MSG_500; msg.len = sizeof(MSG_500)-1;break;
	case 503: msg.s = MSG_503; msg.len = sizeof(MSG_503)-1;break;
	}

	if (code != 200) {
		buf = (char*)pkg_malloc(E_INFO_LEN + error_info[rerrno].len + CRLF_LEN + 1);
		if (!buf) {
			LM_ERR("no pkg memory left\n");
			return -1;
		}
		memcpy(buf, E_INFO, E_INFO_LEN);
		memcpy(buf + E_INFO_LEN, error_info[rerrno].s, error_info[rerrno].len);
		memcpy(buf + E_INFO_LEN + error_info[rerrno].len, CRLF, CRLF_LEN);
		add_lump_rpl( _m, buf, E_INFO_LEN + error_info[rerrno].len + CRLF_LEN,
			LUMP_RPL_HDR|LUMP_RPL_NODUP);

		if (code >= 500 && code < 600 && retry_after) {
			if (add_retry_after(_m) < 0) {
				return -1;
			}
		}
	}

	if (sig_api.reply(_m, code, &msg, NULL) == -1) {
		LM_ERR("failed to send %ld %.*s\n", code, msg.len,msg.s);
		return -1;
	} else return 0;
}

int encrypt_str(str *in, str *out)
{
	if (in->len == 0 || !in->s) {
		out->len = 0;
		out->s = NULL;
		return 0;
	}

	out->len = calc_base64_encode_len(in->len);
	out->s = pkg_malloc(out->len);
	if (!out->s) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	memset(out->s, 0, out->len);

	base64encode((unsigned char *)out->s, (unsigned char *)in->s, in->len);
	return 0;
}

int decrypt_str(str *in, str *out)
{
	out->len = calc_max_base64_decode_len(in->len);
	out->s = pkg_malloc(out->len);
	if (!out->s) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	out->len = base64decode((unsigned char *)out->s,
	             (unsigned char *)in->s, in->len);
	return 0;
}

int fix_contact_domain(struct sip_msg *msg, str *aor)
{
	struct sip_uri uri;
	contact_t *c = NULL;
	struct socket_info *adv_sock;
	struct lump *anchor;
	int is_enclosed;
	str hostport, left, left2;
	char *cp, *buf, temp, *p;
	int len, len1;
	str enct = { NULL, 0 }, ustr;
	char ubuf[2 * MAX_URI_SIZE];

	adv_sock = *get_sock_info_list(PROTO_UDP);

	for (c = get_first_contact(msg); c; c = get_next_contact(c)) {
		/* contact found -> parse it */
		if (parse_uri(c->uri.s, c->uri.len, &uri) < 0 || uri.host.len <= 0) {
			LM_ERR("failed to parse Contact URI\n");
			return -1;
		}

		/* if uri string points outside the original msg buffer, it means
		   the URI was already changed, and we cannot do it again */
		if (c->uri.s < msg->buf || c->uri.s > msg->buf + msg->len) {
			LM_ERR("SCRIPT BUG - second attempt to change URI Contact\n");
			return -1;
		}

		hostport = uri.host;
		if (uri.port.len > 0)
			hostport.len = uri.port.s + uri.port.len - uri.host.s;

		LM_DBG("hostport: '%.*s'\n", hostport.len, hostport.s);

		left.s = hostport.s + hostport.len;
		left.len = c->uri.s+c->uri.len - left.s;

		LM_DBG("left: '%.*s'\n", left.len, left.s);
		LM_DBG("uri.maddr: '%.*s'\n", uri.maddr_val.len, uri.maddr_val.s);

		if (uri.maddr.len) {
			left2.s = uri.maddr_val.s + uri.maddr_val.len;
			left2.len = left.s + left.len - left2.s;
			left.len=uri.maddr.s-1-left.s;
		} else {
			left2.s = "";
			left2.len = 0;
		}

		LM_DBG("left2: '%.*s'\n", left2.len, left2.s);

		LM_DBG("c->name: '%.*s'\nin: %.*s\n", c->len, (c->name.s?c->name.s:c->uri.s), c->uri.len, c->uri.s);

		if (encrypt_str(&c->uri, &enct)) {
			LM_ERR("failed to encrypt contact\n");
			return -1;
		}

		is_enclosed = 0;
		p = hostport.s + hostport.len; /*start searching after ip:port */
		cp = (c->name.s?c->name.s:c->uri.s) + c->len; /* where to end */
		for( ; p<cp ; p++ )
			if (*p=='>') {is_enclosed=1;hostport.len=p-uri.host.s;break;}

		anchor = del_lump(msg, c->uri.s - msg->buf /* offset */,
			hostport.s + hostport.len - c->uri.s /* len */, HDR_CONTACT_T);
		if (!anchor)
			return -1;

		//cp = ip_addr2a(&msg->rcv.src_ip);
		len = (hostport.s - c->uri.s) + strlen(adv_sock->address_str.s) + 6 /* :port */
			+ 2 /* just in case if IPv6 */
			+ 1 + left.len + left2.len
			+ 2 + matching_param.len + enct.len;
		buf = pkg_malloc(len);
		if (buf == NULL) {
			LM_ERR("out of pkg memory\n");
			return -1;
		}
		temp = hostport.s[0]; hostport.s[0] = '\0';

		LM_DBG("building new Contact:\nuri: '%s'\nadv_sock: '%s'\nport: '%s'\n"
		       "l1: '%.*s'\nl2: '%.*s'\nfull Contact: '%.*s\nenc Contact: '%.*s'\n", c->uri.s, adv_sock->address_str.s,
			adv_sock->port_no_str.s,left.len,left.s,left2.len,left2.s,
		    c->uri.len, c->uri.s, enct.len, enct.s);
		len1 = snprintf(buf, len, "%s%s:%s%.*s%.*s;%.*s=%.*s", c->uri.s,
		         adv_sock->address_str.s, adv_sock->port_no_str.s, left.len,
		         left.s, left2.len, left2.s, matching_param.len, matching_param.s,
				 enct.len, enct.s);

		if (len1 < len)
			len = len1;

		hostport.s[0] = temp;

		if (insert_new_lump_after(anchor, buf, len, HDR_CONTACT_T) == 0) {
			pkg_free(buf);
			return -1;
		}

		if (is_enclosed) {
			c->uri.s = buf;
			c->uri.len = len1;
		} else {
			c->uri.s = buf + 1;
			c->uri.len = len - 2;
		}
	}

	return 0;
}


void mid_reg_req_fwded(struct cell *t, int type, struct tmcb_params *params)
{
	struct sip_msg *req = params->req;

	struct mid_reg_queue_entry *entry = *(struct mid_reg_queue_entry **)(params->param);
	str *ruri = GET_NEXT_HOP(req);
	contact_t *c;
	int timeout_tick, timeout;
	struct lump *lump;
	int new_exp_hdr = 0, len;
	char *p;
	str ct_uri;

	parse_message(req);
	if (req->expires)
		LM_DBG("msg expires: '%.*s'\n", req->expires->body.len, req->expires->body.s);

	for (c = get_first_contact(req); c; c = get_next_contact(c)) {
		calc_ob_contact_expires(req, c->expires, &timeout_tick, NULL);
		if (timeout_tick == 0)
			timeout = 0;
		else
			timeout = timeout_tick - act_time;

		entry->expires = timeout;

		/* TODO FIXME we're now assuming the request has an "Expires: " header */
		if (!c->expires) {
			if (!new_exp_hdr) {
				LM_DBG("....... Exp hdr: '%.*s'\n", req->expires->body.len, req->expires->body.s);
				lump = del_lump(req, req->expires->body.s - req->buf, req->expires->body.len, HDR_EXPIRES_T);
				if (!lump) {
					LM_ERR("fail del_lump on 'Expires:' hf value!\n");
					return;
				}

				p = pkg_malloc(10);
				if (!p)
					return;

				len = sprintf(p, "%d", timeout);

				if (!insert_new_lump_after(lump, p, len, HDR_OTHER_T)) {
					LM_ERR("fail to insert_new_lump over 'Expires' hf value!\n");
					return;
				}

				new_exp_hdr = 1;
			}
		} else {
			/* TODO ";expires" overwriting!!! */
		}

		ct_uri.len = c->uri.len;
		ct_uri.s = c->uri.s;

		shm_str_dup(&entry->ct_uri, &ct_uri);

		LM_DBG("....... contact: '%.*s' Calculated TIMEOUT = %d (%d)\n",
		       c->len, c->uri.s, timeout_tick, timeout);
	}

	shm_str_dup(&entry->ruri, ruri);

	if (routing_mode == ROUTE_BY_CONTACT) {
		LM_DBG("fixing contact domain ... \n");
		if (fix_contact_domain(req, &entry->aor))
			LM_ERR("failed to overwrite Contact header field domain\n");
	} else {
		if (prepend_path(req, &entry->aor, 0, 0))
			LM_ERR("failed to append Path header for aor '%.*s'!\n",
			       entry->aor.len, entry->aor.s);
	}

	LM_DBG("REQ FORWARDED TO '%.*s', expires=%d\n",
	       ruri->len, ruri->s, entry->expires_out);
}

int replace_response_expires(struct sip_msg *msg, contact_t *ct, int expires)
{
	struct lump *lump;
	int len;
	char *p;

	LM_DBG("replacing expires for ct '%.*s' '%.*s' with %d, %p -> %p (? %p)\n",
	       ct->uri.len, ct->uri.s, ct->expires->body.len, ct->expires->body.s,
	       expires, msg->buf, msg->buf+msg->len, ct->expires->body.s);

	lump = del_lump(msg, ct->expires->body.s - msg->buf, ct->expires->body.len,
	                HDR_EXPIRES_T);
	if (!lump) {
		LM_ERR("del_lump() failed!\n");
		return -1;
	}

	p = pkg_malloc(10);
	if (!p)
		return -1;

	len = sprintf(p, "%d", expires);

	if (!insert_new_lump_after(lump, p, len, HDR_OTHER_T)) {
		LM_ERR("insert_new_lump_after() failed!\n");
		return -1;
	}

	return 0;
}

static inline int update_contacts(struct sip_msg* req, struct sip_msg* _m, urecord_t* _r,
                                  struct mid_reg_queue_entry *entry)
{
	ucontact_info_t *ci;
	ucontact_t *c, *c_last, *c_it;
	contact_t *_c, *__c;
	int e, e_out;
	unsigned int cflags;
	int ret;
	int num;
	int e_max;
	int tcp_check;
	struct sip_uri uri;
	struct sip_uri uri2;

	/* mem flag */
	cflags = (entry->flags&REG_SAVE_MEMORY_FLAG)?FL_MEM:FL_NONE;

	/* pack the contact_info */
	if ( (ci=pack_ci(req, 0, 0, 0, cflags, entry->flags))==0 ) {
		LM_ERR("failed to initial pack contact info\n");
		goto error;
	}

	/* count how many contacts we have right now */
	num = 0;
	if (entry->max_contacts) {
		c = _r->contacts;
		while(c) {
			if (VALID_CONTACT(c, act_time)) num++;
			c = c->next;
		}
	}

	if (is_tcp_based_proto(_m->rcv.proto) && (_m->flags&tcp_persistent_flag)) {
		e_max = -1;
		tcp_check = 1;
	} else {
		e_max = tcp_check = 0;
	}

	LM_DBG("[UPDATE] trying to match ...\n");
	for (__c = get_first_contact(req); __c; __c = get_next_contact(__c)) {
		/* calculate expires */
		calc_contact_expires(req, __c->expires, &e, NULL);

		if (parse_uri(__c->uri.s, __c->uri.len, &uri) < 0) {
			LM_ERR("failed to parse contact <%.*s>\n",
					__c->uri.len, __c->uri.s);
			return -1;
		}

		ret = ul_api.get_ucontact( _r, &__c->uri, ci->callid, ci->cseq, &c);
		if (ret==-1) {
			LM_ERR("invalid cseq for aor <%.*s>\n",_r->aor.len,_r->aor.s);
			rerrno = R_INV_CSEQ;
			goto error;
		/* old CSeq or de-registration on non-existing contact */
		} else if (ret==-2 || (ret > 0 && e == 0)) {
			continue;
		} else if (ret == 0 && e == 0) {
			if (entry->flags&REG_SAVE_MEMORY_FLAG) {
				c->flags |= FL_MEM;
			} else {
				c->flags &= ~FL_MEM;
			}

			if (ul_api.delete_ucontact(_r, c, 0) < 0) {
				rerrno = R_UL_DEL_C;
				LM_ERR("failed to delete contact\n");
				goto error;
			}
			timer_queue_del_contact(c);
			continue;
		}

		LM_DBG("doing REQ ct:  name='%.*s', uri='%.*s'...\n",
		       uri.user.len, uri.user.s, __c->uri.len, __c->uri.s);
		for (_c = get_first_contact(_m) ; _c ; _c = get_next_contact(_c)) {
			calc_contact_expires(_m, _c->expires, &e_out, NULL);
			LM_DBG("comparing with ct: uri='%.*s'\n", _c->uri.len, _c->uri.s);

			if (parse_uri(_c->uri.s, _c->uri.len, &uri2) < 0) {
				LM_ERR("failed to parse contact <%.*s>\n",
						_c->uri.len, _c->uri.s);
				return -1;
			}

			if (str_strcmp(&uri.user, &uri2.user))
				continue;

			if (e != e_out) {
				if (replace_response_expires(_m, _c, e)) {
					LM_ERR("failed to mangle 200 OK response!\n"); 
					return -1;
				}
			}

			LM_DBG("match! %d - %d\n", e, e_out);
			if (ret > 0) {
				/* we need to add a new contact -> too many ?? */
				while (entry->max_contacts && num>=entry->max_contacts) {
					if (entry->flags&REG_SAVE_FORCE_REG_FLAG) {
						/* we are overflowing the number of maximum contacts,
						   so remove the oldest valid one to prevent this */
						for( c_it=_r->contacts,c_last=NULL ; c_it ;
						c_it=c_it->next )
							if (VALID_CONTACT(c_it, act_time))
								c_last=c_it;
						if (c_last==NULL) {
							LM_CRIT("BUG - overflow detected but no valid "
								"contacts found :( \n");
							goto error;
						}
						LM_DBG("overflow on inserting new contact -> removing "
							"<%.*s>\n", c_last->c.len, c_last->c.s);
						if (ul_api.delete_ucontact( _r, c_last, 0)!=0) {
							LM_ERR("failed to remove contact\n");
							goto error;
						}
						num--;
					} else {
						LM_ERR("too many contacts for AOR <%.*s>, max=%d\n",
							_r->aor.len, _r->aor.s, entry->max_contacts);
						rerrno = R_TOO_MANY;
						return -1;
					}
				}

				/* pack the contact_info */
				if ( (ci=pack_ci( 0, __c, e, e_out, 0, entry->flags))==0 ) {
					LM_ERR("failed to extract contact info\n");
					goto error;
				}

				LM_DBG(":: inserting contact with expires %lu\n", ci->expires);

				if (ul_api.insert_ucontact( _r, &__c->uri, ci, &c, 0) < 0) {
					rerrno = R_UL_INS_C;
					LM_ERR("failed to insert contact\n");
					goto error;
				}

				/* for throttling modes, update the timer structures as well */
				if (reg_mode != MID_REG_MIRROR) {
					entry->expires = e;
					entry->expires_out = e_out;
					entry->rec = _r;
					entry->con = c;
					timer_queue_add(entry);
				}
			} else {
				/* do update */
				/* if the contact to be updated is not valid, it will be after
				 * update, so need to compensate the total number of contact */
				if ( !VALID_CONTACT(c,act_time) )
					num++;
				while ( entry->max_contacts && num>entry->max_contacts ) {
					if (entry->flags&REG_SAVE_FORCE_REG_FLAG) {
						/* we are overflowing the number of maximum contacts,
						   so remove the first (oldest) one to prevent this
						   (but not the one to be updated !) */
						for( c_it=_r->contacts,c_last=NULL ; c_it ;
						c_it=c_it->next )
							if (VALID_CONTACT(c_it, act_time) && c_it!=c)
								c_last=c_it;
						if (c_last==NULL) {
							LM_CRIT("BUG - overflow detected but no "
								"valid contacts found :( \n");
							goto error;
						}
						LM_DBG("overflow on update -> removing contact "
							"<%.*s>\n", c_last->c.len, c_last->c.s);
						if (ul_api.delete_ucontact( _r, c_last, 0)!=0) {
							LM_ERR("failed to remove contact\n");
							goto error;
						}
						num--;
					} else {
						LM_ERR("too many contacts for AOR <%.*s>, max=%d\n",
							_r->aor.len, _r->aor.s, entry->max_contacts);
						rerrno = R_TOO_MANY;
						return -1;
					}
				}

				/* pack the contact specific info */
				if ( (ci=pack_ci( 0, __c, e, e_out, 0, entry->flags))==0 ) {
					LM_ERR("failed to pack contact specific info\n");
					goto error;
				}

				if (ul_api.update_ucontact(_r, c, ci, 0) < 0) {
					rerrno = R_UL_UPD_C;
					LM_ERR("failed to update contact\n");
					goto error;
				}

				if (reg_mode != MID_REG_MIRROR)
					timer_queue_update_by_ct(c, e_out);
			}

			if (tcp_check) {
				/* parse contact uri to see if transport is TCP */
				if (parse_uri( __c->uri.s, __c->uri.len, &uri)<0) {
					LM_ERR("failed to parse contact <%.*s>\n",
							__c->uri.len, __c->uri.s);
				} else if (is_tcp_based_proto(uri.proto)) {
					if (e_max>0) {
						LM_WARN("multiple TCP contacts on single REGISTER\n");
					}
					/* TODO FIXME */
					//if (e_out>e_max) e_max = e_out;
				}
			}
		}
	}

	/* TODO FIXME */
	//if ( tcp_check && e_max>-1 ) {
	//	if (e_max) e_max -= act_time;
	//	trans_set_dst_attr( &_m->rcv, DST_FCNTL_SET_LIFETIME,
	//		(void*)(long)(e_max + 10) );
	//}

	return 0;
error:
	return -1;
}

int get_match_token(str *uri, str *out_tok, struct sip_uri *out_puri, int *out_idx)
{
	struct sip_uri puri;
	int i;

	if (parse_uri(uri->s, uri->len, &puri) < 0) {
		LM_ERR("failed to parse contact <%.*s>\n", uri->len, uri->s);
		return -1;
	}

	if (matching_mode == MATCH_BY_PARAM) {
		for (i = 0; i < puri.u_params_no; i++) {
			if (!str_strcmp(&puri.u_name[i], &matching_param)) {
				*out_tok = puri.u_val[i];
				if (out_idx)
					*out_idx = i;
				break;
			}
		}

		if (!out_tok->s || out_tok->len <= 0) {
			LM_ERR("a Contact from main registrar (%.*s) is missing the '%.*s'"
			       "hf parameter\n", uri->len, uri->s,
			       matching_param.len, matching_param.s);
			return -1;
		}
	} else {
		*out_tok = puri.user;

		if (!out_tok->s || out_tok->len <= 0) {
			LM_ERR("missing SIP user in Contact from main registrar (%.*s)\n",
			       uri->len, uri->s);
			return -1;
		}
	}

	if (out_puri)
		*out_puri = puri;

	return 0;
}

static inline int insert_contacts(struct sip_msg *req, struct sip_msg* _m,
			struct mid_reg_queue_entry *entry, str* _a, urecord_t **rec)
{
	ucontact_info_t* ci;
	urecord_t* r = NULL;
	ucontact_t* c;
	contact_t *_c, *__c;
	unsigned int cflags;
	int num;
	int e, e_out;
	int e_max;
	int tcp_check;
	struct sip_uri uri;
	struct sip_uri uri2;

	_c = get_first_contact(_m);

	cflags = (entry->flags&REG_SAVE_MEMORY_FLAG)?FL_MEM:FL_NONE;
	if (is_tcp_based_proto(_m->rcv.proto) && (_m->flags&tcp_persistent_flag)) {
		e_max = 0;
		tcp_check = 1;
	} else {
		e_max = tcp_check = 0;
	}

	LM_DBG("running\n");

	for (__c = get_first_contact(req); __c; __c = get_next_contact(__c)) {
		/* calculate expires */
		calc_contact_expires(req, __c->expires, &e, NULL);

		/* Skip contacts with zero expires */
		if (e == 0)
			continue;

		if (parse_uri(__c->uri.s, __c->uri.len, &uri) < 0) {
			LM_ERR("failed to parse contact <%.*s>\n",
					__c->uri.len, __c->uri.s);
			return -1;
		}

		LM_DBG("REQ ct: [name='%.*s', uri='%.*s']\n",
		        uri.user.len, uri.user.s, __c->uri.len, __c->uri.s);
		for( num=0,r=0,ci=0 ; _c ; _c = get_next_contact(_c) ) {
			LM_DBG("  REPLY ct: [uri='%.*s']\n", _c->uri.len, _c->uri.s);

			if (parse_uri(_c->uri.s, _c->uri.len, &uri2) < 0) {
				LM_ERR("failed to parse contact <%.*s>\n",
						_c->uri.len, _c->uri.s);
				return -1;
			}

			if (str_strcmp(&uri.user, &uri2.user))
				continue;

			calc_contact_expires(_m, _c->expires, &e_out, NULL);
			LM_DBG("    >> REGISTER %ds ------- %ds 200 OK <<!\n", e, e_out);

			if (e != e_out) {
				if (replace_response_expires(_m, _c, e)) {
					LM_ERR("failed to mangle 200 OK response!\n"); 
					return -1;
				}
			}

			if (entry->max_contacts && (num >= entry->max_contacts)) {
				if (entry->flags&REG_SAVE_FORCE_REG_FLAG) {
					/* we are overflowing the number of maximum contacts,
					   so remove the first (oldest) one to prevent this */
					if (r==NULL || r->contacts==NULL) {
						LM_CRIT("BUG - overflow detected with r=%p and "
							"contacts=%p\n",r,r->contacts);
						goto error;
					}
					if (ul_api.delete_ucontact( r, r->contacts, 0)!=0) {
						LM_ERR("failed to remove contact\n");
						goto error;
					}
				} else {
					LM_ERR("too many contacts (%d) for AOR <%.*s>, max=%d\n",
							num, _a->len, _a->s, entry->max_contacts);
					rerrno = R_TOO_MANY;
					goto error;
				}
			} else {
				num++;
			}

			if (!r) {
				if (ul_api.insert_urecord(entry->dom, _a, &r, 0) < 0) {
					rerrno = R_UL_NEW_R;
					LM_ERR("failed to insert new record structure\n");
					goto error;
				}
			}

			/* pack the contact_info */
			if ( (ci=pack_ci( (ci==0)?req:0, __c, e, e_out, cflags, entry->flags))==0 ) {
				LM_ERR("failed to extract contact info\n");
				goto error;
			}

			if ( r->contacts==0 ||
			ul_api.get_ucontact(r, &__c->uri, ci->callid, ci->cseq+1, &c)!=0 ) {
				LM_DBG("INSERTING .....\n");
				LM_DBG(":: inserting contact with expires %lu\n", ci->expires);
				if (ul_api.insert_ucontact( r, &__c->uri, ci, &c, 0) < 0) {
					rerrno = R_UL_INS_C;
					LM_ERR("failed to insert contact\n");
					goto error;
				}

				if (reg_mode != MID_REG_MIRROR) {
					entry->expires = e;
					entry->expires_out = e_out;
					entry->next_check_ts = act_time + e;
					entry->rec = r;
					entry->con = c;
					timer_queue_add(entry);
				}
			} else {
				LM_DBG("UPDATING .....\n");
				if (ul_api.update_ucontact( r, c, ci, 0) < 0) {
					rerrno = R_UL_UPD_C;
					LM_ERR("failed to update contact\n");
					goto error;
				}
			}

			if (tcp_check) {
				/* parse contact uri to see if transport is TCP */
				if (parse_uri( __c->uri.s, __c->uri.len, &uri)<0) {
					LM_ERR("failed to parse contact <%.*s>\n",
							__c->uri.len, __c->uri.s);
				} else if ( is_tcp_based_proto(uri.proto) ) {
					if (e_max) {
						LM_WARN("multiple TCP contacts on single REGISTER\n");
						if (e_out>e_max) e_max = e_out;
					} else {
						e_max = e_out;
					}
				}
			}
		}
	}

	if (r) {
		//if (r->contacts) {
		//	build_contact(r->contacts,_m);
		//}
		ul_api.release_urecord(r, 0);
		if (rec)
			*rec = r;
	}

	if ( tcp_check && e_max>0 ) {
		e_max -= act_time;
		trans_set_dst_attr( &_m->rcv, DST_FCNTL_SET_LIFETIME,
			(void*)(long)(e_max + 10) );
	}

	return 0;
error:
	if (r)
		ul_api.delete_urecord(entry->dom, _a, r, 0);
	return -1;
}

/*
 * Fixes the required 200 OK reply Contact header field domain
 * so it matches the INVITE Contact header field domain
 */
int fix_reply_contact_domain(struct sip_msg *req, struct sip_msg *rpl)
{
	contact_t *c, *req_ct;
	struct sip_uri newuri, uri, match_uri;
	str match_tok, hostport, dec_uri;
	char *buf;
	int i;
	int delim;
	struct lump *anchor;

	LM_DBG("fixing reply domain\n");

	/* TODO: add proper handling for multiple Contacts!!! */
	req_ct = get_first_contact(req);
	if (parse_uri(req_ct->uri.s, req_ct->uri.len, &newuri) < 0) {
		LM_ERR("failed to parse contact <%.*s>\n",
				req_ct->uri.len, req_ct->uri.s);
		return -1;
	}

	for (c = get_first_contact(rpl); c; c = get_next_contact(c)) {
		memset(&match_tok, 0, sizeof match_tok);

		if (get_match_token(&c->uri, &match_tok, &uri, &i) != 0) {
			LM_ERR("failed to get match token\n");
			return -1;
		}

		if (decrypt_str(&match_tok, &dec_uri)) {
			LM_ERR("failed to decrypt matching Contact param (%.*s=%.*s)\n",
			       matching_param.len, matching_param.s,
			       match_tok.len, match_tok.s);
			return -1;
		}

		if (parse_uri(dec_uri.s, dec_uri.len, &match_uri) < 0) {
			pkg_free(dec_uri.s);
			LM_ERR("failed to parse decrypted uri <%.*s>\n",
			       dec_uri.len, dec_uri.s);
			return -1;
		}

		/* try to match the request Contact with a Contact from the reply */
		if (compare_uris(NULL, &match_uri, NULL, &newuri))
			continue;

		hostport = uri.host;
		if (uri.port.len > 0)
			hostport.len = uri.port.s + uri.port.len - uri.host.s;

		LM_DBG("> hostport for dec_uri '%.*s' is '%.*s\n", dec_uri.len,
		       dec_uri.s, hostport.len, hostport.s);

		anchor = del_lump(rpl, hostport.s - rpl->buf /* offset */,
		                  hostport.len, HDR_CONTACT_T);
		if (!anchor) {
			LM_ERR("del_lump 1 failed for reply Contact URI '%.*s'\n",
			       c->uri.len, c->uri.s);
			return -1;
		}

		hostport = match_uri.host;
		if (match_uri.port.len > 0)
			hostport.len = match_uri.port.s + match_uri.port.len - match_uri.host.s;

		buf = pkg_malloc(hostport.len + 1);
		if (buf == NULL) {
			LM_ERR("out of pkg memory\n");
			return -1;
		}

		memcpy(buf, hostport.s, hostport.len);
		buf[hostport.len] = '\0';

		LM_DBG("inserting new uri: '%s'\n", buf);


		if (insert_new_lump_after(anchor, buf, hostport.len, HDR_CONTACT_T) == 0) {
			pkg_free(buf);
			return -1;
		}

		LM_DBG("deleting param '%.*s' @ %p\n", uri.u_name[i].len, uri.u_name[i].s, uri.u_name[i].s);

		if (matching_mode == MATCH_BY_PARAM) {
			/* remove our added matching parameter on the way back to the UAC */
			if (!del_lump(rpl, uri.u_name[i].s - rpl->buf - 1 /* offset */,
				1 + uri.u_name[i].len + 1 + match_tok.len /* ;param=value */, HDR_OTHER_T)) {
				LM_ERR("del_lump 2 failed for reply Contact URI '%.*s'\n",
				       c->uri.len, c->uri.s);
				return -1;
			}
		}

		pkg_free(dec_uri.s);
	}

	return 0;
}

typedef void (transaction_cb) (struct cell* t, int type, struct tmcb_params*);

void mid_reg_resp_in(struct cell *t, int type, struct tmcb_params *params)
{
	struct mid_reg_queue_entry *entry = *(struct mid_reg_queue_entry **)(params->param);
	//udomain_t *ud = (udomain_t *)dom;
	urecord_t *rec = NULL;
	struct sip_msg *rpl = params->rpl;
	struct sip_msg *req = params->req;
	int code;
	int rc = 1;

	code = rpl->first_line.u.reply.statuscode;
	LM_DBG("pushing reply back to caller: %d\n", code);
	LM_DBG("request -------------- \n%s\nxxx: \n", req->buf);
	LM_DBG("reply -------------- \n%s\n", rpl->buf);

	if (code < 200 || code >= 300)
		return;

	//------------------------------------------------
	/**
	 * TODO
	 *
	 * if throttling_mode == True:
	 *     lock_udomain()
	 *     save_contacts()
	 *     urec = get_urecord()
	 *     if urec->contacts == 1:
	 *         ref(urec)
	 *         write_lock(uac_timer_queue)
	 *         add_to_pending(urec, expires)
	 *         write_unlock(uac_timer_queue)
	 *     unlock_udomain()
	 * else:
	 *     reg_tmcb()
	 */
	get_act_time();

	parse_message(req);
	parse_message(rpl);

	if (routing_mode == ROUTE_BY_CONTACT) {
		LM_DBG("fixing contact domain ... \n");
		if (fix_reply_contact_domain(req, rpl))
			LM_ERR("failed to overwrite Contact header field domain\n");
	}

	ul_api.lock_udomain(entry->dom, &entry->aor);

	rc = ul_api.get_urecord(entry->dom, &entry->aor, &rec);
	/*
	 * at least 1 binding for this AoR, which means the module's
	 * UAC timer is already aware of it
	 */
	if (rc == 0) {
		LM_DBG("+++++ top UPDATE\n");
		if (update_contacts(req, rpl, rec, entry)) {
			//build_contact(rec->contacts, rpl);
			ul_api.release_urecord(rec, 0);
			ul_api.unlock_udomain(entry->dom, &entry->aor);
			return;
		}

		//build_contact(rec->contacts, rpl);
		//ul_api.release_urecord(rec, 0);

		/* TODO: ref urecord_t */

	} else {
		LM_DBG("..... top INSERT\n");
		if (insert_contacts(req, rpl, entry, &entry->aor, &rec)) {
			ul_api.unlock_udomain(entry->dom, &entry->aor);
			return;
		}
	}

	ul_api.unlock_udomain(entry->dom, &entry->aor);

	LM_DBG("got ptr back: %p\n", entry);
	LM_DBG("RESPONSE FORWARDED TO caller!\n");
}

/* !! retcodes: 1 or -1 !! */
int prepare_forward(struct sip_msg *msg, udomain_t *ud, str *aor, int expires_out)
{
	struct mid_reg_queue_entry *entry;

	LM_DBG("from: '%.*s'\n", msg->from->body.len, msg->from->body.s);
	LM_DBG("Contact: '%.*s'\n", msg->from->body.len, msg->from->body.s);

	entry = mk_timer_queue_entry(0, expires_out, ud, aor, NULL, NULL, NULL, &msg->from->body, &msg->callid->body);
	if (!entry)
		return -1;

	if (reg_mode != MID_REG_MIRROR) {
		LM_DBG("registering ptr %p on TMCB_REQUEST_FWDED ...\n", entry);
		if (tm_api.register_tmcb(msg, NULL, TMCB_REQUEST_FWDED,
		    mid_reg_req_fwded, entry, NULL) <= 0) {
			LM_ERR("cannot register additional callbacks\n");
			return -1;
		}
	}

	LM_DBG("registering callback on TMCB_RESPONSE_FWDED, entry=%p ...\n", entry);
	if (tm_api.register_tmcb(msg, NULL, TMCB_RESPONSE_IN,
	    mid_reg_resp_in, entry, NULL) <= 0) {
		LM_ERR("cannot register additional callbacks\n");
		return -1;
	}

	return 1;
}




static int w_mid_reg_save(struct sip_msg *msg, char *dom, char *flags_gp,
                          char *to_uri_gp, char *expires_gp)
{
	udomain_t *ud = (udomain_t *)dom;
	urecord_t *rec;
	str flags = { NULL, 0 }, to_uri = { NULL, 0 };
	str aor = { NULL, 0 };
	int expires_out;
	contact_t *ct;
	ucontact_info_t *ci;
	ucontact_t *c;
	int e, ret;

	if (flags_gp && fixup_get_svalue(msg, (gparam_p)flags_gp, &flags)) {
		LM_ERR("invalid flags parameter");
		return -1;
	}

	if (!to_uri_gp) {
		to_uri = get_to(msg)->uri;
	} else if (fixup_get_svalue(msg, (gparam_p)to_uri_gp, &to_uri)) {
		LM_ERR("invalid AoR parameter");
		return -1;
	}

	if (!expires_gp) {
		expires_out = outbound_expires;
	} else if (fixup_get_ivalue(msg, (gparam_p)expires_gp, &expires_out)) {
		LM_ERR("invalid outbound_expires parameter");
		return -1;
	}

	if (extract_aor(&to_uri, &aor, 0, 0) < 0) {
		LM_ERR("failed to extract Address Of Record\n");
		ul_api.unlock_udomain(ud, &aor);
		return -1;
	}

	parse_message(msg);

	/* in mirror mode, all REGISTER requests simply pass through */
	if (reg_mode == MID_REG_MIRROR)
		return prepare_forward(msg, ud, &aor, expires_out);

	get_act_time();

	ul_api.lock_udomain(ud, &aor);

	if (ul_api.get_urecord(ud, &aor, &rec) != 0) {
		ul_api.unlock_udomain(ud, &aor);
		return prepare_forward(msg, ud, &aor, expires_out);
	}

	/* TODO FIXME */
	//cflags = (flags&REG_SAVE_MEMORY_FLAG)?FL_MEM:FL_NONE;
	/* pack the contact_info */
	if ( (ci=pack_ci(msg, 0, 0, 0, 0, 0))==0 ) {
		LM_ERR("failed to initial pack contact info\n");
		ul_api.unlock_udomain(ud, &aor);
		return -1;
	}

	/* if there are any new contacts, we must return a "forward" code */
	for (ct = get_first_contact(msg); ct; ct = get_next_contact(ct)) {
		calc_contact_expires(msg, ct->expires, &e, NULL);

		ret = ul_api.get_ucontact(rec, &ct->uri, ci->callid, ci->cseq, &c);
		if (ret == -1) {
			LM_ERR("invalid cseq for aor <%.*s>\n",rec->aor.len,rec->aor.s);
			rerrno = R_INV_CSEQ;
			ul_api.unlock_udomain(ud, &aor);
			return -1;
		} else if (ret == -2) { /* duplicate or lower cseq */
			continue;
		} else if (ret == 0) { /* found */
			LM_DBG("found >> %d --- [ %ld, %ld ]\n", e, c->expires_in, c->expires_out);
			if (e == 0 || e != c->expires_in) {
				LM_DBG("FWD 1\n");
				goto out_forward;
			}

			//if (should_relay_register(c, e)) {
			if (timer_queue_update_by_ct(c, e)) {
				LM_DBG("FWD 2\n");
				goto out_forward;
			} else {
				/* pack the contact specific info */
				ci = pack_ci(msg, ct, e, c->expires_out, 0, 0);
				if (!ci) {
					LM_ERR("failed to pack contact specific info\n");
					rerrno = R_UL_UPD_C;
					goto out_error;
				}

				if (ul_api.update_ucontact(rec, c, ci, 0) < 0) {
					rerrno = R_UL_UPD_C;
					LM_ERR("failed to update contact\n");
					goto out_error;
				}

				continue;
			}
		}

		/* not found */
		goto out_forward;
	}

	/* prepare the Contact header field for a quick 200 OK response */
	build_contact(rec->contacts, msg);

	/* no contacts need updating on the far end registrar */
	ul_api.unlock_udomain(ud, &aor);

	/* quick SIP reply */
	send_reply(msg, 0);
	return 2;

out_forward:
	ul_api.unlock_udomain(ud, &aor);
	return prepare_forward(msg, ud, &aor, expires_out);

out_error:
	send_reply(msg, 0);
	return -1;
}

//int set_ruri(struct sip_msg *msg, str *uri)
//


static int w_mid_reg_lookup(struct sip_msg* _m, char* _t, char* _f, char* _s)
{
	unsigned int flags;
	urecord_t* r;
	str aor, uri;
	ucontact_t* ptr,*it;
	int res;
	int ret;
	str path_dst;
	str flags_s;
	char* ua = NULL;
	char* re_end = NULL;
	int re_len = 0;
	char tmp;
	regex_t ua_re;
	int regexp_flags = 0;
	regmatch_t ua_match;
	pv_value_t val;
	int_str istr;
	str sip_instance = {0,0},call_id = {0,0};
	str pst, dec_tok, match_tok, hostport;
	struct sip_uri dec_uri;
	int i;

	/* branch index */
	int idx;

	/* temporary branch values*/
	int tlen;
	char *turi;

	char ubuf[MAX_URI_SIZE];

	qvalue_t tq;

	LM_DBG("mid_reg_lookup ... \n");

	flags = 0;
	if (_f && _f[0]!=0) {
		if (fixup_get_svalue( _m, (gparam_p)_f, &flags_s)!=0) {
			LM_ERR("invalid owner uri parameter");
			return -1;
		}
		for( res=0 ; res< flags_s.len ; res++ ) {
			switch (flags_s.s[res]) {
				case 'm': flags |= REG_LOOKUP_METHODFILTER_FLAG; break;
				case 'b': flags |= REG_LOOKUP_NOBRANCH_FLAG; break;
				case 'r': flags |= REG_BRANCH_AOR_LOOKUP_FLAG; break;
				case 'u':
					if (flags_s.s[res+1] != '/') {
						LM_ERR("no regexp after 'u' flag");
						break;
					}
					res++;
					if ((re_end = strrchr(flags_s.s+res+1, '/')) == NULL) {
						LM_ERR("no regexp after 'u' flag");
						break;
					}
					res++;
					re_len = re_end-flags_s.s-res;
					if (re_len == 0) {
						LM_ERR("empty regexp");
						break;
					}
					ua = flags_s.s+res;
					flags |= REG_LOOKUP_UAFILTER_FLAG;
					LM_DBG("found regexp /%.*s/", re_len, ua);
					res += re_len;
					break;
				case 'i': regexp_flags |= REG_ICASE; break;
				case 'e': regexp_flags |= REG_EXTENDED; break;
				default: LM_WARN("unsupported flag %c \n",flags_s.s[res]);
			}
		}
	}
	if (flags&REG_BRANCH_AOR_LOOKUP_FLAG) {
		/* extract all the branches for further usage */
		nbranches = 0;
		while (
			(turi=get_branch(nbranches, &tlen, &tq, NULL, NULL, NULL, NULL))
				) {
			/* copy uri */
			branch_uris[nbranches].s = urimem[nbranches];
			if (tlen) {
				memcpy(branch_uris[nbranches].s, turi, tlen);
				branch_uris[nbranches].len = tlen;
			} else {
				*branch_uris[nbranches].s  = '\0';
				branch_uris[nbranches].len = 0;
			}

			nbranches++;
		}
		clear_branches();
		idx=0;
	}


	if (_s) {
		if (pv_get_spec_value( _m, (pv_spec_p)_s, &val)!=0) {
			LM_ERR("failed to get PV value\n");
			return -1;
		}
		if ( (val.flags&PV_VAL_STR)==0 ) {
			LM_ERR("PV vals is not string\n");
			return -1;
		}
		uri = val.rs;
	} else {
		uri = *GET_RURI(_m);
	}

	if (get_match_token(&uri, &match_tok, NULL, NULL) != 0) {
		LM_ERR("failed to get match token\n");
		return -1;
	}

	if (decrypt_str(&match_tok, &dec_tok)) {
		LM_ERR("failed to decrypt matching Contact param (%.*s=%.*s)\n",
		       matching_param.len, matching_param.s,
		       match_tok.len, match_tok.s);
		return -1;
	}

	if (parse_uri(dec_tok.s, dec_tok.len, &dec_uri) < 0) {
		LM_ERR("failed to parse dec URI <%.*s>\n", dec_tok.len, dec_tok.s);
		return -1;
	}

	hostport = dec_uri.host;
	if (dec_uri.port.len > 0)
		hostport.len = dec_uri.port.s + dec_uri.port.len - dec_uri.host.s;

	/* replace the host:port part */
	dec_uri.port.s = NULL;
	dec_uri.host = hostport;

	/* remove the match parameter */
	for (i = 0; i < dec_uri.u_params_no; i++) {
		if (str_strcmp(&dec_uri.u_name[i], &matching_param) == 0) {
			dec_uri.u_name[i].s = NULL;
			break;
		}
	}

	pst.s = ubuf;
	pst.len = MAX_URI_SIZE;
	if (print_uri(&dec_uri, &pst) != 0) {
		LM_ERR("failed to print URI\n");
		return -1;
	}

	pkg_free(dec_tok.s);

	if (!_s) {
		if (set_ruri(_m, &pst) != 0) {
			LM_ERR("failed to set R-URI\n");
			return -1;
		}
	}

	if (routing_mode == ROUTE_BY_CONTACT)
		return 1;

	if (extract_aor(&uri, &aor,&sip_instance,&call_id) < 0) {
		LM_ERR("failed to extract address of record\n");
		return -3;
	}

	get_act_time();

	ul_api.lock_udomain((udomain_t*)_t, &aor);
	res = ul_api.get_urecord((udomain_t*)_t, &aor, &r);
	if (res > 0) {
		LM_DBG("'%.*s' Not found in usrloc\n", aor.len, ZSW(aor.s));
		ul_api.unlock_udomain((udomain_t*)_t, &aor);
		return -1;
	}

	if (flags & REG_LOOKUP_UAFILTER_FLAG) {
		tmp = *(ua+re_len);
		*(ua+re_len) = '\0';
		if (regcomp(&ua_re, ua, regexp_flags) != 0) {
			LM_ERR("bad regexp '%s'\n", ua);
			*(ua+re_len) = tmp;
			return -1;
		}
		*(ua+re_len) = tmp;
	}


	ptr = r->contacts;
	ret = -1;
	/* look first for an un-expired and suported contact */
search_valid_contact:
	while ( (ptr) &&
	!(VALID_CONTACT(ptr,act_time) && (ret=-2) && allowed_method(_m,ptr,flags)))
		ptr = ptr->next;
	if (ptr==0) {
		/* nothing found */
		LM_DBG("nothing found !\n");
		goto done;
	}

	ua_re_check(
		ret = -1;
		ptr = ptr->next;
		goto search_valid_contact
	);

	if (sip_instance.len && sip_instance.s) {
		LM_DBG("ruri has gruu in lookup\n");
		/* uri has GRUU */
		if (ptr->instance.len-2 != sip_instance.len ||
				memcmp(ptr->instance.s+1,sip_instance.s,sip_instance.len)) {
			LM_DBG("no match to sip instace - [%.*s] - [%.*s]\n",ptr->instance.len-2,ptr->instance.s+1,
					sip_instance.len,sip_instance.s);
			/* not the targeted instance, search some more */
			ptr = ptr->next;
			goto search_valid_contact;
		}

		LM_DBG("matched sip instace\n");
	}

	if (call_id.len && call_id.s) {
		/* decide whether GRUU is expired or not
		 *
		 * first - match call-id */
		if (ptr->callid.len != call_id.len ||
				memcmp(ptr->callid.s,call_id.s,call_id.len)) {
			LM_DBG("no match to call id - [%.*s] - [%.*s]\n",ptr->callid.len,ptr->callid.s,
					call_id.len,call_id.s);
			ptr = ptr->next;
			goto search_valid_contact;
		}

		/* matched call-id, check if there are newer contacts with
		 * same sip instace bup newer last_modified */

		it = ptr->next;
		while ( it ) {
			if (VALID_CONTACT(it,act_time)) {
				if (it->instance.len-2 == sip_instance.len && sip_instance.s &&
						memcmp(it->instance.s+1,sip_instance.s,sip_instance.len) == 0)
					if (it->last_modified > ptr->last_modified) {
						/* same instance id, but newer modified -> expired GRUU, no match at all */
						break;
					}
			}
			it=it->next;
		}

		if (it != NULL) {
			ret = -1;
			goto done;
		}
	}

	LM_DBG("found a complete match\n");

	ret = 1;
	if (ptr) {
		LM_DBG("setting as ruri <%.*s>\n",ptr->c.len,ptr->c.s);
		if (set_ruri(_m, &ptr->c) < 0) {
			LM_ERR("unable to rewrite Request-URI\n");
			ret = -3;
			goto done;
		}

		/* If a Path is present, use first path-uri in favour of
		 * received-uri because in that case the last hop towards the uac
		 * has to handle NAT. - agranig */
		if (ptr->path.s && ptr->path.len) {
			if (get_path_dst_uri(&ptr->path, &path_dst) < 0) {
				LM_ERR("failed to get dst_uri for Path\n");
				ret = -3;
				goto done;
			}
			if (set_path_vector(_m, &ptr->path) < 0) {
				LM_ERR("failed to set path vector\n");
				ret = -3;
				goto done;
			}
			if (set_dst_uri(_m, &path_dst) < 0) {
				LM_ERR("failed to set dst_uri of Path\n");
				ret = -3;
				goto done;
			}
		} else if (ptr->received.s && ptr->received.len) {
			if (set_dst_uri(_m, &ptr->received) < 0) {
				ret = -3;
				goto done;
			}
		}

		set_ruri_q( _m, ptr->q);

		setbflag( _m, 0, ptr->cflags);

		if (ptr->sock)
			_m->force_send_socket = ptr->sock;

		/* populate the 'attributes' avp */
		if (attr_avp_name != -1) {
			istr.s = ptr->attr;
			if (add_avp_last(AVP_VAL_STR, attr_avp_name, istr) != 0) {
				LM_ERR("Failed to populate attr avp!\n");
			}
		}

		ptr = ptr->next;
	}

	/* Append branches if enabled */
	/* If we got to this point and the URI had a ;gr parameter and it was matched
	 * to a contact. No point in branching */
	if ( flags&REG_LOOKUP_NOBRANCH_FLAG || (sip_instance.len && sip_instance.s) ) goto done;
	LM_DBG("looking for branches\n");

	do {
		for( ; ptr ; ptr = ptr->next ) {
			if (VALID_CONTACT(ptr, act_time) && allowed_method(_m,ptr,flags)) {
				path_dst.len = 0;
				if(ptr->path.s && ptr->path.len
				&& get_path_dst_uri(&ptr->path, &path_dst) < 0) {
					LM_ERR("failed to get dst_uri for Path\n");
					continue;
				}

				ua_re_check(continue);

				/* The same as for the first contact applies for branches
				 * regarding path vs. received. */
				LM_DBG("setting branch <%.*s>\n",ptr->c.len,ptr->c.s);
				if (append_branch(_m,&ptr->c,path_dst.len?&path_dst:&ptr->received,
				&ptr->path, ptr->q, ptr->cflags, ptr->sock) == -1) {
					LM_ERR("failed to append a branch\n");
					/* Also give a chance to the next branches*/
					continue;
				}

				/* populate the 'attributes' avp */
				if (attr_avp_name != -1) {
					istr.s = ptr->attr;
					if (add_avp_last(AVP_VAL_STR, attr_avp_name, istr) != 0) {
						LM_ERR("Failed to populate attr avp!\n");
					}
				}
			}
		}
		/* 0 branches condition also filled; idx initially -1*/
		if (!(flags&REG_BRANCH_AOR_LOOKUP_FLAG) || idx == nbranches)
			goto done;


		/* relsease old aor lock */
		ul_api.unlock_udomain((udomain_t*)_t, &aor);
		ul_api.release_urecord(r, 0);

		/* idx starts from -1 */
		uri = branch_uris[idx];
		if (extract_aor(&uri, &aor, NULL, &call_id) < 0) {
			LM_ERR("failed to extract address of record for branch uri\n");
			return -3;
		}

		/* release old urecord */

		/* get lock on new aor */
		LM_DBG("getting contacts from aor [%.*s]"
					"in branch %d\n", aor.len, aor.s, idx);
		ul_api.lock_udomain((udomain_t*)_t, &aor);
		res = ul_api.get_urecord((udomain_t*)_t, &aor, &r);

		if (res > 0) {
			LM_DBG("'%.*s' Not found in usrloc\n", aor.len, ZSW(aor.s));
			goto done;
		}
		idx++;
		ptr = r->contacts;
	} while (1);

done:
	ul_api.release_urecord(r, 0);
	ul_api.unlock_udomain((udomain_t*)_t, &aor);
	if (flags & REG_LOOKUP_UAFILTER_FLAG) {
		regfree(&ua_re);
	}
	return ret;
}
