/*
 * Registrar module interface
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2020 OpenSIPS Solutions
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
 *  2003-03-11  updated to the new module exports interface (andrei)
 *  2003-03-16  flags export parameter added (janakj)
 *  2003-03-21  save_noreply added, provided by Maxim Sobolev
 *              <sobomax@portaone.com> (janakj)
 *  2005-07-11  added sip_natping_flag for nat pinging with SIP method
 *              instead of UDP package (bogdan)
 *  2006-09-19  AOR may be provided via an AVP instead of being fetched
 *              from URI (bogdan)
 *  2006-10-04  removed the "desc_time_order" parameter, as its functionality
 *              was moved to usrloc (Carsten Bock, BASIS AudioNet GmbH)
 *  2006-11-22  save_noreply and save_memory merged into save();
 *              removed the module parameter "use_domain" - now it is
 *              imported from usrloc module (bogdan)
 *  2006-11-28  Added statistics tracking for the number of accepted/rejected
 *              registrations, as well as for the max expiry time, max
 *              contacts and default expiry time(Jeffrey Magder-SOMA Networks)
 *  2007-02-24  sip_natping_flag moved into branch flags, so migrated to
 *              nathelper module (bogdan)
 *
 */

/*!
 * \defgroup registrar SIP Registrar support
 * The module contains REGISTER processing logic.
 */

/*!
 * \file
 * \brief SIP registrar module - interface
 * \ingroup registrar
 */

#include <stdio.h>

#include "../../sr_module.h"
#include "../../timer.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../socket_info.h"
#include "../../pvar.h"
#include "../../mod_fix.h"
#include "../../lib/reg/config.h"
#include "../../lib/reg/pn.h"
#include "../../lib/reg/common.h"

#include "../usrloc/ul_mod.h"
#include "../signaling/signaling.h"

#include "save.h"
#include "lookup.h"
#include "reply.h"
#include "reg_mod.h"

/*! \brief Module init & destroy function */
static int  mod_init(void);
static int  child_init(int);
static void mod_destroy(void);
static int cfg_validate(void);

/*! \brief Fixup functions */
static int domain_fixup(void** param);

/*! \brief Functions */
static int add_sock_hdr(struct sip_msg* msg, str *str);

int default_expires = 3600; 			/*!< Default expires value in seconds */
qvalue_t default_q  = Q_UNSPECIFIED;	/*!< Default q value multiplied by 1000 */
int case_sensitive  = 1;			/*!< If set to 0, username in aor will be case insensitive */
int tcp_persistent_flag = -1;			/*!< if the TCP connection should be kept open */
char *tcp_persistent_flag_s = 0;
int min_expires     = 60;			/*!< Minimum expires the phones are allowed to use in seconds
 						 * use 0 to switch expires checking off */
int max_expires     = 0;			/*!< Maximum expires the phones are allowed to use in seconds,
 						 * use 0 to switch expires checking off */
int retry_after = 0;				/*!< The value of Retry-After HF in 5xx replies */

extern ucontact_t **selected_cts;
extern int selected_cts_sz;

char* rcv_avp_param = 0;
unsigned short rcv_avp_type = 0;
int rcv_avp_name;

char* mct_avp_param = 0;
unsigned short mct_avp_type = 0;
int mct_avp_name;

char* attr_avp_param = 0;
unsigned short attr_avp_type = 0;
int attr_avp_name;

usrloc_api_t ul;

int reg_use_domain = 0;
/*!< Realm prefix to be removed */
str realm_prefix = str_init("");

str sock_hdr_name = {0,0};
str gruu_secret = {0,0};
int disable_gruu = 1;

#define RCV_NAME "received"
str rcv_param = str_init(RCV_NAME);

stat_var *accepted_registrations;
stat_var *rejected_registrations;
stat_var *max_expires_stat;
stat_var *max_contacts_stat;
stat_var *default_expire_stat;

/** SIGNALING binds */
struct sig_binds sigb;
/** TM bind */
struct tm_binds tmb;


static cmd_export_t cmds[] = {
	{"save", (cmd_function)save, {
		{CMD_PARAM_STR|CMD_PARAM_STATIC, domain_fixup, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE},
	{"remove", (cmd_function)_remove, {
		{CMD_PARAM_STR|CMD_PARAM_STATIC, domain_fixup, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE},
	{"lookup", (cmd_function)reg_lookup, {
		{CMD_PARAM_STR|CMD_PARAM_STATIC, domain_fixup, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE},
	{"add_sock_hdr", (cmd_function)add_sock_hdr, {
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"is_registered", (cmd_function)is_registered, {
		{CMD_PARAM_STR|CMD_PARAM_STATIC, domain_fixup, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"is_contact_registered", (cmd_function)is_contact_registered, {
		{CMD_PARAM_STR|CMD_PARAM_STATIC, domain_fixup, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"is_ip_registered", (cmd_function)is_ip_registered, {
		{CMD_PARAM_STR|CMD_PARAM_STATIC, domain_fixup, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR,0,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{0,0,{{0,0,0}},0}
};

static acmd_export_t acmds[] = {
	pn_async_cmds,
	{0,0,{{0,0,0}}}
};

/*! \brief
 * Exported parameters
 */
static param_export_t params[] = {
	{"default_expires",    INT_PARAM, &default_expires       },
	{"default_q",          INT_PARAM, &default_q             },
	{"case_sensitive",     INT_PARAM, &case_sensitive        },
	{"tcp_persistent_flag",STR_PARAM, &tcp_persistent_flag_s },
	{"realm_prefix",       STR_PARAM, &realm_prefix.s         },
	{"min_expires",        INT_PARAM, &min_expires           },
	{"max_expires",        INT_PARAM, &max_expires           },
	{"received_param",     STR_PARAM, &rcv_param.s           },
	{"received_avp",       STR_PARAM, &rcv_avp_param         },
	{"retry_after",        INT_PARAM, &retry_after           },
	{"sock_hdr_name",      STR_PARAM, &sock_hdr_name.s       },
	{"mcontact_avp",       STR_PARAM, &mct_avp_param         },
	{"attr_avp",           STR_PARAM, &attr_avp_param        },
	{"gruu_secret",        STR_PARAM, &gruu_secret.s         },
	{"disable_gruu",       INT_PARAM, &disable_gruu          },

	/* common registrar modparams */
	reg_modparams,

	/* common SIP Push Notification (RFC 8599) modparams */
	pn_modparams,

	{0, 0, 0}
};


/*! \brief We expose internal variables via the statistic framework below.*/
static stat_export_t mod_stats[] = {
	{"max_expires",       STAT_NO_RESET, &max_expires_stat        },
	{"max_contacts",      STAT_NO_RESET, &max_contacts_stat       },
	{"default_expire",    STAT_NO_RESET, &default_expire_stat     },
	{"accepted_regs",                 0, &accepted_registrations  },
	{"rejected_regs",                 0, &rejected_registrations  },
	{0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "usrloc",    DEP_ABORT  },
		{ MOD_TYPE_DEFAULT, "signaling", DEP_ABORT  },
		{ MOD_TYPE_DEFAULT, "tm",        DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		pn_modparam_deps,
		{ NULL, NULL },
	},
};

/*! \brief
 * Module exports structure
 */
struct module_exports exports = {
	"registrar",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	NULL,        /* load function */
	&deps,       /* OpenSIPS module dependencies */
	cmds,        /* Exported functions */
	acmds,       /* Exported async functions */
	params,      /* Exported parameters */
	mod_stats,   /* exported statistics */
	0,           /* exported MI functions */
	0,           /* exported pseudo-variables */
	0,           /* exported transformations */
	0,           /* extra processes */
	0,           /* module pre-initialization function */
	mod_init,    /* module initialization function */
	0,
	mod_destroy, /* destroy function */
	child_init,  /* Per-child init function */
	cfg_validate /* reload confirm function */
};


/*! \brief
 * Initialize parent
 */
static int mod_init(void)
{
	pv_spec_t avp_spec;
	str s;

	LM_INFO("initializing...\n");

	/* load SIGNALING API */
	if(load_sig_api(&sigb)< 0) {
		LM_ERR("can't load signaling functions\n");
		return -1;
	}

	/* load TM API */
	memset(&tmb, 0, sizeof(struct tm_binds));
	load_tm_api(&tmb);

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

	if (mct_avp_param && *mct_avp_param) {
		s.s = mct_avp_param; s.len = strlen(s.s);
		if (pv_parse_spec(&s, &avp_spec)==0
				|| avp_spec.type!=PVT_AVP) {
			LM_ERR("malformed or non AVP %s AVP definition\n", mct_avp_param);
			return -1;
		}

		if(pv_get_avp_name(0, &avp_spec.pvp, &mct_avp_name, &mct_avp_type)!=0)
		{
			LM_ERR("[%s]- invalid AVP definition\n", mct_avp_param);
			return -1;
		}
	} else {
		mct_avp_name = -1;
		mct_avp_type = 0;
	}

	if (attr_avp_param && *attr_avp_param) {
		s.s = attr_avp_param; s.len = strlen(s.s);
		if (pv_parse_spec(&s, &avp_spec)==0
				|| avp_spec.type!=PVT_AVP) {
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

	if (load_ul_api(&ul) != 0) {
		LM_ERR("failed to bind usrloc\n");
		return -1;
	}

	if (is_script_func_used("save", 4) && !ul.tags_in_use()) {
		LM_ERR("as per your current usrloc module configuration, "
				"save() ownership tags will be completely ignored!\n");
		LM_ERR("Hint: switch the usrloc 'pinging_mode' to 'ownership'\n");
		return -1;
	}

	if (reg_init_globals() != 0) {
		LM_ERR("failed to init globals\n");
		return -1;
	}

	if (sock_hdr_name.s)
		sock_hdr_name.len = strlen(sock_hdr_name.s);

	if (pn_init() < 0) {
		LM_ERR("failed to init SIP Push Notification support\n");
		return -1;
	}

	return 0;
}


static int cfg_validate(void)
{
	if (is_script_func_used("save", 4) && !ul.tags_in_use()) {
		LM_ERR("save() with sharing tag was found, but the module's "
			"configuration has no tag support, better restart\n");
		return 0;
	}

	if (!pn_cfg_validate()) {
		LM_ERR("failed to validate opensips.cfg PN configuration\n");
		return 0;
	}

	return 1;
}


static int child_init(int rank)
{
	if (rank==1) {
		/* init stats */
		update_stat( max_expires_stat, max_expires );
		update_stat( max_contacts_stat, max_contacts );
		update_stat( default_expire_stat, default_expires );
	}

	return 0;
}


/*! \brief
 * Convert char* parameter to udomain_t* pointer
 */
static int domain_fixup(void** param)
{
	udomain_t* d;
	str d_nt;

	if (pkg_nt_str_dup(&d_nt, (str*)*param) < 0)
		return E_OUT_OF_MEM;

	if (ul.register_udomain(d_nt.s, &d) < 0) {
		LM_ERR("failed to register domain\n");
		return E_UNSPEC;
	}

	pkg_free(d_nt.s);

	*param = (void*)d;
	return 0;
}


static void mod_destroy(void)
{
	free_contact_buf();
}


#include "../../data_lump.h"
#include "../../ip_addr.h"
#include "../../ut.h"

static int add_sock_hdr(struct sip_msg* msg, str *hdr_name)
{
	struct socket_info* si;
	struct lump* anchor;
	str hdr;
	char *p;
	str use_sock_str;

	si = msg->rcv.bind_address;

	if(si->adv_sock_str.len) {
		use_sock_str = si->adv_sock_str;
	} else {
		use_sock_str = si->sock_str;
	}

	if (parse_headers( msg, HDR_EOH_F, 0) == -1) {
		LM_ERR("failed to parse message\n");
		goto error;
	}

	anchor = anchor_lump( msg, msg->unparsed-msg->buf, 0);
	if (anchor==0) {
		LM_ERR("can't get anchor\n");
		goto error;
	}

	hdr.len = hdr_name->len + 2 + use_sock_str.len + CRLF_LEN;
	if ( (hdr.s=(char*)pkg_malloc(hdr.len))==0 ) {
		LM_ERR("no more pkg mem\n");
		goto error;
	}

	p = hdr.s;
	memcpy( p, hdr_name->s, hdr_name->len);
	p += hdr_name->len;
	*(p++) = ':';
	*(p++) = ' ';

	memcpy( p, use_sock_str.s, use_sock_str.len);
	p += use_sock_str.len;

	memcpy( p, CRLF, CRLF_LEN);
	p += CRLF_LEN;

	if ( p-hdr.s!=hdr.len ) {
		LM_CRIT("buffer overflow (%d!=%d)\n", (int)(long)(p-hdr.s),hdr.len);
		goto error1;
	}

	if (insert_new_lump_before( anchor, hdr.s, hdr.len, 0) == 0) {
		LM_ERR("can't insert lump\n");
		goto error1;
	}

	return 1;
error1:
	pkg_free(hdr.s);
error:
	return -1;
}
