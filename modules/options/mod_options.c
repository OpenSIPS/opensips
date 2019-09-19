/*
 * Options Reply Module
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * -------
 * 2003-11-11: build_lump_rpl() removed, add_lump_rpl() has flags (bogdan)
 */

#ifdef EXTRA_DEBUG
#include <stdlib.h>   /* required by abort() */
#endif
#include "../../sr_module.h"
#include "mod_options.h"
#include "../../str.h"
#include "../../ut.h"
#include "../../mem/mem.h"
#include "../../data_lump_rpl.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_uri.h"
#include "../signaling/signaling.h"



static str options_reply_hdrs;
static str acpt_s = str_init(ACPT_DEF);
static str acpt_enc_s = str_init(ACPT_ENC_DEF);
static str acpt_lan_s = str_init(ACPT_LAN_DEF);
static str supt_s = str_init(SUPT_DEF);

/** SIGNALING binds */
struct sig_binds sigb;

static str opt_200_rpl = str_init("OK");
static str opt_500_rpl = str_init("Server internal error");

static int mod_init(void);

static int opt_reply(struct sip_msg* _msg);
/*
 * Exported functions
 */

static cmd_export_t cmds[] = {
	{"options_reply", (cmd_function)opt_reply, {{0,0,0}},
		REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"accept",     STR_PARAM, &acpt_s.s},
	{"accept_encoding", STR_PARAM, &acpt_enc_s.s},
	{"accept_language", STR_PARAM, &acpt_lan_s.s},
	{"support",     STR_PARAM, &supt_s.s},
	{0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "signaling", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/*
 * Module description
 */
struct module_exports exports = {
	"options",       /* Module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,            /* Exported functions */
	NULL,            /* Exported async functions */
	params,          /* Exported parameters */
	0,               /* exported statistics */
	0,               /* exported MI functions */
	0,               /* exported pseudo-variables */
	0,			 	 /* exported transformations */
	0,               /* extra processes */
	0,               /* Pre-initialization function */
	mod_init,        /* Initialization function */
	0,               /* Response function */
	0,               /* Destroy function */
	0,               /* Child init function */
	0                /* reload confirm function */
};

/*
 * initialize module
 */
static int mod_init(void) {

	int len, offset;

	LM_INFO("initializing...\n");

	/* load SIGNALING API */
	if(load_sig_api(&sigb)< 0) {
		LM_ERR("can't load signaling functions\n");
		return -1;
	}

	acpt_s.len = strlen(acpt_s.s);
	acpt_enc_s.len = strlen(acpt_enc_s.s);
	acpt_lan_s.len = strlen(acpt_lan_s.s);
	supt_s.len = strlen(supt_s.s);

	len = (acpt_s.len>0 ? ACPT_STR_LEN+acpt_s.len+HF_SEP_STR_LEN : 0)+
		(acpt_enc_s.len>0 ? ACPT_ENC_STR_LEN+acpt_enc_s.len+HF_SEP_STR_LEN : 0)+
		(acpt_lan_s.len>0 ? ACPT_LAN_STR_LEN+acpt_lan_s.len+HF_SEP_STR_LEN : 0)+
		(supt_s.len>0 ? SUPT_STR_LEN+supt_s.len+HF_SEP_STR_LEN : 0);

	options_reply_hdrs.s = pkg_malloc(len);
	if (!options_reply_hdrs.s) {
		LM_ERR("No more pkg memory\n");
		return -1;
	}

	offset = 0;

	/* create the header fields */
	if (acpt_s.len > 0) {
		memcpy(options_reply_hdrs.s, ACPT_STR, ACPT_STR_LEN);
		offset = ACPT_STR_LEN;
		memcpy(options_reply_hdrs.s + offset, acpt_s.s, acpt_s.len);
		offset += acpt_s.len;
		memcpy(options_reply_hdrs.s + offset, HF_SEP_STR, HF_SEP_STR_LEN);
		offset += HF_SEP_STR_LEN;
	}
	if (acpt_enc_s.len > 0) {
		memcpy(options_reply_hdrs.s + offset, ACPT_ENC_STR, ACPT_ENC_STR_LEN);
		offset += ACPT_ENC_STR_LEN;
		memcpy(options_reply_hdrs.s + offset, acpt_enc_s.s, acpt_enc_s.len);
		offset += acpt_enc_s.len;
		memcpy(options_reply_hdrs.s + offset, HF_SEP_STR, HF_SEP_STR_LEN);
		offset += HF_SEP_STR_LEN;
	}
	if (acpt_lan_s.len > 0) {
		memcpy(options_reply_hdrs.s + offset, ACPT_LAN_STR, ACPT_LAN_STR_LEN);
		offset += ACPT_LAN_STR_LEN;
		memcpy(options_reply_hdrs.s + offset, acpt_lan_s.s, acpt_lan_s.len);
		offset += acpt_lan_s.len;
		memcpy(options_reply_hdrs.s + offset, HF_SEP_STR, HF_SEP_STR_LEN);
		offset += HF_SEP_STR_LEN;
	}
	if (supt_s.len > 0) {
		memcpy(options_reply_hdrs.s + offset, SUPT_STR, SUPT_STR_LEN);
		offset += SUPT_STR_LEN;
		memcpy(options_reply_hdrs.s + offset, supt_s.s, supt_s.len);
		offset += supt_s.len;
		memcpy(options_reply_hdrs.s + offset, HF_SEP_STR, HF_SEP_STR_LEN);
		offset += HF_SEP_STR_LEN;
	}

#ifdef EXTRA_DEBUG
	if (offset != len) {
		LM_CRIT("headerlength (%i) != offset (%i)\n", len, offset);
		abort();
	}
#endif

	options_reply_hdrs.len = len;

	return 0;
}


static int opt_reply(struct sip_msg* _msg) {

	/* check if it is called for an OPTIONS request */
	if (_msg->REQ_METHOD!=METHOD_OPTIONS) {
		LM_ERR("called for non-OPTIONS request\n");
		return -1;
	}
	if(_msg->parsed_uri_ok==0 && parse_sip_msg_uri(_msg)<0)
	{
		LM_ERR("ERROR while parsing the R-URI\n");
		return -1;
	}
	/* FIXME: should we additionally check if ruri == server addresses ?! */
	if (_msg->parsed_uri.user.len != 0) {
		LM_ERR("ruri contains username\n");
		return -1;
	}

	if (!options_reply_hdrs.s || options_reply_hdrs.len < 0) {
		LM_CRIT("headers not yet initialized\n");
		goto error;
	}

	if (add_lump_rpl( _msg, options_reply_hdrs.s, options_reply_hdrs.len,
			LUMP_RPL_HDR|LUMP_RPL_NODUP|LUMP_RPL_NOFREE)!=0) {
		if (sigb.reply(_msg, 200, &opt_200_rpl, NULL) == -1) {
			LM_ERR("failed to send 200 via send_reply\n");
			return -1;
		}
		else
			return 0;
	}
	LM_ERR("add_lump_rpl failed\n");

error:
	if (sigb.reply(_msg, 500, &opt_500_rpl, NULL) == -1) {
		LM_ERR("failed to send 500 via send_reply\n");
		return -1;
	}
	else
		return 0;
}

