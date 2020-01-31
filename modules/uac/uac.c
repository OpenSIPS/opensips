/*
 * Copyright (C) 2005-2009 Voice Sistem SRL
*
 * This file is part of opensips, a free SIP server.
 *
 * UAC OpenSIPS-module is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * UAC OpenSIPS-module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * History:
 * ---------
 *  2005-01-31  first version (ramona)
 *  2005-08-12  some TM callbacks replaced with RR callback - more efficient;
 *              (bogdan)
 *  2006-03-02  UAC authentication looks first in AVPs for credential (bogdan)
 *  2006-03-03  the RR parameter is encrypted via XOR with a password
 *              (bogdan)
 *  2009-08-22  TO header replacement added (bogdan)

 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../pvar.h"
#include "../../mem/mem.h"
#include "../../parser/parse_from.h"
#include "../tm/tm_load.h"
#include "../tm/t_hooks.h"
#include "../rr/api.h"
#include "../uac_auth/uac_auth.h"
#include "../dialog/dlg_load.h"

#include "replace.h"
#include "auth.h"





/* local variable used for init */
static char* restore_mode_str = NULL;

/* global param variables */
str rr_from_param = str_init("vsf");
str rr_from_param_new = str_init("739823");
str store_from_bavp = str_init("$bavp(739825)");
str rr_to_param = str_init("vst");
str rr_uac_cseq_param = str_init("aci");
str rr_to_param_new = str_init("739824");
str store_to_bavp = str_init("$bavp(739826)");
pv_spec_t from_bavp_spec;
pv_spec_t to_bavp_spec;

str uac_passwd = str_init("");
int restore_mode = UAC_AUTO_RESTORE;
struct tm_binds uac_tmb;
struct rr_binds uac_rrb;
uac_auth_api_t uac_auth_api;
int force_dialog = 0;
struct dlg_binds dlg_api;

static int w_replace_from(struct sip_msg* msg, str* p1, str* p2);
static int w_restore_from(struct sip_msg* msg);

static int w_replace_to(struct sip_msg* msg, str* p1, str* p2);
static int w_restore_to(struct sip_msg* msg);

static int w_uac_auth(struct sip_msg* msg);
static int fixup_replace_disp_uri(void** param);
static int fixup_free_s(void** param);
static int mod_init(void);
static void mod_destroy(void);
static int cfg_validate(void);

static int uac_does_replace = 0;

/* Exported functions */
static cmd_export_t cmds[]={
	{"uac_replace_from",  (cmd_function)w_replace_from, {
		{CMD_PARAM_STR|CMD_PARAM_OPT, fixup_replace_disp_uri, fixup_free_s},
		{CMD_PARAM_STR, 0, 0},
	       	{0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"uac_restore_from",  (cmd_function)w_restore_from, {{0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"uac_replace_to",  (cmd_function)w_replace_to, {
		{CMD_PARAM_STR|CMD_PARAM_OPT, fixup_replace_disp_uri, fixup_free_s},
		{CMD_PARAM_STR, 0, 0},
	       	{0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"uac_restore_to",  (cmd_function)w_restore_to, {{0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"uac_auth",        (cmd_function)w_uac_auth, {{0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{0,0,{{0,0,0}},0}
};


/* Exported parameters */
static param_export_t params[] = {
	{"rr_from_store_param", STR_PARAM,                &rr_from_param.s       },
	{"rr_to_store_param",   STR_PARAM,                &rr_to_param.s         },
	{"restore_mode",        STR_PARAM,                &restore_mode_str      },
	{"restore_passwd",      STR_PARAM,                &uac_passwd.s          },
	{"force_dialog",        INT_PARAM,                &force_dialog          },
	{0, 0, 0}
};

static module_dependency_t *get_deps_restore_mode(param_export_t *param)
{
	char *mode = *(char **)param->param_pointer;

	if (!mode || strlen(mode) == 0)
		return NULL;

	if (strcmp(mode, "none") != 0)
		return alloc_module_dep(MOD_TYPE_DEFAULT, "rr", DEP_ABORT);

	return NULL;
}

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm",       DEP_ABORT  },
		{ MOD_TYPE_DEFAULT, "dialog",   DEP_SILENT },
		{ MOD_TYPE_DEFAULT, "uac_auth", DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "restore_mode", get_deps_restore_mode },
		{ NULL, NULL },
	},
};

struct module_exports exports= {
	"uac",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* param exports */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	(response_function) 0,
	mod_destroy,
	0,          /* per-child init function */
	cfg_validate/* reload confirm function */
};



inline static int parse_store_bavp(str *s, pv_spec_t *bavp)
{
	s->len = strlen(s->s);
	if (pv_parse_spec(s, bavp)==NULL) {
		LM_ERR("malformed bavp definition %s\n", s->s);
		return -1;
	}
	 /* check if there is a bavp type */
	if (bavp->type != (pv_type_t)(903 + PVT_EXTRA)) {
		LM_ERR("store parameter must be an bavp\n");
		return -1;
	}
	return 0;

}


static int mod_init(void)
{
	LM_INFO("initializing...\n");
	int rr_api_loaded=0;
	int dlg_api_loaded=0;

	if ( is_script_func_used("uac_auth", -1) ) {
		/* load the UAC_AUTH API as uac_auth() is invoked from script */
		if(load_uac_auth_api(&uac_auth_api)<0){
			LM_ERR("can't load UAC_AUTH API, needed for uac_auth()\n");
			goto error;
		}
	}

	/* load the TM API - FIXME it should be loaded only
	 * if NO_RESTORE and AUTH */
	if (load_tm_api(&uac_tmb)!=0) {
		LM_ERR("can't load TM API\n");
		goto error;
	}

	if (restore_mode_str && *restore_mode_str) {
		if (strcasecmp(restore_mode_str,"none")==0) {
			restore_mode = UAC_NO_RESTORE;
		} else if (strcasecmp(restore_mode_str,"manual")==0) {
			restore_mode = UAC_MANUAL_RESTORE;
		} else if (strcasecmp(restore_mode_str,"auto")==0) {
			restore_mode = UAC_AUTO_RESTORE;
		} else {
			LM_ERR("unsupported value '%s' for restore_mode\n",
				restore_mode_str);
			goto error;
		}
	}

	if ( is_script_func_used("uac_replace_from", -1) ||
	is_script_func_used("uac_replace_to", -1) ) {

		/* replace TO/FROM stuff is used, get prepared */

		rr_from_param.len = strlen(rr_from_param.s);
		rr_to_param.len = strlen(rr_to_param.s);
		if ( (rr_from_param.len==0 || rr_to_param.len==0) &&
		restore_mode!=UAC_NO_RESTORE) {
			LM_ERR("rr_store_param cannot be empty if FROM is restoreable\n");
			goto error;
		}

		uac_passwd.len = strlen(uac_passwd.s);

		if (restore_mode!=UAC_NO_RESTORE) {
			/* load the RR API */
			if (load_rr_api(&uac_rrb)!=0) {
				LM_ERR("can't load RR API\n");
				goto error;
			}
			rr_api_loaded=1;

			if (restore_mode==UAC_AUTO_RESTORE) {
				/* we need the append_fromtag on in RR */
				if (!force_dialog && !uac_rrb.append_fromtag) {
					LM_ERR("'append_fromtag' RR param is not enabled!"
						" - required by AUTO restore mode\n");
					goto error;
				}

				/* trying to load dialog module */
				memset(&dlg_api, 0, sizeof(struct dlg_binds));
				if (load_dlg_api(&dlg_api)!=0) {
					if (force_dialog) {
						LM_ERR("cannot force dialog. dialog module not loaded\n");
						goto error;
					}
					LM_DBG("failed to find dialog API - is dialog module loaded?\n");
				} else {
					dlg_api_loaded=1;

					if ( (parse_store_bavp(&store_to_bavp, &to_bavp_spec) ||
					parse_store_bavp(&store_from_bavp, &from_bavp_spec))) {
						LM_ERR("cannot set correct store parameters\n");
						goto error;
					}
					/* install calback to catch all loaded dialogs */
					if ( dlg_api.register_dlgcb( NULL, DLGCB_LOADED,
					dlg_restore_callback, NULL, NULL) != 0 ) {
						LM_ERR("failed to install dialog restore callback\n");
						goto error;
					}
				}

				/* get all requests doing loose route */
				if (uac_rrb.register_rrcb( rr_checker, 0, 2)!=0) {
					LM_ERR("failed to install RR callback\n");
					goto error;
				}
			}
		}

		/* init from replacer */
		init_from_replacer();
		uac_does_replace = 1;
	}

	if (is_script_func_used("uac_auth", -1)) {
		if (!rr_api_loaded) {
			if (load_rr_api(&uac_rrb)!=0) {
				LM_ERR("can't load RR API\n");
				goto error;
			}
		}
		if (!dlg_api_loaded) {
			if (load_dlg_api(&dlg_api)!=0) {
				LM_ERR("Can't load dlg API \n");
			}	
		}

		if (!uac_rrb.append_fromtag) {
			LM_ERR("'append_fromtag' RR param is not enabled!"
			" - required by uac_auth() restore mode\n");
			goto error;
		}

		if (uac_rrb.register_rrcb( rr_uac_auth_checker, 0, 2)!=0) {
			LM_ERR("failed to install RR callback\n");
			goto error;
		}
	}

	return 0;
error:
	return -1;
}


static void mod_destroy(void)
{
	return;
}


static int cfg_validate(void)
{
	/* if the 'uac_auth' func is used, be sure the uac_auth API was loaded */
	if ( is_script_func_used("uac_auth", -1) ) {
		if (uac_auth_api._do_uac_auth==NULL) {
			LM_ERR("uac_auth() was found, but module started without support "
				"for it, better restart\n");
			return 0;
		}
	}

	/* if the 'uac_replace_*' funcs are used, be sure the support for
	 * replacing was initialized */
	if ( is_script_func_used("uac_replace_from", -1) ||
	is_script_func_used("uac_replace_to", -1) ) {
		if (!uac_does_replace) {
			LM_ERR("uac_replace_*() was found, but module started without "
				"support for replacing, better restart\n");
			return 0;
		}
	}

	return 1;
}


/************************** fixup functions ******************************/

static int fixup_replace_disp_uri(void** param)
{
	char *p;
	str *s = (str*)*param;
	str repl;

	/* check to see if it is already quoted */
	if ((s->len >= 2 && s->s[0] == '\"' && s->s[s->len - 1] == '\"') ||
			str_check_token(s)) {
		if (pkg_nt_str_dup(&repl, s) < 0)
			return E_OUT_OF_MEM;
		*s = repl;
		return 0;
	}

	/* put " around display name */
	p = (char*)pkg_malloc(s->len+3);
	if (p==0) {
		LM_CRIT("no more pkg mem\n");
		return E_OUT_OF_MEM;
	}
	p[0] = '\"';
	memcpy(p+1, s->s, s->len);
	p[s->len+1] = '\"';
	p[s->len+2] = '\0';
	s->s = p;
	s->len += 2;

	return 0;
}

static int fixup_free_s(void** param)
{
	pkg_free( ((str*)(*param))->s );
	return 0;
}


/************************** wrapper functions ******************************/

static int w_restore_from(struct sip_msg *msg)
{
	/* safety checks - must be a request */
	if (msg->first_line.type!=SIP_REQUEST) {
		LM_ERR("called for something not request\n");
		return -1;
	}

	return (restore_uri(msg,0,1)==0)?1:-1;
}


static int w_replace_from(struct sip_msg* msg, str* dsp, str* uri)
{
	if (parse_from_header(msg)<0 ) {
		LM_ERR("failed to find/parse FROM hdr\n");
		return -1;
	}

	LM_DBG("dsp=%p (len=%d) , uri=%p (len=%d)\n",
		dsp,dsp?dsp->len:0,uri,uri?uri->len:0);

	return (replace_uri(msg, dsp, uri, msg->from, 0)==0)?1:-1;
}


static int w_restore_to(struct sip_msg *msg)
{
	/* safety checks - must be a request */
	if (msg->first_line.type!=SIP_REQUEST) {
		LM_ERR("called for something not request\n");
		return -1;
	}

	return (restore_uri(msg,1,0)==0)?1:-1;
}


static int w_replace_to(struct sip_msg* msg, str *dsp, str *uri)
{
	/* parse TO hdr */
	if ( msg->to==0 && (parse_headers(msg,HDR_TO_F,0)!=0 || msg->to==0) ) {
		LM_ERR("failed to parse TO hdr\n");
		return -1;
	}

	return (replace_uri(msg, dsp, uri, msg->to, 1)==0)?1:-1;
}




static int w_uac_auth(struct sip_msg* msg)
{
	return (uac_auth(msg)==0)?1:-1;
}


