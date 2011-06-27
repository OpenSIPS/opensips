/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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





/* local variable used for init */
static char* restore_mode_str = NULL;
static char* auth_username_avp = NULL;
static char* auth_realm_avp = NULL;
static char* auth_password_avp = NULL;

/* global param variables */
str rr_from_param = str_init("vsf");
str store_from_bavp = str_init("$bavp(739825)");
str rr_to_param = str_init("vst");
str store_to_bavp = str_init("$bavp(739826)");
pv_spec_t from_bavp_spec;
pv_spec_t to_bavp_spec;

str uac_passwd = str_init("");
int restore_mode = UAC_AUTO_RESTORE;
struct tm_binds uac_tmb;
struct rr_binds uac_rrb;
uac_auth_api_t uac_auth_api;
pv_spec_t auth_username_spec;
pv_spec_t auth_realm_spec;
pv_spec_t auth_password_spec;
int force_dialog = 0;
struct dlg_binds dlg_api;

static int w_replace_from(struct sip_msg* msg, char* p1, char* p2);
static int w_restore_from(struct sip_msg* msg);

static int w_replace_to(struct sip_msg* msg, char* p1, char* p2);
static int w_restore_to(struct sip_msg* msg);

static int w_uac_auth(struct sip_msg* msg, char* str, char* str2);
static int fixup_replace_uri(void** param, int param_no);
static int fixup_replace_disp_uri(void** param, int param_no);
static int mod_init(void);
static void mod_destroy(void);


/* Exported functions */
static cmd_export_t cmds[]={
	{"uac_replace_from",  (cmd_function)w_replace_from,  2,
			fixup_replace_disp_uri, 0,
			REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE },
	{"uac_replace_from",  (cmd_function)w_replace_from,  1,
			fixup_replace_uri, 0,
			REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE },
	{"uac_restore_from",  (cmd_function)w_restore_from,   0,
			0, 0,
			REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE },
	{"uac_replace_to",  (cmd_function)w_replace_to,  2,
			fixup_replace_disp_uri, 0,
			REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE },
	{"uac_replace_to",  (cmd_function)w_replace_to,  1,
			fixup_replace_uri, 0,
			REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE },
	{"uac_restore_to",  (cmd_function)w_restore_to,   0,
			0, 0,
			REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE },
	{"uac_auth",          (cmd_function)w_uac_auth,       0,
			0, 0,
			FAILURE_ROUTE },
	{0,0,0,0,0,0}
};



/* Exported parameters */
static param_export_t params[] = {
	{"rr_from_store_param", STR_PARAM,                &rr_from_param.s       },
	{"rr_to_store_param",   STR_PARAM,                &rr_to_param.s         },
	{"restore_mode",        STR_PARAM,                &restore_mode_str      },
	{"restore_passwd",      STR_PARAM,                &uac_passwd.s          },
	{"auth_username_avp",   STR_PARAM,                &auth_username_avp     },
	{"auth_realm_avp",      STR_PARAM,                &auth_realm_avp        },
	{"auth_password_avp",   STR_PARAM,                &auth_password_avp     },
	{"force_dialog",        INT_PARAM,                &force_dialog          },
	{0, 0, 0}
};



struct module_exports exports= {
	"uac",
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,       /* exported functions */
	params,     /* param exports */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* extra processes */
	mod_init,   /* module initialization function */
	(response_function) 0,
	mod_destroy,
	0  /* per-child init function */
};


inline static int parse_auth_avp( char *avp_spec, pv_spec_t *avp, char *txt)
{
	str s;
	s.s = avp_spec; s.len = strlen(s.s);
	if (pv_parse_spec(&s, avp)==NULL) {
		LM_ERR("malformed or non AVP %s AVP definition\n",txt);
		return -1;
	}
	return 0;
}


inline static int parse_store_bavp(str *s, pv_spec_t *bavp)
{
	s->len = strlen(s->s);
	if (pv_parse_spec(s, bavp)==NULL) {
		LM_ERR("malformed bavp definition %s\n", s->s);
		return -1;
	}
	 /* check if there is a bavp type */
	if (bavp->type != 903 + PVT_EXTRA) {
		LM_ERR("store parameter must be an bavp\n");
		return -1;
	}
	return 0;
	
}


static int mod_init(void)
{
	LM_INFO("initializing...\n");

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

	rr_from_param.len = strlen(rr_from_param.s);
	rr_to_param.len = strlen(rr_to_param.s);
	if ( (rr_from_param.len==0 || rr_to_param.len==0) &&
	restore_mode!=UAC_NO_RESTORE)
	{
		LM_ERR("rr_store_param cannot be empty if FROM is restoreable\n");
		goto error;
	}

	uac_passwd.len = strlen(uac_passwd.s);

	/* parse the auth AVP spesc, if any */
	if ( auth_username_avp || auth_password_avp || auth_realm_avp) {
		if (!auth_username_avp || !auth_password_avp || !auth_realm_avp) {
			LM_ERR("partial definition of auth AVP!");
			goto error;
		}
		if ( parse_auth_avp(auth_realm_avp, &auth_realm_spec, "realm")<0
		|| parse_auth_avp(auth_username_avp, &auth_username_spec, "username")<0
		|| parse_auth_avp(auth_password_avp, &auth_password_spec, "password")<0
		) {
			goto error;
		}
	} else {
		memset( &auth_realm_spec, 0, sizeof(pv_spec_t));
		memset( &auth_password_spec, 0, sizeof(pv_spec_t));
		memset( &auth_username_spec, 0, sizeof(pv_spec_t));
	}

	/* load the TM API - FIXME it should be loaded only
	 * if NO_RESTORE and AUTH */
	if (load_tm_api(&uac_tmb)!=0) {
		LM_ERR("can't load TM API\n");
		goto error;
	}

	/* load the UAC_AUTH API - FIXME it should be loaded only
	 * if uac_auth() is invoked from script */
	if(load_uac_auth_api(&uac_auth_api)<0){
		LM_ERR("can't load UAC_AUTH API\n");
		goto error;
	}

	if (restore_mode!=UAC_NO_RESTORE) {
		/* load the RR API */
		if (load_rr_api(&uac_rrb)!=0) {
			LM_ERR("can't load RR API\n");
			goto error;
		}

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
				if ( (parse_store_bavp(&store_to_bavp, &to_bavp_spec) ||
					 parse_store_bavp(&store_from_bavp, &from_bavp_spec))) {
					LM_ERR("cannot set correct store parameters\n");
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

	return 0;
error:
	return -1;
}


static void mod_destroy(void)
{
	return;
}



/************************** fixup functions ******************************/

static int fixup_replace_uri(void** param, int param_no)
{
	pv_elem_t *model;
	str s;

	model=NULL;
	s.s = (char*)(*param); s.len = strlen(s.s);
	if(pv_parse_format(&s, &model)<0)
	{
		LM_ERR("wrong format[%s]!\n",(char*)(*param));
		return E_UNSPEC;
	}
	if (model==NULL)
	{
		LM_ERR("empty parameter!\n");
		return E_UNSPEC;
	}
	*param = (void*)model;

	return 0;
}


static int fixup_replace_disp_uri(void** param, int param_no)
{
	pv_elem_t *model;
	char *p;
	str s;

	/* convert to str */
	s.s = (char*)*param;
	s.len = strlen(s.s);

	model=NULL;
	if (param_no==1 && s.len) {
		/* put " around display name */
		p = (char*)pkg_malloc(s.len+3);
		if (p==0) {
			LM_CRIT("no more pkg mem\n");
			return E_OUT_OF_MEM;
		}
		p[0] = '\"';
		memcpy(p+1, s.s, s.len);
		p[s.len+1] = '\"';
		p[s.len+2] = '\0';
		pkg_free(s.s);
		s.s = p;
		s.len += 2;
	}
	if(pv_parse_format(&s ,&model)<0) {
		LM_ERR("wrong format [%s] for param no %d!\n", s.s, param_no);
		pkg_free(s.s);
		return E_UNSPEC;
	}
	*param = (void*)model;

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

	return (restore_uri(msg,&rr_from_param,1)==0)?1:-1;
}


static int w_replace_from(struct sip_msg* msg, char* p1, char* p2)
{
	str uri_s;
	str dsp_s;
	str *uri;
	str *dsp;

	if (p2==NULL) {
		p2 = p1;
		p1 = NULL;
		dsp = NULL;
	}

	/* p1 dispaly , p2 uri */

	if ( p1!=NULL ) {
		if(pv_printf_s( msg, (pv_elem_p)p1, &dsp_s)!=0)
			return -1;
		dsp = &dsp_s;
	}

	/* compute the URI string; if empty string -> make it NULL */
	if (pv_printf_s( msg, (pv_elem_p)p2, &uri_s)!=0)
		return -1;
	uri = uri_s.len?&uri_s:NULL;

	if (parse_from_header(msg)<0 ) {
		LM_ERR("failed to find/parse FROM hdr\n");
		return -1;
	}

	LM_DBG("dsp=%p (len=%d) , uri=%p (len=%d)\n",
		dsp,dsp?dsp->len:0,uri,uri?uri->len:0);

	return (replace_uri(msg, dsp, uri, msg->from, &rr_from_param)==0)?1:-1;
}


static int w_restore_to(struct sip_msg *msg)
{
	/* safety checks - must be a request */
	if (msg->first_line.type!=SIP_REQUEST) {
		LM_ERR("called for something not request\n");
		return -1;
	}

	return (restore_uri(msg,&rr_to_param,0)==0)?1:-1;
}


static int w_replace_to(struct sip_msg* msg, char* p1, char* p2)
{
	str uri_s;
	str dsp_s;
	str *uri;
	str *dsp;

	if (p2==NULL) {
		p2 = p1;
		p1 = NULL;
		dsp = NULL;
	}

	/* p1 dispaly , p2 uri */

	if ( p1!=NULL ) {
		if(pv_printf_s( msg, (pv_elem_p)p1, &dsp_s)!=0)
			return -1;
		dsp = &dsp_s;
	}

	/* compute the URI string; if empty string -> make it NULL */
	if (pv_printf_s( msg, (pv_elem_p)p2, &uri_s)!=0)
		return -1;
	uri = uri_s.len?&uri_s:NULL;

	/* parse TO hdr */
	if ( msg->to==0 && (parse_headers(msg,HDR_TO_F,0)!=0 || msg->to==0) ) {
		LM_ERR("failed to parse TO hdr\n");
		return -1;
	}

	return (replace_uri(msg, dsp, uri, msg->to, &rr_to_param)==0)?1:-1;
}




static int w_uac_auth(struct sip_msg* msg, char* str, char* str2)
{
	return (uac_auth(msg)==0)?1:-1;
}


