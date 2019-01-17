/*
 * pua_dialoginfo module - publish dialog-info from dialog module
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
 * Copyright (C) 2007-2008 Dan Pascu
 * Copyright (C) 2008 Klaus Darilion IPCom
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
 *  2008-08-25  initial version (kd)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <time.h>

#include "../../sr_module.h"
#include "../../script_cb.h"
#include "../../parser/parse_expires.h"
#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../parser/msg_parser.h"
#include "../../str.h"
#include "../../trim.h"
#include "../../mem/mem.h"
#include "../../pt.h"
#include "../../mod_fix.h"
#include "../../parser/parse_from.h"
#include "../dialog/dlg_load.h"
#include "../dialog/dlg_hash.h"
#include "../pua/pua_bind.h"
#include "pua_dialoginfo.h"



/* Default module parameter values */
#define DEF_INCLUDE_CALLID 1
#define DEF_INCLUDE_LOCALREMOTE 1
#define DEF_INCLUDE_TAGS 1
#define DEF_CALLER_ALWAYS_CONFIRMED 0

#define DEFAULT_CREATED_LIFETIME 3600

#define DLG_PUB_A_CHAR   'A'  /* caller */
#define DLG_PUB_B_CHAR   'B'  /* callee */
#define DLG_PUB_A      (1<<0)  /* caller */
#define DLG_PUB_B      (1<<1)  /* callee */

pua_api_t pua;

struct dlg_binds dlg_api;
struct tm_binds   tm_api;

/* Module parameter variables */
int include_callid      = DEF_INCLUDE_CALLID;
int include_localremote = DEF_INCLUDE_LOCALREMOTE;
int include_tags        = DEF_INCLUDE_TAGS;
int caller_confirmed    = DEF_CALLER_ALWAYS_CONFIRMED;
str presence_server = {0, 0};
static str caller_spec_param= {0, 0};
static str callee_spec_param= {0, 0};
static pv_spec_t caller_spec;
static pv_spec_t callee_spec;
static int osips_ps = 1;
static int publish_on_trying = 0;
static int nopublish_flag = -1;


/** module functions */

static int mod_init(void);
int dialoginfo_set(struct sip_msg* msg, char* str1, char* str2);
int set_branch_callee(struct sip_msg* msg, char* callee);
static int fixup_dlginfo(void** param, int param_no);
static void build_branch_callee_var_names( int branch, str *var_b, str *var_u);

struct dlginfo_cb_params {
	char flags;
	struct dlginfo_part peer;
	struct dlginfo_part entity;
	long long bitmask_early;
	long long bitmask_failed;
};


static cmd_export_t cmds[]=
{
	{"dialoginfo_set", (cmd_function)dialoginfo_set, 0,
		0, 0, REQUEST_ROUTE},
	{"dialoginfo_set", (cmd_function)dialoginfo_set, 1,
		fixup_dlginfo, 0, REQUEST_ROUTE},
	{"dialoginfo_set_branch_callee", (cmd_function)set_branch_callee, 1,
		fixup_spve_null, 0, BRANCH_ROUTE},
	{0, 0, 0, 0, 0, 0}
};

static param_export_t params[]={
	{"include_callid",      INT_PARAM, &include_callid },
	{"include_localremote", INT_PARAM, &include_localremote },
	{"include_tags",        INT_PARAM, &include_tags },
	{"caller_confirmed",    INT_PARAM, &caller_confirmed },
	{"publish_on_trying",   INT_PARAM, &publish_on_trying },
	{"presence_server",     STR_PARAM, &presence_server.s },
	{"caller_spec_param",   STR_PARAM, &caller_spec_param.s },
	{"callee_spec_param",   STR_PARAM, &callee_spec_param.s },
	{"osips_ps",            INT_PARAM, &osips_ps },
	{"nopublish_flag",      INT_PARAM, &nopublish_flag },
	{0, 0, 0 }
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "pua",    DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "dialog", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "tm",     DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};


struct module_exports exports= {
	"pua_dialoginfo",		/* module name */
	MOD_TYPE_DEFAULT,       /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,		/* dlopen flags */
	&deps,                  /* OpenSIPS module dependencies */
	cmds,					/* exported functions */
	0,						/* exported async functions */
	params,					/* exported parameters */
	0,						/* exported statistics */
	0,						/* exported MI functions */
	0,						/* exported pseudo-variables */
	0,						/* exported transformations */
	0,						/* extra processes */
	mod_init,				/* module initialization function */
	0,						/* response handling function */
	0,						/* destroy function */
	NULL					/* per-child init function */
};


static void
__tm_sendpublish(struct cell *t, int type, struct tmcb_params *_params)
{
	struct sip_msg* msg = _params->rpl;
	struct dlginfo_cb_params *param;
	struct dlginfo_part *peer, *entity, custom;
	struct dlg_cell *dlg;
	str callid, *ttag, *ftag;
	str name_d, name_u;
	int branch, n, expire;

	param = (struct dlginfo_cb_params*)(*_params->param);
	peer = &(param->peer);
	entity = &(param->entity);

	/* this is triggered only for TMCB_RESPONSE_IN */
	branch = tm_api.get_branch_index();

	LM_DBG("TM event %d [%d/%d] received, entity [%.*s], peer [%.*s],"
		" flags %x\n",type, _params->code, branch,
		entity->uri.len, entity->uri.s,
		peer->uri.len, peer->uri.s, param->flags);

	if (include_tags) {
		if ( get_callid( msg, &callid)<0
		|| parse_from_header( msg )<0
		|| parse_to_header( msg )<0 ) {
			LM_ERR("failed to parse the reply\n");
			return;
		}
		ftag = &(get_from(msg)->tag_value);
		ttag = &(get_to(msg)->tag_value);
	} else {
		ftag = ttag = NULL;
	}

	memset( &custom, 0, sizeof(custom) );
	dlg = dlg_api.get_dlg();
	if (dlg && param->flags & DLG_PUB_B) {
		build_branch_callee_var_names( branch, &name_d, &name_u);
		if (dlg_api.fetch_dlg_value(dlg, &name_u, &custom.uri, 1)== 0) {
			/* there is a custom URI for the branch, check for display too */
			dlg_api.fetch_dlg_value(dlg, &name_d, &custom.display, 1);
			peer = &custom;
			LM_DBG("per-branch callee/peer information was found\n");
		}
	}

	LM_DBG("using entity [%.*s]/[%.*s] and peer [%.*s]-/[%.*s]\n",
		entity->display.len, entity->display.s,
		entity->uri.len, entity->uri.s,
		peer->display.len, peer->display.s,
		peer->uri.len, peer->uri.s);

	/* depending on the reply code, see what to publish */
	if (_params->code<180 && _params->code>=100) {

		expire = t->uac[branch].request.fr_timer.time_out - get_ticks();
		if (publish_on_trying) {
			if (param->flags & DLG_PUB_A)
				dialog_publish("trying", entity, peer,
					&callid, branch, 1, expire,
					ftag, ttag);
			if(param->flags & DLG_PUB_B)
				dialog_publish("trying", peer, entity,
					&callid, branch, 0, expire,
					ttag, ftag);
		}

	} else
	if (_params->code<200 && _params->code>=180) {

		/* ringing/early state - is it the first ringing on this branch ? */
		lock_get(&t->reply_mutex);
		if ( param->bitmask_early & (((long long)1)<<branch)) {
			n = 0;
		} else {
			param->bitmask_early |= (((long long)1)<<branch);
			n = 1;
		}
		lock_release(&t->reply_mutex);

		if (n) {
			expire = t->uac[branch].request.fr_timer.time_out - get_ticks();
			if(param->flags & DLG_PUB_A)
				dialog_publish(caller_confirmed?"confirmed":"early",
					entity, peer,
					&callid, branch, 1, expire,
					ftag, ttag);
			if(param->flags & DLG_PUB_B)
				dialog_publish("early", peer, entity,
					&callid, branch, 0, expire,
					ttag, ftag);
		}

	} else
	if (_params->code>=300) {

		/* ringing/early state - is it the first negative on this branch ? */
		lock_get(&t->reply_mutex);
		if ( param->bitmask_failed & (((long long)1)<<branch)) {
			n = 0;
		} else {
			param->bitmask_failed |= (((long long)1)<<branch);
			n = 1;
		}
		lock_release(&t->reply_mutex);

		if (n) {
			if(param->flags & DLG_PUB_A)
				dialog_publish("terminated", entity, peer,
					&callid, branch, 1, 0,
					ftag, ttag);
			if(param->flags & DLG_PUB_B)
				dialog_publish("terminated", peer, entity,
					&callid, branch, 0, 0,
					ttag, ftag);
		}

	}

	if (custom.uri.s) pkg_free(custom.uri.s);
	if (custom.display.s) pkg_free(custom.display.s);
}


static void
__dialog_sendpublish(struct dlg_cell *dlg, int type,
												struct dlg_cb_params *_params)
{
	static str dlg_branch_var = str_init("__dlg_brX");
	struct dlginfo_cb_params *param;
	struct dlginfo_part *peer, *entity, custom;
	str *ftag, *ttag, s;
	str name_d, name_u;
	int branch, expire;
	char *state;

	param = (struct dlginfo_cb_params*)(*_params->param);
	peer = &(param->peer);
	entity = &(param->entity);

	LM_DBG("dialog event %d recevied, entity [%.*s], peer [%.*s], flags %x\n",
		type, entity->uri.len, entity->uri.s,
		peer->uri.len, peer->uri.s, param->flags);

	/* get rid of ACKs that are delivered as WITHIN requests */
	if (type==DLGCB_REQ_WITHIN && _params->msg->REQ_METHOD==METHOD_ACK)
		return;

	if (include_tags) {
		ftag = &(dlg->legs[DLG_CALLER_LEG].tag);
		ttag = &(dlg->legs[callee_idx(dlg)].tag);
	} else {
		ftag = ttag = NULL;
	}

	if (type==DLGCB_CONFIRMED) {

		/* this is triggered in the context of a reply, so its branch
		 * is available here */
		branch = tm_api.get_branch_index();

		s.s = int2str((uint64_t)branch, &s.len);
		if (dlg_api.store_dlg_value(dlg, &dlg_branch_var, &s)< 0) {
			LM_ERR("Failed to store wining branch in dialog\n");
		}

		LM_DBG("stored branch is %d\n", branch);

	} else {

		if (dlg_api.fetch_dlg_value(dlg, &dlg_branch_var, &s, 0)< 0) {
			LM_ERR("Failed to retrieve wining branch from dialog\n");
			branch = 0;
		} else {
			if (str2int(&s, (unsigned int*)&branch)<0)
				branch = 0;
		}

		LM_DBG("retrieved branch is %d\n", branch);

	}

	memset( &custom, 0, sizeof(custom) );
	if (param->flags & DLG_PUB_B) {
		build_branch_callee_var_names( branch, &name_d, &name_u);
		if (dlg_api.fetch_dlg_value(dlg, &name_u, &custom.uri, 1)== 0) {
			/* there is a custom URI for the branch, check for display too */
			dlg_api.fetch_dlg_value(dlg, &name_d, &custom.display, 1);
			peer = &custom;
			LM_DBG("per-branch callee/peer information was found\n");
		}
	}

	LM_DBG("using entity [%.*s]/[%.*s] and peer [%.*s]-/[%.*s]\n",
		entity->display.len, entity->display.s,
		entity->uri.len, entity->uri.s,
		peer->display.len, peer->display.s,
		peer->uri.len, peer->uri.s);

	expire = 0;
	state = "terminated";

	switch (type) {
	case DLGCB_REQ_WITHIN:

		expire = dlg->lifetime;
		state = "confirmed";

	case DLGCB_TERMINATED:
	case DLGCB_EXPIRED:

		if(param->flags & DLG_PUB_A)
			dialog_publish(state, entity, peer,
				&(dlg->callid), branch, 1, expire, ftag, ttag);
		if(param->flags & DLG_PUB_B)
			dialog_publish(state, peer, entity,
				&(dlg->callid), branch, 0, expire,  ttag, ftag);
		break;

	case DLGCB_CONFIRMED:

		if(param->flags & DLG_PUB_A)
			dialog_publish("confirmed", entity, peer,
				&(dlg->callid), branch, 1, dlg->lifetime, ftag, ttag);
		if(param->flags & DLG_PUB_B)
			dialog_publish("confirmed", peer, entity,
				&(dlg->callid), branch, 0, dlg->lifetime, ttag, ftag);
		break;
	default:
		LM_ERR("unhandled dialog callback type %d received\n", type);
	}

	if (custom.uri.s) pkg_free(custom.uri.s);
	if (custom.display.s) pkg_free(custom.display.s);
}


static void
__dump_dlginfo(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	/* TODO
	 * This function should store all the context data into dlg variables,
	 * so they can be saved into DB and later restored 
	 * This is a pair function of __dialog_loaded()
	 */
}


static void
__load_dlginfo(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	/* TODO
	 * This funcion should restore the context data (cbs and their params)
	 * after loading data from DB.
	*/
}


int dialoginfo_process_body(struct publ_info* publ, str** fin_body,
									   int ver, str* tuple)
{
	xmlNodePtr node = NULL;
	xmlDocPtr doc = NULL;
	char* version;
	str* body = NULL;
	int len;

	doc = xmlParseMemory(publ->body->s, publ->body->len);
	if (doc == NULL) {
		LM_ERR("while parsing xml memory\n");
		goto error;
	}
	/* change version */
	node = doc->children;
	if (node == NULL)
	{
		LM_ERR("while extracting dialog-info node\n");
		goto error;
	}
	version = int2str(ver, &len);
	version[len] = '\0';

	if (!xmlNewProp(node, BAD_CAST "version", BAD_CAST version))
	{
		LM_ERR("while setting version attribute\n");
		goto error;
	}
	body = (str*)pkg_malloc(sizeof(str));
	if (body == NULL)
	{
		LM_ERR("NO more memory left\n");
		goto error;
	}
	memset(body, 0, sizeof(str));
	xmlDocDumpMemory(doc, (xmlChar**)(void*)&body->s, &body->len);
	LM_DBG(">>> publish body: >%*s<\n", body->len, body->s);

	xmlFreeDoc(doc);
	*fin_body = body;
	if (*fin_body == NULL)
		LM_DBG("NULL fin_body\n");

	xmlMemoryDump();
	xmlCleanupParser();
	return 1;

	error:
	if (doc)
		xmlFreeDoc(doc);
	if (body)
		pkg_free(body);
	xmlMemoryDump();
	xmlCleanupParser();
	return -1;
}

/**
 * init module function
 */
static int mod_init(void)
{
	bind_pua_t bind_pua;
	evs_process_body_t* evp=0;

	bind_pua= (bind_pua_t)find_export("bind_pua", 1,0);
	if (!bind_pua)
	{
		LM_ERR("Can't bind pua\n");
		return -1;
	}

	if (bind_pua(&pua) < 0)
	{
		LM_ERR("Can't bind pua\n");
		return -1;
	}
	if(pua.send_publish == NULL)
	{
		LM_ERR("Could not import send_publish\n");
		return -1;
	}
	pua_send_publish= pua.send_publish;

	if (nopublish_flag!= -1 && nopublish_flag > MAX_FLAG) {
		LM_ERR("invalid nopublish flag %d!!\n", nopublish_flag);
		return -1;
	}
	nopublish_flag = (nopublish_flag!=-1)?(1<<nopublish_flag):0;

	if(!osips_ps)
		evp = dialoginfo_process_body;

	/* add event in pua module */
	if(pua.add_event(DIALOG_EVENT, "dialog", "application/dialog-info+xml", evp) < 0) {
		LM_ERR("failed to add 'dialog' event to pua module\n");
		return -1;
	}

	/* bind to the dialog API */
	if (load_dlg_api(&dlg_api)!=0) {
		LM_ERR("failed to find dialog API - is dialog module loaded?\n");
		return -1;
	}

	/* register dialog loading callback */
	if (dlg_api.register_dlgcb(NULL, DLGCB_LOADED, __load_dlginfo, NULL, NULL) != 0) {
		LM_CRIT("cannot register callback for dialogs loaded from the database\n");
	}

	/* load the TM API */
	if (load_tm_api(&tm_api)!=0) {
		LM_ERR("can't load TM API\n");
		return -1;
	}

	if(presence_server.s)
		presence_server.len = strlen(presence_server.s);

	if(caller_spec_param.s)
	{
		caller_spec_param.len = strlen(caller_spec_param.s);
		if(pv_parse_spec(&caller_spec_param, &caller_spec)==NULL)
		{
			LM_ERR("failed to parse caller spec\n");
			return -2;
		}
		switch(caller_spec.type) {
			case PVT_NONE:
			case PVT_EMPTY:
			case PVT_NULL:
			case PVT_MARKER:
			case PVT_COLOR:
				LM_ERR("invalid caller spec\n");
				return -3;
			default: ;
		}
	}

	if(callee_spec_param.s)
	{
		callee_spec_param.len = strlen(callee_spec_param.s);
		if(pv_parse_spec(&callee_spec_param, &callee_spec)==NULL)
		{
			LM_ERR("failed to parse callee spec\n");
			return -2;
		}
		switch(callee_spec.type) {
			case PVT_NONE:
			case PVT_EMPTY:
			case PVT_NULL:
			case PVT_MARKER:
			case PVT_COLOR:
				LM_ERR("invalid callee spec\n");
				return -3;
			default: ;
		}
	}

	return 0;
}


static struct dlginfo_cb_params * build_cb_param(int flags,
						struct to_body *entity_p, struct to_body *peer_p)
{
	struct dlginfo_cb_params *param;
	char *p;

	param = (struct dlginfo_cb_params *)shm_malloc(
		sizeof(struct dlginfo_cb_params) +
		entity_p->display.len + entity_p->uri.len +
		peer_p->display.len + peer_p->uri.len );
	if (param==NULL) {
		LM_ERR("failed to allocate a param pack\n");
		return NULL;
	}

	param->flags = flags;

	p = (char*)(param + 1);

	memcpy( p, entity_p->uri.s, entity_p->uri.len);
	param->entity.uri.s = p;
	param->entity.uri.len = entity_p->uri.len;
	p+= entity_p->uri.len;

	if (entity_p->display.len) {
		memcpy( p, entity_p->display.s, entity_p->display.len);
		param->entity.display.s = p;
		param->entity.display.len = entity_p->display.len;
		p+= entity_p->display.len;
	}

	memcpy( p, peer_p->uri.s, peer_p->uri.len);
	param->peer.uri.s = p;
	param->peer.uri.len = peer_p->uri.len;
	p+= peer_p->uri.len;

	if (peer_p->display.len) {
		memcpy( p, peer_p->display.s, peer_p->display.len);
		param->peer.display.s = p;
		param->peer.display.len = peer_p->display.len;
		p+= peer_p->display.len;
	}

	return param;
}


static int pack_cb_params(struct sip_msg * msg, char* flag_pv,
		struct dlginfo_cb_params **param1, struct dlginfo_cb_params **param2)
{
	struct to_body entity, peer;
	struct to_body *entity_p, *peer_p;
	pv_value_t tok;
	char *c_buf = NULL;
	char *p_buf = NULL;
	int len, flags, i;
	str *ruri, s;
	int ret;

	ret = -1;

	/* if defined overwrite */
	if ( caller_spec_param.s!=NULL /* if parameter defined */
	&& pv_get_spec_value(msg, &caller_spec, &tok)>=0   /* if value set */
	&& tok.flags&PV_VAL_STR  /* value is string */
	) {

		trim(&tok.rs);
		c_buf = (char*)pkg_malloc(tok.rs.len + CRLF_LEN + 1);
		if (c_buf==NULL) {
			LM_ERR("no more pkg memeory\n");
			goto error1;
		}
		memcpy(c_buf, tok.rs.s, tok.rs.len);
		len = tok.rs.len;
		memcpy(c_buf + len, CRLF, CRLF_LEN);
		len += CRLF_LEN;

		parse_to( c_buf, c_buf+len , &entity);
		if (entity.error != PARSE_OK) {
			LM_ERR("Failed to parse entity nameaddr [%.*s]\n", len, c_buf);
			goto error1;
		}
		entity_p = &entity;

	} else {

		entity_p = get_from(msg);

	}

	/* if defined overwrite */
	if ( callee_spec_param.s!=NULL /* if parameter defined */
	&& pv_get_spec_value(msg, &callee_spec, &tok)>=0   /* if value set */
	&& tok.flags&PV_VAL_STR  /* value is string */
	) {

		trim(&tok.rs);
		p_buf = (char*)pkg_malloc(tok.rs.len + CRLF_LEN + 1);
		if (p_buf==NULL) {
			LM_ERR("no more pkg memeory\n");
			goto error2;
		}
		memcpy(p_buf, tok.rs.s, tok.rs.len);
		len = tok.rs.len;
		memcpy(p_buf + len, CRLF, CRLF_LEN);
		len += CRLF_LEN;
		LM_DBG("extracted peer nameaddr is [%.*s]\n", len, c_buf);

	} else {

		ruri = GET_RURI(msg);
		peer_p = get_to(msg);
		len = peer_p->display.len + 2 + ruri->len + CRLF_LEN;
		p_buf = (char*)pkg_malloc(len + 1);
		if (p_buf==NULL) {
			LM_ERR("no more pkg memeory\n");
			goto error2;
		}
		len = 0;
		if (peer_p->display.len) {
			memcpy(p_buf, peer_p->display.s, peer_p->display.len);
			len = peer_p->display.len;
			p_buf[len++]='<';
		}
		memcpy(p_buf + len, ruri->s, ruri->len);
		len+= ruri->len;
		if (peer_p->display.len)
			p_buf[len++]='>';
		memcpy(p_buf + len, CRLF, CRLF_LEN);
		len+= CRLF_LEN;
		LM_DBG("computed peer nameaddr is [%.*s]\n", len, c_buf);

	}

	parse_to( p_buf, p_buf+len , &peer);
	if (entity.error != PARSE_OK) {
		LM_ERR("Failed to parse peer nameaddr [%.*s]\n", len, p_buf);
		goto error2;
	}
	peer_p = &peer;

	/* store flag  */
	flags = 0;

	if (flag_pv) {

		if(pv_printf_s(msg, (pv_elem_t*)flag_pv, &s)<0) {
			LM_ERR("cannot print the format\n");
			goto error2;
		}
		for( i=0 ; i<s.len ; i++) {
			switch (s.s[i]) {
				case DLG_PUB_A_CHAR:
					flags |= DLG_PUB_A;
					break;
				case DLG_PUB_B_CHAR:
					flags |= DLG_PUB_B;
					break;
				default:
					LM_ERR("unsupported flag [%c], ignoring\n",s.s[i]);
			}
		}

	}

	if (flags==0)
		flags = DLG_PUB_A | DLG_PUB_B;

	/* now finally pack everything */
	*param1 = build_cb_param(flags, entity_p, peer_p);
	if (*param1==NULL)
		goto error2;

	*param2 = build_cb_param(flags, entity_p, peer_p);
	if (*param1==NULL) {
		shm_free(*param1);
		goto error2;
	}

	LM_DBG("packed dlginfo data: flags %x, entity [%.*s]/[%.*s],"
		" peer [%.*s]/[%.*s]\n", (*param1)->flags,
		(*param1)->entity.display.len, (*param1)->entity.display.s,
		(*param1)->entity.uri.len, (*param1)->entity.uri.s,
		(*param1)->peer.display.len, (*param1)->peer.display.s,
		(*param1)->peer.uri.len, (*param1)->peer.uri.s
		);

	ret = 0;

error2:
	if (p_buf) {
		pkg_free(p_buf);
		free_to_params( &peer );
	}
error1:
	if (c_buf) {
		pkg_free(c_buf);
		free_to_params( &entity );
	}
	return ret;
}


static void free_cb_param(void *param)
{
	shm_free(param);
}


/*
 *	By default
 *		- caller is taken from the From header
 *		- callee is taken from RURI
 *	If the pseudovariables for caller or callee are defined, those values are used
 * */

int dialoginfo_set(struct sip_msg* msg, char* flag_pv, char* str2)
{
	struct dlginfo_cb_params *param_dlg, *param_tm;
	struct dlg_cell * dlg;
	int ret = -1;

	if (msg->REQ_METHOD != METHOD_INVITE)
		return 1;

	if(dlg_api.create_dlg(msg,0)< 0)
	{
		LM_ERR("Failed to create dialog\n");
		return -1;
	}

	dlg = dlg_api.get_dlg();

	LM_DBG("new INVITE dialog created for callid [%.*s]\n",
		dlg->callid.len, dlg->callid.s);

	if (pack_cb_params( msg, flag_pv, &param_dlg, &param_tm)<0) {
		LM_ERR("Failed to allocate parameters\n");
		return -1;
	}

	/* register TM callback to get access to recevied replies */
	if (tm_api.register_tmcb( msg, NULL, TMCB_RESPONSE_IN,
		__tm_sendpublish, (void*)param_tm, free_cb_param) != 1) {
		LM_ERR("cannot register TM callback for incoming replies\n");
		goto end;
	}

	/* register dialog callbacks which triggers sending PUBLISH */
	if (dlg_api.register_dlgcb(dlg,
		DLGCB_CONFIRMED | DLGCB_TERMINATED | DLGCB_EXPIRED |
		DLGCB_REQ_WITHIN ,
		__dialog_sendpublish, (void*)param_dlg, free_cb_param) != 0) {
		LM_ERR("cannot register callback for interesting dialog types\n");
		goto end;
	}

	if (dlg_api.register_dlgcb(dlg, DLGCB_WRITE_VP,
	__dump_dlginfo, param_dlg, NULL) != 0) {
		LM_ERR("cannot register callback for data dumping\n");
	}

	ret=1;
end:
	return ret;
}

static int fixup_dlginfo(void** param, int param_no)
{
	pv_elem_t *model;
	str s;

	if(param_no== 0)
		return 0;

	if(*param)
	{
		s.s = (char*)(*param); s.len = strlen(s.s);
		if(pv_parse_format(&s, &model)<0)
		{
			LM_ERR( "wrong format[%s]\n",(char*)(*param));
			return E_UNSPEC;
		}

		*param = (void*)model;
		return 0;
	}
	LM_ERR( "null format\n");
	return E_UNSPEC;
}


static void build_branch_callee_var_names( int branch, str *var_d, str *var_u)
{
	#define DISPLAY_PATTERN "__dlginfo_br_CALLEED_XXXX"
	#define URI_PATTERN "__dlginfo_br_CALLEEU_XXXX"
	#define br_callee_var_end_offset 3
	static char br_calleeD_var[] = DISPLAY_PATTERN;
	static char br_calleeU_var[] = URI_PATTERN;
	char *p;
	int s;

	p = br_calleeD_var + sizeof(DISPLAY_PATTERN)-1 - br_callee_var_end_offset;
	s = br_callee_var_end_offset;
	int2reverse_hex( &p, &s, (unsigned int)branch );
	var_d->s = br_calleeD_var;
	var_d->len = sizeof(DISPLAY_PATTERN)-1 - s;

	p = br_calleeU_var + sizeof(URI_PATTERN)-1 - br_callee_var_end_offset;
	s = br_callee_var_end_offset;
	int2reverse_hex( &p, &s, (unsigned int)branch );
	var_u->s = br_calleeU_var;
	var_u->len = sizeof(URI_PATTERN)-1 - s;

}

int set_branch_callee(struct sip_msg* msg, char* callee)
{
	struct dlg_cell * dlg;
	struct to_body to_b;
	int branch, len;
	str v, name_u, name_d;
	char *c_buf;

	if (fixup_get_svalue(msg, (gparam_p)callee, &v)!=0) {
		LM_ERR("cannot print the format for callee\n");
		return -1;
	}

	dlg = dlg_api.get_dlg();

	if (dlg==NULL)
		return -1;

	branch = tm_api.get_branch_index();

	/* build var name */
	build_branch_callee_var_names( branch, &name_d, &name_u );

	if (v.s!=NULL || v.len!=0) {

		/* parse input as nameaddr */
		trim( &v );
		c_buf = (char*)pkg_malloc(v.len + CRLF_LEN + 1);
		if (c_buf==NULL) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		memcpy(c_buf, v.s, v.len);
		len = v.len;
		memcpy(c_buf + len, CRLF, CRLF_LEN);
		len += CRLF_LEN;

		parse_to( c_buf, c_buf+len , &to_b);
		if (to_b.error != PARSE_OK) {
			LM_ERR("Failed to parse entity nameaddr [%.*s]\n", len, c_buf);
			goto error;
		}

		LM_DBG("storing [%.*s]->[%.*s] and [%.*s]->[%.*s]\n",
			name_d.len, name_d.s, to_b.display.len, to_b.display.s,
			name_u.len, name_u.s, to_b.uri.len, to_b.uri.s);

		if (dlg_api.store_dlg_value(dlg, &name_u, &to_b.uri)< 0) {
			LM_ERR("Failed to store display for branch %d\n",branch);
			return -1;
		}
		if (dlg_api.store_dlg_value(dlg, &name_d,
		to_b.display.len?&to_b.display:NULL)< 0) {
			LM_ERR("Failed to store URI for branch %d\n",branch);
			return -1;
		}

		pkg_free(c_buf);
		free_to_params(&to_b);

	} else {

		if (dlg_api.store_dlg_value(dlg, &name_d, NULL)< 0) {
			LM_ERR("Failed to remove display for branch %d\n",branch);
			return -1;
		}
		if (dlg_api.store_dlg_value(dlg, &name_u, NULL)< 0) {
			LM_ERR("Failed to remove URI for branch %d\n",branch);
			return -1;
		}

	}

	return 1;
error:
	pkg_free(c_buf);
	free_to_params(&to_b);
	return -1;
}

