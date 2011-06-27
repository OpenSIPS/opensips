/*
 * $Id$
 *
 * registrant module
 *
 * Copyright (C) 2011 VoIP Embedded Inc.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2011-02-11  initial version (Ovidiu Sas)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>

#include "utime.h"

#include "../../sr_module.h"
#include "../../timer.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_authenticate.h"
#include "../../parser/contact/parse_contact.h"
#include "reg_records.h"
#include "../uac_auth/uac_auth.h"


#define UAC_REGISTRAR_URI_PARAM			1
#define UAC_PROXY_URI_PARAM			2
#define UAC_AOR_URI_PARAM			3
#define UAC_THIRD_PARTY_REGISTRANT_URI_PARAM	4
#define UAC_AUTH_USER_PARAM			5
#define UAC_AUTH_PASSWORD_PARAM			6
#define UAC_CONTACT_URI_PARAM			7
#define UAC_CONTACT_PARAMS_PARAM		8
#define UAC_EXPIRES_PARAM			9
#define UAC_FORCED_SOCKET_PARAM			10
#define UAC_MAX_PARAMS_NO			11


#define RXLS(m, str, i) (int)((m)[i].rm_eo - (m)[i].rm_so),(str) + (m)[i].rm_so
#define RXSL(m, str, i) (str) + (m)[i].rm_so,(int)((m)[i].rm_eo - (m)[i].rm_so)
#define RXL(m, str, i) (m)[i].rm_eo - (m)[i].rm_so
#define RXS(m, str, i) (str) + (m)[i].rm_so

#define RX_L_S(m, str, i) _l=(int)((m)[i].rm_eo - (m)[i].rm_so);_s=(str) + (m)[i].rm_so


/** Functions declarations */
static int mod_init(void);
static void mod_destroy(void);
static int child_init(int rank);

void timer_check(unsigned int ticks, void* param);

static int add_uac_params(modparam_t type, void * val);
static struct mi_root* mi_reg_list(struct mi_root* cmd, void* param);
int send_register(unsigned int hash_index, reg_record_t *rec, str *auth_hdr);


/** Global variables */

uac_auth_api_t uac_auth_api;

unsigned int default_expires = 3600;
unsigned int timer_interval = 100;

reg_table_t reg_htable;
unsigned int reg_hsize = 1;
unsigned int hash_index = 0;

static int params_inited = 0;
static regex_t uac_params_regex;

static uac_reg_map_t *uac_params = NULL;

static struct sip_uri uri;
static str register_method = str_init("REGISTER");
static str contact_hdr = str_init("Contact: ");
static str expires_hdr = str_init("Expires: ");
static str expires_param = str_init(";expires=");

char extra_hdrs_buf[512];
static str extra_hdrs={extra_hdrs_buf, 512};


/* TM bind */
struct tm_binds tmb;


typedef struct reg_tm_cb {
	unsigned int hash_index;
	reg_record_t *uac;
}reg_tm_cb_t;

/** Exported functions */
static cmd_export_t cmds[]=
{
	{0,0,0,0,0,0}
};


/** Exported parameters */
static param_export_t params[]= {
	{"hash_size",		INT_PARAM,			&reg_hsize},
	{"default_expires",	INT_PARAM,			&default_expires},
	{"timer_interval",	INT_PARAM,			&timer_interval},
	{"uac",			STR_PARAM|USE_FUNC_PARAM,	(void *)add_uac_params},
	{0,0,0}
};


/** MI commands */
static mi_export_t mi_cmds[] = {
	{"reg_list",	mi_reg_list,	0,	0,	0},
	{0,		0,		0,	0,	0}
};


/** Module interface */
struct module_exports exports= {
	"registrant",			/* module name */
	MODULE_VERSION,			/* module version */
	DEFAULT_DLFLAGS,		/* dlopen flags */
	cmds,				/* exported functions */
	params,				/* exported parameters */
	NULL,				/* exported statistics */
	mi_cmds,			/* exported MI functions */
	NULL,				/* exported pseudo-variables */
	0,				/* extra processes */
	mod_init,			/* module initialization function */
	(response_function) NULL,	/* response handling function */
	(destroy_function) mod_destroy,	/* destroy function */
	child_init			/* per-child init function */
};


/** Module init function */
static int mod_init(void)
{
	uac_reg_map_t *_uac_param, *uac_param = uac_params;
	char *p = NULL;
	int len = 0;
	str now = {NULL, 0};

	LM_DBG("start\n");

	regfree(&uac_params_regex);

	if(load_uac_auth_api(&uac_auth_api)<0){
		LM_ERR("Failed to load uac_auth api\n");
		return -1;
	}

	if(default_expires<15){
		LM_ERR("default_expires to short: [%d]<15\n", default_expires);
		return -1;
	}
	if(timer_interval<10){
		LM_ERR("timer_interval to short: [%d]<10\n", timer_interval);
		return -1;
	}
	if(reg_hsize<1 || reg_hsize>20) {
		LM_ERR("Wrong hash size: 20<[%d]<1\n", reg_hsize);
	}
	reg_hsize = 1<<reg_hsize;

	if(init_reg_htable()<0) {
		LM_ERR("Failed to initialize registrant hash table\n");
		return -1;
	}

	/* load all TM stuff */
	if(load_tm_api(&tmb)==-1) {
		LM_ERR("can't load tm functions\n");
		return -1;
	}

	p = int2str((unsigned long)(time(0)), &len);
	if (p && len>0) {
		now.s = (char *)pkg_malloc(len);
		if(now.s) {
			memcpy(now.s, p, len);
			now.len = len;
		} else {
			LM_ERR("oom\n");
			return -1;
		}
	}
	
	while(uac_param) {
		LM_DBG("let's register [%.*s] on [%.*s] from hash table [%d]\n",
			uac_param->to_uri.len, uac_param->to_uri.s,
			uac_param->registrar_uri.len, uac_param->registrar_uri.s,
			uac_param->hash_code);
		if(add_record(uac_param, &now)<0) {
			LM_ERR("can't load registrant\n");
			if (now.s) {pkg_free(now.s);}
			return -1;
		}
		_uac_param = uac_param;
		uac_param = uac_param->next;
		pkg_free(_uac_param);
	}
	uac_params = NULL;
	if (now.s) {pkg_free(now.s);}

	register_timer(timer_check, 0, timer_interval/reg_hsize);

	return 0;
}


static void mod_destroy(void)
{
	destroy_reg_htable();

	LM_DBG("done\n");
	return;
}

static int child_init(int rank){return 0;}


static int init_params(void)
{
	if (regcomp(&uac_params_regex,
		"^([^, ]+),([^, ]*),([^, ]+),([^, ]*),([^, ]*),([^, ]*),([^, ]+),([^, ]*),([0-9]*),([^, ]*)$",
		REG_EXTENDED|REG_ICASE)) {
		LM_ERR("can't compile modparam regex\n");
		return -1;
	}

	params_inited = 1;
	return 0;
}


static int add_uac_params(modparam_t type, void *val)
{
	regmatch_t m[UAC_MAX_PARAMS_NO];
	char *p, *line = (char *)val;
	char *_s;
	int _l;
	unsigned int size;
	uac_reg_map_t *uac_param;
	str host;
	int port, proto;

	if (!params_inited && init_params())
		return -1;

	if (regexec(&uac_params_regex, line, UAC_MAX_PARAMS_NO, m, 0)) {
		LM_ERR("invalid param: %s\n", (char *)val);
		return -1;
	}
	LM_DBG("registrar=[%.*s] AOR=[%.*s] auth_user=[%.*s] password=[%.*s]"
		" expire=[%.*s] proxy=[%.*s] contact=[%.*s] third_party=[%.*s]\n",
		RXLS(m, line, UAC_REGISTRAR_URI_PARAM), RXLS(m, line, UAC_AOR_URI_PARAM),
		RXLS(m, line, UAC_AUTH_USER_PARAM), RXLS(m, line, UAC_AUTH_PASSWORD_PARAM),
		RXLS(m, line, UAC_EXPIRES_PARAM), RXLS(m, line, UAC_PROXY_URI_PARAM),
		RXLS(m, line, UAC_CONTACT_URI_PARAM),
		RXLS(m, line, UAC_THIRD_PARTY_REGISTRANT_URI_PARAM));

	size = sizeof(uac_reg_map_t) + RXL(m, line, 0);
	uac_param = (uac_reg_map_t *)pkg_malloc(size);
	if (!uac_param) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(uac_param, 0, size);
	p = (char*)(uac_param + 1);

	RX_L_S(m, line, UAC_REGISTRAR_URI_PARAM);
	if (parse_uri(_s, _l, &uri)<0) {
		LM_ERR("cannot parse registrar uri [%.*s]\n", _l, _s);
		return -1;
	}
	if (uri.user.s && uri.user.len) {
		LM_ERR("registrant uri must not have user [%.*s]\n",
			uri.user.len, uri.user.s);
		return -1;
	}
	uac_param->registrar_uri.len = _l;
	uac_param->registrar_uri.s = p;
	memcpy(p, _s, _l);
	p += _l;

	RX_L_S(m, line, UAC_PROXY_URI_PARAM);
	if (_l != 0) {
		if (parse_uri(_s, _l, &uri)<0) {
			LM_ERR("cannot parse proxy uri [%.*s]\n", _l, _s);
			return -1;
		}
		if (uri.user.s && uri.user.len) {
			LM_ERR("proxy uri must not have user [%.*s]\n",
				uri.user.len, uri.user.s);
			return -1;
		}
		uac_param->proxy_uri.len = _l;
		uac_param->proxy_uri.s = p;
		memcpy(p, _s, _l);
		p += _l;
	}

	RX_L_S(m, line, UAC_AOR_URI_PARAM);
	if (parse_uri(_s, _l, &uri)<0) {
		LM_ERR("cannot parse aor uri [%.*s]\n", _l, _s);
		return -1;
	}
	uac_param->to_uri.len = _l;
	uac_param->to_uri.s = p;
	memcpy(p, _s, _l);
	p += _l;

	uac_param->hash_code = core_hash(&uac_param->to_uri, NULL, reg_hsize);

	RX_L_S(m, line, UAC_THIRD_PARTY_REGISTRANT_URI_PARAM);
	if (_l != 0) {
		if (parse_uri(_s, _l, &uri)<0) {
			LM_ERR("cannot parse third party registrant uri [%.*s]\n", _l, _s);
			return -1;
		}
		uac_param->from_uri.len = _l;
		uac_param->from_uri.s = p;
		memcpy(p, _s, _l);
		p += _l;
	}

	RX_L_S(m, line, UAC_CONTACT_URI_PARAM);
	if (parse_uri(_s, _l, &uri)<0) {
		LM_ERR("cannot parse contact uri [%.*s]\n", _l, _s);
		return -1;
	}
	uac_param->contact_uri.len = _l;
	uac_param->contact_uri.s = p;
	memcpy(p, _s, _l);
	p += _l;

	RX_L_S(m, line, UAC_AUTH_USER_PARAM);
	if (_l) {
		uac_param->auth_user.len = _l;
		uac_param->auth_user.s = p;
		memcpy(p, _s, _l);
		p += _l;
	}

	RX_L_S(m, line, UAC_AUTH_PASSWORD_PARAM);
	if (_l) {
		uac_param->auth_password.len = _l;
		uac_param->auth_password.s = p;
		memcpy(p, _s, _l);
		p += _l;
	}

	RX_L_S(m, line, UAC_CONTACT_PARAMS_PARAM);
	if (_l) {
		if (*p == ';') {
			LM_ERR("contact params must start with ';'\n");
			return -1;
		}
		uac_param->contact_params.len = _l;
		uac_param->contact_params.s = p;
		memcpy(p, _s, _l);
		p += _l;
	}

	RX_L_S(m, line, UAC_EXPIRES_PARAM);
	if (_l) {
		uac_param->expires.len = _l;
		uac_param->expires.s = p;
		memcpy(p, _s, _l);
		p += _l;
	}

	RX_L_S(m, line, UAC_FORCED_SOCKET_PARAM);
	if (_l) {
		if (parse_phostport(_s, _l, &host.s, &host.len, &port, &proto)<0) {
			LM_ERR("cannot parse forced socket [%.*s]\n", _l, _s);
			return -1;
		}
		uac_param->send_sock = grep_sock_info(&host,
					(unsigned short) port, (unsigned short) proto);
	}

	if (uac_params)
		uac_param->next = uac_params;
	uac_params = uac_param;

	return 0;
}


void shm_free_param(void* param) {shm_free(param);}

void reg_tm_cback(struct cell *t, int type, struct tmcb_params *ps)
{
	struct sip_msg *msg;
	reg_tm_cb_t *cb_param;
	int statuscode = 0;
	unsigned int exp = 0;
	reg_record_t *rec;
	struct hdr_field *c_ptr, *head_contact;
	struct uac_credential crd;
	contact_t *contact;
	struct authenticate_body *auth = NULL;
	static struct authenticate_nc_cnonce auth_nc_cnonce;
	HASHHEX response;
	str *new_hdr;
	time_t now;

	if(ps==NULL || ps->rpl==NULL) {
		LM_ERR("wrong ps parameter\n");
		return;
	}
	if(ps->param==NULL || *ps->param==NULL) {
		LM_ERR("null callback parameter\n");
		return;
	}
	cb_param = (reg_tm_cb_t *)*ps->param;
	if(cb_param->uac == NULL) {
		LM_ERR("null record\n");
		return;
	}
	statuscode = ps->code;
	now = time(0);
	LM_DBG("tm [%p] notification cb for %s [%d] reply at [%d]\n",
			t, (ps->rpl==FAKED_REPLY)?"FAKED_REPLY":"", statuscode, (unsigned int)now);

	if(statuscode<200) return;

	lock_get(&reg_htable[cb_param->hash_index].lock);
	rec = reg_htable[cb_param->hash_index].first;
	while(rec) {
		if (rec==cb_param->uac) {
			break;
		}
		rec = rec->next;
	}
	if(!rec) {
		LM_ERR("record [%p] not found on hash index [%d]\n",
		cb_param->uac, cb_param->hash_index);
		lock_release(&reg_htable[cb_param->hash_index].lock);
		return;
	}
	reg_print_record(rec);

	switch(statuscode) {
	case 200:
		msg = ps->rpl;
		if(msg==FAKED_REPLY) {
			LM_ERR("FAKED_REPLY\n");
			goto done;
		}
		if (parse_headers(msg, HDR_EOH_F, 0) == -1) {
			LM_ERR("failed to parse headers\n");
			goto done;
		}
		if (msg->contact) {
			c_ptr = msg->contact;
			while(c_ptr) {
				if (c_ptr->type == HDR_CONTACT_T) {
					if (!c_ptr->parsed && (parse_contact(c_ptr)<0)) {
						LM_ERR("failed to parse Contact body\n");
						goto done;
					}
				}
				c_ptr = c_ptr->next;
			}
		} else {
			LM_ERR("No contact header in received 200ok\n");
			goto done;
		}
		head_contact = msg->contact;
		contact = ((contact_body_t*)msg->contact->parsed)->contacts;
		while (contact) {
			/* Check for binding */
			if (contact->uri.len==rec->contact_uri.len &&
				strncmp(contact->uri.s,rec->contact_uri.s,contact->uri.len)==0){
				if (contact->expires && contact->expires->body.len) {
					if (str2int(&contact->expires->body, &exp)<0) {
						LM_ERR("Unable to extract expires from [%.*s]"
							" for binding [%.*s]\n",
							contact->expires->body.len,
							contact->expires->body.s,
							contact->uri.len, contact->uri.s);
					} else {
						rec->expires = exp;
					}
				}
				break;
			}
					
			/* get the next contact */
			if (contact->next == NULL) {
				contact = NULL;
				c_ptr = head_contact->next;
				while(c_ptr) {
					if (c_ptr->type == HDR_CONTACT_T) {
						head_contact = c_ptr;
						contact = ((contact_body_t*)c_ptr->parsed)->contacts;
						break;
					}
					c_ptr = c_ptr->next;
				}
			} else {
				contact = contact->next;
			}
		}
		rec->state = REGISTERED_STATE;
		rec->registration_timeout = now + rec->expires - timer_interval;
		break;

	case WWW_AUTH_CODE:
	case PROXY_AUTH_CODE:
		msg = ps->rpl;
		if(msg==FAKED_REPLY) {
			LM_ERR("FAKED_REPLY\n");
			goto done;
		}

		if (rec->auth_user.s==NULL || rec->auth_user.len==0 ||
			rec->auth_password.s==NULL || rec->auth_password.len==0) {
			LM_ERR("Credentials not provisioned\n");
			rec->state = WRONG_CREDENTIALS_STATE;
			rec->registration_timeout = 0;
			lock_release(&reg_htable[cb_param->hash_index].lock);
			return;
		}

		if (statuscode==WWW_AUTH_CODE) {
			if (0 == parse_www_authenticate_header(msg))
				auth = get_www_authenticate(msg);
		} else if (statuscode==PROXY_AUTH_CODE) {
			if (0 == parse_proxy_authenticate_header(msg))
				auth = get_proxy_authenticate(msg);
		}
		if (auth == NULL) {
			LM_ERR("Unable to extract authentication info\n");
			goto done;
		}
		LM_DBG("flags=[%d] realm=[%.*s] domain=[%.*s] nonce=[%.*s]"
			" opaque=[%.*s] qop=[%.*s]\n",
			auth->flags,
			auth->realm.len, auth->realm.s,
			auth->domain.len, auth->domain.s,
			auth->nonce.len, auth->nonce.s,
			auth->opaque.len, auth->opaque.s,
			auth->qop.len, auth->qop.s);

		switch(rec->state) {
		case REGISTERING_STATE:
			break;
		case AUTHENTICATING_STATE:
			/* We already sent an authenticated REGISTER and we are still challanged! */
			LM_ERR("Wrong credentials for \n");
			rec->state = WRONG_CREDENTIALS_STATE;
			rec->registration_timeout = 0;
			lock_release(&reg_htable[cb_param->hash_index].lock);
			return;
		default:
			LM_ERR("Unexpected [%d] notification cb in state [%d]\n",
				statuscode, rec->state);
			goto done;
		}

		/* perform authentication */
		if (auth->realm.s && auth->realm.len) {
			crd.realm.s = auth->realm.s; crd.realm.len = auth->realm.len;
		} else {
			LM_ERR("No realm found\n");
			goto done;
		}
		crd.user.s = rec->auth_user.s; crd.user.len = rec->auth_user.len;
		crd.passwd.s = rec->auth_password.s; crd.passwd.len = rec->auth_password.len;

		memset(&auth_nc_cnonce, 0, sizeof(struct authenticate_nc_cnonce));
		uac_auth_api._do_uac_auth(&register_method, &rec->td.rem_target, &crd,
					auth, &auth_nc_cnonce, response);
		new_hdr = uac_auth_api._build_authorization_hdr(statuscode, &rec->td.rem_target,
					&crd, auth, &auth_nc_cnonce, response);
		if (!new_hdr) {
			LM_ERR("failed to build authorization hdr\n");
			goto done;
		}
		if(send_register(cb_param->hash_index, rec, new_hdr)==1) {
			rec->state = AUTHENTICATING_STATE;
		} else {
			rec->state = INTERNAL_ERROR_STATE;
		}
		break;

	default:
		if(statuscode<400 && statuscode>=300) {
			LM_ERR("Redirection not implemented yet\n");
			rec->state = INTERNAL_ERROR_STATE;
		} else {
			/* we got an error from the server */
			rec->state = REGISTRAR_ERROR_STATE;
			rec->registration_timeout = now + rec->expires - timer_interval;
			
		}
	}

	lock_release(&reg_htable[cb_param->hash_index].lock);

	return;
done:
	rec->state = INTERNAL_ERROR_STATE;
	rec->registration_timeout = now + rec->expires;
	lock_release(&reg_htable[cb_param->hash_index].lock);
	return;
}


int send_register(unsigned int hash_index, reg_record_t *rec, str *auth_hdr)
{
	int result, expires_len;
	reg_tm_cb_t *cb_param;
	char *p, *expires;

	/* Allocate space for tm callback params */
	cb_param = shm_malloc(sizeof(reg_tm_cb_t));
	if (!cb_param) {
		LM_ERR("oom\n");
		return -1;
	}
	cb_param->hash_index = hash_index;
	cb_param->uac = rec;

	/* get the string version of expires */
	expires = int2str((unsigned long)(rec->expires), &expires_len);

	p = extra_hdrs.s;
	memcpy(p, contact_hdr.s, contact_hdr.len);
	p += contact_hdr.len;
	*p = '<'; p++;
	memcpy(p, rec->contact_uri.s, rec->contact_uri.len);
	p += rec->contact_uri.len;
	*p = '>'; p++;
	memcpy(p, rec->contact_params.s, rec->contact_params.len);
	p += rec->contact_params.len;
	if (1) {
		/* adding exiration time as a parameter */
		memcpy(p, expires_param.s, expires_param.len);
		p += expires_param.len;
	} else {
		/* adding exiration time as a header */
		memcpy(p, CRLF, CRLF_LEN); p += CRLF_LEN;
		memcpy(p, expires_hdr.s, expires_hdr.len);
		p += expires_hdr.len;
	}
	memcpy(p, expires, expires_len);
	p += expires_len;
	memcpy(p, CRLF, CRLF_LEN); p += CRLF_LEN;

	if (auth_hdr) {
		memcpy(p, auth_hdr->s, auth_hdr->len);
		p += auth_hdr->len;
	}
	extra_hdrs.len = (int)(p - extra_hdrs.s);

	LM_DBG("extra_hdrs=[%p][%d]->[%.*s]\n",
		extra_hdrs.s, extra_hdrs.len, extra_hdrs.len, extra_hdrs.s);

	result=tmb.t_request_within(
		&register_method,	/* method */
		&extra_hdrs,		/* extra headers*/
		NULL,			/* body */
		&rec->td,		/* dialog structure*/
		reg_tm_cback,		/* callback function */
		(void *)cb_param,	/* callback param */
		shm_free_param);	/* function to release the parameter */
	LM_DBG("result=[%d]\n", result);
	return result;
}


void timer_check(unsigned int ticks, void* param)
{
	unsigned int i=hash_index;
	reg_record_t *rec;
	char *p;
	int len;
	time_t now;
	str str_now = {NULL, 0};

	now = time(0);

	p = int2str((unsigned long)(time(0)), &len);
	if (p && len>0) {
		str_now.s = (char *)pkg_malloc(len);
		if (str_now.s) {
			memcpy(str_now.s, p, len);
			str_now.len = len;
		} else {
			LM_ERR("oom\n");
			return;
		}
	}

	lock_get(&reg_htable[i].lock);
	//LM_DBG("checking ... [%d] on htable[%d]\n", (unsigned int)now, i);
	rec = reg_htable[i].first;
	while (rec) {
		switch(rec->state){
		case REGISTERING_STATE:
		case AUTHENTICATING_STATE:
		case WRONG_CREDENTIALS_STATE:
			break;
		case REGISTER_TIMEOUT_STATE:
		case INTERNAL_ERROR_STATE:
		case REGISTRAR_ERROR_STATE:
			reg_print_record(rec);
			new_call_id_ftag_4_record(rec, &str_now);
			if(send_register(i, rec, NULL)==1) {
				rec->last_register_sent = now;
				rec->state = REGISTERING_STATE;
			} else {
				rec->registration_timeout = now + rec->expires - timer_interval;
				rec->state = INTERNAL_ERROR_STATE;
			}
			break;
		case REGISTERED_STATE:
			/* check if we need to re-register */
			if (now < rec->registration_timeout) {
				break;
			}
		case NOT_REGISTERED_STATE:
			if(send_register(i, rec, NULL)==1) {
				rec->last_register_sent = now;
				rec->state = REGISTERING_STATE;
			} else {
				rec->registration_timeout = now + rec->expires - timer_interval;
				rec->state = INTERNAL_ERROR_STATE;
			}
			break;
		default:
			LM_ERR("Unexpected state [%d] for rec [%p]\n", rec->state, rec);
		}
		rec = rec->next;
	}
	lock_release(&reg_htable[i].lock);

	if (str_now.s) {pkg_free(str_now.s);}

	hash_index = (++i)%reg_hsize;

	return;
}


static struct mi_root* mi_reg_list(struct mi_root* cmd, void* param)
{
	struct mi_root *rpl_tree;
	struct mi_node *rpl=NULL, *node, *node1;
	struct mi_attr* attr;
	reg_record_t *rec;
	int i, len;
	char* p;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==NULL) return NULL;
	rpl = &rpl_tree->node;

	for(i = 0; i< reg_hsize; i++) {
		lock_get(&reg_htable[i].lock);
		rec = reg_htable[i].first;
		while (rec) {
			node = add_mi_node_child(rpl, MI_DUP_VALUE, "AOR", 3,
					rec->td.rem_uri.s, rec->td.rem_uri.len);
			if(node == NULL) goto error;
			p = int2str(rec->state, &len);
			attr = add_mi_attr(node, MI_DUP_VALUE, "state", 5, p, len);
			if(attr == NULL) goto error;
			p = int2str(rec->expires, &len);
			attr = add_mi_attr(node, MI_DUP_VALUE, "expires", 7, p, len);
			if(attr == NULL) goto error;
			p = int2str((unsigned int)rec->last_register_sent, &len);
			attr = add_mi_attr(node, MI_DUP_VALUE, "last_register_sent", 18, p, len);
                        if(attr == NULL) goto error;
			p = int2str((unsigned int)rec->registration_timeout, &len);
			attr = add_mi_attr(node, MI_DUP_VALUE, "registration_timeout", 20, p, len);
                        if(attr == NULL) goto error;

			node1 = add_mi_node_child(node, MI_DUP_VALUE, "registrar", 9,
					rec->td.rem_target.s, rec->td.rem_target.len);
			if(node1 == NULL) goto error;

			node1 = add_mi_node_child(node, MI_DUP_VALUE, "binding", 7,
					rec->contact_uri.s, rec->contact_uri.len);
			if(node1 == NULL) goto error;

			if(rec->td.loc_uri.s != rec->td.rem_uri.s) {
				node1 = add_mi_node_child(node, MI_DUP_VALUE,
						"third_party_registrant", 12,
						rec->td.loc_uri.s, rec->td.loc_uri.len);
				if(node1 == NULL) goto error;
			}

			if (rec->td.obp.s && rec->td.obp.len) {
				node1 = add_mi_node_child(node, MI_DUP_VALUE,
						"proxy", 5, rec->td.obp.s, rec->td.obp.len);
				if(node1 == NULL) goto error;
			}

			rec = rec->next;
		}
		lock_release(&reg_htable[i].lock);
	}
	return rpl_tree;
error:
	lock_release(&reg_htable[i].lock);
	LM_ERR("Unable to create reply\n");
	free_mi_tree(rpl_tree);
	return NULL;
}

