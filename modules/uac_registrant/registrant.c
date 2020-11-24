/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2011-02-11  initial version (Ovidiu Sas)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../sr_module.h"
#include "../../timer.h"
#include "../../db/db.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_authenticate.h"
#include "../../parser/contact/parse_contact.h"
#include "../../parser/parse_min_expires.h"
#include "../uac_auth/uac_auth.h"
#include "reg_records.h"
#include "reg_db_handler.h"
#include "clustering.h"


#define UAC_REGISTRAR_URI_PARAM              1
#define UAC_PROXY_URI_PARAM                  2
#define UAC_AOR_URI_PARAM                    3
#define UAC_THIRD_PARTY_REGISTRANT_URI_PARAM 4
#define UAC_AUTH_USER_PARAM                  5
#define UAC_AUTH_PASSWORD_PARAM              6
#define UAC_CONTACT_URI_PARAM                7
#define UAC_CONTACT_PARAMS_PARAM             8
#define UAC_EXPIRES_PARAM                    9
#define UAC_FORCED_SOCKET_PARAM             10
#define UAC_MAX_PARAMS_NO                   11

#define UAC_REG_NOT_REGISTERED_STATE    "NOT_REGISTERED_STATE"
#define UAC_REG_REGISTERING_STATE       "REGISTERING_STATE"
#define UAC_REG_AUTHENTICATING_STATE    "AUTHENTICATING_STATE"
#define UAC_REG_REGISTERED_STATE        "REGISTERED_STATE"
#define UAC_REG_REGISTER_TIMEOUT_STATE  "REGISTER_TIMEOUT_STATE"
#define UAC_REG_INTERNAL_ERROR_STATE    "INTERNAL_ERROR_STATE"
#define UAC_REG_WRONG_CREDENTIALS_STATE "WRONG_CREDENTIALS_STATE"
#define UAC_REG_REGISTRAR_ERROR_STATE   "REGISTRAR_ERROR_STATE"
#define UAC_REG_UNREGISTERING_STATE		"UNREGISTERING_STATE"
#define UAC_REG_AUTHENTICATING_UNREGISTER_STATE	"AUTHENTICATING_UNREGISTER_STATE"

const str uac_reg_state[]={
	str_init(UAC_REG_NOT_REGISTERED_STATE),
	str_init(UAC_REG_REGISTERING_STATE),
	str_init(UAC_REG_AUTHENTICATING_STATE),
	str_init(UAC_REG_REGISTERED_STATE),
	str_init(UAC_REG_REGISTER_TIMEOUT_STATE),
	str_init(UAC_REG_INTERNAL_ERROR_STATE),
	str_init(UAC_REG_WRONG_CREDENTIALS_STATE),
	str_init(UAC_REG_REGISTRAR_ERROR_STATE),
	str_init(UAC_REG_UNREGISTERING_STATE),
	str_init(UAC_REG_AUTHENTICATING_UNREGISTER_STATE),
};

/** Functions declarations */
static int mod_init(void);
static void mod_destroy(void);
static int child_init(int rank);

void timer_check(unsigned int ticks, void* hash_counter);
void handle_shtag_change(str *tag_name, int state, int c_id, void *param);

static mi_response_t *mi_reg_list(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_reg_reload(const mi_params_t *params,
								struct mi_handler *async_hdl);
int send_register(unsigned int hash_index, reg_record_t *rec, str *auth_hdr);
int send_unregister(unsigned int hash_index, reg_record_t *rec, str *auth_hdr);


/** Global variables */

uac_auth_api_t uac_auth_api;

unsigned int default_expires = 3600;
unsigned int timer_interval = 100;

reg_table_t reg_htable = NULL;
unsigned int reg_hsize = 1;

static str db_url = {NULL, 0};

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

/** Exported parameters */
static param_export_t params[]= {
	{"hash_size",		INT_PARAM,			&reg_hsize},
	{"default_expires",	INT_PARAM,			&default_expires},
	{"timer_interval",	INT_PARAM,			&timer_interval},
	{"enable_clustering",	INT_PARAM,			&enable_clustering},
	{"db_url",		STR_PARAM,			&db_url.s},
	{"table_name",		STR_PARAM,			&reg_table_name.s},
	{"registrar_column",	STR_PARAM,			&registrar_column.s},
	{"proxy_column",	STR_PARAM,			&proxy_column.s},
	{"aor_column",		STR_PARAM,			&aor_column.s},
	{"third_party_registrant_column",STR_PARAM,&third_party_registrant_column.s},
	{"username_column",	STR_PARAM,		&username_column.s},
	{"password_column",	STR_PARAM,		&password_column.s},
	{"binding_URI_column",	STR_PARAM,		&binding_URI_column.s},
	{"binding_params_column",	STR_PARAM,	&binding_params_column.s},
	{"expiry_column",	STR_PARAM,		&expiry_column.s},
	{"forced_socket_column",	STR_PARAM,	&forced_socket_column.s},
	{"cluster_shtag_column",	STR_PARAM,	&cluster_shtag_column.s},
	{0,0,0}
};


/** MI commands */
static mi_export_t mi_cmds[] = {
	{ "reg_list", 0, 0, 0, {
		{mi_reg_list, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "reg_reload", 0, 0, 0, {
		{mi_reg_reload, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm",       DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "uac_auth", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "enable_clustering", get_deps_clusterer},
		{ NULL, NULL },
	},
};

/** Module interface */
struct module_exports exports= {
	"uac_registrant",		/* module name */
	MOD_TYPE_DEFAULT,       /* class of this module */
	MODULE_VERSION,			/* module version */
	DEFAULT_DLFLAGS,		/* dlopen flags */
	0,						/* load function */
	&deps,					/* OpenSIPS module dependencies */
	0,					/* exported functions */
	0,					/* exported async functions */
	params,				/* exported parameters */
	NULL,				/* exported statistics */
	mi_cmds,			/* exported MI functions */
	NULL,				/* exported pseudo-variables */
	0,					/* exported transformations */
	0,					/* extra processes */
	0,					/* module pre-initialization function */
	mod_init,			/* module initialization function */
	(response_function) NULL,	/* response handling function */
	(destroy_function) mod_destroy,	/* destroy function */
	child_init,			/* per-child init function */
	0					/* reload confirm function */
};


/** Module init function */
static int mod_init(void)
{
	unsigned int _timer;
	int *param;

	if(load_uac_auth_api(&uac_auth_api)<0){
		LM_ERR("Failed to load uac_auth api\n");
		return -1;
	}

	/* load all TM stuff */
	if(load_tm_api(&tmb)==-1) {
		LM_ERR("can't load tm functions\n");
		return -1;
	}

	if (enable_clustering && ureg_init_cluster( handle_shtag_change )<0) {
		LM_ERR("failed to initialized clustering support\n");
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

	reg_table_name.len = strlen(reg_table_name.s);
	registrar_column.len = strlen(registrar_column.s);
	proxy_column.len = strlen(proxy_column.s);
	aor_column.len = strlen(aor_column.s);
	third_party_registrant_column.len =
		strlen(third_party_registrant_column.s);
	username_column.len = strlen(username_column.s);
	password_column.len = strlen(password_column.s);
	binding_URI_column.len = strlen(binding_URI_column.s);
	binding_params_column.len = strlen(binding_params_column.s);
	expiry_column.len = strlen(expiry_column.s);
	forced_socket_column.len = strlen(forced_socket_column.s);
	cluster_shtag_column.len = strlen(cluster_shtag_column.s);
	init_db_url(db_url , 0 /*cannot be null*/);
	if (init_reg_db(&db_url) != 0) {
		LM_ERR("failed to initialize the DB support\n");
		return -1;
	}

	/* allocate a shm variable to keep the counter used by the timer
	 * routine - it must be shared as the routine get executed
	 * in different processes */
	if (NULL==(param=(int*) shm_malloc(sizeof(int)))) {
		LM_ERR("cannot allocate shm memory for keepalive counter\n");
		return -1;
	}
	*param = 0;

	_timer = timer_interval/reg_hsize;
	if (_timer) {
		register_timer("uac_reg_check", timer_check, (void*)(long)param, _timer,
			TIMER_FLAG_DELAY_ON_DELAY);
	} else {
		LM_ERR("timer_interval=[%d] MUST be bigger then reg_hsize=[%d]\n",
			timer_interval, reg_hsize);
		return -1;
	}

	return 0;
}


static void mod_destroy(void)
{
	destroy_reg_htable();

	LM_DBG("done\n");
	return;
}

static int child_init(int rank)
{
	if (db_url.s != NULL && connect_reg_db(&db_url)) {
		LM_ERR("failed to connect to db (rank=%d)\n",rank);
		return -1;
	}
	return 0;
}


struct reg_tm_cback_data {
	struct cell *t;
	struct tmcb_params *ps;
	time_t now;
	reg_tm_cb_t *cb_param;
};

int run_reg_tm_cback(void *e_data, void *data, void *r_data)
{
	struct sip_msg *msg;
	str msg_body;
	int statuscode = 0;
	unsigned int exp = 0;
	unsigned int bindings_counter = 0;
	reg_record_t *rec = (reg_record_t*)e_data;
	struct hdr_field *c_ptr, *head_contact;
	struct uac_credential crd;
	contact_t *contact;
	struct authenticate_body *auth = NULL;
	static struct authenticate_nc_cnonce auth_nc_cnonce;
	HASHHEX response;
	str *new_hdr;
	struct reg_tm_cback_data *tm_cback_data = (struct reg_tm_cback_data*)data;
	struct cell *t;
	struct tmcb_params *ps;
	time_t now;
	reg_tm_cb_t *cb_param;

	cb_param = tm_cback_data->cb_param;
	if (rec!=cb_param->uac) {
		/* no action on current list elemnt */
		return 0; /* continue list traversal */
	}

	t = tm_cback_data->t;
	ps = tm_cback_data->ps;
	now = tm_cback_data->now;

	reg_print_record(rec);

	if (ps->rpl==FAKED_REPLY)
		memset(&rec->td.forced_to_su, 0, sizeof(union sockaddr_union));
	else if (rec->td.forced_to_su.s.sa_family == AF_UNSPEC)
		rec->td.forced_to_su = t->uac[0].request.dst.to;

	statuscode = ps->code;
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
			switch(rec->state) {
			case UNREGISTERING_STATE:
			case AUTHENTICATING_UNREGISTER_STATE:
				if(send_register(cb_param->hash_index, rec, NULL)==1) {
					rec->last_register_sent = now;
					rec->state = REGISTERING_STATE;
				} else {
					rec->registration_timeout = now + rec->expires - timer_interval;
					rec->state = INTERNAL_ERROR_STATE;
				}
				break;
			default:
				LM_ERR("No contact header in received 200ok in state [%d]\n",
					rec->state);
				goto done;
			}
			break; /* done with 200ok handling */
		}

		if (rec->flags&FORCE_SINGLE_REGISTRATION) {
			head_contact = msg->contact;
			contact = ((contact_body_t*)msg->contact->parsed)->contacts;
			while (contact) {
				bindings_counter++;
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
			if (bindings_counter>1) {
				LM_DBG("got [%d] bindings\n", bindings_counter);
				if(send_unregister(cb_param->hash_index, rec, NULL)==1) {
					rec->state = UNREGISTERING_STATE;
				} else {
					rec->state = INTERNAL_ERROR_STATE;
				}
				break;
			}
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
		if (exp) rec->expires = exp;
		if (rec->expires <= timer_interval) {
			LM_ERR("Please decrease timer_interval=[%u]"
				" - imposed server expires [%u] to small for AOR=[%.*s]\n",
				timer_interval, rec->expires,
				rec->td.rem_uri.len, rec->td.rem_uri.s);
		}
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
			/* action successfully completed on current list element */
			return 1; /* exit list traversal */
		}

		if (statuscode==WWW_AUTH_CODE) {
			parse_www_authenticate_header(msg, &auth);
		} else if (statuscode==PROXY_AUTH_CODE) {
			parse_proxy_authenticate_header(msg, &auth);
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
		case UNREGISTERING_STATE:
			break;
		case AUTHENTICATING_STATE:
		case AUTHENTICATING_UNREGISTER_STATE:
			/* We already sent an authenticated REGISTER and we are still challanged! */
			LM_WARN("Wrong credentials for [%.*s]\n",
				rec->td.rem_uri.len, rec->td.rem_uri.s);
			rec->state = WRONG_CREDENTIALS_STATE;
			rec->registration_timeout = 0;
			/* action successfully completed on current list element */
			return 1; /* exit list traversal */
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

		if ((auth->flags & QOP_AUTH_INT) && get_body(msg, &msg_body) < 0) {
			LM_ERR("Failed to get message body\n");
			goto done;
		}

		memset(&auth_nc_cnonce, 0, sizeof(struct authenticate_nc_cnonce));
		uac_auth_api._do_uac_auth(&msg_body, &register_method,
					&rec->td.rem_target, &crd, auth, &auth_nc_cnonce, response);
		new_hdr = uac_auth_api._build_authorization_hdr(statuscode, &rec->td.rem_target,
					&crd, auth, &auth_nc_cnonce, response);
		if (!new_hdr) {
			LM_ERR("failed to build authorization hdr\n");
			goto done;
		}
		switch(rec->state) {
		case REGISTERING_STATE:
			if(send_register(cb_param->hash_index, rec, new_hdr)==1) {
				rec->state = AUTHENTICATING_STATE;
			} else {
				rec->state = INTERNAL_ERROR_STATE;
			}
			break;
		case UNREGISTERING_STATE:
			if(send_unregister(cb_param->hash_index, rec, new_hdr)==1) {
				rec->state = AUTHENTICATING_UNREGISTER_STATE;
			} else {
				rec->state = INTERNAL_ERROR_STATE;
			}
			break;
		default:
			LM_ERR("Unexpected [%d] notification cb in state [%d]\n",
				statuscode, rec->state);
			goto done;
		}
		pkg_free(new_hdr->s);
		new_hdr->s = NULL; new_hdr->len = 0;
		break;

	case 423: /* Interval Too Brief */
		msg = ps->rpl;
		if(msg==FAKED_REPLY) {
			LM_ERR("FAKED_REPLY\n");
			goto done;
		}
		if (0 == parse_min_expires(msg)) {
			rec->expires = (unsigned int)(long)msg->min_expires->parsed;
			if(send_register(cb_param->hash_index, rec, NULL)==1)
				rec->state = REGISTERING_STATE;
			else
				rec->state = INTERNAL_ERROR_STATE;
		} else {
			rec->state = REGISTRAR_ERROR_STATE;
			rec->registration_timeout = now + rec->expires - timer_interval;
		}
		break;

	case 408: /* Interval Too Brief */
		rec->state = REGISTER_TIMEOUT_STATE;
		rec->registration_timeout = now + rec->expires - timer_interval;
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

	/* action successfully completed on current list element */
	return 1; /* exit list traversal */
done:
	rec->state = INTERNAL_ERROR_STATE;
	rec->registration_timeout = now + rec->expires;
	return -1; /* exit list traversal */
}



void reg_tm_cback(struct cell *t, int type, struct tmcb_params *ps)
{
	reg_tm_cb_t *cb_param;
	int statuscode = 0;
	int ret;
	time_t now;
	struct reg_tm_cback_data tm_cback_data;

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
			t, (ps->rpl==FAKED_REPLY)?"FAKED_REPLY":"",
			statuscode, (unsigned int)now);

	if(statuscode<200) return;

	/* Initialize slinkedl run traversal data */
	tm_cback_data.t = t;
    tm_cback_data.ps = ps;
    tm_cback_data.cb_param = cb_param;
	tm_cback_data.now = now;

	lock_get(&reg_htable[cb_param->hash_index].lock);
	ret = slinkedl_traverse(reg_htable[cb_param->hash_index].p_list,
						&run_reg_tm_cback, (void*)&tm_cback_data, NULL);
	lock_release(&reg_htable[cb_param->hash_index].lock);

	if (ret==0) {
		LM_ERR("record [%p] not found on hash index [%d]\n",
		cb_param->uac, cb_param->hash_index);
	}

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
		osips_shm_free);	/* function to release the parameter */

	if (result < 1)
		shm_free(cb_param);

	LM_DBG("result=[%d]\n", result);
	return result;
}

int send_unregister(unsigned int hash_index, reg_record_t *rec, str *auth_hdr)
{
	int result;
	reg_tm_cb_t *cb_param;
	char *p;

	/* Allocate space for tm callback params */
	cb_param = shm_malloc(sizeof(reg_tm_cb_t));
	if (!cb_param) {
		LM_ERR("oom\n");
		return -1;
	}
	cb_param->hash_index = hash_index;
	cb_param->uac = rec;

	p = extra_hdrs.s;
	memcpy(p, contact_hdr.s, contact_hdr.len);
	p += contact_hdr.len;
	*p = '*'; p++;
	memcpy(p, CRLF, CRLF_LEN); p += CRLF_LEN;

	/* adding exires header */
	memcpy(p, expires_hdr.s, expires_hdr.len);
	p += expires_hdr.len;
	*p = '0'; p++;
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
		osips_shm_free);	/* function to release the parameter */

	if (result < 1)
		shm_free(cb_param);

	LM_DBG("result=[%d]\n", result);
	return result;
}

struct timer_check_data {
	time_t now;
	str *s_now;
	int hash_counter;
};

int run_timer_check(void *e_data, void *data, void *r_data)
{
	reg_record_t *rec = (reg_record_t*)e_data;
	struct timer_check_data *t_check_data = (struct timer_check_data*)data;
	time_t now = t_check_data->now;
	str *s_now = t_check_data->s_now;
	unsigned int i = t_check_data->hash_counter;

	if (!ureg_cluster_shtag_is_active( &rec->cluster_shtag, rec->cluster_id))
		return 0;

	switch(rec->state){
	case REGISTERING_STATE:
	case UNREGISTERING_STATE:
	case AUTHENTICATING_STATE:
	case AUTHENTICATING_UNREGISTER_STATE:
		break;
	case WRONG_CREDENTIALS_STATE:
	case REGISTER_TIMEOUT_STATE:
	case INTERNAL_ERROR_STATE:
	case REGISTRAR_ERROR_STATE:
		reg_print_record(rec);
		new_call_id_ftag_4_record(rec, s_now);
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

	return 0; /* continue list traversal */
}


void timer_check(unsigned int ticks, void* hash_counter)
{
	unsigned int i=*(unsigned*)(unsigned long*)hash_counter;
	char *p;
	int len, ret;
	time_t now;
	str str_now = {NULL, 0};
	struct timer_check_data t_check_data;

	now = time(0);
	*(unsigned*)(unsigned long*)hash_counter = (i+1)%reg_hsize;

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

	/* Initialize slinkedl run traversal data */
	t_check_data.now = now;
	t_check_data.s_now = &str_now;
	t_check_data.hash_counter = i;

	LM_DBG("checking ... [%d] on htable[%d]\n", (unsigned int)now, i);
	lock_get(&reg_htable[i].lock);
	ret = slinkedl_traverse(reg_htable[i].p_list, &run_timer_check,
							(void*)&t_check_data, NULL);
	if (ret<0) LM_CRIT("Unexpected return code %d\n", ret);
	lock_release(&reg_htable[i].lock);

	if (str_now.s) {pkg_free(str_now.s);}

	return;
}


struct shtag_check_data {
	str *tag;
	int c_id;
};

static int cluster_shtag_check(void *e_data, void *data, void *r_data)
{
	reg_record_t *rec = (reg_record_t*)e_data;
	struct shtag_check_data *shtag_data = (struct shtag_check_data*)data;

	LM_DBG("checking record with cluster_id [%d] and shtag [%.*s]\n",
		rec->cluster_id, rec->cluster_shtag.len, rec->cluster_shtag.s);
	if (rec->cluster_id==shtag_data->c_id &&
		rec->cluster_shtag.s && rec->cluster_shtag.len &&
		rec->cluster_shtag.len==shtag_data->tag->len &&
		0==memcmp(rec->cluster_shtag.s, shtag_data->tag->s, shtag_data->tag->len)) {
		/* this record matches the shtag + cluster_id, so we need to de-active it */
		LM_DBG("Moving record to NOT_REGISTERED_STATE\n");
		rec->state = NOT_REGISTERED_STATE;
	}


	return 0;
}


void handle_shtag_change(str *tag_name, int state, int c_id, void *param)
{
	struct shtag_check_data shtag_data;
	int ret, i;

	if (state!=SHTAG_STATE_BACKUP)
		return;

	shtag_data.c_id = c_id;
	shtag_data.tag = tag_name;

	/* a shatg in cluster became backup on local node-> check if
	 * one of our uac reg depends on it */
	LM_DBG("checking for shtag [%.*s] in cluster [%d]\n",
		shtag_data.tag->len, shtag_data.tag->s, shtag_data.c_id);

	for( i=0 ; i<reg_hsize ; i++) {

		lock_get(&reg_htable[i].lock);
		ret = slinkedl_traverse(reg_htable[i].p_list, &cluster_shtag_check,
							(void*)&shtag_data, NULL);
		if (ret<0) LM_CRIT("Unexpected return code %d\n", ret);
		lock_release(&reg_htable[i].lock);

	}
}


/*** MI **/
int run_mi_reg_list(void *e_data, void *data, void *r_data)
{
	reg_record_t *rec = (reg_record_t*)e_data;
	int len;
	char* p;
	char cbuf[26];
	struct ip_addr addr;
	mi_item_t *records_arr = (mi_item_t *)data;
	mi_item_t *record_item;

	record_item = add_mi_object(records_arr, NULL, 0);
	if (!record_item)
		goto error;

	if (add_mi_string(record_item, MI_SSTR("AOR"),
		rec->td.rem_uri.s, rec->td.rem_uri.len) < 0)
		goto error;

	if (add_mi_number(record_item, MI_SSTR("expires"), rec->expires) < 0)
		goto error;

	if (add_mi_string(record_item, MI_SSTR("state"),
		uac_reg_state[rec->state].s, uac_reg_state[rec->state].len) < 0)
		goto error;

	ctime_r(&rec->last_register_sent, cbuf);
	if (add_mi_string(record_item, MI_SSTR("last_register_sent"),
		cbuf, strlen(cbuf) - 1) < 0)
		goto error;

	ctime_r(&rec->registration_timeout, cbuf);
	if (add_mi_string(record_item, MI_SSTR("registration_t_out"),
		cbuf, strlen(cbuf) - 1) < 0)
		goto error;

	if (add_mi_string(record_item, MI_SSTR("registrar"),
		rec->td.rem_target.s, rec->td.rem_target.len) < 0)
		goto error;

	if (add_mi_string(record_item, MI_SSTR("binding"),
		rec->contact_uri.s, rec->contact_uri.len) < 0)
		goto error;

	if(rec->contact_params.s && rec->contact_params.len)
		if (add_mi_string(record_item, MI_SSTR("binding_params"),
			rec->contact_params.s, rec->contact_params.len) < 0)
			goto error;

	if(rec->td.loc_uri.s != rec->td.rem_uri.s)
		if (add_mi_string(record_item, MI_SSTR("third_party_registrant"),
			rec->td.loc_uri.s, rec->td.loc_uri.len) < 0)
			goto error;

	if (rec->td.obp.s && rec->td.obp.len)
		if (add_mi_string(record_item, MI_SSTR("proxy"),
			rec->td.obp.s, rec->td.obp.len) < 0)
			goto error;

	switch(rec->td.forced_to_su.s.sa_family) {
	case AF_UNSPEC:
		break;
	case AF_INET:
	case AF_INET6:
		if (add_mi_string(record_item, MI_SSTR("dst_IP"),
			(rec->td.forced_to_su.s.sa_family==AF_INET)?"IPv4":"IPv6", 4) < 0)
			goto error;
		sockaddr2ip_addr(&addr, &rec->td.forced_to_su.s);
		p = ip_addr2a(&addr);
		if (p == NULL) goto error;
		len = strlen(p);
		if (add_mi_string(record_item, MI_SSTR("ip"), p, len) < 0)
			goto error;
		break;
	default:
		LM_ERR("unexpected sa_family [%d]\n", rec->td.forced_to_su.s.sa_family);
		if (add_mi_string(record_item, MI_SSTR("dst_IP"), "Error", 5) < 0)
			goto error;

		if (add_mi_number(record_item, MI_SSTR("sa_family"),
			rec->td.forced_to_su.s.sa_family) < 0)
			goto error;
	}

	if (rec->cluster_shtag.s && rec->cluster_shtag.len) {
		if (add_mi_string(record_item, MI_SSTR("shtag"),
			rec->cluster_shtag.s, rec->cluster_shtag.len) < 0)
			goto error;
		if (add_mi_number(record_item, MI_SSTR("cluster_id"), rec->cluster_id) < 0)
			goto error;
		}

	/* action successfully completed on current list element */
	return 0; /* continue list traversal */

error:
	LM_ERR("Unable to create reply\n");
	return -1; /* exit list traversal */
}


static mi_response_t *mi_reg_list(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int i, ret;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *records_arr;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	records_arr = add_mi_array(resp_obj, MI_SSTR("Records"));
	if (!records_arr)
		goto error;

	for(i=0; i<reg_hsize; i++) {
		lock_get(&reg_htable[i].lock);
		ret = slinkedl_traverse(reg_htable[i].p_list,
						&run_mi_reg_list, (void*)records_arr, NULL);
		lock_release(&reg_htable[i].lock);
		if (ret<0) {
			LM_ERR("Unable to create reply\n");
			goto error;
		}
	}

	return resp;

error:
	free_mi_response(resp);
	return NULL;
}

int run_compare_rec(void *e_data, void *data, void *r_data)
{
	reg_record_t *old_rec = (reg_record_t*)e_data;
	reg_record_t *new_rec = (reg_record_t*)data;

	if ((old_rec->state == REGISTERED_STATE) &&
	    (str_strcmp(&old_rec->td.rem_uri, &new_rec->td.rem_uri) == 0)) {
		memcpy(new_rec->td.id.call_id.s, old_rec->td.id.call_id.s,
		    new_rec->td.id.call_id.len);
		memcpy(new_rec->td.id.loc_tag.s, old_rec->td.id.loc_tag.s,
		    new_rec->td.id.loc_tag.len);
		new_rec->td.loc_seq.value = old_rec->td.loc_seq.value;
		new_rec->last_register_sent = old_rec->last_register_sent;
		new_rec->registration_timeout = old_rec->registration_timeout;
		new_rec->state = old_rec->state;
	}
	return 0;
}

int run_find_same_rec(void *e_data, void *data, void *r_data)
{
	reg_record_t *new_rec = (reg_record_t*)e_data;
	int i = *(int*)data;

	slinkedl_traverse(reg_htable[i].p_list, &run_compare_rec, new_rec, NULL);
	return 0;
}

static mi_response_t *mi_reg_reload(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int i;
	int err = 0;

	for(i=0; i<reg_hsize; i++) {
		lock_get(&reg_htable[i].lock);
		if (reg_htable[i].s_list!=NULL) {
			LM_ERR("Found non NULL s_list\n");
			slinkedl_list_destroy(reg_htable[i].s_list);
			reg_htable[i].s_list = NULL;
		}
		reg_htable[i].s_list = slinkedl_init(&reg_alloc, &reg_free);
		if (reg_htable[i].p_list == NULL) {
			LM_ERR("oom while allocating list\n");
			err = 1;
		}
		lock_release(&reg_htable[i].lock);
		if (err) goto error;
	}
	/* Load registrants into the secondary list */
	if(load_reg_info_from_db(1) !=0){
		LM_ERR("unable to reload the registrant data\n");
		goto error;
	}
	/* Swap the lists: secondary will become primary */
	for(i=0; i<reg_hsize; i++) {
		lock_get(&reg_htable[i].lock);

		slinkedl_traverse(reg_htable[i].s_list, &run_find_same_rec, &i, NULL);

		slinkedl_list_destroy(reg_htable[i].p_list);
		reg_htable[i].p_list = reg_htable[i].s_list;
		reg_htable[i].s_list = NULL;
		lock_release(&reg_htable[i].lock);
	}

	return init_mi_result_ok();

error:
	for(i=0; i<reg_hsize; i++) {
		lock_get(&reg_htable[i].lock);
		if (reg_htable[i].s_list) slinkedl_list_destroy(reg_htable[i].s_list);
		reg_htable[i].s_list = NULL;
		lock_release(&reg_htable[i].lock);
	}
	return NULL;
}

