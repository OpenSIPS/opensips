/*
 * pua module - presence user agent module
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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
 *  2006-11-29  initial version (Anca Vamanu)
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <time.h>

#include "../../sr_module.h"
#include "../../parser/parse_expires.h"
#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../parser/msg_parser.h"
#include "../../str.h"
#include "../../mem/mem.h"
#include "../../pt.h"
#include "../../db/db.h"
#include "../tm/tm_load.h"
#include "../presence/hash.h"
#include "pua.h"
#include "send_publish.h"
#include "send_subscribe.h"
#include "pua_bind.h"
#include "pua_callback.h"
#include "event_list.h"
#include "add_events.h"
#include "pidf.h"


#define PUA_TABLE_VERSION 8

struct tm_binds tmb;
htable_t* HashT= NULL;
int HASH_SIZE= -1;
extern int bind_pua(pua_api_t* api);
int min_expires= 300;
int default_expires=3600;
static str db_url = {NULL, 0};
str db_table= str_init("pua");
int update_period= 100;
pua_event_t* pua_evlist= NULL;

/* database connection */
db_con_t *pua_db = NULL;
db_func_t pua_dbf;

/* database colums */
static str str_pres_uri_col = str_init("pres_uri");
static str str_to_uri_col   = str_init("to_uri");
static str str_pres_id_col = str_init("pres_id");
static str str_expires_col= str_init("expires");
static str str_flag_col= str_init("flag");
static str str_etag_col= str_init("etag");
static str str_tuple_id_col= str_init("tuple_id");
static str str_watcher_uri_col= str_init("watcher_uri");
static str str_call_id_col= str_init("call_id");
static str str_to_tag_col= str_init("to_tag");
static str str_from_tag_col= str_init("from_tag");
static str str_cseq_col= str_init("cseq");
static str str_event_col= str_init("event");
static str str_record_route_col= str_init("record_route");
static str str_contact_col= str_init("contact");
static str str_remote_contact_col= str_init("remote_contact");
static str str_extra_headers_col= str_init("extra_headers");
static str str_desired_expires_col= str_init("desired_expires");
static str str_version_col = str_init("version");

/* module functions */

static int mod_init(void);
static int child_init(int);
static void destroy(void);

static int update_pua(ua_pres_t* p, unsigned int hash_code, unsigned int final);

static int db_restore(void);
static void db_update(unsigned int ticks,void *param);
static void hashT_clean(unsigned int ticks,void *param);

static cmd_export_t cmds[]=
{
	{"bind_libxml_api",         (cmd_function)bind_libxml_api,  1, 0, 0, 0},
	{"bind_pua",                (cmd_function)bind_pua,         1, 0, 0, 0},
	{"pua_update_contact",      (cmd_function)update_contact,   0, 0, 0, REQUEST_ROUTE},
	{0,                         0,                              0, 0, 0, 0}
};

static param_export_t params[]={
	{"hash_size" ,       INT_PARAM, &HASH_SIZE          },
	{"db_url" ,          STR_PARAM, &db_url.s           },
	{"db_table" ,        STR_PARAM, &db_table.s         },
	{"min_expires",      INT_PARAM, &min_expires        },
	{"default_expires",  INT_PARAM, &default_expires    },
	{"update_period",    INT_PARAM, &update_period      },
	{0,                          0,         0           }
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_SQLDB, NULL, DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/** module exports */
struct module_exports exports= {
	"pua",                      /* module name */
	MOD_TYPE_DEFAULT,           /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	&deps,                      /* OpenSIPS module dependencies */
	cmds,                       /* exported functions */
	0,                          /* exported async functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	0,                          /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,                          /* extra processes */
	mod_init,                   /* module initialization function */
	(response_function) 0,      /* response handling function */
	destroy,                    /* destroy function */
	child_init                  /* per-child init function */
};

/**
 * init module function
 */
static int mod_init(void)
{
	load_tm_f  load_tm;

	LM_DBG("...\n");

	if(min_expires< 0)
		min_expires= 0;

	if(default_expires< 600)
		default_expires= 3600;

	/* import the TM auto-loading function */
	if((load_tm=(load_tm_f)find_export("load_tm", 0, 0))==NULL)
	{
		LM_ERR("can't import load_tm\n");
		return -1;
	}
	/* let the auto-loading function load all TM stuff */

	if(load_tm(&tmb)==-1)
	{
		LM_ERR("can't load tm functions\n");
		return -1;
	}

	init_db_url( db_url , 0 /*cannot be null*/);
	db_table.len = strlen(db_table.s);

	/* binding to database module  */
	if (db_bind_mod(&db_url, &pua_dbf))
	{
		LM_ERR("Database module not found\n");
		return -1;
	}
	if (!DB_CAPABILITY(pua_dbf, DB_CAP_ALL)) {
		LM_ERR("Database module does not implement all functions needed"
				" by the module\n");
		return -1;
	}

	pua_db = pua_dbf.init(&db_url);
	if (!pua_db)
	{
		LM_ERR("while connecting database\n");
		return -1;
	}
	/* verify table version  */
	if(db_check_table_version(&pua_dbf, pua_db, &db_table, PUA_TABLE_VERSION) < 0) {
		LM_ERR("error during table version check.\n");
		return -1;
	}

	if(HASH_SIZE<=1)
		HASH_SIZE= 512;
	else
		HASH_SIZE = 1<<HASH_SIZE;

	HashT= new_htable();
	if(HashT== NULL)
	{
		LM_ERR("while creating new hash table\n");
		return -1;
	}
	if(db_restore()< 0)
	{
		LM_ERR("while restoring hash_table\n");
		return -1;
	}

	if(update_period<=0)
	{
		LM_ERR("wrong clean_period\n");
		return -1;
	}
	if ( init_puacb_list() < 0)
	{
		LM_ERR("callbacks initialization failed\n");
		return -1;
	}
	pua_evlist= init_pua_evlist();
	if(pua_evlist==0)
	{
		LM_ERR("when initializing pua_evlist\n");
		return -1;
	}
	if(pua_add_events()< 0)
	{
		LM_ERR("while adding events\n");
		return -1;
	}

	register_timer("pua_clean", hashT_clean, 0, update_period-5,
		TIMER_FLAG_DELAY_ON_DELAY);

	register_timer("pua_dbupdate", db_update, 0, update_period,
		TIMER_FLAG_SKIP_ON_DELAY);


	if(pua_db)
		pua_dbf.close(pua_db);
	pua_db = NULL;

	return 0;
}

static int child_init(int rank)
{
	LM_DBG("child [%d]  pid [%d]\n", rank, getpid());

	if (pua_dbf.init==0)
	{
		LM_CRIT("database not bound\n");
		return -1;
	}
	pua_db = pua_dbf.init(&db_url);
	if (!pua_db)
	{
		LM_ERR("Child %d: connecting to database failed\n", rank);
		return -1;
	}

	LM_DBG("child %d: Database connection opened successfully\n", rank);

	return 0;
}

static void destroy(void)
{
	LM_DBG("destroying module ...\n");
	if (puacb_list)
		destroy_puacb_list();

	if(pua_db && HashT)
		db_update(0,0);

	if(HashT)
		destroy_htable();

	if(pua_db)
		pua_dbf.close(pua_db);
	if(pua_evlist)
		destroy_pua_evlist();

	return ;
}

static int db_restore(void)
{
	ua_pres_t* p= NULL;
	db_key_t result_cols[20];
	db_res_t *res= NULL;
	db_row_t *row = NULL;
	db_val_t *row_vals= NULL;
	str pres_uri, pres_id, to_uri;
	str etag, tuple_id;
	str watcher_uri, call_id;
	str to_tag, from_tag, remote_contact;
	str record_route, contact, extra_headers;
	int size= 0, i;
	int n_result_cols= 0;
	int puri_col,touri_col,pid_col,expires_col,flag_col,etag_col, desired_expires_col;
	int watcher_col,callid_col,totag_col,fromtag_col,cseq_col,remote_contact_col;
	int event_col,contact_col,tuple_col,record_route_col, extra_headers_col;
	int version_col;
	int no_rows = 10;

	result_cols[puri_col=n_result_cols++]	= &str_pres_uri_col;
	result_cols[touri_col=n_result_cols++]	= &str_to_uri_col;
	result_cols[pid_col=n_result_cols++]	= &str_pres_id_col;
	result_cols[expires_col=n_result_cols++]= &str_expires_col;
	result_cols[flag_col=n_result_cols++]	= &str_flag_col;
	result_cols[etag_col=n_result_cols++]	= &str_etag_col;
	result_cols[tuple_col=n_result_cols++]	= &str_tuple_id_col;
	result_cols[watcher_col=n_result_cols++]= &str_watcher_uri_col;
	result_cols[callid_col=n_result_cols++] = &str_call_id_col;
	result_cols[totag_col=n_result_cols++]	= &str_to_tag_col;
	result_cols[fromtag_col=n_result_cols++]= &str_from_tag_col;
	result_cols[cseq_col= n_result_cols++]	= &str_cseq_col;
	result_cols[event_col= n_result_cols++]	= &str_event_col;
	result_cols[record_route_col= n_result_cols++]	= &str_record_route_col;
	result_cols[contact_col= n_result_cols++]	= &str_contact_col;
	result_cols[remote_contact_col= n_result_cols++]	= &str_remote_contact_col;
	result_cols[extra_headers_col= n_result_cols++]	= &str_extra_headers_col;
	result_cols[desired_expires_col= n_result_cols++]	= &str_desired_expires_col;
	result_cols[version_col= n_result_cols++]	= &str_version_col;

	if(!pua_db)
	{
		LM_ERR("null database connection\n");
		return -1;
	}

	if(pua_dbf.use_table(pua_db, &db_table)< 0)
	{
		LM_ERR("in use table\n");
		return -1;
	}

	if (DB_CAPABILITY(pua_dbf, DB_CAP_FETCH)) {
		if(pua_dbf.query(pua_db,0, 0, 0, result_cols,0, n_result_cols, 0,0)< 0)
		{
			LM_ERR("while querying table\n");
			return -1;
		}
		no_rows = estimate_available_rows( 128+128+8+8+4+32+64+64+128+
			128+64+64+16+64, n_result_cols);
		if (no_rows==0) no_rows = 10;

		if(pua_dbf.fetch_result(pua_db, &res, no_rows)<0)
		{
			LM_ERR("Error fetching rows\n");
			return -1;
		}
	} else {
		if(pua_dbf.query(pua_db,0, 0, 0,result_cols,0,n_result_cols,0,&res)< 0)
		{
			LM_ERR("while querrying table\n");
			if(res)
			{
				pua_dbf.free_result(pua_db, res);
				res = NULL;
			}
			return -1;
		}
	}

	if(res== NULL)
		return -1;

	if(res->n<=0)
	{
		LM_INFO("the query returned no result\n");
		pua_dbf.free_result(pua_db, res);
		res = NULL;
		return 0;
	}

	LM_DBG("found %d db entries\n", res->n);

	do {
		for(i =0 ; i< res->n ; i++)
		{
			row = &res->rows[i];
			row_vals = ROW_VALUES(row);
			if(row_vals[expires_col].val.int_val < time(NULL))
				continue;

			pres_uri.s= (char*)row_vals[puri_col].val.string_val;
			pres_uri.len = strlen(pres_uri.s);

			LM_DBG("pres_uri= %.*s\n", pres_uri.len, pres_uri.s);

			memset(&etag,			 0, sizeof(str));
			memset(&tuple_id,		 0, sizeof(str));
			memset(&watcher_uri,	 0, sizeof(str));
			memset(&to_uri,          0, sizeof(str));
			memset(&call_id,		 0, sizeof(str));
			memset(&to_tag,			 0, sizeof(str));
			memset(&from_tag,		 0, sizeof(str));
			memset(&record_route,	 0, sizeof(str));
			memset(&pres_id,         0, sizeof(str));
			memset(&contact,         0, sizeof(str));
			memset(&remote_contact,  0, sizeof(str));
			memset(&extra_headers,   0, sizeof(str));

			pres_id.s= (char*)row_vals[pid_col].val.string_val;
			if(pres_id.s)
				pres_id.len = strlen(pres_id.s);

			if(row_vals[etag_col].val.string_val)
			{
				etag.s= (char*)row_vals[etag_col].val.string_val;
				etag.len = strlen(etag.s);

				if(row_vals[tuple_col].val.string_val)
				{
					tuple_id.s= (char*)row_vals[tuple_col].val.string_val;
					tuple_id.len = strlen(tuple_id.s);
				}
			}

			if(row_vals[watcher_col].val.string_val)
			{
				watcher_uri.s= (char*)row_vals[watcher_col].val.string_val;
				watcher_uri.len = strlen(watcher_uri.s);

				to_uri.s= (char*)row_vals[touri_col].val.string_val;
				if(to_uri.s == NULL)
					to_uri = pres_uri;
				else
					to_uri.len = strlen(to_uri.s);
				LM_DBG("to_uri= %.*s\n", to_uri.len, to_uri.s);
				call_id.s= (char*)row_vals[callid_col].val.string_val;
				call_id.len = strlen(call_id.s);

				to_tag.s= (char*)row_vals[totag_col].val.string_val;
				to_tag.len = strlen(to_tag.s);

				from_tag.s= (char*)row_vals[fromtag_col].val.string_val;
				from_tag.len = strlen(from_tag.s);

				if(row_vals[record_route_col].val.string_val)
				{
					record_route.s= (char*)
						row_vals[record_route_col].val.string_val;
					record_route.len= strlen(record_route.s);
				}

				contact.s= (char*)row_vals[contact_col].val.string_val;
				contact.len = strlen(contact.s);

				remote_contact.s=
					(char*)row_vals[remote_contact_col].val.string_val;
				if(remote_contact.s)
					remote_contact.len = strlen(remote_contact.s);
			}
			extra_headers.s= (char*)row_vals[extra_headers_col].val.string_val;
			if(extra_headers.s)
				extra_headers.len= strlen(extra_headers.s);
			else
				extra_headers.len= 0;

			size= sizeof(ua_pres_t)+ sizeof(str)+ (pres_uri.len+ pres_id.len+
						tuple_id.len)* sizeof(char);

			if(watcher_uri.s)
				size+= sizeof(str)+ to_uri.len + watcher_uri.len+ call_id.len+ to_tag.len+
					from_tag.len+ record_route.len+ contact.len;

			p= (ua_pres_t*)shm_malloc(size);
			if(p== NULL)
			{
				LM_ERR("no more shared memmory");
				goto error;
			}
			memset(p, 0, size);
			size= sizeof(ua_pres_t);

			p->pres_uri= (str*)((char*)p+ size);
			size+= sizeof(str);
			p->pres_uri->s= (char*)p + size;
			memcpy(p->pres_uri->s, pres_uri.s, pres_uri.len);
			p->pres_uri->len= pres_uri.len;
			size+= pres_uri.len;

			if(pres_id.s)
			{
				CONT_COPY(p, p->id, pres_id);
			}

			if(watcher_uri.s && watcher_uri.len)
			{
				p->watcher_uri= (str*)((char*)p+ size);
				size+= sizeof(str);

				p->watcher_uri->s= (char*)p+ size;
				memcpy(p->watcher_uri->s, watcher_uri.s, watcher_uri.len);
				p->watcher_uri->len= watcher_uri.len;
				size+= watcher_uri.len;

				CONT_COPY(p, p->to_uri, to_uri);
				CONT_COPY(p, p->to_tag, to_tag);
				CONT_COPY(p, p->from_tag, from_tag);
				CONT_COPY(p, p->call_id, call_id);

				if(record_route.s && record_route.len)
				{
					CONT_COPY(p, p->record_route, record_route);
				}
				CONT_COPY(p, p->contact, contact);

				p->cseq= row_vals[cseq_col].val.int_val;

				p->remote_contact.s= (char*)shm_malloc(remote_contact.len);
				if(p->remote_contact.s== NULL)
				{
					LM_ERR("No more shared memory\n");
					goto error;
				}
				memcpy(p->remote_contact.s, remote_contact.s, remote_contact.len);
				p->remote_contact.len= remote_contact.len;

				p->version= row_vals[version_col].val.int_val;
			}

			LM_DBG("size= %d\n", size);
			p->event= row_vals[event_col].val.int_val;
			p->expires= row_vals[expires_col].val.int_val;
			p->desired_expires= row_vals[desired_expires_col].val.int_val;
			p->flag|=	row_vals[flag_col].val.int_val;

			memset(&p->etag, 0, sizeof(str));
			if(etag.s && etag.len)
			{
				/* alloc separately */
				p->etag.s= (char*)shm_malloc(etag.len);
				if(p->etag.s==  NULL)
				{
					LM_ERR("no more share memory\n");
					goto error;
				}
				memcpy(p->etag.s, etag.s, etag.len);
				p->etag.len= etag.len;
			}

			memset(&p->extra_headers, 0, sizeof(str));
			if(extra_headers.s && extra_headers.len)
			{
				/* alloc separately */
				p->extra_headers.s= (char*)shm_malloc(extra_headers.len);
				if(p->extra_headers.s==  NULL)
				{
					LM_ERR("no more share memory\n");
					goto error;
				}
				memcpy(p->extra_headers.s, extra_headers.s, extra_headers.len);
				p->extra_headers.len= extra_headers.len;
			}

			print_ua_pres(p);
			insert_htable(p);
		} /* end for(all rows)*/

		if (DB_CAPABILITY(pua_dbf, DB_CAP_FETCH)) {
			if(pua_dbf.fetch_result(pua_db, &res, no_rows)<0) {
				LM_ERR( "fetching rows (1)\n");
				goto error;
			}
		} else {
			break;
		}
	} while(RES_ROW_N(res)>0);

	pua_dbf.free_result(pua_db, res);
	res = NULL;

	if(pua_dbf.delete(pua_db, 0, 0 , 0, 0) < 0)
	{
		LM_ERR("while deleting information from db\n");
		goto error;
	}

	return 0;

error:
	if(res)
		pua_dbf.free_result(pua_db, res);

	if(p)
	{
		if(p->remote_contact.s) shm_free(p->remote_contact.s);
		if(p->extra_headers.s) shm_free(p->extra_headers.s);
		if(p->etag.s) shm_free(p->etag.s);
		shm_free(p);
	}
	return -1;
}

static void hashT_clean(unsigned int ticks,void *param)
{
	int i;
	time_t now;
	ua_pres_t* p= NULL, *q= NULL;

	now = time(NULL);
	for(i= 0;i< HASH_SIZE; i++)
	{
		lock_get(&HashT->p_records[i].lock);
		p= HashT->p_records[i].entity->next;
		while(p)
		{
			print_ua_pres(p);
			LM_DBG("---\n");
			if(p->expires -update_period < now )
			{
				if((p->desired_expires> p->expires + 5) ||
						(p->desired_expires== 0 ))
				{
					LM_DBG("Desired expires greater than expires -> send a "
						"refresh PUBLISH desired_expires=%d - expires=%d\n",
						p->desired_expires, p->expires);

					if(update_pua(p, i, 0)< 0)
					{
						LM_ERR("while updating record\n");
						lock_release(&HashT->p_records[i].lock);
						return;
					}
					p= p->next;
					continue;
				}

				LM_DBG("Found expired: uri= %.*s\n", p->pres_uri->len,
						p->pres_uri->s);
				if(update_pua(p, i, 1)< 0)
				{
					LM_ERR("while updating record\n");
				}
				/* delete it */
				q = p->next;
				delete_htable_safe(p, p->hash_index);
				p = q;
			}
			else
				p= p->next;
		}
		lock_release(&HashT->p_records[i].lock);
	}
}

int update_pua(ua_pres_t* p, unsigned int hash_code, unsigned int final)
{
	str* str_hdr= NULL;
	int expires;
	int result;

	if(final > 0)
	{
		expires= 0;
		p->desired_expires= 0;
	}
	else
	{
		if(p->desired_expires== 0)
			expires= 3600;
		else
			expires= p->desired_expires- (int)time(NULL);

		if(expires < min_expires)
			expires = min_expires;
	}
	if(p->watcher_uri== NULL)
	{
		str met= {"PUBLISH", 7};
		unsigned long cb_param;
		pua_event_t* ev;

		ev = get_event(p->event);
		if(ev == NULL)
		{
			LM_ERR("No event with flag [%d] found\n", p->event);
			goto error;
		}

		str_hdr = publ_build_hdr(expires, ev, NULL,
				&p->etag, &p->extra_headers, 0);
		if(str_hdr == NULL)
		{
			LM_ERR("while building extra_headers\n");
			goto error;
		}
		LM_DBG("str_hdr:\n%.*s expires:%d\n ", str_hdr->len, str_hdr->s, expires);

		cb_param = PRES_HASH_ID(p);

		result= tmb.t_request(&met,    /* Type of the message*/
				p->pres_uri,           /* Request-URI */
				p->pres_uri,           /* To */
				p->pres_uri,           /* From */
				str_hdr,               /* Optional headers */
				0,                     /* Message body */
				(p->outbound_proxy)?p->outbound_proxy:0,/* Outbound proxy*/
				publ_cback_func,       /* Callback function */
				(void*)cb_param,       /* Callback parameter*/
				0
				);
	}
	else
	{
		str met= {"SUBSCRIBE", 9};
		dlg_t* td= NULL;
		ua_pres_t* cb_param= NULL;

		td= pua_build_dlg_t(p);
		if(td== NULL)
		{
			LM_ERR("while building tm dlg_t structure");
			goto error;
		}
		LM_DBG("td->rem_uri= %.*s\n", td->rem_uri.len, td->rem_uri.s);
		str_hdr= subs_build_hdr(&p->contact, expires,p->event,&p->extra_headers);
		if(str_hdr== NULL || str_hdr->s== NULL)
		{
			LM_ERR("while building extra headers\n");
			pkg_free(td);
			return -1;
		}
		cb_param= subs_cbparam_indlg(p, expires, REQ_ME);
		if(cb_param== NULL)
		{
			LM_ERR("while constructing subs callback param\n");
			goto error;

		}
		result= tmb.t_request_within
				(&met,
				str_hdr,
				0,
				td,
				subs_cback_func,
				(void*)cb_param,
				0
				);
		if(result< 0)
		{
			LM_ERR("in t_request function\n");
			shm_free(cb_param);
			pkg_free(td);
			goto error;
		}

		pkg_free(td);
		td= NULL;
	}

	pkg_free(str_hdr);
	return 0;

error:
	if(str_hdr)
		pkg_free(str_hdr);
	return -1;
}

static void db_update(unsigned int ticks,void *param)
{
	ua_pres_t* p= NULL;
	db_key_t q_cols[19];
	db_val_t q_vals[19];
	db_key_t db_cols[5];
	db_val_t db_vals[5];
	db_op_t  db_ops[1] ;
	int n_query_cols= 0, n_query_update= 0;
	int n_update_cols= 0;
	int i;
	int puri_col,touri_col,pid_col,expires_col,flag_col,etag_col,tuple_col,event_col;
	int watcher_col,callid_col,totag_col,fromtag_col,record_route_col,cseq_col;
	int no_lock= 0, contact_col, desired_expires_col, extra_headers_col;
	int remote_contact_col, version_col;

	if(ticks== 0 && param == NULL)
		no_lock= 1;

	/* cols and values used for insert */
	q_cols[puri_col= n_query_cols] = &str_pres_uri_col;
	q_vals[puri_col].type = DB_STR;
	q_vals[puri_col].nul = 0;
	n_query_cols++;

	q_cols[pid_col= n_query_cols] = &str_pres_id_col;
	q_vals[pid_col].type = DB_STR;
	q_vals[pid_col].nul = 0;
	n_query_cols++;

	q_cols[flag_col= n_query_cols] = &str_flag_col;
	q_vals[flag_col].type = DB_INT;
	q_vals[flag_col].nul = 0;
	n_query_cols++;

	q_cols[event_col= n_query_cols] = &str_event_col;
	q_vals[event_col].type = DB_INT;
	q_vals[event_col].nul = 0;
	n_query_cols++;

	q_cols[watcher_col= n_query_cols] = &str_watcher_uri_col;
	q_vals[watcher_col].type = DB_STR;
	q_vals[watcher_col].nul = 0;
	n_query_cols++;

	q_cols[callid_col= n_query_cols] = &str_call_id_col;
	q_vals[callid_col].type = DB_STR;
	q_vals[callid_col].nul = 0;
	n_query_cols++;

	q_cols[totag_col= n_query_cols] = &str_to_tag_col;
	q_vals[totag_col].type = DB_STR;
	q_vals[totag_col].nul = 0;
	n_query_cols++;

	q_cols[fromtag_col= n_query_cols] = &str_from_tag_col;
	q_vals[fromtag_col].type = DB_STR;
	q_vals[fromtag_col].nul = 0;
	n_query_cols++;

	q_cols[etag_col= n_query_cols] = &str_etag_col;
	q_vals[etag_col].type = DB_STR;
	q_vals[etag_col].nul = 0;
	n_query_cols++;

	q_cols[tuple_col= n_query_cols] = &str_tuple_id_col;
	q_vals[tuple_col].type = DB_STR;
	q_vals[tuple_col].nul = 0;
	n_query_cols++;

	q_cols[cseq_col= n_query_cols]= &str_cseq_col;
	q_vals[cseq_col].type = DB_INT;
	q_vals[cseq_col].nul = 0;
	n_query_cols++;

	q_cols[expires_col= n_query_cols] = &str_expires_col;
	q_vals[expires_col].type = DB_INT;
	q_vals[expires_col].nul = 0;
	n_query_cols++;

	q_cols[desired_expires_col= n_query_cols] = &str_desired_expires_col;
	q_vals[desired_expires_col].type = DB_INT;
	q_vals[desired_expires_col].nul = 0;
	n_query_cols++;

	q_cols[record_route_col= n_query_cols] = &str_record_route_col;
	q_vals[record_route_col].type = DB_STR;
	q_vals[record_route_col].nul = 0;
	n_query_cols++;

	q_cols[contact_col= n_query_cols] = &str_contact_col;
	q_vals[contact_col].type = DB_STR;
	q_vals[contact_col].nul = 0;
	n_query_cols++;

	q_cols[remote_contact_col= n_query_cols] = &str_remote_contact_col;
	q_vals[remote_contact_col].type = DB_STR;
	q_vals[remote_contact_col].nul = 0;
	n_query_cols++;

	q_cols[version_col= n_query_cols] = &str_version_col;
	q_vals[version_col].type = DB_INT;
	q_vals[version_col].nul = 0;
	n_query_cols++;

	q_cols[touri_col= n_query_cols] = &str_to_uri_col;
	q_vals[touri_col].type = DB_STR;
	q_vals[touri_col].nul = 0;
	n_query_cols++;

	/* must keep this the last  column to be inserted */
	q_cols[extra_headers_col= n_query_cols] = &str_extra_headers_col;
	q_vals[extra_headers_col].type = DB_STR;
	q_vals[extra_headers_col].nul = 0;
	n_query_cols++;

	/* cols and values used for update */
	db_cols[0]= &str_expires_col;
	db_vals[0].type = DB_INT;
	db_vals[0].nul = 0;

	db_cols[1]= &str_cseq_col;
	db_vals[1].type = DB_INT;
	db_vals[1].nul = 0;

	db_cols[2]= &str_etag_col;
	db_vals[2].type = DB_STR;
	db_vals[2].nul = 0;

	db_cols[3]= &str_desired_expires_col;
	db_vals[3].type = DB_INT;
	db_vals[3].nul = 0;

	db_cols[4]= &str_extra_headers_col;
	db_vals[4].type = DB_STR;
	db_vals[4].nul = 0;

	if(pua_db== NULL)
	{
		LM_ERR("null database connection\n");
		return;
	}

	if(pua_dbf.use_table(pua_db, &db_table)< 0)
	{
		LM_ERR("in use table\n");
		return ;
	}

	for(i=0; i<HASH_SIZE; i++) 
	{
		if(!no_lock)
			lock_get(&HashT->p_records[i].lock);

		p = HashT->p_records[i].entity->next;
		while(p)
		{
			if(p->expires < time(NULL))
			{
				p= p->next;
				continue;
			}
			print_ua_pres(p);
			LM_DBG("--------\n");

			switch(p->db_flag)
			{
				case NO_UPDATEDB_FLAG:
				{
					LM_DBG("NO_UPDATEDB_FLAG\n");
					break;
				}

				case UPDATEDB_FLAG:
				{
					LM_DBG("UPDATEDB_FLAG\n");
					n_update_cols= 0;
					n_query_update= 0;

					q_vals[puri_col].val.str_val = *(p->pres_uri);
					q_vals[pid_col].val.str_val = p->id;
					q_vals[flag_col].val.int_val = p->flag;
					q_vals[event_col].val.int_val = p->event;
					n_query_update = event_col;

					if(p->watcher_uri)
					{
						q_vals[watcher_col].val.str_val = *(p->watcher_uri);
						q_vals[callid_col].val.str_val = p->call_id;
						q_vals[totag_col].val.str_val = p->to_tag;
						q_vals[fromtag_col].val.str_val = p->from_tag;
						n_query_update = fromtag_col;
					}

					db_vals[0].val.int_val= p->expires;
					db_vals[1].val.int_val= p->cseq;
					db_vals[2].val.str_val= p->etag;
					db_vals[3].val.int_val= p->desired_expires;
					if(p->extra_headers.s && p->extra_headers.len)
					{
						db_vals[4].val.str_val= p->extra_headers;
						n_update_cols= 5;
					}
					else
					{
						db_vals[4].val.str_val.s= NULL;
						db_vals[4].val.str_val.len= 0;
						n_update_cols= 4;
					}

					LM_DBG("Updating:n_query_update= %d\tn_update_cols= %d\n",
							n_query_update, n_update_cols);
					p->db_flag= NO_UPDATEDB_FLAG;

					if(pua_dbf.update(pua_db, q_cols, 0, q_vals, db_cols,
							db_vals, n_query_update, n_update_cols)<0)
					{
						LM_ERR("while updating in database\n");
						if(!no_lock)
							lock_release(&HashT->p_records[i].lock);
						return ;
					}
					break;
				}
				case INSERTDB_FLAG:
				{
					LM_DBG("INSERTDB_FLAG\n");
					q_vals[puri_col].val.str_val = *(p->pres_uri);
					q_vals[pid_col].val.str_val = p->id;
					q_vals[flag_col].val.int_val = p->flag;
					if(p->watcher_uri)
						q_vals[watcher_col].val.str_val = *(p->watcher_uri);
					else
						memset(&q_vals[watcher_col].val.str_val, 0, sizeof(str));

					q_vals[callid_col].val.str_val = p->call_id;
					q_vals[totag_col].val.str_val = p->to_tag;
					q_vals[fromtag_col].val.str_val = p->from_tag;
					q_vals[cseq_col].val.int_val= p->cseq;
					q_vals[tuple_col].val.str_val = p->tuple_id;
					q_vals[etag_col].val.str_val = p->etag;
					q_vals[expires_col].val.int_val = p->expires;
					q_vals[desired_expires_col].val.int_val = p->desired_expires;
					q_vals[event_col].val.int_val = p->event;
					q_vals[version_col].val.int_val = p->version;
					q_vals[touri_col].val.str_val = p->to_uri;
					q_vals[record_route_col].val.str_val = p->record_route;
					q_vals[contact_col].val.str_val = p->contact;
					q_vals[remote_contact_col].val.str_val = p->remote_contact;
					q_vals[extra_headers_col].val.str_val = p->extra_headers;

					if(pua_dbf.insert(pua_db, q_cols, q_vals, n_query_cols)< 0)
					{
						LM_ERR("while inserting in db table pua\n");
						if(!no_lock)
							lock_release(&HashT->p_records[i].lock);
						return ;
					}
					break;
				}

			}
			p->db_flag= NO_UPDATEDB_FLAG;
			p= p->next;
		}
		if(!no_lock)
			lock_release(&HashT->p_records[i].lock);
	}

	db_vals[0].val.int_val= (int)time(NULL)- 10;
	db_ops[0]= OP_LT;
	if(pua_dbf.delete(pua_db, db_cols, db_ops, db_vals, 1) < 0)
	{
		LM_ERR("while deleting from db table pua\n");
	}

	return ;
}

