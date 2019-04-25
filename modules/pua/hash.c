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
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../hash_func.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_from.h"
#include "../../db/db.h"
#include "hash.h"
#include "pua.h"
#include "send_publish.h"
#include "../presence/hash.h"

/* database colums */
static str str_pres_uri_col = str_init("pres_uri");
static str str_etag_col = str_init("etag");
static str str_pres_id_col = str_init("pres_id");
static str str_flag_col= str_init("flag");
static str str_watcher_uri_col= str_init("watcher_uri");
static str str_event_col= str_init("event");
static str str_remote_contact_col= str_init("remote_contact");

void print_ua_pres(ua_pres_t* p)
{
	int now = (int)time(NULL);

	LM_DBG("p=[%p] pres_uri=[%.*s]\n", p, p->pres_uri->len, p->pres_uri->s);
	if(p->watcher_uri)
	{
		LM_DBG("watcher_uri=[%.*s]\n", p->watcher_uri->len, p->watcher_uri->s);
		LM_DBG("to_uri=[%.*s]\n", p->to_uri.len, p->to_uri.s);
		LM_DBG("call_id=[%.*s]\n", p->call_id.len, p->call_id.s);
		LM_DBG("from_tag=[%.*s]\n", p->from_tag.len, p->from_tag.s);
		LM_DBG("to_tag=[%.*s]\n", p->to_tag.len, p->to_tag.s);
		LM_DBG("etag=[%.*s]\n", p->etag.len, p->etag.s);
	}
	else
	{
		if(p->id.s)
			LM_DBG("etag=[%.*s] id=[%.*s]\n",
				p->etag.len, p->etag.s, p->id.len, p->id.s);
		else
			LM_DBG("etag=[%.*s]\n", p->etag.len, p->etag.s);
	}
	LM_DBG("flag=[%d] event=[%d]\n", p->flag, p->event);
	if (p->extra_headers.s && p->extra_headers.len)
		LM_DBG("extra_headers=[%.*s]\n",
				p->extra_headers.len, p->extra_headers.s);
	if(p->expires > now)
		LM_DBG("countdown=[%d] expires=[%d] desired_expires=[%d]\n",
				p->expires - now, p->expires, p->desired_expires);
	else
		LM_DBG("expires=[%d] desired_expires=[%d]\n",
				p->expires, p->desired_expires);
}

htable_t* new_htable(void)
{
	htable_t* H= NULL;
	int i= 0, j;

	H= (htable_t*)shm_malloc(sizeof(htable_t));
	if(H== NULL)
	{
		LM_ERR("No more memory\n");
		return NULL;
	}
	memset(H, 0, sizeof(htable_t));

	H->p_records= (hash_entry_t*)shm_malloc(HASH_SIZE* sizeof(hash_entry_t));
	if(H->p_records== NULL)
	{
		LM_ERR("No more share memory\n");
		goto error;
	}

	for(i=0; i<HASH_SIZE; i++)
	{
		if(lock_init(&H->p_records[i].lock)== 0)
		{
			LM_CRIT("initializing lock [%d]\n", i);
			goto error;
		}
		H->p_records[i].entity= (ua_pres_t*)shm_malloc(sizeof(ua_pres_t));
		if(H->p_records[i].entity== NULL)
		{
			LM_ERR("No more share memory\n");
			goto error;
		}
		H->p_records[i].entity->next= NULL;
	}
	return H;

error:

	if(H->p_records)
	{
		for(j=0; j< i; j++)
		{
			if(H->p_records[j].entity)
				shm_free(H->p_records[j].entity);
			lock_destroy(&H->p_records[j].lock);

		}
		shm_free(H->p_records);
	}
	shm_free(H);
	return NULL;

}

ua_pres_t* search_htable(ua_pres_t* pres, unsigned int hash_code)
{
	ua_pres_t* p= NULL,* L= NULL;

	L= HashT->p_records[hash_code].entity;
	LM_DBG("core_hash= %u\n", hash_code);

	LM_DBG("Searched:\n");
	print_ua_pres(pres);
	LM_DBG("\n");
	for(p= L->next; p; p=p->next)
	{
		LM_DBG("Found\n");
		print_ua_pres(p);
		LM_DBG("\n");
		if((p->flag & pres->flag) && (p->event & pres->event))
		{
			if((p->pres_uri->len==pres->pres_uri->len) &&
					(strncmp(p->pres_uri->s, pres->pres_uri->s,pres->pres_uri->len)==0))
			{
				if(pres->id.s && pres->id.len)
				{
					if(!(pres->id.len== p->id.len &&
						strncmp(p->id.s, pres->id.s,pres->id.len)==0))
							continue;
				}

				if(pres->watcher_uri)
				{
					if(p->watcher_uri->len==pres->watcher_uri->len &&
						(strncmp(p->watcher_uri->s, pres->watcher_uri->s,
								  pres->watcher_uri->len )==0))
					{
						/* if to_uri defined check it also */
						if(pres->to_uri.s)
						{
							if(pres->to_uri.len == p->to_uri.len &&
									strncmp(pres->to_uri.s, p->to_uri.s, p->to_uri.len) == 0)
									break;
						}
						else
							break;
					}
				}
				else
				{
					if(pres->etag.s)
					{
						if(pres->etag.len== p->etag.len &&
							strncmp(p->etag.s, pres->etag.s,pres->etag.len)==0)
							break;
					}
					else
					{
						LM_DBG("no etag restriction\n");
						break;
					}
				}
			}
		}
	}

	if (p && p->expires < (int)time(NULL) &&
	!(p->expires==0 &&  p->waiting_reply && p->etag.len==0) )
	/* presentities with expires=0, waiting for reply and no etag are newly added
	 * presentities which were not yet confirmed (no reply received for first PUBLISH)
	 * and we should find such records !  -bogdan */
		return NULL;

	LM_DBG("got presentity [%p]\n", p);
	return p;
}

ua_pres_t* get_htable_safe(unsigned int hash_index, unsigned int local_index)
{
	ua_pres_t* p;

	for(p= HashT->p_records[hash_index].entity->next; p; p=p->next)
	{
		if(p->local_index == local_index)
			break;
	}
	return p;
}


int update_htable(unsigned int hash_index, unsigned int local_index,
		int expires, str* etag, str* contact)
{
	ua_pres_t* p;

	lock_get(&HashT->p_records[hash_index].lock);
	p = get_htable_safe(hash_index, local_index);
	if(p == NULL)
	{
		LM_ERR("Record not found\n");
		goto error;
	}

	if(etag)
	{
		if(p->etag.s)
			shm_free(p->etag.s);
		p->etag.s= (char*)shm_malloc(etag->len);
		if(p->etag.s == NULL)
		{
			LM_ERR("No more shared memory\n");
			goto error;
		}
		memcpy(p->etag.s, etag->s, etag->len);
		p->etag.len= etag->len;
	}
	p->expires= expires+ (int)time(NULL);
	if(p->db_flag == NO_UPDATEDB_FLAG)
		p->db_flag= UPDATEDB_FLAG;

	if(contact)
	{
		if(!(p->remote_contact.len== contact->len &&
				strncmp(p->remote_contact.s, contact->s, contact->len)==0))
		{
			/* update remote contact */
			shm_free(p->remote_contact.s);
			p->remote_contact.s= (char*)shm_malloc(contact->len);
			if(p->remote_contact.s== NULL)
			{
				LM_ERR("no more shared memory\n");
				goto error;
			}
			memcpy(p->remote_contact.s, contact->s, contact->len);
			p->remote_contact.len= contact->len;
		}
	}
	lock_release(&HashT->p_records[hash_index].lock);
	return 0;

error:
	lock_release(&HashT->p_records[hash_index].lock);
	return -1;
}

int find_htable(unsigned int hash_index, unsigned int local_index)
{
	ua_pres_t* p;

	lock_get(&HashT->p_records[hash_index].lock);
	p = get_htable_safe(hash_index, local_index);
	lock_release(&HashT->p_records[hash_index].lock);

	if(p == NULL)
		return 0;
	return 1;
}

ua_pres_t* new_ua_pres(publ_info_t* publ, str* tuple_id)
{
	unsigned int size;
	ua_pres_t* presentity;

	size= sizeof(ua_pres_t) + sizeof(str)+
		publ->pres_uri->len+ publ->id.len;
	if(publ->outbound_proxy.s)
		size+= sizeof(str)+ publ->outbound_proxy.len;
	if(tuple_id->s)
		size+= tuple_id->len;

	presentity= (ua_pres_t*)shm_malloc(size);
	if(presentity== NULL)
	{
		LM_ERR("no more share memory\n");
		goto error;
	}
	memset(presentity, 0, size);

	size= sizeof(ua_pres_t);
	presentity->pres_uri= (str*)((char*)presentity+ size);
	size+= sizeof(str);
	presentity->pres_uri->s= (char*)presentity+ size;
	memcpy(presentity->pres_uri->s, publ->pres_uri->s,
			publ->pres_uri->len);
	presentity->pres_uri->len= publ->pres_uri->len;
	size+= publ->pres_uri->len;

//	presentity->id.s=(char*)presentity+ size;
	CONT_COPY(presentity, presentity->id, publ->id);

	if(publ->extra_headers && publ->extra_headers->s && publ->extra_headers->len)
	{
		presentity->extra_headers.s = (char*)shm_malloc(publ->extra_headers->len);
		if(presentity->extra_headers.s == NULL)
		{
			LM_ERR("No more shared memory\n");
			goto error;
		}
		memcpy(presentity->extra_headers.s, publ->extra_headers->s, publ->extra_headers->len);
		presentity->extra_headers.len = publ->extra_headers->len;
	}

	if(publ->outbound_proxy.s)
	{
		presentity->outbound_proxy= (str*)((char*)presentity+ size);
		size+= sizeof(str);
		presentity->outbound_proxy->s= (char*)presentity+ size;
		memcpy(presentity->outbound_proxy->s, publ->outbound_proxy.s,
			publ->outbound_proxy.len);
		presentity->outbound_proxy->len= publ->outbound_proxy.len;
		size+= publ->outbound_proxy.len;
	}

	presentity->desired_expires= publ->expires + (int)time(NULL);
	presentity->flag  = publ->source_flag;
	presentity->event = publ->event;
	presentity->cb_param = publ->cb_param;
	presentity->waiting_reply = 1;

	return presentity;

error:
	if (presentity) shm_free(presentity);
	return NULL;
}

/* insert in front; so when searching the most recent result is returned*/
unsigned long new_publ_record(publ_info_t* publ, pua_event_t* ev, str* tuple_id)
{
	ua_pres_t* presentity;

	presentity = new_ua_pres(publ, tuple_id);
	if(presentity == NULL)
	{
		LM_ERR("Failed to construct new publish record\n");
		return -1;
	}

	LM_DBG("cb_param = %p\n", publ->cb_param);
	return insert_htable(presentity);
}

unsigned long insert_htable(ua_pres_t* presentity)
{
	unsigned int hash_code;
	str* s1;
	unsigned long pres_id;
	ua_pres_t* p;

	if(presentity->to_uri.s)
		s1 = &presentity->to_uri;
	else
		s1 = presentity->pres_uri;

	LM_DBG("to_uri= %.*s, watcher_uri= %.*s\n", s1->len, s1->s,
		(presentity->watcher_uri?presentity->watcher_uri->len:0),
		(presentity->watcher_uri?presentity->watcher_uri->s:0));

	hash_code= core_hash(s1, presentity->watcher_uri,
			HASH_SIZE);
	presentity->hash_index = hash_code;
	LM_DBG("hash_code = %d\n", hash_code);

	lock_get(&HashT->p_records[hash_code].lock);

	p= HashT->p_records[hash_code].entity;

	presentity->db_flag= INSERTDB_FLAG;
	presentity->next= p->next;
	if(p->next)
	{
		presentity->local_index = p->next->local_index + 1;
	}
	else
		presentity->local_index = 0;

	p->next= presentity;

	pres_id = PRES_HASH_ID(presentity);

	lock_release(&HashT->p_records[hash_code].lock);

	return pres_id;
}

static void pua_db_delete(ua_pres_t* pres)
{
	db_key_t cols[6];
	db_val_t vals[6];
	int n_query_cols= 0;

	cols[n_query_cols] = &str_pres_uri_col;
	vals[n_query_cols].type = DB_STR;
	vals[n_query_cols].nul = 0;
	vals[n_query_cols].val.str_val = *pres->pres_uri;
	n_query_cols++;

	cols[n_query_cols] = &str_event_col;
	vals[n_query_cols].type = DB_INT;
	vals[n_query_cols].nul = 0;
	vals[n_query_cols].val.int_val = pres->event;
	n_query_cols++;

	if(pres->flag)
	{
		cols[n_query_cols] = &str_flag_col;
		vals[n_query_cols].type = DB_INT;
		vals[n_query_cols].nul = 0;
		vals[n_query_cols].val.int_val = pres->flag;
		n_query_cols++;
	}

	if(pres->id.s && pres->id.len)
	{
		cols[n_query_cols] = &str_pres_id_col;
		vals[n_query_cols].type = DB_STR;
		vals[n_query_cols].nul = 0;
		vals[n_query_cols].val.str_val = pres->id;
		n_query_cols++;
	}

	if(pres->watcher_uri)
	{
		cols[n_query_cols] = &str_watcher_uri_col;
		vals[n_query_cols].type = DB_STR;
		vals[n_query_cols].nul = 0;
		vals[n_query_cols].val.str_val = *pres->watcher_uri;
		n_query_cols++;

		if(pres->remote_contact.s)
		{
			cols[n_query_cols] = &str_remote_contact_col;
			vals[n_query_cols].type = DB_STR;
			vals[n_query_cols].nul = 0;
			vals[n_query_cols].val.str_val = pres->remote_contact;
			n_query_cols++;
		}
	}
	else
	{
		if(pres->etag.s)
		{
			cols[n_query_cols] = &str_etag_col;
			vals[n_query_cols].type = DB_STR;
			vals[n_query_cols].nul = 0;
			vals[n_query_cols].val.str_val = pres->etag;
			n_query_cols++;
		}
	}
	/* should not search after etag because I don't know if it has been updated */

	if(pua_dbf.use_table(pua_db, &db_table)< 0)
	{
		LM_ERR("in use table\n");
		return;
	}

	if(pua_dbf.delete(pua_db, cols, 0, vals, n_query_cols)< 0)
	{
		LM_ERR("Sql delete failed\n");
		return;
	}
}


void free_htable_entry(ua_pres_t* p)
{
	/* delete from database also */
	pua_db_delete(p);

	if(p->etag.s)
		shm_free(p->etag.s);
	if(p->remote_contact.s)
		shm_free(p->remote_contact.s);
	if(p->extra_headers.s)
		shm_free(p->extra_headers.s);
	shm_free(p);
}

void delete_htable_safe(ua_pres_t* p, unsigned int hash_index)
{
	ua_pres_t *q= NULL;

	q = HashT->p_records[hash_index].entity;
	while(q && q->next!=p)
		q = q->next;

	if(q)
		q->next = p->next;
	free_htable_entry(p);
}


void delete_htable(unsigned int hash_index, unsigned int local_index)
{
	ua_pres_t* p= NULL, *q= NULL;

	lock_get(&HashT->p_records[hash_index].lock);

	q = HashT->p_records[hash_index].entity;
	for(p= q->next; p; p=p->next)
	{
		if(p->local_index == local_index)
		{
			q->next = p->next;
			free_htable_entry(p);
			break;
		}
		q = p;
	}
	lock_release(&HashT->p_records[hash_index].lock);
}

void destroy_htable(void)
{
	ua_pres_t* p= NULL,*q= NULL;
	int i;

	for(i=0; i<HASH_SIZE; i++)
	{
		lock_destroy(&HashT->p_records[i].lock);
		p=HashT->p_records[i].entity;
		while(p->next)
		{
			q=p->next;
			p->next=q->next;
			if(q->etag.s)
				shm_free(q->etag.s);
			else
				if(q->remote_contact.s)
					shm_free(q->remote_contact.s);
			if(q->extra_headers.s) shm_free(q->extra_headers.s);
			shm_free(q);
			q= NULL;
		}
		shm_free(p);
	}
	shm_free(HashT->p_records);
	shm_free(HashT);

	return;
}

/* must lock the record line before calling this function*/
ua_pres_t* get_dialog(ua_pres_t* dialog, unsigned int hash_code)
{
	ua_pres_t* p= NULL, *L;
	LM_DBG("core_hash= %u\n", hash_code);

	L= HashT->p_records[hash_code].entity;
	for(p= L->next; p; p=p->next)
	{

		if(p->flag& dialog->flag)
		{
			LM_DBG("pres_uri= %.*s\twatcher_uri=%.*s\n\t"
					"callid= %.*s\tto_tag= %.*s\tfrom_tag= %.*s\n",
				p->pres_uri->len, p->pres_uri->s, p->watcher_uri->len,
				p->watcher_uri->s,p->call_id.len, p->call_id.s,
				p->to_tag.len, p->to_tag.s, p->from_tag.len, p->from_tag.s);

			LM_DBG("searched to_tag= %.*s\tfrom_tag= %.*s\n",
				 p->to_tag.len, p->to_tag.s, p->from_tag.len, p->from_tag.s);

				if((p->watcher_uri->len== dialog->watcher_uri->len) &&
				(strncmp(p->watcher_uri->s,dialog->watcher_uri->s,p->watcher_uri->len )==0)&&
				(strncmp(p->call_id.s, dialog->call_id.s, p->call_id.len)== 0) &&
				(strncmp(p->to_tag.s, dialog->to_tag.s, p->to_tag.len)== 0) &&
				(strncmp(p->from_tag.s, dialog->from_tag.s, p->from_tag.len)== 0) )
				{
					if(p->to_uri.s && dialog->to_uri.s)
					{
						if((p->to_uri.len== dialog->to_uri.len) &&
						(strncmp(p->to_uri.s, dialog->to_uri.s,p->to_uri.len)==0))
							break;
					}
					else
                        break;
				}
		}
	}
	return p;
}

int get_record_id(ua_pres_t* dialog, str** rec_id)
{
	unsigned int hash_code;
	ua_pres_t* rec;
	str* id;
    str* s1;

	if(dialog->to_uri.s)
		s1 = &dialog->to_uri;
	else
		s1 = dialog->pres_uri;

	*rec_id= NULL;
	LM_DBG("to_uri= %.*s, watcher_uri= %.*s\n", s1->len, s1->s,
		(dialog->watcher_uri?dialog->watcher_uri->len:0),
		(dialog->watcher_uri?dialog->watcher_uri->s:0));
	hash_code= core_hash(s1, dialog->watcher_uri, HASH_SIZE);
	lock_get(&HashT->p_records[hash_code].lock);

	LM_DBG("hash_code = %d\n", hash_code);
	rec= get_dialog(dialog, hash_code);
	if(rec== NULL)
	{
		LM_DBG("Record not found\n");
		lock_release(&HashT->p_records[hash_code].lock);
		return 0;
	}
	id= (str*)pkg_malloc(sizeof(str));
	if(id== NULL)
	{
		LM_ERR("No more memory\n");
		lock_release(&HashT->p_records[hash_code].lock);
		return -1;
	}
	id->s= (char*)pkg_malloc(rec->id.len);
	if(id->s== NULL)
	{
		LM_ERR("No more memory\n");
		pkg_free(id);
		lock_release(&HashT->p_records[hash_code].lock);
		return -1;
	}
	memcpy(id->s, rec->id.s, rec->id.len);
	id->len= rec->id.len;

	lock_release(&HashT->p_records[hash_code].lock);

	LM_DBG("rec did= %.*s\n", id->len, id->s);

	*rec_id= id;

	return 0;
}

int is_dialog(ua_pres_t* dialog)
{
	int ret_code= 0;
	unsigned int hash_code;
	str* s1;

	if(dialog->to_uri.s)
		s1 = &dialog->to_uri;
	else
		s1 = dialog->pres_uri;

	hash_code= core_hash(s1, dialog->watcher_uri, HASH_SIZE);
	lock_get(&HashT->p_records[hash_code].lock);

	if(get_dialog(dialog, hash_code)== NULL)
		ret_code= -1;
	else
		ret_code= 0;
	lock_release(&HashT->p_records[hash_code].lock);

	return ret_code;

}

int update_contact(struct sip_msg* msg)
{
	ua_pres_t* p, hentity;
	str contact;
	struct to_body *pto= NULL, *pfrom = NULL;
	unsigned int hash_code;

	if ( parse_headers(msg,HDR_EOH_F, 0)==-1 )
	{
		LM_ERR("when parsing headers\n");
		return -1;
	}

	/* find the record */
	if( msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("cannot parse callid header\n");
		return -1;
	}

	if (!msg->from || !msg->from->body.s)
	{
		LM_ERR("cannot find 'from' header!\n");
		return -1;
	}
	if (msg->from->parsed == NULL)
	{
		if ( parse_from_header( msg )<0 )
		{
			LM_ERR("cannot parse From header\n");
			return -1;
		}
	}

	pfrom = (struct to_body*)msg->from->parsed;

	if( pfrom->tag_value.s ==NULL || pfrom->tag_value.len == 0)
	{
		LM_ERR("no from tag value present\n");
		return -1;
	}

	if( msg->to==NULL || msg->to->body.s==NULL)
	{
		LM_ERR("cannot parse TO header\n");
		return -1;
	}

	pto = get_to(msg);
	if (pto == NULL || pto->error != PARSE_OK) {
		LM_ERR("failed to parse TO header\n");
		return -1;
	}

	if( pto->tag_value.s ==NULL || pto->tag_value.len == 0)
	{
		LM_ERR("no to tag value present\n");
		return -1;
	}

	memset( &hentity, 0, sizeof(ua_pres_t));
	/* as we have a NOTIFY, we are looking for any SUBSCRIBER-like
	   entity in the hash (we do not know the exact type) - bogdan */
	hentity.flag = BLA_SUBSCRIBE | XMPP_SUBSCRIBE | XMPP_INITIAL_SUBS |
		MI_SUBSCRIBE | RLS_SUBSCRIBE;
	hentity.watcher_uri= &pto->uri;
	hentity.to_uri= pfrom->uri;
	hentity.call_id=  msg->callid->body;
	hentity.to_tag= pto->tag_value;
	hentity.from_tag= pfrom->tag_value;

	hash_code= core_hash(&hentity.to_uri,hentity.watcher_uri,
				HASH_SIZE);

	/* extract the contact */
	if(msg->contact== NULL || msg->contact->body.s== NULL)
	{
		LM_ERR("no contact header found in 200 OK reply\n");
		return -1;
	}
	contact= msg->contact->body;

	lock_get(&HashT->p_records[hash_code].lock);

	p= get_dialog(&hentity, hash_code);
	if(p== NULL)
	{
		lock_release(&HashT->p_records[hash_code].lock);
		LM_ERR("no record for the dialog found in hash table\n");
		return -1;
	}

	if(!(p->remote_contact.len== contact.len &&
				strncmp(p->remote_contact.s, contact.s, contact.len)==0))
	{
		/* update remote contact */
		shm_free(p->remote_contact.s);
		p->remote_contact.s= (char*)shm_malloc(contact.len);
		if(p->remote_contact.s== NULL)
		{
			LM_ERR("no more shared memory\n");
			lock_release(&HashT->p_records[hash_code].lock);
			return -1;
		}
		memcpy(p->remote_contact.s, contact.s, contact.len);
		p->remote_contact.len= contact.len;
	}

	lock_release(&HashT->p_records[hash_code].lock);

	return 1;

}

list_entry_t *get_subs_list(str *did)
{
	int i;
	str *tmp_str;
	list_entry_t *list = NULL;

	for (i = 0; i < HASH_SIZE; i++)
	{
		ua_pres_t *dialog;

		lock_get(&HashT->p_records[i].lock);
		dialog = HashT->p_records[i].entity;
		while (dialog != NULL)
		{
			if (dialog->id.s != NULL && dialog->id.len > 0 &&
				strncmp(dialog->id.s, did->s, did->len) == 0 &&
				dialog->pres_uri != NULL && dialog->pres_uri->s != NULL &&
				dialog->pres_uri->len > 0)
			{
				if ((tmp_str = (str *)pkg_malloc(sizeof(str))) == NULL)
				{
					LM_ERR("out of private memory\n");
					lock_release(&HashT->p_records[i].lock);
					goto done;
				}
				if ((tmp_str->s = (char *)pkg_malloc(sizeof(char) * dialog->pres_uri->len + 1)) == NULL)
				{
					pkg_free(tmp_str);
					LM_ERR("out of private memory\n");
					lock_release(&HashT->p_records[i].lock);
					goto done;
				}
				memcpy(tmp_str->s, dialog->pres_uri->s, dialog->pres_uri->len);
				tmp_str->len = dialog->pres_uri->len;
				tmp_str->s[tmp_str->len] = '\0';

				list = list_insert(tmp_str, list, NULL);
			}
			dialog = dialog->next;
		}
		lock_release(&HashT->p_records[i].lock);
	}
done:
	return list;
}

