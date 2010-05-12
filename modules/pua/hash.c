/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
	LM_DBG("\tpres_uri= %.*s   len= %d\n", p->pres_uri->len, p->pres_uri->s, p->pres_uri->len);
	if(p->watcher_uri)
	{	
		LM_DBG("\twatcher_uri= %.*s  len= %d\n", p->watcher_uri->len, p->watcher_uri->s, p->watcher_uri->len);
		LM_DBG("\tto_uri= %.*s  len= %d\n", p->to_uri.len, p->to_uri.s, p->to_uri.len);
		LM_DBG("\tcall_id= %.*s   len= %d\n", p->call_id.len, p->call_id.s, p->call_id.len);
		LM_DBG("\tfrom_tag= %.*s   len= %d\n", p->from_tag.len, p->from_tag.s, p->from_tag.len);
		LM_DBG("\tto_tag= %.*s  len= %d\n", p->to_tag.len, p->to_tag.s, p->to_tag.len);
		LM_DBG("\tflag= %d\n", p->flag);
		LM_DBG("\tevent= %d\n", p->event);
	}	
	else
	{
		LM_DBG("\tetag= %.*s - len= %d\n", p->etag.len, p->etag.s, p->etag.len);
		if(p->id.s)
			LM_DBG("\tid= %.*s\n", p->id.len, p->id.s);
	}
	LM_DBG("\texpires= %d\n", p->expires- (int)time(NULL));
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

	if(p)
		LM_DBG("found record\n");
	else
		LM_DBG("record not found\n");

	return p;
}

void update_htable(ua_pres_t* p, int expires, str* etag,
		unsigned int hash_code, str* contact)
{
	if(etag)
	{
		shm_free(p->etag.s);
		p->etag.s= (char*)shm_malloc(etag->len);
		memcpy(p->etag.s, etag->s, etag->len);
		p->etag.len= etag->len;
	}
	p->expires= expires+ (int)time(NULL);
	if(p->db_flag == NO_UPDATEDB_FLAG)
		p->db_flag= UPDATEDB_FLAG;

	if(p->watcher_uri)
		p->cseq ++;

	if(contact)
	{
		if(!(p->remote_contact.len== contact->len && 
				strncmp(p->remote_contact.s, contact->s, contact->len)==0))
		{
			/* update remote contact */
			shm_free(p->remote_contact.s);
			p->remote_contact.s= (char*)shm_malloc(contact->len* sizeof(char));
			if(p->remote_contact.s== NULL)
			{
				LM_ERR("no more shared memory\n");
				return;
			}
			memcpy(p->remote_contact.s, contact->s, contact->len);
			p->remote_contact.len= contact->len;
		}
	}
}
/* insert in front; so when searching the most recent result is returned*/
void insert_htable(ua_pres_t* presentity)
{
	ua_pres_t* p= NULL;
	unsigned int hash_code;
    str* s1;

    if(presentity->to_uri.s)
        s1 = &presentity->to_uri;
    else
        s1 = presentity->pres_uri;

	hash_code= core_hash(s1, presentity->watcher_uri, 
			HASH_SIZE);
	presentity->hash_index = hash_code;
	LM_DBG("start\n");
	lock_get(&HashT->p_records[hash_code].lock);

/*	
 *	useless since always checking before calling insert
	if(get_dialog(presentity, hash_code)!= NULL )
	{
		LM_DBG("Dialog already found- do not insert\n");
		return; 
	}
*/
	p= HashT->p_records[hash_code].entity;

	presentity->db_flag= INSERTDB_FLAG;
	presentity->next= p->next;
	
	p->next= presentity;

	lock_release(&HashT->p_records[hash_code].lock);
	LM_DBG("end\n");

}

void delete_htable(ua_pres_t* presentity)
{
	ua_pres_t* p= NULL, *q= NULL;
	unsigned int hash_code;

	if(presentity == NULL)
	{
		LM_ERR("Entity pointer NULL\n");
		return;
	}
	hash_code = presentity->hash_index;

	p= search_htable(presentity, hash_code);
	if(p== NULL)
		return;

	q=HashT->p_records[hash_code].entity;

	while(q->next!=p)
		q= q->next;
	q->next=p->next;

	if(p->etag.s)
	{
		shm_free(p->etag.s);
		lock_release(&p->publ_lock);
		lock_destroy(&p->publ_lock);
	}
	else
		if(p->remote_contact.s)
			shm_free(p->remote_contact.s);

	shm_free(p);
	p= NULL;
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
	hash_code= core_hash(s1, dialog->watcher_uri, HASH_SIZE);
	lock_get(&HashT->p_records[hash_code].lock);

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
	id->s= (char*)pkg_malloc(rec->id.len* sizeof(char));
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

int update_contact(struct sip_msg* msg, char* str1, char* str2)
{
	ua_pres_t* p, hentity;
	str contact;
	struct to_body *pto= NULL, TO, *pfrom = NULL;
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
	
	if(msg->to->parsed != NULL)
	{
		pto = (struct to_body*)msg->to->parsed;
		LM_DBG("'To' header ALREADY PARSED: <%.*s>\n",pto->uri.len,pto->uri.s);
	}
	else
	{
		memset( &TO , 0, sizeof(TO) );
		parse_to(msg->to->body.s,msg->to->body.s +
			msg->to->body.len + 1, &TO);
		if(TO.uri.len <= 0) 
		{
			LM_DBG("'To' header NOT parsed\n");
			return -1;
		}
		pto = &TO;
	}			
	if( pto->tag_value.s ==NULL || pto->tag_value.len == 0)
	{
		LM_ERR("no from tag value present\n");
		return -1;
	}
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
		LM_ERR("no contact header found in 200 OK reply");
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

	shm_free(p->remote_contact.s);

	if(!(p->remote_contact.len== contact.len && 
				strncmp(p->remote_contact.s, contact.s, contact.len)==0))
	{
		/* update remote contact */
		shm_free(p->remote_contact.s);
		p->remote_contact.s= (char*)shm_malloc(contact.len* sizeof(char));
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

void pua_db_delete(ua_pres_t* pres)
{
	db_key_t cols[6];
	db_val_t vals[6];
	int n_query_cols= 0;

	cols[n_query_cols] = &str_pres_uri_col;
	vals[n_query_cols].type = DB_STR;
	vals[n_query_cols].nul = 0;
	vals[n_query_cols].val.str_val = *pres->pres_uri;
	n_query_cols++;

	if(pres->flag)
	{
		cols[n_query_cols] = &str_flag_col;
		vals[n_query_cols].type = DB_INT;
		vals[n_query_cols].nul = 0;
		vals[n_query_cols].val.int_val = pres->flag;
		n_query_cols++;
	}

	cols[n_query_cols] = &str_event_col;
	vals[n_query_cols].type = DB_INT;
	vals[n_query_cols].nul = 0;
	vals[n_query_cols].val.int_val = pres->event;
	n_query_cols++;

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


