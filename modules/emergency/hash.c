/*
 * emergency module - basic support for emergency calls
 *
 * Copyright (C) 2014-2015 Robison Tesini & Evandro Villaron
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
 *  2015-06-08 change from list to hash (Villaron/Tesini)
 *  2015-08-05 code review (Villaron/Tesini)
 *  2015-09-07 final test cases (Villaron/Tesini)
 */
#include <stdio.h>
#include <stdlib.h>
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../str.h"

#include "hash.h"

emetable_t new_ehtable(int hash_size){
	emetable_t htable= NULL;
	int i, j;

	i = 0;
	htable= (call_table_t*)shm_malloc(hash_size* sizeof(call_table_t));
	if(htable== NULL)
	{
		LM_ERR("--------------------------------------------------no more shm memory\n");
	}
	memset(htable, 0, hash_size* sizeof(call_table_t));

	for(i= 0; i< hash_size; i++)
	{
		if(lock_init(&htable[i].lock)== 0)
		{
			LM_ERR("initializing lock [%d]\n", i);
			goto error;
		}
		htable[i].entries= (NODE*)shm_malloc(sizeof(NODE));
		if(htable[i].entries== NULL)
		{
			lock_destroy(&htable[i].lock);
			LM_ERR("--------------------------------------------------no more shm memory\n");
		}
		memset(htable[i].entries, 0, sizeof(NODE));
		htable[i].entries->next= NULL;
	}

	return htable;

error:
	if(htable){
		for(j=0; j< i; j++){
			lock_destroy(&htable[j].lock);
			shm_free(htable[j].entries);
		}
		shm_free(htable);
	}
	return NULL;
}


sbtable_t new_shtable(int hash_size){
	sbtable_t htable= NULL;
	int i, j;

	i = 0;
	htable= (subs_table_t*)shm_malloc(hash_size* sizeof(subs_table_t));
	if(htable== NULL)
	{
		LM_ERR("--------------------------------------------------no more shm memory\n");
	}
	memset(htable, 0, hash_size* sizeof(subs_table_t));

	for(i= 0; i< hash_size; i++)
	{
		if(lock_init(&htable[i].lock)== 0)
		{
			LM_ERR("initializing lock [%d]\n", i);
			goto error;
		}
		htable[i].entries= (struct sm_subscriber*)shm_malloc(sizeof(struct sm_subscriber));
		if(htable[i].entries== NULL)
		{
			lock_destroy(&htable[i].lock);
			LM_ERR("--------------------------------------------------no more shm memory\n");
		}
		memset(htable[i].entries, 0, sizeof(struct sm_subscriber));
		htable[i].entries->next= NULL;
	}

	return htable;
error:
	if(htable){
		for(j=0; j< i; j++){
			lock_destroy(&htable[j].lock);
			shm_free(htable[j].entries);
		}
		shm_free(htable);
	}
	return NULL;
}



void destroy_ehtable(emetable_t htable, int hash_size){
	int i;

	if(htable== NULL)
		return;

	for(i= 0; i< hash_size; i++)
	{
		lock_destroy(&htable[i].lock);
		free_call_list(htable[i].entries->next);
		shm_free(htable[i].entries);
	}
	shm_free(htable);
	htable= NULL;
}

void destroy_shtable(sbtable_t htable, int hash_size){
	int i;

	if(htable== NULL)
		return;

	for(i= 0; i< hash_size; i++)
	{
		lock_destroy(&htable[i].lock);
		free_subs_list(htable[i].entries->next);
		shm_free(htable[i].entries);
	}
	shm_free(htable);
	htable= NULL;
}


void free_call_list(NODE* s_array){
	NODE* s;

	while(s_array){
		s= s_array;
		s_array= s_array->next;

		shm_free(s);
	}
}

void free_subs_list(struct sm_subscriber* s_array){
	struct sm_subscriber* s;

	while(s_array){
		s= s_array;
		s_array= s_array->next;

		shm_free(s);
	}
}

int insert_ehtable(emetable_t htable, unsigned int hash_code, ESCT* call_eme){
	NODE* new_rec= NULL;

	new_rec= mem_copy_call_noc(call_eme);
	if(new_rec== NULL){
		LM_ERR("copying in share memory a NODE structure\n");
		goto error;
	}

	lock_get(&htable[hash_code].lock);

	new_rec->next= htable[hash_code].entries->next;

	htable[hash_code].entries->next= new_rec;

	LM_DBG("******************************END ENTRADA DO HASH %p\n",(void*)new_rec);

	lock_release(&htable[hash_code].lock);

	return 0;

error:
	if(new_rec)
		shm_free(new_rec);
	return -1;
}


NODE* mem_copy_call_noc(ESCT* s){
	int size;
	NODE* dest = NULL;
	NODE* dest_atr;

	int   size_esgwri;
	int   size_esgw;
	int   size_esqk;
	int   size_callid;
	int   size_ert_srid;
	//int   size_datetimestamp;
	int   size_lro;
	//int   size_disposition;
	int   size_result;
	int   size_source_organizationname;
	int   size_source_hostname;
	int   size_source_nenaid;
	int   size_source_contact;
	int   size_source_certuri;
	int   size_vpc_organizationname;
	int   size_vpc_hostname;
	int   size_vpc_nenaid;
	int   size_vpc_contact;
	int   size_vpc_certuri;
	int   size_call_id;
	int   size_local_tag;
	int   size_rem_tag;
	char *p;

	size_esgwri = s->esgwri? strlen(s->esgwri)+1:1;
	size_esgw = s->esgw?strlen(s->esgw)+1:1;
	size_esqk = s->esqk? strlen(s->esqk)+1:1;
	size_callid = s->callid? strlen(s->callid)+1:1;
	size_ert_srid = s->ert_srid? strlen(s->ert_srid)+1:1;
	//size_datetimestamp = s->datetimestamp? strlen(s->datetimestamp)+1:1;
	size_lro = s->lro? strlen(s->lro)+1:1;
	//size_disposition = s->disposition? strlen(s->disposition)+1:1;
	size_result = s->result? strlen(s->result)+1:1;
	size_source_organizationname = s->source->organizationname? strlen(s->source->organizationname)+1:1;
	size_source_hostname = s->source->hostname? strlen(s->source->hostname)+1:1;
	size_source_nenaid = s->source->nenaid? strlen(s->source->nenaid)+1:1;
	size_source_contact = s->source->contact? strlen(s->source->contact)+1:1;
	size_source_certuri = s->source->certuri? strlen(s->source->certuri)+1:1;
	size_vpc_organizationname = s->vpc->organizationname? strlen(s->vpc->organizationname)+1:1;
	size_vpc_hostname = s->vpc->hostname? strlen(s->vpc->hostname)+1:1;
	size_vpc_nenaid = s->vpc->nenaid? strlen(s->vpc->nenaid)+1:1;
	size_vpc_contact = s->vpc->contact? strlen(s->vpc->contact)+1:1;
	size_vpc_certuri = s->vpc->certuri? strlen(s->vpc->certuri)+1:1;
	size_call_id = s->eme_dlg_id->call_id? strlen(s->eme_dlg_id->call_id)+1:1;
	size_local_tag = s->eme_dlg_id->local_tag? strlen(s->eme_dlg_id->local_tag)+1:1;
	size_rem_tag = s->eme_dlg_id->rem_tag? strlen(s->eme_dlg_id->rem_tag)+1:1;

	size= sizeof(NODE)+ sizeof(ESCT)+ (2 * sizeof(NENA)) + sizeof(struct dialog_set) + size_esgw + size_esqk+ size_callid + size_ert_srid
		+ MAX_TIME_SIZE + size_lro + MAX_DISPOSITION_SIZE + size_result + size_call_id + size_local_tag + size_rem_tag + size_source_organizationname
		+ size_source_hostname + size_source_nenaid + size_source_contact + size_source_certuri + size_vpc_organizationname + size_vpc_hostname
		+ size_vpc_nenaid + size_vpc_contact + size_vpc_certuri;

	p= (char*)shm_malloc(size);
	if(p== NULL){
		//ERR_MEM(SHARE_MEM);
		goto error;
	}
	memset(p, 0, size);

	dest = (NODE*)p;
	p = p + sizeof(NODE);
	dest->esct = (ESCT*)p;
	p = p + sizeof(ESCT);
	dest->esct->eme_dlg_id = (struct dialog_set*)p;

	size= sizeof(struct dialog_set );
	CONT_COPY(dest->esct->eme_dlg_id, dest->esct->eme_dlg_id->call_id, s->eme_dlg_id->call_id);
	CONT_COPY(dest->esct->eme_dlg_id, dest->esct->eme_dlg_id->local_tag, s->eme_dlg_id->local_tag);
	CONT_COPY(dest->esct->eme_dlg_id, dest->esct->eme_dlg_id->rem_tag, s->eme_dlg_id->rem_tag);

	p = p + size;
	dest->esct->source = (NENA*)p;
	size= sizeof(NENA);
	CONT_COPY(dest->esct->source, dest->esct->source->organizationname, s->source->organizationname);
	CONT_COPY(dest->esct->source, dest->esct->source->hostname, s->source->hostname);
	CONT_COPY(dest->esct->source, dest->esct->source->nenaid, s->source->nenaid);
	CONT_COPY(dest->esct->source, dest->esct->source->contact, s->source->contact);
	CONT_COPY(dest->esct->source, dest->esct->source->certuri, s->source->certuri);

	p = p + size;
	dest->esct->vpc = (NENA*)p;
	size= sizeof(NENA);
	CONT_COPY(dest->esct->vpc, dest->esct->vpc->organizationname, s->vpc->organizationname);
	CONT_COPY(dest->esct->vpc, dest->esct->vpc->hostname, s->vpc->hostname);
	CONT_COPY(dest->esct->vpc, dest->esct->vpc->nenaid, s->vpc->nenaid);
	CONT_COPY(dest->esct->vpc, dest->esct->vpc->contact, s->vpc->contact);
	CONT_COPY(dest->esct->vpc, dest->esct->vpc->certuri, s->vpc->certuri);

	p = p + size;
	dest_atr = (NODE*)p;
	size = 0;
	CONT_COPY(dest_atr, dest->esct->esgw, s->esgw);
	CONT_COPY(dest_atr, dest->esct->esqk, s->esqk);
	CONT_COPY(dest_atr, dest->esct->callid, s->callid);
	CONT_COPY(dest_atr, dest->esct->ert_srid, s->ert_srid);

	if(s->datetimestamp){
		dest->esct->datetimestamp= (char*)dest_atr+ size;
		memcpy(dest->esct->datetimestamp, s->datetimestamp, strlen(s->datetimestamp));
		size+=  MAX_TIME_SIZE;
	}

	CONT_COPY(dest_atr, dest->esct->lro, s->lro);

	if(s->disposition){
		dest->esct->disposition= (char*)dest_atr+ size;
		memcpy(dest->esct->disposition, s->disposition, strlen(s->disposition));
		size+=  MAX_DISPOSITION_SIZE;
	}

	CONT_COPY(dest_atr, dest->esct->result, s->result);

	dest->esct->ert_resn= s->ert_resn;
	dest->esct->ert_npa= s->ert_npa;
	dest->esct->timeout= s->timeout;

	dest->esct->esgwri= (char*)shm_malloc(size_esgwri);
	if(dest->esct->esgwri== NULL){
		//ERR_MEM(SHARE_MEM);
		goto error;
	}
	memset(dest->esct->esgwri, 0, size_esgwri);
	memcpy(dest->esct->esgwri, s->esgwri, size_esgwri - 1);

	return dest;

error:
	if(dest)
		shm_free(dest);
	return NULL;
}



struct sm_subscriber* insert_shtable(sbtable_t htable, unsigned int hash_code, struct sm_subscriber* subs){
	struct sm_subscriber* new_rec= NULL;

	new_rec= mem_copy_subs_noc(subs);
	if(new_rec== NULL){
		LM_ERR("copying in share memory a sm_subscriber structure\n");
		return NULL;
	}

	lock_get(&htable[hash_code].lock);

	new_rec->next= htable[hash_code].entries->next;
	htable[hash_code].entries->next= new_rec;

	lock_release(&htable[hash_code].lock);

	return new_rec;
}



struct sm_subscriber* mem_copy_subs_noc(struct sm_subscriber* s){
	int size;
	struct sm_subscriber* dest = NULL;
	struct sm_subscriber* dest_atr;
	char *p;

	size= sizeof(struct sm_subscriber) + (2 * sizeof(struct dialog_id))
		+ s->loc_uri.len + s->rem_uri.len + s->contact.len + s->event.len
		+ s->call_dlg_id->callid.len + s->call_dlg_id->local_tag.len + s->call_dlg_id->rem_tag.len
		+ s->dlg_id->callid.len + s->dlg_id->local_tag.len + s->dlg_id->rem_tag.len;

	p= (char*)shm_malloc(size);
	if(p== NULL){
		LM_ERR("no more shm\n");
		goto error;
	}
	memset(p, 0, size);

	dest = (struct sm_subscriber*)p;
	p = p + sizeof(struct sm_subscriber);
	dest->dlg_id = (struct dialog_id*)p;

	size= sizeof(struct dialog_id);
	CONT_COPY_STR(dest->dlg_id, dest->dlg_id->callid, s->dlg_id->callid);
	CONT_COPY_STR(dest->dlg_id, dest->dlg_id->local_tag, s->dlg_id->local_tag);
	CONT_COPY_STR(dest->dlg_id, dest->dlg_id->rem_tag, s->dlg_id->rem_tag);

	p = p + size;
	dest->call_dlg_id = (struct dialog_id*)p;

	size= sizeof(struct dialog_id);
	CONT_COPY_STR(dest->call_dlg_id, dest->call_dlg_id->callid, s->call_dlg_id->callid);
	CONT_COPY_STR(dest->call_dlg_id, dest->call_dlg_id->local_tag, s->call_dlg_id->local_tag);
	CONT_COPY_STR(dest->call_dlg_id, dest->call_dlg_id->rem_tag, s->call_dlg_id->rem_tag);

	p = p + size;
	dest_atr = (struct sm_subscriber*)p;
	size = 0;
	CONT_COPY_STR(dest_atr, dest->loc_uri, s->loc_uri);
	CONT_COPY_STR(dest_atr, dest->rem_uri, s->rem_uri);
	CONT_COPY_STR(dest_atr, dest->contact, s->contact);
	CONT_COPY_STR(dest_atr, dest->event, s->event);

	dest->expires= s->expires;
	dest->timeout= s->timeout;
	dest->version= s->version;

	return dest;

error:
	if(dest)
		shm_free(dest);
	return NULL;
}



NODE* search_ehtable(emetable_t htable, char* callid, char* from_tag, unsigned int hash_code, int delete){
	NODE* s;
	NODE* ps;
	int size_callid_t;
	int size_from_tag_t;
	int size_callid_m;
	int size_from_tag_m;

	ps= htable[hash_code].entries;
	s= ps->next;

	if (s == NULL){
		LM_DBG("Did not find\n");
		return NULL;
	}

	size_callid_t = strlen(s->esct->eme_dlg_id->call_id);
	size_from_tag_t = strlen(s->esct->eme_dlg_id->local_tag);
	size_callid_m = strlen(callid);
	size_from_tag_m = strlen(from_tag);

	LM_DBG(" --------------------CALLID M%s\n",callid);
	LM_DBG(" --------------------FROM TAG M%s\n",from_tag);
	LM_DBG(" --------------------CALLID T%s\n",s->esct->eme_dlg_id->call_id);
	LM_DBG(" --------------------FROM TAG T%s\n",s->esct->eme_dlg_id->local_tag);

	while(s)
	{
		if(size_callid_t == size_callid_m &&
			strncmp(s->esct->eme_dlg_id->call_id, callid, size_callid_m)==0 &&
			size_from_tag_t == size_from_tag_m &&
			strncmp(s->esct->eme_dlg_id->local_tag, from_tag, size_from_tag_m)== 0){
			LM_DBG(" --------------------found EHTABLE \n");

			if(delete){

				lock_get(&htable[hash_code].lock);

				LM_DBG(" --------------------DELETOU\n");
				ps->next = s->next;

				lock_release(&htable[hash_code].lock);

			}

			return s;
		}


		ps = s;
		s= s->next;
	}
	LM_DBG("Did not find\n");
	return NULL;
}


struct sm_subscriber* search_shtable(sbtable_t htable, str* callid, str* from_tag, unsigned int hash_code, str* method){
	struct sm_subscriber* s;
	struct sm_subscriber* ps;
	struct dialog_id* dlg_id;

	ps= htable[hash_code].entries;
	LM_DBG(" --------------------END HTABLE ENTRIES %p\n", (void*)ps);
	s= ps->next;

	if (s == NULL){
		LM_DBG("Did not find\n");
		return NULL;
	}

	LM_DBG("******************************METODO %.*s\n", method->len, method->s);

	while(s)
	{
		if (memcmp(method->s,"BYE", method->len) == 0) {
			dlg_id = s->call_dlg_id;
		}else{
			dlg_id = s->dlg_id;
		}

		LM_DBG(" --------------------CALLID M%.*s\n", callid->len, callid->s);
		LM_DBG(" --------------------FROM TAG M%.*s\n", from_tag->len, from_tag->s);
		LM_DBG(" --------------------CALLID T%.*s\n",dlg_id->callid.len,dlg_id->callid.s);
		LM_DBG(" --------------------FROM TAG T%.*s\n",dlg_id->rem_tag.len,dlg_id->rem_tag.s);


		if(dlg_id->callid.len == callid->len &&
			strncmp(dlg_id->callid.s, callid->s, callid->len)==0 &&
			dlg_id->rem_tag.len == from_tag->len &&
			strncmp(dlg_id->rem_tag.s, from_tag->s, from_tag->len)== 0){
			LM_DBG(" --------------------found SHTABLE \n");
			s->prev = ps;

			return s;
		}


		ps = s;
		s= s->next;
	}
	LM_DBG("Did not find\n");
	return NULL;
}

int delete_shtable(sbtable_t htable, unsigned int hash_code, struct sm_subscriber* subs){
	struct sm_subscriber* previous;

	lock_get(&htable[hash_code].lock);

	previous = subs->prev;
	previous->next = subs->next;
	shm_free(subs);

	lock_release(&htable[hash_code].lock);

	return 0;
}
