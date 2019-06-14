/*
 * presence module - presence server implementation
 *
 * Copyright (C) 2007 Voice Sistem S.R.L.
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
 *  2007-08-20  initial version (Anca Vamanu)
 */


#ifndef PS_HASH_H
#define PS_HASH_H

#include "../../lock_ops.h"
#include "../../str.h"
//#include "presentity.h"

struct presentity;
#define REMOTE_TYPE   1<<1
#define LOCAL_TYPE    1<<2
#define JUST_CHECK    1<<3

#define PKG_MEM_STR       "pkg"
#define SHARE_MEM         "share"

#define ETAG_LEN  128

#define ERR_MEM(mem_type)  \
		do {	LM_ERR("No more %s memory\n",mem_type);\
				goto error;\
		} while(0)

#define CONT_COPY_P_x(buf, dest, source)\
	do{	dest= (str*)((char*)buf+ size);\
		size+= sizeof(str);\
		dest->s = (char*)buf + size;\
		memcpy(dest->s, source->s, source->len);\
		dest->len= source->len;\
		size+= source->len;\
	} while(0)


#define CONT_COPY(buf, dest, source)\
	do{	dest.s= (char*)buf+ size;\
	memcpy(dest.s, source.s, source.len);\
	dest.len= source.len;\
	size+= source.len;\
	} while(0)

#define PKG_MEM_TYPE     0
#define SHM_MEM_TYPE     1

/* subscribe hash entry */
struct subscription;

typedef struct subs_entry
{
	struct subscription* entries;
	gen_lock_t lock;
}subs_entry_t;

typedef subs_entry_t* shtable_t;

shtable_t new_shtable(int hash_size);

struct subscription* search_shtable(shtable_t htable, str callid,str to_tag,str from_tag,
		unsigned int hash_code);

int insert_shtable(shtable_t htable, unsigned int hash_code, struct subscription* subs);

int delete_shtable(shtable_t htable, unsigned int hash_code, str to_tag);

int update_shtable(shtable_t htable, unsigned int hash_code, struct subscription* subs,
		int type);

struct subscription* mem_copy_subs(struct subscription* s, int mem_type);

void free_subs_list(struct subscription* s_array, int mem_type, int ic);

void destroy_shtable(shtable_t htable, int hash_size);

/* subs htable functions type definitions */
typedef shtable_t (*new_shtable_t)(int hash_size);

typedef struct subscription* (*search_shtable_t)(shtable_t htable, str callid,str to_tag,
		str from_tag, unsigned int hash_code);

typedef int (*insert_shtable_t)(shtable_t htable, unsigned int hash_code,
		struct subscription* subs);

typedef int (*delete_shtable_t)(shtable_t htable, unsigned int hash_code,
		str to_tag);

typedef int (*update_shtable_t)(shtable_t htable, unsigned int hash_code,
		struct subscription* subs, int type);

typedef void (*destroy_shtable_t)(shtable_t htable, int hash_size);

typedef struct subscription* (*mem_copy_subs_t)(struct subscription* s, int mem_type);

void free_subs(struct subscription* s);

#define PRES_FLAG_REPLICATED (1<<0)

/* presentity hash table */
typedef struct pres_entry
{
	str pres_uri;
	int event;
	int etag_count;
	char* sphere;
	char etag[ETAG_LEN];
	int etag_len;
	unsigned int flags;
	/* ordering */
	unsigned int current_turn;
	unsigned int last_turn;
	struct pres_entry* next;
}pres_entry_t;

typedef struct cluster_query_entry
{
	str pres_uri;
	int event;
	struct cluster_query_entry* next;
}cluster_query_entry_t;


typedef struct pres_htable
{
	pres_entry_t          *entries;
	cluster_query_entry_t *cq_entries;
	gen_lock_t lock;
}phtable_t;


phtable_t* new_phtable(void);
void destroy_phtable(void);

pres_entry_t* search_phtable(str* pres_uri, int event, unsigned int hash_code);

pres_entry_t* search_phtable_etag(str* pres_uri, int event,
		str* etag, unsigned int hash_code);

void update_pres_etag(pres_entry_t* p, str* etag);

pres_entry_t* insert_phtable(str* pres_uri, int event, str* etag,
		char* sphere, unsigned int flags, int init_turn);

int update_phtable(struct presentity* presentity, str pres_uri, str body);

void next_turn_phtable(pres_entry_t* p_p, unsigned int hash_code);

int delete_phtable(pres_entry_t* p, unsigned int hash_code);

int delete_phtable_query(str *pres_uri, int event, str* etag);



cluster_query_entry_t* insert_cluster_query(str* pres_uri, int event,
	unsigned int hash_code);

cluster_query_entry_t* search_cluster_query(str* pres_uri, int event,
	unsigned int hash_code);

int delete_cluster_query(str* pres_uri, int event, unsigned int hash_code);

#endif

