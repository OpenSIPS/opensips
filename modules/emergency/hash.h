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
#include "../../lock_ops.h"
#include "xml_parser.h"

#define PKG_MEM_STR       "pkg"
#define SHARE_MEM         "share"

#define CONT_COPY(buf, dest, source)\
	if(source){dest= (char*)buf+ size;\
		if(source == empty){\
			dest = empty;\
		}else{\
			memcpy(dest, source, strlen(source));\
		}\
		size+= strlen(source) + 1;\
	}

#define CONT_COPY_STR(buf, dest, source)\
	do{	dest.s= (char*)buf+ size;\
		memcpy(dest.s, source.s, source.len);\
		dest.len= source.len;\
		size+= source.len;\
	} while(0)

typedef struct call_htable
{
	NODE* entries;
	gen_lock_t lock;
}call_table_t;

typedef call_table_t* emetable_t;

typedef struct subs_htable
{
	struct sm_subscriber* entries;
	gen_lock_t lock;
}subs_table_t;

typedef subs_table_t* sbtable_t;

emetable_t new_ehtable(int hash_size);
void destroy_ehtable(emetable_t htable, int hash_size);
void free_call_list(NODE* s_array);

sbtable_t new_shtable(int hash_size);
void destroy_shtable(sbtable_t htable, int hash_size);
void free_subs_list(struct sm_subscriber* s_array);
NODE* mem_copy_call_noc(ESCT* s);
int insert_ehtable(emetable_t htable, unsigned int hash_code, ESCT* call_eme);
struct sm_subscriber* mem_copy_subs_noc(struct sm_subscriber* s);
struct sm_subscriber* insert_shtable(sbtable_t htable, unsigned int hash_code, struct sm_subscriber* call_eme);
NODE* search_ehtable(emetable_t htable, char* callid, char* from_tag, unsigned int hash_code, int delete);
struct sm_subscriber* search_shtable(sbtable_t htable, str* callid, str* from_tag, unsigned int hash_code, str* method);
int delete_shtable(sbtable_t htable, unsigned int hash_code, struct sm_subscriber* subs);
