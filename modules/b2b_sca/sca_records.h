/*
 * sca logic module
 *
 * Copyright (C) 2010 VoIP Embedded, Inc.
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
 *  2010-11-21  initial version (Ovidiu Sas)
 */

#ifndef B2B_SLA_RECORDS
#define B2B_SLA_RECORDS

#include <stdio.h>
#include <stdlib.h>

#include "../../usr_avp.h"
#include "../b2b_logic/b2b_load.h"

#define CALL_INFO_HEADER_MAX_LEN	512

#define IDLE_STATE		0
#define ALERTING_STATE		1
#define ACTIVE_STATE		2
#define HELD_STATE		3
#define HELD_PRIVATE_STATE	4
#define MAX_INDEX_STATE		4

#define MAX_APPEARANCE_INDEX	10


typedef struct str_lst{
	str watcher;
	struct str_lst *next;
} str_lst_t;

typedef struct b2b_sca_call {
	unsigned int shared_entity;	/* the entity to keep */
	unsigned int appearance_index;	/* appearance index */
	str appearance_index_str;	/* appearance index stored as str */
	unsigned int call_state;	/* state of the call */
	str call_info_uri;		/* call info: absoluteURI */
	str call_info_apperance_uri;	/* call info: appearance param URI */
	str b2bl_key;			/* key for the associated b2b_logic tuple */
} b2b_sca_call_t;

typedef struct b2b_sca_record {
	str shared_line;				/* shared line identifier */
	int expires;
	unsigned int watchers_no;
	str_lst_t *watchers;				/* list of watchers */
	b2b_sca_call_t *call[MAX_APPEARANCE_INDEX];	/* array of appearances */
	struct b2b_sca_record *prev;
	struct b2b_sca_record *next;
} b2b_sca_record_t;

typedef struct b2b_sca_entry {
	b2b_sca_record_t *first;
	gen_lock_t lock;
} b2b_sca_entry_t;

typedef b2b_sca_entry_t *b2b_sca_table_t;

extern b2b_sca_table_t b2b_sca_htable;
extern unsigned int b2b_sca_hsize;

int init_b2b_sca_htable(void);
void destroy_b2b_sca_htable(void);

/*
void memcpy_watchers(str_lst_t *dest, str_lst_t *src, unsigned int size);
void get_watchers_from_csv(str *watchers_csv, str_lst_t **watchers,
	unsigned int *watcher_size, unsigned int *watcher_no);
*/

void add_watcher(str_lst_t **watchers, str_lst_t *new_watcher);
void free_watchers(str_lst_t *watchers);
void print_watchers(str_lst_t *watchers);

void b2b_sca_print_record(b2b_sca_record_t *rec);
b2b_sca_call_t* b2b_sca_search_call_safe(b2b_sca_record_t *record, unsigned int appearance);
b2b_sca_record_t* b2b_sca_search_record_safe(int hash_index, str *shared_line);
int b2b_sca_update_call_record_key(b2b_sca_call_t *call, str* b2bl_key);
int b2b_sca_add_call_record(int hash_index, str *shared_line,
		unsigned int shared_entity, unsigned int app_index,
		str *call_info_uri, str *call_info_apperance_uri,
		b2b_sca_record_t **record, b2b_sca_call_t **call);
void b2b_sca_delete_call_record(int hash_index, b2b_sca_record_t *record, unsigned int appearance);
void b2b_sca_delete_record_if_empty(b2b_sca_record_t *record, unsigned int hash_index);

b2b_sca_call_t* restore_call(b2b_sca_record_t *record,
		unsigned int appearance_index, unsigned int shared_entity,
		unsigned int call_state, str *call_info_uri, str *call_info_apperance_uri);
b2b_sca_record_t* restore_record(str *shared_line, str *watchers_csv);

void insert_record(unsigned int hash_index, b2b_sca_record_t *record);

#endif
