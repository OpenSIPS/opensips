/*
 * shared call appearance module
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
 *  2010-11-02  initial version (Ovidiu Sas)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../ut.h"
#include "../../mem/shm_mem.h"
#include "../../usr_avp.h"
#include "../../parser/parse_uri.h"
#include "sca_records.h"


extern int watchers_avp_name;
extern unsigned short watchers_avp_type;

void add_watcher(str_lst_t **watchers, str_lst_t *new_watcher)
{
	new_watcher->next = *watchers;
	*watchers = new_watcher;
	return;
}


void free_watchers(str_lst_t *watchers)
{
	str_lst_t *watcher = watchers, *w;

	while (watcher) {
		w = watcher->next;
		pkg_free(watcher);
		watcher = w;
	}
	return;
}


void memcpy_watchers(str_lst_t *dest, str_lst_t *src, unsigned int size)
{
	str_lst_t *from = src;
	str_lst_t *to = dest;
	char *p;
	unsigned int len, total_len=0;

	p = (char *)to;
	while (from) {
		len = sizeof(str_lst_t) + from->watcher.len;
		total_len += len;
		if (len > size) {
			LM_CRIT("buffer overflow\n");
			return;
		}
		memcpy((char *)to, (char *)from, len);
		to->watcher.s = (char *)(to + 1);
		if (to->watcher.len != from->watcher.len) {
			LM_CRIT("error\n");
			return;
		}
		if (from->next == NULL) {
			to->next = NULL;
			break;
		}
		to->next = (str_lst_t *)(p + len);

		from = from->next;
		to = to->next;
	}

	return;
}


void print_watchers(str_lst_t *watchers)
{
	str_lst_t *watcher = watchers;
	unsigned int len = 0;

	while (watcher) {
		len += watcher->watcher.len;
		LM_DBG("watcher [%d] [%d][%.*s]\n", len, watcher->watcher.len,
					watcher->watcher.len, watcher->watcher.s);
		watcher = watcher->next;
	}
}


void get_watchers_from_avp(str_lst_t **watchers, unsigned int *watcher_size,
				unsigned int *watchers_no)
{
	str_lst_t *new_watcher;
	struct usr_avp *avp;
	int_str val;
	unsigned int size;
	struct sip_uri parsed_uri;
	char *p;

	*watchers = NULL;
	*watcher_size = 0;
	*watchers_no = 0;
	for(;;) {
		avp = search_first_avp(watchers_avp_type, watchers_avp_name, &val, 0);
		if (avp == NULL)
			break;
		if(avp->flags&AVP_VAL_STR)
			if (parse_uri(val.s.s, val.s.len, &parsed_uri)<0)
				LM_WARN("discarding non URI watcher [%.*s]\n", val.s.len, val.s.s);
			else {
				LM_DBG("got watcher [%.*s]\n", val.s.len, val.s.s);
				size = sizeof(str_lst_t) + val.s.len;
				new_watcher = (str_lst_t *)pkg_malloc(size);
				if (new_watcher == NULL) {
					LM_ERR("OOM\n");
					return;
				}
				memset(new_watcher, 0, size);

				p = (char*)(new_watcher + 1);
				new_watcher->watcher.len = val.s.len;
				new_watcher->watcher.s = p;
				memcpy(p, val.s.s, val.s.len);
				add_watcher(watchers, new_watcher);
				*watcher_size += size;
				*watchers_no += 1;
			}
		else
			LM_WARN("Ignoring non STR AVP\n");
		destroy_avp(avp);
	}
	print_watchers(*watchers);
	return;
}


void get_watchers_from_csv(str *watchers_csv, str_lst_t **watchers, unsigned int *watcher_size,
		unsigned int *watcher_no)
{
	str_lst_t *new_watcher;
	char *tmp;
	char *start = watchers_csv->s;
	char *end = watchers_csv->s + watchers_csv->len;
	unsigned int size;
	char *p;

	*watchers = NULL;
	*watcher_size = 0;
	*watcher_no = 0;
	for( tmp=watchers_csv->s; tmp<=end; tmp++) {
		if (*tmp == ',' || tmp==end) {
			LM_DBG("watcher->[%.*s]\n", (int)(tmp-start), start);

			size = sizeof(str_lst_t) + tmp-start;
			new_watcher = (str_lst_t *)pkg_malloc(size);
			if (new_watcher == NULL) {
				LM_ERR("OOM\n");
				return;
			}
			memset(new_watcher, 0, size);

			p = (char*)(new_watcher + 1);
			new_watcher->watcher.len = tmp-start;
			new_watcher->watcher.s = p;
			memcpy(p, start, tmp-start);
			add_watcher(watchers, new_watcher);
			*watcher_size += size;
			*watcher_no += 1;

			start = tmp + 1;
		}
	}
	print_watchers(*watchers);
	return;
}



void b2b_sca_print_call_record(unsigned int i, b2b_sca_call_t *call)
{
	LM_DBG("appearance[%d][%d:%.*s][%p]->[%.*s][%d][%d][%.*s][%.*s]\n",
		i, call->appearance_index,
		call->appearance_index_str.len, call->appearance_index_str.s,
		call, call->b2bl_key.len, call->b2bl_key.s, call->shared_entity,
		call->call_state, call->call_info_uri.len, call->call_info_uri.s,
		call->call_info_apperance_uri.len, call->call_info_apperance_uri.s);
}


void b2b_sca_print_record(b2b_sca_record_t *rec)
{
	unsigned int i;

	LM_DBG("record:[%p]->[%.*s] [%d] [%p:%p]\n",
		rec, rec->shared_line.len, rec->shared_line.s,
		rec->watchers_no, rec->prev, rec->next);
	print_watchers(rec->watchers);
	for (i=0; i<MAX_APPEARANCE_INDEX; i++) {
		if (rec->call[i]) {
			b2b_sca_print_call_record(i, rec->call[i]);
		}
	}
}



b2b_sca_call_t* b2b_sca_search_call_safe(b2b_sca_record_t *record, unsigned int appearance)
{
	if (!appearance || appearance > MAX_APPEARANCE_INDEX) {
		LM_ERR("out of bounds index [%d]\n", appearance);
		return NULL;
	}
	if (record->call[appearance - 1] == NULL) {
		LM_ERR("non existing call for shared line [%.*s] with index [%d]\n",
			record->shared_line.len, record->shared_line.s, appearance);
		return NULL;
	}
	return record->call[appearance - 1];
}

b2b_sca_record_t* b2b_sca_search_record_safe(int hash_index, str *shared_line)
{
	b2b_sca_record_t *record;

	record = b2b_sca_htable[hash_index].first;
	while(record && (record->shared_line.len != shared_line->len ||
			strncmp(record->shared_line.s, shared_line->s, shared_line->len) != 0)) {
		b2b_sca_print_record(record);
		record = record->next;
	}

	return record;
}

b2b_sca_call_t* restore_call(b2b_sca_record_t *record,
		unsigned int appearance_index, unsigned int shared_entity,
		unsigned int call_state, str *call_info_uri, str *call_info_apperance_uri)
{
	b2b_sca_call_t *call;
	unsigned int size;
	str appearance_index_str;
	char *p;

	appearance_index_str.s = int2str((unsigned long)appearance_index,
						&appearance_index_str.len);
	size = sizeof(b2b_sca_call_t) +
		appearance_index_str.len +
		call_info_uri->len +
		call_info_apperance_uri->len +
		B2BL_MAX_KEY_LEN;
	call = (b2b_sca_call_t *)shm_malloc(size);
	if (call == NULL) {
		LM_ERR("OOM\n");
		return NULL;
	}
	memset(call, 0, size);

	call->appearance_index = appearance_index;
	call->call_state = call_state;
	call->shared_entity = shared_entity;

	p = (char*)(call + 1);

	call->appearance_index_str.len = appearance_index_str.len;
	call->appearance_index_str.s = p;
	memcpy(p, appearance_index_str.s, appearance_index_str.len);
	p += appearance_index_str.len;

	call->call_info_uri.len = call_info_uri->len;
	call->call_info_uri.s = p;
	memcpy(p, call_info_uri->s, call_info_uri->len);
	p += call_info_uri->len;

	call->call_info_apperance_uri.len = call_info_apperance_uri->len;
	call->call_info_apperance_uri.s = p;
	memcpy(p, call_info_apperance_uri->s, call_info_apperance_uri->len);
	p += call_info_apperance_uri->len;

	call->b2bl_key.len = 0;
	call->b2bl_key.s = p;
	p += B2BL_MAX_KEY_LEN;

	record->call[appearance_index-1] = call;

	return call;
}


b2b_sca_record_t* restore_record(str *shared_line, str *watchers_csv)
{
	str_lst_t *watchers;
	unsigned int size, watcher_size, watchers_no;
	char *p;
	b2b_sca_record_t *record;

	get_watchers_from_csv(watchers_csv, &watchers, &watcher_size, &watchers_no);

	size = sizeof(b2b_sca_record_t) + shared_line->len + watcher_size;
	record = (b2b_sca_record_t *)shm_malloc(size);
	if (record == NULL) {
		LM_ERR("OOM\n");
		return NULL;
	}
	memset(record, 0, size);
	p = (char*)(record + 1);
	record->watchers_no = watchers_no;
	record->shared_line.len = shared_line->len;
	record->shared_line.s = p;
	memcpy(p, shared_line->s, shared_line->len);
	p += shared_line->len;
	record->watchers = (str_lst_t *)p;
	memcpy_watchers(record->watchers, watchers, watcher_size);
	if (watchers)
		free_watchers(watchers);
	return record;
}


int b2b_sca_update_call_record_key(b2b_sca_call_t *call, str* b2bl_key)
{
	if (!b2bl_key || !b2bl_key->s || b2bl_key->len > B2BL_MAX_KEY_LEN)
		return -1;
	memcpy(call->b2bl_key.s, b2bl_key->s, b2bl_key->len);
	call->b2bl_key.len = b2bl_key->len;
	return 0;
}


int b2b_sca_add_call_record(int hash_index, str *shared_line,
		unsigned int shared_entity, unsigned int app_index,
		str *call_info_uri, str *call_info_apperance_uri,
		b2b_sca_record_t **record_ctx, b2b_sca_call_t **call_ctx)
{
	//b2b_sca_record_t *rec, *prev_rec;
	b2b_sca_record_t *record;
	b2b_sca_call_t *call;
	unsigned int i, size, watcher_size, watchers_no;
	char *p;
	str_lst_t *watchers;

	if (app_index>=MAX_APPEARANCE_INDEX) {
		LM_ERR("Required app_index [%d] too big\n", app_index);
		return -1;
	}

	record = b2b_sca_search_record_safe(hash_index, shared_line);
	if (record) {
		/* We already have active calls for this shared line */
		if (app_index) {
			i = app_index - 1;
			if (record->call[i]) {
				LM_DBG("Searching for a new slot\n");
				for (i=0; i<MAX_APPEARANCE_INDEX; i++) {
					if (record->call[i] == NULL)
						break;
				}
			}
		} else {
			LM_DBG("no forced app_index\n");
			for (i=0; i<MAX_APPEARANCE_INDEX; i++) {
				if (record->call[i] == NULL)
					break;
			}
		}
		if (i == MAX_APPEARANCE_INDEX) {
			LM_ERR("No available slots for this call\n");
			return -1;
		}
		call = restore_call(record, i+1, shared_entity, ALERTING_STATE,
				call_info_uri, call_info_apperance_uri);
		if (call == NULL) {
			return -1;
		}
	} else {
		/* First call for this shared line */

		/* Get the list of watchers */
		get_watchers_from_avp(&watchers, &watcher_size, &watchers_no);

		size = sizeof(b2b_sca_record_t) + shared_line->len + watcher_size;
		record = (b2b_sca_record_t *)shm_malloc(size);
		if (record == NULL) {
			LM_ERR("OOM\n");
			return -1;
		}
		memset(record, 0, size);
		p = (char*)(record + 1);

		record->watchers_no = watchers_no;
		record->shared_line.len = shared_line->len;
		record->shared_line.s = p;
		memcpy(p, shared_line->s, shared_line->len);
		p += shared_line->len;

		if (watchers && watcher_size) {
			record->watchers = (str_lst_t *)p;
			memcpy_watchers(record->watchers, watchers, watcher_size);
			if (watchers)
				free_watchers(watchers);
		} else {
			record->watchers = NULL;
			LM_WARN("We have no watchers: watchers=[%p] and watcher_size=[%d]\n",
				watchers, watcher_size);
		}

		/* Let's take care of the call now */
		call = restore_call(record, app_index?app_index:1, shared_entity, ALERTING_STATE,
				call_info_uri, call_info_apperance_uri);
		if (call == NULL)
			goto error;

		/* Insert record into the table */
		insert_record(hash_index, record);
		/*
		rec = b2b_sca_htable[hash_index].first;
		if (rec) {
			while(rec) {
				prev_rec = rec;
				rec = rec->next;
			}
			prev_rec->next = record;
			record->prev = prev_rec;
		} else {
			b2b_sca_htable[hash_index].first = record;
			record->prev = record->next = NULL;
		}
		*/
	}

	*record_ctx = record;
	*call_ctx = call;
	return 0;
error:
	shm_free(record);
	return -1;
}


void b2b_sca_delete_call_record(int hash_index, b2b_sca_record_t *record, unsigned int appearance)
{
	b2b_sca_call_t *call = b2b_sca_search_call_safe(record, appearance);
	if (call) {
		shm_free(call);
		record->call[appearance - 1] = NULL;
	}
	return;
}




void b2b_sca_delete_record(b2b_sca_record_t *record, unsigned int hash_index)
{
	unsigned int i;

	if(b2b_sca_htable[hash_index].first == record) {
		b2b_sca_htable[hash_index].first = record->next;
		if(record->next)
			record->next->prev = NULL;
	} else {
		if(record->prev)
			record->prev->next = record->next;
		if(record->next)
			record->next->prev = record->prev;
	}

	for (i=0; i<MAX_APPEARANCE_INDEX; i++)
		if (record->call[i]) {
			b2b_sca_print_call_record(i, record->call[i]);
			LM_WARN("delete record with active appearance [%d]\n", i+1);
			shm_free(record->call[i]);
		}

	shm_free(record);

	return;
}

void b2b_sca_delete_record_if_empty(b2b_sca_record_t *record, unsigned int hash_index)
{
	unsigned int i;

	for (i=0; i<MAX_APPEARANCE_INDEX; i++)
		if (record->call[i])
			return;

	b2b_sca_delete_record(record, hash_index);

	return;
}


void insert_record(unsigned int hash_index, b2b_sca_record_t *record)
{
	b2b_sca_record_t *rec, *prev_rec;

	/* Insert record into the table */
	rec = b2b_sca_htable[hash_index].first;
	if (rec) {
		while(rec) {
			prev_rec = rec;
			rec = rec->next;
		}
		prev_rec->next = record;
		record->prev = prev_rec;
	} else {
		b2b_sca_htable[hash_index].first = record;
		record->prev = record->next = NULL;
	}
}


int init_b2b_sca_htable(void) {
	int i;
	b2b_sca_htable = (b2b_sca_table_t)shm_malloc(b2b_sca_hsize* sizeof(b2b_sca_entry_t));
	if(!b2b_sca_htable) {
		LM_ERR("OOM\n");
		goto error;
	}

	for(i= 0; i< b2b_sca_hsize; i++) {
		lock_init(&b2b_sca_htable[i].lock);
		b2b_sca_htable[i].first = NULL;
	}

	return 0;
error:
	return -1;
}

void destroy_b2b_sca_htable(void) {
	int i;
	b2b_sca_record_t *record;

	if(!b2b_sca_htable)
		return;

	for(i= 0; i< b2b_sca_hsize; i++) {
		lock_destroy(&b2b_sca_htable[i].lock);
		record = b2b_sca_htable[i].first;

		while(record) {
			b2b_sca_delete_record(record, i);
			record = b2b_sca_htable[i].first;
		}
	}

	shm_free(b2b_sca_htable);

	return;
}
