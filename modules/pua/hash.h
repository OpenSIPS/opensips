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


#ifndef _PU_HASH_H_
#define _PU_HASH_H_

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../../str.h"
#include "../../lock_ops.h"
#include "../../dprint.h"
#include "../../parser/msg_parser.h"
#include "event_list.h"
#include "uri_list.h"

#define PRESENCE_EVENT      1<<0
#define PWINFO_EVENT        1<<1
#define BLA_EVENT           1<<2
#define MSGSUM_EVENT        1<<3
#define CONFERENCE_EVENT    1<<4
#define XCAPDIFF_EVENT      1<<5
#define DIALOG_EVENT        1<<6
#define CALLINFO_EVENT      1<<7

#define UL_PUBLISH          1<<0
#define BLA_PUBLISH         1<<1
#define BLA_SUBSCRIBE       1<<2
#define XMPP_PUBLISH        1<<3
#define XMPP_SUBSCRIBE      1<<4
#define XMPP_INITIAL_SUBS   1<<5
#define MI_PUBLISH          1<<6
#define MI_ASYN_PUBLISH     1<<7
#define MI_SUBSCRIBE        1<<8
#define RLS_SUBSCRIBE       1<<9
#define DIALOG_PUBLISH      1<<10
#define CALLINFO_PUBLISH    1<<11

#define NO_UPDATEDB_FLAG    0
#define UPDATEDB_FLAG       1
#define INSERTDB_FLAG       2

#define MAX_FORWARD  70

#define PRES_HASH_ID(presentity)(HASH_SIZE*presentity->local_index + presentity->hash_index)

typedef struct publ
{
	str content_type;
	str body;
	str extra_headers;
	int expires;
	void* cb_param;
	struct publ* next;
}publ_t;

typedef struct ua_pres{
	/* common*/
	unsigned int hash_index;
	unsigned int local_index;
	str id;
	str* pres_uri;
	int event;
	unsigned int expires;
	unsigned int desired_expires;
	int flag;
	int db_flag;
	struct ua_pres* next;
	int ua_flag;

	/* publish */
	str etag;
	str tuple_id;
	int waiting_reply;
	publ_t* pending_publ;

	/* subscribe */
	str to_uri;
	str* watcher_uri;
	str call_id;
	str to_tag;
    str from_tag;
	int cseq;
	int version;
    int watcher_count;
	str* outbound_proxy;
	str extra_headers;
	str record_route;
	str remote_contact;
	str contact;
	void* cb_param;
}ua_pres_t;

typedef struct hash_entry
{
	ua_pres_t* entity;
	gen_lock_t lock;
}hash_entry_t;

typedef struct htable{
    hash_entry_t* p_records;
}htable_t;

htable_t* new_htable(void);

ua_pres_t* search_htable(ua_pres_t* pres, unsigned int hash_code);

struct publ_info;

unsigned long insert_htable(ua_pres_t* presentity);
unsigned long new_publ_record(struct publ_info* publ, pua_event_t* ev, str* tuple);

int update_htable(unsigned int hash_index, unsigned int local_index,
		int expires, str* etag, str* contact);
int find_htable(unsigned int hash_index, unsigned int local_index);
void delete_htable(unsigned int hash_index, unsigned int local_index);
ua_pres_t* get_htable_safe(unsigned int hash_index, unsigned int local_index);

void destroy_htable(void);
int is_dialog(ua_pres_t* dialog);

ua_pres_t* get_dialog(ua_pres_t* dialog, unsigned int hash_code);

int get_record_id(ua_pres_t* dialog, str** rec_id);
typedef int (*get_record_id_t)(ua_pres_t* dialog, str** rec_id);

/* for degug */
void print_ua_pres(ua_pres_t* p);

typedef int  (*query_dialog_t)(ua_pres_t* presentity);

static inline int get_event_flag(str* event)
{
    switch (event->len)
    {
		case 6:
			if (strncasecmp(event->s, "dialog", 6) == 0)
				return DIALOG_EVENT;
			break;
		case 8:
			if (strncasecmp(event->s, "presence", 8) == 0)
				return PRESENCE_EVENT;
			break;
		case 9:
			if (strncasecmp(event->s, "xcap-diff", 9) == 0)
				return XCAPDIFF_EVENT;
			if (strncasecmp(event->s, "call-info", 9) == 0)
				return CALLINFO_EVENT;
			break;
		case 10:
			if (strncasecmp(event->s, "dialog;sla", 10) == 0)
				return BLA_EVENT;
			if (strncmp(event->s, "conference", 10) == 0)
				return CONFERENCE_EVENT;
			break;
		case 14:
			if (strncasecmp(event->s, "presence;winfo", 14) == 0)
				return PWINFO_EVENT;
			break;
		case 15:
			if (strncasecmp(event->s, "message-summary", 15) == 0)
				return MSGSUM_EVENT;
	}
	LM_ERR("Unknown event string\n");
	return -1;
}

int update_contact(struct sip_msg* msg);
void delete_htable_safe(ua_pres_t* p, unsigned int hash_index);

list_entry_t *get_subs_list(str *did);
typedef list_entry_t * (*get_subs_list_t)(str *did);

#endif
