/*
 * presence module - presence server implementation
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
 *  2006-08-15  initial version (Anca Vamanu)
 *  2010-10-19  support for extra headers (osas)
 */

#ifndef PRESENTITY_H
#define PRESENTITY_H

#include "../../str.h"
#include "../../parser/msg_parser.h"
#include "event_list.h"
//#include "presence.h"

extern char prefix;

typedef struct presentity
{
	int presid;
	str user;
	str domain;
	pres_ev_t* event;
	int etag_count;
	str old_etag;
	str new_etag;
	str* sender;
	time_t expires;
	time_t received_time;
	str* extra_hdrs;
	short etag_new;
	char* sphere;
	str body;
	unsigned int flags; /* same as for pres_entry_t */
} presentity_t;

int internal_update_presentity(presentity_t* presentity);

/* update presentity in database */
int update_presentity(struct sip_msg* msg, presentity_t* presentity, int* sent_reply);

/* free memory */
void free_presentity(presentity_t* p);

int generate_ETag(int etag_count, str* etag);

int pres_htable_restore(void);

char* extract_sphere(str body);

char* get_sphere(str* pres_uri);
typedef char* (*pres_get_sphere_t)(str* pres_uri);

int contains_presence(str* pres_uri);
typedef int (*pres_contains_presence_t)(str* pres_uri);

int get_dialog_state(str body, int *dialog_state);
str* xml_dialog_gen_presence(str* pres_uri, int dlg_state);

int pres_expose_evi(pres_ev_t *ev, str *filter);

#endif

