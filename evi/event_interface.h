/*
 * Copyright (C) 2011 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2011-05-xx  created (razvancrainea)
 */

#ifndef _EVENT_INTERFACE_H_
#define _EVENT_INTERFACE_H_

#include "evi_transport.h"
#include "evi.h"
#include "../locking.h"
#include "../str.h"

#define TRANSPORT_SEP	':'
#define DEFAULT_EXPIRE	3600

typedef struct evi_subscriber {
	evi_export_t* trans_mod;			/* transport module */
	evi_reply_sock* reply_sock;		/* reply socket */
	struct evi_subscriber *next;		/* next subscriber */ 
} evi_subs_t, *evi_subs_p;


typedef struct evi_event {
	event_id_t id;					/* event id */
	str name;						/* event name */
	gen_lock_t *lock;				/* lock for list */
	evi_subs_p subscribers;			/* subscribers list for this event */
} evi_event_t, *evi_event_p;


/* function used to subscribe for an event */
struct mi_root * mi_event_subscribe(struct mi_root *cmd_tree, void *param);

/* returns the transport export */
evi_export_t* get_trans_mod(str* tran);

/* returns the transport modules number */
int get_trans_mod_no(void);

#endif /* _EVENT_INTERFACE_H_ */

