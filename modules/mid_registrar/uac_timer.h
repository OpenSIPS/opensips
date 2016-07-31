/*
 * timer routine which periodically generates outbound registrations
 *
 * Copyright (C) 2016 OpenSIPS Solutions
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
 *  2016-07-06 initial version (liviu)
 */

#ifndef __MID_REG_UAC_TIMER_H_
#define __MID_REG_UAC_TIMER_H_

#include "../usrloc/usrloc.h"
#include "../usrloc/urecord.h"
#include "../signaling/signaling.h"
#include "../tm/tm_load.h"

#include "../../lib/list.h"

extern struct usrloc_api ul_api;
extern struct tm_binds tm_api;
extern struct sig_binds sig_api;

extern time_t act_time;

/*
 * may act as an AoR or a contact, depending on whether contact aggregation is
 * enabled or not
 */
struct mid_reg_queue_entry {
	struct list_head queue;
	/* TODO add ld_queue and my_ld_queue */

	/* De-registrations will be generated over to this SIP URI */
	str ruri;

	str ct_uri;

	unsigned int max_contacts;
	unsigned int flags;

	unsigned int expires;
	unsigned int expires_out;

	unsigned int next_check_ts;
	unsigned int last_register_out_ts;

	urecord_t *rec;
	ucontact_t *con;
	udomain_t *dom;
	str aor;
};

/* add to a priority queue, sorted by registration time */
void timer_queue_add(struct mid_reg_queue_entry *te);

int should_relay_register(ucontact_t *con, unsigned int expires);
int timer_queue_update_by_ct(ucontact_t *con, unsigned int expires);

void timer_queue_del_contact(ucontact_t *ct);

/* performs all pending outbound (re)registrations (first in the queue) */
void mid_reg_uac(unsigned int ticks, void *attr);

int timer_queue_init(void);

void print_timer_queue(void);

#endif /* __MID_REG_UAC_TIMER_H_ */
