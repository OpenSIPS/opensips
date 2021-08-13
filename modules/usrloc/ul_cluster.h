/*
 * user location clustering
 *
 * Copyright (C) 2013-2019 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _USRLOC_CLUSTER_H_
#define _USRLOC_CLUSTER_H_

#include "../../ut.h"
#include "../../bin_interface.h"
#include "../../socket_info.h"
#include "../../resolve.h"
#include "../../timer.h"
#include "../clusterer/api.h"

#include "urecord.h"

#define REPL_URECORD_INSERT  1
#define REPL_URECORD_DELETE  2
#define REPL_UCONTACT_INSERT 3
#define REPL_UCONTACT_UPDATE 4
#define REPL_UCONTACT_DELETE 5

#define UL_BIN_V2      2
#define UL_BIN_V3      3 // added "cmatch" (default: CT_MATCH_CONTACT_CALLID)

#define UL_BIN_VERSION UL_BIN_V3

extern int location_cluster;
extern struct clusterer_binds clusterer_api;
extern str ul_shtag_key;

extern str contact_repl_cap;

int ul_init_cluster(void);
#define _is_my_ucontact(__ct) \
	(!__ct->shtag.s || \
	 clusterer_api.shtag_get(&__ct->shtag, location_cluster) \
		== SHTAG_STATE_ACTIVE)

/* duplicate local events to other OpenSIPS instances */
void replicate_urecord_insert(urecord_t *r);
void replicate_urecord_delete(urecord_t *r);
void replicate_ucontact_insert(urecord_t *r, str *contact, ucontact_t *c,
        const struct ct_match *match);
void replicate_ucontact_update(urecord_t *r, ucontact_t *ct,
        const struct ct_match *match);
void replicate_ucontact_delete(urecord_t *r, ucontact_t *c,
        const struct ct_match *match);

void receive_binary_packets(bin_packet_t *packet);
void receive_cluster_event(enum clusterer_event ev, int node_id);

#endif /* _USRLOC_CLUSTER_H_ */
