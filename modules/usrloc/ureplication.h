/*
 * Usrloc record and contact replication
 *
 * Copyright (C) 2013 OpenSIPS Solutions
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
 *  2013-10-09 initial version (Liviu)
 */

#ifndef _USRLOC_REPLICATION_H_
#define _USRLOC_REPLICATION_H_

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

#define BIN_VERSION 1

extern int accept_replicated_udata;
extern str repl_module_name;

extern int ul_replicate_cluster;
extern struct clusterer_binds clusterer_api;

/* duplicate local events to other OpenSIPS instances */
void replicate_urecord_insert(urecord_t *r);
void replicate_urecord_delete(urecord_t *r);
void replicate_ucontact_insert(urecord_t *r, str *contact, ucontact_info_t *ci);
void replicate_ucontact_update(urecord_t *r, str *contact, ucontact_info_t *ci);
void replicate_ucontact_delete(urecord_t *r, ucontact_t *c);

void receive_binary_packet(enum clusterer_event ev, bin_packet_t *, int packet_type,
				struct receive_info *ri, int cluster_id, int src_id, int dest_id);

#endif /* _USRLOC_REPLICATION_H_ */

