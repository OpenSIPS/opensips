/*
 * dialog module - basic support for dialog tracking
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
 *  2013-04-12 initial version (Liviu)
 */

#include "../../ut.h"
#include "../../bin_interface.h"
#include "../../socket_info.h"
#include "../../timer.h"
#include "../clusterer/api.h"

#ifndef _DIALOG_DLG_REPLICATION_H_
#define _DIALOG_DLG_REPLICATION_H_

#define REPLICATION_DLG_CREATED		1
#define REPLICATION_DLG_UPDATED		2
#define REPLICATION_DLG_DELETED		3

#define BIN_VERSION 1

extern int accept_replicated_dlg;
extern int dialog_replicate_cluster;

extern struct clusterer_binds clusterer_api;

void replicate_dialog_created(struct dlg_cell *dlg);
void replicate_dialog_updated(struct dlg_cell *dlg);
void replicate_dialog_deleted(struct dlg_cell *dlg);

int dlg_replicated_create(bin_packet_t *packet, struct dlg_cell *cell, str *ftag, str *ttag, int safe);
int dlg_replicated_update(bin_packet_t *packet);
int dlg_replicated_delete(bin_packet_t *packet);

void receive_repl_packets(enum clusterer_event ev, bin_packet_t *packet, int packet_type,
				struct receive_info *ri, int cluster_id, int src_id, int dest_id);

#endif /* _DIALOG_DLG_REPLICATION_H_ */

