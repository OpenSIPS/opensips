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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2013-04-12 initial version (Liviu)
 */

#include "../../ut.h"
#include "../../bin_interface.h"
#include "../../socket_info.h"
#include "../../timer.h"

#ifndef _DIALOG_DLG_REPLICATION_H_
#define _DIALOG_DLG_REPLICATION_H_

#define REPLICATION_DLG_CREATED		1
#define REPLICATION_DLG_UPDATED		2
#define REPLICATION_DLG_DELETED		3

extern int accept_replicated_dlg;
extern struct replication_dest *replication_dests;

struct replication_dest {
	union sockaddr_union to;
	struct replication_dest *next;
};

void replicate_dialog_created(struct dlg_cell *dlg);
void replicate_dialog_updated(struct dlg_cell *dlg);
void replicate_dialog_deleted(struct dlg_cell *dlg);

int dlg_replicated_create(struct dlg_cell *cell, str *ftag, str *ttag, int safe);
int dlg_replicated_update(void);
int dlg_replicated_delete(void);

void receive_binary_packet(int info_type);

#endif /* _DIALOG_DLG_REPLICATION_H_ */

