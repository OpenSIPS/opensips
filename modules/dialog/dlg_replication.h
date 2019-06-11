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
#include "../../rw_locking.h"
#include "../clusterer/api.h"

#ifndef _DIALOG_DLG_REPLICATION_H_
#define _DIALOG_DLG_REPLICATION_H_

#define REPLICATION_DLG_CREATED		1
#define REPLICATION_DLG_UPDATED		2
#define REPLICATION_DLG_DELETED		3
#define DLG_SHARING_TAG_ACTIVE		4
#define REPLICATION_DLG_CSEQ		5

#define BIN_VERSION 1

#define SHTAG_STATE_BACKUP 0
#define SHTAG_STATE_ACTIVE 1

struct n_send_info {
	int node_id;
	struct n_send_info *next;
};

struct dlg_sharing_tag {
	str name;
	int state;
	int send_active_msg;
	struct n_send_info *active_msgs_sent;
	struct dlg_sharing_tag *next;
};

extern struct dlg_sharing_tag **shtags_list;
extern rw_lock_t *shtags_lock;

extern int dialog_repl_cluster;
extern int profile_repl_cluster;

extern str dlg_repl_cap;
extern str prof_repl_cap;

extern struct clusterer_binds clusterer_api;

extern str shtag_dlg_val;

void replicate_dialog_created(struct dlg_cell *dlg);
void replicate_dialog_updated(struct dlg_cell *dlg);
void replicate_dialog_deleted(struct dlg_cell *dlg);
void replicate_dialog_cseq_updated(struct dlg_cell *dlg, int leg);

int dlg_replicated_create(bin_packet_t *packet, struct dlg_cell *cell, str *ftag,
							str *ttag, int safe);
int dlg_replicated_update(bin_packet_t *packet);
int dlg_replicated_delete(bin_packet_t *packet);

void receive_dlg_repl(bin_packet_t *packet);
void rcv_cluster_event(enum clusterer_event ev, int node_id);

struct mi_root *mi_sync_cl_dlg(struct mi_root *cmd, void *param);
struct mi_root *mi_set_shtag_active(struct mi_root *cmd, void *param);

int get_shtag(str *tag_name);
int get_shtag_state(struct dlg_cell *dlg);
int set_dlg_shtag(struct dlg_cell *dlg, str *tag_name);
void free_active_msgs_info(struct dlg_sharing_tag *tag);

struct mi_root *mi_list_sharing_tags(struct mi_root *cmd_tree, void *param);

int dlg_sharing_tag_paramf(modparam_t type, void *val);

#endif /* _DIALOG_DLG_REPLICATION_H_ */

