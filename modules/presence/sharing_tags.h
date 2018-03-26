/*
 * Copyright (C) 2018 OpenSIPS Solutions
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


#ifndef _PRESENCE_SHARING_TAGS_H
#define _PRESENCE_SHARING_TAGS_H

#define SHTAG_STATE_BACKUP 0
#define SHTAG_STATE_ACTIVE 1

#include "../../sr_module.h"
#include "../../mi/mi.h"
#include "../clusterer/api.h"

struct n_send_info {
	int node_id;
	struct n_send_info *next;
};

struct sharing_tag {
	str name;
	int state;
	int send_active_msg;
	struct n_send_info *active_msgs_sent;
	struct sharing_tag *next;
};


#define SHTAG_IS_ACTIVE         10001


int init_shtag_list(void);

int sharing_tag_func(modparam_t type, void *val);

void shlist_flush_state(struct clusterer_binds *c_api, int c_id,
		str *cap, int node_id);

int send_shtag_active_info(struct clusterer_binds *c_api, int c_id,
		str *cap, str *tag_name, int node_id);

struct sharing_tag *get_shtag(str *tag_name, int set, int new_state);

str** get_all_active_shtags(void);

int list_shtags(struct mi_node *rpl);


#endif

