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


#include "../../ut.h"
#include "../../str.h"
#include "../../rw_locking.h"
#include "../../bin_interface.h"
#include "sharing_tags.h"

static struct sharing_tag **shtags_list = NULL;
static rw_lock_t *shtags_lock = NULL;

static struct sharing_tag *get_shtag_unsafe(str *tag_name);

#define SHTAG_BIN_VERSION       1


int init_shtag_list(void)
{
	if (shtags_list==NULL) {
		if ((shtags_list = shm_malloc(sizeof *shtags_list)) == NULL) {
			LM_CRIT("No more shm memory\n");
			return -1;
		}
		*shtags_list = NULL;

		if ((shtags_lock = lock_init_rw()) == NULL) {
			LM_CRIT("Failed to init lock\n");
			return -1;
		}
	}
	return 0;
}


int sharing_tag_func(modparam_t type, void *val)
{
	str tag_name;
	str val_s;
	int init_state;
	char *p;
	struct sharing_tag *tag;

	val_s.s = (char *)val;
	val_s.len = strlen(val_s.s);

	/* tag name */
	p = memchr(val_s.s, '=', val_s.len);
	if (!p) {
		LM_ERR("Bad definition for sharing tag param\n");
		return -1;
	}
	tag_name.s = val_s.s;
	tag_name.len = p - val_s.s;
	/* initial tag state */
	if (!memcmp(p+1, "active", val_s.len - tag_name.len - 1))
		init_state = SHTAG_STATE_ACTIVE;
	else if (!memcmp(p+1, "backup", val_s.len - tag_name.len - 1))
		init_state = SHTAG_STATE_BACKUP;
	else {
		LM_ERR("Bad state for sharing tag param\n");
		return -1;
	}

	if (init_shtag_list()<0) {
		LM_ERR("failed to init the sharing tags list\n");
		return -1;
	}

	/* create sharing tag with given state */
	if ((tag = get_shtag_unsafe(&tag_name)) == NULL) {
		LM_ERR("Unable to create replication tag [%.*s]\n",
			tag_name.len, tag_name.s);
		return -1;
	}
	tag->state = init_state;

	if (init_state == SHTAG_STATE_ACTIVE)
		/* broadcast (later) in cluster that this tag is active */
		tag->send_active_msg = 1;

	return 0;
}

static struct sharing_tag *create_shtag(str *tag_name)
{
	struct sharing_tag *new_tag;

	new_tag = shm_malloc(sizeof *new_tag + tag_name->len);
	if (!new_tag) {
		LM_ERR("No more shm memory\n");
		return NULL;
	}
	memset(new_tag, 0, sizeof *new_tag);

	new_tag->name.s = (char *)(new_tag + 1);
	new_tag->name.len = tag_name->len;
	memcpy(new_tag->name.s, tag_name->s, tag_name->len);

	new_tag->state = SHTAG_STATE_BACKUP;

	new_tag->next = *shtags_list;
	*shtags_list = new_tag;

	return new_tag;
}


/* should be called under writing lock */
static struct sharing_tag *get_shtag_unsafe(str *tag_name)
{
	struct sharing_tag *tag;

	for (tag = *shtags_list; tag && str_strcmp(&tag->name, tag_name);
		tag = tag->next) ;
	if (!tag && !(tag = create_shtag(tag_name))) {
		LM_ERR("Failed to create sharing tag\n");
		return NULL;
	}

	return tag;
}


struct sharing_tag *get_shtag(str *tag_name, int set, int new_state)
{
	struct sharing_tag *tag;
	int lock_old_flag;

	lock_start_sw_read(shtags_lock);

	for (tag = *shtags_list; tag && str_strcmp(&tag->name, tag_name);
		tag = tag->next) ;
	if (!tag) {
		lock_switch_write(shtags_lock, lock_old_flag);
		if ((tag = create_shtag(tag_name)) == NULL) {
			LM_ERR("Failed to create sharing tag\n");
			lock_switch_read(shtags_lock, lock_old_flag);
			lock_stop_sw_read(shtags_lock);
			return NULL;
		}
	} else {
		lock_switch_write(shtags_lock, lock_old_flag);
	}

	if (set)
		tag->state = new_state;

	lock_switch_read(shtags_lock, lock_old_flag);
	lock_stop_sw_read(shtags_lock);

	return tag;
}


str** get_all_active_shtags(void)
{
	#define MAX_TAGS_NO 64
	static str* tag_name[MAX_TAGS_NO+1];
	struct sharing_tag *tag;
	unsigned int n;

	lock_start_sw_read(shtags_lock);

	for ( tag=*shtags_list,n=0 ; tag ; tag = tag->next) {
		if (tag->state==SHTAG_STATE_ACTIVE && n<MAX_TAGS_NO) {
			tag_name[n++] = &tag->name;
		}
	}

	lock_stop_sw_read(shtags_lock);

	/* set an ennd marker */
	tag_name[n] = NULL;

	return tag_name;
}


int send_shtag_active_info(struct clusterer_binds *c_api, int c_id, str *cap,
													str *tag_name, int node_id)
{
	bin_packet_t packet;

	if (bin_init(&packet, cap, SHTAG_IS_ACTIVE, SHTAG_BIN_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin packet\n");
		return -1;
	}
	bin_push_str(&packet, tag_name);

	if (node_id) {
		if (c_api->send_to(&packet, c_id, node_id) !=
			CLUSTERER_SEND_SUCCESS) {
			bin_free_packet(&packet);
			return -1;
		}
	} else
		if (c_api->send_all(&packet, c_id) !=
			CLUSTERER_SEND_SUCCESS) {
			bin_free_packet(&packet);
			return -1;
		}

	bin_free_packet(&packet);

	return 0;
}


void shlist_flush_state(struct clusterer_binds *c_api, int c_id, str *cap,
																int node_id)
{
	struct sharing_tag *tag;
	struct n_send_info *ni;
	int lock_old_flag;

	lock_start_sw_read(shtags_lock);
	for (tag = *shtags_list; tag; tag = tag->next) {
		if (!tag->send_active_msg)
			continue;

		/* send repltag active msg to nodes to which we didn't already */
		for (ni = tag->active_msgs_sent; ni && ni->node_id != node_id;
			ni = ni->next) ;
		if (!ni) {
			if (send_shtag_active_info(c_api,c_id,cap,&tag->name,node_id)<0){
				LM_ERR("Failed to send info about replication tag\n");
				continue;
			}
			ni = shm_malloc(sizeof *ni);
			if (!ni) {
				LM_ERR("No more shm memory!\n");
				continue;
			}
			ni->node_id = node_id;
			ni->next = tag->active_msgs_sent;
			lock_switch_write(shtags_lock, lock_old_flag);
			tag->active_msgs_sent = ni;
			lock_switch_read(shtags_lock, lock_old_flag);
		}
	}
	lock_stop_sw_read(shtags_lock);
}


static void free_active_msgs_info(struct sharing_tag *tag)
{
	struct n_send_info *it, *tmp;

	it = tag->active_msgs_sent;
	while (it) {
		tmp = it;
		it = it->next;
		shm_free(tmp);
	}
	tag->active_msgs_sent = NULL;
}


int handle_repltag_active_msg(bin_packet_t *packet)
{
	str tag_name;
	struct sharing_tag *tag;

	bin_pop_str(packet, &tag_name);

	lock_start_write(shtags_lock);

	if ((tag = get_shtag_unsafe(&tag_name)) == NULL) {
		LM_ERR("Unable to fetch sharing tag\n");
		lock_stop_write(shtags_lock);
		return -1;
	}

	/* directly go to backup state when another
	 * node in the cluster is to active */
	tag->state = SHTAG_STATE_BACKUP;

	tag->send_active_msg = 0;
	free_active_msgs_info(tag);

	lock_stop_write(shtags_lock);

	return 0;
}


int list_shtags(struct mi_node *rpl)
{
	struct sharing_tag *tag;
	struct mi_node *node;
	struct mi_attr *attr;
	str val;

	rpl->flags |= MI_IS_ARRAY;

	lock_start_read(shtags_lock);
	for (tag = *shtags_list; tag; tag = tag->next) {
		node = add_mi_node_child(rpl, MI_DUP_VALUE,
			MI_SSTR("Tag"), tag->name.s, tag->name.len);
		if (!node) goto error;

		val.s = int2str(tag->state, &val.len);
		attr = add_mi_attr(node, MI_DUP_VALUE,
			MI_SSTR("State"), val.s, val.len);
		if (!attr) goto error;
	}

	lock_stop_read(shtags_lock);
	return 0;
error:
	lock_stop_read(shtags_lock);
	return -1;

}
