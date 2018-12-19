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
#include "clusterer.h"
#include "node_info.h"
#include "sharing_tags.h"


struct n_send_info {
	int node_id;
	struct n_send_info *next;
};

struct sharing_tag {
	str name;
	int cluster_id;
	int state;
	int send_active_msg;
	struct n_send_info *active_msgs_sent;
	struct sharing_tag *next;
};


static struct sharing_tag **shtags_list = NULL;
static rw_lock_t *shtags_lock = NULL;


void shtag_validate_list(void)
{
	struct sharing_tag *tag;
	struct sharing_tag *next_tag;
	struct sharing_tag *prev_tag;

	lock_start_read(cl_list_lock);
	lock_start_read(shtags_lock);

	for (tag=*shtags_list,prev_tag=NULL ; tag ; tag=next_tag) {

		if (!get_cluster_by_id(tag->cluster_id)) {

			LM_WARN("cluster id [%d] required by tag <%.*s> not found, "
				"purging tag\n", tag->cluster_id,
				tag->name.len, tag->name.s);

			if (prev_tag==NULL)
				*shtags_list = tag->next;
			else
				prev_tag->next = tag->next;

			next_tag = tag->next;
			tag->next = NULL;
			shm_free(tag);
			tag=NULL;

		} else {

			next_tag = tag->next;
			prev_tag=tag;

		}

	}

	lock_stop_read(shtags_lock);
	lock_stop_read(cl_list_lock);

}


static struct sharing_tag *shtag_create(str *tag_name, int cluster_id)
{
	struct sharing_tag *new_tag;

	LM_DBG("creating sharing tag <%.*s> in cluster %d\n",
		tag_name->len, tag_name->s, cluster_id);
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
	new_tag->cluster_id = cluster_id;

	new_tag->next = *shtags_list;
	*shtags_list = new_tag;

	return new_tag;
}


/* should be called under writing lock */
static struct sharing_tag *shtag_get_unsafe(str *tag_name, int c_id)
{
	struct sharing_tag *tag;

	for (tag = *shtags_list;
		tag && (tag->cluster_id!=c_id || str_strcmp(&tag->name, tag_name));
		tag = tag->next);
	if (!tag && !(tag = shtag_create(tag_name, c_id))) {
		LM_ERR("Failed to create sharing tag\n");
		return NULL;
	}

	return tag;
}


int shtag_init_list(void)
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


int shtag_modparam_func(modparam_t type, void *val_s)
{
	str tag_name;
	str val;
	str s;
	int init_state;
	int c_id;
	char *p;
	struct sharing_tag *tag;

	val.s = (char *)val_s;
	val.len = strlen(val.s);

	p = memchr(val.s, '=', val.len);
	if (!p) {
		LM_ERR("Bad definition for sharing tag param <%.*s>\n",
			val.len, val.s);
		return -1;
	}

	/* tag name */
	tag_name.s = val.s;
	tag_name.len = p - val.s;

	/* identify the value */
	s.s = p + 1;
	s.len = val.s + val.len - s.s;
	trim_spaces_lr( s );
	if (!memcmp(s.s, "active", s.len))
		init_state = SHTAG_STATE_ACTIVE;
	else if (!memcmp(s.s, "backup", s.len))
		init_state = SHTAG_STATE_BACKUP;
	else {
		LM_ERR("Bad state <%.*s> for sharing tag param <%.*s>, allowed only "
			"<active/backup>\n", s.len, s.s, val.len, val.s);
		return -1;
	}

	/* now split the tag in tag name and cluster ID */
	p = memchr(tag_name.s, '/', tag_name.len);
	if (!p) {
		LM_ERR("Bad naming for sharing tag param <%.*s>, <name/cluster_id> "
			"expected\n", tag_name.len, tag_name.s);
		return -1;
	}
	s.s = p + 1;
	s.len = tag_name.s + tag_name.len - s.s;
	trim_spaces_lr( s );
	tag_name.len = p - tag_name.s;
	trim_spaces_lr( tag_name );

	/* get the cluster ID */
	if (str2int( &s, (unsigned int*)&c_id)<0) {
		LM_ERR("Invalid cluster id <%.*s> for sharing tag param <%.*s> \n",
			s.len, s.s, val.len, val.s);
		return -1;
	}

	/* initial tag state */
	LM_DBG("found tag <%.*s>, cluster ID <%d>, value <%s> \n",
		tag_name.len, tag_name.s, c_id,
		init_state==SHTAG_STATE_ACTIVE?"active":"backup");

	if (shtag_init_list()<0) {
		LM_ERR("failed to init the sharing tags list\n");
		return -1;
	}

	/* create sharing tag with given state */
	if ((tag = shtag_get_unsafe(&tag_name, c_id)) == NULL) {
		LM_ERR("Unable to create replication tag [%.*s]\n",
			tag_name.len, tag_name.s);
		return -1;
	}
	/* force the given state */
	tag->state = init_state;

	if (init_state == SHTAG_STATE_ACTIVE)
		/* broadcast (later) in cluster that this tag is active */
		tag->send_active_msg = 1;

	return 0;
}


static struct sharing_tag *__shtag_get_safe(str *tag_name, int c_id)
{
	struct sharing_tag *tag;
	int lock_old_flag;

	for (tag = *shtags_list;
		tag && (tag->cluster_id!=c_id || str_strcmp(&tag->name, tag_name));
		tag = tag->next) ;
	if (!tag) {
		lock_switch_write(shtags_lock, lock_old_flag);
		if ((tag = shtag_create(tag_name, c_id)) == NULL) {
			LM_ERR("Failed to create sharing tag\n");
			lock_switch_read(shtags_lock, lock_old_flag);
			lock_stop_sw_read(shtags_lock);
			return NULL;
		}
		lock_switch_read(shtags_lock, lock_old_flag);
	}

	return tag;
}


int shtag_get(str *tag_name, int cluster_id)
{
	struct sharing_tag *tag;
	int ret;

	lock_start_sw_read(shtags_lock);
	tag = __shtag_get_safe( tag_name, cluster_id);
	ret = (tag==NULL)? -1 : tag->state ;
	lock_stop_sw_read(shtags_lock);

	return ret;
}


int shtag_set(str *tag_name, int cluster_id, int new_state)
{
	struct sharing_tag *tag;
	int lock_old_flag;
	int ret;

	lock_start_sw_read(shtags_lock);
	tag = __shtag_get_safe( tag_name, cluster_id);
	if (tag!=NULL) {
		lock_switch_write(shtags_lock, lock_old_flag);
		tag->state = new_state;
		lock_switch_read(shtags_lock, lock_old_flag);
	}
	ret = (tag==NULL)? -1 : tag->state ;
	lock_stop_sw_read(shtags_lock);

	return ret;
}


str** shtag_get_all_active(int cluster_id)
{
	#define MAX_TAGS_NO 64
	static str* tag_name[MAX_TAGS_NO+1];
	struct sharing_tag *tag;
	unsigned int n;

	lock_start_read(shtags_lock);

	for ( tag=*shtags_list,n=0 ; tag ; tag = tag->next) {
		if ( tag->state==SHTAG_STATE_ACTIVE
		&& (cluster_id<0 || cluster_id==tag->cluster_id)
		&& n<MAX_TAGS_NO ) {
			tag_name[n++] = &tag->name;
		}
	}

	lock_stop_read(shtags_lock);

	/* set an end marker */
	tag_name[n] = NULL;

	return tag_name;
}


int shtag_send_active_info(int c_id, str *tag_name, int node_id)
{
	bin_packet_t packet;

	if (bin_init(&packet, &cl_extra_cap, CLUSTERER_SHTAG_ACTIVE,
	BIN_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin packet\n");
		return CLUSTERER_SEND_ERR;
	}

	if (bin_push_str(&packet, tag_name) < 0)
		return CLUSTERER_SEND_ERR;

	if (node_id) {
		if (cl_send_to(&packet, c_id, node_id) != CLUSTERER_SEND_SUCCES) {
			bin_free_packet(&packet);
			return CLUSTERER_SEND_ERR;
		}
	} else
		if (cl_send_all(&packet, c_id) != CLUSTERER_SEND_SUCCES) {
			bin_free_packet(&packet);
			return -1;
		}

	bin_free_packet(&packet);

	return 0;
}


void shtag_flush_state(int c_id, int node_id)
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
			if (shtag_send_active_info(c_id,&tag->name,node_id)<0){
				LM_ERR("Failed to send info about replication tag\n");
				continue;
			}
			ni = shm_malloc(sizeof *ni);
			if (!ni) {
				LM_ERR("No more shm memory!\n");
				return;
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


int handle_shtag_active(bin_packet_t *packet, int cluster_id)
{
	str tag_name;
	struct sharing_tag *tag;

	bin_pop_str(packet, &tag_name);

	LM_DBG("receiving ACTIVE advertising for tag <%.*s> cluster %d\n",
		tag_name.len, tag_name.s, cluster_id);
	lock_start_write(shtags_lock);

	if ((tag = shtag_get_unsafe(&tag_name, cluster_id)) == NULL) {
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


void shtag_event_handler(int cluster_id, enum clusterer_event ev, int node_id)
{
	if (ev == CLUSTER_NODE_UP)
		shtag_flush_state( cluster_id, node_id);
}


struct mi_root *shtag_mi_list(struct mi_root *cmd, void *param)
{
	struct sharing_tag *tag;
	struct mi_node *node;
	struct mi_attr *attr;
	struct mi_root *rpl;
	str val;

	rpl = init_mi_tree(200, MI_SSTR(MI_OK));
	if (rpl==0)
		return NULL;

	rpl->node.flags |= MI_IS_ARRAY;

	lock_start_read(shtags_lock);

	for (tag = *shtags_list; tag; tag = tag->next) {

		node = add_mi_node_child(&rpl->node, MI_DUP_VALUE,
			MI_SSTR("Tag"), tag->name.s, tag->name.len);
		if (!node) continue;

		val.s = int2str( tag->cluster_id, &val.len);
		attr = add_mi_attr(node, MI_DUP_VALUE,
			MI_SSTR("Cluster"), val.s, val.len);
		if (!attr) continue;

		if (tag->state == SHTAG_STATE_ACTIVE)
			attr = add_mi_attr(node, MI_DUP_VALUE,
				MI_SSTR("State"), MI_SSTR("active"));
		else
			attr = add_mi_attr(node, MI_DUP_VALUE,
				MI_SSTR("State"), MI_SSTR("backup"));
		if (!attr) continue;

	}

	lock_stop_read(shtags_lock);
	return rpl;
}


struct mi_root *shtag_mi_set_active(struct mi_root *cmd, void *param)
{
	struct mi_node *node;
	str tag;
	str s;
	int c_id;
	char *p;

	node = cmd->node.kids;
	if (node == NULL || !node->value.s || !node->value.len)
		return init_mi_tree(400, MI_SSTR(MI_MISSING_PARM));

	p = memchr(node->value.s, '/', node->value.len);
	if (!p) {
		LM_ERR("Bad naming for sharing tag param <%.*s>, <name/cluster_id> "
			"expected\n", node->value.len, node->value.s);
		return init_mi_tree(400, MI_SSTR("Bad tag format <name/cluster_id>"));
	}
	tag.s = node->value.s;
	tag.len = p - tag.s;
	trim_spaces_lr( tag );

	/* get the cluster ID */
	s.s = p + 1;
	s.len = node->value.s + node->value.len - s.s;
	trim_spaces_lr( s );
	if (str2int( &s, (unsigned int*)&c_id)<0) {
		LM_ERR("Invalid cluster id <%.*s> for sharing tag param <%.*s> \n",
			s.len, s.s, node->value.len, node->value.s);
		return init_mi_tree(400, MI_SSTR("Bad cluster ID in tag"));
	}

	LM_DBG("requested to activate tag <%.*s> in cluster %d\n",
		tag.len, tag.s, c_id);

	lock_start_read(cl_list_lock);
	if (!get_cluster_by_id(c_id)) {
		lock_stop_read(cl_list_lock);
		return init_mi_tree(404, MI_SSTR("Cluster ID not found"));
	}
	lock_stop_read(cl_list_lock);

	if (shtag_set( &tag, c_id, SHTAG_STATE_ACTIVE)<0) {
		LM_ERR("Failed set active the tag [%.*s/%d] \n",
			tag.len, tag.s, c_id);
		return init_mi_tree(500, MI_SSTR("Internal failure when activating "
			"tag"));
	}

	if (shtag_send_active_info(c_id, &tag, 0) < 0)
		LM_ERR("Failed to broadcast message about tag [%.*s/%d] "
			"going active\n", tag.len, tag.s, c_id);

	return init_mi_tree( 200, MI_SSTR(MI_OK));
}

