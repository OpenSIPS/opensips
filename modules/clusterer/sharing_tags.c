/*
 * Copyright (C) 2018-2019 OpenSIPS Solutions
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

struct shtag_cb {
	str tag_name;
	int cluster_id;
	void *param;
	shtag_cb_f func;
	struct shtag_cb *next;
};


static struct sharing_tag **shtags_list = NULL;
static rw_lock_t *shtags_lock = NULL;

static struct shtag_cb *shtag_cb_list=NULL;


int shtag_register_callback(str *tag_name, int c_id, void *param,
															shtag_cb_f func)
{
	struct shtag_cb *cb;

	cb = (struct shtag_cb*)pkg_malloc
		(sizeof(struct shtag_cb) + (tag_name?tag_name->len:0));
	if (cb==NULL) {
		LM_ERR("failed to allocate pkg mem for a new shtag callback\n");
		return -1;
	}

	cb->cluster_id = c_id;
	cb->param = param;
	cb->func = func;

	if (tag_name && tag_name->len) {
		cb->tag_name.s =(char*) (cb + 1);
		cb->tag_name.len = tag_name->len;
		memcpy(cb->tag_name.s , tag_name->s, tag_name->len);
	} else {
		cb->tag_name.s = NULL;
		cb->tag_name.len = 0;
	}

	cb->next = shtag_cb_list;
	shtag_cb_list = cb;

	return 0;
}


static void shtag_run_callbacks(str *tag_name, int state, int c_id)
{
	struct shtag_cb *cb;

	LM_DBG("running callbacks for tag <%.*s>/%d becoming active\n",
		tag_name->len, tag_name->s, c_id);

	for (cb = shtag_cb_list ; cb ; cb=cb->next ) {
		if ( (cb->cluster_id<0 || cb->cluster_id==c_id)
		&& (cb->tag_name.s==NULL || (cb->tag_name.len==tag_name->len &&
			memcmp(cb->tag_name.s, tag_name->s, tag_name->len)==0))
		) {
			cb->func( tag_name, state, c_id, cb->param);
		}
	}
}


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


static int shtag_send_active_info(int c_id, str *tag_name, int node_id)
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


int shtag_activate(str *tag_name, int cluster_id)
{
	struct sharing_tag *tag;
	int lock_old_flag;
	int ret, old_state;

	lock_start_sw_read(shtags_lock);
	tag = __shtag_get_safe( tag_name, cluster_id);
	if (tag!=NULL) {
		lock_switch_write(shtags_lock, lock_old_flag);
		old_state = tag->state;
		tag->state = SHTAG_STATE_ACTIVE;
		lock_switch_read(shtags_lock, lock_old_flag);
	}
	ret = (tag==NULL)? -1 : tag->state ;
	lock_stop_sw_read(shtags_lock);

	/* do we have a transition from BACKUP to ACTIVE? */
	if (ret==SHTAG_STATE_ACTIVE && old_state!=SHTAG_STATE_ACTIVE) {

		/* inform the other nodes that we are active now */
		if (shtag_send_active_info(cluster_id, tag_name, 0) < 0)
		LM_ERR("Failed to broadcast message about tag [%.*s/%d] "
			"going active\n", tag_name->len, tag_name->s, cluster_id);

		/* run the callbacks */
		shtag_run_callbacks( tag_name, SHTAG_STATE_ACTIVE, cluster_id);
	}

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
	int old_state;

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
	old_state = tag->state;
	tag->state = SHTAG_STATE_BACKUP;

	tag->send_active_msg = 0;
	free_active_msgs_info(tag);

	lock_stop_write(shtags_lock);

	if (old_state!=SHTAG_STATE_BACKUP)
		shtag_run_callbacks( &tag_name, SHTAG_STATE_BACKUP, cluster_id);

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

	if (shtag_activate( &tag, c_id)<0) {
		LM_ERR("Failed set active the tag [%.*s/%d] \n",
			tag.len, tag.s, c_id);
		return init_mi_tree(500, MI_SSTR("Internal failure when activating "
			"tag"));
	}

	return init_mi_tree( 200, MI_SSTR(MI_OK));
}


struct shtag_var_name {
	str shtag;
	int cluster_id;
};

int var_get_sh_tag(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res)
{
	struct shtag_var_name *v_name;
	int ret;

	if (param==NULL || param->pvn.type!=PV_NAME_PVAR ||
	param->pvn.u.dname==NULL) {
		LM_CRIT("BUG - bad parameters\n");
		return -1;
	}

	v_name = (struct shtag_var_name *)param->pvn.u.dname;

	ret = shtag_get( &v_name->shtag, v_name->cluster_id);
	if (ret==-1)
		return pv_get_null(msg, param, res);

	if (ret==SHTAG_STATE_ACTIVE) {
		res->rs.s = "active";
		res->rs.len = 6;
		res->ri = 1;
	} else {
		res->rs.s = "backup";
		res->rs.len = 6;
		res->ri = 0;
	}

	res->flags = PV_VAL_STR|PV_VAL_INT;

	return 0;
}


int var_set_sh_tag(struct sip_msg* msg, pv_param_t *param, int op,
															pv_value_t *val)
{
	struct shtag_var_name *v_name;
	int state;

	if (param==NULL || param->pvn.type!=PV_NAME_PVAR ||
	param->pvn.u.dname==NULL) {
		LM_CRIT("BUG - bad parameters\n");
		return -1;
	}

	v_name = (struct shtag_var_name *)param->pvn.u.dname;

	if (val==NULL || val->flags&(PV_VAL_NONE|PV_VAL_NULL|PV_VAL_EMPTY)) {
		/* NULL/empty is a NOP */
		return 0;
	}

	if ( val->flags&PV_VAL_STR ) {
		/* val is string */
		if (val->rs.len==6 && strncasecmp(val->rs.s,"active",6)==0)
			state = SHTAG_STATE_ACTIVE;
		else if (val->rs.len==6 && strncasecmp(val->rs.s,"backup",6)==0)
			state = SHTAG_STATE_BACKUP;
		else {
			LM_ERR("unknown value <%.*s> while setting tag <%.*s/%d>\n",
				val->rs.len, val->rs.s,
				v_name->shtag.len, v_name->shtag.s, v_name->cluster_id);
			return -1;
		}
	} else {
		/* val is integer */
		state = (val->ri>0)?SHTAG_STATE_ACTIVE:SHTAG_STATE_BACKUP;
	}

	if (state!=SHTAG_STATE_ACTIVE) {
		LM_WARN("cannot set tag <%.*s/%d> to backup, operation not allowed\n",
			v_name->shtag.len, v_name->shtag.s, v_name->cluster_id);
		return 0;
	}

	if (shtag_activate( &v_name->shtag, v_name->cluster_id)==-1) {
		LM_ERR("failed to set sharing tag <%.*s/%d> to new state %d\n",
			v_name->shtag.len, v_name->shtag.s, v_name->cluster_id, state);
		return -1;
	}

	return 0;
}


int var_parse_sh_tag_name(pv_spec_p sp, str *in)
{
	struct shtag_var_name *v_name;
	str s;
	char *p;

	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;

	v_name = (struct shtag_var_name*)pkg_malloc(sizeof(struct shtag_var_name));
	if (v_name==NULL) {
		LM_ERR("failed to allocate name for a shtag var\n");
		return -1;
	}
	memset(v_name, 0, sizeof(struct shtag_var_name));

	/* now split the shtag in tag name and cluster ID */
	p = memchr(in->s, '/', in->len);
	if (!p) {
		LM_ERR("Bad naming for sharing tag var <%.*s>, <name/cluster_id> "
			"expected\n", in->len, in->s);
		return -1;
	}
	s.s = p + 1;
	s.len = in->s + in->len - s.s;
	trim_spaces_lr( s );
	v_name->shtag.len = p - in->s;
	v_name->shtag.s = in->s;
	trim_spaces_lr( v_name->shtag );

	/* get the cluster ID */
	if (str2int( &s, (unsigned int*)&v_name->cluster_id)<0) {
		LM_ERR("Invalid cluster id <%.*s> for sharing tag var <%.*s> \n",
			s.len, s.s, in->len, in->s);
		return -1;
	}

	sp->pvp.pvn.type = PV_NAME_PVAR;
	sp->pvp.pvn.u.dname = (void*)v_name;

	return 0;
}
