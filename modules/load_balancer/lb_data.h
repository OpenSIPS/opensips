/*
 * load balancer module - complex call load balancing
 *
 * Copyright (C) 2009 Voice Sistem SRL
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
 *
 */



#ifndef LB_LB_DATA_H_
#define LB_LB_DATA_H_

#include "../../str.h"
#include "../../locking.h"
#include "../../parser/msg_parser.h"
#include "../dialog/dlg_load.h"
#include "../freeswitch/fs_api.h"
#include "lb_parser.h"

#define LB_FLAGS_RELATIVE (1<<0) /* do relative versus absolute estimation. default is absolute */
#define LB_FLAGS_NEGATIVE (1<<1) /* do not skip negative loads. default to skip */
#define LB_FLAGS_RANDOM   (1<<2) /* pick a random destination among all selected dsts with equal load */
#define LB_FLAGS_DEFAULT  0

#define LB_DST_PING_DSBL_FLAG   (1<<0)
#define LB_DST_PING_PERM_FLAG   (1<<1)
#define LB_DST_STAT_DSBL_FLAG   (1<<2)
#define LB_DST_STAT_NOEN_FLAG   (1<<3)
#define LB_DST_STAT_MASK        (LB_DST_STAT_DSBL_FLAG|LB_DST_STAT_NOEN_FLAG)

/* max number of IPs for a destination (DNS loookup) */
#define LB_MAX_IPS  32

extern rw_lock_t *ref_lock;

struct lb_resource {
	str name;
	gen_lock_t *lock;
	struct dlg_profile_table *profile;
	unsigned int bitmap_size;
	unsigned int *dst_bitmap;
	struct lb_resource *next;
};

struct lb_resource_map {
	struct lb_resource *resource;
	unsigned int max_load;

	int fs_enabled;
};

struct lb_dst {
	unsigned int group;
	unsigned int id;
	str uri;
	str profile_id;
	unsigned int rmap_no;
	unsigned int flags;
	struct lb_resource_map *rmap;
	struct ip_addr ips[LB_MAX_IPS]; /* IP-Address of the entry */
	unsigned short int ports[LB_MAX_IPS]; /* Port of the request URI */
	unsigned short int protos[LB_MAX_IPS]; /* Protocol of the request URI */
	unsigned short ips_cnt;
	fs_evs *fs_sock;
	str attrs;
	struct lb_dst *next;
};

struct lb_data {
	unsigned int res_no;
	struct lb_resource * resources;
	unsigned int dst_no;
	struct lb_dst *dsts;
	struct lb_dst *last_dst;
};

struct lb_data* load_lb_data(void);

int add_lb_dsturi( struct lb_data *data, int id, int group, char *uri,
						char* resource, char* attrs, unsigned int flags);

void free_lb_data(struct lb_data *data);

int do_lb_start(struct sip_msg *req, int group, struct lb_res_str_list *rl,
		unsigned int flags, struct lb_data *data, str *attrs);

int do_lb_next(struct sip_msg *req, struct lb_data *data, str *attrs);

int do_lb_reset(struct sip_msg *req, struct lb_data *data);

int do_lb_is_started(struct sip_msg *req);

int do_lb_disable_dst(struct sip_msg *req, struct lb_data *data,
		unsigned int verbose);

int lb_is_dst(struct lb_data *data, struct sip_msg *_m,
				str *ip_str, int port, int group, int active, str *attrs);

int lb_count_call(struct lb_data *data, struct sip_msg *req,struct ip_addr *ip,
					int port, int group, struct lb_res_str_list *rl, int dir);

int lb_init_event(void);

void lb_raise_event(struct lb_dst *dst);

void lb_status_changed(struct lb_dst *dst);

/* failover stuff */
extern int group_avp_name;
extern int flags_avp_name;
extern int mask_avp_name;
extern int id_avp_name;
extern int res_avp_name;
#endif
