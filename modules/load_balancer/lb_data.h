/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2009-02-01 initial version (bogdan)
 */



#ifndef LB_LB_DATA_H_
#define LB_LB_DATA_H_

#include "../../mod_fix.h"
#include "../../str.h"
#include "../../locking.h"
#include "../../parser/msg_parser.h"
#include "../dialog/dlg_load.h"
#include "lb_parser.h"

#define LB_ABSOLUTE_LOAD_ALG    0
#define LB_RELATIVE_LOAD_ALG    1

#define LB_DST_PING_DSBL_FLAG   (1<<0)
#define LB_DST_PING_PERM_FLAG   (1<<1)
#define LB_DST_STAT_DSBL_FLAG   (1<<2)
#define LB_DST_STAT_NOEN_FLAG   (1<<3)

/* max number of IPs for a destination (DNS loookup) */
#define LB_MAX_IPS  32

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
		char* resource, unsigned int flags);

void free_lb_data(struct lb_data *data);

int do_load_balance(struct sip_msg *req, int grp, struct lb_res_str_list *rl,
		unsigned int alg, struct lb_data *data);

int do_lb_disable(struct sip_msg *req, struct lb_data *data);

int lb_is_dst(struct lb_data *data, struct sip_msg *_m,
		pv_spec_t *pv_ip, gparam_t *pv_port, int group, int active);

int lb_count_call(struct lb_data *data, struct sip_msg *req,
		struct ip_addr *ip, int port, int grp, struct lb_res_str_list *rl);

/* failover stuff */
extern int grp_avp_name;
extern int mask_avp_name;
extern int id_avp_name;
#endif
