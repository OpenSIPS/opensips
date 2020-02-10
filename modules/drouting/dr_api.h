/**
 * drouting module developer api
 *
 * Copyright (C) 2014-2020 OpenSIPS Solutions
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
 */

#ifndef _DROUTING_API_H_
#define _DROUTING_API_H_

#include "routing.h"
#include "dr_cb.h"
#include "../../lock_ops.h"
#include "../../rw_locking.h"
#include "../../sr_module.h"
#include "dr_cb.h"

typedef struct _dr_head_t {
	ptree_t *pt;
	ptree_node_t noprefix;
} dr_head_t, *dr_head_p; /*Easier to spot outside dr */

typedef rt_info_t* (*match_number_f) (dr_head_p partition, unsigned int gr_id,
		const str *number, unsigned int *matched_len);

typedef dr_head_p (*create_head_f) (void);
typedef void (*free_head_f)(dr_head_p partition);
typedef int (*add_rule_f)(dr_head_p partition, unsigned int rid,
		str *prefix, unsigned int gr_id, unsigned int priority,
		tmrec_t *time_rec, void *attr);
typedef str * (*get_gw_name_f) (pgw_t *gw);
typedef int (*get_cr_n_gw_f) (pcr_t *cr);
typedef str * (*get_cr_name_f) (pcr_t *cr);
typedef  pgw_t * (*get_gw_from_cr_f) (pcr_t *cr, int n); /* gets the n-th
															gateway from the
															carrier */
typedef void * (*get_qr_rule_handle_f) (rt_info_t *);
struct dr_binds {
	create_head_f    create_head;
	free_head_f      free_head;
	match_number_f   match_number;
	add_rule_f       add_rule;
	register_drcb_f  register_drcb;
	get_gw_name_f    get_gw_name;
	get_cr_name_f    get_cr_name;
	get_cr_n_gw_f    get_cr_n_gw;
	get_gw_from_cr_f get_gw_from_cr;
	get_qr_rule_handle_f get_qr_rule_handle;
};

typedef int (*load_dr_api_f)(struct dr_binds *drb);

static inline int load_dr_api(struct dr_binds *drb)
{
	load_dr_api_f load_dr;

	if ( !(load_dr = (load_dr_api_f)find_export("load_dr", 0)))
		return -1;

	return load_dr(drb);
}

#endif
