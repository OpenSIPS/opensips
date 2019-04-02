/*
 * Copyright (C) 2005 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * History:
 * ---------
 *  2005-08-02  first version (bogdan)
 */

/*!
 * \file
 * \brief RR module API
 * \ingroup rr
 */


#ifndef RR_API_H_
#define RR_API_H_

#include "../../str.h"
#include "../../sr_module.h"
#include "loose.h"
#include "rr_cb.h"

#define ROUTING_LL (1<<1)
#define ROUTING_SL (1<<2)
#define ROUTING_SS (1<<3)
#define ROUTING_LS (1<<4)

typedef  int (*add_rr_param_t)(struct sip_msg*, str*);
typedef  int (*check_route_param_t)(struct sip_msg*, regex_t*);
typedef  int (*is_direction_t)(struct sip_msg*, int);
typedef  int (*get_route_param_t)(struct sip_msg*, str*, str*);
typedef  str* (*get_remote_target_t)(struct sip_msg*);
typedef  str* (*get_route_set_t)(struct sip_msg*,int *nr_routes);
typedef  int (*loose_route_t)(struct sip_msg*);
typedef  int (*record_route_t)(struct sip_msg*, str*);

struct rr_binds {
	add_rr_param_t      add_rr_param;
	check_route_param_t check_route_param;
	is_direction_t      is_direction;
	get_route_param_t   get_route_param;
	register_rrcb_t     register_rrcb;
	get_remote_target_t get_remote_target;
	get_route_set_t     get_route_set;
	loose_route_t       loose_route;
	record_route_t      record_route;
	int                 append_fromtag;
};

typedef  int (*load_rr_f)( struct rr_binds* );

/*! \brief
 * function exported by module - it will load the other functions
 */
int load_rr( struct rr_binds * );


/*! \brief
 * function to be called directly from other modules
 * to load the RR API
 */
inline static int load_rr_api( struct rr_binds *rrb )
{
	load_rr_f load_rr_v;

	/* import the RR auto-loading function */
	if ( !(load_rr_v=(load_rr_f)find_export("load_rr", 0)))
		return -1;

	/* let the auto-loading function load all RR stuff */
	load_rr_v( rrb );

	return 0;
}


#endif
