/*
 * Route & Record-Route module, loose routing support
 *
 * Copyright (C) 2001-2003 FhG Fokus
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

/*!
 * \file
 * \brief Route & Record-Route module, loose routing support
 * \ingroup rr
 */


#ifndef LOOSE_H
#define LOOSE_H


#include <regex.h>
#include "../../str.h"
#include "../../parser/msg_parser.h"

#define RR_FLOW_DOWNSTREAM  (1<<0)
#define RR_FLOW_UPSTREAM    (1<<1)

extern int ctx_rrparam_idx;
extern int ctx_routing_idx;


/*! \brief
 * Do loose routing as per RFC3261
 */
int loose_route(struct sip_msg* _m);


/*! \brief
 * Check if the our route hdr has required params
 */
int check_route_param(struct sip_msg *msg, regex_t* re);


/*! \brief
 * Check the direction of the message
 */
int is_direction(struct sip_msg *msg, int dir);


/*! \brief
 * Gets the value of a route parameter
 */
int get_route_param( struct sip_msg *msg, str *name, str *val);


/*! \brief
 * Gets all route params as a string
 */
int get_route_params(struct sip_msg *msg, str *val);

/* returns the remote contact, based on the routing decisions made */
str* get_remote_target(struct sip_msg *msg);

/* returns an array of the URIs in all Route Headers */
str* get_route_set(struct sip_msg *msg,int *nr_routes);
/*
 * Check if the given uri contains lr parameter which marks loose routers
 */
static inline int is_strict(str* _params)
{
	str s;
	int i, state = 0;

	if (_params->len == 0) return 1;

	s.s = _params->s;
	s.len = _params->len;

	for(i = 0; i < s.len; i++) {
		switch(state) {
		case 0:
			switch(s.s[i]) {
			case ' ':
			case '\r':
			case '\n':
			case '\t':           break;
			case 'l':
			case 'L': state = 1; break;
			default:  state = 4; break;
			}
			break;

		case 1:
			switch(s.s[i]) {
			case 'r':
			case 'R': state = 2; break;
			default:  state = 4; break;
			}
			break;

		case 2:
			switch(s.s[i]) {
			case ';':  return 0;
			case '=':  return 0;
			case ' ':
			case '\r':
			case '\n':
			case '\t': state = 3; break;
			default:   state = 4; break;
			}
			break;

		case 3:
			switch(s.s[i]) {
			case ';':  return 0;
			case '=':  return 0;
			case ' ':
			case '\r':
			case '\n':
			case '\t': break;
			default:   state = 4; break;
			}
			break;

		case 4:
			switch(s.s[i]) {
			case '\"': state = 5; break;
			case ';':  state = 0; break;
			default:              break;
			}
			break;

		case 5:
			switch(s.s[i]) {
			case '\\': state = 6; break;
			case '\"': state = 4; break;
			default:              break;
			}
			break;

		case 6: state = 5; break;
		}
	}

	if ((state == 2) || (state == 3)) return 0;
	else return 1;
}


#endif /* LOOSE_H */
