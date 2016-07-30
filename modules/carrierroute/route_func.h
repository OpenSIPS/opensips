/*
 * Copyright (C) 2007-2008 1&1 Internet AG
 *
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
 */

/**
 * @file route_func.h
 * @brief Routing and balancing functions.
 */

#ifndef SP_ROUTE_ROUTE_FUNC_H
#define SP_ROUTE_ROUTE_FUNC_H

#include "../../parser/msg_parser.h"
#include "../../pvar.h"
#include "../../prime_hash.h"
#include "carrierroute.h"

/**
 * Loads user carrier from subscriber table and stores it in an AVP.
 *
 * @param _msg the current SIP message
 * @param _user the user to determine the route tree
 * @param _domain the domain to determine the route tree
 * @param _dstavp the name of the AVP where to store the carrier tree id
 *
 * @return 1 on success, -1 on failure
 */
int cr_load_user_carrier(struct sip_msg * _msg, pv_elem_t *_user,
		pv_elem_t *_domain, struct multiparam_t *_dstavp);


/**
 * rewrites the request URI of msg after determining the
 * new destination URI
 *
 * @param _msg the current SIP message
 * @param _carrier the requested carrier
 * @param _domain the requested routing domain
 * @param _prefix_matching the user to be used for prefix matching
 * @param _rewrite_user the localpart of the URI to be rewritten
 * @param _hsrc the SIP header used for hashing
 * @param _dstavp the name of the destination AVP where the used host name is stored
 *
 * @return 1 on success, -1 on failure
 */
int cr_route(struct sip_msg * _msg, struct multiparam_t *_carrier,
		struct multiparam_t *_domain, pv_elem_t *_prefix_matching,
		pv_elem_t *_rewrite_user, enum hash_source _hsrc,
		struct multiparam_t *_dstavp);

/**
 * rewrites the request URI of msg after determining the
 * new destination URI
 *
 * @param _msg the current SIP message
 * @param _carrier the requested carrier
 * @param _domain the requested routing domain
 * @param _prefix_matching the user to be used for prefix matching
 * @param _rewrite_user the localpart of the URI to be rewritten
 * @param _hsrc the SIP header used for hashing
 * @param _dstavp the name of the destination AVP where the used host name is stored
 *
 * @return 1 on success, -1 on failure
 */
int cr_prime_route(struct sip_msg * _msg, struct multiparam_t *_carrier,
		struct multiparam_t *_domain, pv_elem_t *_prefix_matching,
		pv_elem_t *_rewrite_user, enum hash_source _hsrc,
		struct multiparam_t *_dstavp);


/**
 * Loads next domain from failure routing table and stores it in an AVP.
 *
 * @param _msg the current SIP message
 * @param _carrier the requested carrier
 * @param _domain the requested routing domain
 * @param _prefix_matching the user to be used for prefix matching
 * @param _host the host name to be used for rule matching
 * @param _reply_code the reply code to be used for rule matching
 * @param _dstavp the name of the destination AVP
 *
 * @return 1 on success, -1 on failure
 */
int cr_load_next_domain(struct sip_msg * _msg, struct multiparam_t *_carrier,
		struct multiparam_t *_domain, pv_elem_t *_prefix_matching, pv_elem_t *_host,
		pv_elem_t *_reply_code, struct multiparam_t *_dstavp);



#endif
