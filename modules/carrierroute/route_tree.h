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
 * @file route_tree.h
 * @brief Contains the functions to manage routing tree data in a digital tree.
 */

#ifndef SP_ROUTE_ROUTE_TREE_H
#define SP_ROUTE_ROUTE_TREE_H

#include "route.h"

/**
 * Adds the given route information to the route tree identified by
 * route_tree. scan_prefix identifies the number for which the information
 * is and the rewrite_* parameters define what to do in case of a match.
 * prob gives the probability with which this rule applies if there are
 * more than one for a given prefix.
 *
 * Note that this is a recursive function. It strips of digits from the
 * beginning of scan_prefix and calls itself.
 *
 * @param route_tree the current route tree node
 * @param scan_prefix the prefix at the current position
 * @param flags user defined flags
 * @param mask mask for user defined flags
 * @param full_prefix the whole scan prefix
 * @param max_targets the number of targets
 * @param prob the weight of the rule
 * @param rewrite_hostpart the rewrite_host of the rule
 * @param strip the number of digits to be stripped off userpart before prepending prefix
 * @param rewrite_local_prefix the rewrite prefix
 * @param rewrite_local_suffix the rewrite suffix
 * @param status the status of the rule
 * @param hash_index the hash index of the rule
 * @param backup indicates if the route is backed up by another. only
                 useful if status==0, if set, it is the hash value
                 of another rule
 * @param backed_up an -1-termintated array of hash indices of the route
                    for which this route is backup
 * @param comment a comment for the route rule
 *
 * @return 0 on success, -1 on failure
 *
 * @see add_route()
 */
int add_route_to_tree(struct route_tree_item * route_tree, const str * scan_prefix,
		flag_t flags, flag_t mask, const str * full_prefix, int max_targets, double prob,
		const str * rewrite_hostpart, int strip, const str * rewrite_local_prefix,
		const str * rewrite_local_suffix, int status, int hash_index,
		int backup, int * backed_up, const str * comment);

/**
 * Adds the given failure route information to the failure route tree identified by
 * route_tree. scan_prefix, host, reply_code, flags identifies the number for which
 * the information is and the next_domain parameters defines where to continue
 * routing in case of a match.
 *
 * Note that this is a recursive function. It strips of digits from the
 * beginning of scan_prefix and calls itself.
 *
 * @param failure_tree the current route tree node
 * @param scan_prefix the prefix at the current position
 * @param full_prefix the whole scan prefix
 * @param host the hostname last tried
 * @param reply_code the reply code
 * @param flags user defined flags
 * @param mask mask for user defined flags
 * @param next_domain continue routing with this domain id
 * @param comment a comment for the route rule
 *
 * @return 0 on success, -1 on failure
 *
 * @see add_route()
 */
int add_failure_route_to_tree(struct failure_route_tree_item * failure_tree, const str * scan_prefix,
		const str * full_prefix, const str * host, const str * reply_code,
		const flag_t flags, const flag_t mask, const int next_domain, const str * comment);

/**
 * Create a new route tree root in shared memory and set it up.
 *
 * @param domain the domain name of the route tree
 * @param id the domain id of the route tree
 *
 * @return a pointer to the newly allocated route tree or NULL on
 * error, in which case it LOGs an error message.
 */
struct route_tree * create_route_tree(const str * domain, int id);



/**
 * Tries to add a domain to the domain map. If the given domain doesn't
 * exist, it is added. Otherwise, nothing happens.
 *
 * @param domain the domain to be added
 *
 * @return values: on success the numerical index of the given domain,
 * -1 on failure
 */
int add_domain(const str * domain);

/**
 * returns the routing tree for the given domain, if domain's tree doesn't
 * exist, it will be created. If the trees are completely filled and a not
 * existing domain shall be added, an error is returned.
 *
 * @param domain the domain name of desired routing tree
 * @param rd route data to be searched
 *
 * @return a pointer to the desired routing tree, NULL on failure
 */
struct route_tree * get_route_tree(const str * domain, struct carrier_tree * rd);

struct route_tree * get_route_tree_by_id(struct carrier_tree * ct, int id);

void destroy_route_tree(struct route_tree *route_tree);

void destroy_route_map(void);

#endif
