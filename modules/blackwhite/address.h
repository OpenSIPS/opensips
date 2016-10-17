/*
 * $Id$
 *
 * BLACKWHITE module
 *
 * Copyright (C) 2016 sa
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
 */

#ifndef BW_ADDRESS_H
#define BW_ADDRESS_H


#include "../../str.h"
#include "../../ip_addr.h"


/*
 * Access list black/white
 */
struct address_node
{
	struct net *subnet;
	struct address_node *next;
};


/*
 * Access rules of sip id
 */
struct address
{
	str id;
	struct address_node *black;
	struct address_node *white;
};


/*
 * Need for swap single pointer
 */
struct bw_data
{
	struct address *addrs;
	size_t data_n;
} **cur_data, *bw_data1, *bw_data2;


int blackwhite_(str *id, struct ip_addr *ip, const struct address *addrs, size_t data_n);

int data_append(const str *id, const struct net *subnet, int black, struct address *addrs, size_t *n);
void free_data(struct address *rec, size_t *n);

int cmpstringp(const void *p1, const void *p2);

#endif
