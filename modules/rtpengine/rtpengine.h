/*
 * Copyright (C) 2003 Porta Software Ltd
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
 * History:
 * ---------
 * 2014-06-17 Imported from rtpproxy module
*/


#ifndef _RTPENGINE_H
#define _RTPENGINE_H

#include "bencode.h"
#include "../../str.h"

struct rtpe_node {
	unsigned int		idx;			/* overall index */
	str					rn_url;			/* unparsed, deletable */
	int					rn_umode;
	char				*rn_address;	/* substring of rn_url */
	int					rn_disabled;	/* found unaccessible? */
	unsigned			rn_weight;		/* for load balancing */
	unsigned int		rn_recheck_ticks;
	struct rtpe_node	*rn_next;
};


struct rtpe_set{
	unsigned int 		id_set;
	unsigned			weight_sum;
	unsigned int		rtpe_node_count;
	int 				set_disabled;
	unsigned int		set_recheck_ticks;
	struct rtpe_node	*rn_first;
	struct rtpe_node	*rn_last;
	struct rtpe_set     *rset_next;
};


struct rtpe_set_head{
	struct rtpe_set		*rset_first;
	struct rtpe_set		*rset_last;
};

#define RTPENGINE_TABLE_VERSION 1

#endif
