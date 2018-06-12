/*
 *
 * $Id$
 *
 *
 * Copyright (C) 2001-2003 Fhg Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#ifndef _T_STATS_H
#define _T_STATS_H

#include "defs.h"


#include "../../pt.h"


extern struct t_stats *tm_stats;
typedef unsigned long stat_counter;

struct t_stats {
	/* number of transactions in wait state */
	stat_counter *s_waiting;
	/* number of server transactions */
	stat_counter *s_transactions;
	/* number of UAC transactions (part of transactions) */
	stat_counter *s_client_transactions;
	/* number of transactions which completed with this status */
	stat_counter completed_3xx, completed_4xx, completed_5xx, 
		completed_6xx, completed_2xx;
	stat_counter replied_localy;
	stat_counter deleted;
};

inline void static t_stats_new(int local)
{
	/* keep it in process's piece of shmem */
	tm_stats->s_transactions[process_no]++;
	if(local) tm_stats->s_client_transactions[process_no]++;
}

inline void static t_stats_wait()
{
	/* keep it in process's piece of shmem */
	tm_stats->s_waiting[process_no]++;
}

inline void static t_stats_deleted( int local )
{
	/* no locking needed here -- only timer process deletes */
	tm_stats->deleted++;
}

inline static void update_reply_stats( int code ) {
	if (code>=600) {
		tm_stats->completed_6xx++;
	} else if (code>=500) {
		tm_stats->completed_5xx++;
	} else if (code>=400) {
		tm_stats->completed_4xx++;
	} else if (code>=300) {
		tm_stats->completed_3xx++;
	} else if (code>=200) {
		tm_stats->completed_2xx++;
	}
}


int init_tm_stats(void);
void free_tm_stats();

#endif
