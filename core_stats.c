/*
 * Copyright (C) 2006 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * History:
 * ---------
 *  2006-01-23  first version (bogdan)
 *  2006-11-28  Added statistics for the number of bad URI's, methods, and
 *              proxy requests (Jeffrey Magder - SOMA Networks)
 *  2009-04-23  NET and PKG statistics added (bogdan)
 */

/*!
 * \file
 * \brief OpenSIPS Core statistics
 */


#include <string.h>

#include "statistics.h"
#include "globals.h"
#include "pt.h"
#include "timer.h"
#include <sys/types.h>
#include <signal.h>
#include "socket_info.h"
#include "ipc.h"


#ifdef STATISTICS

/*************************** SIP statistics *********************************/
stat_var* rcv_reqs;
stat_var* rcv_rpls;
stat_var* fwd_reqs;
stat_var* fwd_rpls;
stat_var* drp_reqs;
stat_var* drp_rpls;
stat_var* err_reqs;
stat_var* err_rpls;
stat_var* bad_URIs;
stat_var* unsupported_methods;
stat_var* bad_msg_hdr;
stat_var* slow_msgs;


stat_export_t core_stats[] = {
	{"rcv_requests" ,         0,  &rcv_reqs              },
	{"rcv_replies" ,          0,  &rcv_rpls              },
	{"fwd_requests" ,         0,  &fwd_reqs              },
	{"fwd_replies" ,          0,  &fwd_rpls              },
	{"drop_requests" ,        0,  &drp_reqs              },
	{"drop_replies" ,         0,  &drp_rpls              },
	{"err_requests" ,         0,  &err_reqs              },
	{"err_replies" ,          0,  &err_rpls              },
	{"bad_URIs_rcvd",         0,  &bad_URIs              },
	{"unsupported_methods",   0,  &unsupported_methods   },
	{"bad_msg_hdr",           0,  &bad_msg_hdr           },
	{"slow_messages" ,        0,  &slow_msgs             },
	{"timestamp",  STAT_IS_FUNC, (stat_var**)get_ticks   },
	{0,0,0}
};



/*************************** NET statistics *********************************/

static unsigned long net_get_wb_udp(unsigned short foo)
{
	return get_total_bytes_waiting(PROTO_UDP);
}

static unsigned long net_get_wb_tcp(unsigned short foo)
{
	return get_total_bytes_waiting(PROTO_TCP);
}

static unsigned long net_get_wb_tls(unsigned short foo)
{
	return get_total_bytes_waiting(PROTO_TLS);
}

stat_export_t net_stats[] = {
	{"waiting_udp" ,    STAT_IS_FUNC,  (stat_var**)net_get_wb_udp    },
	{"waiting_tcp" ,    STAT_IS_FUNC,  (stat_var**)net_get_wb_tcp    },
	{"waiting_tls" ,    STAT_IS_FUNC,  (stat_var**)net_get_wb_tls    },
	{0,0,0}
};



/*************************** PKG statistics *********************************/

#ifdef PKG_MALLOC
static pkg_status_holder *pkg_status = NULL;
static time_t *marker_t = NULL;
static int no_pkg_status = 0;

static void rpc_get_pkg_stats(int sender_id, void *foo)
{
#ifdef PKG_MALLOC
	pkg_status_holder *holder;

	holder = (pkg_status && process_no<no_pkg_status)?
		&(pkg_status[process_no]) : NULL ;

	set_pkg_stats( holder );
#endif
	return;
}

static inline void signal_pkg_status(unsigned long proc_id)
{
	time_t t;

	if (IPC_FD_WRITE(proc_id)<=0)
		return;

	t = time(NULL);
	if (t>marker_t[proc_id]+1) {

		if (ipc_send_rpc( proc_id, rpc_get_pkg_stats, NULL)<0) {
			LM_ERR("failed to trigger pkg stats for process %ld\n", proc_id );
			return;
		}

		marker_t[proc_id] = t;
		usleep(20);
	}
}

static unsigned long get_pkg_total_size( void* proc_id)
{
	signal_pkg_status((unsigned long)proc_id);
	return pkg_status[(unsigned long)proc_id][PKG_TOTAL_SIZE_IDX];
}

static unsigned long get_pkg_used_size( void* proc_id)
{
	signal_pkg_status((unsigned long)proc_id);
	return pkg_status[(unsigned long)proc_id][PKG_USED_SIZE_IDX];
}

static unsigned long get_pkg_real_used_size( void* proc_id)
{
	signal_pkg_status((unsigned long)proc_id);
	return pkg_status[(unsigned long)proc_id][PKG_REAL_USED_SIZE_IDX];
}

static unsigned long get_pkg_max_used_size( void* proc_id)
{
	signal_pkg_status((unsigned long)proc_id);
	return pkg_status[(unsigned long)proc_id][PKG_MAX_USED_SIZE_IDX];
}

static unsigned long get_pkg_free_size( void* proc_id)
{
	signal_pkg_status((unsigned long)proc_id);
	return pkg_status[(unsigned long)proc_id][PKG_FREE_SIZE_IDX];
}

static unsigned long get_pkg_fragments( void*proc_id)
{
	signal_pkg_status((unsigned long)proc_id);
	return pkg_status[(unsigned long)proc_id][PKG_FRAGMENTS_SIZE_IDX];
}


int init_pkg_stats(int procs_no)
{
	int n;
	str n_str;
	char *name;
	str sname;

	LM_DBG("setting stats for %d processes\n",procs_no);

	pkg_status = shm_malloc(procs_no*sizeof(pkg_status_holder));
	marker_t = shm_malloc(procs_no*sizeof(time_t));
	if (pkg_status==NULL || marker_t==NULL) {
		LM_ERR("no more pkg mem for stats\n");
		return -1;
	}
	memset( pkg_status, 0, procs_no*sizeof(pkg_status_holder));
	memset( marker_t, 0, procs_no*sizeof(time_t));
	no_pkg_status = procs_no;

	/* build the stats and register them */
	for( n=0 ; n<procs_no ; n++) {
		n_str.s = int2str( n, &n_str.len);

		if ( (name=build_stat_name( &n_str,"total_size"))==0 ||
		register_stat2("pkmem", name, (stat_var**)get_pkg_total_size,
		STAT_NO_RESET|STAT_SHM_NAME|STAT_IS_FUNC, (void*)(long)n, 0)!=0 ) {
			LM_ERR("failed to add stat variable\n");
			return -1;
		}
		sname.s = name;
		sname.len = strlen(name);
		pt[n].pkg_total = get_stat(&sname);
		pt[n].pkg_total->flags |= STAT_HIDDEN;

		if ( (name=build_stat_name( &n_str,"used_size"))==0 ||
		register_stat2("pkmem", name, (stat_var**)get_pkg_used_size,
		STAT_NO_RESET|STAT_SHM_NAME|STAT_IS_FUNC, (void*)(long)n, 0)!=0 ) {
			LM_ERR("failed to add stat variable\n");
			return -1;
		}
		sname.s = name;
		sname.len = strlen(name);
		pt[n].pkg_used = get_stat(&sname);
		pt[n].pkg_used->flags |= STAT_HIDDEN;

		if ( (name=build_stat_name( &n_str,"real_used_size"))==0 ||
		register_stat2("pkmem", name, (stat_var**)get_pkg_real_used_size,
		STAT_NO_RESET|STAT_SHM_NAME|STAT_IS_FUNC, (void*)(long)n, 0)!=0 ) {
			LM_ERR("failed to add stat variable\n");
			return -1;
		}
		sname.s = name;
		sname.len = strlen(name);
		pt[n].pkg_rused = get_stat(&sname);
		pt[n].pkg_rused->flags |= STAT_HIDDEN;

		if ( (name=build_stat_name( &n_str,"max_used_size"))==0 ||
		register_stat2("pkmem", name, (stat_var**)get_pkg_max_used_size,
		STAT_NO_RESET|STAT_SHM_NAME|STAT_IS_FUNC, (void*)(long)n, 0)!=0 ) {
			LM_ERR("failed to add stat variable\n");
			return -1;
		}
		sname.s = name;
		sname.len = strlen(name);
		pt[n].pkg_mused = get_stat(&sname);
		pt[n].pkg_mused->flags |= STAT_HIDDEN;

		if ( (name=build_stat_name( &n_str,"free_size"))==0 ||
		register_stat2("pkmem", name, (stat_var**)get_pkg_free_size,
		STAT_NO_RESET|STAT_SHM_NAME|STAT_IS_FUNC, (void*)(long)n, 0)!=0 ) {
			LM_ERR("failed to add stat variable\n");
			return -1;
		}
		sname.s = name;
		sname.len = strlen(name);
		pt[n].pkg_free = get_stat(&sname);
		pt[n].pkg_free->flags |= STAT_HIDDEN;

		if ( (name=build_stat_name( &n_str,"fragments"))==0 ||
		register_stat2("pkmem", name, (stat_var**)get_pkg_fragments,
		STAT_NO_RESET|STAT_SHM_NAME|STAT_IS_FUNC, (void*)(long)n, 0)!=0 ) {
			LM_ERR("failed to add stat variable\n");
			return -1;
		}
		sname.s = name;
		sname.len = strlen(name);
		pt[n].pkg_frags = get_stat(&sname);
		pt[n].pkg_frags->flags |= STAT_HIDDEN;

	}

	return 0;
}
#endif /* PKG */

#endif /* STATISTICS */
