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
stat_var* bad_msg_hdr;
stat_var* slow_msgs;


const stat_export_t core_stats[] = {
	{"rcv_requests" ,         0,  &rcv_reqs              },
	{"rcv_replies" ,          0,  &rcv_rpls              },
	{"fwd_requests" ,         0,  &fwd_reqs              },
	{"fwd_replies" ,          0,  &fwd_rpls              },
	{"drop_requests" ,        0,  &drp_reqs              },
	{"drop_replies" ,         0,  &drp_rpls              },
	{"err_requests" ,         0,  &err_reqs              },
	{"err_replies" ,          0,  &err_rpls              },
	{"bad_URIs_rcvd",         0,  &bad_URIs              },
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

const stat_export_t net_stats[] = {
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

		if (proc_id==process_no) {
			/* avoid sending IPC to ourselves, as it will get executed
			 * after we ar done with pkg_status job; better do it inline */
			rpc_get_pkg_stats(process_no, NULL);
		} else {
			if (ipc_send_rpc( proc_id, rpc_get_pkg_stats, NULL)<0) {
				LM_ERR("failed to trigger pkg stats for process %ld\n",
					proc_id );
				return;
			}
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

int hg_pkg_peak_all(unsigned long *peak, unsigned long *sum, int *nproc)
{
	unsigned long mx = 0, tot = 0;
	int i, n = 0;

	if (!pkg_status || no_pkg_status <= 0)
		return -1;

	/* two passes: signal_pkg_status() only asks for a refresh over IPC, so
	 * ask everyone, let the replies land, then read */
	for (i = 0; i < no_pkg_status; i++)
		signal_pkg_status((unsigned long)i);

	usleep(50000);

	for (i = 0; i < no_pkg_status; i++) {
		unsigned long v = pkg_status[i][PKG_MAX_USED_SIZE_IDX];

		/* a slot with no total_size has never been filled in: that
		 * process either does not exist or has not answered yet */
		if (!pkg_status[i][PKG_TOTAL_SIZE_IDX])
			continue;
		n++;
		tot += v;
		if (v > mx)
			mx = v;
	}

	if (peak)  *peak  = mx;
	if (sum)   *sum   = tot;
	if (nproc) *nproc = n;
	return n ? 0 : -1;
}



#if defined(HG_MALLOC) && !defined(INLINE_ALLOC)
#include "mem/hg_arena.h"
#include "mem/hg_buddy.h"
#include "mem/shm_mem.h"
#include "evi/evi_core.h"
#include "evi/evi_modules.h"

/* idle-cache sweep: __thread caches strand memory once a worker stops
 * allocating, so each owner is told by IPC to flush */
/* every 4th interval sweeps the clean processes too (their pkg caches) */
#define HG_SWEEP_FORCE_EVERY 4
#define HG_SWEEP_INTERVAL 30   /* seconds; a slow leak, and each sweep
                                * costs a lock per arena per process */

static void rpc_hg_cache_flush(int sender, void *param)
{
	/* runs in the target process: publish the sweep to its threads IPC
	 * cannot reach (hg_sweep_gen is per process), then flush this one */
	__atomic_fetch_add(&hg_sweep_gen, 1, __ATOMIC_RELAXED);
	hg_cache_flush_self();
}

/* GROW-BLOCKED alert: shm arena only (pkg is per process), re-raised
 * while the latch holds */
#define HG_GROW_REWARN_SWEEPS 10   /* x 30s sweep = every 5 minutes */

static str hg_gb_arena_str     = str_init("arena");
static str hg_gb_committed_str = str_init("committed_mb");
static str hg_gb_cap_str       = str_init("cap_mb");
static str hg_gb_refused_str   = str_init("grow_refused");
static str hg_ls_reason_str    = str_init("reason");
static str hg_ls_hold_str      = str_init("hold_us");
static str hg_ls_proc_str      = str_init("process");
static str hg_ls_stalls_str    = str_init("stalls");

static void hg_lock_stall_event(unsigned long hold_ns, int reason, int proc,
                                unsigned long stalls)
{
	evi_params_p list;
	str arena = str_init("shm");
	str rs;
	int hold_us = (int)(hold_ns / 1000), stalls_i = (int)stalls;

	rs.s = (char *)(reason >= 0 && reason < HG_LK_REASONS ?
	                hg_lk_reason_str[reason] : "?");
	rs.len = strlen(rs.s);
	if (!evi_probe_event(EVI_HG_LOCK_STALL_ID))
		return;           /* hg_shm_lock_stalls has it for pollers */
	list = evi_get_params();
	if (!list)
		return;
	if (evi_param_add_str(list, &hg_gb_arena_str, &arena) ||
	    evi_param_add_str(list, &hg_ls_reason_str, &rs) ||
	    evi_param_add_int(list, &hg_ls_hold_str, &hold_us) ||
	    evi_param_add_int(list, &hg_ls_proc_str, &proc) ||
	    evi_param_add_int(list, &hg_ls_stalls_str, &stalls_i)) {
		LM_ERR("unable to build the lock-stall event parameters\n");
		evi_free_params(list);
		return;
	}
	if (evi_raise_event(EVI_HG_LOCK_STALL_ID, list))
		LM_ERR("unable to raise the lock-stall event\n");
}

static void hg_grow_blocked_event(unsigned int ticks)
{
	struct hg_block *hb = (struct hg_block *)shm_block;
	evi_params_p list;
	int due, committed_mb, cap_mb, refused;
	unsigned int stall_due;
	unsigned long stall_ns, stalls;
	int stall_reason, stall_proc;
	str arena = str_init("shm");

	/* the sweep also runs for -k HG_MALLOC alone, where shm_block
	 * belongs to another allocator */
	if (!hb || (mem_allocator_shm != MM_HG_MALLOC &&
	            mem_allocator_shm != MM_HG_MALLOC_DBG))
		return;

	/* consume the due flag and sample the numbers under the lock; the
	 * raise itself must happen outside it */
	hg_lock_enter(hb, HG_LK_POLICY);
	/* promote (or disarm) an armed episode first, so a latch earns its
	 * event in the same tick that detects it */
	hg_grow_blocked_tick(hb);
	/* the shm arena's policy tick; each pkg arena ticks itself from its
	 * owner's flush path */
	if (!hb->maint_active) {        /* else the maintenance process ticks */
		hg_grow_tick(hb);
		hg_shrink_tick(hb);
	}
	due = hb->grow_event_due;
	hb->grow_event_due = 0;
	if (!due && hb->grow_blocked &&
	    (ticks / HG_SWEEP_INTERVAL) % HG_GROW_REWARN_SWEEPS == 0)
		due = 1;
	committed_mb = (int)(hb->committed_bytes >> 20);
	cap_mb       = (int)(hb->hcap >> 20);
	refused      = (int)hb->grow_refused;
	stall_due    = hb->lk_stall_event_due;
	hb->lk_stall_event_due = 0;
	stall_ns     = hb->lk_last_stall_ns;
	stall_reason = hb->lk_last_stall_reason;
	stall_proc   = hb->lk_last_stall_proc;
	stalls       = hb->lk_stalls;
	hg_lock_leave(hb);

	if (stall_due)
		hg_lock_stall_event(stall_ns, stall_reason, stall_proc, stalls);

	if (!due)
		return;

	if (!evi_probe_event(EVI_SHM_GROW_BLOCKED_ID)) {
		LM_WARN("shm GROW-BLOCKED event due, no subscribers - alert "
			"on the hg_shm_grow_blocked statistic instead\n");
		return;
	}

	list = evi_get_params();
	if (!list)
		return;
	if (evi_param_add_str(list, &hg_gb_arena_str, &arena) ||
	    evi_param_add_int(list, &hg_gb_committed_str, &committed_mb) ||
	    evi_param_add_int(list, &hg_gb_cap_str, &cap_mb) ||
	    evi_param_add_int(list, &hg_gb_refused_str, &refused)) {
		LM_ERR("unable to build the grow-blocked event parameters\n");
		evi_free_params(list);
		return;
	}
	if (evi_raise_event(EVI_SHM_GROW_BLOCKED_ID, list))
		LM_ERR("unable to raise the grow-blocked event\n");
}

/* staggered: each process gets one second of the interval, so flushes do
 * not convoy on the arena lock and then all refill at once */
static void hg_cache_sweep(unsigned int ticks, void *param)
{
	/* the timer's tick, not a static counter: timer jobs run in whichever
	 * process reads the timer pipe, each with its own statics */
	unsigned int slot = ticks % HG_SWEEP_INTERVAL;
	int i, n = counted_max_processes;

	hg_sample_live_peaks();

	if (slot == 0) {
		hg_grow_blocked_event(ticks);
		hg_oom_report_shared();
	}

	for (i = 0; i < n; i++) {
		/* a multiplicative hash of the index spreads contiguous (live,
		 * low-index) processes over the whole interval, once each */
		if ((unsigned int)((unsigned int)i * 2654435761u % HG_SWEEP_INTERVAL) != slot)
			continue;
		/* skip a process with clean shared caches; its pkg caches are not
		 * visible here */
		if ((ticks / HG_SWEEP_INTERVAL) % HG_SWEEP_FORCE_EVERY &&
		    !hg_proc_cache_dirty(i)) {
			if (mem_allocator_shm == MM_HG_MALLOC ||
			    mem_allocator_shm == MM_HG_MALLOC_DBG)
				((struct hg_block *)shm_block)->sweeps_skipped++;
			continue;
		}
		if (i == process_no) {
			/* never RPC this process - see signal_pkg_status() */
			hg_cache_flush_self();
			continue;
		}
		if (IPC_FD_WRITE(i) <= 0)
			continue;
		/* fire and forget: a failed dispatch is not worth logging every
		 * 30 seconds for a process that may simply be shutting down */
		ipc_send_rpc(i, rpc_hg_cache_flush, NULL);
	}
}

int hg_register_cache_sweep(void)
{
	/* both variants: -a HG_MALLOC_DBG resolves to MM_HG_MALLOC_DBG */
	if (mem_allocator_shm != MM_HG_MALLOC &&
	    mem_allocator_shm != MM_HG_MALLOC_DBG &&
	    mem_allocator_pkg != MM_HG_MALLOC &&
	    mem_allocator_pkg != MM_HG_MALLOC_DBG)
		return 0;

	if (register_timer("hg-cache-sweep", hg_cache_sweep, NULL,
	                   1, TIMER_FLAG_SKIP_ON_DELAY) < 0) {
		LM_ERR("failed to register the HG_MALLOC cache sweep\n");
		return -1;
	}
	LM_NOTICE("HG_MALLOC idle-cache sweep registered, every %d s per "
		"process, staggered (shm=%s pkg=%s)\n", HG_SWEEP_INTERVAL,
		mm_str(mem_allocator_shm), mm_str(mem_allocator_pkg));
	return 0;
}
#else
int hg_register_cache_sweep(void) { return 0; }
#endif /* HG_MALLOC */

int init_pkg_stats(int procs_no)
{
	int n;
	str n_str;
	char *name;
	str sname;
	group_stats *total_size_grp, *used_size_grp, *real_used_size_grp,
				*max_used_size_grp, *free_size_grp, *frags_grp;

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


	total_size_grp = register_stats_group("proc_total_size");
	if (!total_size_grp) {
		LM_ERR("could not register stats group proc_total_size");
		return -1;
	}
	used_size_grp = register_stats_group("proc_used_size");
	if (!used_size_grp) {
		LM_ERR("could not register stats group proc_used_size");
		return -1;
	}
	real_used_size_grp = register_stats_group("proc_real_used_size");
	if (!real_used_size_grp) {
		LM_ERR("could not register stats group proc_real_used_size");
		return -1;
	}
	max_used_size_grp = register_stats_group("proc_max_used_size");
	if (!max_used_size_grp) {
		LM_ERR("could not register stats group proc_max_used_size");
		return -1;
	}
	free_size_grp = register_stats_group("proc_free_size");
	if (!free_size_grp) {
		LM_ERR("could not register stats group proc_free_size");
		return -1;
	}
	frags_grp = register_stats_group("proc_fragments");
	if (!frags_grp) {
		LM_ERR("could not register stats group proc_fragments");
		return -1;
	}

	/* build the stats and register them */
	for( n=0 ; n<procs_no ; n++) {
		n_str.s = int2str( n, &n_str.len);

		if ( (name=build_stat_name( &n_str,"total_size"))==0 ||
		register_stat2("pkmem", name, (stat_var**)get_pkg_total_size,
		STAT_NO_RESET|STAT_SHM_NAME|STAT_IS_FUNC|STAT_PER_PROC,
		(void*)(long)n, 0)!=0 ) {
			LM_ERR("failed to add stat variable\n");
			return -1;
		}
		sname.s = name;
		sname.len = strlen(name);
		pt[n].pkg_total = get_stat(&sname);
		pt[n].pkg_total->flags |= STAT_HIDDEN;
		add_stats_group(total_size_grp, pt[n].pkg_total);

		if ( (name=build_stat_name( &n_str,"used_size"))==0 ||
		register_stat2("pkmem", name, (stat_var**)get_pkg_used_size,
		STAT_NO_RESET|STAT_SHM_NAME|STAT_IS_FUNC|STAT_PER_PROC,
		(void*)(long)n, 0)!=0 ) {
			LM_ERR("failed to add stat variable\n");
			return -1;
		}
		sname.s = name;
		sname.len = strlen(name);
		pt[n].pkg_used = get_stat(&sname);
		pt[n].pkg_used->flags |= STAT_HIDDEN;
		add_stats_group(used_size_grp, pt[n].pkg_used);

		if ( (name=build_stat_name( &n_str,"real_used_size"))==0 ||
		register_stat2("pkmem", name, (stat_var**)get_pkg_real_used_size,
		STAT_NO_RESET|STAT_SHM_NAME|STAT_IS_FUNC|STAT_PER_PROC,
		(void*)(long)n, 0)!=0 ) {
			LM_ERR("failed to add stat variable\n");
			return -1;
		}
		sname.s = name;
		sname.len = strlen(name);
		pt[n].pkg_rused = get_stat(&sname);
		pt[n].pkg_rused->flags |= STAT_HIDDEN;
		add_stats_group(real_used_size_grp, pt[n].pkg_rused);

		if ( (name=build_stat_name( &n_str,"max_used_size"))==0 ||
		register_stat2("pkmem", name, (stat_var**)get_pkg_max_used_size,
		STAT_NO_RESET|STAT_SHM_NAME|STAT_IS_FUNC|STAT_PER_PROC,
		(void*)(long)n, 0)!=0 ) {
			LM_ERR("failed to add stat variable\n");
			return -1;
		}
		sname.s = name;
		sname.len = strlen(name);
		pt[n].pkg_mused = get_stat(&sname);
		pt[n].pkg_mused->flags |= STAT_HIDDEN;
		add_stats_group(max_used_size_grp, pt[n].pkg_mused);

		if ( (name=build_stat_name( &n_str,"free_size"))==0 ||
		register_stat2("pkmem", name, (stat_var**)get_pkg_free_size,
		STAT_NO_RESET|STAT_SHM_NAME|STAT_IS_FUNC|STAT_PER_PROC,
		(void*)(long)n, 0)!=0 ) {
			LM_ERR("failed to add stat variable\n");
			return -1;
		}
		sname.s = name;
		sname.len = strlen(name);
		pt[n].pkg_free = get_stat(&sname);
		pt[n].pkg_free->flags |= STAT_HIDDEN;
		add_stats_group(free_size_grp, pt[n].pkg_free);

		if ( (name=build_stat_name( &n_str,"fragments"))==0 ||
		register_stat2("pkmem", name, (stat_var**)get_pkg_fragments,
		STAT_NO_RESET|STAT_SHM_NAME|STAT_IS_FUNC|STAT_PER_PROC,
		(void*)(long)n, 0)!=0 ) {
			LM_ERR("failed to add stat variable\n");
			return -1;
		}
		sname.s = name;
		sname.len = strlen(name);
		pt[n].pkg_frags = get_stat(&sname);
		pt[n].pkg_frags->flags |= STAT_HIDDEN;
		add_stats_group(frags_grp, pt[n].pkg_frags);
	}

	return 0;
}
#endif /* PKG */

#endif /* STATISTICS */

#if !defined(STATISTICS) || !defined(PKG_MALLOC)
/* the sweep runs over the pkg statistics: nothing to register without them */
int hg_register_cache_sweep(void) { return 0; }
#endif
