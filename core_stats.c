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

	/*
	 * Two passes on purpose.  signal_pkg_status() only ASKS each process to
	 * refresh its slot - the answer arrives later over IPC - so reading in
	 * the same loop that asks would report whatever was there from the
	 * previous round, and on the very first call that is zero.  Ask
	 * everyone, give the replies a moment to land, then read.
	 */
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
#include "mem/hg_buddy.h"       /* hg_grow_blocked_tick */
#include "mem/shm_mem.h"        /* shm_block, for the grow-blocked gauge */
#include "evi/evi_core.h"       /* EVI_SHM_GROW_BLOCKED_ID */
#include "evi/evi_modules.h"    /* evi_probe/get_params/raise */

/*
 * The HG_MALLOC idle-cache sweep.
 *
 * HG_MALLOC's per-thread free caches live in __thread storage, so no other
 * process or thread can reach them - a cell parked there is invisible to the
 * block accounting and pins a whole block from being reclaimed. The allocator
 * flushes its own cache when it is about to grow the arena, but nothing fires
 * on a thread that has simply STOPPED allocating, which is precisely what a
 * worker does after a traffic burst subsides - the case that strands memory.
 *
 * So the flush has to be dispatched to each worker to run in its own context,
 * exactly the problem signal_pkg_status() above already solves: ipc_send_rpc()
 * makes the target execute the job on its own reactor. Two things are carried
 * over from it deliberately:
 *
 *   - the self case runs INLINE. Sending ourselves an IPC job would order
 *     behind the job we are currently running.
 *   - nothing waits for a result. Its read side blocks on usleep(20) for a
 *     value that is a request behind; a flush is not a reader, so it is
 *     fire-and-forget and the next tick simply tries again.
 *
 * NOT covered, and it needs saying: TCP main's IO pool threads wait on a
 * condition variable rather than the reactor, so IPC never reaches them. Their
 * caches still need a flag checked at a job boundary.
 */
#define HG_SWEEP_INTERVAL 30   /* seconds; the caches are a slow leak, not a
                                * fast one, and each sweep costs a lock per
                                * arena per process */

static void rpc_hg_cache_flush(int sender, void *param)
{
	hg_cache_flush_self();
}

/*
 * The deferred half of GROW-BLOCKED alerting (v3). hg_buddy_grow() latches
 * the state under hb->lock and may not raise an event there:
 * evi_raise_event() allocates shm, and the arena that just refused to grow
 * is the arena it would allocate from. This runs in the timer process with
 * no arena lock held, once per sweep - which also gives the design's
 * "re-warn interval exceeds a GC cycle" for free.
 *
 * SHM arena only, and honestly so: each worker's PKG arena is
 * MAP_PRIVATE, its grow_blocked visible only inside that process - a pkg
 * latch still WARNs in that worker's log and shows in its hg_stats pkg
 * section, but no single process can gauge them all.
 *
 * While the latch holds, the event re-raises every
 * HG_GROW_REWARN_SWEEPS sweeps so a subscriber that attached late (or an
 * event pipeline that dropped one) still learns of a persistent block.
 */
#define HG_GROW_REWARN_SWEEPS 10   /* x 30s sweep = every 5 minutes */

static str hg_gb_arena_str     = str_init("arena");
static str hg_gb_committed_str = str_init("committed_mb");
static str hg_gb_cap_str       = str_init("cap_mb");
static str hg_gb_refused_str   = str_init("grow_refused");

static void hg_grow_blocked_event(void)
{
	struct hg_block *hb = (struct hg_block *)shm_block;
	static unsigned int blocked_sweeps;
	evi_params_p list;
	int due, committed_mb, cap_mb, refused;
	str arena = str_init("shm");

	if (!hb)
		return;

	/* consume the due flag and sample the numbers under the lock; the
	 * raise itself must happen outside it */
	lock_get(&hb->lock);
	/* promote (or disarm) an armed episode first, so a latch earns its
	 * event in the same tick that detects it */
	hg_grow_blocked_tick(hb);
	/* the profile's proactive grow gate, then the down-slow shrink gate -
	 * the shm arena's once-per-interval policy heartbeat (pkg arenas tick
	 * themselves from each process's flush path; a private arena has one
	 * owner) */
	hg_grow_tick(hb);
	hg_shrink_tick(hb);
	due = hb->grow_event_due;
	hb->grow_event_due = 0;
	if (!due && hb->grow_blocked &&
	    ++blocked_sweeps >= HG_GROW_REWARN_SWEEPS) {
		due = 1;                     /* still blocked - re-warn */
	}
	if (due)
		blocked_sweeps = 0;
	if (!hb->grow_blocked)
		blocked_sweeps = 0;
	committed_mb = (int)(hb->hsize >> 20);
	cap_mb       = (int)(hb->hcap >> 20);
	refused      = (int)hb->grow_refused;
	lock_release(&hb->lock);

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

static void hg_cache_sweep(unsigned int ticks, void *param)
{
	int i;

	hg_grow_blocked_event();

	/*
	 * Publish the sweep to threads IPC cannot reach BEFORE dispatching to
	 * the ones it can. TCP main's IO pool waits on a condition variable
	 * rather than the reactor, so those threads never receive an RPC job;
	 * they compare this counter at a job boundary instead
	 * (hg_cache_flush_if_due()). Bumping it first means a thread that is
	 * between jobs right now picks the sweep up immediately rather than
	 * waiting for the next one.
	 */
	hg_sweep_gen++;

	for (i = 0; i < counted_max_processes; i++) {
		if (i == process_no) {
			/* never RPC ourselves - see signal_pkg_status() */
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
	/*
	 * Both variants, for correctness rather than for a bug that was
	 * observed: with -a HG_MALLOC the allocator resolves to MM_HG_MALLOC,
	 * but -a HG_MALLOC_DBG resolves to MM_HG_MALLOC_DBG and would otherwise
	 * silently decline to register. Every other such test in the tree pairs
	 * them (mem/shm_mem.c:327, :918, :948, :1033, :1226).
	 */
	if (mem_allocator_shm != MM_HG_MALLOC &&
	    mem_allocator_shm != MM_HG_MALLOC_DBG &&
	    mem_allocator_pkg != MM_HG_MALLOC &&
	    mem_allocator_pkg != MM_HG_MALLOC_DBG)
		return 0;   /* not our allocator - nothing caches anything */

	if (register_timer("hg-cache-sweep", hg_cache_sweep, NULL,
	                   HG_SWEEP_INTERVAL, TIMER_FLAG_SKIP_ON_DELAY) < 0) {
		LM_ERR("failed to register the HG_MALLOC cache sweep\n");
		return -1;
	}
	LM_NOTICE("HG_MALLOC idle-cache sweep registered, every %d s "
		"(shm=%s pkg=%s)\n", HG_SWEEP_INTERVAL,
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
