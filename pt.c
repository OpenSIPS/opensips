/*
 * Copyright (C) 2007 Voice Sistem SRL
 * Copyright (C) 2008-2019 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* for cpu_set_t / CPU_SET / sched_setaffinity, used by the pin_*_cpu()
 * helpers below. Defined before the first include and never #undef'd -
 * undefining it after the fact is what broke the musl build in lib/url.c
 * (see PR #4119). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "lib/dbg/profiling.h"
#include "mem/shm_mem.h"
#include "net/net_tcp.h"
#include "net/net_udp.h"
#include "db/db_insertq.h"
#include "sr_module.h"
#include "dprint.h"
#include "pt.h"
#include "bin_interface.h"
#include "core_stats.h"


/* array with children pids, 0= main proc,
 * alloc'ed in shared mem if possible */
struct process_table *pt = NULL;

/* The maximum number of processes that will ever exist in OpenSIPS. This is
 * actually the size of the process table
 * This is READONLY!! */
unsigned int counted_max_processes = 0;

/* flag per process to control the termination stages */
int _termination_in_progress = 0;

static int internal_fork_child_setup(const struct internal_fork_params *);

static struct internal_fork_handler default_fh = {
	.desc = "internal_fork_child_setup()",
	.post_fork.in_child = internal_fork_child_setup,
};

static struct internal_fork_handler *_fork_handlers = &default_fh;

/* Register handlers to be invoked after internal_fork()
 * to do various per-subsystem setup / cleanup tasks.
 * Takes a reference to a "stable" structure (i.e. static or
 * malloc'ed) which has to be alive until the last internal_fork()
 * is called. */
void register_fork_handler(struct internal_fork_handler *h)
{
	struct internal_fork_handler *hp;

	if (is_main == 0) {
		LM_BUG("buggy call from non-main process!!!\n");
		abort();
	}
	if (h->_next != NULL) {
		LM_BUG("buggy call h->_next != NULL!!!\n");
		abort();
	}

	for (hp = _fork_handlers; hp->_next != NULL; hp = hp->_next)
		continue;
	hp->_next = h;
};

/*
 * CPU pinning is Linux-only: cpu_set_t and sched_setaffinity() are a
 * glibc/Linux interface. OpenSIPS also builds on the BSDs, Solaris and
 * Darwin, which each spell this differently (FreeBSD has cpuset_t and
 * cpuset_setaffinity, for instance), so the whole feature is compiled out
 * elsewhere rather than guessed at. Configuring it there is reported once
 * instead of silently doing nothing.
 */
#ifdef __OS_linux

/*
 * Per-process-type CPU groups.
 *
 * "pin_workers=1" turns pinning on; each of these then optionally confines
 * one kind of process to a CPU list:
 *
 *     pin_udp_cpus   = "0-7"
 *     pin_tcp_cpus   = "8-11"
 *     pin_timer_cpus = "12"
 *
 * A type with no list set may use every CPU the process is allowed. Note
 * that bin and hep are not process types of their own - they are transport
 * protocols carried by the ordinary UDP/TCP workers, so they follow
 * whichever of those they run over.
 */
static cpu_set_t pin_type_set[TYPE_MODULE + 1];
static char pin_type_has[TYPE_MODULE + 1];
static int pin_spec_parsed;

/* "0-7,12" -> set. Returns -1 on malformed input. */
static int pin_parse_cpulist(const char *s, cpu_set_t *set)
{
	long a, b;
	char *end;

	CPU_ZERO(set);
	while (*s) {
		while (*s == ' ' || *s == ',') s++;
		if (!*s)
			break;
		a = strtol(s, &end, 10);
		if (end == s || a < 0 || a >= CPU_SETSIZE)
			return -1;
		s = end;
		b = a;
		if (*s == '-') {
			s++;
			b = strtol(s, &end, 10);
			if (end == s || b < a || b >= CPU_SETSIZE)
				return -1;
			s = end;
		}
		for (; a <= b; a++)
			CPU_SET(a, set);
	}
	return 0;
}

static void pin_set_group(enum process_type t, const char *list,
                                                       const char *name)
{
	if (!list)
		return;
	if (pin_parse_cpulist(list, &pin_type_set[t]) < 0 ||
	    CPU_COUNT(&pin_type_set[t]) == 0) {
		LM_ERR("pin_%s_cpus: bad or empty CPU list \"%s\"\n", name, list);
		return;
	}
	pin_type_has[t] = 1;
	LM_INFO("pinning %s processes to %d CPU(s)\n", name,
		CPU_COUNT(&pin_type_set[t]));
}

/* did the config name a CPU list for any process type at all? */
static int pin_any_group(void)
{
	int t;

	for (t = 0; t <= TYPE_MODULE; t++)
		if (pin_type_has[t])
			return 1;

	return 0;
}

/* parsed once, lazily, in the parent before any fork */
static void pin_parse_spec(void)
{
	pin_spec_parsed = 1;
	pin_set_group(TYPE_UDP,    pin_udp_cpus,    "udp");
	pin_set_group(TYPE_TCP,    pin_tcp_cpus,    "tcp");
	pin_set_group(TYPE_TIMER,  pin_timer_cpus,  "timer");
	pin_set_group(TYPE_MODULE, pin_module_cpus, "module");
}

/*
 * Choose the CPU a new process should be pinned to, or -1 for "do not pin".
 * Runs in the PARENT, before fork.
 *
 * Two things matter here:
 *
 *  - The candidate CPUs come from the set this process is ALREADY allowed to
 *    run on, read back with sched_getaffinity() rather than assumed from the
 *    machine's CPU count. Under a cgroup or cpuset - a container, a systemd
 *    slice - we may be confined to a subset, and picking a raw CPU number
 *    would either fail or quietly widen affinity past what the operator
 *    confined us to. Intersecting can only ever narrow.
 *
 *  - The CPU is the least-occupied one, counted over the processes actually
 *    running right now. Deriving it from the process-table slot instead would
 *    look balanced at startup and drift badly afterwards: with auto-scaling,
 *    slots are freed and reused, so a recycled slot can land on a CPU that
 *    already has workers while another sits idle.
 */
static int pin_pick_cpu(enum process_type ptype, struct socket_info *sock)
{
	cpu_set_t allowed;
	cpu_set_t sock_set;
	int count[CPU_SETSIZE];
	int i, n, best = -1, best_load = 0;

	if (!pin_workers && !(sock && sock->pin_cpus))
		return -1;

	if (!pin_spec_parsed)
		pin_parse_spec();

	CPU_ZERO(&allowed);
	if (sched_getaffinity(0, sizeof allowed, &allowed) != 0) {
		LM_WARN("cannot read CPU affinity, leaving new process unpinned: %s\n",
			strerror(errno));
		return -1;
	}

	/* narrow to this process type's group, if the spec named one. The
	 * intersection keeps the cpuset guarantee: a group can only ever
	 * restrict further, never grant a CPU we were not already allowed. */
	if (sock && sock->pin_cpus) {
		/* the listener named its own CPUs - more specific than the group */
		if (pin_parse_cpulist(sock->pin_cpus, &sock_set) < 0 ||
		    CPU_COUNT(&sock_set) == 0) {
			LM_ERR("pin_cpus: bad or empty CPU list \"%s\" on listener "
				"%.*s - leaving its workers unpinned\n", sock->pin_cpus,
				sock->name.len, sock->name.s);
			return -1;
		}
		CPU_AND(&allowed, &allowed, &sock_set);
		if (CPU_COUNT(&allowed) == 0) {
			LM_WARN("pin_cpus on listener %.*s has no CPU in common with "
				"the allowed set - leaving its workers unpinned\n",
				sock->name.len, sock->name.s);
			return -1;
		}
	} else if (ptype >= 0 && ptype <= TYPE_MODULE && pin_type_has[ptype]) {
		CPU_AND(&allowed, &allowed, &pin_type_set[ptype]);
		if (CPU_COUNT(&allowed) == 0) {
			LM_WARN("pin_workers: group for this process type has no CPU "
				"in common with the allowed set - leaving unpinned\n");
			return -1;
		}
	} else if (pin_any_group()) {
		/* This process belongs to no named group while other groups do
		 * exist. Pinning it anyway would place it by occupancy across
		 * every CPU, including the ones a group was given precisely so
		 * that nothing else would run there - which is the opposite of
		 * what the operator asked for. Leave it to the scheduler. */
		return -1;
	}

	n = CPU_COUNT(&allowed);
	if (n < 1)
		return -1;

	memset(count, 0, sizeof count);
	for (i = 0; i < counted_max_processes; i++) {
		int c = pt[i].pinned_cpu;

		if (c >= 0 && c < CPU_SETSIZE && is_process_running(i))
			count[c]++;
	}

	for (i = 0; i < CPU_SETSIZE; i++) {
		if (!CPU_ISSET(i, &allowed))
			continue;
		if (best < 0 || count[i] < best_load) {
			best = i;
			best_load = count[i];
		}
	}

	return best;
}

/* Apply the choice made above. Runs in the CHILD. */
static void pin_apply_cpu(int cpu)
{
	cpu_set_t one;

	if (cpu < 0)
		return;

	CPU_ZERO(&one);
	CPU_SET(cpu, &one);
	if (sched_setaffinity(0, sizeof one, &one) != 0) {
		LM_WARN("failed to pin process %d to CPU %d: %s\n",
			process_no, cpu, strerror(errno));
		return;
	}

	LM_INFO("process %d pinned to CPU %d\n", process_no, cpu);
}

/* Confine a multithreaded process to its group's whole CPU list. Runs in
 * the CHILD, before any of its threads exist, so they all inherit it. */
static void pin_apply_group(enum process_type t)
{
	cpu_set_t set;

	if (!pin_spec_parsed)
		pin_parse_spec();
	if (t < 0 || t > TYPE_MODULE || !pin_type_has[t])
		return;

	if (sched_getaffinity(0, sizeof set, &set) != 0)
		return;
	CPU_AND(&set, &set, &pin_type_set[t]);
	if (CPU_COUNT(&set) == 0) {
		LM_WARN("pin group for process %d has no CPU in common with the "
			"allowed set - leaving it unpinned\n", process_no);
		return;
	}
	if (sched_setaffinity(0, sizeof set, &set) != 0) {
		LM_WARN("failed to pin process %d to its CPU group: %s\n",
			process_no, strerror(errno));
		return;
	}
	LM_INFO("process %d pinned to a %d-CPU group\n", process_no,
		CPU_COUNT(&set));
}


#else  /* !__OS_linux */

static int pin_pick_cpu(enum process_type ptype, struct socket_info *sock)
{
	static int warned;

	if (pin_workers && !warned) {
		warned = 1;
		LM_WARN("CPU pinning is only implemented on Linux - "
			"pin_workers and pin_*_cpus have no effect here\n");
	}
	return -1;
}

static void pin_apply_cpu(int cpu)
{
}

static void pin_apply_group(enum process_type t)
{
}

#endif /* __OS_linux */

static unsigned long count_running_processes(void *x)
{
	int i,cnt=0;

	if (pt)
		for ( i=0 ; i<counted_max_processes ; i++ )
			if (is_process_running(i))
				cnt++;

	return cnt;
}


int init_multi_proc_support(void)
{
	int i;
	/* at this point we know exactly the possible number of processes, since
	 * all the other modules already adjusted their extra numbers */
	counted_max_processes = count_child_processes();

#ifdef UNIT_TESTS
#include "mem/test/test_malloc.h"
	counted_max_processes += TEST_MALLOC_PROCS - 1;
#endif

	/* allocate the PID table to accomodate the maximum possible number of
	 * process we may have during runtime (covering extra procs created 
	 * due auto-scaling) */
	pt = shm_malloc(sizeof(struct process_table)*counted_max_processes);
	if (pt==0){
		LM_ERR("out of memory\n");
		return -1;
	}
	memset(pt, 0, sizeof(struct process_table)*counted_max_processes);

	for( i=0 ; i<counted_max_processes ; i++ ) {
		/* reset fds to prevent bogus ops */
		pt[i].pid = -1;
		pt[i].pinned_cpu = -1;
		pt[i].ipc_pipe[0] = pt[i].ipc_pipe[1] = -1;
		pt[i].ipc_sync_pipe[0] = pt[i].ipc_sync_pipe[1] = -1;
	}

	/* create the load-related stats (initially marked as hidden */
	/* until the proc starts) */
	if (register_processes_load_stats( counted_max_processes ) != 0) {
		LM_ERR("failed to create load stats\n");
		return -1;
	}

	/* create the IPC pipes for all possible procs */
	if (create_ipc_pipes( counted_max_processes )<0) {
		LM_ERR("failed to create IPC pipes, aborting\n");
		return -1;
	}

	/* create the pkg_mem stats */
	#ifdef PKG_MALLOC
	if (init_pkg_stats(counted_max_processes)!=0) {
		LM_ERR("failed to init stats for pkg\n");
		return -1;
	}
	#endif

	/* set the pid for the starter process */
	set_proc_attrs("starter");

	/* register the stats for the global load */
	if ( register_stat2( "load", "load", (stat_var**)pt_get_rt_load,
	STAT_IS_FUNC, NULL, 0) != 0) {
		LM_ERR("failed to add RT global load stat\n");
		return -1;
	}

	if ( register_stat2( "load", "load1m", (stat_var**)pt_get_1m_load,
	STAT_IS_FUNC, NULL, 0) != 0) {
		LM_ERR("failed to add RT global load stat\n");
		return -1;
	}

	if ( register_stat2( "load", "load10m", (stat_var**)pt_get_10m_load,
	STAT_IS_FUNC, NULL, 0) != 0) {
		LM_ERR("failed to add RT global load stat\n");
		return -1;
	}

	/* register the stats for the extended global load */
	if ( register_stat2( "load", "load-all", (stat_var**)pt_get_rt_loadall,
	STAT_IS_FUNC, NULL, 0) != 0) {
		LM_ERR("failed to add RT global load stat\n");
		return -1;
	}

	if ( register_stat2( "load", "load1m-all", (stat_var**)pt_get_1m_loadall,
	STAT_IS_FUNC, NULL, 0) != 0) {
		LM_ERR("failed to add RT global load stat\n");
		return -1;
	}

	if ( register_stat2( "load", "load10m-all", (stat_var**)pt_get_10m_loadall,
	STAT_IS_FUNC, NULL, 0) != 0) {
		LM_ERR("failed to add RT global load stat\n");
		return -1;
	}

	if ( register_stat2( "load", "processes_number",
	(stat_var**)count_running_processes,
	STAT_IS_FUNC, NULL, 0) != 0) {
		LM_ERR("failed to add processes_number stat\n");
		return -1;
	}

	return 0;
}


void set_proc_attrs(const char *fmt, ...)
{
	va_list ap;

	/* description */
	va_start(ap, fmt);
	vsnprintf( pt[process_no].desc, MAX_PT_DESC, fmt, ap);
	va_end(ap);

	/* pid */
	pt[process_no].pid=getpid();
}


/* Resets all the values in the process table for a given id (a slot) so that
 * it can be reused later 
 * WARNING: this should be called only by main process and when it is 100% 
 *  that the process mapped on this slot is not running anymore */
void reset_process_slot( int p_id )
{
	if (is_main==0) {
		LM_BUG("buggy call from non-main process!!!");
		return;
	}

	/* we cannot simply do a memset here, as we need to preserve the holders
	 * with the inter-process communication fds */
	pt[p_id].pid = -1;
	pt[p_id].pinned_cpu = -1;
	pt[p_id].type = TYPE_NONE;
	pt[p_id].pg_filter = NULL;
	pt[p_id].desc[0] = 0;
	pt[p_id].flags = 0;

	pt[p_id].ipc_pipe[0] = pt[p_id].ipc_pipe[1] = -1;
	pt[p_id].ipc_sync_pipe[0] = pt[p_id].ipc_sync_pipe[1] = -1;

	pt[p_id].log_level = pt[p_id].default_log_level = 0; /*not really needed*/
	pt[p_id].profiling_proc_level = LEVEL_OFF;

	/* purge all load-related data */
	memset( &pt[p_id].load, 0, sizeof(struct proc_load_info));
	/* hide the load stats */
	pt[p_id].load_rt->flags |= STAT_HIDDEN;
	pt[p_id].load_1m->flags |= STAT_HIDDEN;
	pt[p_id].load_10m->flags |= STAT_HIDDEN;
	#ifdef PKG_MALLOC
	pt[p_id].pkg_total->flags |= STAT_HIDDEN;
	pt[p_id].pkg_used->flags |= STAT_HIDDEN;
	pt[p_id].pkg_rused->flags |= STAT_HIDDEN;
	pt[p_id].pkg_mused->flags |= STAT_HIDDEN;
	pt[p_id].pkg_free->flags |= STAT_HIDDEN;
	pt[p_id].pkg_frags->flags |= STAT_HIDDEN;
	#endif
}


enum {CHLD_STARTING, CHLD_OK, CHLD_FAILED};

static __attribute__((__noreturn__)) void child_startup_failed(void)
{
	atomic_store(&pt[process_no].startup_result, CHLD_FAILED);
	exit(1);
}

static int internal_fork_child_setup(const struct internal_fork_params *ifpp)
{
	init_log_level();

	/* free the script if not needed */
	if (!(ifpp->flags & OSS_PROC_NEEDS_SCRIPT) && sroutes) {
		free_route_lists(sroutes);
		sroutes = NULL;
	}
	return 0;
}

/* This function is to be called only by the main process!
 * Returns, on success, the ID (non zero) in the process table of the
 * newly forked procees.
 * */
int internal_fork(const struct internal_fork_params *ifpp)
{
	int new_idx;
	pid_t pid;
	unsigned int seed;

	if (is_main==0) {
		LM_BUG("buggy call from non-main process!!!");
		return -1;
	}

	new_idx = 1; /* start from 1 as 0 (attendent) is always running */
	for( ; new_idx<counted_max_processes ; new_idx++)
		if ( (pt[new_idx].flags&OSS_PROC_IS_RUNNING)==0 ) break;
	if (new_idx==counted_max_processes) {
		LM_BUG("no free process slot found while trying to fork again\n");
		return -1;
	}

	seed = rand();

	LM_DBG("forking new process \"%s\" on slot %d\n", ifpp->proc_desc, new_idx);

	/* set the IPC pipes */
	if ( (ifpp->flags & OSS_PROC_NO_IPC) ) {
		/* advertise no IPC to the rest of the procs */
		pt[new_idx].ipc_pipe[0] = -1;
		pt[new_idx].ipc_pipe[1] = -1;
		pt[new_idx].ipc_sync_pipe[0] = -1;
		pt[new_idx].ipc_sync_pipe[1] = -1;
		/* NOTE: the IPC fds will remain open in the other processes,
		 * but they will not be known */
	} else {
		/* activate the IPC pipes */
		pt[new_idx].ipc_pipe[0]=pt[new_idx].ipc_pipe_holder[0];
		pt[new_idx].ipc_pipe[1]=pt[new_idx].ipc_pipe_holder[1];
		pt[new_idx].ipc_sync_pipe[0]=pt[new_idx].ipc_sync_pipe_holder[0];
		pt[new_idx].ipc_sync_pipe[1]=pt[new_idx].ipc_sync_pipe_holder[1];
	}

	pt[new_idx].pid = 0;

	atomic_init(&pt[new_idx].startup_result, CHLD_STARTING);

	/* decided here, in the parent, while the process table is stable;
	 * a whole-group process gets no single CPU - it is confined to the
	 * full group in the child instead, and must not count as occupying
	 * one slot of it here */
	pt[new_idx].pinned_cpu = ifpp->pin_whole_group ? -1 :
	                         pin_pick_cpu(ifpp->pin_group ?
	                                     ifpp->pin_group : ifpp->type,
	                                     ifpp->sock);

	if ( (pid=fork())<0 ){
		LM_CRIT("cannot fork \"%s\" process (%d: %s)\n",ifpp->proc_desc,
				errno, strerror(errno));
		reset_process_slot( new_idx );
		return -1;
	}

	if (pid==0){
		const struct internal_fork_handler *cfhp;
		/* child process */
		is_main = 0; /* a child is not main process */

		/* Pin BEFORE the allocator reset below: the reset makes this
		 * worker carve fresh chunks on first use, and we want that to
		 * happen once it is already on its final CPU. The CPU itself was
		 * chosen by the parent (pin_pick_cpu) so the decision could see a
		 * consistent view of who is running where. */
		if (ifpp->pin_whole_group)
			pin_apply_group(ifpp->pin_group ? ifpp->pin_group : ifpp->type);
		else
			pin_apply_cpu(pt[new_idx].pinned_cpu);

#ifdef HG_MALLOC
		/*
		 * MUST run before this child allocates anything. HG_MALLOC keeps
		 * its fast-path allocation state (per-size-class bump pointer +
		 * private free stack) in plain process memory, so a fresh child
		 * inherits an identical COPY of the parent's - pointing at the
		 * very same shm cells. Left alone, every worker would hand out
		 * the same cells to different callers.
		 */
		if (mem_allocator_shm == MM_HG_MALLOC ||
		    mem_allocator_shm == MM_HG_MALLOC_DBG) {
			hg_malloc_child_init((struct hg_block *)shm_block);
#ifdef DBG_MALLOC
			if (shm_dbg_block)
				hg_malloc_child_init((struct hg_block *)shm_dbg_block);
#endif
		}
#ifdef PKG_MALLOC
		if (mem_allocator_pkg == MM_HG_MALLOC ||
		    mem_allocator_pkg == MM_HG_MALLOC_DBG)
			hg_malloc_child_init((struct hg_block *)mem_block);
#endif
#endif /* HG_MALLOC */

		/* set uid */
		process_no = new_idx;
		/* set attributes, pid etc */
		set_proc_attrs(ifpp->proc_desc);

		pt[process_no].flags |= ifpp->flags;
		pt[process_no].type = ifpp->type;
		/* activate its load & pkg statistics, but only if IPC present */
		if ( (ifpp->flags & OSS_PROC_NO_IPC)==0 ) {
			pt[process_no].load_rt->flags &= (~STAT_HIDDEN);
			pt[process_no].load_1m->flags &= (~STAT_HIDDEN);
			pt[process_no].load_10m->flags &= (~STAT_HIDDEN);
			#ifdef PKG_MALLOC
			pt[process_no].pkg_total->flags &= (~STAT_HIDDEN);
			pt[process_no].pkg_used->flags &= (~STAT_HIDDEN);
			pt[process_no].pkg_rused->flags &= (~STAT_HIDDEN);
			pt[process_no].pkg_mused->flags &= (~STAT_HIDDEN);
			pt[process_no].pkg_free->flags &= (~STAT_HIDDEN);
			pt[process_no].pkg_frags->flags &= (~STAT_HIDDEN);
			#endif
		}
		/* each children need a unique seed */
		seed_child(seed);

		for (cfhp = _fork_handlers; cfhp != NULL; cfhp = cfhp->_next) {
			if (cfhp->post_fork.in_child == NULL)
				continue;
			if (cfhp->post_fork.in_child(ifpp) != 0) {
				LM_CRIT("failed to run %s for process %d\n", cfhp->desc,
				    process_no);
				child_startup_failed();
			}
		}
		atomic_store(&pt[process_no].startup_result, CHLD_OK);
		return 0;
	}else{
		/* parent process */
		/* wait for the child to complete the critical sectoin of the
		 * start-up */
		while (atomic_load(&pt[new_idx].startup_result) == CHLD_STARTING) {
			int status;
			sched_yield();
			pid_t result = waitpid(pid, &status, WNOHANG);
			if (result < 0) {
				if (errno == EINTR)
					continue;
				goto child_is_down;
			}
			if (result == 0) {
				// Child has not exited yet
				continue;
			}
			// Child has exited, oops
			goto child_is_down;
		}
		if (atomic_load(&pt[new_idx].startup_result) != CHLD_OK) {
			goto child_is_down;
		}
		pt[new_idx].flags |= OSS_PROC_IS_RUNNING;
		return new_idx;
child_is_down:
		LM_CRIT("failed to initialize child process %d\n", new_idx);
		reset_process_slot( new_idx );
		return -1;
	}
}


/* counts the number of processes created by OpenSIPS at startup. processes
 * that also do child_init() (the per-process module init)
 *
 * used for proper status return code
 */
int count_init_child_processes(void)
{
	int ret=0;

	/* listening children to be create at startup */
	ret += udp_count_processes(NULL);
	ret += tcp_count_processes(NULL);
	ret += timer_count_processes(NULL) - 2/*for keeper & trigger*/;

	/* attendent */
	ret++;

	/* count number of module procs going to be initialised */
	ret += count_module_procs(PROC_FLAG_INITCHILD);

	LM_DBG("%d children are going to be inited\n",ret);
	return ret;
}

/* counts the number of processes known by OpenSIPS at startup.
 * Note that the number of processes might change during init, if one of the
 * module decides that it will no longer use a process (ex; rtpproxy timeout
 * process)
 */
int count_child_processes(void)
{
	unsigned int proc_no;
	unsigned int proc_extra_no;
	unsigned int extra;

	proc_no = 0;
	proc_extra_no = 0;

	/* UDP based listeners */
	proc_no += udp_count_processes( &extra );
	proc_extra_no += extra;

	/* TCP based listeners */
	proc_no += tcp_count_processes( &extra );
	proc_extra_no += extra;

	/* Timer related processes */
	proc_no += timer_count_processes( &extra );
	proc_extra_no += extra;

	/* attendent */
	proc_no++;

	/* count the processes requested by modules */
	proc_no += count_module_procs(0);

	return proc_no + proc_extra_no;
}


void dynamic_process_final_exit(void)
{
	/* prevent any more IPC */
	pt[process_no].ipc_pipe[0] = -1;
	pt[process_no].ipc_pipe[1] = -1;
	pt[process_no].ipc_sync_pipe[0] = -1;
	pt[process_no].ipc_sync_pipe[1] = -1;

	/* clear the per-process connection from the DB queues */
	ql_force_process_disconnect(process_no);

	/* if a TCP proc by chance, reset the tcp-related data */
	tcp_reset_worker_slot();

	pt_become_idle();

	/* mark myself as DYNAMIC (just in case) to have an err-less termination */
	pt[process_no].flags |= OSS_PROC_SELFEXIT;
	LM_INFO("doing self termination\n");

	/* the process slot in the proc table will be purge on SIGCHLD by main */
	exit(0);
}

int run_post_fork_handlers(void)
{
	const struct internal_fork_handler *cfhp;

	for (cfhp = _fork_handlers; cfhp != NULL; cfhp = cfhp->_next) {
		if (cfhp->post_fork.in_parent == NULL)
			continue;
		if (cfhp->post_fork.in_parent() != 0) {
			LM_CRIT("failed to run %s for process %d\n", cfhp->desc,
			    process_no);
			return (-1);
		}
	}
	return (0);
}
