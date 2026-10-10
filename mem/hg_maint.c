/*
 * Copyright (C) 2026 Yury Kirsanov
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * The HG_MALLOC maintenance process.
 *
 * Why a process of its own: timer jobs are executed by whichever process
 * reads the timer-job pipe - the Timer handlers AND every UDP/TCP worker
 * (net/net_udp.c, net/net_tcp_proc.c) - so a "proactive" grow run from
 * a timer job populated its granule inside a SIP worker, 20-60 ms of
 * page faults on the data path (measured: the 2 s-tick experiment made
 * the tails worse, not better). With the two-phase commit the populate no
 * longer holds the arena lock, but the worker running it is still parked
 * for its duration. Here it runs in a process that serves no request.
 *
 * What it does, every second under the arena lock for microseconds:
 * the headroom rule (grow one granule ahead whenever the free grid is
 * below twice the reserve floor and the reservation has room), and every
 * thirty ticks - the profile's cycle - the profile gate and the shrink
 * gate. The populate itself (hg_mem_commit inside hg_buddy_grow) runs
 * with the lock released, in this process. While it is alive the sweep
 * timer's copies of those ticks stand down (hb->maint_active), so no
 * worker grows proactively any more; exhaustion growth stays armed in
 * every process as the backstop it always was.
 *
 * Only the shared arena: a pkg arena is private to its process and can
 * only be populated there.
 */

#ifdef HG_MALLOC

#include <unistd.h>
#include <string.h>

#include "../dprint.h"
#include "../globals.h"
#include "../pt.h"
#include "../reactor.h"
#include "../ipc.h"
#include "../daemonize.h"
#include "shm_mem.h"
#include "hg_malloc.h"
#include "hg_buddy.h"
#include "hg_maint.h"

#define HG_MAINT_TICK_MS     1000
/*
 * reactor_main_loop()'s first argument is a timeout in MILLISECONDS since
 * upstream 1968b9ded7 (the same change that added worker_reactor_timeout),
 * so this constant is passed as is. The guard in hg_maint_tick() below
 * is in nanoseconds and needs no unit.
 */
/* the policy cycle (profile gates, shrink decision) is hg_scaling_cycle
 * ticks */

static unsigned long maint_last_ns;
static unsigned int maint_ticks;

/* a shared arena with a cap above its initial size: the shm arena under
 * -a HG_MALLOC with -m INIT:CAP, or any module arena (hg_arena_create) -
 * the registry has them all, and module arenas exist before the process
 * count (modules initialise first) */
static int maint_arena(const struct hg_block *hb)
{
	return hb && hb->shared && hb->buddy_ready &&
	       hb->hcap > hb->committed_min;
}

static int hg_maint_wanted(void)
{
	int i;

	for (i = 0; i < HG_ARENA_REG_MAX; i++)
		if (maint_arena(hg_arena_reg[i].hb))
			return 1;
	return 0;
}

int hg_maint_count_processes(void)
{
	return hg_maint_wanted() ? 1 : 0;
}

static void hg_maint_tick(void)
{
	unsigned long now = hg_now_ns();
	int i, slow;

	/* the reactor returns on every IPC job too; tick once a second */
	if (now - maint_last_ns < (unsigned long)HG_MAINT_TICK_MS * 1000000UL)
		return;
	maint_last_ns = now;
	slow = (++maint_ticks >= (unsigned int)hg_scaling_cycle);
	if (slow)
		maint_ticks = 0;

	for (i = 0; i < HG_ARENA_REG_MAX; i++) {
		struct hg_block *hb = hg_arena_reg[i].hb;

		if (!maint_arena(hb))
			continue;
		hg_lock_enter(hb, HG_LK_POLICY);
		hg_grow_headroom_tick(hb);
		if (slow) {
			hg_grow_tick(hb);
			hg_shrink_tick(hb);
		} else {
			hg_drain_tick(hb);   /* the decision's execution */
		}
		hg_lock_leave(hb);
	}
}

inline static int handle_io(struct fd_map *fm, int idx, int event_type)
{
	switch (fm->type) {
	case F_IPC:
		ipc_handle_job(fm->fd);
		break;
	default:
		LM_CRIT("unknown fd type %d in the HG maintenance process\n",
			fm->type);
		return -1;
	}
	return 0;
}

int hg_maint_start(void)
{
	const struct internal_fork_params ifp = {
		.proc_desc = "HG maintenance",
		.flags = OSS_PROC_NO_LOAD,
		.type = TYPE_NONE,
	};
	int id;

	if (!hg_maint_wanted())
		return 0;

	id = internal_fork(&ifp);
	if (id < 0) {
		LM_CRIT("cannot fork the HG maintenance process\n");
		return -1;
	}
	if (id > 0)
		return 0;                       /* parent */

	/* the child */
	clean_write_pipeend();
	if (init_worker_reactor("HG_maintenance", RCT_PRIO_MAX) < 0) {
		LM_ERR("failed to init the maintenance reactor\n");
		goto error;
	}
	if (reactor_add_reader(IPC_FD_READ_SELF, F_IPC, RCT_PRIO_ASYNC, NULL) < 0) {
		LM_CRIT("failed to add the IPC pipe to the maintenance reactor\n");
		goto error;
	}
	{
		int i;
		char names[256] = "";

		for (i = 0; i < HG_ARENA_REG_MAX; i++) {
			struct hg_block *hb = hg_arena_reg[i].hb;

			if (!maint_arena(hb))
				continue;
			hb->maint_proc = process_no;
			__atomic_store_n(&hb->maint_active, 1, __ATOMIC_RELEASE);
			if (strlen(names) + strlen(hb->name) + 2 < sizeof names) {
				if (*names)
					strcat(names, ",");
				strcat(names, hb->name);
			}
		}
		maint_last_ns = hg_now_ns();
		LM_NOTICE("HG maintenance process started: arena(s) %s grow ahead "
			"of demand here (headroom tick every %d ms, policy every %d "
			"s), the sweep's proactive ticks stand down\n", names,
			HG_MAINT_TICK_MS, hg_scaling_cycle);
	}

	reactor_main_loop(HG_MAINT_TICK_MS, error, hg_maint_tick());
	destroy_worker_reactor();
error:
	LM_ERR("the HG maintenance process failed to initialise, exiting\n");
	{
		int i;

		for (i = 0; i < HG_ARENA_REG_MAX; i++)
			if (maint_arena(hg_arena_reg[i].hb))
				__atomic_store_n(&hg_arena_reg[i].hb->maint_active, 0,
					__ATOMIC_RELEASE);
	}
	exit(-1);
}

#endif /* HG_MALLOC */
