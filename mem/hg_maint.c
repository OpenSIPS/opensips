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
#include "hg_arena.h"
#include "hg_buddy.h"
#include "hg_maint.h"

#define HG_MAINT_TICK_MS     1000

static hg_ns_t maint_last_ns;
static unsigned int maint_ticks;

/* module arenas count too: they exist before the process count, as modules
 * init first */
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
	hg_ns_t now = hg_now_ns();
	int i, slow;

	/* the reactor returns on every IPC job too; tick once a second */
	if (now - maint_last_ns < (hg_ns_t)HG_MAINT_TICK_MS * 1000000ULL)
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
		hg_gc_tick(hb, HG_GC_TICK_BUDGET);
		if (slow) {
			hg_gc_cycle(hb);
			hg_grow_tick(hb);
			hg_shrink_tick(hb);
		} else {
			hg_drain_tick(hb);
		}
		hg_lock_leave(hb);
		hg_collapse_deferred(hb);
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
		return 0;

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
