/*
 * buddy allocator over the HG_MALLOC page grid - growth
 *
 * Copyright (C) 2026 Yury Kirsanov
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

#ifdef HG_MALLOC

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "hg_version.h"
#include "hg_malloc.h"
#include "hg_buddy.h"
#include "hg_arena.h"
#include "../dprint.h"
#include "../globals.h"
#include "hg_buddy_int.h"

/* --- grow ------------------------------------------------------------- */

/*
 * A RESOURCE refusal - the host, not the admin, said no: count it and run the
 * two-step latch (see grow_blocked's declaration). The event is raised by the
 * sweep timer via grow_event_due, never here under hb->lock.
 */
static int grow_resource_refused(struct hg_block *hb)
{
	hb->grow_refused++;

	if (hb->grow_blocked)
		return -1;

	if (!hb->grow_blocked_mark) {
		/* the mark doubles as the "armed" flag: gc_passes + 1
		 * is never 0, and is the count gc_passes reaches once a
		 * GC pass has run */
		hb->grow_blocked_mark = hb->gc_passes + 1;
		hb->grow_blocked_refuse0 = hb->grow_refused;
	} else if (hb->gc_passes >= hb->grow_blocked_mark) {
		hb->grow_blocked = 1;
		hb->grow_event_due = 1;
		LM_WARN("%s: GROW-BLOCKED latched - the arena cannot grow and "
			"a GC pass did not change that (%lu refusals so far). "
			"Alert on %s; details precede this line.\n", hb->name,
			hb->grow_refused, hb->shared ? "hg_shm_grow_blocked" :
			"hg_pkg_grow_blocked");
	}
	return -1;
}

/* end the episode, if any, and re-arm the once-per-episode messages */
void hg_grow_unblock(struct hg_block *hb, const char *how)
{
	if (hb->grow_blocked)
		LM_NOTICE("%s: GROW-BLOCKED cleared - %s\n", hb->name, how);
	hb->grow_blocked = 0;
	hb->grow_blocked_mark = 0;
	hb->grow_blocked_refuse0 = 0;
	hb->grow_event_due = 0;
	hb->grow_refuse_said = 0;
	hb->grow_refuse_mlock = 0;
}

/*
 * The sweep timer's half of the latch (see grow_blocked_refuse0), once per
 * sweep interval with hb->lock held.
 */
void hg_grow_blocked_tick(struct hg_block *hb)
{
	if (hb->grow_blocked || !hb->grow_blocked_mark)
		return;
	if (hb->grow_refused > hb->grow_blocked_refuse0) {
		hb->grow_blocked = 1;
		hb->grow_event_due = 1;
		LM_WARN("%s: GROW-BLOCKED latched - the arena cannot grow and "
			"a full sweep interval did not change that (%lu refusals "
			"so far). Alert on %s; details precede this line.\n",
			hb->name, hb->grow_refused,
			hb->shared ? "hg_shm_grow_blocked" : "hg_pkg_grow_blocked");
	} else {
		/* armed but quiet for a whole interval: the spike passed */
		hb->grow_blocked_mark = 0;
		hb->grow_blocked_refuse0 = 0;
	}
}

/* how long an exhausted worker waits, lock released, for a grow another worker
 * has in flight; past it the request is refused and counted */
#define HG_GROW_WAIT_MAX_NS  2000000000UL
#define HG_GROW_WAIT_SLICE_US 100

static int hg_buddy_regrow_holes_unlocks(struct hg_block *hb, unsigned long need,
                                         unsigned long room);

/*
 * Deferred collapse. A worker's exhaustion grow publishes a delta that did not
 * fault in huge on 4 KB pages, flagged want_collapse (hg_mem_commit()), so the
 * worker does not wait for the MADV_COLLAPSE retrofit. The maintenance process
 * calls this every tick: at most one pass over the pages, each flagged page
 * collapsed with the arena lock released, until HG_COLLAPSE_BUDGET_NS is
 * spent. Failures are usually transient (a page just faulted cannot be
 * isolated yet), so a page gets HG_COLLAPSE_TRIES attempts over later ticks
 * before it is left on 4 KB. Pages are only released by this same process, so
 * a page picked here cannot be released under it; the flag is re-checked
 * once the lock is back all the same.
 */
#define HG_COLLAPSE_BUDGET_NS	(100UL * 1000000UL)

void hg_collapse_deferred(struct hg_block *hb)
{
	unsigned long start = hg_now_ns(), i;
	struct hg_page *pg;
	int rc;

	if (!__atomic_load_n(&hb->collapse_pending, __ATOMIC_ACQUIRE))
		return;
	while (hg_now_ns() - start < HG_COLLAPSE_BUDGET_NS) {
		hg_lock_enter(hb, HG_LK_POLICY);
		pg = NULL;
		for (i = hb->collapse_scan; i < hb->npages; i++)
			if (hb->pages[i].want_collapse && !hb->pages[i].releasing &&
			    !hb->pages[i].punched) {
				pg = &hb->pages[i];
				break;
			}
		if (!pg) {
			/* end of this tick's pass; the next tick starts over */
			hb->collapse_scan = 0;
			if (!hb->collapse_wanting)
				hb->collapse_pending = 0;
			hg_lock_leave(hb);
			return;
		}
		hb->collapse_scan = i + 1;
		hg_lock_leave(hb);

		rc = hg_mem_collapse(hb, pg->base, hb->hps);

		hg_lock_enter(hb, HG_LK_POLICY);
		if (!pg->want_collapse) {
			/* released meanwhile: not counted either way */
		} else if (rc > 0) {
			if (pg->tier == HG_MEM_4K) {
				if (hb->tier_bytes[HG_MEM_4K] >= hb->hps)
					hb->tier_bytes[HG_MEM_4K] -= hb->hps;
				hb->tier_bytes[HG_MEM_THP_COLLAPSE] += hb->hps;
				pg->tier = HG_MEM_THP_COLLAPSE;
			}
			pg->want_collapse = 0;
			hb->collapse_wanting--;
			hb->collapsed_late++;
		} else if (rc < 0 && --pg->want_collapse) {
			hb->collapse_retries++;
			if (!hb->collapse_fail_said) {
				hb->collapse_fail_said = 1;
				LM_INFO("%s: deferred collapse of a 2 MB page failed (%s) "
					"- retrying it on later ticks\n", hb->name,
					strerror(-rc));
			}
		} else {
			/* tries used up, or the host forbids collapse now */
			pg->want_collapse = 0;
			hb->collapse_wanting--;
			hb->collapse_late_failed++;
			LM_NOTICE("%s: a 2 MB page stays on 4 KB pages - %s\n",
				hb->name, rc < 0 ? strerror(-rc) :
				"the host no longer allows collapse");
		}
		hg_lock_leave(hb);
	}
}

/*
 * Grow in three phases: RESERVE the range under hb->lock, POPULATE it with
 * hg_mem_commit() with the lock released (faulting, pinning and verifying the
 * backing are slow and must not stall the arena), PUBLISH under the lock.
 * grow_inflight keeps every other grow, trim and punch out meanwhile. Reached
 * on buddy exhaustion (carve_chunk, the large tier) and from the proactive
 * ticks, never on the fast path.
 */
static int buddy_grow_body(struct hg_block *hb, unsigned long need, enum hg_grow_why why)
{
	unsigned long delta, room, old_pages, i, limit, t0, off, commit_ns;
	unsigned long cp_ns[HG_CP_PHASES];
	int tier, reason, later;

	if (!hb->buddy_ready)
		return -1;

	/* advise-only mode: report what growth WOULD have done, act never -
	 * the arena behaves exactly like a fixed one, with evidence */
	if (hg_autoscale_dry_run) {
		hb->grow_refused++;
		hb->grow_refuse_why = HG_GR_DRY_RUN;
		if (!hb->pol_dry_said) {
			hb->pol_dry_said = 1;
			LM_WARN("%s: DRY RUN - would grow for a %lu byte request "
				"(committed %lu MB); counting further suppressed "
				"grows in hg_shm_grow_refused\n",
				hb->name, need, hb->committed_bytes >> 20);
		}
		return -1;
	}

	/*
	 * Another grow is in flight: wait for its publish WITHOUT the lock and
	 * report "grew", so the caller retries its carve on the new pages.
	 */
	if (hb->grow_inflight) {
		unsigned long gen = hb->grow_gen, waited = 0;

		hb->grow_waits++;
		reason = hb->lk_cur;
		t0 = hg_now_ns();
		/*
		 * The token can be re-taken between the poll seeing it
		 * clear and the lock coming back (a grow after a refused
		 * one, the drain's punch after its trim). That is no
		 * timeout: keep waiting, within the same budget, until it
		 * is clear UNDER the lock.
		 */
		do {
			hg_lock_leave(hb);
			do {
				usleep(HG_GROW_WAIT_SLICE_US);
				waited = hg_now_ns() - t0;
			} while (__atomic_load_n(&hb->grow_inflight, __ATOMIC_ACQUIRE) &&
			         waited < HG_GROW_WAIT_MAX_NS);
			hg_lock_enter(hb, (enum hg_lock_reason)reason);
			/* a grow or a hole re-grow published pages: retry the
			 * carve. A trim or a punch also holds the token; after
			 * one of those, try this caller's own grow below */
			if (hb->grow_gen != gen) {
				hg_lkstat_add(&hb->lk_grow_wait, waited);
				return 0;
			}
		} while (hb->grow_inflight && waited < HG_GROW_WAIT_MAX_NS);
		hg_lkstat_add(&hb->lk_grow_wait, waited);
		if (hb->grow_inflight) {
			hb->grow_wait_timeouts++; /* still populating - give up */
			hb->grow_refused++;
			hb->grow_refuse_why = HG_GR_WAIT_TIMEOUT;
			return -1;
		}
		/* the in-flight operation went away; fall through and grow */
	}

	/* the ceiling: the profile's scale-up target (within the -m INIT:CAP
	 * reservation), else the reservation */
	limit = (hb->pol.active && hb->pol.up_bytes) ? hb->pol.up_bytes
	                                             : hb->hcap;
	/* room is counted in committed bytes: the ceiling bounds what is
	 * backed, not the span. Holes are refilled first (below); an append
	 * past the reservation is refused by hg_mem_commit() */
	room = limit > hb->committed_bytes ? limit - hb->committed_bytes : 0;
	if (room == 0) {
		hb->grow_refused++;
		hb->grow_refuse_why = limit == hb->hcap ? HG_GR_CAP
		                                        : HG_GR_PROFILE;
		/* a ceiling doing its job is a notice, not an alarm; an arena
		 * with no cap lives here silently. grows > 0 tells them apart:
		 * a growable arena reaches room == 0 only by growing. Once per
		 * episode; grow_refused counts. */
		if (hb->grows && !hb->grow_refuse_said) {
			hb->grow_refuse_said = 1;
			LM_NOTICE("%s: at the %lu MB growth ceiling (%s), "
				"a %lu byte request must fail - counting further "
				"refusals in hg_shm_grow_refused\n",
				hb->name, limit >> 20,
				limit == hb->hcap ? "the -m/-M reservation"
				                  : "the profile scale-up target",
				need);
		}
		return -1;
	}

	/* holes first: re-committing one costs a pin and no new span, and
	 * keeps a punched arena from growing past its own free space */
	{
		int r = hg_buddy_regrow_holes_unlocks(hb, need, room);

		if (r > 0)
			return 0;       /* served: the caller retries */
		if (r < 0)
			return -1;           /* the RAM limb refused */
	}

	delta = hb->grow_granule;
	if (need > delta)
		delta = (need + hb->grow_granule - 1) /
		        hb->grow_granule * hb->grow_granule;
	if (delta > room)
		delta = room;

	/* the host-RAM limb of the ceiling, before any work is done */
	if (hg_grow_ram_refused(hb, delta))
		return grow_resource_refused(hb);

	/* phase 1 - RESERVE the range under the lock, taking grow_inflight */
	off = hb->span_end;
	hb->grow_inflight = 1;
	hb->span_pending = off + delta;
	reason = hb->lk_cur;
	hg_lock_leave(hb);

	/* phase 2 - POPULATE with the lock released */
	t0 = hg_now_ns();
	later = 0;
	tier = hg_mem_commit(hb, off, delta, cp_ns,
		(why == HG_GROW_EXHAUSTION && hb->shared &&
		 __atomic_load_n(&hb->maint_active, __ATOMIC_ACQUIRE)) ?
		&later : NULL);
	commit_ns = hg_now_ns() - t0;

	/* phase 3 - PUBLISH under the lock */
	hg_lock_enter(hb, (enum hg_lock_reason)reason);
	hg_lkstat_add(&hb->lk_commit, commit_ns);
	for (i = 0; i < HG_CP_PHASES; i++)
		if (cp_ns[i])
			hg_lkstat_add(&hb->lk_cphase[i], cp_ns[i]);
	__atomic_store_n(&hb->grow_inflight, 0, __ATOMIC_RELEASE);
	if (tier < 0) {
		/* the commit rolled itself back; give the reservation back */
		hb->span_pending = hb->span_end;
		return grow_resource_refused(hb);
	}

	hb->tier_bytes[tier] += delta;
	/* hb->size feeds every "total/free" report and free_to_carve
	 * (size - real_used), which underflows if size lags. The per-thread
	 * cache budget and chunk_max keep their init values, so the cell
	 * caches do not change behaviour mid-flight. */
	hb->size += delta;
	old_pages = hb->npages;
	hb->npages = (unsigned long)(hb->hbase + off + delta - hb->pbase)
	             >> hb->hps_shift;

	for (i = old_pages; i < hb->npages; i++) {
		hb->pages[i].tier = (unsigned char)tier;
		hb->pages[i].want_collapse = later ? HG_COLLAPSE_TRIES : 0;
		page_publish_whole(hb, &hb->pages[i]);
	}
	if (later) {
		hb->collapse_deferred += hb->npages - old_pages;
		hb->collapse_wanting += hb->npages - old_pages;
		__atomic_store_n(&hb->collapse_pending, 1, __ATOMIC_RELEASE);
	}
	/* the published sizes move last, with release semantics: nothing that
	 * reads them lock-free may see the new figure before the pages exist */
	__atomic_store_n(&hb->span_end, off + delta, __ATOMIC_RELEASE);
	__atomic_store_n(&hb->committed_bytes, hb->committed_bytes + delta,
	                 __ATOMIC_RELEASE);
	hb->span_pending = hb->span_end;
	span_check(hb, "a grow");

	/* keep the floor at 1/16 of the grid it now guards */
	floor_recompute(hb);

	hb->grows++;
	hb->grow_gen++;
	hb->grow_bytes += delta;
	if (why == HG_GROW_PROACTIVE)
		hb->grows_proactive++;
	else
		hb->grows_exhaustion++;
	hb->shrink_quiet = 0;    /* fresh demand voids any quiet window */
	hb->draining = 0;
	hb->pol_cooldown = hb->pol.active ? hb->pol.cooldown : 0;
	hb->pol_dry_said = 0;
	hg_grow_unblock(hb, "the arena grew, the resource came back");

	LM_NOTICE("%s arena grew %s by %lu MB to %lu MB (%lu new pages on %s; "
		"commit %lu us with the lock released; %lu MB headroom left)\n",
		hb->name, why == HG_GROW_PROACTIVE ? "proactively" : "on exhaustion",
		delta >> 20, hb->committed_bytes >> 20, hb->npages - old_pages,
		hg_mem_tier_str((enum hg_mem_tier)tier),
		commit_ns / 1000, (hb->hcap - hb->committed_bytes) >> 20);
	return 0;
}

int hg_buddy_grow_unlocks(struct hg_block *hb, unsigned long need, enum hg_grow_why why)
{
	int r;

	hg_lock_assert_held(hb, "hg_buddy_grow_unlocks entry");
	r = buddy_grow_body(hb, need, why);
	hg_lock_assert_held(hb, "hg_buddy_grow_unlocks return");
	return r;
}

/*
 * Re-commit holes, from hg_buddy_grow_unlocks() before it extends the span. A
 * hole is faulted back in AND re-pinned in THIS process before it can be
 * carved again: mlock() is per-vma and does not survive fork. Phases as in the
 * grow: select under hb->lock (holes are off the free list, so no carve
 * reaches them; grow_inflight keeps trim and punch out), pin with the lock
 * released, publish under it. Returns 1 if it served the request, 0 if no hole
 * could serve it, -1 if the RAM limb or every re-pin refused.
 */
static int buddy_regrow_holes_body(struct hg_block *hb, unsigned long need,
                                   unsigned long room)
{
	unsigned long sel[HG_PAGES_PER_EVENT];
	unsigned long want, i, got = 0, ok, t0, pin_ns;
	unsigned long lpp = hg_leaves_per_page(hb);
	unsigned int top = hb->buddy_top;
	int reason;

	if (!hb->punched_pages)
		return 0;

	/* at least a granule, like a span grow, and at least what the
	 * request needs - one round trip, not one per page */
	want = (need + hb->hps - 1) >> hb->hps_shift;
	if (want < hb->grow_granule >> hb->hps_shift)
		want = hb->grow_granule >> hb->hps_shift;
	if (want < 1)
		want = 1;
	if (want > hb->punched_pages)
		want = hb->punched_pages;
	if (want > room >> hb->hps_shift)
		want = room >> hb->hps_shift;
	if (want > HG_PAGES_PER_EVENT)
		want = HG_PAGES_PER_EVENT;
	if (!want)
		return 0;
	if (hg_grow_ram_refused(hb, want << hb->hps_shift))
		return grow_resource_refused(hb);

	/* phase 1 - select, lowest first */
	for (i = 0; i < hb->npages && got < want; i++)
		if (hb->pages[i].punched && !hb->pages[i].releasing)
			sel[got++] = i;
	hb->grow_inflight = 1;
	reason = hb->lk_cur;
	hg_lock_leave(hb);

	/* phase 2 - pin, in this process, lock released. On hugetlb a hole's
	 * pages went back to the pool for anyone to take, so the re-commit can
	 * fail and those pages stay holes. The other tiers populate even when
	 * they cannot pin (hg_mem_repin() counts that). */
	t0 = hg_now_ns();
	for (i = 0, ok = 0; i < got; i++) {
		struct hg_page *pg = &hb->pages[sel[i]];

		if (hg_mem_repin(hb, (unsigned long)(pg->base - hb->hbase),
		                 hb->hps, pg->tier) == 0 ||
		    pg->tier != HG_MEM_HUGETLB)
			sel[ok++] = sel[i];
	}
	got = ok;
	pin_ns = hg_now_ns() - t0;

	/* phase 3 - publish what came back */
	hg_lock_enter(hb, (enum hg_lock_reason)reason);
	hg_lkstat_add(&hb->lk_commit, pin_ns);
	if (!got) {
		__atomic_store_n(&hb->grow_inflight, 0, __ATOMIC_RELEASE);
		hb->grow_refuse_why = HG_GR_HOLE_REPIN;
		return grow_resource_refused(hb);
	}
	for (i = 0; i < got; i++) {
		struct hg_page *pg = &hb->pages[sel[i]];

		pg->punched = 0;
		fl_push(hb, pg->base, top);
		hb->buddy_free_leaves += lpp;
		hb->tier_bytes[pg->tier] += hb->hps;
		if (hb->punched_pages)
			hb->punched_pages--;
	}
	/* the count moves last, with release semantics: a waiter polling it
	 * lock-free must not see it before the pages are back on the list */
	__atomic_store_n(&hb->committed_bytes,
	                 hb->committed_bytes + (got << hb->hps_shift),
	                 __ATOMIC_RELEASE);
	__atomic_store_n(&hb->grow_inflight, 0, __ATOMIC_RELEASE);
	hb->repins += got;
	hb->repin_bytes += got << hb->hps_shift;
	hb->hole_regrows++;
	hb->grow_gen++;
	floor_recompute(hb);
	hb->shrink_quiet = 0;    /* fresh demand voids any quiet window */
	hb->draining = 0;
	hb->pol_cooldown = hb->pol.active ? hb->pol.cooldown : 0;
	span_check(hb, "a re-commit");

	LM_NOTICE("%s arena re-committed %lu hole%s (%lu MB) instead of "
		"growing the span; pin %lu us with the lock released; %lu MB "
		"committed of a %lu MB span, %lu hole%s left\n", hb->name, got,
		got == 1 ? "" : "s", (got << hb->hps_shift) >> 20,
		pin_ns / 1000, hb->committed_bytes >> 20, hb->span_end >> 20,
		hb->punched_pages, hb->punched_pages == 1 ? "" : "s");
	return 1;
}

static int hg_buddy_regrow_holes_unlocks(struct hg_block *hb, unsigned long need,
                                         unsigned long room)
{
	int r;

	hg_lock_assert_held(hb, "hg_buddy_regrow_holes_unlocks entry");
	r = buddy_regrow_holes_body(hb, need, room);
	hg_lock_assert_held(hb, "hg_buddy_regrow_holes_unlocks return");
	return r;
}

/*
 * The always-on headroom rule, profile or not: keep the free grid above twice
 * the floor while the reservation allows, so the arena does not sit at its
 * floor flushing caches every sweep. Ticked every second by the maintenance
 * process, else once per sweep interval. Returns 1 if it grew.
 */
static int grow_headroom_tick_body(struct hg_block *hb)
{
	if (!hb->buddy_ready || !hg_grow_ahead)
		return 0;
	if (hb->span_end < hb->hcap && !hb->grow_inflight &&
	    hb->buddy_free_leaves < 2 * hb->reserve_floor)
		return hg_buddy_grow_unlocks(hb, hb->grow_granule, HG_GROW_PROACTIVE) == 0;
	return 0;
}

int hg_grow_headroom_tick(struct hg_block *hb)
{
	int r;

	hg_lock_assert_held(hb, "hg_grow_headroom_tick entry");
	r = grow_headroom_tick_body(hb);
	hg_lock_assert_held(hb, "hg_grow_headroom_tick return");
	return r;
}

/*
 * The profile's proactive grow: grow BEFORE exhaustion when usage crossed the
 * up-threshold often enough. Same call sites and lock contract as
 * hg_shrink_tick(). Exhaustion growth stays armed with a profile too: a burst
 * between ticks must not fail allocations.
 */
static void grow_tick_body(struct hg_block *hb)
{
	int hit;

	if (!hb->buddy_ready)
		return;
	if (!hb->maint_active && hg_grow_headroom_tick(hb))
		return;
	if (!hb->pol.active)
		return;
	if (hb->committed_bytes >= hb->pol.up_bytes)
		return;                          /* at the profile ceiling */

	hb->pol_up_ticks++;
	if (hg_get_real_used(hb) * 100 >=
	    (unsigned long)hb->pol.up_pct * hb->committed_bytes)
		hb->pol_up_hits++;

	if (hb->pol_up_ticks <
	    (hb->pol.up_window ? hb->pol.up_window : 1))
		return;
	hit = hb->pol_up_hits >= (hb->pol.up_need ? hb->pol.up_need : 1);
	hb->pol_up_ticks = 0;
	hb->pol_up_hits = 0;
	if (!hit)
		return;

	if (hg_autoscale_dry_run) {
		if (!hb->pol_dry_said) {
			hb->pol_dry_said = 1;
			LM_NOTICE("%s: DRY RUN - would grow (committed %lu MB, "
				"usage %lu%%, profile ceiling %lu MB)\n",
				hb->name, hb->committed_bytes >> 20,
				hg_get_real_used(hb) * 100 /
				hb->committed_bytes,
				hb->pol.up_bytes >> 20);
		}
		return;
	}
	hg_buddy_grow_unlocks(hb, hb->grow_granule, HG_GROW_PROACTIVE);
}

void hg_grow_tick(struct hg_block *hb)
{
	hg_lock_assert_held(hb, "hg_grow_tick entry");
	grow_tick_body(hb);
	hg_lock_assert_held(hb, "hg_grow_tick return");
}
#endif /* HG_MALLOC */
