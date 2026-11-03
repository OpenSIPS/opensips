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
#include "hg_memlimit.h"
#include "../dprint.h"
#include "../globals.h"
#include "hg_buddy_int.h"

/* a RESOURCE refusal (the host, not the admin, said no): count it and run
 * the two-step latch */
static int grow_resource_refused(struct hg_block *hb)
{
	hb->grow_refused++;

	if (hb->grow_blocked)
		return -1;

	if (!hb->grow_blocked_mark) {
		/* the mark doubles as the "armed" flag: gc_passes + 1 is
		 * never 0, and is what gc_passes reaches after one GC pass */
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

/* called without hb->lock: takes it per page, within HG_COLLAPSE_BUDGET_NS */
#define HG_COLLAPSE_BUDGET_NS	(100UL * 1000000UL)

void hg_collapse_deferred(struct hg_block *hb)
{
	hg_ns_t start = hg_now_ns();
	unsigned long i;
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

/* while hb->lock is dropped, grow_inflight keeps other grows, trims and
 * punches out */
static int buddy_grow_body(struct hg_block *hb, unsigned long need, enum hg_grow_why why)
{
	unsigned long delta, room, old_pages, i, limit, off, commit_ns;
	hg_ns_t t0;
	unsigned long cp_ns[HG_CP_PHASES];
	int tier, reason, later;
	struct hg_room_short rs;

	if (!hb->buddy_ready)
		return -1;

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

	/* another grow is in flight: wait for its publish WITHOUT the lock and
	 * report "grew", so the caller retries its carve on the new pages */
	if (hb->grow_inflight) {
		unsigned long gen = hb->grow_gen, waited = 0;

		hb->grow_waits++;
		reason = hb->lk_cur;
		t0 = hg_now_ns();
		/* the token can be re-taken between poll and relock: not a
		 * timeout, keep waiting till it is clear UNDER the lock */
		do {
			hg_lock_leave(hb);
			do {
				usleep(HG_GROW_WAIT_SLICE_US);
				waited = hg_ns_ul(hg_now_ns() - t0);
			} while (__atomic_load_n(&hb->grow_inflight, __ATOMIC_ACQUIRE) &&
			         waited < HG_GROW_WAIT_MAX_NS);
			hg_lock_enter(hb, (enum hg_lock_reason)reason);
			if (hb->grow_gen != gen) {
				hg_lkstat_add(&hb->lk_grow_wait, waited);
				return 0;
			}
		} while (hb->grow_inflight && waited < HG_GROW_WAIT_MAX_NS);
		hg_lkstat_add(&hb->lk_grow_wait, waited);
		if (hb->grow_inflight) {
			hb->grow_wait_timeouts++;
			hb->grow_refused++;
			hb->grow_refuse_why = HG_GR_WAIT_TIMEOUT;
			return -1;
		}
	}

	limit = (hb->pol.active && hb->pol.up_bytes) ? hb->pol.up_bytes
	                                             : hb->hcap;
	/* committed bytes: the ceiling bounds what is backed, not the span */
	room = limit > hb->committed_bytes ? limit - hb->committed_bytes : 0;
	if (room == 0) {
		hb->grow_refused++;
		hb->grow_refuse_why = limit == hb->hcap ? HG_GR_CAP
		                                        : HG_GR_PROFILE;
		/* an arena with no cap (grows == 0) stays silent here */
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
			return 0;
		if (r < 0)
			return -1;
	}

	delta = hb->grow_granule;
	if (need > delta)
		delta = (need + hb->grow_granule - 1) /
		        hb->grow_granule * hb->grow_granule;
	if (delta > room)
		delta = room;

	/* phase 1 - RESERVE under the lock */
	off = hb->span_end;
	hb->grow_inflight = 1;
	backed_fast_update(hb);
	hb->span_pending = off + delta;
	reason = hb->lk_cur;
	hg_lock_leave(hb);

	/* phase 2 - unlocked: the host-RAM check, then POPULATE */
	if (hg_grow_room_short(hb, delta, &rs)) {
		hg_lock_enter(hb, (enum hg_lock_reason)reason);
		hb->span_pending = hb->span_end;
		__atomic_store_n(&hb->grow_inflight, 0, __ATOMIC_RELEASE);
		hg_grow_room_refused(hb, &rs);
		return grow_resource_refused(hb);
	}
	t0 = hg_now_ns();
	later = 0;
	tier = hg_mem_commit(hb, off, delta, cp_ns,
		(why == HG_GROW_EXHAUSTION && hb->shared &&
		 __atomic_load_n(&hb->maint_active, __ATOMIC_ACQUIRE)) ?
		&later : NULL);
	commit_ns = hg_ns_ul(hg_now_ns() - t0);

	/* phase 3 - PUBLISH under the lock */
	hg_lock_enter(hb, (enum hg_lock_reason)reason);
	hg_lkstat_add(&hb->lk_commit, commit_ns);
	for (i = 0; i < HG_CP_PHASES; i++)
		if (cp_ns[i])
			hg_lkstat_add(&hb->lk_cphase[i], cp_ns[i]);
	__atomic_store_n(&hb->grow_inflight, 0, __ATOMIC_RELEASE);
	if (tier < 0) {
		hb->span_pending = hb->span_end;
		return grow_resource_refused(hb);
	}

	hb->tier_bytes[tier] += delta;
	/* hb->size feeds free_to_carve (size - real_used), which underflows if
	 * size lags; cache budget and chunk_max keep their init values */
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

	floor_recompute(hb);

	hb->grows++;
	hb->grow_gen++;
	hb->grow_bytes += delta;
	if (why == HG_GROW_PROACTIVE)
		hb->grows_proactive++;
	else
		hb->grows_exhaustion++;
	hb->shrink_quiet = 0;
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
	backed_fast_update(hb);
	hg_lock_assert_held(hb, "hg_buddy_grow_unlocks return");
	return r;
}

/* re-commit punched holes: 1 served, 0 no hole fits, -1 refused */
static int buddy_regrow_holes_body(struct hg_block *hb, unsigned long need,
                                   unsigned long room)
{
	unsigned long sel[HG_PAGES_PER_EVENT];
	unsigned long want, i, got = 0, ok, pin_ns;
	hg_ns_t t0;
	unsigned long lpp = hg_leaves_per_page(hb);
	unsigned int top = hb->buddy_top;
	int reason;
	struct hg_room_short rs;

	if (!hb->punched_pages)
		return 0;

	/* a granule or the request, whichever is more: one round trip, not one
	 * per page */
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

	/* phase 1 - select, lowest first */
	for (i = 0; i < hb->npages && got < want; i++)
		if (hb->pages[i].punched && !hb->pages[i].releasing)
			sel[got++] = i;
	hb->grow_inflight = 1;
	backed_fast_update(hb);
	reason = hb->lk_cur;
	hg_lock_leave(hb);

	/* nothing is off a list yet: a refusal only gives the token back */
	if (hg_grow_room_short(hb, got << hb->hps_shift, &rs)) {
		hg_lock_enter(hb, (enum hg_lock_reason)reason);
		__atomic_store_n(&hb->grow_inflight, 0, __ATOMIC_RELEASE);
		hg_grow_room_refused(hb, &rs);
		return grow_resource_refused(hb);
	}

	/* phase 2 - pin, lock released; on hugetlb a hole's pages went back to
	 * the pool, so this can fail and leave holes */
	t0 = hg_now_ns();
	for (i = 0, ok = 0; i < got; i++) {
		struct hg_page *pg = &hb->pages[sel[i]];

		if (hg_mem_repin(hb, (unsigned long)(pg->base - hb->hbase),
		                 hb->hps, pg->tier) == 0 ||
		    pg->tier != HG_MEM_HUGETLB)
			sel[ok++] = sel[i];
	}
	got = ok;
	pin_ns = hg_ns_ul(hg_now_ns() - t0);

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
	/* last, with release semantics, as in a span grow */
	__atomic_store_n(&hb->committed_bytes,
	                 hb->committed_bytes + (got << hb->hps_shift),
	                 __ATOMIC_RELEASE);
	__atomic_store_n(&hb->grow_inflight, 0, __ATOMIC_RELEASE);
	hb->repins += got;
	hb->repin_bytes += got << hb->hps_shift;
	hb->hole_regrows++;
	hb->grow_gen++;
	floor_recompute(hb);
	hb->shrink_quiet = 0;
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
	backed_fast_update(hb);
	hg_lock_assert_held(hb, "hg_buddy_regrow_holes_unlocks return");
	return r;
}

/* under twice the floor free, every sweep would flush the caches */
static int grow_headroom_tick_body(struct hg_block *hb)
{
	if (!hb->buddy_ready || !hg_grow_ahead)
		return 0;
	/* committed, not the span: with holes punched at the ceiling the span
	 * is full, and the grow re-commits them first */
	if (hb->committed_bytes < hb->hcap && !hb->grow_inflight &&
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
		return;

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
