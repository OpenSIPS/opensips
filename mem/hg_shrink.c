/*
 * buddy allocator over the HG_MALLOC page grid - trim, punch and drain
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

/* Trim: release whole-free pages from the TOP of the span; returns how many */
static unsigned long buddy_shrink_body(struct hg_block *hb)
{
	unsigned long lpp = hg_leaves_per_page(hb);
	unsigned long limit = hb->shrink_step >> hb->hps_shift;
	unsigned long n = 0, i, off, len, backed = 0, rel_ns;
	hg_ns_t t0;
	unsigned int top = hb->buddy_top;
	int reason, rc;

	/* only still-backed pages count against committed_min: a punched
	 * page's bytes left committed_bytes at the punch */
	while (n < limit) {
		struct hg_page *pg = &hb->pages[hb->npages - 1 - n];
		unsigned long cost = pg->punched ? 0 : hb->hps;
		unsigned long bpages = (backed + cost) >> hb->hps_shift;
		unsigned long floor_after, free_after;

		if (pg->releasing || !page_is_whole_free(hb, pg))
			break;
		if (hb->committed_bytes - backed < hb->committed_min + cost)
			break;
		/* stay above the headroom line (free >= 2x the floor after this
		 * page), or the next tick regrows what this one released */
		if (hb->buddy_free_leaves < bpages * lpp)
			break;
		free_after = hb->buddy_free_leaves - bpages * lpp;
		floor_after = ((hb->npages - hb->punched_pages - bpages) * lpp)
		              / 16;
		if (free_after < 2 * floor_after)
			break;
		backed += cost;
		n++;
	}
	if (!n)
		return 0;

	len = n << hb->hps_shift;
	off = (unsigned long)(hb->pages[hb->npages - n].base - hb->hbase);
	if (off + len != hb->span_end) {
		/* the grid does not end at the span end (an unaligned
		 * non-Linux base): decline rather than approximate */
		return 0;
	}

	/* phase 1 - off the free set under the lock, out of every carve's
	 * reach; a punched page is already off */
	for (i = hb->npages - n; i < hb->npages; i++) {
		struct hg_page *pg = &hb->pages[i];

		if (!pg->punched)
			fl_unlink(hb, pg->base, top);
		pg->releasing = 1;
	}
	hb->grow_inflight = 1;
	backed_fast_update(hb);
	reason = hb->lk_cur;
	hg_lock_leave(hb);

	/* phase 2 - the syscalls, lock released */
	t0 = hg_now_ns();
	rc = hg_mem_release(hb, off, len);
	rel_ns = hg_ns_ul(hg_now_ns() - t0);

	/* phase 3 - publish, or put back */
	hg_lock_enter(hb, (enum hg_lock_reason)reason);
	hg_lkstat_add(&hb->lk_release, rel_ns);
	__atomic_store_n(&hb->grow_inflight, 0, __ATOMIC_RELEASE);
	if (rc != 0) {
		for (i = hb->npages - n; i < hb->npages; i++) {
			struct hg_page *pg = &hb->pages[i];

			pg->releasing = 0;
			if (!pg->punched)
				fl_push(hb, pg->base, top);
		}
		return 0;
	}

	for (i = hb->npages - n; i < hb->npages; i++) {
		struct hg_page *pg = &hb->pages[i];

		pg->releasing = 0;
		bit_clear(pg->bitmap, node_id(top, top, 0));
		memset(pg->leaforder, HG_LEAF_NONE, (size_t)lpp);
		pg->free_leaves = 0;
		pg->run_len = 0;
		if (pg->punched) {
			/* the hole leaves the span with its page; its bytes and
			 * its leaves left the counts at the punch */
			pg->punched = 0;
			if (hb->punched_pages)
				hb->punched_pages--;
		} else {
			hb->buddy_free_leaves -= lpp;
			if (hb->tier_bytes[pg->tier] >= hb->hps)
				hb->tier_bytes[pg->tier] -= hb->hps;
		}
		if (pg->want_collapse) {
			pg->want_collapse = 0;
			hb->collapse_wanting--;
		}
	}
	hb->npages -= n;
	hb->span_end -= len;
	hb->committed_bytes -= backed;
	hb->span_pending = hb->span_end;
	hb->size -= len;
	hb->shrinks++;
	hb->shrink_bytes += backed;
	floor_recompute(hb);
	span_check(hb, "a shrink");

	LM_NOTICE("%s arena shrank by %lu MB to %lu MB (%lu pages released "
		"to the %s in %lu us with the lock released; %lu MB of growth "
		"still held)\n", hb->name, len >> 20, hb->committed_bytes >> 20,
		n, hb->tier == HG_MEM_HUGETLB ? "hugetlb pool" : "host",
		rel_ns / 1000, (hb->committed_bytes - hb->committed_min) >> 20);
	return n;
}

static unsigned long hg_buddy_shrink_unlocks(struct hg_block *hb)
{
	unsigned long r;

	hg_lock_assert_held(hb, "hg_buddy_shrink_unlocks entry");
	r = buddy_shrink_body(hb);
	backed_fast_update(hb);
	hg_lock_assert_held(hb, "hg_buddy_shrink_unlocks return");
	return r;
}
static unsigned long buddy_punch_body(struct hg_block *hb)
{
	unsigned long sel[HG_PAGES_PER_EVENT];
	unsigned long limit = hb->shrink_step >> hb->hps_shift;
	unsigned long lpp = hg_leaves_per_page(hb);
	unsigned long i, got = 0, ok, rel_ns, free_after, floor_after;
	hg_ns_t t0;
	unsigned int top = hb->buddy_top;
	int reason;

	if (!hg_interior_release || hb->shrink_unsupported || !limit)
		return 0;
	if (limit > HG_PAGES_PER_EVENT)
		limit = HG_PAGES_PER_EVENT;

	/* phase 1 - choose from the bottom, where the re-commit refills too;
	 * the floor is in COMMITTED bytes, as a hole is not usable memory */
	for (i = 0; i + 1 < hb->npages && got < limit; i++) {
		struct hg_page *pg = &hb->pages[i];

		if (pg->punched || pg->releasing || !page_is_whole_free(hb, pg))
			continue;
		if (hb->committed_bytes <
		    hb->committed_min + ((got + 1) << hb->hps_shift))
			break;
		if (hb->buddy_free_leaves < (got + 1) * lpp)
			break;
		free_after = hb->buddy_free_leaves - (got + 1) * lpp;
		floor_after = ((hb->npages - hb->punched_pages - got - 1) * lpp)
		              / 16;
		if (free_after < 2 * floor_after)
			break;
		fl_unlink(hb, pg->base, top);
		pg->releasing = 1;
		sel[got++] = i;
	}
	if (!got)
		return 0;
	hb->grow_inflight = 1;
	backed_fast_update(hb);
	reason = hb->lk_cur;
	hg_lock_leave(hb);

	/* phase 2 - the syscalls, lock released; stop at the first refusal */
	t0 = hg_now_ns();
	for (ok = 0; ok < got; ok++) {
		struct hg_page *pg = &hb->pages[sel[ok]];

		if (hg_mem_release(hb, (unsigned long)(pg->base - hb->hbase),
		                   hb->hps) != 0)
			break;
	}
	rel_ns = hg_ns_ul(hg_now_ns() - t0);

	/* phase 3 - publish what went, put back what did not */
	hg_lock_enter(hb, (enum hg_lock_reason)reason);
	hg_lkstat_add(&hb->lk_release, rel_ns);
	__atomic_store_n(&hb->grow_inflight, 0, __ATOMIC_RELEASE);
	for (i = 0; i < got; i++) {
		struct hg_page *pg = &hb->pages[sel[i]];

		pg->releasing = 0;
		if (i >= ok) {
			fl_push(hb, pg->base, top);
			continue;
		}
		pg->punched = 1;
		hb->buddy_free_leaves -= lpp;
		hb->committed_bytes -= hb->hps;
		hb->punches++;
		hb->punch_bytes += hb->hps;
		hb->punched_pages++;
		if (hb->tier_bytes[pg->tier] >= hb->hps)
			hb->tier_bytes[pg->tier] -= hb->hps;
		if (pg->want_collapse) {
			pg->want_collapse = 0;
			hb->collapse_wanting--;
		}
	}
	if (ok) {
		floor_recompute(hb);
		span_check(hb, "a punch");
		LM_NOTICE("%s arena punched %lu interior page%s (%lu MB) back "
			"to the %s in %lu us with the lock released; %lu MB "
			"committed of a %lu MB span, %lu page%s held as "
			"holes\n", hb->name, ok, ok == 1 ? "" : "s",
			(ok << hb->hps_shift) >> 20,
			hb->tier == HG_MEM_HUGETLB ? "hugetlb pool" : "host",
			rel_ns / 1000, hb->committed_bytes >> 20,
			hb->span_end >> 20, hb->punched_pages,
			hb->punched_pages == 1 ? "" : "s");
	}
	return ok;
}

static unsigned long hg_buddy_punch_unlocks(struct hg_block *hb)
{
	unsigned long r;

	hg_lock_assert_held(hb, "hg_buddy_punch_unlocks entry");
	r = buddy_punch_body(hb);
	backed_fast_update(hb);
	hg_lock_assert_held(hb, "hg_buddy_punch_unlocks return");
	return r;
}


/* no-profile default: consecutive quiet sweep ticks before a drain starts (two
 * minutes at the 30 s sweep); a profile sets its own cycle count */
#define HG_SHRINK_QUIET_TICKS 4

/* no grow-step margin here: buddy_shrink_body() re-checks each page, so a
 * shrink cannot cause a grow */
static void shrink_tick_body(struct hg_block *hb)
{
	unsigned long lpp = hg_leaves_per_page(hb);
	unsigned int need_ticks;

	if (!hb->buddy_ready || hb->shrink_unsupported)
		return;
	if (hb->committed_bytes <= hb->committed_min) {
		hb->shrink_quiet = 0;
		return;
	}
	/* never move the top while a grow is populating above it */
	if (hb->grow_inflight) {
		hb->shrink_quiet = 0;
		return;
	}
	if (hb->pol_cooldown) {
		hb->pol_cooldown--;
		hb->shrink_quiet = 0;
		return;
	}
	/* never shrink a starved or latched arena; a busy top page ends the
	 * tick only without interior release, as the punch exists for it */
	if (hb->below_floor || hb->grow_blocked ||
	    (!hg_interior_release &&
	     !page_is_whole_free(hb, &hb->pages[hb->npages - 1]))) {
		hb->shrink_quiet = 0;
		return;
	}
	if (hb->pol.active) {
		if (hg_get_real_used(hb) * 100 > (unsigned long)hb->pol.down_pct *
		                          hb->committed_bytes ||
		    hb->buddy_free_leaves < lpp + hb->reserve_floor * 2) {
			hb->shrink_quiet = 0;
			return;
		}
		need_ticks = hb->pol.down_cycles ? hb->pol.down_cycles : 1;
	} else {
		if (hb->buddy_free_leaves < lpp + hb->reserve_floor * 4) {
			hb->shrink_quiet = 0;
			return;
		}
		need_ticks = HG_SHRINK_QUIET_TICKS;
	}
	if (++hb->shrink_quiet < need_ticks)
		return;
	hb->shrink_quiet = 0;
	if (hg_autoscale_dry_run) {
		if (!hb->pol_dry_said) {
			hb->pol_dry_said = 1;
			LM_NOTICE("%s: DRY RUN - would shrink (committed %lu MB, "
				"usage %lu%%)\n", hb->name,
				hb->committed_bytes >> 20,
				hg_get_real_used(hb) * 100 /
				hb->committed_bytes);
		}
		return;
	}
	hb->draining = 1;
	hg_drain_tick(hb);
}

void hg_shrink_tick(struct hg_block *hb)
{
	hg_lock_assert_held(hb, "hg_shrink_tick entry");
	shrink_tick_body(hb);
	hg_lock_assert_held(hb, "hg_shrink_tick return");
}

/* the gates are re-tested each step, as one tick of demand ends the drain */
void hg_drain_tick(struct hg_block *hb)
{
	unsigned long lpp = hg_leaves_per_page(hb), released;

	if (!hb->draining || !hb->buddy_ready)
		return;
	if (hb->shrink_unsupported || hb->below_floor || hb->grow_blocked ||
	    hb->committed_bytes <= hb->committed_min) {
		hb->draining = 0;
		return;
	}
	if (hb->grow_inflight)
		return;
	if (hb->pol.active) {
		if (hg_get_real_used(hb) * 100 >
		    (unsigned long)hb->pol.down_pct * hb->committed_bytes ||
		    hb->buddy_free_leaves < 2 * hb->reserve_floor + lpp) {
			hb->draining = 0;
			return;
		}
	} else if (hb->buddy_free_leaves < 4 * hb->reserve_floor + lpp) {
		hb->draining = 0;
		return;
	}

	released = hg_buddy_shrink_unlocks(hb);
	/* the trim reaches only the top of the span; the punch also frees what
	 * sits below a long-lived allocation at the top */
	released += hg_buddy_punch_unlocks(hb);
	if (!released)
		hb->draining = 0;
}
#endif /* HG_MALLOC */
