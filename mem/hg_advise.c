/*
 * slab allocator with elastic arenas - -m/-M sizing advice
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#ifdef HG_MALLOC

#include <string.h>

#include "hg_malloc.h"
#include "hg_advise.h"
#include "hg_buddy.h"

/* margins multiply the HIGH-WATER, not current use; pkg gets more, as pkg
 * exhaustion kills the process outright */
#define HG_ADVISE_SHM_MARGIN   2
#define HG_ADVISE_PKG_MARGIN   3
/* floors kept low: a floor should stop a silly recommendation, not become
 * the recommendation */
#define HG_ADVISE_SHM_FLOOR_MB 8
#define HG_ADVISE_PKG_FLOOR_MB 2

/* bands of peak as % of the size, or of an elastic arena's cap: TIGHT starts
 * at 70, as an arena at 77% can be one busy hour from failing an allocation */
#define HG_ADVISE_TIGHT_PCT    70
#define HG_ADVISE_WATCH_PCT    50
#define HG_ADVISE_LOOSE_PCT    20

/* grow-ahead commits more once under two reserve floors are free, a floor
 * being INIT/16 (hg_buddy.c): an INIT of 8/7 the peak stays clear of it */
#define HG_ADVISE_INIT_NUM     8
#define HG_ADVISE_INIT_DEN     7

static const char hg_advise_large_caveat[] =
	"most of this arena's live bytes are in the large tier, and at "
	"least some large consumers size themselves as a fraction of the "
	"arena - so this recommendation is an upper bound, not a fixed "
	"point. Apply it once, restart, and re-read rather than "
	"iterating.";

static unsigned int pct_of(unsigned long part, unsigned long whole)
{
	return whole ? (unsigned int)((unsigned long long)part * 100 / whole) : 0;
}

/* rounded up to a whole huge page so the arena does not map a partial one */
static unsigned long advise_mb(unsigned long long bytes, unsigned long floor_mb,
                               unsigned long hps)
{
	unsigned long mb = (unsigned long)((bytes + (1UL << 20) - 1) >> 20);
	unsigned long step = (hps >= (1UL << 20)) ? (hps >> 20) : 1;

	if (mb < floor_mb)
		mb = floor_mb;
	if (step > 1)
		mb = ((mb + step - 1) / step) * step;
	return mb;
}

static const char *advise_verdict(const struct hg_advice *a)
{
	if (a->peak_pct > HG_ADVISE_TIGHT_PCT)
		return a->elastic ?
			"TIGHT - raise the cap before the next busy period" :
			"TIGHT - raise it before the next busy period";
	if (a->peak_pct > HG_ADVISE_WATCH_PCT)
		return a->elastic ?
			"watch - fine now, the cap leaves no room for a bad day" :
			"watch - fine now, no room for a bad day";
	/* only committed memory is pinned: an elastic arena's unused cap is not
	 * (on hugetlb it is a pool reservation), so INIT is what can be oversized */
	if (a->elastic)
		return pct_of(a->peak, a->init) < HG_ADVISE_LOOSE_PCT ?
			"INIT oversized - pinned from startup and never used" :
			"reasonable";
	if (a->peak_pct < HG_ADVISE_LOOSE_PCT)
		return "oversized - the surplus is pinned and unusable elsewhere";
	return "reasonable";
}

void hg_advise_compute(struct hg_advice *a)
{
	unsigned long floor_mb;
	unsigned long long need;

	a->margin = a->pkg ? HG_ADVISE_PKG_MARGIN : HG_ADVISE_SHM_MARGIN;
	floor_mb = a->pkg ? HG_ADVISE_PKG_FLOOR_MB : HG_ADVISE_SHM_FLOOR_MB;
	a->elastic = a->cap > a->init;
	/* an elastic arena commits just past its peak, so committed says
	 * nothing about room: the cap does */
	a->peak_pct = pct_of(a->peak, a->elastic ? a->cap : a->size);
	a->rec_mb = advise_mb((unsigned long long)a->peak * a->margin, floor_mb,
		a->hps);

	a->rec_init_mb = 0;
	if (a->elastic) {
		need = (unsigned long long)a->peak * HG_ADVISE_INIT_NUM /
			HG_ADVISE_INIT_DEN;
		if (a->grow_pct &&
		    (unsigned long long)a->peak * 100 / a->grow_pct > need)
			need = (unsigned long long)a->peak * 100 / a->grow_pct;
		a->rec_init_mb = advise_mb(need, floor_mb, a->hps);
		if (a->rec_mb < a->rec_init_mb)
			a->rec_mb = a->rec_init_mb;
	}
	a->verdict = advise_verdict(a);

	a->large_share_pct = pct_of(a->large_live, a->slab_live + a->large_live);
	a->caveat = a->large_share_pct > 50 ? hg_advise_large_caveat : NULL;

	a->pinned_total_mb = a->rec_total_mb = 0;
	if (a->nproc > 0) {
		a->pinned_total_mb = a->elastic ? a->committed_all >> 20 :
			(unsigned long)a->nproc * (a->size >> 20);
		a->rec_total_mb = (unsigned long)a->nproc *
			(a->elastic ? a->rec_init_mb : a->rec_mb);
	}
}

void hg_advise_arena(struct hg_block *hb, unsigned long peak, int pkg,
		int nproc, unsigned long committed_all, struct hg_advice *a)
{
	memset(a, 0, sizeof *a);
	a->init = hb->init_bytes;
	a->size = hb->size;
	a->committed = hb->committed_bytes;
	a->cap = hg_grow_limit(hb);
	a->grow_pct = hb->pol.active ? hb->pol.up_pct : 0;
	a->hps = hb->hps;
	a->peak = peak;
	a->pkg = pkg;
	a->nproc = nproc;
	a->committed_all = committed_all;
	a->slab_live = hg_cell_live(hb);
	a->large_live = hb->large_live;
	hg_advise_compute(a);
}

#endif /* HG_MALLOC */
