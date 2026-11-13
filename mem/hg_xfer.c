/*
 * HG_MALLOC transfer cache - whole private chains parked between processes
 *
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

#include "hg_malloc.h"
#include "hg_arena.h"
#include "hg_buddy.h"
#include "../dprint.h"
#include "../globals.h"
#include "hg_arena_int.h"
#include "hg_xfer.h"

/* a class may park 1/128 of the arena, at most 32 MB: tm frees a timer tick's
 * transactions in one burst, so a few chains overflow at once */
#define HG_XFER_SHARE_SHIFT 7
#define HG_XFER_CLASS_MAX   (32UL << 20)

void hg_xfer_caps(struct hg_block *hb)
{
	unsigned long budget = hb->size >> HG_XFER_SHARE_SHIFT, chain, n;
	int c;

	if (budget > HG_XFER_CLASS_MAX)
		budget = HG_XFER_CLASS_MAX;
	for (c = 0; c < HG_NCLASSES; c++) {
		chain = (unsigned long)hb->priv_donate[c] * cell_sizes[c];
		n = (!hb->shared || !chain) ? 0 : budget / chain;
		hb->xfer[c].cap = n > HG_XFER_SLOTS ? HG_XFER_SLOTS : (unsigned int)n;
	}
}

int hg_xfer_put(struct hg_block *hb, int c, void *head, unsigned int len)
{
	struct hg_xfer *x = &hb->xfer[c];

	if (x->n >= x->cap) {
		hb->xfer_full++;
		return 0;
	}
	x->head[x->n] = head;
	x->len[x->n++] = len;
	x->busy++;
	hb->xfer_puts++;
	return 1;
}

void *hg_xfer_get(struct hg_block *hb, int c, unsigned int *len)
{
	struct hg_xfer *x = &hb->xfer[c];

	if (!x->n)
		return NULL;
	x->n--;
	x->busy++;
	hb->xfer_gets++;
	*len = x->len[x->n];
	return x->head[x->n];
}

/* through hg_gpool_push(), which vets each cell; a refusal leaks the rest */
static unsigned int xfer_drain_chain(struct hg_block *hb, int c, void *p,
		unsigned int len)
{
	unsigned int n = 0;
	void *next;

	while (p && n < len) {
		next = cell_next(p);
		if (hg_gpool_push(hb, c, p) < 0)
			break;
		p = next;
		n++;
	}
	hb->xfer_drained += n;
	return n;
}

void hg_xfer_cycle(struct hg_block *hb)
{
	struct hg_xfer *x;
	int c;

	for (c = 0; c < HG_NCLASSES; c++) {
		x = &hb->xfer[c];
		if (!x->busy && x->n) {
			x->n--;
			xfer_drain_chain(hb, c, x->head[x->n], x->len[x->n]);
		}
		x->busy = 0;
	}
}

unsigned int hg_xfer_drain_all(struct hg_block *hb)
{
	unsigned int got = 0;
	struct hg_xfer *x;
	int c;

	for (c = 0; c < HG_NCLASSES; c++)
		for (x = &hb->xfer[c]; x->n; ) {
			x->n--;
			got += xfer_drain_chain(hb, c, x->head[x->n], x->len[x->n]);
		}
	return got;
}

#endif /* HG_MALLOC */
