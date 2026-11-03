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

/* HG_MALLOC transfer cache: a donation or a refill of a whole private chain
 * is one swap under hb->lock, not a walk of its cells; all under hb->lock */
#ifndef hg_xfer_h
#define hg_xfer_h

#ifdef HG_MALLOC
struct hg_block;

/* per-class chain caps from the arena size and priv_donate; 0 for pkg */
void hg_xfer_caps(struct hg_block *hb);
/* 1 = parked, 0 = full: the caller hands the cells over one by one */
int hg_xfer_put(struct hg_block *hb, int c, void *head, unsigned int len);
/* a parked chain of @len cells, or NULL */
void *hg_xfer_get(struct hg_block *hb, int c, unsigned int *len);
/* from hg_gc_cycle(): a class idle since the last cycle returns a chain */
void hg_xfer_cycle(struct hg_block *hb);
/* every parked cell back to its block, for a carve at exhaustion */
unsigned int hg_xfer_drain_all(struct hg_block *hb);
#endif

#endif /* hg_xfer_h */
