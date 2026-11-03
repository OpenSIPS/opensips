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

#ifndef _HG_ADVISE_H
#define _HG_ADVISE_H

#ifdef HG_MALLOC

struct hg_block;

/* one arena's advice: sizes in bytes, recommendations in MB */
struct hg_advice {
	/* what hg_advise_compute() reads */
	unsigned long init;        /* committed at startup */
	unsigned long size;        /* the span, a fixed arena's size */
	unsigned long committed;
	unsigned long cap;         /* the most growth may commit */
	unsigned long peak;        /* the carve high-water */
	unsigned long hps;
	unsigned int grow_pct;     /* profile's grow line, % of committed; 0: none */
	int pkg;
	int nproc;                 /* pkg: processes counted, else 0 */
	unsigned long committed_all; /* pkg: committed over those processes */
	unsigned long slab_live;
	unsigned long large_live;

	/* what it fills in */
	int elastic;               /* cap above init */
	unsigned int margin;
	unsigned int peak_pct;     /* of the size, or of an elastic arena's cap */
	unsigned long rec_mb;      /* the size, or an elastic arena's cap */
	unsigned long rec_init_mb; /* elastic: an INIT the peak does not grow past */
	const char *verdict;
	unsigned int large_share_pct;
	const char *caveat;        /* NULL, or why rec_mb is an upper bound */
	unsigned long pinned_total_mb;  /* pkg, over nproc processes */
	unsigned long rec_total_mb;
};

void hg_advise_compute(struct hg_advice *a);
/* @nproc/@committed_all: pkg's figures over every process, 0 if unknown */
void hg_advise_arena(struct hg_block *hb, unsigned long peak, int pkg,
		int nproc, unsigned long committed_all, struct hg_advice *a);

#endif /* HG_MALLOC */

#endif
