/*
 * slab allocator with elastic arenas - HG_MALLOC_DBG checks
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

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "hg_malloc.h"
#include "hg_arena.h"
#include "hg_dbg.h"
#include "../dprint.h"

/*
 * The checks HG_MALLOC_DBG adds, on an arena whose hb->dbg is set: the tail
 * red zone of every allocation, and the poisoned quarantine every freed
 * cell passes through before it can be reused. The production paths test
 * the flag and nothing else - see the call sites in hg_arena.c, hg_large.c
 * and hg_malloc_dyn.h.
 */

/* the trailer is stored XORed with this, so neither the red zone's own
 * bytes nor a stray small integer reads back as a plausible size */
static inline unsigned long tail_key(const void *cs)
{
	unsigned long long x = ((unsigned long long)(unsigned long)cs ^
		hg_hdr_secret) * 0x9e3779b97f4a7c15ULL;

	return (unsigned long)(x ^ (x >> 32));
}

/* the first of @len bytes that is not @byte, or @len */
static unsigned long first_unlike(const unsigned char *b, unsigned long len,
                                  unsigned char byte)
{
	unsigned long i;

	for (i = 0; i < len; i++)
		if (b[i] != byte)
			break;
	return i;
}

/* @size + HG_DBG_TAIL <= @cap: the allocation was sized for it */
void hg_dbg_tail_set(void *cs, unsigned long cap, unsigned long size)
{
	char *pay = (char *)cs + HG_CELL_HDR;
	unsigned long enc = size ^ tail_key(cs);

	memset(pay + size, HG_DBG_REDZONE, cap - HG_DBG_TAIL - size);
	memcpy(pay + cap - HG_DBG_TAIL, &enc, HG_DBG_TAIL);
}

int hg_dbg_tail_check(struct hg_block *hb, void *cs, unsigned long cap)
{
	const unsigned char *pay = (const unsigned char *)cs + HG_CELL_HDR;
	unsigned long enc, size, i;
	char what[64];

	memcpy(&enc, pay + cap - HG_DBG_TAIL, HG_DBG_TAIL);
	size = enc ^ tail_key(cs);
	if (size <= cap - HG_DBG_TAIL) {
		i = size + first_unlike(pay + size, cap - HG_DBG_TAIL - size,
		                        HG_DBG_REDZONE);
		if (i == cap - HG_DBG_TAIL)
			return 0;
		snprintf(what, sizeof what, "the %lu bytes asked for (byte %lu)",
			size, i);
	} else {
		/* the trailer itself was overwritten: the size is lost */
		snprintf(what, sizeof what, "its size (trailer lost)");
	}
	hg_corrupt(hb, HG_C_OVERFLOW);
#ifdef DBG_MALLOC
	LM_CRIT("%s: %p (%lu bytes) was written past %s - allocated at "
		"%s: %s(%lu)\n", hb->name, (const void *)pay, cap, what,
		HG_CELL_AT(cs)->file ? HG_CELL_AT(cs)->file : "?",
		HG_CELL_AT(cs)->func ? HG_CELL_AT(cs)->func : "?",
		HG_CELL_AT(cs)->line);
#else
	LM_CRIT("%s: %p (%lu bytes) was written past %s\n", hb->name,
		(const void *)pay, cap, what);
#endif
	return -1;
}

/*
 * The quarantine: a freed cell is filled with HG_DBG_POISON and parked here,
 * oldest out first, before it goes back on a free list - so a write through
 * a dangling pointer lands in a cell nobody else holds yet, and is seen when
 * the cell leaves. Per thread and per arena like the private lists, so no
 * lock; bounded by HG_QUAR_CELLS cells and hb->quar_bytes. The ring is mapped
 * on the first free, outside the arena it serves.
 */
struct hg_quar {
	unsigned int  head;                  /* oldest entry */
	unsigned int  n;                     /* entries held */
	unsigned long bytes;                 /* cell bytes held */
	char         *cell[HG_QUAR_CELLS];   /* cell starts */
	unsigned char cls[HG_QUAR_CELLS];    /* their classes */
};

/* a cell leaving quarantine is still all poison under an intact FREE
 * header, or it was written after its free: then it is leaked, never
 * handed out again */
static int quar_check(struct hg_block *hb, char *cs, unsigned int c)
{
	const unsigned char *pay = (const unsigned char *)cs + HG_CELL_HDR;
	unsigned long cap = hg_cell_total_size(c) - HG_CELL_HDR, i;

	if (hg_hdr_state(cs) != HG_ST_FREE || HG_CELL_AT(cs)->cls != c) {
		hg_corrupt(hb, HG_C_HEADER);
		LM_CRIT("%s: the header of %p was overwritten while the cell sat "
			"in quarantine - leaking it\n", hb->name, (const void *)pay);
		return -1;
	}
	i = first_unlike(pay, cap, HG_DBG_POISON);
	if (i == cap)
		return 0;
	hg_corrupt(hb, HG_C_USE_AFTER_FREE);
#ifdef DBG_MALLOC
	LM_CRIT("%s: %p (%lu bytes) was written after it was freed - byte %lu "
		"is 0x%02x; freed at %s: %s(%lu) - leaking it\n", hb->name,
		(const void *)pay, cap, i, pay[i],
		HG_CELL_AT(cs)->file ? HG_CELL_AT(cs)->file : "?",
		HG_CELL_AT(cs)->func ? HG_CELL_AT(cs)->func : "?",
		HG_CELL_AT(cs)->line);
#else
	LM_CRIT("%s: %p (%lu bytes) was written after it was freed - byte %lu "
		"is 0x%02x - leaking it\n", hb->name, (const void *)pay, cap, i,
		pay[i]);
#endif
	return -1;
}

static void quar_evict(struct hg_block *hb, struct hg_palloc *pl,
                       struct hg_quar *q)
{
	char *cs = q->cell[q->head];
	unsigned int c = q->cls[q->head];

	q->head = (q->head + 1) % HG_QUAR_CELLS;
	q->n--;
	q->bytes -= hg_cell_total_size(c);
	hg_san_open(hb, cs, hg_cell_total_size(c) - HG_CELL_HDR);
	if (quar_check(hb, cs, c) == 0) {
		hg_san_take(hb, cs, hg_cell_total_size(c) - HG_CELL_HDR);
		hg_cell_push_private(hb, pl, c, cs);
	} else {
		/* leaked: closed, so a further stale access is reported too */
		hg_san_close(hb, cs, hg_cell_total_size(c) - HG_CELL_HDR);
	}
}

void hg_quar_put(struct hg_block *hb, struct hg_palloc *pl, unsigned int c,
                 char *cs)
{
	struct hg_quar *q = pl->quar;
	unsigned int i;

	if (!q) {
		void *m = mmap(NULL, sizeof *q, PROT_READ | PROT_WRITE,
		               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (m == MAP_FAILED) {
			/* no quarantine: the cell goes back at once, unchecked */
			hg_san_take(hb, cs, hg_cell_total_size(c) - HG_CELL_HDR);
			hg_cell_push_private(hb, pl, c, cs);
			return;
		}
		q = pl->quar = m;
	}
	memset(cs + HG_CELL_HDR, HG_DBG_POISON, hg_cell_total_size(c) - HG_CELL_HDR);
	hg_san_close(hb, cs, hg_cell_total_size(c) - HG_CELL_HDR);
	while (q->n == HG_QUAR_CELLS ||
	       (q->n && q->bytes + hg_cell_total_size(c) > hb->quar_bytes))
		quar_evict(hb, pl, q);
	i = (q->head + q->n) % HG_QUAR_CELLS;
	q->cell[i] = cs;
	q->cls[i] = (unsigned char)c;
	q->n++;
	q->bytes += hg_cell_total_size(c);
}

void hg_quar_reset(struct hg_quar *q)
{
	q->head = q->n = 0;
	q->bytes = 0;
}

unsigned int hg_quar_drain(struct hg_block *hb, struct hg_palloc *pl)
{
	struct hg_quar *q = pl->quar;
	unsigned int n = 0;

	for (; q && q->n; n++)
		quar_evict(hb, pl, q);
	return n;
}

#endif /* HG_MALLOC */
