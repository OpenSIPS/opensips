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

#ifndef hg_dbg_h
#define hg_dbg_h

#include "hg_malloc.h"

/* HG_MALLOC_DBG: a cell's last HG_DBG_TAIL bytes hold the encoded size and
 * the gap before them is red zone; freed cells are poisoned, quarantined */
#define HG_DBG_TAIL     (sizeof(unsigned long))
#define HG_DBG_REDZONE  0xcc
#define HG_DBG_POISON   0x6b
#define HG_QUAR_CELLS   256       /* cells one thread holds per arena */
#define HG_QUAR_MIN     (16UL << 10)
#define HG_QUAR_MAX     (1UL << 20)

/* stamp/check the trailer and red zone of cell @cs (@cap payload bytes,
 * @size asked for); check returns 0 if intact, else counts and logs */
void hg_dbg_tail_set(void *cs, unsigned long cap, unsigned long size);
int hg_dbg_tail_check(struct hg_block *hb, void *cs, unsigned long cap);

/* per-thread, per-arena quarantine: put poisons a FREE cell of class @c in,
 * drain checks all out (returns how many left), reset empties after fork */
void hg_quar_put(struct hg_block *hb, struct hg_palloc *pl, unsigned int c,
                 char *cs);
unsigned int hg_quar_drain(struct hg_block *hb, struct hg_palloc *pl);
void hg_quar_reset(struct hg_quar *q);

#endif /* hg_dbg_h */
