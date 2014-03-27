/**
 * the truly parallel memory allocator
 *
 * Copyright (C) 2014 OpenSIPS Solutions
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2014-01-19 initial version (liviu)
 */

#ifndef HP_MALLOC_STATS_H
#define HP_MALLOC_STATS_H

#include "../lock_ops.h"

/* specified in microseconds */
#define SHM_STATS_SAMPLING_PERIOD 200000L

extern gen_lock_t *hp_stats_lock;

int stats_are_expired(struct hp_block *qm);
void update_shm_stats(struct hp_block *qm);

#ifdef STATISTICS
unsigned long hp_get_size(struct hp_block *qm);
unsigned long hp_get_used(struct hp_block *qm);
unsigned long hp_get_free(struct hp_block *qm);
unsigned long hp_get_real_used(struct hp_block *qm);
unsigned long hp_get_max_real_used(struct hp_block *qm);
unsigned long hp_get_frags(struct hp_block *qm);
#endif /* STATISTICS */

#endif /* HP_MALLOC_STATS_H */
