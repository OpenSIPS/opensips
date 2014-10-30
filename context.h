/*
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
 *  2014-10-30 initial version (liviu)
 */

/*
 * This header defines the basic operations with an OpenSIPS context.
 * It should only be included in order to define operations on a new context.
 *
 * A "context" is:
 *		- a data storage buffer
 *		- visible across different processes (stored in shared memory)
 *		- typically allocated next to the intended structure
 *			e.g. | struct sip_msg | CONTEXT_BUFFER |
 * 
 * All data registrations must be done in the pre-forking phase (e.g. mod_init)
 */

#ifndef __CONTEXT_H
#define __CONTEXT_H

#include <stdlib.h>

enum osips_context {
	CONTEXT_MSG,
	CONTEXT_TRAN,
	CONTEXT_COUNT,
};

unsigned int context_sizes[CONTEXT_COUNT];
unsigned int type_sizes[CONTEXT_COUNT][3];
unsigned int type_offsets[CONTEXT_COUNT][3];

#define context_of(entity) ((void *)((entity) + 1))
#define context_size(ctx) (context_sizes[ctx])

static inline int __context_register_int(enum osips_context ctx)
{
	context_sizes[ctx] += sizeof(int);
	type_offsets[ctx][1] += sizeof(int);
	type_offsets[ctx][2] += sizeof(int);

	return type_sizes[ctx][0]++;
}

static inline int __context_register_str(enum osips_context ctx)
{
	context_sizes[ctx] += sizeof(str);
	type_offsets[ctx][2] += sizeof(str);

	return type_sizes[ctx][1]++;
}

static inline int __context_register_ptr(enum osips_context ctx)
{
	context_sizes[ctx] += sizeof(void *);

	return type_sizes[ctx][2]++;
}

static inline void __context_put_int(enum osips_context ctx, void *block,
									 int pos, int data)
{
#ifdef DBG_QM_MALLOC
	if (pos < 0 || pos >= type_sizes[ctx][0]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[ctx][0]);
		abort();
	}
#endif

	((int *)block)[pos] = data;
}

static inline void __context_put_str(enum osips_context ctx, void *block,
									 int pos, str *data)
{
#ifdef DBG_QM_MALLOC
	if (pos < 0 || pos >= type_sizes[ctx][1]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[ctx][1]);
		abort();
	}
#endif

	((str *)((char *)block + type_offsets[ctx][1]))[pos] = *data;
}

static inline void __context_put_ptr(enum osips_context ctx, void *block,
									 int pos, void *data)
{
#ifdef DBG_QM_MALLOC
	if (pos < 0 || pos >= type_sizes[ctx][2]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[ctx][2]);
		abort();
	}
#endif

	((void **)((char *)block + type_offsets[ctx][2]))[pos] = data;
}

static inline int __context_get_int(enum osips_context ctx, void *block, int pos)
{
#ifdef DBG_QM_MALLOC
	if (pos < 0 || pos >= type_sizes[ctx][0]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[ctx][0]);
		abort();
	}
#endif

	return ((int *)block)[pos];
}

static inline str *__context_get_str(enum osips_context ctx, void *block, int pos)
{
#ifdef DBG_QM_MALLOC
	if (pos < 0 || pos >= type_sizes[ctx][1]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[ctx][1]);
		abort();
	}
#endif

	return &((str *)((char *)block + type_offsets[ctx][1]))[pos];
}

static inline void *__context_get_ptr(enum osips_context ctx, void *block, int pos)
{
#ifdef DBG_QM_MALLOC
	if (pos < 0 || pos >= type_sizes[ctx][2]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[ctx][2]);
		abort();
	}
#endif

	return ((void **)((char *)block + type_offsets[ctx][2]))[pos];
}

#endif /* __CONTEXT_H */
