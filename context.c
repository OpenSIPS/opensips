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
 *  2014-12-10 initial version (liviu)
 */

#include "str.h"
#include "mem/mem.h"
#include "context.h"

/* Pointer to the current processing context */
context_p current_processing_ctx = NULL;

unsigned int context_sizes[CONTEXT_COUNT];

static unsigned int type_sizes[CONTEXT_COUNT][3];
static unsigned int type_offsets[CONTEXT_COUNT][3];

context_p context_alloc(void)
{
	context_p ctx;

	ctx = pkg_malloc(context_size(CONTEXT_GLOBAL));
	if (!ctx) {
		LM_ERR("no more pkg mem\n");
		return NULL;
	}

	return ctx;
}

int context_register_int(enum osips_context type)
{
	context_sizes[type] += sizeof(int);
	type_offsets[type][1] += sizeof(int);
	type_offsets[type][2] += sizeof(int);

	return type_sizes[type][0]++;
}

int context_register_str(enum osips_context type)
{
	context_sizes[type] += sizeof(str);
	type_offsets[type][2] += sizeof(str);

	return type_sizes[type][1]++;
}

int context_register_ptr(enum osips_context type)
{
	context_sizes[type] += sizeof(void *);

	return type_sizes[type][2]++;
}

void context_put_int(enum osips_context type, context_p ctx,
									 int pos, int data)
{
#ifdef DBG_QM_MALLOC
	if (pos < 0 || pos >= type_sizes[type][0]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[type][0]);
		abort();
	}
#endif

	if (!ctx)
		LM_CRIT("NULL context given\n");

	((int *)ctx)[pos] = data;
}

void context_put_str(enum osips_context type, context_p ctx,
									 int pos, str *data)
{
#ifdef DBG_QM_MALLOC
	if (pos < 0 || pos >= type_sizes[type][1]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[type][1]);
		abort();
	}
#endif

	if (!ctx)
		LM_CRIT("NULL context given\n");

	((str *)((char *)ctx + type_offsets[type][1]))[pos] = *data;
}

void context_put_ptr(enum osips_context type, context_p ctx,
									 int pos, void *data)
{
#ifdef DBG_QM_MALLOC
	if (pos < 0 || pos >= type_sizes[type][2]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[type][2]);
		abort();
	}
#endif

	if (!ctx)
		LM_CRIT("NULL context given\n");

	((void **)((char *)ctx + type_offsets[type][2]))[pos] = data;
}

int context_get_int(enum osips_context type, context_p ctx, int pos)
{
#ifdef DBG_QM_MALLOC
	if (pos < 0 || pos >= type_sizes[type][0]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[type][0]);
		abort();
	}
#endif

	if (!ctx)
		LM_CRIT("NULL context given\n");

	return ((int *)ctx)[pos];
}

str *context_get_str(enum osips_context type, context_p ctx, int pos)
{
#ifdef DBG_QM_MALLOC
	if (pos < 0 || pos >= type_sizes[type][1]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[type][1]);
		abort();
	}
#endif

	if (!ctx)
		LM_CRIT("NULL context given\n");

	return &((str *)((char *)ctx + type_offsets[type][1]))[pos];
}

void *context_get_ptr(enum osips_context type, context_p ctx, int pos)
{
#ifdef DBG_QM_MALLOC
	if (pos < 0 || pos >= type_sizes[type][2]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[type][2]);
		abort();
	}
#endif

	if (!ctx)
		LM_CRIT("NULL context given\n");

	return ((void **)((char *)ctx + type_offsets[type][2]))[pos];
}
