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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2014-12-10 initial version (liviu)
 */

#include "str.h"
#include "mem/mem.h"
#include "context.h"
#include <string.h>

/* Pointer to the current processing context */
context_p current_processing_ctx = NULL;

unsigned int context_sizes[CONTEXT_COUNT];

unsigned int type_sizes[CONTEXT_COUNT][CONTEXT_COUNT_TYPE];
unsigned int type_offsets[CONTEXT_COUNT][CONTEXT_COUNT_TYPE];

/* vector of destroy functions */
static context_destroy_f *context_destroy_array[CONTEXT_COUNT];

static void register_context_destroy(context_destroy_f f,
		enum osips_context ctx, enum osips_context_val t)
{
	static int count = 0; /* contains all counters */
	context_destroy_f *tmp;
	int pos = 0;
	int i;

	/*
	 * group all functions based on their types:
	 * first the int functions, then the str and pointers the last
	 */
	switch (t) {
	case CONTEXT_PTR_TYPE:
		pos += type_sizes[ctx][CONTEXT_PTR_TYPE];
	case CONTEXT_STR_TYPE:
		pos += type_sizes[ctx][CONTEXT_STR_TYPE];
	case CONTEXT_INT_TYPE:
		pos += type_sizes[ctx][CONTEXT_INT_TYPE];
		break;
	default:
		LM_ERR("should not get here with ctx %d\n", t);
		return;
	}
	/* TODO: check whether this should be in pkg or shm? */
	tmp = pkg_realloc(context_destroy_array[ctx], (count + 1) * sizeof(context_destroy_f));
	if (!tmp) {
		LM_ERR("cannot add any more destroy functions\n");
		return;
	}
	context_destroy_array[ctx] = tmp;

	/* move everything to the right to make room for pos */
	for (i = count; i > pos; i--)
		context_destroy_array[ctx][i] = context_destroy_array[ctx][i - 1];
	context_destroy_array[ctx][pos] = f;
	count++;
}

void context_destroy(enum osips_context ctxtype, context_p ctx)
{
	int f = 0;
	int n;
	int i;
	str *s;
	void *p;


	/* int ctx */
	for (n = 0; n < type_sizes[ctxtype][CONTEXT_INT_TYPE]; n++, f++)
		if (context_destroy_array[ctxtype][f]) {
			i = context_get_int(ctxtype, ctx, n);
			if (i)/* XXX: should we call for 0 values? */
				context_destroy_array[ctxtype][f](&i);
		}

	/* str ctx */
	for (n = 0; n < type_sizes[ctxtype][CONTEXT_STR_TYPE]; n++, f++)
		if (context_destroy_array[ctxtype][f]) {
			s = context_get_str(ctxtype, ctx, n);
			if (s)/* XXX: how do we determine if s is empty? */
				context_destroy_array[ctxtype][f](s);
		}

	/* ptr ctx */
	for (n = 0; n < type_sizes[ctxtype][CONTEXT_PTR_TYPE]; n++, f++) {
		if (context_destroy_array[ctxtype][f]) {
			p = context_get_ptr(ctxtype, ctx, n);
			if (p)
				context_destroy_array[ctxtype][f](p);
		}
	}
}

context_p context_alloc(enum osips_context type)
{
	context_p ctx;

	ctx = pkg_malloc(context_size(type));
	if (!ctx) {
		LM_ERR("no more pkg mem\n");
		return NULL;
	}

	return ctx;
}


int ensure_global_context(void)
{
	if (current_processing_ctx)
		return 0;

	current_processing_ctx = context_alloc(CONTEXT_GLOBAL);
	if (!current_processing_ctx) {
		LM_ERR("oom\n");
		return -1;
	}

	memset(current_processing_ctx, 0, context_size(CONTEXT_GLOBAL));
	return 0;
}


void clear_global_context(void)
{
	if (current_processing_ctx) {
		context_destroy(CONTEXT_GLOBAL, current_processing_ctx);
		current_processing_ctx = NULL;
	}
}


int context_register_int(enum osips_context type, context_destroy_f f)
{
	context_sizes[type] += sizeof(int);
	type_offsets[type][CONTEXT_STR_TYPE] += sizeof(int);
	type_offsets[type][CONTEXT_PTR_TYPE] += sizeof(int);
	register_context_destroy(f, type, CONTEXT_INT_TYPE);

	return type_sizes[type][CONTEXT_INT_TYPE]++;
}

int context_register_str(enum osips_context type, context_destroy_f f)
{
	context_sizes[type] += sizeof(str);
	type_offsets[type][CONTEXT_PTR_TYPE] += sizeof(str);
	register_context_destroy(f, type, CONTEXT_STR_TYPE);

	return type_sizes[type][CONTEXT_STR_TYPE]++;
}

int context_register_ptr(enum osips_context type, context_destroy_f f)
{
	context_sizes[type] += sizeof(void *);
	register_context_destroy(f, type, CONTEXT_PTR_TYPE);

	return type_sizes[type][CONTEXT_PTR_TYPE]++;
}
