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
 *  2014-10-30 initial version (liviu)
 */

/*
 * This header exposes the basic operations with an OpenSIPS context.
 *
 * A "context" is:
 *		- a data storage buffer
 *		- typically allocated next to the intended structure
 *			e.g. | struct cell | CONTEXT_BUFFER |
 *
 * !! All data registrations must be done in the pre-forking phases !!
 *		(see the register functions below)
 */

#ifndef __CONTEXT_H
#define __CONTEXT_H

#include <stdlib.h>

#include "dprint.h"

typedef void * context_p;
enum osips_context {
	CONTEXT_GLOBAL,
	CONTEXT_TRAN,
	CONTEXT_DIALOG,

	CONTEXT_COUNT,
};

enum osips_context_val {
	CONTEXT_INT_TYPE,
	CONTEXT_STR_TYPE,
	CONTEXT_PTR_TYPE,

	CONTEXT_COUNT_TYPE
};

#define context_of(entity_p) ((context_p)((entity_p) + 1))
#define context_size(enum_ctx) (context_sizes[enum_ctx])

extern context_p current_processing_ctx;
extern unsigned int context_sizes[];
extern unsigned int type_sizes[CONTEXT_COUNT][CONTEXT_COUNT_TYPE];
extern unsigned int type_offsets[CONTEXT_COUNT][CONTEXT_COUNT_TYPE];

/*
 * allocate a new context in pkg mem
 *
 * Note: this will not change the "current_processing_ctx"
 */
context_p context_alloc(enum osips_context type);
#define   context_free(context_p) pkg_free(context_p)


/*
 * ensure the global context is non-NULL
 *
 * Return: context pointer on success, NULL on internal error
 */
int ensure_global_context(void);


/* free and reset the global context */
void clear_global_context(void);


/*
 * destroys a context by calling each callback registered
 */
void context_destroy(enum osips_context type, context_p ctx);


/*
 * - register a different function for each field you add in the context
 * - each function will be called exactly once, every time a context is freed
 *
 * Note: for int and (str *) types, you must perform the appropriate casting
 */
typedef void (*context_destroy_f)(void *);

/*
 * - the register functions should be called before any forks are made
 *		(mod_init(), function fixups)
 *
 * - they reserve and return a position in the context buffer of the given type
 */
int context_register_int(enum osips_context type, context_destroy_f f);
int context_register_str(enum osips_context type, context_destroy_f f);
int context_register_ptr(enum osips_context type, context_destroy_f f);

   /****************************** SETTERS ********************************/

static inline void context_put_int(enum osips_context type, context_p ctx,
								   int pos, int data)
{
#ifdef DBG_MALLOC
	if (pos < 0 || pos >= type_sizes[type][CONTEXT_INT_TYPE]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[type][CONTEXT_INT_TYPE]);
		abort();
	}
#endif

	((int *)ctx)[pos] = data;
}

static inline void context_put_str(enum osips_context type, context_p ctx,
								   int pos, str *data)
{
#ifdef DBG_MALLOC
	if (pos < 0 || pos >= type_sizes[type][CONTEXT_STR_TYPE]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[type][CONTEXT_STR_TYPE]);
		abort();
	}
#endif

	((str *)((char *)ctx + type_offsets[type][CONTEXT_STR_TYPE]))[pos] = *data;
}

static inline void context_put_ptr(enum osips_context type, context_p ctx,
				   int pos, void *data)
{
#ifdef DBG_MALLOC
	if (pos < 0 || pos >= type_sizes[type][CONTEXT_PTR_TYPE]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[type][CONTEXT_PTR_TYPE]);
		abort();
	}
#endif

	((void **)((char *)ctx + type_offsets[type][CONTEXT_PTR_TYPE]))[pos] = data;
}

   /****************************** GETTERS ********************************/

static inline int context_get_int(enum osips_context type,
								  context_p ctx, int pos)
{
#ifdef DBG_MALLOC
	if (pos < 0 || pos >= type_sizes[type][CONTEXT_INT_TYPE]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[type][CONTEXT_INT_TYPE]);
		abort();
	}
#endif

	return ((int *)ctx)[pos];
}

static inline str *context_get_str(enum osips_context type,
								   context_p ctx, int pos)
{
#ifdef DBG_MALLOC
	if (pos < 0 || pos >= type_sizes[type][CONTEXT_STR_TYPE]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[type][CONTEXT_STR_TYPE]);
		abort();
	}
#endif

	return &((str *)((char *)ctx + type_offsets[type][CONTEXT_STR_TYPE]))[pos];
}

static inline void *context_get_ptr(enum osips_context type,
									context_p ctx, int pos)
{
#ifdef DBG_MALLOC
	if (pos < 0 || pos >= type_sizes[type][CONTEXT_PTR_TYPE]) {
		LM_CRIT("Bad pos: %d (%d)\n", pos, type_sizes[type][CONTEXT_PTR_TYPE]);
		abort();
	}
#endif

	return ((void **)((char *)ctx +
	                  type_offsets[type][CONTEXT_PTR_TYPE]))[pos];
}

#endif /* __CONTEXT_H */
