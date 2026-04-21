/*
 * Profiling hooks for external instrumentation
 *
 * Copyright (C) 2026 OpenSIPS Project
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#ifndef PROFILING_H
#define PROFILING_H

#include <stddef.h>
#include <stdint.h>
#include "pt.h"

struct sip_msg;

typedef struct profiling_ctx {
	uint8_t trace_id[16];
	uint8_t span_id[8];
	uint8_t trace_flags;
	uint64_t start_system_ns;
	uint64_t start_steady_ns;
	uint8_t has_start_time;
} profiling_ctx_t;

#define PROFILING_DATA_TYPE_SCRIPT (1u << 0)
#define PROFILING_DATA_TYPE_PROC   (1u << 1)

typedef struct profiling_handlers {
	const char *name;
	uint32_t accepted_data_types;
	struct profiling_handlers *next;

	void (*on_start)(int data_type, const char *name, int subtype, int depth,
		void *payload);
	void (*on_end)(int data_type, const char *name, int subtype, int depth,
		int status, void *payload);
	void (*on_enter)(int data_type, const char *name, int subtype, int depth,
		const char *file, int line, void *payload);
	void (*on_exit)(int data_type, const char *name, int subtype, int depth,
		const char *file, int line, int status, void *payload);
	int (*get_ctx)(profiling_ctx_t *ctx);
	int (*set_ctx)(const profiling_ctx_t *ctx);
} profiling_handlers_t;

extern profiling_handlers_t *profiling_handlers;

int init_profiling(void);
int register_profiling_handler(profiling_handlers_t *handlers);
void unregister_profiling_handler(profiling_handlers_t *handlers);

static inline int profiling_enabled(unsigned int data_type_mask)
{
	profiling_handlers_t *handlers;

	for (handlers = profiling_handlers; handlers; handlers = handlers->next)
		if (handlers->accepted_data_types & data_type_mask)
			return 1;
	return 0;
}

static inline void profiling_msg_start(struct sip_msg *msg, int route_type,
	const char *route_name, int depth)
{
	profiling_handlers_t *handlers;
	for (handlers = profiling_handlers; handlers; handlers = handlers->next)
		if ((handlers->accepted_data_types & PROFILING_DATA_TYPE_SCRIPT) &&
			handlers->on_start)
			handlers->on_start(PROFILING_DATA_TYPE_SCRIPT, route_name,
				route_type, depth, msg);
}

static inline void profiling_msg_end(struct sip_msg *msg, int route_type,
	const char *route_name, int depth, int status)
{
	profiling_handlers_t *handlers;
	for (handlers = profiling_handlers; handlers; handlers = handlers->next)
		if ((handlers->accepted_data_types & PROFILING_DATA_TYPE_SCRIPT) &&
			handlers->on_end)
			handlers->on_end(PROFILING_DATA_TYPE_SCRIPT, route_name,
				route_type, depth, status, msg);
}

static inline void profiling_route_enter(struct sip_msg *msg, int route_type,
	const char *route_name, const char *file, int line,
	int depth)
{
	profiling_handlers_t *handlers;
	for (handlers = profiling_handlers; handlers; handlers = handlers->next)
		if ((handlers->accepted_data_types & PROFILING_DATA_TYPE_SCRIPT) &&
			handlers->on_enter)
			handlers->on_enter(PROFILING_DATA_TYPE_SCRIPT, route_name,
				route_type, depth, file, line, msg);
}

static inline void profiling_route_exit(struct sip_msg *msg, int route_type,
	const char *route_name, const char *file, int line,
	int depth, int status)
{
	profiling_handlers_t *handlers;
	for (handlers = profiling_handlers; handlers; handlers = handlers->next)
		if ((handlers->accepted_data_types & PROFILING_DATA_TYPE_SCRIPT) &&
			handlers->on_exit)
			handlers->on_exit(PROFILING_DATA_TYPE_SCRIPT, route_name,
				route_type, depth, file, line, status, msg);
}

static inline int profiling_get_ctx(profiling_ctx_t *ctx)
{
	profiling_handlers_t *handlers;

	for (handlers = profiling_handlers; handlers; handlers = handlers->next)
		if ((handlers->accepted_data_types & PROFILING_DATA_TYPE_SCRIPT) &&
			handlers->get_ctx && handlers->get_ctx(ctx))
			return 1;

	return 0;
}

static inline int profiling_set_ctx(const profiling_ctx_t *ctx)
{
	profiling_handlers_t *handlers;
	int ret = 0;

	for (handlers = profiling_handlers; handlers; handlers = handlers->next)
		if ((handlers->accepted_data_types & PROFILING_DATA_TYPE_SCRIPT) &&
			handlers->set_ctx && handlers->set_ctx(ctx))
			ret = 1;

	return ret;
}



/**************** structs and functions for process profiling **************/

static inline char * ss_merge256( char *s1, char *s2)
{
	static char b[256], *c;
	c = stpncpy( b, s1, 255);
	strncpy( c, s2, 255-(c-b));
	b[255] = 0;
	return b;
}
static inline char * sss_merge256( char *s1, char *s2, char *s3)
{
	static char b[256], *c;
	c = stpncpy( b, s1, 255);
	c = stpncpy( c, s2, 255-(c-b));
	strncpy( c, s3, 255-(c-b));
	b[255] = 0;
	return b;
}


/* Keep enough room for deeply nested proc enter() flows. */
#define PROFILING_PROC_STACK_MAX 16
typedef struct profiling_proc_pending {
	const char *name;
	const char *file;
	int line;
	uint16_t depth;
	uint8_t is_start;
} profiling_proc_pending_t;

/* stack for pending start+enter, waiting to be flushed */
extern profiling_proc_pending_t
	profiling_proc_pending_stack[PROFILING_PROC_STACK_MAX];
extern uint16_t profiling_proc_pending_no;

/* depth, as number of "enter"s done by process profiling */
extern uint16_t proc_depth;


#define profiling_proc_level_enabled(_level) \
	( (_level!=LEVEL_OFF) && (_level<=pt[process_no].profiling_proc_level) )

static inline void profiling_proc_flush_pending(void)
{
	uint16_t i;
	profiling_handlers_t *handlers;
	profiling_proc_pending_t *rec;

	if (!profiling_proc_pending_no)
		return;

	for (i = 0; i < profiling_proc_pending_no; i++) {
		rec = &profiling_proc_pending_stack[i];

		for (handlers = profiling_handlers; handlers;
			handlers = handlers->next) {
			if (!(handlers->accepted_data_types &
				PROFILING_DATA_TYPE_PROC))
				continue;

			if (rec->is_start) {
				if (handlers->on_start)
					handlers->on_start(PROFILING_DATA_TYPE_PROC,
						rec->name, pt[process_no].type, i, NULL);
			} else {
				if (handlers->on_enter)
					handlers->on_enter(PROFILING_DATA_TYPE_PROC,
						rec->name, pt[process_no].type,
						i, rec->file, rec->line, NULL);
			}
		}
	}

	profiling_proc_pending_no = 0;
}


static inline void profiling_proc_start(enum profiling_proc_level level,
	int with_next)
{
	profiling_handlers_t *handlers;

	if (!profiling_proc_level_enabled(level))
		return;

	proc_depth = 0;
	if (with_next) {
		profiling_proc_pending_stack[proc_depth].name =
			pt[process_no].desc;
		profiling_proc_pending_stack[proc_depth].file = NULL;
		profiling_proc_pending_stack[proc_depth].line = 0;
		profiling_proc_pending_stack[proc_depth].is_start = 1;
		profiling_proc_pending_no = 1;
		return;
	}

	for (handlers = profiling_handlers; handlers; handlers = handlers->next)
		if ((handlers->accepted_data_types & PROFILING_DATA_TYPE_PROC) &&
			handlers->on_start)
			handlers->on_start(PROFILING_DATA_TYPE_PROC, pt[process_no].desc,
				pt[process_no].type, proc_depth, NULL);
}


static inline void profiling_proc_end(enum profiling_proc_level level,
	int status)
{
	profiling_handlers_t *handlers;

	if (!profiling_proc_level_enabled(level))
		return;

	if (profiling_proc_pending_no) {
		profiling_proc_pending_no--;
		return;
	}

	for (handlers = profiling_handlers; handlers; handlers = handlers->next)
		if ((handlers->accepted_data_types & PROFILING_DATA_TYPE_PROC) &&
			handlers->on_end)
			handlers->on_end(PROFILING_DATA_TYPE_PROC, pt[process_no].desc,
				pt[process_no].type, proc_depth, status, NULL);
}


#define profiling_proc_enter( _level, _name, _with_next ) \
	_profiling_proc_enter( _level, _name, __func__, __LINE__, _with_next)
static inline void _profiling_proc_enter(enum profiling_proc_level level,
	const char *name, const char *file, int line, int with_next)
{
	profiling_handlers_t *handlers;

	if (!profiling_proc_level_enabled(level))
		return;

	proc_depth++;

	if (with_next) {
		if (proc_depth < PROFILING_PROC_STACK_MAX) {
			profiling_proc_pending_stack[profiling_proc_pending_no].name =
				name;
			profiling_proc_pending_stack[profiling_proc_pending_no].file =
				file;
			profiling_proc_pending_stack[profiling_proc_pending_no].line =
				line;
			profiling_proc_pending_stack[profiling_proc_pending_no].is_start =
				0;
			profiling_proc_pending_no++;
		}
		return;
	}

	profiling_proc_flush_pending();

	for (handlers = profiling_handlers; handlers; handlers = handlers->next)
		if ((handlers->accepted_data_types & PROFILING_DATA_TYPE_PROC) &&
			handlers->on_enter)
			handlers->on_enter(PROFILING_DATA_TYPE_PROC, name,
				pt[process_no].type, proc_depth, file, line, NULL);
}


#define profiling_proc_exit( _level, _name, _status ) \
	_profiling_proc_exit( _level, _name, __func__, __LINE__, _status)
static inline void _profiling_proc_exit(enum profiling_proc_level level,
	const char *name, const char *file, int line, int status)
{
	profiling_handlers_t *handlers;

	if (!profiling_proc_level_enabled(level))
		return;

	proc_depth--;

	if (profiling_proc_pending_no) {
		profiling_proc_pending_no--;
		return;
	}

	for (handlers = profiling_handlers; handlers; handlers = handlers->next)
		if ((handlers->accepted_data_types & PROFILING_DATA_TYPE_PROC) &&
			handlers->on_exit)
			handlers->on_exit(PROFILING_DATA_TYPE_PROC, name,
				pt[process_no].type, proc_depth, file, line, status, NULL);
}



#endif /* PROFILING_H */
