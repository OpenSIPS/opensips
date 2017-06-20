/*
 * Copyright (C) 2017 OpenSIPS Solutions
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

#ifndef __STRUCT_HIST_H__
#define __STRUCT_HIST_H__

#include "../../locking.h"
#include "../../timer.h"

#include "../list.h"

/**
 * Generic struct debugging support. Especially useful for troubleshooting
 * bugs related to reference counted structures, including:
 *   - mem corruption due to free() operations on lingering references
 *   - too many / too little ref operations
 *
 * How To use:
 *  - before the forking phase, use shl_init() to initialize a global history
 *    list for the code you are about to troubleshoot
 *
 *  - for each new object you want to track, use sh_push() and store the
 *    resulting object history inside this object (e.g. obj->hist)
 *
 *  - log any relevant events during the object's lifetime with sh_log()
 *
 *  - call sh_unref() upon deletion of the object - its history will still
 *    remain available inside the global history list for a while
 */

#define FULL_LOGGING

/**
 * To be freely extended by any piece of OpenSIPS code which makes use of
 * struct history logging
 */
enum struct_hist_verb {
	ZER0,

	TCP_SEND2CHILD,
	TCP_SEND2MAIN,

	TCP_REF,
	TCP_UNREF,
	TCP_DESTROY,
};

#define verb2str(v) ( \
		v == TCP_SEND2CHILD ? "TCP_SEND2CHILD": \
		v == TCP_SEND2MAIN ? "TCP_SEND2MAIN": \
		v == TCP_REF ? "TCP_REF": \
		v == TCP_UNREF ? "TCP_UNREF": \
		v == TCP_DESTROY ? "TCP_DESTROY" : "!!FOOBAR!!")

struct struct_hist_action {
	enum struct_hist_verb verb;
	utime_t t;
	int pid;
	char *log;
};

#define ACTIONS_SIZE 5
struct struct_hist {
	void *obj;
	int ref;

	struct struct_hist_action *actions;
	int len;
	int max_len;
	int flush_offset;

	gen_lock_t wlock;

	struct list_head list;
};

#define FLUSH_LIMIT 2000
#define flushable(sh) (sh->len == FLUSH_LIMIT)

struct struct_hist_list {
	struct list_head objects;
	int len;
	int win_sz;
	long long total_obj;

	gen_lock_t wlock;
};

#ifndef DBG_STRUCT_HIST
#define shl_init(...) NULL
#define shl_destroy(...)
#define sh_push(...) NULL
#define sh_unref(...)
#define sh_log(...) ({0;})
#else
/**
 * WARNING: a history window_size = 0 (infinite) is essentially a memory leak,
 * use with caution!
 */
struct struct_hist_list *shl_init(int window_size);
void shl_destroy(struct struct_hist_list *shl);

struct struct_hist *sh_push(void *obj, struct struct_hist_list *list);
void sh_unref(struct struct_hist *sh, struct struct_hist_list *list);

#define MAX_SHLOG_SIZE 50 /* anything above will get truncated */
int sh_log(struct struct_hist *sh, enum struct_hist_verb verb, char *fmt, ...);
#endif

#endif /* __STRUCT_HIST_H__ */
