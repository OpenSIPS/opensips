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

#define ENABLE_SH_LOGGING

#define MAX_SHLOG_SIZE 50 /* longer log lines will get truncated */

/**
 * To be freely extended by any piece of OpenSIPS code which makes use of
 * struct history logging
 */
#define SH_ALL_VERBS(VERB_FUN) \
	VERB_FUN(TCP_SEND2CHILD) \
	VERB_FUN(TCP_SEND2MAIN) \
	VERB_FUN(TCP_REF) \
	VERB_FUN(TCP_UNREF) \
	VERB_FUN(TCP_DESTROY) \

#define __SH_VERB_TO_ENUM(ENUM) ENUM,
enum struct_hist_verb {
	SH_VERB_ZERO,
	SH_ALL_VERBS(__SH_VERB_TO_ENUM)
	SH_VERB_LAST
};

struct struct_hist_action {
	enum struct_hist_verb verb;
	utime_t t;
	int pid;
	char log[MAX_SHLOG_SIZE];
};

#define ACTIONS_SIZE 5
struct struct_hist {
	void *obj;
	char *obj_name;
	utime_t created;

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
	char *obj_name;

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
 * Initializes a global holder for the histories of all logically linked
 * structs that one intends to troubleshoot
 *
 * @obj_name: A name for the structs which will be troubleshooted
 * @window_size: (gliding window) - the max number of retained histories
 *
 * WARNING: a "window_size" of 0 (infinite) is essentially a memory leak,
 * use with caution!
 */
struct struct_hist_list *shl_init(char *obj_name, int window_size);

/**
 * Frees up the global history holder, along with all of its content
 */
void shl_destroy(struct struct_hist_list *shl);

/**
 * Create a new history tracker, usually for each newly allocated struct.
 *
 * @obj: The corresponding struct address. This value will be embedded into
 *       the history object, to allow look-ups inside gdb
 * @list: global holder where this history will be pushed
 */
struct struct_hist *sh_push(void *obj, struct struct_hist_list *list);

/**
 * Unreference a history struct. Depending on whether it is still in the
 * gliding window or not, it may also get freed immediately.
 *
 * @sh: a struct history tracker
 * @list: the global holder of histories
 */
void sh_unref(struct struct_hist *sh, struct struct_hist_list *list);

/**
 * Record a log line to the history of a struct. The max length of a line is
 * MAX_SHLOG_SIZE - any expanded lines longer than this will get truncated.
 *
 * @sh: a struct history tracker
 * @verb: the type of the log line recorded (taken from SH_ALL_VERBS)
 * @fmt: C format string
 */
int sh_log(struct struct_hist *sh, enum struct_hist_verb verb, char *fmt, ...);
#endif

#endif /* __STRUCT_HIST_H__ */
