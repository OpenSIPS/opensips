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

#include "../../timer.h"

/**
 * Generic struct debugging support.  Some major use cases:
 *   - troubleshooting bugs related to reference counted structures, including:
 *     * mem corruption due to free() operations on lingering references
 *     * too many / too little ref operations
 *   - logging and keeping the last N events in memory and only dumping them
 *     on a certain condition (e.g. occurrence of a bug)
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

#define MAX_SHLOG_SIZE 100 /* longer log lines will get truncated */

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
	VERB_FUN(DLG_REF) \
	VERB_FUN(DLG_UNREF) \
	VERB_FUN(DLG_DESTROY) \

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

struct struct_hist;
struct struct_hist_list;

#define FLUSH_LIMIT 2000
#define flushable(sh) (sh->len == FLUSH_LIMIT)

#ifndef DBG_STRUCT_HIST
#define shl_init(...) NULL
#define shl_destroy(...)
#define sh_push(...) NULL
#define sh_unref(...)
#define _sh_log(...) ({0;})
#define sh_log _sh_log
#define sh_flush(...)
#else

/**
 * Initializes a global holder for the histories of all logically linked
 * structs that one intends to troubleshoot
 *
 * @obj_name: A name for the structs which will be troubleshooted
 * @window_size: (gliding window) - the max number of retained histories
 * @auto_logging: if true, each struct_hist object will log info as it grows
 * @init_actions_sz: initial allocation size of each object's actions array
 *
 * WARNING: a "window_size" of 0 (infinite) is essentially a memory leak,
 * use with caution!
 */
struct struct_hist_list *_shl_init(char *obj_name, int window_size,
			int auto_logging, int init_actions_sz);
#define shl_init(nm, wsz, autolog) _shl_init(nm, wsz, autolog, 5)

/**
 * Flush all contents of a struct hist list to the log.  Useful when collecting
 * data over time in a rotating log list under high traffic volume conditions
 * and only flushing the logs once a certain condition hits (e.g. bug occurs).
 *
 * @shl: a struct history list
 */
void sh_list_flush(struct struct_hist_list *shl);

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
 * @refs: the amount of references to the new object kept by the calling code
 */
struct struct_hist *_sh_push(void *obj, struct struct_hist_list *list, int refs);
#define sh_push(obj, list) _sh_push(obj, list, 1)

/**
 * Unreference a history struct. Depending on whether it is still in the
 * gliding window or not, it may also get freed immediately.
 *
 * @sh: a struct history tracker
 */
void sh_unref(struct struct_hist *sh);

/**
 * Record a log line to the history of a struct. The max length of a line is
 * MAX_SHLOG_SIZE - any expanded lines longer than this will get truncated.
 *
 * @sh: a struct history tracker
 * @verb: the type of the log line recorded (taken from SH_ALL_VERBS)
 * @fmt: C format string
 */
int _sh_log(struct struct_hist *sh, enum struct_hist_verb verb, char *fmt, ...);
#define sh_log(sh, verb, fmt, args...) \
	do { \
		_sh_log(sh, verb, "%s:%s:%d: "fmt, \
		        __FILE__, __FUNCTION__, __LINE__, ##args); \
	} while (0)

/**
 * Force the contents of a struct hist to be flushed to the log.  Useful in
 * high-volume traffic conditions, where only certain (dubious) objects
 * must be logged.
 *
 * @sh: a struct history tracker
 */
void sh_flush(struct struct_hist *sh);

#endif

#endif /* __STRUCT_HIST_H__ */
