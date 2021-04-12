/*
 * Copyright (C) 2001-2003 FhG Fokus
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
 */

/*!
 * \file
 * \brief OpenSIPS generic functions
 */


#ifndef action_h
#define action_h

#include "parser/msg_parser.h"
#include "route.h"
#include "route_struct.h"

#define ACT_FL_EXIT     (1<<0)
#define ACT_FL_RETURN   (1<<1)
#define ACT_FL_DROP     (1<<2)
#define ACT_FL_TBCONT   (1<<3)
#define ACT_FL_BREAK    (1<<4)

extern int action_flags;
extern int use_script_trace;
extern int script_trace_log_level;
extern char *script_trace_info;
extern pv_elem_t script_trace_elem;

#define LONGEST_ACTION_SIZE		5

typedef struct {
	struct action* a;
	int a_time;
} action_time;

extern action_time longest_action[LONGEST_ACTION_SIZE];
extern int min_action_time;

/* the current route call stack, containing route names */
extern char *route_stack[];
extern int route_stack_size;

int do_action(struct action* a, struct sip_msg* msg);
int run_top_route(struct script_route sr, struct sip_msg* msg);
int run_action_list(struct action* a, struct sip_msg* msg);
int _run_actions(struct action *a, struct sip_msg *msg);

/* run the error route with correct handling */
extern int inside_error_route;
void run_error_route(struct sip_msg* msg, int force_reset);

#define script_trace(class, action, msg, file, line) \
	do { \
		if (use_script_trace) \
			__script_trace(class, action, msg, file, line); \
	} while (0)

void __script_trace(char *class, char *action, struct sip_msg *msg,
		char *file, int line);

typedef int (*param_getf_t)(struct sip_msg*, pv_param_t*, pv_value_t*, void *, void *);

/**
 * Increase the recursion level of route parameters and/or the route call stack
 *
 * @rt_name: if not NULL, a new route name will be pushed to the route stack.
 *           A leading '!' may be provided in order to force that exact name
 *             (e.g. avoid "route[error_route]", rather just "error_route")
 * @params: data to push (the values of each parameter)
 * @extra: optional, extra data
 * @getf: the function to be invoked when extracting each parameter
 */
void route_params_push_level(char *rt_name, void *params, void *extra, param_getf_t getf);
void route_params_pop_level(void);
int route_params_run(struct sip_msg *msg,  pv_param_t *ip, pv_value_t *res);


struct sip_msg* get_dummy_sip_msg(void);
void release_dummy_sip_msg( struct sip_msg* req);
int is_dummy_sip_msg(struct sip_msg *req);

#endif
