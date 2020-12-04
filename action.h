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
#include "route_struct.h"

#define ACT_FL_EXIT     (1<<0)
#define ACT_FL_RETURN   (1<<1)
#define ACT_FL_DROP     (2<<2)
#define ACT_FL_TBCONT   (2<<3)

extern int action_flags;
extern int use_script_trace;

extern action_elem_p route_params[MAX_REC_LEV];
extern int route_params_number[MAX_REC_LEV];
extern int route_rec_level;

#define LONGEST_ACTION_SIZE		5

typedef struct {
	struct action* a;
	int a_time;
} action_time;

extern action_time longest_action[LONGEST_ACTION_SIZE];
extern int min_action_time;

int do_action(struct action* a, struct sip_msg* msg);
int run_top_route(struct action* a, struct sip_msg* msg);
int run_action_list(struct action* a, struct sip_msg* msg);
void run_error_route(struct sip_msg* msg, int force_reset);

#define script_trace(class, action, msg, file, line) \
	do { \
		if (use_script_trace) \
			__script_trace(class, action, msg, file, line); \
	} while (0)

void __script_trace(char *class, char *action, struct sip_msg *msg,
		char *file, int line);


struct sip_msg* get_dummy_sip_msg(void);
void release_dummy_sip_msg( struct sip_msg* req);

#endif
