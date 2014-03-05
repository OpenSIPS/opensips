/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*!
 * \file
 * \brief OpenSIPS generic functions
 */


#ifndef action_h
#define action_h

#include "parser/msg_parser.h"
#include "route_struct.h"

#define ACT_FL_EXIT		1
#define ACT_FL_RETURN	2
#define ACT_FL_DROP		4

extern int action_flags;
extern int use_script_trace;

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

#define script_trace(class, action, msg, line) \
	do { \
		if (use_script_trace) \
			__script_trace(class, action, msg, line); \
	} while (0)

void __script_trace(char *class, char *action, struct sip_msg *msg, int line);

#endif
