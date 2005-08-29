/*
 * $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#ifndef route_h
#define route_h

#include <sys/types.h>
#include <regex.h>
#include <netdb.h>

#include "config.h"
#include "error.h"
#include "route_struct.h"
#include "parser/msg_parser.h"

/*#include "cfg_parser.h" */


/* main "script table" */
extern struct action* rlist[RT_NO];
/* main reply route table */
extern struct action* onreply_rlist[ONREPLY_RT_NO];
extern struct action* failure_rlist[FAILURE_RT_NO];
extern struct action* branch_rlist[BRANCH_RT_NO];

#define REQUEST_ROUTE 1  /* Request route block */
#define FAILURE_ROUTE 2  /* Negative-reply route block */
#define ONREPLY_ROUTE 4  /* Received-reply route block */
#define BRANCH_ROUTE  8  /* Sending-branch route block */

extern int route_type;

#define set_route_type(_new_type) \
	do{\
		route_type=_new_type;\
	}while(0)

#define swap_route_type(_backup, _new_type) \
	do{\
		_backup=route_type;\
		route_type=_new_type;\
	}while(0)


void push(struct action* a, struct action** head);
int add_actions(struct action* a, struct action** head);
void print_rl();
int fix_rls();
int check_rls();

int eval_expr(struct expr* e, struct sip_msg* msg);






#endif
