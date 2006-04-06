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


#ifndef action_h
#define action_h

#include "parser/msg_parser.h"
#include "route_struct.h"

#define ACT_FL_EXIT		1
#define ACT_FL_RETURN	2
#define ACT_FL_DROP		4

extern int action_flags;

int do_action(struct action* a, struct sip_msg* msg);
int run_top_route(struct action* a, struct sip_msg* msg);
int run_action_list(struct action* a, struct sip_msg* msg);

#endif
