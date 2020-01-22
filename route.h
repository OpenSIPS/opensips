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
 * \brief SIP routing engine
 */

#ifndef route_h
#define route_h

#include <sys/types.h>
#include <regex.h>
#include <netdb.h>

#include "pvar.h"
#include "config.h"
#include "error.h"
#include "route_struct.h"
#include "parser/msg_parser.h"


/*
 * Definition of a script route
 */
struct script_route{
	char *name;            /* name of the route */
	struct action *a;      /* the actions tree defining the route logic */
};

struct script_timer_route{
	unsigned int interval;
	struct action* a;
};

struct os_script_routes {
	/* request routing script table  */
	struct script_route request[RT_NO];
	/* reply routing table */
	struct script_route onreply[ONREPLY_RT_NO];
	/* failure routes */
	struct script_route failure[FAILURE_RT_NO];
	/* branch routes */
	struct script_route branch[BRANCH_RT_NO];
	/* local requests route */
	struct script_route local;
	/* error route */
	struct script_route error;
	/* startup route */
	struct script_route startup;
	/* timer route */
	struct script_timer_route timer[TIMER_RT_NO];
	/* event route */
	struct script_route event[EVENT_RT_NO];
};


#define REQUEST_ROUTE 1   /*!< Request route block */
#define FAILURE_ROUTE 2   /*!< Negative-reply route block */
#define ONREPLY_ROUTE 4   /*!< Received-reply route block */
#define BRANCH_ROUTE  8   /*!< Sending-branch route block */
#define ERROR_ROUTE  16   /*!< Error-handling route block */
#define LOCAL_ROUTE  32   /*!< Local-requests route block */
#define STARTUP_ROUTE 64  /*!< Startup route block */
#define TIMER_ROUTE  128  /*!< Timer route block */
#define EVENT_ROUTE  256  /*!< Event route block */
#define ALL_ROUTES \
	(REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE| \
	 ERROR_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE)

extern struct os_script_routes *sroutes;
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

#define is_route_type(_type) (route_type==_type)

struct os_script_routes* new_sroutes_holder(void);

void free_route_lists(struct os_script_routes *sr);


int run_startup_route(void);

int get_script_route_idx( char* name, struct script_route *sr,
		int size, int set);

int get_script_route_ID_by_name(char *name,
		struct script_route *sr, int size);

int get_script_route_ID_by_name_str(str *name,
		struct script_route *sr, int size);

int is_script_func_used( char *name, int param_no);

int is_script_async_func_used( char *name, int param_no);


void push(struct action* a, struct action** head);

void print_rl(struct os_script_routes *srs);

int fix_rls(void);

int check_rls(void);

int eval_expr(struct expr* e, struct sip_msg* msg, pv_value_t *val);


#endif
