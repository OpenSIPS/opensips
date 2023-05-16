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
	char *name;
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
	/* script version (due to reload) */
	unsigned int version;
};


struct script_route_ref {
	/* the name of the route, kept both with len and null terminated */
	/* the actual string is allocated together with this map structure */
	str name;
	/* the index of the route in the script_route array
	 * it is set to -1 if the route does not exist anymore */
	int idx;
	/* type of route */
	int type;
	union {
		/* how many times this script route was referentiated
		 * by opensips code (by looking the name) */
		unsigned int refcnt;
		/* script version */
		unsigned int version;
	} u;
	/* linking into per-process list of ref's. this is not used
	 * if the ref resides in SHM */
	struct script_route_ref *next;
};


extern struct os_script_routes *sroutes;

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

extern str str_route;
extern str str_request_route;
extern str str_failure_route;
extern str str_onreply_route;
extern str str_branch_route;
extern str str_error_route;
extern str str_local_route;
extern str str_startup_route;
extern str str_timer_route;
extern str str_event_route;

extern int route_type;

/**
 * Extract the type of the top-level @route_type
 *
 * @type: string representation of the route's type
 * @has_name: whether the top route has a name or not
 */
void get_top_route_type(str *type, int *has_name);

void get_route_type(int idx, str *type);
void get_route_name(int idx, str *name);

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

#define ref_script_route_is_valid(_ref) \
	((_ref)!=NULL && (_ref)->idx!=-1)

#define ref_script_route_check_and_update(_ref) \
	((_ref)!=NULL && (\
		((_ref)->u.version==sroutes->version)\
		||\
		(update_script_route_ref(_ref)==0 && ((_ref)->u.version=sroutes->version))\
	) && (_ref)->idx!=-1)

#define ref_script_route_name(_ref) \
	((_ref)?(_ref)->name.s:"n/a")

#define ref_script_route_idx(_ref) \
	((_ref)?(_ref)->idx:-1)


struct os_script_routes* new_sroutes_holder( int inc_ver );

void free_route_lists(struct os_script_routes *sr);


int run_startup_route(void);

int get_script_route_idx( char* name, struct script_route *sr,
		int size, int set);

int get_script_route_ID_by_name(char *name,
		struct script_route *sr, int size);

int get_script_route_ID_by_name_str(str *name,
		struct script_route *sr, int size);

struct script_route_ref * ref_script_route_by_name(char *name,
		struct script_route *sr, int size,
		int type, int in_shm);

struct script_route_ref * ref_script_route_by_name_str(str *name,
		struct script_route *sr, int size,
		int type, int in_shm);

void unref_script_route(struct script_route_ref *ref);

int update_script_route_ref(struct script_route_ref *ref);

void update_all_script_route_refs(void);

struct script_route_ref *dup_ref_script_route_in_shm(
		struct script_route_ref *ref, int from_shm);

void print_script_route_refs(void);

int is_script_func_used(const char *name, int param_no);

int is_script_async_func_used(const char *name, int param_no);


void push(struct action* a, struct action** head);

void print_rl(struct os_script_routes *srs);

int fix_rls(void);

int check_rls(void);

int eval_expr(struct expr* e, struct sip_msg* msg, pv_value_t *val);


#endif
