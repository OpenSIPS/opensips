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
 *
 * History:
 * --------
 *
 *  2003-04-12  FORCE_RPORT_T added (andrei)
 *  2003-04-22  strip_tail added (jiri)
 *  2003-10-10  >,<,>=,<=, != and MSGLEN_O added (andrei)
 *  2003-10-28  FORCE_TCP_ALIAS added (andrei)
 *  2006-03-02  new field "line" in action struct - the cfg line (bogdan)
 *  2006-12-22  support for script and branch flags added (bogdan)
 */

/*!
 * \file
 * \brief SIP routing engine - structure management
 */


#ifndef route_struct_h
#define route_struct_h

#define EXPR_DROP -127  /* used only by the expression and if evaluator */
/*
 * Other important values (no macros for them yet):
 * expr true = 1
 * expr false = 0 (used only inside the expression and if evaluator)
 *
 * action continue  or if used in condition true = 1
 * action drop/quit/stop script processing = 0
 * action error or if used in condition false = -1 (<0 and !=EXPR_DROP)
 *
 */

/*! \todo Add documentation for all ENUMs in this file. */
enum { EXP_T=1, ELEM_T };
enum { AND_OP=1, OR_OP, NOT_OP, EVAL_OP, PLUS_OP, MINUS_OP, DIV_OP, MULT_OP, MODULO_OP,
		BAND_OP, BOR_OP, BXOR_OP, BNOT_OP, BLSHIFT_OP, BRSHIFT_OP };
enum { EQUAL_OP=20, MATCH_OP, NOTMATCH_OP, MATCHD_OP, NOTMATCHD_OP,
	GT_OP, LT_OP, GTE_OP, LTE_OP, DIFF_OP, VALUE_OP, NO_OP };
enum { METHOD_O=1, PROTO_O, MSGLEN_O, DEFAULT_O, ACTION_O,
	   EXPR_O, NUMBER_O, NUMBERV_O, STRINGV_O, RETCODE_O, SCRIPTVAR_O};

enum { FORWARD_T=1, SEND_T, ASSERT_T, DROP_T, LOG_T, ERROR_T, ROUTE_T, EXEC_T,
		SET_HOST_T, SET_HOSTPORT_T, SET_USER_T, SET_USERPASS_T,
		SET_PORT_T, SET_URI_T, IF_T, MODULE_T, AMODULE_T,
		SETFLAG_T, RESETFLAG_T, ISFLAGSET_T ,
		SETBFLAG_T, RESETBFLAG_T, ISBFLAGSET_T ,
		LEN_GT_T, PREFIX_T, STRIP_T,STRIP_TAIL_T,
		APPEND_BRANCH_T,
		REMOVE_BRANCH_T,
		REVERT_URI_T,
		FORCE_RPORT_T,
		FORCE_LOCAL_RPORT_T,
		SET_ADV_ADDR_T,
		SET_ADV_PORT_T,
		FORCE_TCP_ALIAS_T,
		FORCE_SEND_SOCKET_T,
		SERIALIZE_BRANCHES_T,
		NEXT_BRANCHES_T,
		RETURN_T,
		EXIT_T,
		SWITCH_T, CASE_T, DEFAULT_T, SBREAK_T,
		WHILE_T, FOR_EACH_T,
		SET_DSTURI_T, SET_DSTHOST_T, SET_DSTPORT_T, RESET_DSTURI_T, ISDSTURISET_T,
		EQ_T, COLONEQ_T, PLUSEQ_T, MINUSEQ_T, DIVEQ_T, MULTEQ_T, MODULOEQ_T,
		BANDEQ_T, BOREQ_T, BXOREQ_T, USE_BLACKLIST_T, UNUSE_BLACKLIST_T,
		SET_TIME_STAMP_T,RESET_TIME_STAMP_T, DIFF_TIME_STAMP_T,
		PV_PRINTF_T,
		CACHE_STORE_T, CACHE_FETCH_T, CACHE_COUNTER_FETCH_T, CACHE_REMOVE_T,
		CACHE_ADD_T,CACHE_SUB_T,CACHE_RAW_QUERY_T,
		XDBG_T, XLOG_T,
		RAISE_EVENT_T, SUBSCRIBE_EVENT_T,
		CONSTRUCT_URI_T,
		GET_TIMESTAMP_T, SCRIPT_TRACE_T, ASYNC_T, LAUNCH_T,
		IS_MYSELF_T
};
enum { NOSUBTYPE=0, STRING_ST, NET_ST, NUMBER_ST, IP_ST, RE_ST, PROXY_ST,
		EXPR_ST, ACTIONS_ST, CMD_ST, ACMD_ST, MODFIXUP_ST,
		STR_ST, SOCKID_ST, SOCKETINFO_ST, SCRIPTVAR_ST, NULLV_ST,
		BLACKLIST_ST, SCRIPTVAR_ELEM_ST};

struct expr;
#include "pvar.h"

typedef struct operand {
	int type;
	union operand_val {
		struct expr* expr;
		str s;
		int n;
		pv_spec_t* spec;
		void* data;
	} v;
} operand_t, *operand_p;


struct expr{
	int type; /*!< exp, exp_elem */
	int op; /*!< and, or, not | ==,  =~ */
	operand_t left;
	operand_t right;
};

typedef struct action_elem_ {
	int type;
	union {
		long number;
		char* string;
		void* data;
		str s;
		pv_spec_t* item;
	} u;
} action_elem_t, *action_elem_p;

/*! \brief increase MAX_ACTION_ELEMS to support more module function parameters
   if you change this define, you need also to change the assignment in
   the action.c file
 */
#define MAX_ACTION_ELEMS	7
struct action{
	int type;  /* forward, drop, log, send ...*/
	action_elem_t elem[MAX_ACTION_ELEMS];
	int line;
	char *file;
	struct action* next;
};



struct expr* mk_exp(int op, struct expr* left, struct expr* right);
struct expr* mk_elem(int op, int leftt, void *leftd, int rightt, void *rightd);
struct action* mk_action(int type, int n, action_elem_t *elem,
		int line, char *file);
struct action* append_action(struct action* a, struct action* b);


void print_action(struct action* a);
void print_expr(struct expr* exp);
void print_actions(struct action* a);
int is_mod_func_used(struct action *a, char *name, int param_no);
int is_mod_async_func_used(struct action *a, char *name, int param_no);




#endif

