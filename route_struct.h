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
enum { DEFAULT_O=1, ACTION_O, EXPR_O, NUMBER_O, NUMBERV_O, STRINGV_O, SCRIPTVAR_O};

enum {  ASSERT_T, DROP_T, LOG_T, ERROR_T, ROUTE_T, EXEC_T,
		IF_T, CMD_T, AMODULE_T,
		LEN_GT_T,
		RETURN_T,
		EXIT_T,
		SWITCH_T, CASE_T, DEFAULT_T, BREAK_T,
		WHILE_T, FOR_EACH_T,
		EQ_T, COLONEQ_T, PLUSEQ_T, MINUSEQ_T, DIVEQ_T, MULTEQ_T, MODULOEQ_T,
		BANDEQ_T, BOREQ_T, BXOREQ_T,
		XDBG_T, XLOG_T,
		ASYNC_T, LAUNCH_T,
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
 */
#define MAX_ACTION_ELEMS	9
struct action{
	int type;  /* forward, drop, log, send ...*/
	action_elem_t elem[MAX_ACTION_ELEMS];
	int line;
	char *file;
	struct action* next;
};

#define assignop_str(op) ( \
	(op) == EQ_T ?       "=" : \
	(op) == COLONEQ_T ?  ":=" : \
	(op) == PLUSEQ_T ?   "+=" : \
	(op) == MINUSEQ_T ?  "-=" : \
	(op) == DIVEQ_T ?    "/=" : \
	(op) == MULTEQ_T ?   "*=" : \
	(op) == MODULOEQ_T ? "%=" : \
	(op) == BANDEQ_T ?   "&=" : \
	(op) == BOREQ_T ?    "|=" : \
	(op) == BXOREQ_T ?   "^=" : "unknown")

struct expr* mk_exp(int op, struct expr* left, struct expr* right);
struct expr* mk_elem(int op, int leftt, void *leftd, int rightt, void *rightd);
struct action* mk_action(int type, int n, action_elem_t *elem,
		int line, char *file);
struct action* append_action(struct action* a, struct action* b);
void free_action_list( struct action *a);


void print_action(struct action* a);
void print_expr(struct expr* exp);
void print_actions(struct action* a);
int is_mod_func_used(struct action *a, char *name, int param_no);
int is_mod_async_func_used(struct action *a, char *name, int param_no);

#endif
