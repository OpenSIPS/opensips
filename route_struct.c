/*
 * route structures helping functions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2003-01-29  src_port introduced (jiri)
 *  2003-03-19  replaced all mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2003-04-12  FORCE_RPORT_T added (andrei)
 *  2003-10-02  added SET_ADV_ADDRESS & SET_ADV_PORT (andrei)
 *  2006-03-02  mk_action -> mk_action_2p and mk_action3 -> mk_action_3p;
 *              both functions take as extra param the cfg line (bogdan)
 *  2006-12-22  support for script and branch flags added (bogdan)
 */

/*!
 * \file
 * \brief SIP routing engine - structure helping functions
 */

#include  "route_struct.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_module.h"
#include "dprint.h"
#include "ip_addr.h"
#include "mem/mem.h"
#include "ut.h" /* ZSW() */

struct expr* mk_exp(int op, struct expr* left, struct expr* right)
{
	struct expr * e;
	e=(struct expr*)pkg_malloc(sizeof (struct expr));
	if (e==0) goto error;
	e->type=EXP_T;
	e->op=op;
	e->left.v.expr=left;
	e->right.v.expr=right;
	return e;
error:
	LM_CRIT("pkg memory allocation failure\n");
	return 0;
}


struct expr* mk_elem(int op, int leftt, void *leftd, int rightt, void *rightd)
{
	struct expr * e;
	e=(struct expr*)pkg_malloc(sizeof (struct expr));
	if (e==0) goto error;
	memset(e, 0, sizeof(struct expr));
	e->type=ELEM_T;
	e->op=op;
	e->left.type    = leftt;
	e->left.v.data  = leftd;
	if((e->left.type==STR_ST || e->left.type==STRINGV_O)
			&& e->left.v.s.s!=NULL)
		e->left.v.s.len = strlen(e->left.v.s.s);
	e->right.type   = rightt;
	e->right.v.data = rightd;
	if((e->right.type==STR_ST || e->right.type==STRINGV_O)
			&& e->right.v.s.s!=0)
		e->right.v.s.len = strlen(e->right.v.s.s);
	return e;
error:
	LM_CRIT("pkg memory allocation failure\n");
	return 0;
}



struct action* mk_action(int type, int n, action_elem_t *elem,
														int line, char *file)
{
	int i;
	struct action* a;

	if(n>MAX_ACTION_ELEMS)
	{
		LM_ERR("too many action elements at %s:%d for %d",
			file, line, type);
		return 0;
	}

	a=(struct action*)pkg_malloc(sizeof(struct action));
	if (a==0) goto  error;
	memset(a,0,sizeof(struct action));
	a->type=type;

	for(i=0; i<n; i++)
	{
		a->elem[i].type = elem[i].type;
		a->elem[i].u.data = elem[i].u.data;
		if(a->elem[i].type==STR_ST && a->elem[i].u.s.s!=NULL)
			a->elem[i].u.s.len = strlen(a->elem[i].u.s.s);
	}

	a->line = line;
	a->file = file;
	a->next=0;
	return a;

error:
	LM_CRIT("pkg memory allocation failure\n");
	return 0;

}


struct action* append_action(struct action* a, struct action* b)
{
	struct action *t;
	if (b==0) return a;
	if (a==0) return b;

	for(t=a;t->next;t=t->next);
	t->next=b;
	return a;
}


static void free_expr( struct expr *e)
{
	if (e==NULL)
		return;

	if (e->type==ELEM_T) {

		/* left ... */
		switch (e->left.type) {
			case EXPR_O:
				free_expr( e->left.v.expr ); break;
			case ACTION_O:
				free_action_list( (struct action*)e->left.v.data ); break;
			case SCRIPTVAR_O:
				pkg_free( e->left.v.data ); break;
		}
		/* ... and right */
		switch (e->right.type) {
			case EXPR_ST:
				free_expr( e->right.v.expr ); break;
			case ACTIONS_ST:
				free_action_list( (struct action*)e->right.v.data ); break;
			case SCRIPTVAR_ST:
				pkg_free( e->right.v.data ); break;
		}

	} else if (e->type==EXP_T) {

		/* left ... */
		if (e->left.v.expr)
			free_expr( e->left.v.expr );
		/* ... and right */
		if (e->right.v.expr)
			free_expr( e->right.v.expr );

	}

	pkg_free( e );
}


static void free_action_elem( action_elem_t *e )
{
	if (e->type==EXPR_ST)
		free_expr( (struct expr*)e->u.data );
	else if (e->type==ACTIONS_ST)
		free_action_list( (struct action*)e->u.data );
	else if (e->type==SCRIPTVAR_ST)
		pkg_free(e->u.data);
	else if (e->type==SCRIPTVAR_ELEM_ST)
		pv_elem_free_all(e->u.data);
}


void free_action_list( struct action *a)
{
	int i;

	if (a==NULL)
		return;

	for( i=0 ; i<MAX_ACTION_ELEMS ; i++)
		if (a->elem[i].type)
			free_action_elem( &a->elem[i] );

	if (a->next)
		free_action_list(a->next);

	pkg_free(a);
}



void print_expr(struct expr* exp)
{
	if (exp==0){
		LM_CRIT("null expression!\n");
		return;
	}
	if (exp->type==ELEM_T){
		switch(exp->left.type){
			case SCRIPTVAR_O:
				LM_GEN1(L_DBG, "scriptvar[%d]",
					(exp->left.v.spec)?exp->left.v.spec->type:0);
				break;
			case NUMBER_O:
			case NUMBERV_O:
				LM_GEN1(L_DBG, "%d",exp->left.v.n);
				break;
			case STRINGV_O:
				LM_GEN1(L_DBG, "\"%s\"", ZSW((char*)exp->left.v.data));
				break;
			case ACTION_O:
				break;
			case EXPR_O:
				print_expr((struct expr*)exp->left.v.data);
				break;
			default:
				LM_GEN1(L_DBG, "UNKNOWN[%d]", exp->left.type);
		}
		switch(exp->op){
			case EQUAL_OP:
				LM_GEN1(L_DBG, "==");
				break;
			case MATCHD_OP:
			case MATCH_OP:
				LM_GEN1(L_DBG, "=~");
				break;
			case NOTMATCHD_OP:
			case NOTMATCH_OP:
				LM_GEN1(L_DBG, "!~");
				break;
			case GT_OP:
				LM_GEN1(L_DBG, ">");
				break;
			case GTE_OP:
				LM_GEN1(L_DBG, ">=");
				break;
			case LT_OP:
				LM_GEN1(L_DBG, "<");
				break;
			case LTE_OP:
				LM_GEN1(L_DBG, "<=");
				break;
			case DIFF_OP:
				LM_GEN1(L_DBG, "!=");
				break;
			case PLUS_OP:
				LM_GEN1(L_DBG, "+");
				break;
			case MINUS_OP:
				LM_GEN1(L_DBG, "-");
				break;
			case DIV_OP:
				LM_GEN1(L_DBG, "/");
				break;
			case MULT_OP:
				LM_GEN1(L_DBG, "*");
				break;
			case MODULO_OP:
				LM_GEN1(L_DBG, " mod ");
				break;
			case BAND_OP:
				LM_GEN1(L_DBG, "&");
				break;
			case BOR_OP:
				LM_GEN1(L_DBG, "|");
				break;
			case BXOR_OP:
				LM_GEN1(L_DBG, "^");
				break;
			case BLSHIFT_OP:
				LM_GEN1(L_DBG, "<<");
				break;
			case BRSHIFT_OP:
				LM_GEN1(L_DBG, ">>");
				break;
			case BNOT_OP:
				LM_GEN1(L_DBG, "~");
				break;
			case VALUE_OP:
			case NO_OP:
				break;
			default:
				LM_GEN1(L_DBG, "<UNKNOWN[%d]>", exp->op);
		}
		switch(exp->right.type){
			case NOSUBTYPE:
					/* LM_GEN1(L_DBG, "N/A"); */
					break;
			case STRING_ST:
					LM_GEN1(L_DBG, "\"%s\"", ZSW((char*)exp->right.v.data));
					break;
			case NET_ST:
					print_net((struct net*)exp->right.v.data);
					break;
			case IP_ST:
					print_ip("", (struct ip_addr*)exp->right.v.data, "");
					break;
			case ACTIONS_ST:
					print_actions((struct action*)exp->right.v.data);
					break;
			case NUMBER_ST:
					LM_GEN1(L_DBG, "%d",exp->right.v.n);
					break;
			case SCRIPTVAR_ST:
					LM_GEN1(L_DBG, "scriptvar[%d]", exp->right.v.spec->type);
					break;
			case NULLV_ST:
					LM_GEN1(L_DBG, "null");
					break;
			case EXPR_ST:
					print_expr((struct expr*)exp->right.v.data);
					break;
			default:
					LM_GEN1(L_DBG, "type<%d>", exp->right.type);
		}
	}else if (exp->type==EXP_T){
		switch(exp->op){
			case AND_OP:
					LM_GEN1(L_DBG, "AND( ");
					print_expr(exp->left.v.expr);
					LM_GEN1(L_DBG, ", ");
					print_expr(exp->right.v.expr);
					LM_GEN1(L_DBG, " )");
					break;
			case OR_OP:
					LM_GEN1(L_DBG, "OR( ");
					print_expr(exp->left.v.expr);
					LM_GEN1(L_DBG, ", ");
					print_expr(exp->right.v.expr);
					LM_GEN1(L_DBG, " )");
					break;
			case NOT_OP:
					LM_GEN1(L_DBG, "NOT( ");
					print_expr(exp->left.v.expr);
					LM_GEN1(L_DBG, " )");
					break;
			case EVAL_OP:
					LM_GEN1(L_DBG, "EVAL( ");
					print_expr(exp->left.v.expr);
					LM_GEN1(L_DBG, " )");
					break;
			case PLUS_OP:
					LM_GEN1(L_DBG, "PLUS( ");
					print_expr(exp->left.v.expr);
					LM_GEN1(L_DBG, ", ");
					print_expr(exp->right.v.expr);
					LM_GEN1(L_DBG, " )");
					break;
			case MINUS_OP:
					LM_GEN1(L_DBG, "MINUS( ");
					print_expr(exp->left.v.expr);
					LM_GEN1(L_DBG, ", ");
					print_expr(exp->right.v.expr);
					LM_GEN1(L_DBG, " )");
					break;
			case DIV_OP:
					LM_GEN1(L_DBG, "DIV( ");
					print_expr(exp->left.v.expr);
					LM_GEN1(L_DBG, ", ");
					print_expr(exp->right.v.expr);
					LM_GEN1(L_DBG, " )");
					break;
			case MULT_OP:
					LM_GEN1(L_DBG, "MULT( ");
					print_expr(exp->left.v.expr);
					LM_GEN1(L_DBG, ", ");
					print_expr(exp->right.v.expr);
					LM_GEN1(L_DBG, " )");
					break;
			case MODULO_OP:
					LM_GEN1(L_DBG, "MODULO( ");
					print_expr(exp->left.v.expr);
					LM_GEN1(L_DBG, ", ");
					print_expr(exp->right.v.expr);
					LM_GEN1(L_DBG, " )");
					break;
			case BAND_OP:
					LM_GEN1(L_DBG, "BAND( ");
					print_expr(exp->left.v.expr);
					LM_GEN1(L_DBG, ", ");
					print_expr(exp->right.v.expr);
					LM_GEN1(L_DBG, " )");
					break;
			case BOR_OP:
					LM_GEN1(L_DBG, "BOR( ");
					print_expr(exp->left.v.expr);
					LM_GEN1(L_DBG, ", ");
					print_expr(exp->right.v.expr);
					LM_GEN1(L_DBG, " )");
					break;
			case BXOR_OP:
					LM_GEN1(L_DBG, "BXOR( ");
					print_expr(exp->left.v.expr);
					LM_GEN1(L_DBG, ", ");
					print_expr(exp->right.v.expr);
					LM_GEN1(L_DBG, " )");
					break;
			case BLSHIFT_OP:
					LM_GEN1(L_DBG, "BLSHIFT( ");
					print_expr(exp->left.v.expr);
					LM_GEN1(L_DBG, ", ");
					print_expr(exp->right.v.expr);
					LM_GEN1(L_DBG, " )");
					break;
			case BRSHIFT_OP:
					LM_GEN1(L_DBG, "BRSHIFT( ");
					print_expr(exp->left.v.expr);
					LM_GEN1(L_DBG, ", ");
					print_expr(exp->right.v.expr);
					LM_GEN1(L_DBG, " )");
					break;
			case BNOT_OP:
					LM_GEN1(L_DBG, "BNOT( ");
					print_expr(exp->left.v.expr);
					LM_GEN1(L_DBG, " )");
					break;
			default:
					LM_GEN1(L_DBG, "UNKNOWN_EXP[%d] ", exp->op);
		}

	}else{
		LM_ERR("unknown type\n");
	}
}


void print_action(struct action* t)
{
	switch(t->type){
		case ASSERT_T:
				LM_GEN1(L_DBG, "assert(");
				break;
		case DROP_T:
				LM_GEN1(L_DBG, "drop(");
				break;
		case LOG_T:
				LM_GEN1(L_DBG, "log(");
				break;
		case ERROR_T:
				LM_GEN1(L_DBG, "error(");
				break;
		case ROUTE_T:
				LM_GEN1(L_DBG, "route(");
				break;
		case EXEC_T:
				LM_GEN1(L_DBG, "exec(");
				break;
		case LEN_GT_T:
				LM_GEN1(L_DBG, "len_gt(");
				break;
		case IF_T:
				LM_GEN1(L_DBG, "if (");
				break;
		case WHILE_T:
				LM_GEN1(L_DBG, "while (");
				break;
		case CMD_T:
				LM_GEN1(L_DBG, " function_call(");
				break;
		case RETURN_T:
				LM_GEN1(L_DBG, "return(");
				break;
		case EXIT_T:
				LM_GEN1(L_DBG, "exit(");
				break;
		case SWITCH_T:
				LM_GEN1(L_DBG, "switch(");
				break;
		case CASE_T:
				LM_GEN1(L_DBG, "case(");
				break;
		case DEFAULT_T:
				LM_GEN1(L_DBG, "default(");
				break;
		case BREAK_T:
				LM_GEN1(L_DBG, "break(");
				break;
		case EQ_T:
				LM_GEN1(L_DBG, "assign(");
				break;
		default:
				LM_GEN1(L_DBG, "UNKNOWN(");
	}
	switch(t->elem[0].type){
		case STRING_ST:
				LM_GEN1(L_DBG, "\"%s\"", ZSW(t->elem[0].u.string));
				break;
		case NUMBER_ST:
				LM_GEN1(L_DBG, "%lu",t->elem[0].u.number);
				break;
		case SCRIPTVAR_ST:
				LM_GEN1(L_DBG, "scriptvar[%d]",t->elem[0].u.item->type);
				break;
		case IP_ST:
				print_ip("", (struct ip_addr*)t->elem[0].u.data, "");
				break;
		case EXPR_ST:
				print_expr((struct expr*)t->elem[0].u.data);
				break;
		case ACTIONS_ST:
				print_actions((struct action*)t->elem[0].u.data);
				break;
		case CMD_ST:
				LM_GEN1(L_DBG, "f<%s>",((cmd_export_t*)t->elem[0].u.data)->name);
				break;
		case SOCKID_ST:
				LM_GEN1(L_DBG, "%d:%s:%d",
						((struct socket_id*)t->elem[0].u.data)->proto,
						ZSW(((struct socket_id*)t->elem[0].u.data)->name),
						((struct socket_id*)t->elem[0].u.data)->port
						);
				break;
		default:
				LM_GEN1(L_DBG, "type<%d>", t->elem[0].type);
	}
	if (t->type==IF_T) LM_GEN1(L_DBG, ") {");
	switch(t->elem[1].type){
		case NOSUBTYPE:
				break;
		case STRING_ST:
				LM_GEN1(L_DBG, ", \"%s\"", ZSW(t->elem[1].u.string));
				break;
		case NUMBER_ST:
				LM_GEN1(L_DBG, ", %lu",t->elem[1].u.number);
				break;
		case EXPR_ST:
				print_expr((struct expr*)t->elem[1].u.data);
				break;
		case ACTIONS_ST:
				print_actions((struct action*)t->elem[1].u.data);
				break;
		case SOCKID_ST:
				LM_GEN1(L_DBG, "%d:%s:%d",
						((struct socket_id*)t->elem[1].u.data)->proto,
						ZSW(((struct socket_id*)t->elem[1].u.data)->name),
						((struct socket_id*)t->elem[1].u.data)->port
						);
				break;
		default:
				LM_GEN1(L_DBG, ", type<%d>", t->elem[1].type);
	}
	if (t->type==IF_T && t->elem[2].type!=NOSUBTYPE) LM_GEN1(L_DBG, " } else { ");
	switch(t->elem[2].type){
		case NOSUBTYPE:
				break;
		case STRING_ST:
				LM_GEN1(L_DBG, ", \"%s\"", ZSW(t->elem[2].u.string));
				break;
		case NUMBER_ST:
				LM_GEN1(L_DBG, ", %lu",t->elem[2].u.number);
				break;
		case EXPR_ST:
				print_expr((struct expr*)t->elem[2].u.data);
				break;
		case ACTIONS_ST:
				print_actions((struct action*)t->elem[2].u.data);
				break;
		case SOCKID_ST:
				LM_GEN1(L_DBG, "%d:%s:%d",
					((struct socket_id*)t->elem[2].u.data)->proto,
					ZSW(((struct socket_id*)t->elem[2].u.data)->name),
					((struct socket_id*)t->elem[2].u.data)->port
					);
			break;
		default:
			LM_GEN1(L_DBG, ", type<%d>", t->elem[2].type);
	}
	if (t->type==IF_T) LM_GEN1(L_DBG, "}; ");
	else	LM_GEN1(L_DBG, "); ");

}

void print_actions(struct action* a)
{
	while(a) {
		print_action(a);
		a = a->next;
	}
}


static int is_mod_func_in_expr(struct expr *e, char *name, int param_no)
{
	if (e->type==ELEM_T) {
		if (e->left.type==ACTION_O)
			if (is_mod_func_used((struct action*)e->right.v.data,name,param_no)==1)
				return 1;
	} else if (e->type==EXP_T) {
		if (e->left.v.expr && is_mod_func_in_expr(e->left.v.expr,name,param_no)==1)
			return 1;
		if (e->right.v.expr && is_mod_func_in_expr(e->right.v.expr,name,param_no)==1)
			return 1;
	}
	return 0;
}


int is_mod_func_used(struct action *a, char *name, int param_no)
{
	cmd_export_t *cmd;
	while(a) {
		if (a->type==CMD_T) {
			/* first param is the name of the function */
			cmd = (cmd_export_t*)a->elem[0].u.data;
			if (strcasecmp(cmd->name, name)==0) {
				if (param_no==-1 ||
					(a->elem[param_no].type != NOSUBTYPE &&
					a->elem[param_no].type != NULLV_ST)) {
					LM_DBG("function %s found to be used in script\n",name);
					return 1;
				}

			}
		}

		/* follow all leads from actions/expressions than may have 
		 * sub-blocks of instructions */
		if (a->elem[0].type==ACTIONS_ST)
			if (is_mod_func_used((struct action*)a->elem[0].u.data,
			name,param_no)==1)
				return 1;
		if (a->elem[0].type==EXPR_ST)
			if (is_mod_func_in_expr((struct expr*)a->elem[0].u.data,
			name,param_no)==1)
				return 1;

		if (a->elem[1].type==ACTIONS_ST)
			if (is_mod_func_used((struct action*)a->elem[1].u.data,
			name,param_no)==1)
				return 1;
		if (a->elem[1].type==EXPR_ST)
			if (is_mod_func_in_expr((struct expr*)a->elem[1].u.data,
			name,param_no)==1)
				return 1;

		if (a->elem[2].type==ACTIONS_ST)
			if (is_mod_func_used((struct action*)a->elem[2].u.data,
			name,param_no)==1)
				return 1;
		if (a->elem[2].type==EXPR_ST)
			if (is_mod_func_in_expr((struct expr*)a->elem[2].u.data,
			name,param_no)==1)
				return 1;

		a = a->next;
	}

	return 0;
}

int is_mod_async_func_used(struct action *a, char *name, int param_no)
{
	acmd_export_t *acmd;

	for (; a; a=a->next) {
		if (a->type==ASYNC_T || a->type==LAUNCH_T) {
			acmd = ((struct action *)(a->elem[0].u.data))->elem[0].u.data;

			if (strcasecmp(acmd->name, name)==0) {
				if (param_no==-1 ||
					(((struct action *)(a->elem[0].u.data))->elem[param_no].type != NOSUBTYPE &&
					((struct action *)(a->elem[0].u.data))->elem[param_no].type != NULLV_ST)) {
					LM_DBG("function %s found to be used in script\n",name);
					return 1;
				}

			}
		}

		/* follow all leads from actions than may have 
		 * sub-blocks of instructions */
		if (a->elem[0].type==ACTIONS_ST)
				if (is_mod_async_func_used((struct action*)a->elem[0].u.data,
				name,param_no)==1)
					return 1;

		if (a->elem[1].type==ACTIONS_ST)
				if (is_mod_async_func_used((struct action*)a->elem[1].u.data,
				name,param_no)==1)
					return 1;

		if (a->elem[2].type==ACTIONS_ST)
				if (is_mod_async_func_used((struct action*)a->elem[2].u.data,
				name,param_no)==1)
					return 1;
	}

	return 0;
}
