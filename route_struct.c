/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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



struct action* mk_action(int type, int n, action_elem_t *elem, int line)
{
	int i;
	struct action* a;
	
	if(n>MAX_ACTION_ELEMS)
	{
		LM_ERR("too many action elements at line %d for %d", line, type);
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



void print_expr(struct expr* exp)
{
	if (exp==0){
		LM_CRIT("null expression!\n");
		return;
	}
	if (exp->type==ELEM_T){
		switch(exp->left.type){
			case METHOD_O:
				LM_DBG("method");
				break;
			case URI_O:
				LM_DBG("uri");
				break;
			case FROM_URI_O:
				LM_DBG("from_uri");
				break;
			case TO_URI_O:
				LM_DBG("to_uri");
				break;
			case SRCIP_O:
				LM_DBG("srcip");
				break;
			case SRCPORT_O:
				LM_DBG("srcport");
				break;
			case DSTIP_O:
				LM_DBG("dstip");
				break;
			case DSTPORT_O:
				LM_DBG("dstport");
				break;
			case SCRIPTVAR_O:
				LM_DBG("scriptvar[%d]",
					(exp->left.v.spec)?exp->left.v.spec->type:0);
				break;
			case NUMBER_O:
			case NUMBERV_O:
				LM_DBG("%d",exp->left.v.n);
				break;
			case STRINGV_O:
				LM_DBG("\"%s\"", ZSW((char*)exp->left.v.data));
				break;
			case ACTION_O:
				break;
			case EXPR_O:
				print_expr((struct expr*)exp->left.v.data);
				break;
			default:
				LM_DBG("UNKNOWN[%d]", exp->left.type);
		}
		switch(exp->op){
			case EQUAL_OP:
				LM_DBG("==");
				break;
			case MATCHD_OP:
			case MATCH_OP:
				LM_DBG("=~");
				break;
			case NOTMATCHD_OP:
			case NOTMATCH_OP:
				LM_DBG("!~");
				break;
			case GT_OP:
				LM_DBG(">");
				break;
			case GTE_OP:
				LM_DBG(">=");
				break;
			case LT_OP:
				LM_DBG("<");
				break;
			case LTE_OP:
				LM_DBG("<=");
				break;
			case DIFF_OP:
				LM_DBG("!=");
				break;
			case PLUS_OP:
				LM_DBG("+");
				break;
			case MINUS_OP:
				LM_DBG("-");
				break;
			case DIV_OP:
				LM_DBG("/");
				break;
			case MULT_OP:
				LM_DBG("*");
				break;
			case MODULO_OP:
				LM_DBG(" mod ");
				break;
			case BAND_OP:
				LM_DBG("&");
				break;
			case BOR_OP:
				LM_DBG("|");
				break;
			case BXOR_OP:
				LM_DBG("^");
				break;
			case BLSHIFT_OP:
				LM_DBG("<<");
				break;
			case BRSHIFT_OP:
				LM_DBG(">>");
				break;
			case BNOT_OP:
				LM_DBG("~");
				break;
			case VALUE_OP:
			case NO_OP:
				break;
			default:
				LM_DBG("<UNKNOWN[%d]>", exp->op);
		}
		switch(exp->right.type){
			case NOSUBTYPE: 
					/* LM_DBG("N/A"); */
					break;
			case STRING_ST:
					LM_DBG("\"%s\"", ZSW((char*)exp->right.v.data));
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
					LM_DBG("%d",exp->right.v.n);
					break;
			case MYSELF_ST:
					LM_DBG("_myself_");
					break;
			case SCRIPTVAR_ST:
					LM_DBG("scriptvar[%d]", exp->right.v.spec->type);
					break;
			case NULLV_ST:
					LM_DBG("null");
					break;
			case EXPR_ST:
					print_expr((struct expr*)exp->right.v.data);
					break;
			default:
					LM_DBG("type<%d>", exp->right.type);
		}
	}else if (exp->type==EXP_T){
		switch(exp->op){
			case AND_OP:
					LM_DBG("AND( ");
					print_expr(exp->left.v.expr);
					LM_DBG(", ");
					print_expr(exp->right.v.expr);
					LM_DBG(" )");
					break;
			case OR_OP:
					LM_DBG("OR( ");
					print_expr(exp->left.v.expr);
					LM_DBG(", ");
					print_expr(exp->right.v.expr);
					LM_DBG(" )");
					break;
			case NOT_OP:	
					LM_DBG("NOT( ");
					print_expr(exp->left.v.expr);
					LM_DBG(" )");
					break;
			case EVAL_OP:
					LM_DBG("EVAL( ");
					print_expr(exp->left.v.expr);
					LM_DBG(" )");
					break;
			case PLUS_OP:
					LM_DBG("PLUS( ");
					print_expr(exp->left.v.expr);
					LM_DBG(", ");
					print_expr(exp->right.v.expr);
					LM_DBG(" )");
					break;
			case MINUS_OP:
					LM_DBG("MINUS( ");
					print_expr(exp->left.v.expr);
					LM_DBG(", ");
					print_expr(exp->right.v.expr);
					LM_DBG(" )");
					break;
			case DIV_OP:
					LM_DBG("DIV( ");
					print_expr(exp->left.v.expr);
					LM_DBG(", ");
					print_expr(exp->right.v.expr);
					LM_DBG(" )");
					break;
			case MULT_OP:
					LM_DBG("MULT( ");
					print_expr(exp->left.v.expr);
					LM_DBG(", ");
					print_expr(exp->right.v.expr);
					LM_DBG(" )");
					break;
			case MODULO_OP:
					LM_DBG("MODULO( ");
					print_expr(exp->left.v.expr);
					LM_DBG(", ");
					print_expr(exp->right.v.expr);
					LM_DBG(" )");
					break;
			case BAND_OP:
					LM_DBG("BAND( ");
					print_expr(exp->left.v.expr);
					LM_DBG(", ");
					print_expr(exp->right.v.expr);
					LM_DBG(" )");
					break;
			case BOR_OP:
					LM_DBG("BOR( ");
					print_expr(exp->left.v.expr);
					LM_DBG(", ");
					print_expr(exp->right.v.expr);
					LM_DBG(" )");
					break;
			case BXOR_OP:
					LM_DBG("BXOR( ");
					print_expr(exp->left.v.expr);
					LM_DBG(", ");
					print_expr(exp->right.v.expr);
					LM_DBG(" )");
					break;
			case BLSHIFT_OP:
					LM_DBG("BLSHIFT( ");
					print_expr(exp->left.v.expr);
					LM_DBG(", ");
					print_expr(exp->right.v.expr);
					LM_DBG(" )");
					break;
			case BRSHIFT_OP:
					LM_DBG("BRSHIFT( ");
					print_expr(exp->left.v.expr);
					LM_DBG(", ");
					print_expr(exp->right.v.expr);
					LM_DBG(" )");
					break;
			case BNOT_OP:
					LM_DBG("BNOT( ");
					print_expr(exp->left.v.expr);
					LM_DBG(" )");
					break;
			default:
					LM_DBG("UNKNOWN_EXP[%d] ", exp->op);
		}
					
	}else{
		LM_ERR("unknown type\n");
	}
}


void print_action(struct action* t)
{
	switch(t->type){
		case FORWARD_T:
				LM_DBG("forward(");
				break;
		case SEND_T:
				LM_DBG("send(");
				break;
		case DROP_T:
				LM_DBG("drop(");
				break;
		case LOG_T:
				LM_DBG("log(");
				break;
		case ERROR_T:
				LM_DBG("error(");
				break;
		case ROUTE_T:
				LM_DBG("route(");
				break;
		case EXEC_T:
				LM_DBG("exec(");
				break;
		case REVERT_URI_T:
				LM_DBG("revert_uri(");
				break;
		case STRIP_T:
				LM_DBG("strip(");
				break;
		case APPEND_BRANCH_T:
				LM_DBG("append_branch(");
				break;
		case PREFIX_T:
				LM_DBG("prefix(");
				break;
		case LEN_GT_T:
				LM_DBG("len_gt(");
				break;
		case SET_DEBUG_T:
				LM_DBG("setdebug(");
				break;
		case SETFLAG_T:
				LM_DBG("setflag(");
				break;
		case RESETFLAG_T:
				LM_DBG("resetflag(");
				break;
		case ISFLAGSET_T:
				LM_DBG("isflagset(");
				break;
		case SETBFLAG_T:
				LM_DBG("setbflag(");
				break;
		case RESETBFLAG_T:
				LM_DBG("resetbflag(");
				break;
		case ISBFLAGSET_T:
				LM_DBG("isbflagset(");
				break;
		case SETSFLAG_T:
				LM_DBG("setsflag(");
				break;
		case RESETSFLAG_T:
				LM_DBG("resetsflag(");
				break;
		case ISSFLAGSET_T:
				LM_DBG("issflagset(");
				break;
		case SET_HOST_T:
				LM_DBG("sethost(");
				break;
		case SET_HOSTPORT_T:
				LM_DBG("sethostport(");
				break;
		case SET_USER_T:
				LM_DBG("setuser(");
				break;
		case SET_USERPASS_T:
				LM_DBG("setuserpass(");
				break;
		case SET_PORT_T:
				LM_DBG("setport(");
				break;
		case SET_URI_T:
				LM_DBG("seturi(");
				break;
		case IF_T:
				LM_DBG("if (");
				break;
		case WHILE_T:
				LM_DBG("while (");
				break;
		case MODULE_T:
				LM_DBG(" external_module_call(");
				break;
		case FORCE_RPORT_T:
				LM_DBG("force_rport(");
				break;
		case SET_ADV_ADDR_T:
				LM_DBG("set_advertised_address(");
				break;
		case SET_ADV_PORT_T:
				LM_DBG("set_advertised_port(");
				break;
		case FORCE_TCP_ALIAS_T:
				LM_DBG("force_tcp_alias(");
				break;
		case FORCE_SEND_SOCKET_T:
				LM_DBG("force_send_socket");
				break;
		case RETURN_T:
				LM_DBG("return(");
				break;
		case EXIT_T:
				LM_DBG("exit(");
				break;
		case SWITCH_T:
				LM_DBG("switch(");
				break;
		case CASE_T:
				LM_DBG("case(");
				break;
		case DEFAULT_T:
				LM_DBG("default(");
				break;
		case SBREAK_T:
				LM_DBG("sbreak(");
				break;
		case EQ_T:
				LM_DBG("assign(");
				break;
		default:
				LM_DBG("UNKNOWN(");
	}
	switch(t->elem[0].type){
		case STRING_ST:
				LM_DBG("\"%s\"", ZSW(t->elem[0].u.string));
				break;
		case NUMBER_ST:
				LM_DBG("%lu",t->elem[0].u.number);
				break;
		case SCRIPTVAR_ST:
				LM_DBG("scriptvar[%d]",t->elem[0].u.item->type);
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
				LM_DBG("f<%s>",((cmd_export_t*)t->elem[0].u.data)->name);
				break;
		case SOCKID_ST:
				LM_DBG("%d:%s:%d",
						((struct socket_id*)t->elem[0].u.data)->proto,
						ZSW(((struct socket_id*)t->elem[0].u.data)->name),
						((struct socket_id*)t->elem[0].u.data)->port
						);
				break;
		default:
				LM_DBG("type<%d>", t->elem[0].type);
	}
	if (t->type==IF_T) LM_DBG(") {");
	switch(t->elem[1].type){
		case NOSUBTYPE:
				break;
		case STRING_ST:
				LM_DBG(", \"%s\"", ZSW(t->elem[1].u.string));
				break;
		case NUMBER_ST:
				LM_DBG(", %lu",t->elem[1].u.number);
				break;
		case EXPR_ST:
				print_expr((struct expr*)t->elem[1].u.data);
				break;
		case ACTIONS_ST:
				print_actions((struct action*)t->elem[1].u.data);
				break;
		case SOCKID_ST:
				LM_DBG("%d:%s:%d",
						((struct socket_id*)t->elem[1].u.data)->proto,
						ZSW(((struct socket_id*)t->elem[1].u.data)->name),
						((struct socket_id*)t->elem[1].u.data)->port
						);
				break;
		default:
				LM_DBG(", type<%d>", t->elem[1].type);
	}
	if (t->type==IF_T && t->elem[2].type!=NOSUBTYPE) LM_DBG(" } else { ");
	switch(t->elem[2].type){
		case NOSUBTYPE:
				break;
		case STRING_ST:
				LM_DBG(", \"%s\"", ZSW(t->elem[2].u.string));
				break;
		case NUMBER_ST:
				LM_DBG(", %lu",t->elem[2].u.number);
				break;
		case EXPR_ST:
				print_expr((struct expr*)t->elem[2].u.data);
				break;
		case ACTIONS_ST:
				print_actions((struct action*)t->elem[2].u.data);
				break;
		case SOCKID_ST:
				LM_DBG("%d:%s:%d",
					((struct socket_id*)t->elem[2].u.data)->proto,
					ZSW(((struct socket_id*)t->elem[2].u.data)->name),
					((struct socket_id*)t->elem[2].u.data)->port
					);
			break;
		default:
			LM_DBG(", type<%d>", t->elem[2].type);
	}
	if (t->type==IF_T) LM_DBG("}; ");
	else	LM_DBG("); ");

}
			
void print_actions(struct action* a)
{
	while(a) {
		print_action(a);
		a = a->next;
	}
}	


