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
#include "mod_fix.h"

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
		case FORWARD_T:
				LM_GEN1(L_DBG, "forward(");
				break;
		case SEND_T:
				LM_GEN1(L_DBG, "send(");
				break;
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
		case REVERT_URI_T:
				LM_GEN1(L_DBG, "revert_uri(");
				break;
		case STRIP_T:
				LM_GEN1(L_DBG, "strip(");
				break;
		case APPEND_BRANCH_T:
				LM_GEN1(L_DBG, "append_branch(");
				break;
		case PREFIX_T:
				LM_GEN1(L_DBG, "prefix(");
				break;
		case LEN_GT_T:
				LM_GEN1(L_DBG, "len_gt(");
				break;
		case SETFLAG_T:
				LM_GEN1(L_DBG, "setflag(");
				break;
		case RESETFLAG_T:
				LM_GEN1(L_DBG, "resetflag(");
				break;
		case ISFLAGSET_T:
				LM_GEN1(L_DBG, "isflagset(");
				break;
		case SETBFLAG_T:
				LM_GEN1(L_DBG, "setbflag(");
				break;
		case RESETBFLAG_T:
				LM_GEN1(L_DBG, "resetbflag(");
				break;
		case ISBFLAGSET_T:
				LM_GEN1(L_DBG, "isbflagset(");
				break;
		case SET_HOST_T:
				LM_GEN1(L_DBG, "sethost(");
				break;
		case SET_HOSTPORT_T:
				LM_GEN1(L_DBG, "sethostport(");
				break;
		case SET_USER_T:
				LM_GEN1(L_DBG, "setuser(");
				break;
		case SET_USERPASS_T:
				LM_GEN1(L_DBG, "setuserpass(");
				break;
		case SET_PORT_T:
				LM_GEN1(L_DBG, "setport(");
				break;
		case SET_URI_T:
				LM_GEN1(L_DBG, "seturi(");
				break;
		case IF_T:
				LM_GEN1(L_DBG, "if (");
				break;
		case WHILE_T:
				LM_GEN1(L_DBG, "while (");
				break;
		case MODULE_T:
				LM_GEN1(L_DBG, " external_module_call(");
				break;
		case FORCE_RPORT_T:
				LM_GEN1(L_DBG, "force_rport(");
				break;
		case SET_ADV_ADDR_T:
				LM_GEN1(L_DBG, "set_advertised_address(");
				break;
		case SET_ADV_PORT_T:
				LM_GEN1(L_DBG, "set_advertised_port(");
				break;
		case FORCE_TCP_ALIAS_T:
				LM_GEN1(L_DBG, "force_tcp_alias(");
				break;
		case FORCE_SEND_SOCKET_T:
				LM_GEN1(L_DBG, "force_send_socket");
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
		case SBREAK_T:
				LM_GEN1(L_DBG, "sbreak(");
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
		if (a->type==MODULE_T) {
			/* first param is the name of the function */
			cmd = (cmd_export_t*)a->elem[0].u.data;
			if (strcasecmp(cmd->name, name)==0 || param_no==-1) {
				LM_DBG("function %s found to be used in script\n",name);
				return 1;
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

			LM_DBG("checking %s against %s\n", name, acmd->name);
			if (strcasecmp(acmd->name, name) == 0 || param_no == -1)
				return 1;
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

static char *re_buff=NULL;
static int re_buff_len = 0;
int fixup_regcomp(regex_t **re, str *re_str, int dup_nt)
{
	char *regex;

	if (dup_nt) {
		if (re_str->len + 1 > re_buff_len) {
			re_buff = pkg_realloc(re_buff,re_str->len + 1);
			if (re_buff == NULL) {
				LM_ERR("No more pkg \n");
				return E_OUT_OF_MEM;
			}

			re_buff_len = re_str->len + 1;
		}

		memcpy(re_buff,re_str->s,re_str->len);
		re_buff[re_str->len] = 0;

		regex = re_buff;
	} else
		regex = re_str->s;

	if ((*re = pkg_malloc(sizeof **re)) == 0) {
		LM_ERR("no more pkg memory\n");
		return E_OUT_OF_MEM;
	}
	if (regcomp(*re, regex, (REG_EXTENDED|REG_ICASE|REG_NEWLINE))) {
		LM_ERR("bad re %s\n", regex);
		pkg_free(*re);
		return E_BAD_RE;
	}

	return 0;
}

int fix_cmd(struct cmd_param *params, action_elem_t *elems)
{
	int i;
	struct cmd_param *param;
	gparam_p gp = NULL;
	int ret;
	pv_elem_t *pve;
	regex_t *re = NULL;

	for (param=params, i=1; param->flags; param++, i++) {
		if ((elems[i].type == NOSUBTYPE) ||
			(elems[i].type == NULLV_ST)) {
			if (param->flags & CMD_PARAM_OPT)
				continue;
			else {
				LM_BUG("Mandatory parameter missing\n");
				ret = E_BUG;
				goto error;
			}
		}

		gp = pkg_malloc(sizeof *gp);
		if (!gp) {
			LM_ERR("no more pkg memory\n");
			ret = E_OUT_OF_MEM;
			goto error;
		}
		memset(gp, 0, sizeof *gp);

		if (param->flags & CMD_PARAM_INT) {

			if (elems[i].type == NUMBER_ST) {
				if (param->fixup) {
					gp->v.val = (void *)&elems[i].u.number;
					if (param->fixup(&gp->v.val) < 0) {
						LM_ERR("Fixup failed for param [%d]\n", i);
						ret = E_UNSPEC;
						goto error;
					}
					gp->type = GPARAM_TYPE_FIXUP;
				} else {
					gp->v.ival = elems[i].u.number;
					gp->type = GPARAM_TYPE_INT;
				}
			} else if (elems[i].type == SCRIPTVAR_ST) {
				gp->v.pvs = elems[i].u.data;
				gp->type = GPARAM_TYPE_PVS;
			} else {
				LM_ERR("Param [%d] expected to be an integer "
					"or variable\n", i);
				return E_CFG;
			}

		} else if (param->flags & CMD_PARAM_STR) {

			if (elems[i].type == STR_ST) {
				if (pv_parse_format(&elems[i].u.s, &pve) < 0) {
					LM_ERR("Failed to parse formatted string in param "
						"[%d]\n",i);
					ret = E_UNSPEC;
					goto error;
				}
				if (!pve->next && pve->spec.type == PVT_NONE) {
					/* no variables in the provided string */
					pv_elem_free_all(pve);

					if (param->fixup) {
						gp->v.val = (void *)&elems[i].u.s;
						if (param->fixup(&gp->v.val) < 0) {
							LM_ERR("Fixup failed for param [%d]\n", i);
							ret = E_UNSPEC;
							goto error;
						}
						gp->type = GPARAM_TYPE_FIXUP;
					} else {
						gp->v.sval = elems[i].u.s;
						gp->type = GPARAM_TYPE_STR;
					}
				} else {
					gp->v.pve = pve;
					gp->type = GPARAM_TYPE_PVE;
				}
			} else if (elems[i].type == SCRIPTVAR_ST) {
				gp->v.pvs = elems[i].u.data;
				gp->type = GPARAM_TYPE_PVS;
			} else {
				LM_ERR("Param [%d] expected to be a string "
					"or variable\n", i);
				ret = E_CFG;
				goto error;
			}

		} else if (param->flags & CMD_PARAM_VAR) {

			if (elems[i].type != SCRIPTVAR_ST) {
				LM_ERR("Param [%d] expected to be a variable\n",i);
				ret = E_CFG;
				goto error;
			}

			gp->v.pvs = elems[i].u.data;
			gp->type = GPARAM_TYPE_PVS;

		} else if (param->flags & CMD_PARAM_REGEX) {

			if (elems[i].type == STR_ST) {
				if (pv_parse_format(&elems[i].u.s, &pve) < 0) {
					LM_ERR("Failed to parse formatted string in param "
						"[%d]\n",i);
					ret = E_UNSPEC;
					goto error;
				}
				if (!pve->next && pve->spec.type == PVT_NONE) {
					/* no variables in the provided string */
					pv_elem_free_all(pve);

					ret = fixup_regcomp(&re, &elems[i].u.s, 0);
					if (ret < 0)
						return ret;

					if (param->fixup) {
						gp->v.val = re;
						if (param->fixup(&gp->v.val) < 0) {
							LM_ERR("Fixup failed for param [%d]\n", i);
							ret = E_UNSPEC;
							goto error;
						}
						gp->type = GPARAM_TYPE_FIXUP;
					} else {
						gp->v.re = re;
						gp->type = GPARAM_TYPE_REGEX;
					}
				} else {
					gp->v.pve = pve;
					gp->type = GPARAM_TYPE_PVE;
				}
			} else if (elems[i].type == SCRIPTVAR_ST) {
				gp->v.pvs = elems[i].u.data;
				gp->type = GPARAM_TYPE_PVS;
			} else {
				LM_ERR("Param [%d] expected to be a string "
					"or variable\n", i);
				ret = E_CFG;
				goto error;
			}

		} else {
			LM_BUG("Bad command parameter type\n");
			ret = E_BUG;
			goto error;
		}

		elems[i].u.data = (void*)gp;
	}

	return 0;
error:
	if (gp)
		pkg_free(gp);
	if (re)
		pkg_free(re);
	return ret;
}

int get_cmd_fixups(struct sip_msg* msg, struct cmd_param *params,
				action_elem_t *elems, void **cmdp, pv_value_t *tmp_vals)
{
	int i;
	struct cmd_param *param;
	gparam_p gp;
	regex_t *re = NULL;
	int ret;

	for (param=params, i=1; param->flags; param++, i++) {
		gp = (gparam_p)elems[i].u.data;
		if (!gp) {
			cmdp[i-1] = NULL;
			continue;
		}

		if (param->flags & CMD_PARAM_INT) {

			switch (gp->type) {
			case GPARAM_TYPE_INT:
				cmdp[i-1] = (void*)&gp->v.ival;
				break;
			case GPARAM_TYPE_PVS:
				if (pv_get_spec_value(msg, gp->v.pvs, &tmp_vals[i]) != 0) {
					LM_ERR("Failed to get spec value in param [%d]\n", i);
					return E_UNSPEC;
				}
				if (tmp_vals[i].flags & PV_VAL_NULL ||
					!(tmp_vals[i].flags & PV_VAL_INT)) {
					LM_ERR("Variable in param [%d] is not an integer\n", i);
					return E_UNSPEC;
				}

				cmdp[i-1] = (void *)&tmp_vals[i].ri;

				/* run fixup as we now have the value of the variable */
				if (param->fixup && param->fixup(&cmdp[i-1]) < 0) {
					LM_ERR("Fixup failed for param [%d]\n", i);
					return E_UNSPEC;
				}

				break;
			case GPARAM_TYPE_FIXUP:
				/* fixup was possible at startup */
				cmdp[i-1] = gp->v.val;
				break;
			default:
				LM_BUG("Bad type for generic parameter\n");
				return E_BUG;
			}

		} else if (param->flags & CMD_PARAM_STR) {

			switch (gp->type) {
			case GPARAM_TYPE_STR:
				cmdp[i-1] = (void*)&gp->v.sval;
				break;
			case GPARAM_TYPE_PVE:
				if (pv_printf_s(msg, gp->v.pve, &tmp_vals[i].rs) != 0) {
					LM_ERR("Failed to print formatted string in param [%d]\n", i);
					return E_UNSPEC;
				}

				cmdp[i-1] = &tmp_vals[i].rs;

				if (param->fixup && param->fixup(&cmdp[i-1]) < 0) {
					LM_ERR("Fixup failed for param [%d]\n", i);
					return E_UNSPEC;
				}

				break;
			case GPARAM_TYPE_PVS:
				if (pv_get_spec_value(msg, gp->v.pvs, &tmp_vals[i]) != 0) {
					LM_ERR("Failed to get spec value in param [%d]\n", i);
					return E_UNSPEC;
				}
				if (tmp_vals[i].flags & PV_VAL_NULL ||
					!(tmp_vals[i].flags & PV_VAL_STR)) {
					LM_ERR("Variable in param [%d] is not a string\n", i);
					return E_UNSPEC;
				}

				cmdp[i-1] = &tmp_vals[i].rs;

				if (param->fixup && param->fixup(&cmdp[i-1]) < 0) {
					LM_ERR("Fixup failed for param [%d]\n", i);
					return E_UNSPEC;
				}

				break;
			case GPARAM_TYPE_FIXUP:
				cmdp[i-1] = gp->v.val;
				break;
			default:
				LM_BUG("Bad type for generic parameter\n");
				return E_BUG;
			}

		} else if (param->flags & CMD_PARAM_VAR) {
			if (gp->type != GPARAM_TYPE_PVS) {
				LM_BUG("Bad type for generic parameter\n");
				return E_BUG;
			}

			cmdp[i-1] = gp->v.pvs;

			if (param->fixup && param->fixup(&cmdp[i-1]) < 0) {
				LM_ERR("Fixup failed for param [%d]\n", i);
				return E_UNSPEC;
			}

		} else if (param->flags & CMD_PARAM_REGEX) {

			switch (gp->type) {
			case GPARAM_TYPE_REGEX:
				cmdp[i-1] = (void*)&gp->v.re;
				break;
			case GPARAM_TYPE_PVE:
				if (pv_printf_s(msg, gp->v.pve, &tmp_vals[i].rs) != 0) {
					LM_ERR("Failed to print formatted string in param [%d]\n", i);
					return E_UNSPEC;
				}

				ret = fixup_regcomp(&re, &tmp_vals[i].rs, 1);
				if (ret < 0)
					return ret;
				cmdp[i-1] = re;

				if (param->fixup) {
					if (param->fixup(&cmdp[i-1]) < 0) {
						LM_ERR("Fixup failed for param [%d]\n", i);
						ret = E_UNSPEC;
					}

					regfree(re);
					pkg_free(re);

					if (ret < 0)
						return ret;
				}

				break;
			case GPARAM_TYPE_PVS:
				if (pv_get_spec_value(msg, gp->v.pvs, &tmp_vals[i]) != 0) {
					LM_ERR("Failed to get spec value in param [%d]\n", i);
					return E_UNSPEC;
				}
				if (tmp_vals[i].flags & PV_VAL_NULL ||
					!(tmp_vals[i].flags & PV_VAL_STR)) {
					LM_ERR("Variable in param [%d] is not a string\n", i);
					return E_UNSPEC;
				}

				ret = fixup_regcomp(&re, &tmp_vals[i].rs, 1);
				if (ret < 0)
					return ret;
				cmdp[i-1] = re;

				if (param->fixup) {
					if (param->fixup(&cmdp[i-1]) < 0) {
						LM_ERR("Fixup failed for param [%d]\n", i);
						ret = E_UNSPEC;
					}

					regfree(re);
					pkg_free(re);

					if (ret < 0)
						return ret;
				}

				break;
			case GPARAM_TYPE_FIXUP:
				cmdp[i-1] = gp->v.val;
				break;
			default:
				LM_BUG("Bad type for generic parameter\n");
				return E_BUG;
			}

		} else {
			LM_BUG("Bad command parameter type\n");
			return E_BUG;
		}
	}

	return 0;
}

int free_cmd_fixups(struct cmd_param *params, action_elem_t *elems, void **cmdp)
{
	int i;
	struct cmd_param *param;
	gparam_p gp;

	for (param=params, i=1; param->flags; param++, i++) {
		gp = (gparam_p)elems[i].u.data;
		if (!gp)
			continue;

		if (param->flags & CMD_PARAM_INT) {
			if (param->free_fixup && gp->type == GPARAM_TYPE_PVS)
				if (param->free_fixup(&cmdp[i-1]) < 0) {
					LM_ERR("Failed to free fixup for param [%d]\n", i);
					return E_UNSPEC;
				}
		} else if (param->flags & CMD_PARAM_STR) {
			if (param->free_fixup && (gp->type == GPARAM_TYPE_PVS ||
				gp->type == GPARAM_TYPE_PVE))
				if (param->free_fixup(&cmdp[i-1]) < 0) {
					LM_ERR("Failed to free fixup for param [%d]\n", i);
					return E_UNSPEC;
				}
		} else if (param->flags & CMD_PARAM_VAR) {
			if (param->free_fixup)
				if (param->free_fixup(&cmdp[i-1]) < 0) {
					LM_ERR("Failed to free fixup for param [%d]\n", i);
					return E_UNSPEC;
				}
		} else if (param->flags & CMD_PARAM_REGEX) {
			if (gp->type == GPARAM_TYPE_PVS || gp->type == GPARAM_TYPE_PVE) {
				if (param->fixup) {
					if (param->free_fixup && param->free_fixup(&cmdp[i-1]) < 0) {
						LM_ERR("Failed to free fixup for param [%d]\n", i);
						return E_UNSPEC;
					}
				} else {
					regfree((regex_t*)cmdp[i-1]);
					pkg_free(cmdp[i-1]);
				}
			}
		} else {
			LM_BUG("Bad command parameter type\n");
			return E_BUG;
		}
	}

	return 0;
}
