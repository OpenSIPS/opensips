/*
 * SIP routing engine
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2005-2006 Voice Sistem S.R.L.
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
 *  2003-01-28  scratchpad removed, src_port introduced (jiri)
 *  2003-02-28  scratchpad compatibility abandoned (jiri)
 *  2003-03-10  updated to the new module exports format (andrei)
 *  2003-03-19  replaced all mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2003-04-01  added dst_port, proto, af; renamed comp_port to comp_no,
 *               inlined all the comp_* functions (andrei)
 *  2003-04-05  s/reply_route/failure_route, onreply_route introduced (jiri)
 *  2003-05-23  comp_ip fixed, now it will resolve its operand and compare
 *              the ip with all the addresses (andrei)
 *  2003-10-10  added more operators support to comp_* (<,>,<=,>=,!=) (andrei)
 *  2004-10-19  added from_uri & to_uri (andrei)
 *  2006-03-02  MODULE_T action points to a cmd_export_t struct instead to
 *               a function address - more info is accessible (bogdan)
 *              Fixup failure reports the config line (bogdan)
 *  2006-12-22  support for script and branch flags added (bogdan)
 */


/*!
 * \file
 * \brief SIP routing engine
 */



#include <stdlib.h>
#include <sys/types.h>
#include <regex.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "route.h"
#include "forward.h"
#include "dprint.h"
#include "proxy.h"
#include "action.h"
#include "sr_module.h"
#include "ip_addr.h"
#include "resolve.h"
#include "socket_info.h"
#include "blacklists.h"
#include "mem/mem.h"
#include "xlog.h"
#include "evi/evi_modules.h"
#include "mod_fix.h"

/* instance of script routes used for script interpreting */
struct os_script_routes *sroutes = NULL;

int route_type = REQUEST_ROUTE;


static int fix_actions(struct action* a); /*fwd declaration*/

extern int return_code;



/*!
 * \brief Allocates and initializes a new routing list holder
 */
struct os_script_routes* new_sroutes_holder(void)
{
	struct os_script_routes *sr;

	sr = (struct os_script_routes *) pkg_malloc
		( sizeof(struct os_script_routes) );
	if ( sr==NULL) {
		LM_ERR("failed to allocate table for script routes\n");
		return NULL;
	}
	memset( sr, 0, sizeof(struct os_script_routes) );

	sr->request[DEFAULT_RT].name = "0";
	sr->onreply[DEFAULT_RT].name = "0";

	return sr;
}


/*!
 * \brief Frees a routing list holder
 */
void free_route_lists(struct os_script_routes *sr)
{
	int i;

	for( i=0 ; i<RT_NO ; i++ )
		if (sr->request[i].a)
			free_action_list(sr->request[i].a);

	for( i=0 ; i<ONREPLY_RT_NO ; i++ )
		if (sr->onreply[i].a)
			free_action_list(sr->onreply[i].a);

	for( i=0 ; i<FAILURE_RT_NO ; i++ )
		if (sr->failure[i].a)
			free_action_list(sr->failure[i].a);

	for( i=0 ; i<BRANCH_RT_NO ; i++ )
		if (sr->branch[i].a)
			free_action_list(sr->branch[i].a);

	if (sr->local.a)
		free_action_list(sr->local.a);

	if (sr->error.a)
		free_action_list(sr->error.a);

	if (sr->startup.a)
		free_action_list(sr->startup.a);

	for( i=0 ; i<TIMER_RT_NO ; i++ )
		if (sr->timer[i].a)
			free_action_list(sr->timer[i].a);

	for( i=0 ; i<EVENT_RT_NO ; i++ )
		if (sr->event[i].a)
			free_action_list(sr->event[i].a);

}


/************************** Generic functions ***********************/

int get_script_route_ID_by_name(char *name, struct script_route *sr, int size)
{
	unsigned int i;

	for(i=1;i<size;i++) {
		if (sr[i].name==0)
			return -1;
		if (strcmp(sr[i].name,name)==0 )
			return i;
	}
	return -1;
}

int get_script_route_ID_by_name_str(str *name, struct script_route *sr, int size)
{
	unsigned int i;

	for(i=1;i<size;i++) {
		if (sr[i].name==0)
			return -1;
		if (strlen(sr[i].name)==name->len &&
				strncmp(sr[i].name, name->s, name->len) == 0)
			return i;
	}
	return -1;
}


/********************** Interpreter related functions ***********************/

/*! \brief comp_scriptvar helping function */
inline static int comp_ip(int op, str *ip_str, struct net *ipnet)
{
	struct ip_addr *ip_tmp = NULL;

	ip_tmp = str2ip(ip_str);
	if (!ip_tmp) {
		ip_tmp = str2ip6(ip_str);
		if (!ip_tmp) {
			LM_DBG("Var value is not an IP\n");
			return -1;
		}
	}

	if (op == EQUAL_OP) {
		return (matchnet(ip_tmp, ipnet) == 1);
	} else if (op == DIFF_OP) {
		return (matchnet(ip_tmp, ipnet) != 1);
	} else {
		LM_CRIT("invalid operator %d\n", op);
		return -1;
	}
}

/*! \brief compare str to str */
inline static int comp_s2s(int op, str *s1, str *s2)
{
#define make_nt_copy(_sd,_so) \
	do { \
		if (pkg_str_extend(_sd, (_so)->len+1)<0) \
			return -1; \
		memcpy((_sd)->s, (_so)->s, (_so)->len);\
		(_sd)->s[(_so)->len] = '\0'; \
	} while(0)
	static str cp1 = {NULL,0};
	static str cp2 = {NULL,0};
	int rt;
	int ret;
	regex_t* re;

	ret = -1;
	/* check the input values :
	 *  s1 - must be a non-empty string
	 *  s2 - must be a non-empty string or a regexp* for [NOT]MATCH_OP */
	if ( s1->s==NULL )
		return 0;

	switch(op) {
		case EQUAL_OP:
			if ( s2->s==NULL || s1->len != s2->len) return 0;
			ret=(str_strcasecmp(s1, s2)==0);
		break;
		case DIFF_OP:
			if ( s2->s==NULL ) return 0;
			if(s1->len != s2->len) return 1;
			ret=(str_strcasecmp(s1, s2)!=0);
			break;
		case GT_OP:
			if ( s2->s==NULL ) return 0;
			rt = str_strcasecmp(s1, s2);
			if (rt>0)
				ret = 1;
			else if(rt==0 && s1->len>s2->len)
				ret = 1;
			else ret = 0;
			break;
		case GTE_OP:
			if ( s2->s==NULL ) return 0;
			rt = str_strcasecmp(s1, s2);
			if (rt>0)
				ret = 1;
			else if(rt==0 && s1->len>=s2->len)
				ret = 1;
			else ret = 0;
			break;
		case LT_OP:
			if ( s2->s==NULL ) return 0;
			rt = str_strcasecmp(s1, s2);
			if (rt<0)
				ret = 1;
			else if(rt==0 && s1->len<s2->len)
				ret = 1;
			else ret = 0;
			break;
		case LTE_OP:
			if ( s2->s==NULL ) return 0;
			rt = str_strcasecmp(s1, s2);
			if (rt<0)
				ret = 1;
			else if(rt==0 && s1->len<=s2->len)
				ret = 1;
			else ret = 0;
			break;
		case MATCH_OP:
			if ( s2==NULL ) return 0;
			make_nt_copy( &cp1, s1);
			ret=(regexec((regex_t*)s2, cp1.s, 0, 0, 0)==0);
			break;
		case NOTMATCH_OP:
			if ( s2==NULL ) return 1;
			make_nt_copy( &cp1, s1);
			ret=(regexec((regex_t*)s2, cp1.s, 0, 0, 0)!=0);
			break;
		case MATCHD_OP:
		case NOTMATCHD_OP:
			if ( s2==NULL || s2->s==NULL)
				return (op == MATCHD_OP? 0 : 1);
			re=(regex_t*)pkg_malloc(sizeof(regex_t));
			if (re==0) {
				LM_CRIT("pkg memory allocation failure\n");
				return -1;
			}

			make_nt_copy( &cp1, s1);
			make_nt_copy( &cp2, s2);

			if (regcomp(re, cp2.s, REG_EXTENDED|REG_NOSUB|REG_ICASE)) {
				pkg_free(re);
				return -1;
			}
			if(op==MATCHD_OP)
				ret=(regexec(re, cp1.s, 0, 0, 0)==0);
			else
				ret=(regexec(re, cp1.s, 0, 0, 0)!=0);
			regfree(re);
			pkg_free(re);
			break;
		default:
			LM_CRIT("unknown op %d\n", op);
	}
	return ret;
}

/*! \brief compare nr to nr */
inline static int comp_n2n(int op, int n1, int n2)
{
	switch(op) {
		case EQUAL_OP:
		case MATCH_OP:
		case MATCHD_OP:
			if(n1 == n2)
				return 1;
			return 0;
		case NOTMATCH_OP:
		case NOTMATCHD_OP:
		case DIFF_OP:
			if(n1 != n2)
				return 1;
			return 0;
		case GT_OP:
			if(n1 > n2)
				return 1;
			return 0;
		case GTE_OP:
			if(n1 >= n2)
				return 1;
			return 0;
		case LT_OP:
			if(n1 < n2)
				return 1;
			return 0;
		case LTE_OP:
			if(n1 <= n2)
				return 1;
			return 0;
		default:
			LM_CRIT("unknown op %d\n", op);
	}
	return -1;
}


static inline const char *op_id_2_string(int op_id)
{
	switch (op_id) {
		case EQUAL_OP:
			return "EQUAL";
		case MATCH_OP:
			return "REGEXP_MATCH";
		case NOTMATCH_OP:
			return "REGEXP_NO_MATCH";
		case MATCHD_OP:
			return "DYN_REGEXP_MATCH";
		case NOTMATCHD_OP:
			return "DYN_REGEXP_NO_MATCH";
		case GT_OP:
			return "GREATER_THAN";
		case LT_OP:
			return "LESS_THAN";
		case GTE_OP:
			return "GREATER_OR_EQUAL";
		case LTE_OP:
			return "LESS_OR_EQUAL";
		case DIFF_OP:
			return "DIFFERENT_THAN";
		case VALUE_OP:
			return "VALUE";
		case NO_OP:
		default:
			return "NONE";
	}
}


static inline const char *expr_type_2_string(int expr_type)
{
	switch (expr_type) {
		case STRING_ST:
			return "STRING";
		case NET_ST:
			return "NET_MASK";
		case NUMBER_ST:
			return "NUMBER";
		case IP_ST:
			return "IP";
		case RE_ST:
			return "REGEXP";
		case PROXY_ST:
			return "PROXY";
		case EXPR_ST:
			return "EXPRESSION";
		case ACTIONS_ST:
			return "ACTION";
		case CMD_ST:
			return "FUNCTION";
		case MODFIXUP_ST:
			return "MOD_FIXUP";
		case STR_ST:
			return "STR";
		case SOCKID_ST:
			return "SOCKET";
		case SOCKETINFO_ST:
			return "SOCKET_INFO";
		case SCRIPTVAR_ST:
			return "VARIABLE";
		case NULLV_ST:
			return "NULL";
		case BLACKLIST_ST:
			return "BLACKLIST";
		case SCRIPTVAR_ELEM_ST:
			return "VARIABLE_ELEMENT";
		case NOSUBTYPE:
		default:
			return"NONE";
	}
}

static inline const char *val_type_2_string(int val_type)
{
	if (val_type&PV_VAL_STR)
		return "STRING_VAL";
	if (val_type&PV_VAL_INT)
		return "INTEGER_VAL";
	if (val_type&PV_VAL_NULL)
		return "NULL_VAL";
	if (val_type&PV_VAL_EMPTY)
		return "EMPTY_VAL";
	return "NO_VAL";
}


inline static int comp_scriptvar(struct sip_msg *msg, int op, operand_t *left,
		operand_t *right)
{
	str lstr;
	str rstr;
	int ln;
	int rn;
	pv_value_t lvalue;
	pv_value_t rvalue;
	int type;
	struct net *rnet;

	lstr.s = 0; lstr.len = 0;
	rstr.s = 0; rstr.len = 0;
	ln = 0; rn =0;

	if(pv_get_spec_value(msg, left->v.spec, &lvalue)!=0)
	{
		LM_ERR("cannot get left var value\n");
		goto error;
	}
	if(right->type==NULLV_ST)
	{
		if(op==EQUAL_OP)
		{
			if(lvalue.flags&PV_VAL_NULL)
				return 1;
			return 0;
		} else {
			if(lvalue.flags&PV_VAL_NULL)
				return 0;
			return 1;
		}
	}

	lstr = lvalue.rs;
	ln   = lvalue.ri;
	type = 0;
	rvalue.flags = 0; /*just for err printing purposes */

	if(right->type == SCRIPTVAR_ST)
	{
		if(pv_get_spec_value(msg, right->v.spec, &rvalue)!=0)
		{
			LM_ERR("cannot get right var value\n");
			goto error;
		}
		if(rvalue.flags&PV_VAL_NULL || lvalue.flags&PV_VAL_NULL ) {
			if (rvalue.flags&PV_VAL_NULL && lvalue.flags&PV_VAL_NULL )
				return (op==EQUAL_OP || op==MATCH_OP || op==MATCHD_OP)?1:0;
			return (op==DIFF_OP || op==NOTMATCH_OP || op==NOTMATCHD_OP)?1:0;
		}

		if(op==MATCH_OP||op==NOTMATCH_OP)
		{
			if(!((rvalue.flags&PV_VAL_STR) && (lvalue.flags&PV_VAL_STR)))
				goto error_op;
			if(op==MATCH_OP)
				return comp_s2s(MATCHD_OP, &lstr, &rvalue.rs);
			else
				return comp_s2s(NOTMATCHD_OP, &lstr, &rvalue.rs);
		}

		if((rvalue.flags&PV_VAL_INT) && (lvalue.flags&PV_VAL_INT)) {
			/* comparing int */
			rn = rvalue.ri;
			type =2;
		} else if((rvalue.flags&PV_VAL_STR) && (lvalue.flags&PV_VAL_STR)) {
			/* comparing string */
			rstr = rvalue.rs;
			type =1;
		} else
			goto error_op;
	} else {
		/* null against a not-null constant */
		if(lvalue.flags&PV_VAL_NULL)
			return (op==DIFF_OP || op==NOTMATCH_OP || op==NOTMATCHD_OP)?1:0;

		if (right->type == NET_ST) {
			if(!(lvalue.flags&PV_VAL_STR))
				goto error_op;
			/* comparing IP */
			type = 3;
			rnet =  (struct net*)right->v.data;
		} else if(right->type == NUMBER_ST) {
			if(!(lvalue.flags&PV_VAL_INT))
				goto error_op;
			/* comparing int */
			type =2;
			rn = right->v.n;
		} else if(right->type == STR_ST) {
			if(!(lvalue.flags&PV_VAL_STR))
				goto error_op;
			/* comparing string */
			type =1;
			rstr = right->v.s;
		} else {
			if(op==MATCH_OP || op==NOTMATCH_OP)
			{
				if(!(lvalue.flags&PV_VAL_STR) || right->type != RE_ST)
					goto error_op;
				return comp_s2s(op, &lstr, (str*)right->v.expr);
			}
			/* comparing others */
			type = 0;
		}
	}

	if(type==1) { /* compare str */
		LM_DBG("str %d : %.*s\n", op, lstr.len, ZSW(lstr.s));
		return comp_s2s(op, &lstr, &rstr);
	} else if(type==2) {
		LM_DBG("int %d : %d / %d\n", op, ln, rn);
		return comp_n2n(op, ln, rn);
	} else if (type==3) {
		LM_DBG("ip %d : %.*s\n", op, lstr.len, ZSW(lstr.s));
		return comp_ip(op, &lstr, rnet);
	}
	/* default is error */

error_op:
	LM_WARN("invalid %s operation: left is %s/%s, right is %s/%s\n",
		op_id_2_string(op),
		expr_type_2_string(left->type), val_type_2_string(lvalue.flags),
		expr_type_2_string(right->type), val_type_2_string(rvalue.flags) );
error:
	return -1;
}


/*! \brief
 * \return 0/1 (false/true) or -1 on error, -127 EXPR_DROP
 */
static int eval_elem(struct expr* e, struct sip_msg* msg, pv_value_t *val)
{
	int ret;
/*	int retl;
	int retr; */
	int ival;
	pv_value_t lval;
	pv_value_t rval;
	char *p;
	int i,n;

	ret=E_BUG;
	if (e->type!=ELEM_T){
		LM_CRIT("invalid type\n");
		goto error;
	}

	if(val) memset(val, 0, sizeof(pv_value_t));

	switch(e->left.type){
		case NUMBER_O:
				ret=!(!e->right.v.n); /* !! to transform it in {0,1} */
				break;
		case ACTION_O:
				ret=run_action_list( (struct action*)e->right.v.data, msg);
				if(val)
				{
					val->flags = PV_TYPE_INT|PV_VAL_INT;
					val->ri = ret;
				}
				if (ret<=0) ret=(ret==0)?EXPR_DROP:0;
				else ret=1;
				return ret;
		case EXPR_O:
				/* retl = retr = 0; */
				memset(&lval, 0, sizeof(pv_value_t));
				memset(&rval, 0, sizeof(pv_value_t));
				if(e->left.v.data)
					eval_expr((struct expr*)e->left.v.data,msg,&lval);
					/* XXX why is retl used here ?? */
					/* retl=eval_expr((struct expr*)e->left.v.data,msg,&lval); */
				if(lval.flags == PV_VAL_NONE)
				{
					pv_value_destroy(&lval);
					pv_value_destroy(&rval);
					return 0;
				}
				if(e->op == BNOT_OP)
				{
					if(lval.flags&PV_VAL_INT)
					{
						if(val!=NULL)
						{
							val->flags = PV_TYPE_INT|PV_VAL_INT;
							val->ri = ~lval.ri;
						}
						pv_value_destroy(&lval);
						pv_value_destroy(&rval);
						return (val->ri)?1:0;
					}
					LM_ERR("binary NOT on non-numeric value\n");
					pv_value_destroy(&lval);
					pv_value_destroy(&rval);
					return 0;
				}
				if(e->right.v.data)
					eval_expr((struct expr*)e->right.v.data,msg,&rval);
					/* retr=eval_expr((struct expr*)e->right.v.data,msg,&rval); */

				if(lval.flags&PV_TYPE_INT)
				{
					if( (rval.flags&PV_VAL_NULL) )
					{
						rval.ri = 0;
					} else if(!(rval.flags&PV_VAL_INT))
					{
						LM_ERR("invalid numeric operands\n");
						pv_value_destroy(&lval);
						pv_value_destroy(&rval);
						return 0;
					}
					if(val!=NULL)
						val->flags = PV_TYPE_INT|PV_VAL_INT;

					ival = 0;
					switch(e->op) {
						case PLUS_OP:
							ival = lval.ri + rval.ri;
							break;
						case MINUS_OP:
							ival = lval.ri - rval.ri;
							break;
						case DIV_OP:
							if(rval.ri==0)
							{
								LM_ERR("divide by 0\n");
								pv_value_destroy(&lval);
								pv_value_destroy(&rval);
								return 0;
							} else
								ival = lval.ri / rval.ri;
							break;
						case MULT_OP:
							ival = lval.ri * rval.ri;
							break;
						case MODULO_OP:
							if(rval.ri==0)
							{
								LM_ERR("divide by 0\n");
								pv_value_destroy(&lval);
								pv_value_destroy(&rval);
								return 0;
							} else
								ival = lval.ri % rval.ri;
							break;
						case BAND_OP:
							ival = lval.ri & rval.ri;
							break;
						case BOR_OP:
							ival = lval.ri | rval.ri;
							break;
						case BXOR_OP:
							ival = lval.ri ^ rval.ri;
							break;
						case BLSHIFT_OP:
							ival = lval.ri << rval.ri;
							break;
						case BRSHIFT_OP:
							ival = lval.ri >> rval.ri;
							break;
						default:
							LM_ERR("invalid int op %d\n", e->op);
							if(val!=NULL) val->ri = 0;
							pv_value_destroy(&lval);
							pv_value_destroy(&rval);
							return 0;
					}
					pv_value_destroy(&lval);
					pv_value_destroy(&rval);
					if(val!=NULL) val->ri = ival;
					return (ival)?1:0;
				} else if (e->op == PLUS_OP) {
					if (!val) {
						ret = (lval.rs.len>0 || rval.rs.len>0);
						pv_value_destroy(&lval);
						pv_value_destroy(&rval);
						return ret;
					}

					if (rval.flags & PV_VAL_NULL) {
						pv_value_destroy(&rval);
						rval.flags = PV_VAL_STR;
					}

					if(!(rval.flags&PV_VAL_STR))
					{
						LM_ERR("invalid string operands\n");
						pv_value_destroy(&lval);
						pv_value_destroy(&rval);
						return 0;
					}
					val->rs.s=(char*)pkg_malloc((lval.rs.len+rval.rs.len+1)
							*sizeof(char));
					if(val->rs.s==0)
					{
						LM_ERR("no more memory\n");
						pv_value_destroy(&lval);
						pv_value_destroy(&rval);
						return 0;
					}
					val->flags = PV_VAL_PKG|PV_VAL_STR;
					memcpy(val->rs.s, lval.rs.s, lval.rs.len);
					memcpy(val->rs.s+lval.rs.len, rval.rs.s, rval.rs.len);
					val->rs.len = lval.rs.len + rval.rs.len;
					val->rs.s[val->rs.len] = '\0';
					pv_value_destroy(&lval);
					pv_value_destroy(&rval);
					return 1;
				} else if ((lval.flags & PV_VAL_STR) && (rval.flags & PV_VAL_STR)) {
					if (lval.rs.len != rval.rs.len)
					{
						LM_ERR("Different length string operands\n");
						pv_value_destroy(&lval);
						pv_value_destroy(&rval);
						return 0;
					}
					n = lval.rs.len;
					val->rs.s = pkg_malloc(n+1);
					if (!val->rs.s)
					{
						LM_ERR("no more memory\n");
						pv_value_destroy(&lval);
						pv_value_destroy(&rval);
						return 0;
					}
					switch(e->op) {
						case BAND_OP:
							for (i=0;i<n;i++)
								val->rs.s[i] = lval.rs.s[i] & rval.rs.s[i];
							break;
						case BOR_OP:
							for (i=0;i<n;i++)
								val->rs.s[i] = lval.rs.s[i] | rval.rs.s[i];
							break;
						case BXOR_OP:
							for (i=0;i<n;i++)
								val->rs.s[i] = lval.rs.s[i] ^ rval.rs.s[i];
							break;
						default:
							LM_ERR("Only bitwise operations can be applied on strings\n");
							val->ri = 0;
							pv_value_destroy(&lval);
							pv_value_destroy(&rval);
							return 0;
					}
					val->flags = PV_VAL_PKG|PV_VAL_STR;
					val->rs.len = n;
					val->rs.s[n] = '\0';
					pv_value_destroy(&lval);
					pv_value_destroy(&rval);
					return 1;
				}
				else {
					LM_ERR("Invalid operator : %d \n",e->op);
					pv_value_destroy(&lval);
					pv_value_destroy(&rval);
					return 0;
				}
				break;
		case STRINGV_O:
				if(val) {
					val->flags = PV_VAL_STR;
					val->rs = e->left.v.s;
				}
				/* optimization for no dup ?!?! */
				return (e->left.v.s.len>0)?1:0;
		case NUMBERV_O:
				if(val) {
					val->flags = PV_TYPE_INT|PV_VAL_INT;
					val->ri = e->left.v.n;
				}
				ret=!(!e->left.v.n); /* !! to transform it in {0,1} */
				return ret;
		case SCRIPTVAR_O:
				if(e->op==NO_OP)
				{
					memset(&rval, 0, sizeof(pv_value_t));
					if(pv_get_spec_value(msg, e->right.v.spec, &rval)==0)
					{
						if(rval.flags==PV_VAL_NONE || (rval.flags&PV_VAL_NULL)
								|| (rval.flags&PV_VAL_EMPTY)
								|| ((rval.flags&PV_TYPE_INT)&&rval.ri==0))
						{
							pv_value_destroy(&rval);
							return 0;
						}
						if(rval.flags&PV_TYPE_INT)
						{
							pv_value_destroy(&rval);
							return 1;
						}
						if(rval.rs.len!=0)
						{
							pv_value_destroy(&rval);
							return 1;
						}
						pv_value_destroy(&rval);
					}
					return 0;
				}
				if(e->op==VALUE_OP)
				{
					if(pv_get_spec_value(msg, e->left.v.spec, &lval)==0)
					{
						if(val!=NULL)
							memcpy(val, &lval, sizeof(pv_value_t));
						if(lval.flags&PV_VAL_STR)
						{
							if(!((lval.flags&PV_VAL_PKG)
									|| (lval.flags&PV_VAL_SHM)))
							{
								if(val!=NULL)
								{
									/* do pkg duplicate */
									p = (char*)pkg_malloc((val->rs.len+1)
											*sizeof(char));
									if(p==0)
									{
										LM_ERR("no more pkg memory\n");
										memset(val, 0, sizeof(pv_value_t));
										return 0;
									}
									memcpy(p, val->rs.s, val->rs.len);
									p[val->rs.len] = 0;
									val->rs.s = p;
									val->flags|= PV_VAL_PKG;
								}
							}
							return 1;
						}
						if(lval.flags==PV_VAL_NONE
								|| (lval.flags & PV_VAL_NULL)
								|| (lval.flags & PV_VAL_EMPTY))
							return 0;
						if(lval.flags&PV_TYPE_INT)
							return (lval.ri!=0);
						else
							return (lval.rs.len>0);
					}
					return 0;
				}

				ret=comp_scriptvar(msg, e->op, &e->left, &e->right);
				break;
		default:
				LM_CRIT("invalid operand %d\n", e->left.type);
	}
	if(val)
	{
		val->flags = PV_TYPE_INT|PV_VAL_INT;
		val->ri = ret;
	}
	return ret;
error:
	if(val)
	{
		val->flags = PV_TYPE_INT|PV_VAL_INT;
		val->ri = -1;
	}
	return -1;
}



/*! \return ret= 0/1 (false/true) ,  -1 on error or EXPR_DROP (-127)  */
int eval_expr(struct expr* e, struct sip_msg* msg, pv_value_t *val)
{
	static int rec_lev=0;
	int ret;

	rec_lev++;
	if (rec_lev>MAX_REC_LEV){
		LM_CRIT("too many expressions (%d)\n", rec_lev);
		ret=-1;
		goto skip;
	}

	if (e->type==ELEM_T){
		ret=eval_elem(e, msg, val);
	}else if (e->type==EXP_T){
		switch(e->op){
			case AND_OP:
				ret=eval_expr(e->left.v.expr, msg, val);
				/* if error or false stop evaluating the rest */
				if (ret!=1) break;
				ret=eval_expr(e->right.v.expr, msg, val); /*ret1 is 1*/
				break;
			case OR_OP:
				ret=eval_expr(e->left.v.expr, msg, val);
				/* if true or error stop evaluating the rest */
				if (ret!=0) break;
				ret=eval_expr(e->right.v.expr, msg, val); /* ret1 is 0 */
				break;
			case NOT_OP:
				ret=eval_expr(e->left.v.expr, msg, val);
				if (ret<0) break;
				ret= ! ret;
				break;
			case EVAL_OP:
				ret=eval_expr(e->left.v.expr, msg, val);
				break;
			default:
				LM_CRIT("unknown op %d\n", e->op);
				ret=-1;
		}
	}else{
		LM_CRIT("unknown type %d\n", e->type);
		ret=-1;
	}

skip:
	rec_lev--;
	return ret;
}


int run_startup_route(void)
{
	struct sip_msg *req;
	int ret, old_route_type;

	req = get_dummy_sip_msg();
	if(req == NULL) {
		LM_ERR("No more memory\n");
		return -1;
	}

	swap_route_type(old_route_type, STARTUP_ROUTE);
	/* run the route */
	ret = run_top_route( sroutes->startup.a, req);
	set_route_type(old_route_type);

	/* clean whatever extra structures were added by script functions */
	release_dummy_sip_msg(req);

	return ret;
}


/********************* Parsing/fixing related functions *********************/


int get_script_route_idx( char* name,struct script_route *sr, int size,int set)
{
	unsigned int i;

	for(i=1;i<size;i++) {
		if (sr[i].name==NULL) {
			/* name not found -> allocate it now */
			sr[i].name = name;
			return i;
		}
		if (strcmp(sr[i].name,name)==0 ) {
			/* name found */
			if (sr[i].a && set) {
				LM_ERR("Script route <%s> is redefined\n",name);
				return -1;
			}
			return i;
		}
	}
	LM_ERR("Too many routes - no socket left for <%s>\n",name);
	return -1;
}


/*! \brief traverses an expression tree and compiles the REs where necessary)
 * \return 0 for ok, <0 if errors
 */
static int fix_expr(struct expr* exp)
{
	regex_t* re;
	int ret;

	ret=E_BUG;
	if (exp==0){
		LM_CRIT("null pointer\n");
		return E_BUG;
	}
	if (exp->type==EXP_T){
		switch(exp->op){
			case AND_OP:
			case OR_OP:
					if ((ret=fix_expr(exp->left.v.expr))!=0)
						return ret;
					ret=fix_expr(exp->right.v.expr);
					break;
			case NOT_OP:
			case EVAL_OP:
					ret=fix_expr(exp->left.v.expr);
					break;
			default:
					LM_CRIT("unknown op %d\n", exp->op);
		}
	}else if (exp->type==ELEM_T){
			if (exp->op==MATCH_OP || exp->op==NOTMATCH_OP){
				if (exp->right.type==STR_ST){
					re=(regex_t*)pkg_malloc(sizeof(regex_t));
					if (re==0){
						LM_CRIT("out of pkg memory\n");
						return E_OUT_OF_MEM;
					}
					if (regcomp(re, (char*) exp->right.v.data,
								REG_EXTENDED|REG_NOSUB|REG_ICASE) ){
						LM_CRIT("bad re \"%s\"\n", (char*) exp->right.v.data);
						pkg_free(re);
						return E_BAD_RE;
					}
					/* replace the string with the re */
					pkg_free(exp->right.v.data);
					exp->right.v.data=re;
					exp->right.type=RE_ST;
				}else if (exp->right.type!=RE_ST
						&& exp->right.type!=SCRIPTVAR_ST){
					LM_CRIT("invalid type for match\n");
					return E_BUG;
				}
			}
			if (exp->left.type==ACTION_O){
				ret=fix_actions((struct action*)exp->right.v.data);
				if (ret!=0){
					LM_CRIT("fix_actions error\n");
					return ret;
				}
			}
			if (exp->left.type==EXPR_O){
				ret=fix_expr(exp->left.v.expr);
				if (ret!=0){
					LM_CRIT("fix left exp error\n");
					return ret;
				}
			}
			if (exp->right.type==EXPR_ST){
				ret=fix_expr(exp->right.v.expr);
				if (ret!=0){
					LM_CRIT("fix right exp error\n");
					return ret;
				}
			}
			ret=0;
	}
	return ret;
}


/*! \brief Adds the proxies in the proxy list & resolves the hostnames
 * \return 0 if ok, <0 on error */
static int fix_actions(struct action* a)
{
	struct action *t;
	int ret;
	cmd_export_t* cmd;
	acmd_export_t* acmd;
	str s;
	pv_elem_t *model=NULL;
	xl_level_p xlp;

	if (a==0){
		LM_CRIT("null pointer\n");
		return E_BUG;
	}
	for(t=a; t!=0; t=t->next){
		switch(t->type){
			case ROUTE_T:
				ret = 0;
				switch (t->elem[0].type) {
					case SCRIPTVAR_ST:
					case SCRIPTVAR_ELEM_ST:
						break;
					case NUMBER_ST:
						if ((t->elem[0].u.number>RT_NO)||(t->elem[0].u.number<0)){
							LM_ALERT("invalid routing table number in"
									"route(%lu)\n", t->elem[0].u.number);
							ret = -1;
						}
						if (sroutes->request[t->elem[0].u.number].a==NULL) {
							LM_ERR("called route [%s] (id=%d) is not defined\n",
									sroutes->request[t->elem[0].u.number].name,
									(int)t->elem[0].u.number);
							ret = -1;
						}
						break;
					default:
						ret = -1;
						break;
				}
				if (ret == -1) {
					LM_ERR("failed to validate a route() statement (type %d)\n",
					           t->elem[0].type);
					ret = E_CFG;
					goto error;
				}
				if (t->elem[1].type != 0) {
					if (t->elem[1].type != NUMBER_ST ||
							t->elem[2].type != SCRIPTVAR_ST) {
						LM_ALERT("BUG in route() type %d/%d\n",
								 t->elem[1].type, t->elem[2].type);
						ret=E_BUG;
						goto error;
					}
					if (t->elem[1].u.number >= MAX_ACTION_ELEMS ||
							t->elem[1].u.number <= 0) {
						LM_ALERT("BUG in number of route parameters %d\n",
								 (int)t->elem[1].u.number);
						ret=E_BUG;
						goto error;
					}
				}
				break;
			case ASSERT_T:
				if (t->elem[0].type!=EXPR_ST){
					LM_CRIT("invalid subtype %d for assert (should be expr)\n",
								t->elem[0].type);
					ret = E_BUG;
					goto error;
				}
				if (t->elem[0].u.data)
					if ((ret=fix_expr((struct expr*)t->elem[0].u.data))<0)
						return ret;
				break;
			case IF_T:
				if (t->elem[0].type!=EXPR_ST){
					LM_CRIT("invalid subtype %d for if (should be expr)\n",
								t->elem[0].type);
					ret = E_BUG;
					goto error;
				}else if( (t->elem[1].type!=ACTIONS_ST)
						&&(t->elem[1].type!=NOSUBTYPE) ){
					LM_CRIT("invalid subtype %d for if() {...} (should be"
								"action)\n", t->elem[1].type);
					ret = E_BUG;
					goto error;
				}else if( (t->elem[2].type!=ACTIONS_ST)
						&&(t->elem[2].type!=NOSUBTYPE) ){
					LM_CRIT("invalid subtype %d for if() {} else{...}(should"
							"be action)\n", t->elem[2].type);
					ret = E_BUG;
					goto error;
				}
				if (t->elem[0].u.data){
					if ((ret=fix_expr((struct expr*)t->elem[0].u.data))<0)
						return ret;
				}
				if ( (t->elem[1].type==ACTIONS_ST)&&(t->elem[1].u.data) ){
					if ((ret=fix_actions((struct action*)t->elem[1].u.data))<0)
						return ret;
				}
				if ( (t->elem[2].type==ACTIONS_ST)&&(t->elem[2].u.data) ){
					if((ret=fix_actions((struct action*)t->elem[2].u.data))<0)
						return ret;
				}
				break;
			case WHILE_T:
				if (t->elem[0].type!=EXPR_ST){
					LM_CRIT("invalid subtype %d for while (should be expr)\n",
								t->elem[0].type);
					ret = E_BUG;
					goto error;
				}else if( (t->elem[1].type!=ACTIONS_ST)
						&&(t->elem[1].type!=NOSUBTYPE) ){
					LM_CRIT("invalid subtype %d for while() {...} (should be"
								"action)\n", t->elem[1].type);
					ret = E_BUG;
					goto error;
				}
				if (t->elem[0].u.data){
					if ((ret=fix_expr((struct expr*)t->elem[0].u.data))<0)
						return ret;
				}
				if ( (t->elem[1].type==ACTIONS_ST)&&(t->elem[1].u.data) ){
					if ((ret=fix_actions((struct action*)t->elem[1].u.data))<0)
						return ret;
				}
				break;
			case FOR_EACH_T:
				if (t->elem[2].type != ACTIONS_ST) {
					LM_CRIT("bad subtype %d in for-each (should be actions)\n",
				             t->elem[2].type);
					ret = E_BUG;
					goto error;
				}

				if (t->elem[2].u.data) {
					if ((ret=fix_actions((struct action*)t->elem[2].u.data))<0)
						return ret;
				}
				break;
			case SWITCH_T:
				if ( (t->elem[1].type==ACTIONS_ST)&&(t->elem[1].u.data) ){
					if ((ret=fix_actions((struct action*)t->elem[1].u.data))<0)
						return ret;
				}
				break;
			case CASE_T:
				if ( (t->elem[1].type==ACTIONS_ST)&&(t->elem[1].u.data) ){
					if ((ret=fix_actions((struct action*)t->elem[1].u.data))<0)
						return ret;
				}
				break;
			case DEFAULT_T:
				if ( (t->elem[0].type==ACTIONS_ST)&&(t->elem[0].u.data) ){
					if ((ret=fix_actions((struct action*)t->elem[0].u.data))<0)
						return ret;
				}
				break;
			case CMD_T:
				cmd = (cmd_export_t*)t->elem[0].u.data;
				LM_DBG("fixing %s, %s:%d\n", cmd->name, t->file, t->line);

				if ((ret = fix_cmd(cmd->params, t->elem)) < 0) {
					LM_ERR("Failed to fix command <%s>\n", cmd->name);
					goto error;
				}
				break;
			case ASYNC_T:
			case LAUNCH_T:
				if ( (t->elem[0].type==ACTIONS_ST)&&(t->elem[0].u.data) ){
					if ((ret=fix_actions((struct action*)t->elem[0].u.data))<0)
						return ret;
				}
				break;
			case AMODULE_T:
				acmd = (acmd_export_t*)t->elem[0].u.data;
				LM_DBG("fixing async %s, %s:%d\n", acmd->name, t->file, t->line);

				if ((ret = fix_cmd(acmd->params, t->elem)) < 0) {
					LM_ERR("Failed to fix command <%s>\n", acmd->name);
					goto error;
				}
				break;
			case EQ_T:
			case COLONEQ_T:
			case PLUSEQ_T:
			case MINUSEQ_T:
			case DIVEQ_T:
			case MULTEQ_T:
			case MODULOEQ_T:
			case BANDEQ_T:
			case BOREQ_T:
			case BXOREQ_T:
				if (t->elem[1].u.data){
					if ((ret=fix_expr((struct expr*)t->elem[1].u.data))<0)
						return ret;
				}
				break;
			case XDBG_T:
			case XLOG_T:
				s.s = (char*)t->elem[1].u.data;
				if (s.s == NULL)
				{
					/* commands have only one parameter */
					s.s = (char *)t->elem[0].u.data;
					s.len = strlen(s.s);
					if(s.len==0)
					{
						LM_ERR("param is empty string!\n");
						return E_CFG;
					}

					if(pv_parse_format(&s ,&model) || model==NULL)
					{
						LM_ERR("wrong format [%s] for value param!\n", s.s);
						ret=E_BUG;
						goto error;
					}

					t->elem[0].u.data = (void*)model;
					t->elem[0].type = SCRIPTVAR_ELEM_ST;
				}
				else
				{
					/* there are two parameters */
					s.s = (char *)t->elem[0].u.data;
					s.len = strlen(s.s);
					if (s.len == 0)
					{
						LM_ERR("param is empty string\n");
						return E_CFG;
					}
					xlp = (xl_level_p)pkg_malloc(sizeof(xl_level_t));
					if(xlp == NULL)
					{
						LM_ERR("no more memory\n");
						return E_UNSPEC;
					}

					memset(xlp, 0, sizeof(xl_level_t));
					if(s.s[0]==PV_MARKER)
					{
						xlp->type = 1;
						if(pv_parse_spec(&s, &xlp->v.sp)==NULL)
						{
							LM_ERR("invalid level param\n");
							return E_UNSPEC;
						}
					}
					else
					{
						xlp->type = 0;
						switch(s.s[2])
						{
							case 'A': xlp->v.level = L_ALERT; break;
							case 'C': xlp->v.level = L_CRIT; break;
							case 'E': xlp->v.level = L_ERR; break;
							case 'W': xlp->v.level = L_WARN; break;
							case 'N': xlp->v.level = L_NOTICE; break;
							case 'I': xlp->v.level = L_INFO; break;
							case 'D': xlp->v.level = L_DBG; break;
							default:
								LM_ERR("unknown log level\n");
								return E_UNSPEC;
						}
					}
					t->elem[0].u.data = xlp;

					s.s = t->elem[1].u.data;
					s.len = strlen(s.s);
					if (pv_parse_format(&s, &model) || model == NULL)
					{
						LM_ERR("wrong format [%s] for value param\n",s.s);
						ret=E_BUG;
						goto error;
					}

					t->elem[1].u.data = model;
					t->elem[1].type = SCRIPTVAR_ELEM_ST;
				}
				break;
		}
	}
	return 0;
error:
	LM_ERR("fixing failed (code=%d) at %s:%d\n", ret, t->file, t->line);
	return ret;
}


/*! \brief adds an action list to head; a must be null terminated (last a->next=0))
 */
void push(struct action* a, struct action** head)
{
	struct action *t;
	if (*head==0){
		*head=a;
		return;
	}
	for (t=*head; t->next;t=t->next);
	t->next=a;
}


/*! \brief fixes all action tables
 * \return 0 if ok , <0 on error
 */
int fix_rls(void)
{
	int i,ret;
	for(i=0;i<RT_NO;i++){
		if(sroutes->request[i].a){
			if ((ret=fix_actions(sroutes->request[i].a))!=0){
				return ret;
			}
		}
	}
	for(i=0;i<ONREPLY_RT_NO;i++){
		if(sroutes->onreply[i].a){
			if ((ret=fix_actions(sroutes->onreply[i].a))!=0){
				return ret;
			}
		}
	}
	for(i=0;i<FAILURE_RT_NO;i++){
		if(sroutes->failure[i].a){
			if ((ret=fix_actions(sroutes->failure[i].a))!=0){
				return ret;
			}
		}
	}
	for(i=0;i<BRANCH_RT_NO;i++){
		if(sroutes->branch[i].a){
			if ((ret=fix_actions(sroutes->branch[i].a))!=0){
				return ret;
			}
		}
	}
	if(sroutes->error.a){
		if ((ret=fix_actions(sroutes->error.a))!=0){
			return ret;
		}
	}
	if(sroutes->local.a){
		if ((ret=fix_actions(sroutes->local.a))!=0){
			return ret;
		}
	}
	if(sroutes->startup.a){
		if ((ret=fix_actions(sroutes->startup.a))!=0){
			return ret;
		}
	}

	for(i = 0; i< TIMER_RT_NO; i++) {
		if(sroutes->timer[i].a == NULL)
			break;

		if ((ret=fix_actions(sroutes->timer[i].a))!=0){
			return ret;
		}
	}

	for(i = 1; i< EVENT_RT_NO; i++) {
		if(sroutes->event[i].a == NULL)
			break;

		if ((ret=fix_actions(sroutes->event[i].a))!=0){
			return ret;
		}
	}


return 0;
}


static int rcheck_stack[RT_NO];
static int rcheck_stack_p = 0;
static int rcheck_status = 0;

static int check_expr(struct expr* exp, int r_type);

static int check_actions(struct action *a, int r_type)
{
	struct action *aitem;
	cmd_export_t  *fct;
	int n;

	for( ; a ; a=a->next ) {
		switch (a->type) {
			case ROUTE_T:
				/* this route is already on the current path ? */
				for( n=0 ; n<rcheck_stack_p ; n++ ) {
					if (rcheck_stack[n]==(int)a->elem[0].u.number)
						break;
				}
				if (n!=rcheck_stack_p)
					break;
				if (++rcheck_stack_p==RT_NO) {
					LM_CRIT("stack overflow (%d)\n", rcheck_stack_p);
					goto error;
				}
				rcheck_stack[rcheck_stack_p] = a->elem[0].u.number;
				if (check_actions(sroutes->request[a->elem[0].u.number].a,
				r_type)!=0)
					goto error;
				rcheck_stack_p--;
				break;
			case IF_T:
				if (check_expr((struct expr*)a->elem[0].u.data, r_type) < 0)
					goto error;
				if (check_actions((struct action*)a->elem[1].u.data, r_type)!=0)
					goto error;
				if (check_actions((struct action*)a->elem[2].u.data, r_type)!=0)
					goto error;
				break;
			case WHILE_T:
				if (check_actions((struct action*)a->elem[1].u.data, r_type)!=0)
					goto error;
				break;
			case FOR_EACH_T:
				if (check_actions((struct action*)a->elem[2].u.data, r_type)!=0)
					goto error;
				break;
			case SWITCH_T:
				aitem = (struct action*)a->elem[1].u.data;
				for( ; aitem ; aitem=aitem->next ) {
					n = check_actions((struct action*)aitem->elem[1].u.data,
							r_type);
					if (n!=0) goto error;
				}
				break;
			case CMD_T:
				/* do check :D */
				fct = (cmd_export_t*)(a->elem[0].u.data);
				if ( (fct->flags&r_type)!=r_type ) {
					rcheck_status = -1;
					LM_ERR("script function "
						"\"%s\" (types=%d) does not support route type "
						"(%d)\n",fct->name, fct->flags, r_type);
					for( n=rcheck_stack_p-1; n>=0 ; n-- ) {
						LM_ERR("route stack[%d]=%d\n",n,rcheck_stack[n]);
					}
				}

				if (check_cmd(fct->params, a->elem) < 0) {
					LM_ERR("check failed for function <%s>, %s:%d\n", fct->name,
						a->file, a->line);
					rcheck_status = -1;
				}
				break;
			default:
				break;
		}
	}

	return 0;
error:
	return -1;
}

static int check_expr(struct expr* exp, int r_type)
{
	int ret = -1;

	if (exp==0) {
		LM_CRIT("null pointer\n");
		return -1;
	}

	if (exp->type==EXP_T){
		switch(exp->op){
			case AND_OP:
			case OR_OP:
				if (check_expr(exp->left.v.expr, r_type) < 0)
					return -1;
				return check_expr(exp->right.v.expr, r_type);
			case NOT_OP:
			case EVAL_OP:
				return check_expr(exp->left.v.expr, r_type);
			default:
				LM_CRIT("unknown op %d\n", exp->op);
				return -1;
		}
	} else if (exp->type==ELEM_T){
			if (exp->left.type==ACTION_O){
				ret=check_actions((struct action*)exp->right.v.data, r_type);
				if (ret!=0){
					LM_CRIT("check_actions error\n");
					return ret;
				}
			}
			if (exp->left.type==EXPR_O){
				ret=check_expr(exp->left.v.expr, r_type);
				if (ret!=0){
					LM_CRIT("check left exp error\n");
					return ret;
				}
			}
			if (exp->right.type==EXPR_ST){
				ret=check_expr(exp->right.v.expr, r_type);
				if (ret!=0){
					LM_CRIT("fix right exp error\n");
					return ret;
				}
			}
			ret=0;
	}

	return ret;
}


/*! \brief check all parsed routing tables for compatiblity between
 * route types and called module functions;
 * \return 0 if ok , <0 on error
 */
int check_rls(void)
{
	int i,ret;

	rcheck_status = 0;

	if(sroutes->request[0].a){
		if ((ret=check_actions(sroutes->request[0].a,
		REQUEST_ROUTE))!=0){
			LM_ERR("check failed for main request route\n");
			return ret;
		}
	}
	for(i=0;i<ONREPLY_RT_NO;i++){
		if(sroutes->onreply[i].a){
			if ((ret=check_actions(sroutes->onreply[i].a,
			ONREPLY_ROUTE))!=0){
				LM_ERR("check failed for onreply_route[%d]\n",i);
				return ret;
			}
		}
	}
	for(i=0;i<FAILURE_RT_NO;i++){
		if(sroutes->failure[i].a){
			if ((ret=check_actions(sroutes->failure[i].a,
			FAILURE_ROUTE))!=0){
				LM_ERR("check failed for failure_route[%d]\n",i);
				return ret;
			}
		}
	}
	for(i=0;i<BRANCH_RT_NO;i++){
		if(sroutes->branch[i].a){
			if ((ret=check_actions(sroutes->branch[i].a,
			BRANCH_ROUTE))!=0){
				LM_ERR("check failed for branch_route[%d]\n",i);
				return ret;
			}
		}
	}
	if(sroutes->error.a){
		if ((ret=check_actions(sroutes->error.a,ERROR_ROUTE))!=0){
			LM_ERR("check failed for error_route\n");
			return ret;
		}
	}
	if(sroutes->local.a){
		if ((ret=check_actions(sroutes->local.a,LOCAL_ROUTE))!=0){
			LM_ERR("check failed for local_route\n");
			return ret;
		}
	}
	if(sroutes->startup.a){
		if ((ret=check_actions(sroutes->startup.a,STARTUP_ROUTE))!=0){
			LM_ERR("check failed for startup_route\n");
			return ret;
		}
	}

	for(i = 0; i< TIMER_RT_NO; i++) {
		if(sroutes->timer[i].a == NULL)
			break;

		if ((ret=check_actions(sroutes->timer[i].a,TIMER_ROUTE))!=0){
			LM_ERR("check failed for timer_route\n");
			return ret;
		}
	}

	for(i = 1; i< EVENT_RT_NO; i++) {
		if(sroutes->event[i].a == NULL)
			break;

		if ((ret=check_actions(sroutes->event[i].a,EVENT_ROUTE))!=0){
			LM_ERR("check failed for event_route\n");
			return ret;
		}
	}

	return rcheck_status;
}


/*! \brief debug function, prints main routing table */
void print_rl(struct os_script_routes *srs)
{
#define dump_script_routes( route, max, desc) \
	{ \
		int __j; \
		for (__j = 0; __j < max; __j++) { \
			if (!(route)[__j].a) \
				continue; \
			LM_GEN1(L_DBG, desc " routing block %d:\n", __j); \
			print_actions((route)[__j].a); \
			LM_GEN1(L_DBG, "\n\n"); \
		} \
	}

	dump_script_routes(srs->request,  RT_NO,         "main");
	dump_script_routes(srs->onreply,  ONREPLY_RT_NO, "onreply");
	dump_script_routes(srs->failure,  FAILURE_RT_NO, "failure");
	dump_script_routes(srs->branch,   BRANCH_RT_NO,  "branch");
	dump_script_routes(&srs->local,   1,             "local");
	dump_script_routes(&srs->error,   1,             "error");
	dump_script_routes(&srs->startup, 1,             "startup");
	dump_script_routes(srs->timer,    TIMER_RT_NO,   "timer");
	dump_script_routes(srs->event,    EVENT_RT_NO,   "event");
}


int is_script_func_used( char *name, int param_no)
{
	unsigned int i;

	for( i=0; i<RT_NO ; i++ )
		if (sroutes->request[i].a &&
		is_mod_func_used(sroutes->request[i].a,name,param_no) )
			return 1;

	for( i=0; i<ONREPLY_RT_NO ; i++ )
		if (sroutes->onreply[i].a &&
		is_mod_func_used(sroutes->onreply[i].a,name,param_no) )
			return 1;

	for( i=0; i<FAILURE_RT_NO ; i++ )
		if (sroutes->failure[i].a &&
		is_mod_func_used(sroutes->failure[i].a,name,param_no) )
			return 1;

	for( i=0; i<BRANCH_RT_NO ; i++ )
		if (sroutes->branch[i].a &&
		is_mod_func_used(sroutes->branch[i].a,name,param_no) )
			return 1;

	for( i=0; i<TIMER_RT_NO ; i++ )
		if (sroutes->timer[i].a &&
		is_mod_func_used(sroutes->timer[i].a,name,param_no) )
			return 1;

	for( i=0; i<EVENT_RT_NO ; i++ )
		if (sroutes->event[i].a &&
		is_mod_func_used(sroutes->event[i].a,name,param_no) )
			return 1;

	if (sroutes->error.a &&
	is_mod_func_used(sroutes->error.a,name,param_no) )
		return 1;

	if (sroutes->local.a &&
	is_mod_func_used(sroutes->local.a,name,param_no) )
		return 1;

	if (sroutes->startup.a &&
	is_mod_func_used(sroutes->startup.a,name,param_no) )
		return 1;

	return 0;
}

int is_script_async_func_used( char *name, int param_no)
{
	unsigned int i;

	for( i=0; i<RT_NO ; i++ )
		if (sroutes->request[i].a &&
		is_mod_async_func_used(sroutes->request[i].a,name,param_no) )
			return 1;

	for( i=0; i<ONREPLY_RT_NO ; i++ )
		if (sroutes->onreply[i].a &&
		is_mod_async_func_used(sroutes->onreply[i].a,name,param_no) )
			return 1;

	for( i=0; i<FAILURE_RT_NO ; i++ )
		if (sroutes->failure[i].a &&
		is_mod_async_func_used(sroutes->failure[i].a,name,param_no) )
			return 1;

	for( i=0; i<BRANCH_RT_NO ; i++ )
		if (sroutes->branch[i].a &&
		is_mod_async_func_used(sroutes->branch[i].a,name,param_no) )
			return 1;

	for( i=0; i<TIMER_RT_NO ; i++ )
		if (sroutes->timer[i].a &&
		is_mod_async_func_used(sroutes->timer[i].a,name,param_no) )
			return 1;

	for( i=0; i<EVENT_RT_NO ; i++ )
		if (sroutes->event[i].a &&
		is_mod_async_func_used(sroutes->event[i].a,name,param_no) )
			return 1;

	if (sroutes->error.a &&
	is_mod_async_func_used(sroutes->error.a,name,param_no) )
		return 1;

	if (sroutes->local.a &&
	is_mod_async_func_used(sroutes->local.a,name,param_no) )
		return 1;

	if (sroutes->startup.a &&
	is_mod_async_func_used(sroutes->startup.a,name,param_no) )
		return 1;

	return 0;
}
