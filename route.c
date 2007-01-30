/*
 * $Id$
 *
 * SIP routing engine
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2005-2006 Voice Sistem S.R.L.
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
#include "parser/parse_uri.h"
#include "parser/parse_from.h"
#include "parser/parse_to.h"
#include "mem/mem.h"


/* main routing script table  */
struct action* rlist[RT_NO];
/* reply routing table */
struct action* onreply_rlist[ONREPLY_RT_NO];
struct action* failure_rlist[FAILURE_RT_NO];
struct action* branch_rlist[BRANCH_RT_NO];
struct action* error_rlist;

int route_type = REQUEST_ROUTE;


static int fix_actions(struct action* a); /*fwd declaration*/

extern int return_code;

/*
 *
 */
void init_route_lists()
{
	memset(rlist, 0, sizeof(rlist));
	memset(onreply_rlist, 0, sizeof(onreply_rlist));
	memset(failure_rlist, 0, sizeof(failure_rlist));
	memset(branch_rlist, 0, sizeof(branch_rlist));
	error_rlist = 0;
}

/* traverses an expr tree and compiles the REs where necessary) 
 * returns: 0 for ok, <0 if errors */
static int fix_expr(struct expr* exp)
{
	regex_t* re;
	int ret;
	
	ret=E_BUG;
	if (exp==0){
		LOG(L_CRIT, "BUG: fix_expr: null pointer\n");
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
						LOG(L_CRIT, "BUG: fix_expr: unknown op %d\n",
								exp->op);
		}
	}else if (exp->type==ELEM_T){
			if (exp->op==MATCH_OP || exp->op==NOTMATCH_OP){
				if (exp->right.type==STRING_ST){
					re=(regex_t*)pkg_malloc(sizeof(regex_t));
					if (re==0){
						LOG(L_CRIT, "ERROR: fix_expr: memory allocation"
								" failure\n");
						return E_OUT_OF_MEM;
					}
					if (regcomp(re, (char*) exp->right.v.data,
								REG_EXTENDED|REG_NOSUB|REG_ICASE) ){
						LOG(L_CRIT, "ERROR: fix_expr : bad re \"%s\"\n",
									(char*) exp->right.v.data);
						pkg_free(re);
						return E_BAD_RE;
					}
					/* replace the string with the re */
					pkg_free(exp->right.v.data);
					exp->right.v.data=re;
					exp->right.type=RE_ST;
				}else if (exp->right.type!=RE_ST
						&& exp->right.type!=SCRIPTVAR_ST){
					LOG(L_CRIT, "BUG: fix_expr : invalid type for match\n");
					return E_BUG;
				}
			}
			if (exp->left.type==ACTION_O){
				ret=fix_actions((struct action*)exp->right.v.data);
				if (ret!=0){
					LOG(L_CRIT, "ERROR: fix_expr : fix_actions error\n");
					return ret;
				}
			}
			if (exp->left.type==EXPR_O){
				ret=fix_expr(exp->left.v.expr);
				if (ret!=0){
					LOG(L_CRIT, "ERROR: fix_expr : fix left exp error\n");
					return ret;
				}
			}
			if (exp->right.type==EXPR_ST){
				ret=fix_expr(exp->right.v.expr);
				if (ret!=0){
					LOG(L_CRIT, "ERROR: fix_expr : fix rigth exp error\n");
					return ret;
				}
			}
			ret=0;
	}
	return ret;
}



/* adds the proxies in the proxy list & resolves the hostnames */
/* returns 0 if ok, <0 on error */
static int fix_actions(struct action* a)
{
	struct action
		*t;
	int ret;
	cmd_export_t* cmd;
	struct hostent* he;
	struct ip_addr ip;
	struct socket_info* si;
	str host;
	int proto, port;
	struct proxy_l *p;
	struct bl_head *blh;

	if (a==0){
		LOG(L_CRIT,"BUG: fix_actions: null pointer\n");
		return E_BUG;
	}
	for(t=a; t!=0; t=t->next){
		switch(t->type){
			case FORWARD_T:
				if (t->elem[0].type==NOSUBTYPE)
					break;
			case SEND_T:
				if (t->elem[0].type!=STRING_ST) {
					LOG(L_CRIT, "BUG: fix_actions: invalid type"
						"%d (should be string)\n", t->type);
					return E_BUG;
				}
				ret = parse_phostport( t->elem[0].u.string,
						strlen(t->elem[0].u.string),
						&host.s, &host.len, &port, &proto);
				if (ret!=0) {
					LOG(L_ERR,"ERROR:fix_actions: FORWARD/SEND bad "
						"argument\n");
					return E_CFG;
				}
				p = add_proxy( &host,(unsigned short)port, proto);
				if (p==0) {
					LOG(L_ERR,"ERROR:fix_actions: FORWARD/SEND failed to "
						"add proxy");
					return E_CFG;
				}
				t->elem[0].type = PROXY_ST;
				t->elem[0].u.data = (void*)p;
				break;
			case IF_T:
				if (t->elem[0].type!=EXPR_ST){
					LOG(L_CRIT, "BUG: fix_actions: invalid subtype"
								"%d for if (should be expr)\n",
								t->elem[0].type);
					return E_BUG;
				}else if( (t->elem[1].type!=ACTIONS_ST)
						&&(t->elem[1].type!=NOSUBTYPE) ){
					LOG(L_CRIT, "BUG: fix_actions: invalid subtype"
								"%d for if() {...} (should be action)\n",
								t->elem[1].type);
					return E_BUG;
				}else if( (t->elem[2].type!=ACTIONS_ST)
						&&(t->elem[2].type!=NOSUBTYPE) ){
					LOG(L_CRIT, "BUG: fix_actions: invalid subtype"
								"%d for if() {} else{...}(should be action)\n",
								t->elem[2].type);
					return E_BUG;
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
			case MODULE_T:
				cmd = (cmd_export_t*)t->elem[0].u.data;
				DBG("fixing %s, line %d\n", cmd->name, t->line);
				if (cmd->fixup){
					if (cmd->param_no>0){
						ret=cmd->fixup(&t->elem[1].u.data, 1);
						t->elem[1].type=MODFIXUP_ST;
						if (ret<0) goto error;
					}
					if (cmd->param_no>1){
						ret=cmd->fixup(&t->elem[2].u.data, 2);
						t->elem[2].type=MODFIXUP_ST;
						if (ret<0) goto error;
					}
					if (cmd->param_no==0){
						ret=cmd->fixup( 0, 0);
						if (ret<0) goto error;
					}
				}
				break;
			case FORCE_SEND_SOCKET_T:
				if (t->elem[0].type!=SOCKID_ST){
					LOG(L_CRIT, "BUG: fix_actions: invalid subtype"
								"%d for force_send_socket\n",
								t->elem[0].type);
					return E_BUG;
				}
				he=resolvehost(((struct socket_id*)t->elem[0].u.data)->name,0);
				if (he==0){
					LOG(L_ERR, "ERROR: fix_actions: force_send_socket:"
								" could not resolve %s\n",
								((struct socket_id*)t->elem[0].u.data)->name);
					ret = E_BAD_ADDRESS;
					goto error;
				}
				hostent2ip_addr(&ip, he, 0);
				si=find_si(&ip, ((struct socket_id*)t->elem[0].u.data)->port,
								((struct socket_id*)t->elem[0].u.data)->proto);
				if (si==0){
					LOG(L_ERR, "ERROR: fix_actions: bad force_send_socket"
							" argument: %s:%d (ser doesn't listen on it)\n",
							((struct socket_id*)t->elem[0].u.data)->name,
							((struct socket_id*)t->elem[0].u.data)->port);
					ret = E_BAD_ADDRESS;
					goto error;
				}
				t->elem[0].u.data=si;
				t->elem[0].type=SOCKETINFO_ST;
				break;
			case SETFLAG_T:
			case RESETFLAG_T:
			case ISFLAGSET_T:
				if (t->elem[0].type!=NUMBER_ST) {
					LOG(L_CRIT, "BUG: fix_actions: bad xxxflag() type %d\n",
						t->elem[0].type );
					ret=E_BUG;
					goto error;
				}
				if (!flag_in_range( t->elem[0].u.number )) {
					ret=E_CFG;
					goto error;
				}
				break;
			case SETSFLAG_T:
			case RESETSFLAG_T:
			case ISSFLAGSET_T:
				if (t->elem[0].type!=NUMBER_ST) {
					LOG(L_CRIT, "BUG: fix_actions: bad xxxsflag() type %d\n",
						t->elem[0].type );
					ret=E_BUG;
					goto error;
				}
				t->elem[0].u.number = fixup_flag( t->elem[0].u.number );
				if (t->elem[0].u.data==0) {
					ret=E_CFG;
					goto error;
				}
				break;
			case SETBFLAG_T:
			case RESETBFLAG_T:
			case ISBFLAGSET_T:
				if (t->elem[0].type!=NUMBER_ST || t->elem[1].type!=NUMBER_ST) {
					LOG(L_CRIT, "BUG: fix_actions: bad xxxbflag() type "
						"%d,%d\n", t->elem[0].type, t->elem[0].type);
					ret=E_BUG;
					goto error;
				}
				t->elem[1].u.number = fixup_flag( t->elem[1].u.number );
				if (t->elem[1].u.data==0) {
					ret=E_CFG;
					goto error;
				}
				break;
			case EQ_T:
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
			case USE_BLACKLIST_T:
				if (t->elem[0].type!=STRING_ST) {
					LOG(L_CRIT, "BUG: fix_actions: bad USE_BLACKLIST type "
						"%d\n", t->elem[0].type);
					ret=E_BUG;
					goto error;
				}
				host.s = t->elem[0].u.string;
				host.len = strlen(host.s);
				blh = get_bl_head_by_name(&host);
				if (blh==NULL) {
					LOG(L_ERR, "ERROR: fix_actions: USE_BLACKLIST - list "
						"%s not configured\n", t->elem[0].u.string);
					ret=E_CFG;
					goto error;
				}
				t->elem[0].type = BLACKLIST_ST;
				t->elem[0].u.data = blh;
				break;
		}
	}
	return 0;
error:
	LOG(L_ERR,"ERROR: fix_actions: fixing failed (code=%d) at cfg line %d\n",
		ret, t->line);
	return ret;
}


inline static int comp_no( int port, void *param, int op, int subtype )
{
	
	if (subtype!=NUMBER_ST) {
		LOG(L_CRIT, "BUG: comp_no: number expected: %d\n", subtype );
		return E_BUG;
	}
	switch (op){
		case EQUAL_OP:
			return port==(long)param;
		case DIFF_OP:
			return port!=(long)param;
		case GT_OP:
			return port>(long)param;
		case LT_OP:
			return port<(long)param;
		case GTE_OP:
			return port>=(long)param;
		case LTE_OP:
			return port<=(long)param;
		default:
		LOG(L_CRIT, "BUG: comp_no: unknown operator: %d\n", op );
		return E_BUG;
	}
}

/* eval_elem helping function, returns str op param */
inline static int comp_strval(struct sip_msg *msg, int op, str* ival,
		operand_t *opd)
{
	int ret;
	regex_t* re;
	char backup;
	char backup2;
	str res;
	xl_value_t value;
	
	res.s = 0; res.len = 0;
	if(opd->type == SCRIPTVAR_ST)
	{
		if(xl_get_spec_value(msg, opd->v.spec, &value, 0)!=0)
		{
			LOG(L_CRIT, "comp_strval: cannot get var value\n");
			goto error;
		}
		if(value.flags&XL_VAL_STR)
		{
			res = value.rs;
		} else {
			res.s = sint2str(value.ri, &res.len);
		}
	} else if(opd->type == NUMBER_ST) {
		res.s = sint2str(opd->v.n, &res.len);
	}else if(opd->type == STRING_ST) {
		res = opd->v.s;
	} else {
		if(op!=MATCH_OP || opd->type != RE_ST)
		{
			LOG(L_CRIT, "comp_strval: invalid operation %d/%d\n", op,
					opd->type);
			goto error;
		}
	}


	ret=-1;
	switch(op){
		case EQUAL_OP:
			if(ival->len != res.len) return 0;
			ret=(strncasecmp(ival->s, res.s, ival->len)==0);
			break;
		case DIFF_OP:
			if(ival->len != res.len) return 1;
			ret=(strncasecmp(ival->s, res.s, ival->len)!=0);
			break;
		case MATCH_OP:
			backup=ival->s[ival->len];ival->s[ival->len]='\0';

			if(opd->type == SCRIPTVAR_ST) {
				re=(regex_t*)pkg_malloc(sizeof(regex_t));
				if (re==0){
					LOG(L_CRIT, "ERROR: comp_strval: memory allocation"
					    " failure\n");
					ival->s[ival->len]=backup;
					goto error;
				}
				backup2 = res.s[res.len];res.s[res.len] = '\0';
				if (regcomp(re, res.s, REG_EXTENDED|REG_NOSUB|REG_ICASE)) {
					pkg_free(re);
					res.s[res.len] = backup2;
					ival->s[ival->len]=backup;
					goto error;
				}
				ret=(regexec(re, ival->s, 0, 0, 0)==0);
				regfree(re);
				pkg_free(re);
				res.s[res.len] = backup2;
			} else {
				ret=(regexec((regex_t*)opd->v.data, ival->s, 0, 0, 0)==0);
			}

			ival->s[ival->len]=backup;
			break;
		default:
			LOG(L_CRIT, "BUG: comp_str: unknown op %d\n", op);
			goto error;
	}
	return ret;
	
error:
	return -1;
}

/* eval_elem helping function, returns str op param */
inline static int comp_str(char* str, void* param, int op, int subtype)
{
	int ret;
	
	ret=-1;
	switch(op){
		case EQUAL_OP:
			if (subtype!=STRING_ST){
				LOG(L_CRIT, "BUG: comp_str: bad type %d, "
						"string expected\n", subtype);
				goto error;
			}
			ret=(strcasecmp(str, (char*)param)==0);
			break;
		case DIFF_OP:
			if (subtype!=STRING_ST){
				LOG(L_CRIT, "BUG: comp_str: bad type %d, "
						"string expected\n", subtype);
				goto error;
			}
			ret=(strcasecmp(str, (char*)param)!=0);
			break;
		case MATCH_OP:
			if (subtype!=RE_ST){
				LOG(L_CRIT, "BUG: comp_str: bad type %d, "
						" RE expected\n", subtype);
				goto error;
			}
			ret=(regexec((regex_t*)param, str, 0, 0, 0)==0);
			break;
		default:
			LOG(L_CRIT, "BUG: comp_str: unknown op %d\n", op);
			goto error;
	}
	return ret;
	
error:
	return -1;
}


/* check_self wrapper -- it checks also for the op */
inline static int check_self_op(int op, str* s, unsigned short p)
{
	int ret;
	
	ret=check_self(s, p, 0);
	switch(op){
		case EQUAL_OP:
			break;
		case DIFF_OP:
			if (ret>=0) ret=!ret;
			break;
		default:
			LOG(L_CRIT, "BUG: check_self_op: invalid operator %d\n", op);
			ret=-1;
	}
	return ret;
}


/* eval_elem helping function, returns an op param */
inline static int comp_ip(struct sip_msg *msg, int op, struct ip_addr* ip,
		operand_t *opd)
{
	struct hostent* he;
	char ** h;
	int ret;
	str tmp;

	ret=-1;
	switch(opd->type){
		case NET_ST:
			switch(op){
				case EQUAL_OP:
					ret=(matchnet(ip, (struct net*)opd->v.data)==1);
					break;
				case DIFF_OP:
					ret=(matchnet(ip, (struct net*)opd->v.data)!=1);
					break;
				default:
					goto error_op;
			}
			break;
		case STRING_ST:
		case RE_ST:
			switch(op){
				case EQUAL_OP:
				case MATCH_OP:
					/* 1: compare with ip2str*/
					ret=comp_str(ip_addr2a(ip), opd->v.data, op, opd->type);
					if (ret==1) break;
					/* 2: resolve (name) & compare w/ all the ips */
					if (opd->type==STRING_ST){
						he=resolvehost((char*)opd->v.data,0);
						if (he==0){
							DBG("comp_ip: could not resolve %s\n",
									(char*)opd->v.data);
						}else if (he->h_addrtype==ip->af){
							for(h=he->h_addr_list;(ret!=1)&& (*h); h++){
								ret=(memcmp(ip->u.addr, *h, ip->len)==0);
							}
							if (ret==1) break;
						}
					}
					/* 3: (slow) rev dns the address
					* and compare with all the aliases
					* !!??!! review: remove this? */
					he=rev_resolvehost(ip);
					if (he==0){
						print_ip( "comp_ip: could not rev_resolve ip address:"
									" ", ip, "\n");
					ret=0;
					}else{
						/*  compare with primary host name */
						ret=comp_str(he->h_name, opd->v.data, op, opd->type);
						/* compare with all the aliases */
						for(h=he->h_aliases; (ret!=1) && (*h); h++){
							ret=comp_str(*h, opd->v.data, op, opd->type);
						}
					}
					break;
				case DIFF_OP:
					ret=comp_ip(msg, op, ip, opd);
					if (ret>=0) ret=!ret;
					break;
				default:
					goto error_op;
			}
			break;
		case MYSELF_ST: /* check if it's one of our addresses*/
			tmp.s=ip_addr2a(ip);
			tmp.len=strlen(tmp.s);
			ret=check_self_op(op, &tmp, 0);
			break;
		default:
			LOG(L_CRIT, "BUG: comp_ip: invalid type for "
						" src_ip or dst_ip (%d)\n", opd->type);
			ret=-1;
	}
	return ret;
error_op:
	LOG(L_CRIT, "BUG: comp_ip: invalid operator %d\n", op);
	return -1;
	
}

/* compare str to str */
inline static int comp_s2s(int op, str *s1, str *s2)
{
	char backup;
	char backup2;
	int n;
	int rt;
	int ret;
	regex_t* re;

	ret = -1;
	switch(op) {
		case EQUAL_OP:
			if(s1->len != s2->len) return 0;
			ret=(strncasecmp(s1->s, s2->s, s2->len)==0);
		break;
		case DIFF_OP:
			if(s1->len != s2->len) return 1;
			ret=(strncasecmp(s1->s, s2->s, s2->len)!=0);
			break;
		case GT_OP:
			n = (s1->len>=s2->len)?s1->len:s2->len;
			rt = strncasecmp(s1->s,s2->s, n);
			if (rt>0)
				ret = 1;
			else if(rt==0 && s1->len>s1->len)
				ret = 1;
			else ret = 0;
			break;
		case GTE_OP:
			n = (s1->len>=s2->len)?s1->len:s2->len;
			rt = strncasecmp(s1->s,s2->s, n);
			if (rt>0)
				ret = 1;
			else if(rt==0 && s1->len>=s1->len)
				ret = 1;
			else ret = 0;
			break;
		case LT_OP:
			n = (s1->len>=s2->len)?s1->len:s2->len;
			rt = strncasecmp(s1->s,s2->s, n);
			if (rt<0)
				ret = 1;
			else if(rt==0 && s1->len<s1->len)
				ret = 1;
			else ret = 0;
			break;
		case LTE_OP:
			n = (s1->len>=s2->len)?s1->len:s2->len;
			rt = strncasecmp(s1->s,s2->s, n);
			if (rt<0)
				ret = 1;
			else if(rt==0 && s1->len<=s1->len)
				ret = 1;
			else ret = 0;
			break;
		case MATCH_OP:
			backup  = s1->s[s1->len];  s1->s[s1->len] = '\0';
			ret=(regexec((regex_t*)s2, s1->s, 0, 0, 0)==0);
			s1->s[s1->len] = backup;
			break;
		case NOTMATCH_OP:
			backup  = s1->s[s1->len];  s1->s[s1->len] = '\0';
			ret=(regexec((regex_t*)s2, s1->s, 0, 0, 0)!=0);
			s1->s[s1->len] = backup;
			break;
		case MATCHD_OP:
		case NOTMATCHD_OP:
			re=(regex_t*)pkg_malloc(sizeof(regex_t));
			if (re==0) {
				LOG(L_CRIT, "ERROR: comp_strval: memory allocation failure\n");
				return -1;
			}

			backup  = s1->s[s1->len];  s1->s[s1->len] = '\0';
			backup2 = s2->s[s2->len];  s2->s[s2->len] = '\0';

			if (regcomp(re, s2->s, REG_EXTENDED|REG_NOSUB|REG_ICASE)) {
				pkg_free(re);
				s2->s[s2->len] = backup2;
				s1->s[s1->len] = backup;
				return -1;
			}
			if(op==MATCHD_OP)
				ret=(regexec(re, s1->s, 0, 0, 0)==0);
			else
				ret=(regexec(re, s1->s, 0, 0, 0)!=0);
			regfree(re);
			pkg_free(re);
			s2->s[s2->len] = backup2;
			s1->s[s1->len] = backup;
			break;
		default:
			LOG(L_CRIT, "BUG: comp_s2s: unknown op %d\n", op);
	}
	return ret;
}

/* compare nr to nr */
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
			LOG(L_CRIT, "BUG: comp_n2n: unknown op %d\n", op);
	}
	return -1;
}


inline static int comp_scriptvar(struct sip_msg *msg, int op, operand_t *left,
		operand_t *right)
{
	str lstr;
	str rstr;
	int ln;
	int rn;
	xl_value_t lvalue;
	xl_value_t rvalue;
	int type;
	
	lstr.s = 0; lstr.len = 0;
	rstr.s = 0; rstr.len = 0;
	ln = 0; rn =0;
	if(xl_get_spec_value(msg, left->v.spec, &lvalue, 0)!=0)
	{
		LOG(L_CRIT, "comp_scriptvar: cannot get left var value\n");
		goto error;
	}
	lstr = lvalue.rs;
	ln   = lvalue.ri;
	type = 0;

	if(right->type == SCRIPTVAR_ST)
	{
		if(xl_get_spec_value(msg, right->v.spec, &rvalue, 0)!=0)
		{
			LOG(L_CRIT, "comp_scriptvar: cannot get right var value\n");
			goto error;
		}
		
		if(op==MATCH_OP||op==NOTMATCH_OP)
		{
			if(!((rvalue.flags&XL_VAL_STR) && (lvalue.flags&XL_VAL_STR)))
			{
				LOG(L_CRIT, "comp_scriptvar: invalid operation %d/%d\n", op,
					right->type);
				goto error;
			}
			if(op==MATCH_OP)
				return comp_s2s(MATCHD_OP, &lstr, &rvalue.rs);
			else
				return comp_s2s(NOTMATCHD_OP, &lstr, &rvalue.rs);
		}

		if((rvalue.flags&XL_VAL_INT) && (lvalue.flags&XL_VAL_INT)) {
			/* comparing int */
			rn = rvalue.ri;
			type =2;
		} else if((rvalue.flags&XL_VAL_STR) && (lvalue.flags&XL_VAL_STR)) {
			/* comparing string */
			rstr = rvalue.rs;
			type =1;
		} else {
			LOG(L_CRIT, "comp_scriptvar: invalid operation %d/%d!\n", op,
					right->type);
			goto error;
		}
	} else if(right->type == NUMBER_ST) {
		if(!(lvalue.flags&XL_VAL_INT))
		{
			LOG(L_CRIT, "comp_scriptvar: invalid operation %d/%d/%d!!\n", op,
					right->type, lvalue.flags);
			goto error;
		}
		/* comparing int */
		type =2;
		rn = right->v.n;
	} else if(right->type == STRING_ST) {
		if(!(lvalue.flags&XL_VAL_STR))
		{
			LOG(L_CRIT, "comp_scriptvar: invalid operation %d/%d!!!\n", op,
					right->type);
			goto error;
		}
		/* comparing string */
		type =1;
		rstr = right->v.s;
	} else {
		if(op==MATCH_OP || op==NOTMATCH_OP)
		{
			if(!(lvalue.flags&XL_VAL_STR) || right->type != RE_ST)
			{
				LOG(L_CRIT, "comp_scriptvar: invalid operation %d/%d\n", op,
					right->type);
				goto error;
			}
			return comp_s2s(op, &lstr, (str*)right->v.expr);
		}
		/* comparing others */
		type = 0;
	}

	if(type==1) { /* compare str */
		DBG("comp_scriptvar: str %d : %.*s\n", op, lstr.len, lstr.s); 
		return comp_s2s(op, &lstr, &rstr);
	} else if(type==2) {
		DBG("comp_scriptvar: int %d : %d / %d\n", op, ln, rn); 
		return comp_n2n(op, ln, rn);
	} else {
		LOG(L_CRIT, "comp_scriptvar: invalid operation %d/%d\n", op,
			right->type);
	}
	
error:
	return -1;
}


/* returns: 0/1 (false/true) or -1 on error, -127 EXPR_DROP */
static int eval_elem(struct expr* e, struct sip_msg* msg, xl_value_t *val)
{

	struct sip_uri uri;
	int ret;
	int retl;
	int retr;
	int ival;
	ret=E_BUG;
	xl_value_t lval;
	xl_value_t rval;
	char *p;
	
	if (e->type!=ELEM_T){
		LOG(L_CRIT," BUG: eval_elem: invalid type\n");
		goto error;
	}
	
	if(val) memset(val, 0, sizeof(xl_value_t));

	switch(e->left.type){
		case METHOD_O:
				ret=comp_strval(msg, e->op, &msg->first_line.u.request.method,
						&e->right);
				break;
		case URI_O:
				if(msg->new_uri.s){
					if (e->right.type==MYSELF_ST){
						if (parse_sip_msg_uri(msg)<0) ret=-1;
						else	ret=check_self_op(e->op, &msg->parsed_uri.host,
									msg->parsed_uri.port_no?
									msg->parsed_uri.port_no:SIP_PORT);
					}else{
						ret=comp_strval(msg, e->op, &msg->new_uri, &e->right);
					}
				}else{
					if (e->right.type==MYSELF_ST){
						if (parse_sip_msg_uri(msg)<0) ret=-1;
						else	ret=check_self_op(e->op, &msg->parsed_uri.host,
									msg->parsed_uri.port_no?
									msg->parsed_uri.port_no:SIP_PORT);
					}else{
						ret=comp_strval(msg, e->op,
								&msg->first_line.u.request.uri,
								&e->right);
					}
				}
				break;
		case FROM_URI_O:
				if (parse_from_header(msg)<0){
					LOG(L_ERR, "ERROR: eval_elem: bad or missing"
								" From: header\n");
					goto error;
				}
				if (e->right.type==MYSELF_ST){
					if (parse_uri(get_from(msg)->uri.s, get_from(msg)->uri.len,
									&uri) < 0){
						LOG(L_ERR, "ERROR: eval_elem: bad uri in From:\n");
						goto error;
					}
					ret=check_self_op(e->op, &uri.host,
										uri.port_no?uri.port_no:SIP_PORT);
				}else{
					ret=comp_strval(msg, e->op, &get_from(msg)->uri,
							&e->right);
				}
				break;
		case TO_URI_O:
				if ((msg->to==0) && ((parse_headers(msg, HDR_TO_F, 0)==-1) ||
							(msg->to==0))){
					LOG(L_ERR, "ERROR: eval_elem: bad or missing"
								" To: header\n");
					goto error;
				}
				/* to content is parsed automatically */
				if (e->right.type==MYSELF_ST){
					if (parse_uri(get_to(msg)->uri.s, get_to(msg)->uri.len,
									&uri) < 0){
						LOG(L_ERR, "ERROR: eval_elem: bad uri in To:\n");
						goto error;
					}
					ret=check_self_op(e->op, &uri.host,
										uri.port_no?uri.port_no:SIP_PORT);
				}else{
					ret=comp_strval(msg, e->op, &get_to(msg)->uri,
										&e->right);
				}
				break;
		case SRCIP_O:
				ret=comp_ip(msg, e->op, &msg->rcv.src_ip, &e->right);
				break;
		case DSTIP_O:
				ret=comp_ip(msg, e->op, &msg->rcv.dst_ip, &e->right);
				break;
		case NUMBER_O:
				ret=!(!e->right.v.n); /* !! to transform it in {0,1} */
				break;
		case ACTION_O:
				ret=run_action_list( (struct action*)e->right.v.data, msg);
				if(val)
				{
					val->flags = XL_TYPE_INT|XL_VAL_INT;
					val->ri = ret;
				}
				if (ret<=0) ret=(ret==0)?EXPR_DROP:0;
				else ret=1;
				return ret;
		case EXPR_O:
				retl = retr = 0;
				memset(&lval, 0, sizeof(xl_value_t));
				memset(&rval, 0, sizeof(xl_value_t));
				if(e->left.v.data)
					retl=eval_expr((struct expr*)e->left.v.data,msg,&lval);
				if(lval.flags == XL_VAL_NONE)
				{
					xl_value_destroy(&lval);
					xl_value_destroy(&rval);
					return 0;
				}
				if(e->op == BNOT_OP)
				{
					if(lval.flags&XL_VAL_INT)
					{
						if(val!=NULL)
						{
							val->flags = XL_TYPE_INT|XL_VAL_INT;
							val->ri = ~lval.ri;
						}
						xl_value_destroy(&lval);
						xl_value_destroy(&rval);
						return (val->ri)?1:0;
					}
					LOG(L_ERR, "eval_elem: binary NOT on non-numeric value\n");
					xl_value_destroy(&lval);
					xl_value_destroy(&rval);
					return 0;
				}
				if(e->right.v.data)
					retr=eval_expr((struct expr*)e->right.v.data,msg,&rval);
			
				if(lval.flags&XL_TYPE_INT)
				{
					if(!(rval.flags&XL_VAL_INT))
					{
						LOG(L_ERR, "eval_elem: invalid numeric operands\n");
						xl_value_destroy(&lval);
						xl_value_destroy(&rval);
						return 0;
					}
					if(val!=NULL)
						val->flags = XL_TYPE_INT|XL_VAL_INT;

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
								LOG(L_ERR,
									"eval_elem: divide by 0\n");
								xl_value_destroy(&lval);
								xl_value_destroy(&rval);
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
								LOG(L_ERR,
									"eval_elem: divide by 0\n");
								xl_value_destroy(&lval);
								xl_value_destroy(&rval);
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
						default:
							LOG(L_ERR,
									"eval_elem: invalid int op %d\n", e->op);
								val->ri = 0;
							xl_value_destroy(&lval);
							xl_value_destroy(&rval);
							return 0;
					}
					xl_value_destroy(&lval);
					xl_value_destroy(&rval);
					if(val!=NULL) val->ri = ival;
					return (ival)?1:0;
				} else {
					if(!(rval.flags&XL_VAL_STR))
					{
						LOG(L_ERR,
								"eval_elem: invalid string operands\n");
						xl_value_destroy(&lval);
						xl_value_destroy(&rval);
						return 0;
					}
					if(e->op != PLUS_OP)
					{
						LOG(L_ERR,
								"eval_elem: invalid string operator %d\n",
								e->op);
						xl_value_destroy(&lval);
						xl_value_destroy(&rval);
						return 0;
					}
					if(val==NULL)
					{
						ret = (lval.rs.len>0 || rval.rs.len>0);
						xl_value_destroy(&lval);
						xl_value_destroy(&rval);
						return ret;
					}
					val->rs.s=(char*)pkg_malloc((lval.rs.len+rval.rs.len+1)
							*sizeof(char));
					if(val->rs.s==0)
					{
						LOG(L_ERR, "eval_elem: no more memory\n");
						xl_value_destroy(&lval);
						xl_value_destroy(&rval);
						return 0;
					}
					val->flags = XL_VAL_PKG|XL_VAL_STR;
					memcpy(val->rs.s, lval.rs.s, lval.rs.len);
					memcpy(val->rs.s+lval.rs.len, rval.rs.s, rval.rs.len);
					val->rs.len = lval.rs.len + rval.rs.len;
					val->rs.s[val->rs.len] = '\0';
					xl_value_destroy(&lval);
					xl_value_destroy(&rval);
					return 1;
				}
				break;
		case SRCPORT_O:
				ret=comp_no(msg->rcv.src_port, 
					e->right.v.data, /* e.g., 5060 */
					e->op, /* e.g. == */
					e->right.type /* 5060 is number */);
				break;
		case DSTPORT_O:
				ret=comp_no(msg->rcv.dst_port, e->right.v.data, e->op, 
							e->right.type);
				break;
		case PROTO_O:
				ret=comp_no(msg->rcv.proto, e->right.v.data, e->op,
						e->right.type);
				break;
		case AF_O:
				ret=comp_no(msg->rcv.src_ip.af, e->right.v.data, e->op,
						e->right.type);
				break;
		case RETCODE_O:
				ret=comp_no(return_code, e->right.v.data, e->op,
						e->right.type);
				break;
		case MSGLEN_O:
				ret=comp_no(msg->len, e->right.v.data, e->op,
						e->right.type);
				break;
		case STRINGV_O:
				if(val) {
					val->flags = XL_VAL_STR;
					val->rs = e->left.v.s;
				}
				/* optimization for no dup ?!?! */
				return (e->left.v.s.len>0)?1:0;
		case NUMBERV_O:
				if(val) {
					val->flags = XL_TYPE_INT|XL_VAL_INT;
					val->ri = e->left.v.n;
				}
				ret=!(!e->left.v.n); /* !! to transform it in {0,1} */
				return ret;
		case SCRIPTVAR_O:
				if(e->op==NO_OP)
				{
					memset(&rval, 0, sizeof(xl_value_t));
					if(xl_get_spec_value(msg, e->right.v.spec, &rval, 0)==0)
					{
						if(rval.flags==XL_VAL_NONE || (rval.flags&XL_VAL_NULL)
								|| (rval.flags&XL_VAL_EMPTY)
								|| ((rval.flags&XL_TYPE_INT)&&rval.ri==0))
						{
							xl_value_destroy(&rval);
							return 0;
						}
						if(rval.flags&XL_TYPE_INT)
						{
							xl_value_destroy(&rval);
							return 1;
						}
						if(rval.rs.len!=0)
						{
							xl_value_destroy(&rval);
							return 1;
						}
						xl_value_destroy(&rval);
					}
					return 0;
				}
				if(e->op==VALUE_OP)
				{
					if(xl_get_spec_value(msg, e->left.v.spec, &lval, 0)==0)
					{
						if(val!=NULL)
							memcpy(val, &lval, sizeof(xl_value_t));
						if(lval.flags&XL_VAL_STR)
						{
							if(!((lval.flags&XL_VAL_PKG) 
									|| (lval.flags&XL_VAL_SHM)))
							{
								if(val!=NULL)
								{
									/* do pkg duplicate */
									p = (char*)pkg_malloc((val->rs.len+1)*sizeof(char));
									if(p==0)
									{
										LOG(L_ERR, "eval_elem: no more memory\n");
										memset(val, 0, sizeof(xl_value_t));
										return 0;
									}
									memcpy(p, val->rs.s, val->rs.len);
									p[val->rs.len] = 0;
									val->rs.s = p;
								}
							}
							return 1;
						}
						if(lval.flags==XL_VAL_NONE 
								|| (lval.flags & XL_VAL_NULL)
								|| (lval.flags & XL_VAL_EMPTY))
							return 0;
						if(lval.flags&XL_TYPE_INT)
							return (lval.ri!=0);
						else
							return (lval.rs.len>0);
					}
					return 0;
				}

				ret=comp_scriptvar(msg, e->op, &e->left, &e->right);
				break;
		default:
				LOG(L_CRIT, "BUG: eval_elem: invalid operand %d\n",
							e->left.type);
	}
	if(val)
	{
		val->flags = XL_TYPE_INT|XL_VAL_INT;
		val->ri = ret;
	}
	return ret;
error:
	if(val)
	{
		val->flags = XL_TYPE_INT|XL_VAL_INT;
		val->ri = -1;
	}
	return -1;
}



/* ret= 0/1 (true/false) ,  -1 on error or EXPR_DROP (-127)  */
int eval_expr(struct expr* e, struct sip_msg* msg, xl_value_t *val)
{
	static int rec_lev=0;
	int ret;
	
	rec_lev++;
	if (rec_lev>MAX_REC_LEV){
		LOG(L_CRIT, "ERROR: eval_expr: too many expressions (%d)\n",
				rec_lev);
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
				LOG(L_CRIT, "BUG: eval_expr: unknown op %d\n", e->op);
				ret=-1;
		}
	}else{
		LOG(L_CRIT, "BUG: eval_expr: unknown type %d\n", e->type);
		ret=-1;
	}

skip:
	rec_lev--;
	return ret;
}


/* adds an action list to head; a must be null terminated (last a->next=0))*/
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


int add_actions(struct action* a, struct action** head)
{
	int ret;

	LOG(L_DBG, "add_actions: fixing actions...\n");
	if ((ret=fix_actions(a))!=0) goto error;
	push(a,head);
	return 0;
	
error:
	return ret;
}



/* fixes all action tables */
/* returns 0 if ok , <0 on error */
int fix_rls()
{
	int i,ret;
	for(i=0;i<RT_NO;i++){
		if(rlist[i]){
			if ((ret=fix_actions(rlist[i]))!=0){
				return ret;
			}
		}
	}
	for(i=0;i<ONREPLY_RT_NO;i++){
		if(onreply_rlist[i]){
			if ((ret=fix_actions(onreply_rlist[i]))!=0){
				return ret;
			}
		}
	}
	for(i=0;i<FAILURE_RT_NO;i++){
		if(failure_rlist[i]){
			if ((ret=fix_actions(failure_rlist[i]))!=0){
				return ret;
			}
		}
	}
	for(i=0;i<BRANCH_RT_NO;i++){
		if(branch_rlist[i]){
			if ((ret=fix_actions(branch_rlist[i]))!=0){
				return ret;
			}
		}
	}
	if(error_rlist){
		if ((ret=fix_actions(error_rlist))!=0){
			return ret;
		}
	}
	return 0;
}


static int rcheck_stack[RT_NO];
static int rcheck_stack_p = 0;
static int rcheck_status = 0;

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
					LOG(L_CRIT,"BUG:check_actions: stack overflow (%d)\n",
						rcheck_stack_p);
					goto error;
				}
				rcheck_stack[rcheck_stack_p] = a->elem[0].u.number;
				if (check_actions( rlist[a->elem[0].u.number], r_type)!=0)
					goto error;
				rcheck_stack_p--;
				break;
			case IF_T:
				if (check_actions((struct action*)a->elem[1].u.data, r_type)!=0)
					goto error;
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
			case MODULE_T:
				/* do check :D */
				fct = (cmd_export_t*)(a->elem[0].u.data);
				if ( (fct->flags&r_type)!=r_type ) {
					rcheck_status = -1;
					LOG(L_ERR,"ERROR:check_actions: script function "
						"\"%s\" (types=%d) does not support route type "
						"(%d)\n",fct->name, fct->flags, r_type);
					for( n=rcheck_stack_p-1; n>=0 ; n-- ) {
						LOG(L_ERR,"ERROR:check_actions: route "
							"stack[%d]=%d\n",n,rcheck_stack[n]);
					}
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


/* check all routing tables for compatiblity between
 * route types and called module functions;
 * returns 0 if ok , <0 on error */
int check_rls()
{
	int i,ret;

	rcheck_status = 0;

	if(rlist[0]){
		if ((ret=check_actions(rlist[0],REQUEST_ROUTE))!=0){
			LOG(L_ERR,"ERROR:check_rls: check failed for main "
				"request route\n");
			return ret;
		}
	}
	for(i=0;i<ONREPLY_RT_NO;i++){
		if(onreply_rlist[i]){
			if ((ret=check_actions(onreply_rlist[i],ONREPLY_ROUTE))!=0){
				LOG(L_ERR,"ERROR:check_rls: check failed for "
					"onreply_route[%d]\n",i);
				return ret;
			}
		}
	}
	for(i=0;i<FAILURE_RT_NO;i++){
		if(failure_rlist[i]){
			if ((ret=check_actions(failure_rlist[i],FAILURE_ROUTE))!=0){
				LOG(L_ERR,"ERROR:check_rls: check failed for "
					"failure_route[%d]\n",i);
				return ret;
			}
		}
	}
	for(i=0;i<BRANCH_RT_NO;i++){
		if(branch_rlist[i]){
			if ((ret=check_actions(branch_rlist[i],BRANCH_ROUTE))!=0){
				LOG(L_ERR,"ERROR:check_rls: check failed for "
					"branch_route[%d]\n",i);
				return ret;
			}
		}
	}
	if(error_rlist){
		if ((ret=check_actions(error_rlist,ERROR_ROUTE))!=0){
			LOG(L_ERR,"ERROR:check_rls: check failed for "
				"error_route\n");
			return ret;
		}
	}
	return rcheck_status;
}




/* debug function, prints main routing table */
void print_rl()
{
	int j;

	for(j=0; j<RT_NO; j++){
		if (rlist[j]==0){
			if (j==0) DBG("WARNING: the main routing table is empty\n");
			continue;
		}
		DBG("routing table %d:\n",j);
		print_actions(rlist[j]);
		DBG("\n");
	}
	for(j=0; j<ONREPLY_RT_NO; j++){
		if (onreply_rlist[j]==0){
			continue;
		}
		DBG("onreply routing table %d:\n",j);
		print_actions(onreply_rlist[j]);
		DBG("\n");
	}
	for(j=0; j<FAILURE_RT_NO; j++){
		if (failure_rlist[j]==0){
			continue;
		}
		DBG("failure routing table %d:\n",j);
		print_actions(failure_rlist[j]);
		DBG("\n");
	}
	for(j=0; j<BRANCH_RT_NO; j++){
		if (branch_rlist[j]==0){
			continue;
		}
		DBG("T-branch routing table %d:\n",j);
		print_actions(branch_rlist[j]);
		DBG("\n");
	}
}


