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


/* main routing script table  */
struct script_route rlist[RT_NO];
/* reply routing table */
struct script_route onreply_rlist[ONREPLY_RT_NO];
/* failure routes */
struct script_route failure_rlist[FAILURE_RT_NO];
/* branch routes */
struct script_route branch_rlist[BRANCH_RT_NO];
/* local requests route */
struct script_route local_rlist;
/* error route */
struct script_route error_rlist;
/* startup route */
struct script_route startup_rlist;
/* timer route */
struct script_timer_route timer_rlist[TIMER_RT_NO];
/* event route */
struct script_event_route event_rlist[EVENT_RT_NO];

int route_type = REQUEST_ROUTE;


static int fix_actions(struct action* a); /*fwd declaration*/

extern int return_code;

/*!
 * \brief Initialize routing lists
 */
void init_route_lists(void)
{
	memset(rlist, 0, sizeof(rlist));
	memset(onreply_rlist, 0, sizeof(onreply_rlist));
	memset(failure_rlist, 0, sizeof(failure_rlist));
	memset(branch_rlist, 0, sizeof(branch_rlist));
	memset(&local_rlist, 0, sizeof(local_rlist));
	memset(&error_rlist, 0, sizeof(error_rlist));
	memset(&startup_rlist, 0, sizeof(startup_rlist));
	memset(timer_rlist, 0, sizeof(timer_rlist));
	memset(event_rlist, 0, sizeof(event_rlist));
	rlist[DEFAULT_RT].name = "0";
	onreply_rlist[DEFAULT_RT].name = "0";
}


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
	struct hostent* he;
	struct ip_addr ip;
	struct socket_info* si;
	str host;
	int proto=PROTO_NONE, port;
	struct proxy_l *p;
	struct bl_head *blh;
	int i = 0;
	str s;
	pv_elem_t *model=NULL;
	pv_elem_t *models[5];
	pv_spec_p sp = NULL;
	xl_level_p xlp;
	event_id_t ev_id;

	if (a==0){
		LM_CRIT("null pointer\n");
		return E_BUG;
	}
	for(t=a; t!=0; t=t->next){
		switch(t->type){
			case ROUTE_T:
				if (t->elem[0].type!=NUMBER_ST){
					LM_ALERT("BUG in route() type %d\n",
						t->elem[0].type);
					ret = E_BUG;
					goto error;
				}
				if ((t->elem[0].u.number>RT_NO)||(t->elem[0].u.number<0)){
					LM_ALERT("invalid routing table number in"
							"route(%lu)\n", t->elem[0].u.number);
					ret = E_CFG;
					goto error;
				}
				if ( rlist[t->elem[0].u.number].a==NULL ) {
					LM_ERR("called route [%s] (id=%d) is not defined\n",
						rlist[t->elem[0].u.number].name,
						(int)t->elem[0].u.number);
					ret = E_CFG;
					goto error;
				}
				if (t->elem[1].type != 0) {
					if (t->elem[1].type != NUMBER_ST ||
							t->elem[2].type != SCRIPTVAR_ELEM_ST) {
						LM_ALERT("BUG in route() type %d/%d\n",
								 t->elem[1].type, t->elem[2].type);
						ret=E_BUG;
						break;
					}
					if (t->elem[1].u.number >= MAX_ACTION_ELEMS ||
							t->elem[1].u.number <= 0) {
						LM_ALERT("BUG in number of route parameters %d\n",
								 (int)t->elem[1].u.number);
						ret=E_BUG;
						break;
					}
				}
				break;
			case FORWARD_T:
				if (sl_fwd_disabled>0) {
					LM_ERR("stateless forwarding disabled, but forward() "
						"is used!!\n");
					ret = E_CFG;
					goto error;
				}
				sl_fwd_disabled = 0;
				if (t->elem[0].type==NOSUBTYPE)
					break;
			case SEND_T:
				if (t->elem[0].type!=STRING_ST) {
					LM_CRIT("invalid type %d (should be string)\n", t->type);
					ret = E_BUG;
					goto error;
				}
				ret = parse_phostport( t->elem[0].u.string,
						strlen(t->elem[0].u.string),
						&host.s, &host.len, &port, &proto);
				if (ret!=0) {
					LM_ERR("ERROR:fix_actions: FORWARD/SEND bad "
						"argument\n");
					ret = E_CFG;
					goto error;
				}
				p = mk_proxy( &host,(unsigned short)port, proto, 0);
				if (p==0) {
					LM_ERR("forward/send failed to add proxy");
					ret = E_CFG;
					goto error;
				}
				t->elem[0].type = PROXY_ST;
				t->elem[0].u.data = (void*)p;

				s.s = (char*)t->elem[1].u.data;
				if (s.s && t->elem[1].type == STRING_ST)
				{
					/* commands have only one parameter */
					s.s = (char *)t->elem[1].u.data;
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

					t->elem[1].u.data = (void*)model;
					t->elem[1].type = SCRIPTVAR_ELEM_ST;
				}
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
			case MODULE_T:
				cmd = (cmd_export_t*)t->elem[0].u.data;
				LM_DBG("fixing %s, %s:%d\n", cmd->name, t->file, t->line);
				if (cmd->fixup){
					if (cmd->param_no==0){
						ret=cmd->fixup( 0, 0);
						if (ret<0) goto error;
					}
					else {
						for (i=1; i<=cmd->param_no; i++) {
							/* we only call the fixup for non-null arguments */
							if (t->elem[i].type != NULLV_ST) {
								ret=cmd->fixup(&t->elem[i].u.data, i);
								t->elem[i].type=MODFIXUP_ST;
								if (ret<0) goto error;
							}
						}
					}
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
				if (acmd->fixup){
					if (acmd->param_no==0){
						ret=acmd->fixup( 0, 0);
						if (ret<0) goto error;
					}
					else {
						for (i=1; i<=acmd->param_no; i++) {
							/* we only call the fixup for non-null arguments */
							if (t->elem[i].type != NULLV_ST) {
								ret=acmd->fixup(&t->elem[i].u.data, i);
								t->elem[i].type=MODFIXUP_ST;
								if (ret<0) goto error;
							}
						}
					}
				}
				break;
			case FORCE_SEND_SOCKET_T:
				if (t->elem[0].type!=SOCKID_ST){
					LM_CRIT("invalid subtype %d for force_send_socket\n",
								t->elem[0].type);
					ret = E_BUG;
					goto error;
				}
				he=resolvehost(((struct socket_id*)t->elem[0].u.data)->name,0);
				if (he==0){
					LM_ERR(" could not resolve %s\n",
								((struct socket_id*)t->elem[0].u.data)->name);
					ret = E_BAD_ADDRESS;
					goto error;
				}
				hostent2ip_addr(&ip, he, 0);
				si=find_si(&ip, ((struct socket_id*)t->elem[0].u.data)->port,
								((struct socket_id*)t->elem[0].u.data)->proto);
				if (si==0){
					LM_ERR("bad force_send_socket"
						" argument: %s:%d (opensips doesn't listen on it)\n",
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
				if (t->elem[0].type == NUMBER_ST) {
					s.s = int2str((unsigned long)t->elem[0].u.number, &s.len);
				    t->elem[0].u.number = fixup_flag(FLAG_TYPE_MSG, &s);

				} else if (t->elem[0].type == STR_ST) {
					t->elem[0].u.number = fixup_flag(FLAG_TYPE_MSG, &t->elem[0].u.s);

				} else {
					LM_CRIT("bad xxxflag() type %d\n", t->elem[0].type);
					ret = E_BUG;
					goto error;
				}

				if (t->elem[0].u.number == NAMED_FLAG_ERROR) {
					LM_CRIT("Fixup flag failed!\n");
					ret=E_CFG;
					goto error;
				}
				break;
			case SETBFLAG_T:
			case RESETBFLAG_T:
			case ISBFLAGSET_T:
				if (t->elem[0].type!=NUMBER_ST) {
					LM_CRIT("bad xxxbflag() type "
						"%d,%d\n", t->elem[0].type, t->elem[0].type);
					ret=E_BUG;
					goto error;
				}

				if (t->elem[1].type == NUMBER_ST) {
					s.s = int2str((unsigned long)t->elem[1].u.number, &s.len);
				    t->elem[1].u.number = fixup_flag(FLAG_TYPE_BRANCH, &s);

				} else if (t->elem[1].type == STR_ST) {
					t->elem[1].u.number = fixup_flag(FLAG_TYPE_BRANCH,
					                                 &t->elem[1].u.s);
				} else {
					LM_CRIT("bad xxxbflag() type "
						"%d,%d\n", t->elem[1].type, t->elem[1].type);
					ret=E_BUG;
					goto error;
				}

				if (t->elem[1].u.number == NAMED_FLAG_ERROR) {
					LM_CRIT("Fixup flag failed!\n");
					ret=E_CFG;
					goto error;
				}

				if (t->elem[1].u.data==0) {
					ret=E_CFG;
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
			case USE_BLACKLIST_T:
			case UNUSE_BLACKLIST_T:
				if (t->elem[0].type!=STRING_ST) {
					LM_CRIT("bad [UN]USE_BLACKLIST type %d\n",t->elem[0].type);
					ret=E_BUG;
					goto error;
				}
				host.s = t->elem[0].u.string;
				host.len = strlen(host.s);
				if (!strcasecmp(host.s, "all")) {
					blh = NULL;
				} else {
					blh = get_bl_head_by_name(&host);
					if (!blh) {
						LM_ERR("[UN]USE_BLACKLIST - list "
							"%s not configured\n", t->elem[0].u.string);
						ret=E_CFG;
						goto error;
					}
				}
				t->elem[0].type = BLACKLIST_ST;
				t->elem[0].u.data = blh;
				break;
			case CACHE_STORE_T:
			case CACHE_FETCH_T:
			case CACHE_COUNTER_FETCH_T:
			case CACHE_REMOVE_T:
			case CACHE_ADD_T:
			case CACHE_SUB_T:
			case CACHE_RAW_QUERY_T:
				/* attr name */
				s.s = (char*)t->elem[1].u.data;
				s.len = strlen(s.s);
				if(s.len==0) {
					LM_ERR("param 2 is empty string!\n");
					return E_CFG;
				}

				if(pv_parse_format(&s ,&model) || model==NULL) {
						LM_ERR("wrong format [%s] for value param!\n", s.s);
						ret=E_BUG;
						goto error;
				}
				t->elem[1].u.data = (void*)model;

				if (t->type==CACHE_REMOVE_T)
					break;

				/* value */
				if (t->type==CACHE_FETCH_T ||
					t->type==CACHE_COUNTER_FETCH_T) {
					if(((pv_spec_p)t->elem[2].u.data)->setf == NULL)
					{
						LM_ERR("Third argument cannot be a read-only pvar\n");
						ret=E_CFG;
						goto error;
					}
				} else if (t->type==CACHE_STORE_T) {
					s.s = (char*)t->elem[2].u.data;
					s.len = strlen(s.s);
					if(s.len==0) {
						LM_ERR("param 2 is empty string!\n");
						return E_CFG;
					}

					if(pv_parse_format(&s ,&model) || model==NULL) {
						LM_ERR("wrong format [%s] for value param!\n",s.s);
						ret=E_BUG;
						goto error;
					}
					t->elem[2].u.data = (void*)model;
				} else if (t->type==CACHE_RAW_QUERY_T) {
					if(t->elem[2].u.data != NULL) {
						s.s = (char*)t->elem[2].u.data;
						s.len = strlen(s.s);

						t->elem[2].u.data = (void*)parse_pvname_list(&s, PVT_AVP);
						if (t->elem[2].u.data == NULL) {
							ret=E_BUG;
							goto error;
						}
					}
				} else if (t->type==CACHE_ADD_T || t->type==CACHE_SUB_T) {
					if(t->elem[4].u.data != NULL && ((pv_spec_p)t->elem[4].u.data)->setf == NULL)
					{
						LM_ERR("Fourth argument cannot be a read-only pvar\n");
						ret=E_CFG;
						goto error;
					}

				}
				break;
			case SET_ADV_ADDR_T:
				s.s = (char *)t->elem[0].u.data;
				if (s.s == NULL) {
					LM_ERR("null param in set_advertised_address\n");
					ret=E_BUG;
					goto error;
				}
				s.len = strlen(s.s);
				if(pv_parse_format(&s ,&model) || model==NULL) {
						LM_ERR("wrong format for [%.*s] advertised param!\n",
								t->elem[1].u.s.len,t->elem[1].u.s.s);
						ret=E_BUG;
						goto error;
				}
				t->elem[0].u.data = (void*)model;
				break;
			case SET_ADV_PORT_T:
				if (t->elem[0].type == STR_ST) {
					s.s = (char *)t->elem[0].u.data;
					s.len = strlen(s.s);

					if (pv_parse_format(&s ,&model) != 0 || !model) {
							LM_ERR("wrong format for [%.*s] advertised port!\n",
									t->elem[1].u.s.len, t->elem[1].u.s.s);
							ret = E_BUG;
							goto error;
					}

					t->elem[0].u.data = model;
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
			case RAISE_EVENT_T:
				s.s = t->elem[0].u.data;
				s.len = strlen(s.s);
				ev_id = evi_get_id(&s);
				if (ev_id == EVI_ERROR) {
					ev_id = evi_publish_event(s);
					if (ev_id == EVI_ERROR) {
						LM_ERR("cannot subscribe event\n");
						ret=E_UNSPEC;
						goto error;
					}
				}
				t->elem[0].u.number = ev_id;
				t->elem[0].type = NUMBER_ST;
				if (t->elem[1].u.data &&
						((pv_spec_p)t->elem[1].u.data)->type != PVT_AVP) {
					LM_ERR("second parameter should be an avp\n");
					ret=E_UNSPEC;
					goto error;
				}
				/* if was called with 3 parameters */
				if (t->elem[2].u.data &&
						((pv_spec_p)t->elem[2].u.data)->type != PVT_AVP) {
					LM_ERR("third parameter should be also an avp\n");
					ret=E_UNSPEC;
					goto error;
				}
				break;
			case CONSTRUCT_URI_T:
				for (i=0;i<5;i++)
				{
					s.s = (char*)t->elem[i].u.data;
					s.len = strlen(s.s);
					if(s.len==0)
						continue;

					if(pv_parse_format(&s ,&(models[i])) || models[i]==NULL)
					{
						LM_ERR("wrong format [%s] for value param!\n",s.s);
						ret=E_BUG;
						goto error;
					}

					t->elem[i].u.data = (void*)models[i];
				}

				if (((pv_spec_p)t->elem[5].u.data)->type != PVT_AVP)
				{
					LM_ERR("Wrong type for the third argument - "
						"must be an AVP\n");
					ret=E_BUG;
					goto error;
				}

				break;
			case GET_TIMESTAMP_T:
				if (((pv_spec_p)t->elem[0].u.data)->type != PVT_AVP)
				{
					LM_ERR("Wrong type for the first argument - "
						"must be an AVP\n");
					ret=E_BUG;
					goto error;
				}

				if (((pv_spec_p)t->elem[1].u.data)->type != PVT_AVP)
				{
					LM_ERR("Wrong type for the second argument - "
						"must be an AVP\n");
					ret=E_BUG;
					goto error;
				}
				break;
			case IS_MYSELF_T:
				s.s = (char*)t->elem[0].u.data;
				s.len = strlen(s.s);
				if(s.len == 0) {
					LM_ERR("param 1 is empty string!\n");
					return E_CFG;
				}

				if(pv_parse_format(&s ,&model) || model == NULL) {
						LM_ERR("wrong format [%s] for value param!\n", s.s);
						ret=E_BUG;
						goto error;
				}
				t->elem[0].u.data = (void*)model;
				t->elem[0].type = SCRIPTVAR_ELEM_ST;

				s.s = (char *)t->elem[1].u.data;
				if (s.s == NULL)
					break;

				s.len = strlen(s.s);
				if(s.len == 0) {
					LM_ERR("param 2 is empty string!\n");
					return E_CFG;
				}
				if (s.s[0] == PV_MARKER) {
					sp = pkg_malloc(sizeof *sp);
					if (!sp) {
						LM_ERR("No more pkg memory\n");
						return E_BUG;
					}
					if (pv_parse_spec(&s, sp) == NULL) {
						LM_ERR("Unable to parse port paremeter var\n");
						return E_BUG;
					}
					t->elem[1].u.data = (void*)sp;
					t->elem[1].type = SCRIPTVAR_ST;
				} else {
					if (str2int(&s, (unsigned int *)&port) < 0) {
						LM_ERR("port parameter should be a number\n");
						return E_CFG;
					}
					t->elem[1].u.number = port;
					t->elem[1].type = NUMBER_ST;
				}
		}
	}
	return 0;
error:
	LM_ERR("fixing failed (code=%d) at %s:%d\n", ret, t->file, t->line);
	return ret;
}


inline static int comp_no( int port, void *param, int op, int subtype )
{

	if (subtype!=NUMBER_ST) {
		LM_CRIT("number expected: %d\n", subtype );
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
		LM_CRIT("unknown operator: %d\n", op );
		return E_BUG;
	}
}

/*! \brief eval_elem helping function
 * \return str op param
 */
inline static int comp_strval(struct sip_msg *msg, int op, str* ival,
		operand_t *opd)
{
	int ret;
	regex_t* re;
	char backup;
	char backup2;
	str res;
	pv_value_t value;

	if(ival==NULL || ival->s==NULL)
		goto error;

	res.s = 0; res.len = 0;
	if(opd->type == SCRIPTVAR_ST)
	{
		if(pv_get_spec_value(msg, opd->v.spec, &value)!=0)
		{
			LM_CRIT("cannot get var value\n");
			goto error;
		}
		if(value.flags&PV_VAL_STR)
		{
			res = value.rs;
		} else {
			res.s = sint2str(value.ri, &res.len);
		}
	} else if(opd->type == NUMBER_ST) {
		res.s = sint2str(opd->v.n, &res.len);
	}else if(opd->type == STR_ST) {
		res = opd->v.s;
	} else {
		if((op!=MATCH_OP && op!=NOTMATCH_OP) || opd->type != RE_ST)
		{
			LM_CRIT("invalid operation %d/%d\n", op, opd->type);
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
		case NOTMATCH_OP:
			backup=ival->s[ival->len];ival->s[ival->len]='\0';

			if(opd->type == SCRIPTVAR_ST) {
				re=(regex_t*)pkg_malloc(sizeof(regex_t));
				if (re==0){
					LM_CRIT("pkg memory allocation failure\n");
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
			if(op==NOTMATCH_OP)
				ret = !ret;
			break;
		default:
			LM_CRIT("unknown op %d\n", op);
			goto error;
	}
	return ret;

error:
	return -1;
}

/*! \brief eval_elem helping function, returns str op param
 */
inline static int comp_str(char* str, void* param, int op, int subtype)
{
	int ret;

	ret=-1;
	switch(op){
		case EQUAL_OP:
			if (subtype!=STR_ST){
				LM_CRIT("bad type %d, string expected\n", subtype);
				goto error;
			}
			ret=(strcasecmp(str, (char*)param)==0);
			break;
		case DIFF_OP:
			if (subtype!=STR_ST){
				LM_CRIT("bad type %d, string expected\n", subtype);
				goto error;
			}
			ret=(strcasecmp(str, (char*)param)!=0);
			break;
		case MATCH_OP:
			if (subtype!=RE_ST){
				LM_CRIT("bad type %d, RE expected\n", subtype);
				goto error;
			}
			ret=(regexec((regex_t*)param, str, 0, 0, 0)==0);
			break;
		case NOTMATCH_OP:
			if (subtype!=RE_ST){
				LM_CRIT("bad type %d, RE expected!\n", subtype);
				goto error;
			}
			ret=(regexec((regex_t*)param, str, 0, 0, 0)!=0);
			break;
		default:
			LM_CRIT("unknown op %d\n", op);
			goto error;
	}
	return ret;

error:
	return -1;
}


/*! \brief check_self wrapper -- it checks also for the op */
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
			LM_CRIT("invalid operator %d\n", op);
			ret=-1;
	}
	return ret;
}


/*! \brief eval_elem helping function, returns an op param */
inline static int comp_ip(struct sip_msg *msg, int op, struct ip_addr* ip,
		operand_t *opd)
{
	struct hostent* he;
	char ** h;
	int ret;

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
		case STR_ST:
		case RE_ST:
			switch(op){
				case EQUAL_OP:
				case MATCH_OP:
					/* 1: compare with ip2str*/
					ret=comp_str(ip_addr2a(ip), opd->v.data, op, opd->type);
					if (ret==1) break;
					/* 2: resolve (name) & compare w/ all the ips */
					if (opd->type==STR_ST){
						he=resolvehost((char*)opd->v.data,0);
						if (he==0){
							LM_DBG("could not resolve %s\n",(char*)opd->v.data);
						}else if (he->h_addrtype==(int)ip->af){
							for(h=he->h_addr_list;(ret!=1)&& (*h); h++){
								ret=(memcmp(ip->u.addr, *h, ip->len)==0);
							}
							if (ret==1) break;
						}
					}
					/* 3: (slow) rev dns the address
					* and compare with all the aliases
					* !!??!! review: remove this? */
					if(received_dns & DO_REV_DNS)
					{
						he=rev_resolvehost(ip);
						if (he==0){
							print_ip("could not rev_resolve ip address: ",
								 ip, "\n");
							ret=0;
						}else{
							/*  compare with primary host name */
							ret=comp_str(he->h_name, opd->v.data, op,
									opd->type);
							/* compare with all the aliases */
							for(h=he->h_aliases; (ret!=1) && (*h); h++){
								ret=comp_str(*h, opd->v.data, op, opd->type);
							}
						}
					} else {
						return 0;
					}
					break;
				case DIFF_OP:
					ret=comp_ip(msg, MATCH_OP, ip, opd);
					if (ret>=0) ret=!ret;
					break;
				default:
					goto error_op;
			}
			break;
		default:
			LM_CRIT("invalid type for src_ip or dst_ip (%d)\n", opd->type);
			ret=-1;
	}
	return ret;
error_op:
	LM_CRIT("invalid operator %d\n", op);
	return -1;

}

/*! \brief compare str to str */
inline static int comp_s2s(int op, str *s1, str *s2)
{
	char backup;
	char backup2;
	int n;
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
			ret=(strncasecmp(s1->s, s2->s, s2->len)==0);
		break;
		case DIFF_OP:
			if ( s2->s==NULL ) return 0;
			if(s1->len != s2->len) return 1;
			ret=(strncasecmp(s1->s, s2->s, s2->len)!=0);
			break;
		case GT_OP:
			if ( s2->s==NULL ) return 0;
			n = (s1->len>=s2->len)?s1->len:s2->len;
			rt = strncasecmp(s1->s,s2->s, n);
			if (rt>0)
				ret = 1;
			else if(rt==0 && s1->len>s2->len)
				ret = 1;
			else ret = 0;
			break;
		case GTE_OP:
			if ( s2->s==NULL ) return 0;
			n = (s1->len>=s2->len)?s1->len:s2->len;
			rt = strncasecmp(s1->s,s2->s, n);
			if (rt>0)
				ret = 1;
			else if(rt==0 && s1->len>=s2->len)
				ret = 1;
			else ret = 0;
			break;
		case LT_OP:
			if ( s2->s==NULL ) return 0;
			n = (s1->len>=s2->len)?s1->len:s2->len;
			rt = strncasecmp(s1->s,s2->s, n);
			if (rt<0)
				ret = 1;
			else if(rt==0 && s1->len<s2->len)
				ret = 1;
			else ret = 0;
			break;
		case LTE_OP:
			if ( s2->s==NULL ) return 0;
			n = (s1->len>=s2->len)?s1->len:s2->len;
			rt = strncasecmp(s1->s,s2->s, n);
			if (rt<0)
				ret = 1;
			else if(rt==0 && s1->len<=s2->len)
				ret = 1;
			else ret = 0;
			break;
		case MATCH_OP:
			if ( s2==NULL || s1->len == 0 ) return 0;
			backup = s1->s[s1->len];  s1->s[s1->len] = '\0';
			ret=(regexec((regex_t*)s2, s1->s, 0, 0, 0)==0);
			s1->s[s1->len] = backup;
			break;
		case NOTMATCH_OP:
			if ( s2==NULL || s1->len == 0 ) return 0;
			backup = s1->s[s1->len];  s1->s[s1->len] = '\0';
			ret=(regexec((regex_t*)s2, s1->s, 0, 0, 0)!=0);
			s1->s[s1->len] = backup;
			break;
		case MATCHD_OP:
		case NOTMATCHD_OP:
			if ( s2->s==NULL || s1->len == 0 ) return 0;
			re=(regex_t*)pkg_malloc(sizeof(regex_t));
			if (re==0) {
				LM_CRIT("pkg memory allocation failure\n");
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
				return (op==EQUAL_OP)?1:0;
			return (op==DIFF_OP)?1:0;
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

		if(right->type == NUMBER_ST) {
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
		case METHOD_O:
				ret=comp_strval(msg, e->op, &msg->first_line.u.request.method,
						&e->right);
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
								val->ri = 0;
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


int add_actions(struct action* a, struct action** head)
{
	int ret;

	LM_DBG("fixing actions...\n");
	if ((ret=fix_actions(a))!=0) goto error;
	push(a,head);
	return 0;

error:
	return ret;
}



/*! \brief fixes all action tables
 * \return 0 if ok , <0 on error
 */
int fix_rls(void)
{
	int i,ret;
	for(i=0;i<RT_NO;i++){
		if(rlist[i].a){
			if ((ret=fix_actions(rlist[i].a))!=0){
				return ret;
			}
		}
	}
	for(i=0;i<ONREPLY_RT_NO;i++){
		if(onreply_rlist[i].a){
			if ((ret=fix_actions(onreply_rlist[i].a))!=0){
				return ret;
			}
		}
	}
	for(i=0;i<FAILURE_RT_NO;i++){
		if(failure_rlist[i].a){
			if ((ret=fix_actions(failure_rlist[i].a))!=0){
				return ret;
			}
		}
	}
	for(i=0;i<BRANCH_RT_NO;i++){
		if(branch_rlist[i].a){
			if ((ret=fix_actions(branch_rlist[i].a))!=0){
				return ret;
			}
		}
	}
	if(error_rlist.a){
		if ((ret=fix_actions(error_rlist.a))!=0){
			return ret;
		}
	}
	if(local_rlist.a){
		if ((ret=fix_actions(local_rlist.a))!=0){
			return ret;
		}
	}
	if(startup_rlist.a){
		if ((ret=fix_actions(startup_rlist.a))!=0){
			return ret;
		}
	}

	for(i = 0; i< TIMER_RT_NO; i++) {
		if(timer_rlist[i].a == NULL)
			break;

		if ((ret=fix_actions(timer_rlist[i].a))!=0){
			return ret;
		}
	}

	for(i = 1; i< EVENT_RT_NO; i++) {
		if(event_rlist[i].a == NULL)
			break;

		if ((ret=fix_actions(event_rlist[i].a))!=0){
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
					LM_CRIT("stack overflow (%d)\n", rcheck_stack_p);
					goto error;
				}
				rcheck_stack[rcheck_stack_p] = a->elem[0].u.number;
				if (check_actions( rlist[a->elem[0].u.number].a, r_type)!=0)
					goto error;
				rcheck_stack_p--;
				break;
			case IF_T:
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
			case MODULE_T:
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
				break;
			default:
				break;
		}
	}

	return 0;
error:
	return -1;
}


/*! \brief check all routing tables for compatiblity between
 * route types and called module functions;
 * \return 0 if ok , <0 on error
 */
int check_rls(void)
{
	int i,ret;

	rcheck_status = 0;

	if(rlist[0].a){
		if ((ret=check_actions(rlist[0].a,REQUEST_ROUTE))!=0){
			LM_ERR("check failed for main request route\n");
			return ret;
		}
	}
	for(i=0;i<ONREPLY_RT_NO;i++){
		if(onreply_rlist[i].a){
			if ((ret=check_actions(onreply_rlist[i].a,ONREPLY_ROUTE))!=0){
				LM_ERR("check failed for onreply_route[%d]\n",i);
				return ret;
			}
		}
	}
	for(i=0;i<FAILURE_RT_NO;i++){
		if(failure_rlist[i].a){
			if ((ret=check_actions(failure_rlist[i].a,FAILURE_ROUTE))!=0){
				LM_ERR("check failed for failure_route[%d]\n",i);
				return ret;
			}
		}
	}
	for(i=0;i<BRANCH_RT_NO;i++){
		if(branch_rlist[i].a){
			if ((ret=check_actions(branch_rlist[i].a,BRANCH_ROUTE))!=0){
				LM_ERR("check failed for branch_route[%d]\n",i);
				return ret;
			}
		}
	}
	if(error_rlist.a){
		if ((ret=check_actions(error_rlist.a,ERROR_ROUTE))!=0){
			LM_ERR("check failed for error_route\n");
			return ret;
		}
	}
	if(local_rlist.a){
		if ((ret=check_actions(local_rlist.a,LOCAL_ROUTE))!=0){
			LM_ERR("check failed for local_route\n");
			return ret;
		}
	}
	if(startup_rlist.a){
		if ((ret=check_actions(startup_rlist.a,STARTUP_ROUTE))!=0){
			LM_ERR("check failed for startup_route\n");
			return ret;
		}
	}

	for(i = 0; i< TIMER_RT_NO; i++) {
		if(timer_rlist[i].a == NULL)
			break;

		if ((ret=check_actions(timer_rlist[i].a,TIMER_ROUTE))!=0){
			LM_ERR("check failed for timer_route\n");
			return ret;
		}

	}

	for(i = 1; i< EVENT_RT_NO; i++) {
		if(event_rlist[i].a == NULL)
			break;

		if ((ret=check_actions(event_rlist[i].a,EVENT_ROUTE))!=0){
			LM_ERR("check failed for event_route\n");
			return ret;
		}

	}



	return rcheck_status;
}




/*! \brief debug function, prints main routing table */
void print_rl(void)
{
#define dump_rlist(rlist, max, desc) \
	{ \
		int __j; \
		for (__j = 0; __j < max; __j++) { \
			if (!(rlist)[__j].a) \
				continue; \
			LM_GEN1(L_DBG, desc " routing block %d:\n", __j); \
			print_actions((rlist)[__j].a); \
			LM_GEN1(L_DBG, "\n\n"); \
		} \
	}

	dump_rlist(rlist,          RT_NO,         "main");
	dump_rlist(onreply_rlist,  ONREPLY_RT_NO, "onreply");
	dump_rlist(failure_rlist,  FAILURE_RT_NO, "failure");
	dump_rlist(branch_rlist,   BRANCH_RT_NO,  "branch");
	dump_rlist(&local_rlist,   1,             "local");
	dump_rlist(&error_rlist,   1,             "error");
	dump_rlist(&startup_rlist, 1,             "startup");
	dump_rlist(timer_rlist,    TIMER_RT_NO,   "timer");
	dump_rlist(event_rlist,    EVENT_RT_NO,   "event");
}


int is_script_func_used( char *name, int param_no)
{
	unsigned int i;

	for( i=0; i<RT_NO ; i++ )
		if (rlist[i].a && is_mod_func_used(rlist[i].a,name,param_no) )
			return 1;

	for( i=0; i<ONREPLY_RT_NO ; i++ )
		if (onreply_rlist[i].a &&
		is_mod_func_used(onreply_rlist[i].a,name,param_no) )
			return 1;

	for( i=0; i<FAILURE_RT_NO ; i++ )
		if (failure_rlist[i].a &&
		is_mod_func_used(failure_rlist[i].a,name,param_no) )
			return 1;

	for( i=0; i<BRANCH_RT_NO ; i++ )
		if (branch_rlist[i].a &&
		is_mod_func_used(branch_rlist[i].a,name,param_no) )
			return 1;

	for( i=0; i<TIMER_RT_NO ; i++ )
		if (timer_rlist[i].a &&
		is_mod_func_used(timer_rlist[i].a,name,param_no) )
			return 1;

	for( i=0; i<EVENT_RT_NO ; i++ )
		if (event_rlist[i].a &&
		is_mod_func_used(event_rlist[i].a,name,param_no) )
			return 1;

	if (error_rlist.a &&
	is_mod_func_used(error_rlist.a,name,param_no) )
		return 1;

	if (local_rlist.a &&
	is_mod_func_used(local_rlist.a,name,param_no) )
		return 1;

	if (startup_rlist.a &&
	is_mod_func_used(startup_rlist.a,name,param_no) )
		return 1;

	return 0;
}

int is_script_async_func_used( char *name, int param_no)
{
	unsigned int i;

	for( i=0; i<RT_NO ; i++ )
		if (rlist[i].a && is_mod_async_func_used(rlist[i].a,name,param_no) )
			return 1;

	for( i=0; i<ONREPLY_RT_NO ; i++ )
		if (onreply_rlist[i].a &&
		is_mod_async_func_used(onreply_rlist[i].a,name,param_no) )
			return 1;

	for( i=0; i<FAILURE_RT_NO ; i++ )
		if (failure_rlist[i].a &&
		is_mod_async_func_used(failure_rlist[i].a,name,param_no) )
			return 1;

	for( i=0; i<BRANCH_RT_NO ; i++ )
		if (branch_rlist[i].a &&
		is_mod_async_func_used(branch_rlist[i].a,name,param_no) )
			return 1;

	for( i=0; i<TIMER_RT_NO ; i++ )
		if (timer_rlist[i].a &&
		is_mod_async_func_used(timer_rlist[i].a,name,param_no) )
			return 1;

	for( i=0; i<EVENT_RT_NO ; i++ )
		if (event_rlist[i].a &&
		is_mod_async_func_used(event_rlist[i].a,name,param_no) )
			return 1;

	if (error_rlist.a &&
	is_mod_async_func_used(error_rlist.a,name,param_no) )
		return 1;

	if (local_rlist.a &&
	is_mod_async_func_used(local_rlist.a,name,param_no) )
		return 1;

	if (startup_rlist.a &&
	is_mod_async_func_used(startup_rlist.a,name,param_no) )
		return 1;

	return 0;
}


int run_startup_route(void)
{
	struct sip_msg req;

	memset(&req, 0, sizeof(struct sip_msg));
	req.first_line.type = SIP_REQUEST;

	req.first_line.u.request.method.s= "DUMMY";
	req.first_line.u.request.method.len= 5;
	req.first_line.u.request.uri.s= "sip:user@domain.com";
	req.first_line.u.request.uri.len= 19;
	req.rcv.src_ip.af = AF_INET;
	req.rcv.dst_ip.af = AF_INET;

	/* run the route */
	return run_top_route( startup_rlist.a, &req);
}
