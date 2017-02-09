/*
 * Copyright (C) 2010-2014 OpenSIPS Solutions
 * Copyright (C) 2005-2006 Voice Sistem S.R.L.
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
 * ---------
 *  2003-02-28  scratchpad compatibility abandoned (jiri)
 *  2003-01-29  removed scratchpad (jiri)
 *  2003-03-19  fixed set* len calculation bug & simplified a little the code
 *              (should be a little faster now) (andrei)
 *              replaced all mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2003-04-01  Added support for loose routing in forward (janakj)
 *  2003-04-12  FORCE_RPORT_T added (andrei)
 *  2003-04-22  strip_tail added (jiri)
 *  2003-10-02  added SET_ADV_ADDR_T & SET_ADV_PORT_T (andrei)
 *  2003-10-29  added FORCE_TCP_ALIAS_T (andrei)
 *  2004-11-30  added FORCE_SEND_SOCKET_T (andrei)
 *  2005-11-29  added serialize_branches and next_branches (bogdan)
 *  2006-03-02  MODULE_T action points to a cmd_export_t struct instead to
 *               a function address - more info is accessible (bogdan)
 *  2006-05-22  forward(_udp,_tcp,_tls) and send(_tcp) merged in forward() and
 *               send() (bogdan)
 *  2006-12-22  functions for script and branch flags added (bogdan)
 */

/*!
 * \file
 * \brief OpenSIPS Generic functions
 */

#include "action.h"
#include "config.h"
#include "error.h"
#include "dprint.h"
#include "proxy.h"
#include "forward.h"
#include "route.h"
#include "parser/msg_parser.h"
#include "parser/parse_uri.h"
#include "ut.h"
#include "sr_module.h"
#include "mem/mem.h"
#include "globals.h"
#include "dset.h"
#include "flags.h"
#include "errinfo.h"
#include "serialize.h"
#include "blacklists.h"
#include "cachedb/cachedb.h"
#include "msg_translator.h"
#include "mod_fix.h"
/* needed by tcpconn_add_alias() */
#include "net/tcp_conn_defs.h"

#include "script_var.h"
#include "xlog.h"
#include "evi/evi_modules.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#ifdef DEBUG_DMALLOC
#include <dmalloc.h>
#endif

int action_flags = 0;
int return_code  = 0;
int max_while_loops = 100;

/* script tracing options  */
int use_script_trace = 0;
int script_trace_log_level = L_ALERT;
char *script_trace_info = NULL;
pv_elem_t script_trace_elem;

static int rec_lev=0;

extern err_info_t _oser_err_info;

action_time longest_action[LONGEST_ACTION_SIZE];
int min_action_time=0;

action_elem_p route_params[MAX_REC_LEV];
int route_params_number[MAX_REC_LEV];
int route_rec_level = -1;

int curr_action_line;
char *curr_action_file;

static int for_each_handler(struct sip_msg *msg, struct action *a);


/* run actions from a route */
/* returns: 0, or 1 on success, <0 on error */
/* (0 if drop or break encountered, 1 if not ) */
static inline int run_actions(struct action* a, struct sip_msg* msg)
{
	int ret;

	rec_lev++;
	if (rec_lev>ROUTE_MAX_REC_LEV){
		LM_ERR("too many recursive routing table lookups (%d) giving up!\n",
			rec_lev);
		ret=E_UNSPEC;
		goto error;
	}

	if (a==0){
		LM_WARN("null action list (rec_level=%d)\n",
			rec_lev);
		ret=1;
		goto error;
	}

	ret=run_action_list(a, msg);

	/* if 'return', reset the flag */
	if(action_flags&ACT_FL_RETURN)
		action_flags &= ~ACT_FL_RETURN;

	rec_lev--;
	return ret;

error:
	rec_lev--;
	return ret;
}


/* run the error route with correct handling - simpler wrapper to
   allow the usage from other parts of the code */
void run_error_route(struct sip_msg* msg, int force_reset)
{
	int old_route;
	LM_DBG("triggering\n");
	swap_route_type(old_route, ERROR_ROUTE);
	run_actions(error_rlist.a, msg);
	/* reset error info */
	init_err_info();
	set_route_type(old_route);
}


/* run a list of actions */
int run_action_list(struct action* a, struct sip_msg* msg)
{
	int ret=E_UNSPEC;
	struct action* t;
	for (t=a; t!=0; t=t->next){
		ret=do_action(t, msg);
		/* if action returns 0, then stop processing the script */
		if(ret==0)
			action_flags |= ACT_FL_EXIT;

		/* check for errors */
		if (_oser_err_info.eclass!=0 && error_rlist.a!=NULL &&
		(route_type&(ERROR_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE))==0 )
			run_error_route(msg,0);

		/* continue or not ? */
		if( action_flags&(ACT_FL_RETURN|ACT_FL_EXIT) )
			break;
	}
	return ret;
}



int run_top_route(struct action* a, struct sip_msg* msg)
{
	int bk_action_flags;
	int bk_rec_lev;
	int ret;

	bk_action_flags = action_flags;
	bk_rec_lev = rec_lev;

	action_flags = 0;
	rec_lev = 0;
	init_err_info();

	run_actions(a, msg);
	ret = action_flags;

	action_flags = bk_action_flags;
	rec_lev = bk_rec_lev;
	/* reset script tracing */
	use_script_trace = 0;

	return ret;
}


/* execute assignment operation */
int do_assign(struct sip_msg* msg, struct action* a)
{
	int ret;
	pv_value_t val;
	pv_spec_p dspec;

	ret = -1;
	dspec = (pv_spec_p)a->elem[0].u.data;
	if(!pv_is_w(dspec))
	{
		LM_ERR("read only PV in left expression\n");
		goto error;
	}

	memset(&val, 0, sizeof(pv_value_t));
	if(a->elem[1].type != NULLV_ST)
	{
		ret = eval_expr((struct expr*)a->elem[1].u.data, msg, &val);
		if(ret < 0 || !(val.flags & (PV_VAL_STR | PV_VAL_INT | PV_VAL_NULL)))
		{
			LM_WARN("no value in right expression at %s:%d\n",
				a->file, a->line);
			goto error2;
		}
	}

	switch ((unsigned char)a->type){
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
			script_trace("assign",
				(unsigned char)a->type == EQ_T      ? "equal" :
				(unsigned char)a->type == COLONEQ_T ? "colon-eq" :
				(unsigned char)a->type == PLUSEQ_T  ? "plus-eq" :
				(unsigned char)a->type == MINUSEQ_T ? "minus-eq" :
				(unsigned char)a->type == DIVEQ_T   ? "div-eq" :
				(unsigned char)a->type == MULTEQ_T  ? "mult-eq" :
				(unsigned char)a->type == MODULOEQ_T? "modulo-eq" :
				(unsigned char)a->type == BANDEQ_T  ? "b-and-eq" :
				(unsigned char)a->type == BOREQ_T   ? "b-or-eq":"b-xor-eq",
				msg, a->file, a->line);

			if(a->elem[1].type == NULLV_ST || (val.flags & PV_VAL_NULL))
			{
				if(pv_set_value(msg, dspec, (int)a->type, 0)<0)
				{
					LM_ERR("setting PV failed\n");
					goto error;
				}
			} else {
				if(pv_set_value(msg, dspec, (int)a->type, &val)<0)
				{
					LM_ERR("setting PV failed\n");
					goto error;
				}
			}
			ret = 1;
		break;
		default:
			LM_ALERT("BUG -> unknown op type %d\n", a->type);
			goto error;
	}

	pv_value_destroy(&val);
	return ret;

error:
	LM_ERR("error at %s:%d\n", a->file, a->line);
error2:
	pv_value_destroy(&val);
	return -1;
}

static int do_action_set_adv_address(struct sip_msg *msg, struct action *a)
{
	str adv_addr;
	int ret = 1; /* continue processing */

	if (a->elem[0].type != STR_ST) {
		report_programming_bug("set_advertised_address type %d", a->elem[0].type);
		ret = E_BUG;
		goto out;
	}

	if (pv_printf_s(msg, (pv_elem_t *)a->elem[0].u.data, &adv_addr) != 0
	    || adv_addr.len <= 0) {
		LM_WARN("cannot get string for value (%s:%d)\n",a->file,a->line);
		ret = E_BUG;
		goto out;
	}

	LM_DBG("setting adv address = [%.*s]\n", adv_addr.len, adv_addr.s);

	/* duplicate the advertised address into private memory */
	if (adv_addr.len > msg->set_global_address.len) {
		msg->set_global_address.s = pkg_realloc(msg->set_global_address.s,
											    adv_addr.len);
		if (!msg->set_global_address.s) {
			LM_ERR("out of pkg mem\n");
			ret = E_OUT_OF_MEM;
			goto out;
		}
	}
	memcpy(msg->set_global_address.s, adv_addr.s, adv_addr.len);
	msg->set_global_address.len = adv_addr.len;

out:
	return ret;
}

static int do_action_set_adv_port(struct sip_msg *msg, struct action *a)
{
	str adv_port;
	int ret = 1;

	if (a->elem[0].type != STR_ST) {
		report_programming_bug("set_advertised_port type %d", a->elem[0].type);
		ret = E_BUG;
		goto out;
	}

	if (pv_printf_s(msg, (pv_elem_t *)a->elem[0].u.data, &adv_port) != 0
	    || adv_port.len <= 0) {

		LM_WARN("cannot get string for value (%s:%d)\n", a->file,a->line);
		ret = E_BUG;
		goto out;
	}

	LM_DBG("setting adv port '%.*s'\n", adv_port.len, adv_port.s);

	/* duplicate the advertised port into private memory */
	if (adv_port.len > msg->set_global_port.len) {
		msg->set_global_port.s = pkg_realloc(msg->set_global_port.s,
											 adv_port.len);
		if (!msg->set_global_port.s) {
			LM_ERR("out of pkg mem\n");
			ret = E_OUT_OF_MEM;
			goto out;
		}
	}
	memcpy(msg->set_global_port.s, adv_port.s, adv_port.len);
	msg->set_global_port.len = adv_port.len;

out:
	return ret;
}

#define should_skip_updating(action_type) \
	(action_type == IF_T || action_type == ROUTE_T || \
	 action_type == WHILE_T || action_type == FOR_EACH_T)

#define update_longest_action(a) do {	\
		if (execmsgthreshold && !should_skip_updating((unsigned char)(a)->type)) { \
			end_time = get_time_diff(&start);	\
			if (end_time > min_action_time) {	\
				for (i=0;i<LONGEST_ACTION_SIZE;i++) {	\
					if (longest_action[i].a_time < end_time) {	\
						memmove(longest_action+i+1,longest_action+i,	\
								(LONGEST_ACTION_SIZE-i-1)*sizeof(action_time));	\
						longest_action[i].a_time=end_time;	\
						longest_action[i].a = a;	\
						min_action_time = longest_action[LONGEST_ACTION_SIZE-1].a_time;	\
						break;	\
					}	\
				}	\
			}	\
		}	\
	} while(0)

/* ret= 0! if action -> end of list(e.g DROP),
      > 0 to continue processing next actions
   and <0 on error */
int do_action(struct action* a, struct sip_msg* msg)
{
	int ret;
	int v;
	int sec,usec;
	union sockaddr_union* to;
	struct proxy_l* p;
	char* tmp;
	char *new_uri, *end, *crt;
	int len,i;
	int user = 0;
	int expires = 0;
	str vals[5];
	str result;
	struct sip_uri uri, next_hop;
	struct sip_uri *u;
	unsigned short port;
	int cmatch;
	struct action *aitem;
	struct action *adefault;
	pv_spec_t *spec;
	pv_elem_p model;
	pv_value_t val;
	pv_elem_t *pve;
	str name_s;
	struct timeval start;
	int end_time;
	int aux_counter;

	/* reset the value of error to E_UNSPEC so avoid unknowledgable
	   functions to return with error (status<0) and not setting it
	   leaving there previous error; cache the previous value though
	   for functions which want to process it */
	prev_ser_error=ser_error;
	ser_error=E_UNSPEC;

	start_expire_timer(start,execmsgthreshold);

	curr_action_line = a->line;
	curr_action_file = a->file;

	ret=E_BUG;
	switch ((unsigned char)a->type){
		case ASSERT_T:
				if (enable_asserts) {
					/* if null expr => ignore if? */
					if ((a->elem[0].type==EXPR_ST)&&a->elem[0].u.data){
						v=eval_expr((struct expr*)a->elem[0].u.data, msg, 0);

						ret=1;  /*default is continue */

						if (v<=0) {
							ret=0;

							LM_CRIT("ASSERTION FAILED - %s\n", a->elem[1].u.string);

							if (abort_on_assert) {
								abort();
							} else {
								set_err_info(OSER_EC_ASSERT, OSER_EL_CRITIC, "assertion failed");
								set_err_reply(500, "server error");

								run_error_route(msg,0);
							}
						}
					}
				}
			break;
		case DROP_T:
				script_trace("core", "drop", msg, a->file, a->line) ;
				action_flags |= ACT_FL_DROP|ACT_FL_EXIT;
			break;
		case EXIT_T:
				script_trace("core", "exit", msg, a->file, a->line) ;
				ret=0;
				action_flags |= ACT_FL_EXIT;
			break;
		case RETURN_T:
				script_trace("core", "return", msg, a->file, a->line) ;
				if (a->elem[0].type == SCRIPTVAR_ST)
				{
					spec = (pv_spec_t*)a->elem[0].u.data;
					if(pv_get_spec_value(msg, spec, &val)!=0
						|| (val.flags&PV_VAL_NULL))
					{
						ret=-1;
					} else {
						if(!(val.flags&PV_VAL_INT))
							ret = 1;
						else
							ret = val.ri;
					}
					pv_value_destroy(&val);
				} else {
					ret=a->elem[0].u.number;
				}
				action_flags |= ACT_FL_RETURN;
			break;
		case FORWARD_T:
			script_trace("core", "forward", msg, a->file, a->line) ;
			if (a->elem[0].type==NOSUBTYPE){
				/* parse uri and build a proxy */
				if (msg->dst_uri.len) {
					ret = parse_uri(msg->dst_uri.s, msg->dst_uri.len,
						&next_hop);
					u = &next_hop;
				} else {
					ret = parse_sip_msg_uri(msg);
					u = &msg->parsed_uri;
				}
				if (ret<0) {
					LM_ERR("forward: bad_uri dropping packet\n");
					break;
				}
				/* create a temporary proxy*/
				p=mk_proxy(u->maddr_val.len?&u->maddr_val:&u->host,
					u->port_no, u->proto, (u->type==SIPS_URI_T)?1:0 );
				if (p==0){
					LM_ERR("bad host name in uri, dropping packet\n");
					ret=E_BAD_ADDRESS;
					goto error_fwd_uri;
				}
				ret=forward_request(msg, p);
				free_proxy(p); /* frees only p content, not p itself */
				pkg_free(p);
				if (ret==0) ret=1;
			}else if (a->elem[0].type==PROXY_ST) {
				if (0==(p=clone_proxy((struct proxy_l*)a->elem[0].u.data))) {
					LM_ERR("failed to clone proxy, dropping packet\n");
					ret=E_OUT_OF_MEM;
					goto error_fwd_uri;
				}
				ret=forward_request(msg, p);
				free_proxy(p); /* frees only p content, not p itself */
				pkg_free(p);
				if (ret==0) ret=1;
			}else{
				LM_ALERT("BUG in forward() types %d, %d\n",
						a->elem[0].type, a->elem[1].type);
				ret=E_BUG;
			}
			break;
		case SEND_T:
			script_trace("core", "send", msg, a->file, a->line) ;
			if (a->elem[0].type!= PROXY_ST){
				LM_ALERT("BUG in send() type %d\n", a->elem[0].type);
				ret=E_BUG;
				break;
			}
			if (a->elem[1].u.data) {
				if (a->elem[1].type != SCRIPTVAR_ELEM_ST){
					LM_ALERT("BUG in send() header type %d\n",a->elem[1].type);
					ret=E_BUG;
					break;
				} else {
					pve = (pv_elem_t *)a->elem[1].u.data;
				}
			} else {
				pve = NULL;
			}
			to=(union sockaddr_union*)
					pkg_malloc(sizeof(union sockaddr_union));
			if (to==0){
				LM_ERR("memory allocation failure\n");
				ret=E_OUT_OF_MEM;
				break;
			}
			if (0==(p=clone_proxy((struct proxy_l*)a->elem[0].u.data))) {
				LM_ERR("failed to clone proxy, dropping packet\n");
				ret=E_OUT_OF_MEM;
				break;
			}
			ret=hostent2su(to, &p->host, p->addr_idx,
						(p->port)?p->port:SIP_PORT );
			if (ret==0){
				if (pve) {
					if ( pv_printf_s(msg, pve, &name_s)!=0 ||
							name_s.len == 0 || name_s.s == NULL) {
						LM_WARN("cannot get string for value (%s:%d)\n",
							a->file,a->line);
						ret=E_UNSPEC;
						break;
					}
					/* build new msg */
					tmp = pkg_malloc(msg->len + name_s.len);
					if (!tmp) {
						LM_ERR("memory allocation failure\n");
						ret = E_OUT_OF_MEM;
						break;
					}
					LM_DBG("searching for first line %d\n",
							msg->first_line.len);
					/* search first line of previous msg */
					/* copy headers */
					len = msg->first_line.len;
					memcpy(tmp, msg->buf, len);
					memcpy(tmp + len, name_s.s, name_s.len);
					memcpy(tmp + len + name_s.len,
							msg->buf + len, msg->len - len);
					ret = msg_send(0/*send_sock*/, p->proto, to, 0/*id*/,
							tmp, msg->len + name_s.len, msg);
					pkg_free(tmp);
				} else {
					ret = msg_send(0/*send_sock*/, p->proto, to, 0/*id*/,
							msg->buf, msg->len, msg);
				}
				if (ret!=0 && p->host.h_addr_list[p->addr_idx+1])
					p->addr_idx++;
			}
			free_proxy(p); /* frees only p content, not p itself */
			pkg_free(p);
			pkg_free(to);
			if (ret==0)
				ret=1;
			break;
		case LOG_T:
			script_trace("core", "log", msg, a->file, a->line) ;
			if ((a->elem[0].type!=NUMBER_ST)|(a->elem[1].type!=STRING_ST)){
				LM_ALERT("BUG in log() types %d, %d\n",
						a->elem[0].type, a->elem[1].type);
				ret=E_BUG;
				break;
			}
			LM_GEN1(a->elem[0].u.number, "%s", a->elem[1].u.string);
			ret=1;
			break;
		case APPEND_BRANCH_T:
			script_trace("core", "append_branch", msg, a->file, a->line) ;
			if ((a->elem[0].type!=STR_ST)) {
				LM_ALERT("BUG in append_branch %d\n",
					a->elem[0].type );
				ret=E_BUG;
				break;
			}
			if (a->elem[0].u.s.s==NULL) {
				ret = append_branch(msg, 0, &msg->dst_uri, &msg->path_vec,
					get_ruri_q(msg), getb0flags(msg), msg->force_send_socket);
				/* reset all branch info */
				msg->force_send_socket = 0;
				setb0flags(msg,0);
				set_ruri_q(msg,Q_UNSPECIFIED);
				if(msg->dst_uri.s!=0)
					pkg_free(msg->dst_uri.s);
				msg->dst_uri.s = 0;
				msg->dst_uri.len = 0;
				if(msg->path_vec.s!=0)
					pkg_free(msg->path_vec.s);
				msg->path_vec.s = 0;
				msg->path_vec.len = 0;
			} else {
				ret = append_branch(msg, &a->elem[0].u.s, &msg->dst_uri,
					&msg->path_vec, a->elem[1].u.number, getb0flags(msg),
					msg->force_send_socket);
			}
			break;
		case REMOVE_BRANCH_T:
			script_trace("core", "remove_branch", msg, a->file, a->line) ;
			if (a->elem[0].type == SCRIPTVAR_ST) {
				spec = (pv_spec_t*)a->elem[0].u.data;
				if( pv_get_spec_value(msg, spec, &val)!=0
				|| (val.flags&PV_VAL_NULL) || !(val.flags&PV_VAL_INT) ) {
					ret=-1;
					break;
				}
				i = val.ri;
			} else {
				i=a->elem[0].u.number;
			}
			ret = (remove_branch((unsigned int)i)==0)?1:-1;
			break;
		case LEN_GT_T:
			script_trace("core", "len_gt", msg, a->file, a->line) ;
			if (a->elem[0].type!=NUMBER_ST) {
				LM_ALERT("BUG in len_gt type %d\n",
					a->elem[0].type );
				ret=E_BUG;
				break;
			}
			ret = (msg->len >= (unsigned int)a->elem[0].u.number) ? 1 : -1;
			break;
		case SETFLAG_T:
			script_trace("core", "setflag", msg, a->file, a->line) ;
			ret = setflag( msg, a->elem[0].u.number );
			break;
		case RESETFLAG_T:
			script_trace("core", "resetflag", msg, a->file, a->line) ;
			ret = resetflag( msg, a->elem[0].u.number );
			break;
		case ISFLAGSET_T:
			script_trace("core", "isflagset", msg, a->file, a->line) ;
			ret = isflagset( msg, a->elem[0].u.number );
			break;
		case SETBFLAG_T:
			script_trace("core", "setbflag", msg, a->file, a->line) ;
			ret = setbflag( msg, a->elem[0].u.number, a->elem[1].u.number );
			break;
		case RESETBFLAG_T:
			script_trace("core", "resetbflag", msg, a->file, a->line) ;
			ret = resetbflag( msg, a->elem[0].u.number, a->elem[1].u.number  );
			break;
		case ISBFLAGSET_T:
			script_trace("core", "isbflagset", msg, a->file, a->line) ;
			ret = isbflagset( msg, a->elem[0].u.number, a->elem[1].u.number  );
			break;
		case ERROR_T:
			script_trace("core", "error", msg, a->file, a->line) ;
			if ((a->elem[0].type!=STRING_ST)|(a->elem[1].type!=STRING_ST)){
				LM_ALERT("BUG in error() types %d, %d\n",
						a->elem[0].type, a->elem[1].type);
				ret=E_BUG;
				break;
			}
			LM_ERR("error(\"%s\", \"%s\") not implemented yet\n",
				a->elem[0].u.string, a->elem[1].u.string);
			ret=1;
			break;
		case ROUTE_T:
			script_trace("route", rlist[a->elem[0].u.number].name, msg, a->file, a->line) ;
			if (a->elem[0].type!=NUMBER_ST){
				LM_ALERT("BUG in route() type %d\n",
						a->elem[0].type);
				ret=E_BUG;
				break;
			}
			if ((a->elem[0].u.number>RT_NO)||(a->elem[0].u.number<0)){
				LM_ALERT("BUG - invalid routing table number in"
							"route(%lu)\n", a->elem[0].u.number);
				ret=E_CFG;
				break;
			}
			/* check if the route has parameters */
			if (a->elem[1].type != 0) {
				if (a->elem[1].type != NUMBER_ST || a->elem[2].type != SCRIPTVAR_ELEM_ST) {
					LM_ALERT("BUG in route() type %d/%d\n",
							a->elem[1].type, a->elem[2].type);
					ret=E_BUG;
					break;
				}
				route_rec_level++;
				route_params[route_rec_level] = (action_elem_t *)a->elem[2].u.data;
				route_params_number[route_rec_level] = a->elem[1].u.number;
				return_code=run_actions(rlist[a->elem[0].u.number].a, msg);

				route_rec_level--;
			} else {
				route_rec_level++;
				route_params[route_rec_level] = NULL;
				route_params_number[route_rec_level] = 0;
				return_code=run_actions(rlist[a->elem[0].u.number].a, msg);
				route_rec_level--;
			}
			ret=return_code;
			break;
		case REVERT_URI_T:
			script_trace("core", "revert_uri", msg, a->file, a->line) ;
			if (msg->new_uri.s) {
				pkg_free(msg->new_uri.s);
				msg->new_uri.len=0;
				msg->new_uri.s=0;
				msg->parsed_uri_ok=0; /* invalidate current parsed uri*/
			};
			ret=1;
			break;
		case SET_HOST_T:
		case SET_HOSTPORT_T:
		case SET_USER_T:
		case SET_USERPASS_T:
		case SET_PORT_T:
		case SET_URI_T:
		case PREFIX_T:
		case STRIP_T:
		case STRIP_TAIL_T:
				script_trace("core",
					(unsigned char)a->type == SET_HOST_T     ? "set_host" :
					(unsigned char)a->type == SET_HOSTPORT_T ? "set_hostport" :
					(unsigned char)a->type == SET_USER_T     ? "set_user" :
					(unsigned char)a->type == SET_USERPASS_T ? "set_userpass" :
					(unsigned char)a->type == SET_PORT_T     ? "set_port" :
					(unsigned char)a->type == SET_URI_T      ? "set_uri" :
					(unsigned char)a->type == PREFIX_T       ? "prefix" :
					(unsigned char)a->type == STRIP_T  ? "strip" : "strip_tail",
					msg, a->file, a->line);
				user=0;
				if (a->type==STRIP_T || a->type==STRIP_TAIL_T) {
					if (a->elem[0].type!=NUMBER_ST) {
						LM_ALERT("BUG in set*() type %d\n",
							a->elem[0].type);
						break;
					}
				} else if (a->elem[0].type!=STR_ST){
					LM_ALERT("BUG in set*() type %d\n",
							a->elem[0].type);
					ret=E_BUG;
					break;
				}
				if (a->type==SET_URI_T) {
					if (set_ruri( msg, &a->elem[0].u.s) ) {
						LM_ERR("failed to set new RURI\n");
						ret=E_OUT_OF_MEM;
						break;
					}
					ret=1;
					break;
				}
				if (msg->new_uri.s) {
					tmp=msg->new_uri.s;
					len=msg->new_uri.len;
				}else{
					tmp=msg->first_line.u.request.uri.s;
					len=msg->first_line.u.request.uri.len;
				}
				if (parse_uri(tmp, len, &uri)<0){
					LM_ERR("bad uri <%.*s>, dropping packet\n", len, tmp);
					ret=E_UNSPEC;
					break;
				}

				new_uri=pkg_malloc(MAX_URI_SIZE);
				if (new_uri==0){
					LM_ERR("memory allocation failure\n");
					ret=E_OUT_OF_MEM;
					break;
				}
				end=new_uri+MAX_URI_SIZE;
				crt=new_uri;
				/* begin copying */
				len = (uri.user.len?uri.user.s:uri.host.s) - tmp;
				if (crt+len>end) goto error_uri;
				memcpy(crt,tmp,len);crt+=len;

				if (a->type==PREFIX_T) {
					if (crt+a->elem[0].u.s.len>end) goto error_uri;
					memcpy( crt, a->elem[0].u.s.s, a->elem[0].u.s.len);
					crt+=a->elem[0].u.s.len;
					/* whatever we had before, with prefix we have username
					   now */
					user=1;
				}

				if ((a->type==SET_USER_T)||(a->type==SET_USERPASS_T)) {
					tmp=a->elem[0].u.s.s;
					len=a->elem[0].u.s.len;
				} else if (a->type==STRIP_T) {
					if (a->elem[0].u.number>uri.user.len) {
						LM_WARN("too long strip asked; "
								" deleting username: %lu of <%.*s>\n",
								a->elem[0].u.number, uri.user.len, uri.user.s);
						len=0;
					} else if (a->elem[0].u.number==uri.user.len) {
						len=0;
					} else {
						tmp=uri.user.s + a->elem[0].u.number;
						len=uri.user.len - a->elem[0].u.number;
					}
				} else if (a->type==STRIP_TAIL_T) {
					if (a->elem[0].u.number>uri.user.len) {
						LM_WARN("too long strip_tail asked;"
								" deleting username: %lu of <%.*s>\n",
								a->elem[0].u.number, uri.user.len, uri.user.s);
						len=0;
					} else if (a->elem[0].u.number==uri.user.len) {
						len=0;
					} else {
						tmp=uri.user.s;
						len=uri.user.len - a->elem[0].u.number;
					}
				} else {
					tmp=uri.user.s;
					len=uri.user.len;
				}

				if (len){
					if(crt+len>end) goto error_uri;
					memcpy(crt,tmp,len);crt+=len;
					user=1; /* we have an user field so mark it */
				}

				if (a->type==SET_USERPASS_T) tmp=0;
				else tmp=uri.passwd.s;
				/* passwd */
				if (tmp){
					len=uri.passwd.len; if(crt+len+1>end) goto error_uri;
					*crt=':'; crt++;
					memcpy(crt,tmp,len);crt+=len;
				}
				/* host */
				if (user || tmp){ /* add @ */
					if(crt+1>end) goto error_uri;
					*crt='@'; crt++;
				}
				if ((a->type==SET_HOST_T) ||(a->type==SET_HOSTPORT_T)) {
					tmp=a->elem[0].u.s.s;
					len=a->elem[0].u.s.len;
				} else {
					tmp=uri.host.s;
					len = uri.host.len;
				}
				if (tmp){
					if(crt+len>end) goto error_uri;
					memcpy(crt,tmp,len);crt+=len;
				}
				/* port */
				if (a->type==SET_HOSTPORT_T) tmp=0;
				else if (a->type==SET_PORT_T) {
					tmp=a->elem[0].u.s.s;
					len=a->elem[0].u.s.len;
				} else {
					tmp=uri.port.s;
					len = uri.port.len;
				}
				if (tmp && len>0){
					if(crt+len+1>end) goto error_uri;
					*crt=':'; crt++;
					memcpy(crt,tmp,len);crt+=len;
				}
				/* params */
				tmp=uri.params.s;
				if (tmp){
					/* include in param string the starting ';' */
					len=uri.params.len+1;
					tmp--;
					if(crt+len+1>end) goto error_uri;
					/* if a maddr param is present, strip it out */
					if (uri.maddr.len &&
					(a->type==SET_HOSTPORT_T || a->type==SET_HOST_T)) {
						memcpy(crt,tmp,uri.maddr.s-tmp-1);
						crt+=uri.maddr.s-tmp-1;
						memcpy(crt,uri.maddr_val.s+uri.maddr_val.len,
							tmp+len-uri.maddr_val.s-uri.maddr_val.len);
						crt+=tmp+len-uri.maddr_val.s-uri.maddr_val.len;
					} else {
						memcpy(crt,tmp,len);crt+=len;
					}
				}
				/* headers */
				tmp=uri.headers.s;
				if (tmp){
					len=uri.headers.len; if(crt+len+1>end) goto error_uri;
					*crt='?'; crt++;
					memcpy(crt,tmp,len);crt+=len;
				}
				*crt=0; /* null terminate the thing */
				/* copy it to the msg */
				if (msg->new_uri.s) pkg_free(msg->new_uri.s);
				msg->new_uri.s=new_uri;
				msg->new_uri.len=crt-new_uri;
				msg->parsed_uri_ok=0;
				ret=1;
				break;
		case SET_DSTURI_T:
			script_trace("core", "set_dsturi", msg, a->file, a->line) ;
			if (a->elem[0].type!=STR_ST){
				LM_ALERT("BUG in setdsturi() type %d\n",
							a->elem[0].type);
				ret=E_BUG;
				break;
			}
			if(set_dst_uri(msg, &a->elem[0].u.s)!=0)
				ret = -1;
			else
				ret = 1;
			break;
		case SET_DSTHOST_T:
		case SET_DSTPORT_T:
			script_trace("core", (unsigned char) a->type == SET_DSTHOST_T ?
					"set_dsturi" : "set_dstport", msg, a->file, a->line);
			if (a->elem[0].type!=STR_ST){
				LM_ALERT("BUG in domain setting type %d\n",
							a->elem[0].type);
				ret=E_BUG;
				break;
			}

			tmp = msg->dst_uri.s;
			len = msg->dst_uri.len;

			if (tmp == NULL || len == 0) {
				LM_ERR("failure - null uri\n");
				ret = E_UNSPEC;
				break;
			}
			if (a->type == SET_DSTHOST_T &&
					(a->elem[0].u.s.s == NULL || a->elem[0].u.s.len == 0)) {
				LM_ERR("cannot set a null uri domain\n");
				break;
			}
			if (parse_uri(tmp, len, &uri)<0) {
				LM_ERR("bad uri <%.*s>, dropping packet\n", len, tmp);
				break;
			}
			new_uri=pkg_malloc(MAX_URI_SIZE);
			if (new_uri == NULL) {
				LM_ERR("memory allocation failure\n");
				ret=E_OUT_OF_MEM;
				break;
			}
			end=new_uri+MAX_URI_SIZE;
			crt=new_uri;
			len = (uri.user.len?uri.user.s:uri.host.s) - tmp;
			if (crt+len>end) goto error_uri;
			memcpy(crt,tmp,len);
			crt += len;
			/* user */
			tmp = uri.user.s;
			len = uri.user.len;
			if (tmp) {
				if (crt+len>end) goto error_uri;
				memcpy(crt,tmp,len);
				crt += len;
				user = 1;
			}
			/* passwd */
			tmp = uri.passwd.s;
			len = uri.passwd.len;
			if (tmp) {
				if (crt+len+1>end) goto error_uri;
				*crt++=':';
				memcpy(crt, tmp, len);
				crt += len;
			}
			/* host */
			if (a->type==SET_DSTHOST_T) {
				tmp = a->elem[0].u.s.s;
				len = a->elem[0].u.s.len;
			} else {
				tmp = uri.host.s;
				len = uri.host.len;
			}
			if (tmp) {
				if (user) {
					if (crt+1>end) goto error_uri;
					*crt++='@';
				}
				if (crt+len+1>end) goto error_uri;
				memcpy(crt, tmp, len);
				crt += len;
			}
			/* port */
			if (a->type==SET_DSTPORT_T) {
				tmp = a->elem[0].u.s.s;
				len = a->elem[0].u.s.len;
			} else {
				tmp = uri.port.s;
				len = uri.port.len;
			}
			if (tmp) {
				if (crt+len+1>end) goto error_uri;
				*crt++=':';
				memcpy(crt, tmp, len);
				crt += len;
			}
			/* params */
			tmp=uri.params.s;
			if (tmp){
				len=uri.params.len; if(crt+len+1>end) goto error_uri;
				*crt++=';';
				memcpy(crt,tmp,len);
				crt += len;
			}
			/* headers */
			tmp=uri.headers.s;
			if (tmp){
				len=uri.headers.len; if(crt+len+1>end) goto error_uri;
				*crt++='?';
				memcpy(crt,tmp,len);
				crt += len;
			}
			*crt=0; /* null terminate the thing */
			/* copy it to the msg */
			pkg_free(msg->dst_uri.s);
			msg->dst_uri.s=new_uri;
			msg->dst_uri.len=crt-new_uri;
			ret = 1;
			break;
		case RESET_DSTURI_T:
			script_trace("core", "reset_dsturi", msg, a->file, a->line) ;
			if(msg->dst_uri.s!=0)
				pkg_free(msg->dst_uri.s);
			msg->dst_uri.s = 0;
			msg->dst_uri.len = 0;
			ret = 1;
			break;
		case ISDSTURISET_T:
			script_trace("core", "isdsturiset", msg, a->file, a->line) ;
			if(msg->dst_uri.s==0 || msg->dst_uri.len<=0)
				ret = -1;
			else
				ret = 1;
			break;
		case IF_T:
			script_trace("core", "if", msg, a->file, a->line) ;
				/* if null expr => ignore if? */
				if ((a->elem[0].type==EXPR_ST)&&a->elem[0].u.data){
					v=eval_expr((struct expr*)a->elem[0].u.data, msg, 0);
					/* set return code to expr value */
					if (v<0 || (action_flags&ACT_FL_RETURN)
							|| (action_flags&ACT_FL_EXIT) ){
						if (v==EXPR_DROP || (action_flags&ACT_FL_RETURN)
								|| (action_flags&ACT_FL_EXIT) ){ /* hack to quit on DROP*/
							ret=0;
							return_code = 0;
							break;
						}else{
							LM_WARN("error in expression at %s:%d\n",
								a->file, a->line);
						}
					}

					ret=1;  /*default is continue */
					if (v>0) {
						if ((a->elem[1].type==ACTIONS_ST)&&a->elem[1].u.data){
							ret=run_action_list(
									(struct action*)a->elem[1].u.data,msg );
							return_code = ret;
						} else return_code = v;
					}else{
						if ((a->elem[2].type==ACTIONS_ST)&&a->elem[2].u.data){
							ret=run_action_list(
								(struct action*)a->elem[2].u.data,msg);
							return_code = ret;
						} else return_code = v;
					}
				}
			break;
		case WHILE_T:
			script_trace("core", "while", msg, a->file, a->line) ;
				/* if null expr => ignore if? */
				if ((a->elem[0].type==EXPR_ST)&&a->elem[0].u.data){
					len = 0;
					while(1)
					{
						if(len++ >= max_while_loops)
						{
							LM_INFO("max while loops are encountered\n");
							break;
						}
						v=eval_expr((struct expr*)a->elem[0].u.data, msg, 0);
						/* set return code to expr value */
						if (v<0 || (action_flags&ACT_FL_RETURN)
								|| (action_flags&ACT_FL_EXIT) ){
							if (v==EXPR_DROP || (action_flags&ACT_FL_RETURN)
									|| (action_flags&ACT_FL_EXIT) ){
								ret=0;
								return_code = 0;
								break;
							}else{
								LM_WARN("error in expression at %s:%d\n",
										a->file, a->line);
							}
						}

						ret=1;  /*default is continue */
						if (v>0) {
							if ((a->elem[1].type==ACTIONS_ST)
									&&a->elem[1].u.data){
								ret=run_action_list(
									(struct action*)a->elem[1].u.data,msg );
								/* check if return was done */
								if ((action_flags&ACT_FL_RETURN)
								|| (action_flags&ACT_FL_EXIT) ){
									break;
								}
								return_code = ret;
							} else {
								/* we should not get here */
								return_code = v;
								break;
							}
						} else {
							/* condition was false */
							return_code = v;
							break;
						}
					}
				}
			break;
		case FOR_EACH_T:
			script_trace("core", "for-each", msg, a->file, a->line) ;
			ret = for_each_handler(msg, a);
			break;
		case CACHE_STORE_T:
			script_trace("core", "cache_store", msg, a->file, a->line) ;
			if ((a->elem[0].type!=STR_ST)) {
				LM_ALERT("BUG in cache_store() - first argument not of"
						" type string [%d]\n",
					a->elem[0].type );
				ret=E_BUG;
				break;
			}

			if ((a->elem[1].type!=STR_ST)) {
				LM_ALERT("BUG in cache_store()  - second argument not of "
						"type string [%d]\n", a->elem[1].type );
				ret=E_BUG;
				break;
			}

			if ((a->elem[2].type!=STR_ST)) {
				LM_ALERT("BUG in cache_store() - third argument not of type"
						" string%d\n", a->elem[2].type );
				ret=E_BUG;
				break;
			}

			str val_s;

			/* parse the name argument */
			pve = (pv_elem_t *)a->elem[1].u.data;
			if ( pv_printf_s(msg, pve, &name_s)!=0 ||
			name_s.len == 0 || name_s.s == NULL) {
				LM_WARN("cannot get string for value\n");
				ret=E_BUG;
				break;
			}

			/* parse the value argument */
			pve = (pv_elem_t *)a->elem[2].u.data;
			if ( pv_printf_s(msg, pve, &val_s)!=0 ||
			val_s.len == 0 || val_s.s == NULL) {
				LM_WARN("cannot get string for value\n");
				ret=E_BUG;
				break;
			}

			/* get the expires value */
			if ( a->elem[3].type == SCRIPTVAR_ST )
			{
				spec = (pv_spec_t*)a->elem[3].u.data;
				memset(&val, 0, sizeof(pv_value_t));
				if(pv_get_spec_value(msg, spec, &val) < 0)
				{
					LM_DBG("Failed to get scriptvar value while executing cache_store\n");
					ret=E_BUG;
					break;
				}
				if (!(val.flags&PV_VAL_INT))
				{
					LM_ERR("Wrong value for cache_store expires, not an integer [%.*s]\n",
							val.rs.len, val.rs.s);
				}
				expires = val.ri;
			}
			else
			if ( a->elem[3].type == NUMBER_ST )
			{
				expires = (int)a->elem[3].u.number;
			}

			ret = cachedb_store( &a->elem[0].u.s, &name_s, &val_s,expires);

			break;
		case CACHE_REMOVE_T:
			script_trace("core", "cache_remove", msg, a->file, a->line) ;
			if ((a->elem[0].type!=STR_ST)) {
				LM_ALERT("BUG in cache_remove() %d\n",
					a->elem[0].type );
				ret=E_BUG;
				break;
			}
			if ((a->elem[1].type!=STR_ST)) {
				LM_ALERT("BUG in cache_remove() %d\n",
					a->elem[1].type );
				ret=E_BUG;
				break;
			}
			/* parse the name argument */
			pve = (pv_elem_t *)a->elem[1].u.data;
			if ( pv_printf_s(msg, pve, &name_s)!=0 ||
			name_s.len == 0 || name_s.s == NULL) {
				LM_WARN("cannot get string for value\n");
				ret=E_BUG;
				break;
			}
			ret = cachedb_remove( &a->elem[0].u.s, &name_s);
			break;
		case CACHE_FETCH_T:
			script_trace("core", "cache_fetch", msg, a->file, a->line) ;
			if ((a->elem[0].type!=STR_ST)) {
				LM_ALERT("BUG in cache_fetch() %d\n",
					a->elem[0].type );
				ret=E_BUG;
				break;
			}
			if ((a->elem[1].type!=STR_ST)) {
				LM_ALERT("BUG in cache_fetch() %d\n",
					a->elem[1].type );
				ret=E_BUG;
				break;
			}
			if (a->elem[2].type!=SCRIPTVAR_ST){
				LM_ALERT("BUG in cache_fetch() type %d\n",
						a->elem[2].type);
				ret=E_BUG;
				break;
			}
			str aux = {0, 0};
			/* parse the name argument */
			pve = (pv_elem_t *)a->elem[1].u.data;
			if ( pv_printf_s(msg, pve, &name_s)!=0 ||
			name_s.len == 0 || name_s.s == NULL) {
				LM_WARN("cannot get string for value\n");
				ret=E_BUG;
				break;
			}

			ret = cachedb_fetch( &a->elem[0].u.s, &name_s, &aux);
			if(ret > 0)
			{
				val.rs = aux;
				val.flags = PV_VAL_STR;

				spec = (pv_spec_t*)a->elem[2].u.data;
				if (pv_set_value(msg, spec, 0, &val) < 0) {
					LM_ERR("cannot set the variable value\n");
					pkg_free(aux.s);
					return -1;
				}
				pkg_free(aux.s);
			}

			break;
		case CACHE_COUNTER_FETCH_T:
			script_trace("core", "cache_counter_fetch", msg, a->file, a->line) ;
			if ((a->elem[0].type!=STR_ST)) {
				LM_ALERT("BUG in cache_fetch() %d\n",
					a->elem[0].type );
				ret=E_BUG;
				break;
			}
			if ((a->elem[1].type!=STR_ST)) {
				LM_ALERT("BUG in cache_fetch() %d\n",
					a->elem[1].type );
				ret=E_BUG;
				break;
			}
			if (a->elem[2].type!=SCRIPTVAR_ST){
				LM_ALERT("BUG in cache_fetch() type %d\n",
						a->elem[2].type);
				ret=E_BUG;
				break;
			}

			/* parse the name argument */
			pve = (pv_elem_t *)a->elem[1].u.data;
			if ( pv_printf_s(msg, pve, &name_s)!=0 ||
			name_s.len == 0 || name_s.s == NULL) {
				LM_WARN("cannot get string for value\n");
				ret=E_BUG;
				break;
			}

			ret = cachedb_counter_fetch( &a->elem[0].u.s, &name_s, &aux_counter);
			if(ret > 0)
			{
				val.ri = aux_counter;
				val.flags = PV_TYPE_INT|PV_VAL_INT;

				spec = (pv_spec_t*)a->elem[2].u.data;
				if (pv_set_value(msg, spec, 0, &val) < 0) {
					LM_ERR("cannot set the variable value\n");
					pkg_free(aux.s);
					return -1;
				}
			}
			break;
		case CACHE_ADD_T:
			script_trace("core", "cache_add", msg, a->file, a->line) ;
			if ((a->elem[0].type!=STR_ST)) {
				LM_ALERT("BUG in cache_add() - first argument not of"
						" type string [%d]\n",
					a->elem[0].type );
				ret=E_BUG;
				break;
			}

			if ((a->elem[1].type!=STR_ST)) {
				LM_ALERT("BUG in cache_add()  - second argument not of "
						"type string [%d]\n", a->elem[1].type );
				ret=E_BUG;
				break;
			}

			/* parse the name argument */
			pve = (pv_elem_t *)a->elem[1].u.data;
			if ( pv_printf_s(msg, pve, &name_s)!=0 ||
			name_s.len == 0 || name_s.s == NULL) {
				LM_WARN("cannot get string for value\n");
				ret=E_BUG;
				break;
			}

			int increment=0;

			/* get the increment value */
			if ( a->elem[2].type == SCRIPTVAR_ST )
			{
				spec = (pv_spec_t*)a->elem[2].u.data;
				memset(&val, 0, sizeof(pv_value_t));
				if(pv_get_spec_value(msg, spec, &val) < 0)
				{
					LM_DBG("Failed to get scriptvar value while executing cache_add\n");
					ret=E_BUG;
					break;
				}
				if (!(val.flags&PV_VAL_INT))
				{
					LM_ERR("Wrong value for cache_add, not an integer [%.*s]\n",
							val.rs.len, val.rs.s);
				}
				increment = val.ri;
			}
			else if ( a->elem[2].type == NUMBER_ST )
			{
				increment = (int)a->elem[2].u.number;
			}

			expires = (int)a->elem[3].u.number;

			ret = cachedb_add(&a->elem[0].u.s, &name_s, increment, expires, &aux_counter);

			/* Return the new value */
			if (ret > 0 && a->elem[4].u.data != NULL) {
				val.ri = aux_counter;
				val.flags = PV_TYPE_INT|PV_VAL_INT;

				spec = (pv_spec_t*)a->elem[4].u.data;
				if (pv_set_value(msg, spec, 0, &val) < 0) {
					LM_ERR("cannot set the variable value\n");
					return -1;
				}
			}

			break;
		case CACHE_SUB_T:
			script_trace("core", "cache_sub", msg, a->file, a->line) ;
			if ((a->elem[0].type!=STR_ST)) {
				LM_ALERT("BUG in cache_sub() - first argument not of"
						" type string [%d]\n",
					a->elem[0].type );
				ret=E_BUG;
				break;
			}

			if ((a->elem[1].type!=STR_ST)) {
				LM_ALERT("BUG in cache_sub()  - second argument not of "
						"type string [%d]\n", a->elem[1].type );
				ret=E_BUG;
				break;
			}

			/* parse the name argument */
			pve = (pv_elem_t *)a->elem[1].u.data;
			if ( pv_printf_s(msg, pve, &name_s)!=0 ||
			name_s.len == 0 || name_s.s == NULL) {
				LM_WARN("cannot get string for value\n");
				ret=E_BUG;
				break;
			}

			int decrement=0;

			/* get the increment value */
			if ( a->elem[2].type == SCRIPTVAR_ST )
			{
				spec = (pv_spec_t*)a->elem[2].u.data;
				memset(&val, 0, sizeof(pv_value_t));
				if(pv_get_spec_value(msg, spec, &val) < 0)
				{
					LM_DBG("Failed to get scriptvar value while executing cache_sub\n");
					ret=E_BUG;
					break;
				}
				if (!(val.flags&PV_VAL_INT))
				{
					LM_ERR("Wrong value for cache_sub, not an integer [%.*s]\n",
							val.rs.len, val.rs.s);
				}
				decrement = val.ri;
			}
			else if ( a->elem[2].type == NUMBER_ST )
			{
				decrement = (int)a->elem[2].u.number;
			}

			expires = (int)a->elem[3].u.number;

			ret = cachedb_sub(&a->elem[0].u.s, &name_s, decrement,expires,&aux_counter);

			/* Return the new value */
			if (ret > 0 && a->elem[4].u.data != NULL) {
				val.ri = aux_counter;
				val.flags = PV_TYPE_INT|PV_VAL_INT;

				spec = (pv_spec_t*)a->elem[4].u.data;
				if (pv_set_value(msg, spec, 0, &val) < 0) {
					LM_ERR("cannot set the variable value\n");
					return -1;
				}
			}

			break;
		case CACHE_RAW_QUERY_T:
			if ((a->elem[0].type!=STR_ST)) {
				LM_ALERT("BUG in cache_fetch() %d\n",
					a->elem[0].type );
				ret=E_BUG;
				break;
			}
			if ((a->elem[1].type!=STR_ST)) {
				LM_ALERT("BUG in cache_fetch() %d\n",
					a->elem[1].type );
				ret=E_BUG;
				break;
			}
			if (a->elem[2].u.data != NULL &&
				a->elem[2].type!=STR_ST){
				LM_ALERT("BUG in cache_raw_query() type %d\n",
						a->elem[2].type);
				ret=E_BUG;
				break;
			}
			/* parse the name argument */
			pve = (pv_elem_t *)a->elem[1].u.data;
			if ( pv_printf_s(msg, pve, &name_s)!=0 ||
			name_s.len == 0 || name_s.s == NULL) {
				LM_WARN("cannot get string for value\n");
				ret=E_BUG;
				break;
			}

			cdb_raw_entry **cdb_reply;
			int val_number=0,i,j;
			int key_number=0;
			pvname_list_t *cdb_res,*it;
			int_str avp_val;
			int_str avp_name;
			unsigned short avp_type;

			if (a->elem[2].u.data) {
				cdb_res = (pvname_list_t*)a->elem[2].u.data;
				for (it=cdb_res;it;it=it->next)
					val_number++;

				LM_DBG("The query expects %d results back\n",val_number);

				ret = cachedb_raw_query( &a->elem[0].u.s, &name_s, &cdb_reply,val_number,&key_number);
				if (ret >= 0 && val_number > 0) {
					for (i=key_number-1; i>=0;i--) {
						it=cdb_res;
						for (j=0;j < val_number;j++) {
							avp_type = 0;
							if (pv_get_avp_name(msg,&it->sname.pvp,&avp_name.n,
								&avp_type) != 0) {
								LM_ERR("cannot get avp name [%d/%d]\n",i,j);
								goto next_avp;
							}

							switch (cdb_reply[i][j].type) {
								case CDB_INT:
									avp_val.n = cdb_reply[i][j].val.n;
									break;
								case CDB_STR:
									avp_type |= AVP_VAL_STR;
									avp_val.s = cdb_reply[i][j].val.s;
									break;
								case CDB_NULL:
									avp_type |= AVP_VAL_NULL;
									avp_val.s = cdb_reply[i][j].val.s;
									break;
								default:
									LM_WARN("Unknown type %d\n",cdb_reply[i][j].type);
									goto next_avp;
							}
							if (add_avp(avp_type,avp_name.n,avp_val) != 0) {
								LM_ERR("Unable to add AVP\n");
								free_raw_fetch(cdb_reply,val_number,key_number);
								return -1;
							}
next_avp:
							if (it) {
								it = it->next;
								if (it==NULL)
									break;
							}
						}
					}
					free_raw_fetch(cdb_reply,val_number,key_number);
				}
			}
			else
				ret = cachedb_raw_query( &a->elem[0].u.s, &name_s, NULL,0,NULL);
			break;
		case XDBG_T:
			script_trace("core", "xdbg", msg, a->file, a->line) ;
			if (a->elem[0].type == SCRIPTVAR_ELEM_ST)
			{
				if (xdbg(msg, a->elem[0].u.data, val.rs.s) < 0)
				{
					LM_ALERT("Cannot print message\n");
					break;
				}
			}
			else
			{
				LM_ALERT("BUG in xdbg() type %d\n", a->elem[0].type);
				ret=E_BUG;
			}
			break;
		case XLOG_T:
			script_trace("core", "xlog", msg, a->file, a->line) ;
			if (a->elem[1].u.data != NULL)
			{
				if (a->elem[1].type != SCRIPTVAR_ELEM_ST)
				{
					LM_ALERT("BUG in xlog() type %d\n", a->elem[1].type);
					ret=E_BUG;
					break;
				}
				if (a->elem[0].type != STR_ST)
				{
					LM_ALERT("BUG in xlog() type %d\n", a->elem[0].type);
					ret=E_BUG;
					break;
				}
				if (xlog_2(msg,a->elem[0].u.data, a->elem[1].u.data) < 0)
				{
					LM_ALERT("Cannot print xlog debug message\n");
					break;
				}
			}
			else
			{
				if (a->elem[0].type != SCRIPTVAR_ELEM_ST)
				{
					LM_ALERT("BUG in xlog() type %d\n", a->elem[0].type);
					ret=E_BUG;
					break;
				}
				if (xlog_1(msg,a->elem[0].u.data, val.rs.s) < 0)
				{
					LM_ALERT("Cannot print xlog debug message\n");
					break;
				}
			}

			break;
		case RAISE_EVENT_T:
			script_trace("core", "raise_event", msg, a->file, a->line) ;
			if (a->elem[0].type != NUMBER_ST) {
				LM_ERR("invalid event id\n");
				ret=E_BUG;
				break;
			}
			if (a->elem[2].u.data) {
				/* three parameters specified */
				ret = evi_raise_script_event(msg, (event_id_t)a->elem[0].u.number,
						a->elem[1].u.data, a->elem[2].u.data);
			} else {
				/* two parameters specified */
				ret = evi_raise_script_event(msg, (event_id_t)a->elem[0].u.number,
						NULL, a->elem[1].u.data);
			}
			if (ret <= 0) {
				LM_ERR("cannot raise event\n");
				ret=E_UNSPEC;
				break;
			}
			break;
		case SUBSCRIBE_EVENT_T:
			script_trace("core", "subscribe_event", msg, a->file, a->line) ;
			if (a->elem[0].type != STR_ST || a->elem[1].type != STR_ST) {
				LM_ERR("BUG in subscribe arguments\n");
				ret=E_BUG;
				break;
			}
			if (a->elem[2].u.data) {
				if (a->elem[2].type != NUMBER_ST) {
					LM_ERR("BUG in subscribe expiration time\n");
					ret=E_BUG;
					break;
				} else {
					i = a->elem[2].u.number;
				}
			} else {
				i = 0;
			}

			name_s.s = a->elem[0].u.data;
			name_s.len = strlen(name_s.s);
			/* result should be the socket */
			result.s = a->elem[1].u.data;
			result.len = strlen(result.s);
			ret = evi_event_subscribe(name_s, result, i, 0);
			break;

		case CONSTRUCT_URI_T:
			script_trace("core", "construct_uri", msg, a->file, a->line) ;
			for (i=0;i<5;i++)
			{
				pve = (pv_elem_t *)a->elem[i].u.data;
				if (pve->spec.getf)
				{
					if ( pv_printf_s(msg, pve, &vals[i])!=0 ||
						vals[i].len == 0 || vals[i].s == NULL)
					{
						LM_WARN("cannot get string for value\n");
						ret=E_BUG;
						return -1;
					}
				}
				else
					vals[i] = pve->text;
			}

			result.s = construct_uri(&vals[0],&vals[1],&vals[2],&vals[3],&vals[4],
					&result.len);

			if (result.s)
			{
				int_str res;
				int avp_name;
				unsigned short avp_type;

				spec = (pv_spec_t*)a->elem[5].u.data;
				if (pv_get_avp_name( msg, &(spec->pvp), &avp_name,
						&avp_type)!=0){
					LM_CRIT("BUG in getting AVP name\n");
					return -1;
				}

				res.s = result;
				if (add_avp(AVP_VAL_STR|avp_type, avp_name, res)<0){
					LM_ERR("cannot add AVP\n");
					return -1;
				}
			}

			break;
		case GET_TIMESTAMP_T:
			script_trace("core", "get_timestamp", msg, a->file, a->line) ;
			if (get_timestamp(&sec,&usec) == 0) {
				int avp_name;
				int_str res;
				unsigned short avp_type;

				spec = (pv_spec_t*)a->elem[0].u.data;
				if (pv_get_avp_name(msg, &(spec->pvp), &avp_name,
						&avp_type) != 0) {
					LM_CRIT("BUG in getting AVP name\n");
					return -1;
				}

				res.n = sec;
				if (add_avp(avp_type, avp_name, res) < 0) {
					LM_ERR("cannot add AVP\n");
					return -1;
				}

				spec = (pv_spec_t*)a->elem[1].u.data;
				if (pv_get_avp_name(msg, &(spec->pvp), &avp_name,
						&avp_type) != 0) {
					LM_CRIT("BUG in getting AVP name\n");
					return -1;
				}

				res.n = usec;
				if (add_avp(avp_type, avp_name, res) < 0) {
					LM_ERR("cannot add AVP\n");
					return -1;
				}
			} else {
				LM_ERR("failed to get time\n");
				return -1;
			}
			break;
		case SWITCH_T:
			script_trace("core", "switch", msg, a->file, a->line) ;
			if (a->elem[0].type!=SCRIPTVAR_ST){
				LM_ALERT("BUG in switch() type %d\n",
						a->elem[0].type);
				ret=E_BUG;
				break;
			}
			spec = (pv_spec_t*)a->elem[0].u.data;
			if(pv_get_spec_value(msg, spec, &val)!=0)
			{
				LM_ALERT("BUG - no value in switch()\n");
				ret=E_BUG;
				break;
			}

			/* get the value of pvar */
			if(a->elem[1].type!=ACTIONS_ST) {
				LM_ALERT("BUG in switch() actions\n");
				ret=E_BUG;
				break;
			}
			return_code=1;
			adefault = NULL;
			aitem = (struct action*)a->elem[1].u.data;
			cmatch=0;
			while(aitem)
			{
				if((unsigned char)aitem->type==DEFAULT_T)
					adefault=aitem;
				if(cmatch==0)
				{
					if(aitem->elem[0].type==STR_ST)
					{
						if(val.flags&PV_VAL_STR
								&& val.rs.len==aitem->elem[0].u.s.len
								&& strncasecmp(val.rs.s, aitem->elem[0].u.s.s,
									val.rs.len)==0)
							cmatch = 1;
					} else { /* number */
						if(val.flags&PV_VAL_INT &&
								val.ri==aitem->elem[0].u.number)
							cmatch = 1;
					}
				}
				if(cmatch==1)
				{
					if(aitem->elem[1].u.data)
					{
						return_code=run_action_list(
							(struct action*)aitem->elem[1].u.data, msg);
						if ((action_flags&ACT_FL_RETURN) ||
						(action_flags&ACT_FL_EXIT))
							break;
					}
					if(aitem->elem[2].u.number==1)
						break;
				}
				aitem = aitem->next;
			}
			if((cmatch==0) && (adefault!=NULL))
			{
				LM_DBG("switch: running default statement\n");
				if(adefault->elem[0].u.data)
					return_code=run_action_list(
						(struct action*)adefault->elem[0].u.data, msg);
			}
			ret=return_code;
			break;
		case MODULE_T:
			script_trace("module", ((cmd_export_t*)(a->elem[0].u.data))->name,
				msg, a->file, a->line) ;
			if ( (a->elem[0].type==CMD_ST) && a->elem[0].u.data ) {
				ret=((cmd_export_t*)(a->elem[0].u.data))->function(msg,
						 (char*)a->elem[1].u.data, (char*)a->elem[2].u.data,
						 (char*)a->elem[3].u.data, (char*)a->elem[4].u.data,
						 (char*)a->elem[5].u.data, (char*)a->elem[6].u.data);
			}else{
				LM_ALERT("BUG in module call\n");
			}
			break;
		case ASYNC_T:
			/* first param - an ACTIONS_ST containing an ACMD_ST
			 * second param - a NUMBER_ST pointing to resume route */
			aitem = (struct action *)(a->elem[0].u.data);
			if (async_script_start_f==NULL || a->elem[0].type!=ACTIONS_ST ||
			a->elem[1].type!=NUMBER_ST || aitem->type!=AMODULE_T) {
				LM_ALERT("BUG in async expression\n");
			} else {
				script_trace("async",
					((acmd_export_t*)(aitem->elem[0].u.data))->name,
					msg, a->file, a->line) ;
				ret = async_script_start_f( msg, aitem, a->elem[1].u.number);
				if (ret>=0)
					action_flags |= ACT_FL_TBCONT;
			}
			ret = 0;
			break;
		case LAUNCH_T:
			/* first param - an ACTIONS_ST containing an ACMD_ST
			 * second param - an optional NUMBER_ST pointing to an end route */
			aitem = (struct action *)(a->elem[0].u.data);
			if (async_script_start_f==NULL || a->elem[0].type!=ACTIONS_ST ||
			a->elem[1].type!=NUMBER_ST || aitem->type!=AMODULE_T) {
				LM_ALERT("BUG in launch expression\n");
			} else {
				script_trace("launch",
					((acmd_export_t*)(aitem->elem[0].u.data))->name,
					msg, a->file, a->line) ;
				/* NOTE that the routeID (a->elem[1].u.number) is set to 
				 * -1 if no reporting route is set */
				ret = async_script_launch( msg, aitem, a->elem[1].u.number);
			}
			break;
		case FORCE_RPORT_T:
			script_trace("core", "force_rport", msg, a->file, a->line) ;
			msg->msg_flags|=FL_FORCE_RPORT;
			ret=1; /* continue processing */
			break;
		case FORCE_LOCAL_RPORT_T:
			script_trace("core", "force_local_rport", msg, a->file, a->line) ;
			msg->msg_flags|=FL_FORCE_LOCAL_RPORT;
			ret=1; /* continue processing */
			break;

		case SET_ADV_ADDR_T:
			script_trace("core", "set_adv_addr", msg, a->file, a->line);
			ret = do_action_set_adv_address(msg, a);
			break;

		case SET_ADV_PORT_T:
			script_trace("core", "set_adv_port", msg, a->file, a->line);
			ret = do_action_set_adv_port(msg, a);
			break;

		case FORCE_TCP_ALIAS_T:
			script_trace("core", "force_tcp_alias", msg, a->file, a->line) ;
			if (is_tcp_based_proto(msg->rcv.proto)) {
				if (a->elem[0].type==NOSUBTYPE)	port=msg->via1->port;
				else if (a->elem[0].type==NUMBER_ST)
					port=(int)a->elem[0].u.number;
				else{
					LM_ALERT("BUG in force_tcp_alias"
							" port type %d\n", a->elem[0].type);
					ret=E_BUG;
					break;
				}

				if (tcpconn_add_alias(msg->rcv.proto_reserved1, port,
									msg->rcv.proto)!=0){
					LM_WARN("tcp alias failed\n");
					ret=E_UNSPEC;
					break;
				}
			}
			ret=1; /* continue processing */
			break;
		case FORCE_SEND_SOCKET_T:
			script_trace("core", "force_send_socket", msg, a->file, a->line) ;
			if (a->elem[0].type!=SOCKETINFO_ST){
				LM_ALERT("BUG in force_send_socket argument"
						" type: %d\n", a->elem[0].type);
				ret=E_BUG;
				break;
			}
			msg->force_send_socket=(struct socket_info*)a->elem[0].u.data;
			ret=1; /* continue processing */
			break;
		case SERIALIZE_BRANCHES_T:
			script_trace("core", "serialize_branches", msg, a->file, a->line) ;
			if (a->elem[0].type!=NUMBER_ST){
				LM_ALERT("BUG in serialize_branches argument"
						" type: %d\n", a->elem[0].type);
				ret=E_BUG;
				break;
			}
			if (serialize_branches(msg,(int)a->elem[0].u.number)!=0) {
				LM_ERR("serialize_branches failed\n");
				ret=E_UNSPEC;
				break;
			}
			ret=1; /* continue processing */
			break;
		case NEXT_BRANCHES_T:
			script_trace("core", "next_branches", msg, a->file, a->line) ;
			if ((ret=next_branches(msg))<0) {
				LM_ERR("next_branches failed\n");
				ret=E_UNSPEC;
				break;
			}
			/* continue processing */
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
			ret = do_assign(msg, a);
			break;
		case USE_BLACKLIST_T:
			script_trace("core", "use_blacklist", msg, a->file, a->line) ;
			mark_for_search((struct bl_head*)a->elem[0].u.data, 1);
			break;
		case UNUSE_BLACKLIST_T:
			script_trace("core", "unuse_blacklist", msg, a->file, a->line);
			mark_for_search((struct bl_head*)a->elem[0].u.data, 0);
			break;
		case PV_PRINTF_T:
			script_trace("core", "pv_printf", msg, a->file, a->line);
			ret = -1;
			spec = (pv_spec_p)a->elem[0].u.data;
			if(!pv_is_w(spec))
			{
				LM_ERR("read only PV in first parameter of pv_printf\n");
				goto error;
			}

			model = (pv_elem_p)a->elem[1].u.data;

			memset(&val, 0, sizeof(pv_value_t));
			if(pv_printf_s(msg, model, &val.rs)!=0)
			{
				LM_ERR("cannot eval second parameter\n");
				goto error;
			}
			val.flags = PV_VAL_STR;
			if(pv_set_value(msg, spec, EQ_T, &val)<0)
			{
				LM_ERR("setting PV failed\n");
				goto error;
			}

			ret = 1;
			break;
		case SCRIPT_TRACE_T:
			script_trace("core", "script_trace", msg, a->file, a->line);
			if (a->elem[0].type==NOSUBTYPE) {
				use_script_trace = 0;
			} else {

				use_script_trace = 1;

				if (a->elem[0].type != NUMBER_ST ||
					a->elem[1].type != SCRIPTVAR_ELEM_ST) {

					LM_ERR("BUG in use_script_trace() arguments\n");
					ret=E_BUG;
					break;
				}

				if (a->elem[2].type!=NOSUBTYPE) {
					script_trace_info = (char *)a->elem[2].u.data;
				} else {
					script_trace_info = NULL;
				}

				script_trace_log_level = (int)a->elem[0].u.number;
				script_trace_elem = *(pv_elem_p)a->elem[1].u.data;
			}

			break;
		default:
			LM_ALERT("BUG - unknown type %d\n", a->type);
			goto error;
	}

	if((unsigned char)a->type!=IF_T && (unsigned char)a->type!=ROUTE_T)
		return_code = ret;
/*skip:*/

	update_longest_action(a);
	return ret;

error:
	LM_ERR("error in %s:%d\n", a->file, a->line);
	update_longest_action(a);
	return ret;

error_uri:
	LM_ERR("set*: uri too long\n");
	if (new_uri)
		pkg_free(new_uri);
	update_longest_action(a);
	return E_UNSPEC;

error_fwd_uri:
	update_longest_action(a);
	return ret;
}

static int for_each_handler(struct sip_msg *msg, struct action *a)
{
	pv_spec_p iter, spec;
	pv_param_t pvp;
	pv_value_t val;
	int ret = 1;
	int op = 0;

	if (a->elem[2].type == ACTIONS_ST && a->elem[2].u.data) {
		iter = a->elem[0].u.data;
		spec = a->elem[1].u.data;

		/*
		 * simple is always better.
		 * just don't allow fancy for-each statements
		 */
		if (spec->pvp.pvi.type != PV_IDX_ALL) {
			LM_ERR("for-each must be used on a \"[*]\" index! skipping!\n");
			return E_SCRIPT;
		}

		memset(&pvp, 0, sizeof pvp);
		pvp.pvi.type = PV_IDX_INT;
		pvp.pvn = spec->pvp.pvn;

		/*
		 * for $json iterators, better to assume script writer
		 * wants data to be interpreted, rather than not
		 *    (i.e. ":=" script operator, and not simply "=")
		 */
		if (iter->type == PVT_JSON)
			op = COLONEQ_T;

		for (;;) {
			if (spec->getf(msg, &pvp, &val) != 0) {
				LM_ERR("failed to get spec value\n");
				return E_BUG;
			}

			if (val.flags & PV_VAL_NULL)
				break;

			if (iter->setf(msg, &iter->pvp, op, &val) != 0) {
				LM_ERR("failed to set scriptvar value\n");
				return E_BUG;
			}

			ret = run_action_list(
			              (struct action *)a->elem[2].u.data, msg);

			/* check for "return" statements or "0" retcodes */
			if (action_flags & (ACT_FL_RETURN | ACT_FL_EXIT))
				return ret;

			pvp.pvi.u.ival++;
		}
	}

	return ret;
}

/**
 * prints the current point of execution in the OpenSIPS script
 *
 * @class - optional, string to be printed meaning the class of action (if any)
 * @action - mandatory, string with the name of action
 * @msg - mandatory, sip message
 * @line - line in script
 */
void __script_trace(char *class, char *action, struct sip_msg *msg,
														char *file, int line)
{
	gparam_t param;
	str val;

	param.type = GPARAM_TYPE_PVE;
	param.v.pve = &script_trace_elem;

	val.s = NULL;
	val.len = 0;
	if (fixup_get_svalue(msg, &param, &val) != 0) {
		LM_ERR("Failed to get pv elem value!\n");
		return;
	}

	/* Also print extra info */
	if (script_trace_info) {
		LM_GEN1(script_trace_log_level, "[Script Trace][%s:%d][%s][%s %s]"\
			" -> (%.*s)\n", file, line, script_trace_info,
			class?class:"", action, val.len, val.s);
	} else {
		LM_GEN1(script_trace_log_level, "[Script Trace][%s:%d][%s %s]"\
			" -> (%.*s)\n", file, line,
			class?class:"", action, val.len, val.s);
	}
}
