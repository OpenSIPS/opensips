/*
 * $Id$
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
#include "udp_server.h"
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
#include "memcache.h"
#include "msg_translator.h"
#ifdef USE_TCP
#include "tcp_server.h"
#endif

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

static int rec_lev=0;

extern err_info_t _oser_err_info;


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
		if(error_rlist.a!=NULL &&
				(route_type&(ERROR_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE))==0
				&& _oser_err_info.eclass!=0)

		{
			LM_DBG("jumping to error route\n");
			set_route_type( ERROR_ROUTE );
			run_actions(error_rlist.a, msg);
			/* if don't exit, then reset error info */
			if(!(action_flags&ACT_FL_EXIT))
				init_err_info();
		}
		
		if((action_flags&ACT_FL_RETURN) || (action_flags&ACT_FL_EXIT))
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
	reset_bl_markers();

	resetsflag( (unsigned int)-1 );

	run_actions(a, msg);
	ret = action_flags;

	action_flags = bk_action_flags;
	rec_lev = bk_rec_lev;

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
		if(!((val.flags&PV_VAL_STR)||(val.flags&PV_VAL_INT))) {
			LM_ERR("no value in right expression\n");
			goto error;
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
			if(a->elem[1].type == NULLV_ST)
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
	LM_ERR("error at line: %d\n", a->line);
	pv_value_destroy(&val);
	return -1;
}

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
	int user;
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

	/* reset the value of error to E_UNSPEC so avoid unknowledgable
	   functions to return with error (status<0) and not setting it
	   leaving there previous error; cache the previous value though
	   for functions which want to process it */
	prev_ser_error=ser_error;
	ser_error=E_UNSPEC;

	ret=E_BUG;
	switch ((unsigned char)a->type){
		case DROP_T:
				action_flags |= ACT_FL_DROP;
		case EXIT_T:
				ret=0;
				action_flags |= ACT_FL_EXIT;
			break;
		case RETURN_T:
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
			}else if ((a->elem[0].type==PROXY_ST)) {
				ret=forward_request(msg,(struct proxy_l*)a->elem[0].u.data);
				if (ret==0) ret=1;
			}else{
				LM_ALERT("BUG in forward() types %d, %d\n",
						a->elem[0].type, a->elem[1].type);
				ret=E_BUG;
			}
			break;
		case SEND_T:
			if (a->elem[0].type!= PROXY_ST){
				LM_ALERT("BUG in send() type %d\n", a->elem[0].type);
				ret=E_BUG;
				break;
			}
			to=(union sockaddr_union*)
					pkg_malloc(sizeof(union sockaddr_union));
			if (to==0){
				LM_ERR("memory allocation failure\n");
				ret=E_OUT_OF_MEM;
				break;
			}
			
			p=(struct proxy_l*)a->elem[0].u.data;
			
			ret=hostent2su(to, &p->host, p->addr_idx,
						(p->port)?p->port:SIP_PORT );
			if (ret==0){
				ret = msg_send(0/*send_sock*/, p->proto, to, 0/*id*/,
						msg->buf, msg->len);
				if (ret!=0 && p->host.h_addr_list[p->addr_idx+1])
					p->addr_idx++;
			}
			pkg_free(to);
			if (ret==0)
				ret=1;
			break;
		case LOG_T:
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
			if ((a->elem[0].type!=STR_ST)) {
				LM_ALERT("BUG in append_branch %d\n",
					a->elem[0].type );
				ret=E_BUG;
				break;
			}
			if (a->elem[0].u.s.s==NULL) {
				ret = append_branch(msg, 0, &msg->dst_uri, &msg->path_vec,
					get_ruri_q(), getb0flags(), msg->force_send_socket);
				/* reset all branch info */
				msg->force_send_socket = 0;
				setb0flags(0);
				set_ruri_q(Q_UNSPECIFIED);
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
					&msg->path_vec, a->elem[1].u.number, getb0flags(),
					msg->force_send_socket);
			}
			break;
		case REMOVE_BRANCH_T:
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
			if (a->elem[0].type!=NUMBER_ST) {
				LM_ALERT("BUG in len_gt type %d\n",
					a->elem[0].type );
				ret=E_BUG;
				break;
			}
			ret = (msg->len >= (unsigned int)a->elem[0].u.number) ? 1 : -1;
			break;
		case SET_DEBUG_T:
			if (a->elem[0].type==NUMBER_ST)
				set_proc_debug_level(a->elem[0].u.number);
			else
				reset_proc_debug_level();
			ret = 1;
			break;
		case SETFLAG_T:
			ret = setflag( msg, a->elem[0].u.number );
			break;
		case RESETFLAG_T:
			ret = resetflag( msg, a->elem[0].u.number );
			break;
		case ISFLAGSET_T:
			ret = isflagset( msg, a->elem[0].u.number );
			break;
		case SETSFLAG_T:
			ret = setsflag( a->elem[0].u.number );
			break;
		case RESETSFLAG_T:
			ret = resetsflag( a->elem[0].u.number );
			break;
		case ISSFLAGSET_T:
			ret = issflagset( a->elem[0].u.number );
			break;
		case SETBFLAG_T:
			ret = setbflag( a->elem[0].u.number, a->elem[1].u.number );
			break;
		case RESETBFLAG_T:
			ret = resetbflag( a->elem[0].u.number, a->elem[1].u.number  );
			break;
		case ISBFLAGSET_T:
			ret = isbflagset( a->elem[0].u.number, a->elem[1].u.number  );
			break;
		case ERROR_T:
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
			return_code=run_actions(rlist[a->elem[0].u.number].a, msg);
			ret=return_code;
			break;
		case REVERT_URI_T:
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
			if (user || tmp) {
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
			if(msg->dst_uri.s!=0)
				pkg_free(msg->dst_uri.s);
			msg->dst_uri.s = 0;
			msg->dst_uri.len = 0;
			ret = 1;
			break;
		case ISDSTURISET_T:
			if(msg->dst_uri.s==0 || msg->dst_uri.len<=0)
				ret = -1;
			else
				ret = 1;
			break;
		case IF_T:
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
							LM_WARN("error in expression (l=%d)\n", a->line);
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
								LM_WARN("error in expression (l=%d)\n",
										a->line);
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
		case CACHE_STORE_T:
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
			int expires = 0;

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

			ret = cache_store( &a->elem[0].u.s, &name_s, &val_s, expires);
			break;
		case CACHE_REMOVE_T:
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
			ret = cache_remove( &a->elem[0].u.s, &name_s);
			break;
		case CACHE_FETCH_T:
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

			ret = cache_fetch( &a->elem[0].u.s, &name_s, &aux);
			if(ret > 0)
			{
				int_str res;
				int avp_name;
				unsigned short avp_type;

				spec = (pv_spec_t*)a->elem[2].u.data;
				if (pv_get_avp_name( msg, &(spec->pvp), &avp_name,
						&avp_type)!=0){
					LM_CRIT("BUG in getting AVP name\n");
					pkg_free(aux.s);
					return -1;
				}
				res.s = aux;
				if (add_avp(AVP_VAL_STR|avp_type, avp_name, res)<0){
					LM_ERR("cannot add AVP\n");
					pkg_free(aux.s);
					return -1;
				}
				pkg_free(aux.s);
			}
			
			break;

		case XDBG_T:
			if (a->elem[0].type == SCRIPTVAR_ELEM_ST)
			{
				if (xdbg(msg, a->elem[0].u.data, val.rs.s) < 0)
				{
					LM_ALERT("Cannot print message");
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
					LM_ALERT("Cannot print xlog debug message");
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
					LM_ALERT("Cannot print xlog debug message");
					break;
				}
			}

			break;
		case RAISE_EVENT_T:
			if (a->elem[0].type != NUMBER_ST) {
				LM_ERR("invalid event id\n");
				ret=E_BUG;
				break;
			}
			if (a->elem[2].u.data) {
				/* three parameters specified */
				ret = evi_raise_script_event((event_id_t)a->elem[0].u.number,
						a->elem[1].u.data, a->elem[2].u.data);
			} else {
				/* two parameters specified */
				ret = evi_raise_script_event((event_id_t)a->elem[0].u.number,
						NULL, a->elem[1].u.data);
			}
			if (ret <= 0) {
				LM_ERR("cannot raise event\n");
				ret=E_UNSPEC;
				break;
			}
			break;

		case CONSTRUCT_URI_T:
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
			if ( (a->elem[0].type==CMD_ST) && a->elem[0].u.data ) {
				ret=((cmd_export_t*)(a->elem[0].u.data))->function(msg,
						 (char*)a->elem[1].u.data, (char*)a->elem[2].u.data,
						 (char*)a->elem[3].u.data, (char*)a->elem[4].u.data,
						 (char*)a->elem[5].u.data, (char*)a->elem[6].u.data);
			}else{
				LM_ALERT("BUG in module call\n");
			}
			break;
		case FORCE_RPORT_T:
			msg->msg_flags|=FL_FORCE_RPORT;
			ret=1; /* continue processing */
			break;
		case FORCE_LOCAL_RPORT_T:
			msg->msg_flags|=FL_FORCE_LOCAL_RPORT;
			ret=1; /* continue processing */
			break;
		case SET_ADV_ADDR_T:
			if (a->elem[0].type!=STR_ST){
				LM_ALERT("BUG in set_advertised_address() "
						"type %d\n", a->elem[0].type);
				ret=E_BUG;
				break;
			}
			msg->set_global_address=*((str*)a->elem[0].u.data);
			ret=1; /* continue processing */
			break;
		case SET_ADV_PORT_T:
			if (a->elem[0].type!=STR_ST){
				LM_ALERT("BUG in set_advertised_port() "
						"type %d\n", a->elem[0].type);
				ret=E_BUG;
				break;
			}
			msg->set_global_port=*((str*)a->elem[0].u.data);
			ret=1; /* continue processing */
			break;
#ifdef USE_TCP
		case FORCE_TCP_ALIAS_T:
			if ( msg->rcv.proto==PROTO_TCP
#ifdef USE_TLS
					|| msg->rcv.proto==PROTO_TLS
#endif
			   ){
				
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
					LM_ERR("tcp alias failed\n");
					ret=E_UNSPEC;
					break;
				}
			}
#endif
			ret=1; /* continue processing */
			break;
		case FORCE_SEND_SOCKET_T:
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
			mark_for_search((struct bl_head*)a->elem[0].u.data, 1);
			break;
		case UNUSE_BLACKLIST_T:
			mark_for_search((struct bl_head*)a->elem[0].u.data, 0);
			break;
		case PV_PRINTF_T:
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
		default:
			LM_ALERT("BUG - unknown type %d\n", a->type);
			goto error;
	}

	if((unsigned char)a->type!=IF_T && (unsigned char)a->type!=ROUTE_T)
		return_code = ret;
/*skip:*/
	return ret;

error:
	LM_ERR("error at line: %d\n", a->line);
	return ret;
	
error_uri:
	LM_ERR("set*: uri too long\n");
	if (new_uri) pkg_free(new_uri);
	return E_UNSPEC;
error_fwd_uri:
	return ret;
}



