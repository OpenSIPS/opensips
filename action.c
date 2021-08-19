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
#include "route.h"
#include "parser/msg_parser.h"
#include "ut.h"
#include "sr_module.h"
#include "mem/mem.h"
#include "errinfo.h"
#include "msg_translator.h"
#include "mod_fix.h"
#include "script_var.h"
#include "xlog.h"
#include "cfg_pp.h"

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

struct route_params_level {
	void *params;
	void *extra; /* extra params used */
	param_getf_t get_param;
};
static struct route_params_level route_params[MAX_REC_LEV];
static int route_rec_level = -1;

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
	run_actions(sroutes->error.a, msg);
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
		if (_oser_err_info.eclass!=0 && sroutes->error.a!=NULL &&
		(route_type&(ERROR_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE))==0 )
			run_error_route(msg,0);

		/* continue or not ? */
		if (action_flags & (ACT_FL_RETURN | ACT_FL_EXIT | ACT_FL_BREAK))
			break;
	}
	return ret;
}

int run_top_route_get_code(struct action*a, struct sip_msg *msg, int *code_ret)
{
	int bk_action_flags;
	int bk_rec_lev;
	int ret, cret;
	context_p ctx = NULL;

	bk_action_flags = action_flags;
	bk_rec_lev = rec_lev;

	action_flags = 0;
	rec_lev = 0;
	init_err_info();

	if (current_processing_ctx==NULL) {
		if ( (ctx=context_alloc(CONTEXT_GLOBAL))==NULL) {
			LM_ERR("failed to allocated new global context\n");
			return -1;
		}
		memset( ctx, 0, context_size(CONTEXT_GLOBAL));
		current_processing_ctx = ctx;
	}

	cret = run_actions(a, msg);
	if (code_ret)
		*code_ret = cret;

	ret = action_flags;

	action_flags = bk_action_flags;
	rec_lev = bk_rec_lev;
	/* reset script tracing */
	use_script_trace = 0;

	if (ctx && current_processing_ctx) {
		context_destroy(CONTEXT_GLOBAL, ctx);
		context_free(ctx);
		current_processing_ctx = NULL;
	}

	return ret;
}

int run_top_route(struct action* a, struct sip_msg* msg)
{
	int bk_action_flags;
	int bk_rec_lev;
	int ret;
	context_p ctx = NULL;

	bk_action_flags = action_flags;
	bk_rec_lev = rec_lev;

	action_flags = 0;
	rec_lev = 0;
	init_err_info();

	if (current_processing_ctx==NULL) {
		if ( (ctx=context_alloc(CONTEXT_GLOBAL))==NULL) {
			LM_ERR("failed to allocated new global context\n");
			return -1;
		}
		memset( ctx, 0, context_size(CONTEXT_GLOBAL));
		current_processing_ctx = ctx;
	}

	run_actions(a, msg);
	ret = action_flags;

	action_flags = bk_action_flags;
	rec_lev = bk_rec_lev;
	/* reset script tracing */
	use_script_trace = 0;

	if (ctx && current_processing_ctx) {
		context_destroy(CONTEXT_GLOBAL, ctx);
		context_free(ctx);
		current_processing_ctx = NULL;
	}

	return ret;
}


/* execute assignment operation */
int do_assign(struct sip_msg* msg, struct action* a)
{
	str st;
	int ret;
	pv_value_t lval, val;
	pv_spec_p dspec;

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

	switch (a->type) {
	case EQ_T:
	case COLONEQ_T:
		break;
	case PLUSEQ_T:
	case MINUSEQ_T:
	case DIVEQ_T:
	case MULTEQ_T:
	case MODULOEQ_T:
	case BANDEQ_T:
	case BOREQ_T:
	case BXOREQ_T:
		if (pv_get_spec_value(msg, dspec, &lval) != 0) {
			LM_ERR("failed to get left-hand side value\n");
			goto error;
		}

		if (lval.flags & PV_VAL_NULL || val.flags & PV_VAL_NULL) {
			LM_ERR("NULL value(s) in complex assignment expressions "
			         "(+=, -=, etc.)\n");
			goto error;
		}

		/* both include STR versions and neither is primarily an INT */
		if ((lval.flags & PV_VAL_STR) && (val.flags & PV_VAL_STR) &&
			!(lval.flags & PV_TYPE_INT) && !(val.flags & PV_TYPE_INT)) {
			val.ri = 0;

			if (a->type != PLUSEQ_T)
				goto bad_operands;

			if (!(val.flags & PV_VAL_PKG)) {
				st = val.rs;
				val.rs.s = pkg_malloc(val.rs.len + lval.rs.len + 1);
				if (!val.rs.s) {
					val.rs.s = st.s;
					LM_ERR("oom 1\n");
					goto error;
				}

				memcpy(val.rs.s, lval.rs.s, lval.rs.len);
				memcpy(val.rs.s + lval.rs.len, st.s, st.len);
				val.rs.len += lval.rs.len;
				val.rs.s[val.rs.len] = '\0';
				val.flags |= PV_VAL_PKG;

				if (val.flags & PV_VAL_SHM) {
					val.flags &= ~PV_VAL_SHM;
					shm_free(st.s);
				}
			} else {
				st.len = val.rs.len;
				if (pkg_str_extend(&val.rs, val.rs.len + lval.rs.len + 1) != 0) {
					LM_ERR("oom 2\n");
					goto error;
				}
				val.rs.len--;
				memmove(val.rs.s + lval.rs.len, val.rs.s, st.len);
				memcpy(val.rs.s, lval.rs.s, lval.rs.len);
				val.rs.s[val.rs.len] = '\0';
			}
		} else if ((lval.flags & PV_VAL_INT) && (val.flags & PV_VAL_INT)) {
			if (val.flags & PV_VAL_STR)
				val.flags &= ~PV_VAL_STR;
			switch (a->type) {
			case PLUSEQ_T:
				val.ri = lval.ri + val.ri;
				break;
			case MINUSEQ_T:
				val.ri = lval.ri - val.ri;
				break;
			case DIVEQ_T:
				val.ri = lval.ri / val.ri;
				break;
			case MULTEQ_T:
				val.ri = lval.ri * val.ri;
				break;
			case MODULOEQ_T:
				val.ri = lval.ri % val.ri;
				break;
			case BANDEQ_T:
				val.ri = lval.ri & val.ri;
				break;
			case BOREQ_T:
				val.ri = lval.ri | val.ri;
				break;
			case BXOREQ_T:
				val.ri = lval.ri ^ val.ri;
				break;
			}
		} else {
			goto bad_operands;
		}
		break;
	default:
		LM_ALERT("BUG -> unknown op type %d\n", a->type);
		goto error;
	}

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

	pv_value_destroy(&val);
	return 1;

bad_operands:
	LM_ERR("unsupported operand type(s) for %s: %s and %s\n",
	       assignop_str(a->type),
	       lval.flags & PV_VAL_STR ? "string" : "int",
	       val.flags & PV_VAL_STR ? "string" : "int");
	pv_value_destroy(&val);
	return -1;

error:
	LM_ERR("error at %s:%d\n", a->file, a->line);
error2:
	pv_value_destroy(&val);
	return -1;
}


/* function used to get parameter from a route scope */
static int route_param_get(struct sip_msg *msg,  pv_param_t *ip,
		pv_value_t *res, void *params, void *extra)
{
	int index;
	pv_value_t tv;
	action_elem_p actions = (action_elem_p)params;
	int params_no = (int)(unsigned long)extra;

	if(ip->pvn.type==PV_NAME_INTSTR)
	{
		if (ip->pvn.u.isname.type != 0)
		{
			LM_ERR("$param expects an integer index here.  Strings "
			       "(named parameters) are only accepted within event_route\n");
			return -1;
		}
		index = ip->pvn.u.isname.name.n;
	} else
	{
		/* pvar -> it might be another $param variable! */
		route_rec_level--;
		if(pv_get_spec_value(msg, (pv_spec_p)(ip->pvn.u.dname), &tv)!=0)
		{
			LM_ERR("cannot get spec value\n");
			route_rec_level++;
			return -1;
		}
		route_rec_level++;

		if(tv.flags&PV_VAL_NULL || tv.flags&PV_VAL_EMPTY)
		{
			LM_ERR("null or empty name\n");
			return -1;
		}
		if (!(tv.flags&PV_VAL_INT) || str2int(&tv.rs,(unsigned int*)&index) < 0)
		{
			LM_ERR("invalid index <%.*s>\n", tv.rs.len, tv.rs.s);
			return -1;
		}
	}

	if (!params)
	{
		LM_DBG("no parameter specified for this route\n");
		return pv_get_null(msg, ip, res);
	}

	if (index < 1 || index > params_no)
	{
		LM_DBG("no such parameter index %d\n", index);
		return pv_get_null(msg, ip, res);
	}

	/* the parameters start at 0, whereas the index starts from 1 */
	index--;
	switch (actions[index].type)
	{
	case NULLV_ST:
		res->rs.s = NULL;
		res->rs.len = res->ri = 0;
		res->flags = PV_VAL_NULL;
		break;

	case STRING_ST:
		res->rs.s = actions[index].u.string;
		res->rs.len = strlen(res->rs.s);
		res->flags = PV_VAL_STR;
		break;

	case NUMBER_ST:
		res->rs.s = sint2str(actions[index].u.number, &res->rs.len);
		res->ri = actions[index].u.number;
		res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
		break;

	case SCRIPTVAR_ST:
		route_rec_level--;
		if(pv_get_spec_value(msg, (pv_spec_p)actions[index].u.data, res)!=0)
		{
			LM_ERR("cannot get spec value\n");
			route_rec_level++;
			return -1;
		}
		route_rec_level++;
		break;

	default:
		LM_ALERT("BUG: invalid parameter type %d\n",
				actions[index].type);
		return -1;
	}

	return 0;
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
	int i;
	int len;
	int cmatch;
	struct action *aitem;
	struct action *adefault;
	pv_spec_t *spec;
	pv_value_t val;
	struct timeval start;
	int end_time;
	cmd_export_t *cmd = NULL;
	acmd_export_t *acmd;
	void* cmdp[MAX_CMD_PARAMS];
	pv_value_t tmp_vals[MAX_CMD_PARAMS];
	str sval;

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
			init_str(&sval, "unknown");
			switch (a->elem[0].type) {
				case NUMBER_ST:
					i = a->elem[0].u.number;
					break;
				case SCRIPTVAR_ST:
					if (pv_get_spec_value(msg, a->elem[0].u.item, &val) < 0) {
						LM_ERR("cannot print route name!\n");
						i = -1;
						break;
					}
					if (val.flags & PV_VAL_INT)
						sval.s = int2str(val.ri, &sval.len);
					else
						sval = val.rs;
					i = get_script_route_ID_by_name_str(&sval, sroutes->request, RT_NO);
					break;
				case SCRIPTVAR_ELEM_ST:
					if (pv_printf_s(msg, a->elem[0].u.data, &sval) < 0) {
						LM_ERR("cannot print route name!\n");
						i = -1;
						break;
					}
					i = get_script_route_ID_by_name_str(&sval, sroutes->request, RT_NO);
					break;
				default:
					i = -1;
					break;
			}
			if (i == -1) {
				LM_ALERT("unknown route(%.*s) (type %d)\n", sval.len, sval.s,
						a->elem[0].type);
				ret=E_BUG;
				break;
			}
			if ((i>=RT_NO)||(i<0)){
				LM_BUG("invalid routing table number in route(%u)\n", i);
				ret=E_CFG;
				break;
			}
			script_trace("route", sroutes->request[i].name,
				msg, a->file, a->line) ;
			/* check if the route has parameters */
			if (a->elem[1].type != 0) {
				if (a->elem[1].type != NUMBER_ST || a->elem[2].type != SCRIPTVAR_ST) {
					LM_ALERT("BUG in route() type %d/%d\n",
							a->elem[1].type, a->elem[2].type);
					ret=E_BUG;
					break;
				}
				route_params_push_level(a->elem[2].u.data,
						(void*)(unsigned long)a->elem[1].u.number, route_param_get);
				return_code=run_actions(sroutes->request[i].a, msg);
				route_params_pop_level();
			} else {
				route_params_push_level(NULL, 0, route_param_get);
				return_code=run_actions(sroutes->request[i].a, msg);
				route_params_pop_level();
			}
			ret=return_code;
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
							if (action_flags &
									(ACT_FL_RETURN|ACT_FL_EXIT|ACT_FL_BREAK)) {
								action_flags &= ~ACT_FL_BREAK;
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
		case BREAK_T:
			script_trace("core", "break", msg, a->file, a->line) ;
			action_flags |= ACT_FL_BREAK;
			break;
		case FOR_EACH_T:
			script_trace("core", "for-each", msg, a->file, a->line) ;
			ret = for_each_handler(msg, a);
			break;
		case XDBG_T:
			script_trace("core", "xdbg", msg, a->file, a->line) ;
			if (a->elem[0].type == SCRIPTVAR_ELEM_ST)
			{
				ret = xdbg(msg, a->elem[0].u.data);
				if (ret < 0)
				{
					LM_ERR("error while printing xdbg message\n");
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
				ret = xlog_2(msg,a->elem[0].u.data, a->elem[1].u.data);
				if (ret < 0)
				{
					LM_ERR("error while printing xlog message\n");
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
				ret = xlog_1(msg,a->elem[0].u.data);
				if (ret < 0)
				{
					LM_ERR("error while printing xlog message\n");
					break;
				}
			}

			break;
		case SWITCH_T:
			script_trace("core", "switch", msg, a->file, a->line) ;
#ifdef EXTRA_DEBUG
			if (a->elem[0].type!=SCRIPTVAR_ST || a->elem[1].type!=ACTIONS_ST) {
				LM_ALERT("BUG in switch() type %d\n",
						a->elem[0].type);
				ret=E_BUG;
				break;
			}
#endif
			spec = (pv_spec_t*)a->elem[0].u.data;
			if(pv_get_spec_value(msg, spec, &val)!=0)
			{
				LM_ALERT("BUG - no value in switch()\n");
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
						if (action_flags &
								(ACT_FL_RETURN | ACT_FL_EXIT | ACT_FL_BREAK)) {
							action_flags &= ~ACT_FL_BREAK;
							break;
						}
					}

					if (!aitem->next)
						cmatch = 0;
				}
				aitem = aitem->next;
			}
			if((cmatch==0) && (adefault!=NULL))
			{
				LM_DBG("switch: running default statement\n");
				if(adefault->elem[0].u.data)
					return_code=run_action_list(
						(struct action*)adefault->elem[0].u.data, msg);
				if (action_flags & ACT_FL_BREAK)
					action_flags &= ~ACT_FL_BREAK;
			}
			ret=return_code;
			break;
		case CMD_T:
			if (a->elem[0].type != CMD_ST ||
				((cmd = (cmd_export_t*)a->elem[0].u.data) == NULL)) {
				LM_ALERT("BUG in module call\n");
				break;
			}

			script_trace("module", cmd->name, msg, a->file, a->line);

			if ((ret = get_cmd_fixups(msg, cmd->params, a->elem, cmdp,
				tmp_vals)) < 0) {
				LM_ERR("Failed to get fixups for command <%s> in %s, line %d\n",
					cmd->name, a->file, a->line);
				break;
			}

			ret = cmd->function(msg,
				cmdp[0],cmdp[1],cmdp[2],
				cmdp[3],cmdp[4],cmdp[5],
				cmdp[6],cmdp[7]);

			if (free_cmd_fixups(cmd->params, a->elem, cmdp) < 0) {
				LM_ERR("Failed to free fixups for command <%s> in %s, line %d\n",
					cmd->name, a->file, a->line);
				break;
			}

			break;
		case ASYNC_T:
			/* first param - an ACTIONS_ST containing an ACMD_ST
			 * second param - a NUMBER_ST pointing to resume route
			 * third param - an optional NUMBER_ST with a timeout */
			aitem = (struct action *)(a->elem[0].u.data);
			acmd = (acmd_export_t *)aitem->elem[0].u.data;

			if (async_script_start_f==NULL || a->elem[0].type!=ACTIONS_ST ||
			a->elem[1].type!=NUMBER_ST || aitem->type!=AMODULE_T) {
				LM_ALERT("BUG in async expression "
				         "(is the 'tm' module loaded?)\n");
			} else {
				script_trace("async", acmd->name, msg, a->file, a->line);

				if ((ret = get_cmd_fixups(msg, acmd->params, aitem->elem, cmdp,
					tmp_vals)) < 0) {
					LM_ERR("Failed to get fixups for async command <%s> in %s,"
					       " line %d\n", acmd->name, a->file, a->line);
					break;
				}

				ret = async_script_start_f(msg, aitem, a->elem[1].u.number,
					(unsigned int)a->elem[2].u.number, cmdp);
				if (ret>=0)
					action_flags |= ACT_FL_TBCONT;

				if (free_cmd_fixups(acmd->params, aitem->elem, cmdp) < 0) {
					LM_ERR("Failed to free fixups for async command <%s> in %s,"
					       " line %d\n", acmd->name, a->file, a->line);
					break;
				}
			}
			ret = 0;
			break;
		case LAUNCH_T:
			/* first param - an ACTIONS_ST containing an ACMD_ST
			 * second param - an optional NUMBER_ST pointing to an end route */
			aitem = (struct action *)(a->elem[0].u.data);
			acmd = (acmd_export_t *)aitem->elem[0].u.data;

			if (async_script_start_f==NULL || a->elem[0].type!=ACTIONS_ST ||
			a->elem[1].type!=NUMBER_ST || aitem->type!=AMODULE_T) {
				LM_ALERT("BUG in launch expression\n");
			} else {
				script_trace("launch", acmd->name, msg, a->file, a->line);
				/* NOTE that the routeID (a->elem[1].u.number) is set to 
				 * -1 if no reporting route is set */

				if ((ret = get_cmd_fixups(msg, acmd->params, aitem->elem,
					cmdp, tmp_vals)) < 0) {
					LM_ERR("Failed to get fixups for launch command <%s> in %s,"
					       " line %d\n", acmd->name, a->file, a->line);
					break;
				}

				ret = async_script_launch( msg, aitem, a->elem[1].u.number, cmdp);

				if (free_cmd_fixups(acmd->params, aitem->elem, cmdp) < 0) {
					LM_ERR("Failed to free fixups for launch command <%s> in %s,"
					       " line %d\n", acmd->name, a->file, a->line);
					break;
				}
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
			ret = do_assign(msg, a);
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
		if (pv_type(iter->type) == PVT_JSON)
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
			if (action_flags & (ACT_FL_RETURN | ACT_FL_EXIT | ACT_FL_BREAK)) {
				action_flags &= ~ACT_FL_BREAK;
				return ret;
			}

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
	str val;

	if (pv_printf_s(msg, &script_trace_elem, &val) != 0) {
		LM_ERR("Failed to evaluate variables\n");
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

/**
 * functions used to populate $params() vars in the route_param structure
 */

void route_params_push_level(void *params, void *extra, param_getf_t getf)
{
	route_rec_level++;
	route_params[route_rec_level].params = params;
	route_params[route_rec_level].extra = extra;
	route_params[route_rec_level].get_param = getf;
}

void route_params_pop_level(void)
{
	route_rec_level--;
}

int route_params_run(struct sip_msg *msg,  pv_param_t *ip, pv_value_t *res)
{
	if (route_rec_level == -1)
	{
		LM_DBG("no parameter specified for this route\n");
		return pv_get_null(msg, ip, res);
	}

	return route_params[route_rec_level].get_param(msg, ip, res,
			route_params[route_rec_level].params,
			route_params[route_rec_level].extra);
}


static const char *_sip_msg_buf =
"DUMMY sip:user@dummy.com SIP/2.0\r\n"
"Via: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKdummy\r\n"
"To: <sip:to@dummy.com>\r\n"
"From: <sip:from@dummy.com>;tag=1\r\n"
"Call-ID: dummy-1\r\n"
"CSeq: 1 DUMMY\r\n\r\n";
static struct sip_msg* dummy_static_req= NULL;
static int dummy_static_in_used = 0;

int is_dummy_sip_msg(struct sip_msg *req)
{
	if (req && req->buf==_sip_msg_buf)
		return 0;
	return -1;
}

struct sip_msg* get_dummy_sip_msg(void)
{
	struct sip_msg* req;

	if (dummy_static_req == NULL || dummy_static_in_used) {
		/* if the static request is not yet allocated, or the static
		 * request is already in used (nested calls?), we better allocate
		 * a new structure */
		LM_DBG("allocating new sip msg\n");
		req = (struct sip_msg*)pkg_malloc(sizeof(struct sip_msg));
		if(req == NULL)
		{
			LM_ERR("No more memory\n");
			return NULL;
		}
		memset( req, 0, sizeof(struct sip_msg));

		req->buf = (char*)_sip_msg_buf;
		req->len = strlen(_sip_msg_buf);
		req->rcv.src_ip.af = AF_INET;
		req->rcv.dst_ip.af = AF_INET;

		parse_msg((char*)_sip_msg_buf, strlen(_sip_msg_buf), req);
		parse_headers( req, HDR_EOH_F, 0);
		if (dummy_static_req==NULL) {
			dummy_static_req = req;
			dummy_static_in_used = 1;
			LM_DBG("setting as static to %p\n",req);
		}
	} else {
		/* reuse the static request */
		req = dummy_static_req;
		LM_DBG("reusing the static sip msg %p\n",req);
	}

	return req;
}

void release_dummy_sip_msg( struct sip_msg* req)
{
	struct hdr_field* hdrs;

	if (req==dummy_static_req) {
		/* for the static request, just strip out the potential
		 * changes (lumps, new_uri, dst_uri, etc), but keep the parsed
		 * list of headers (this never changes) */
		LM_DBG("cleaning the static sip msg %p\n",req);
		hdrs = req->headers;
		req->headers = NULL;
		free_sip_msg(req);
		req->headers = hdrs;
		req->msg_cb = NULL;
		req->new_uri.s = req->dst_uri.s = req->path_vec.s = NULL;
		req->new_uri.len = req->dst_uri.len = req->path_vec.len = 0;
		req->set_global_address.s = req->set_global_port.s = NULL;
		req->set_global_address.len = req->set_global_port.len = 0;
		req->add_rm = req->body_lumps = NULL;
		req->reply_lump = NULL;
		req->ruri_q = Q_UNSPECIFIED;
		req->ruri_bflags = 0;
		req->force_send_socket = NULL;
		req->parsed_uri_ok = 0;
		req->parsed_orig_ruri_ok = 0;
		req->add_to_branch_len = 0;
		req->flags = 0;
		req->msg_flags = 0;
		dummy_static_in_used = 0;
	} else {
		LM_DBG("freeing allocated sip msg %p\n",req);
		/* is was an 100% allocated request */
		free_sip_msg(req);
		pkg_free(req);
	}
}
