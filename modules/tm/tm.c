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
 *  2003-02-18  added t_forward_nonack_{udp, tcp}, t_relay_to_{udp,tcp},
 *               t_replicate_{udp, tcp} (andrei)
 *  2003-02-19  added t_rely_{udp, tcp} (andrei)
 *  2003-03-06  voicemail changes accepted (jiri)
 *  2003-03-10  module export interface updated to the new format (andrei)
 *  2003-03-16  flags export parameter added (janakj)
 *  2003-03-19  replaced all mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2003-03-30  set_kr for requests only (jiri)
 *  2003-04-05  s/reply_route/failure_route, onreply_route introduced (jiri)
 *  2003-04-14  use protocol from uri (jiri)
 *  2003-07-07  added t_relay_to_tls, t_replicate_tls, t_forward_nonack_tls
 *              removed t_relay_{udp,tcp,tls} (andrei)
 *  2003-09-26  added t_forward_nonack_uri() - same as t_forward_nonack() but
 *              takes no parameters -> forwards to uri (bogdan)
 *  2004-02-11  FIFO/CANCEL + alignments (hash=f(callid,cseq)) (uli+jiri)
 *  2004-02-18  t_reply exported via FIFO - imported from VM (bogdan)
 *  2004-10-01  added a new param.: restart_fr_on_each_reply (andrei)
 *  2005-05-30  light version of tm_load - find_export dropped -> module
 *              interface dosen't need to export internal functions (bogdan)
 *  2006-01-15  merged functions which diff only via proto (like t_relay,
 *              t_replicate and t_forward_nonack) (bogdan)
 *  2007-01-25  t_forward_nonack removed as it merged into t_relay,
 *              t_replicate also accepts flags for controlling DNS failover
 *              (bogdan)
 *  2008-04-04  added support for local and remote dispaly name in TM dialogs
 *              (by Andrei Pisau <andrei.pisau at voice-system dot ro> )
 */


#include <stdio.h>
#include <string.h>
#include <netdb.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../script_cb.h"
#include "../../mi/mi.h"
#include "../../usr_avp.h"
#include "../../mem/mem.h"
#include "../../pvar.h"
#include "../../mod_fix.h"

#include "sip_msg.h"
#include "h_table.h"
#include "ut.h"
#include "t_reply.h"
#include "t_fwd.h"
#include "t_lookup.h"
#include "callid.h"
#include "t_cancel.h"
#include "t_fifo.h"
#include "mi.h"
#include "tm_load.h"
#include "t_ctx.h"
#include "async.h"


/* item functions */
static int pv_get_tm_branch_idx(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_get_tm_reply_code(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_get_tm_ruri(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

/* TODO: remove in future versions (deprecated parameters) */
int __set_fr_timer(modparam_t type, void* val);
int __set_fr_inv_timer(modparam_t type, void* val);

/* fixup functions */
static int fixup_t_send_reply(void** param, int param_no);
static int fixup_local_replied(void** param, int param_no);
static int fixup_t_relay1(void** param, int param_no);
static int fixup_t_relay2(void** param, int param_no);
static int fixup_t_replicate(void** param, int param_no);
static int fixup_cancel_branch(void** param, int param_no);
static int fixup_froute(void** param, int param_no);
static int fixup_rroute(void** param, int param_no);
static int fixup_broute(void** param, int param_no);
static int fixup_t_new_request(void** param, int param_no);


/* init functions */
static int mod_init(void);
static int child_init(int rank);


/* exported functions */
inline static int w_t_newtran(struct sip_msg* p_msg);
inline static int w_t_reply(struct sip_msg *msg, char* code, char* text);
inline static int w_pv_t_reply(struct sip_msg *msg, char* code, char* text);
inline static int w_t_relay(struct sip_msg *p_msg , char *proxy, char* flags);
inline static int w_t_replicate(struct sip_msg *p_msg, char *dst,char* );
inline static int w_t_on_negative(struct sip_msg* msg, char *go_to);
inline static int w_t_on_reply(struct sip_msg* msg, char *go_to);
inline static int w_t_on_branch(struct sip_msg* msg, char *go_to);
inline static int t_check_status(struct sip_msg* msg, char *regexp);
inline static int t_flush_flags(struct sip_msg* msg);
inline static int t_local_replied(struct sip_msg* msg, char *type);
inline static int t_check_trans(struct sip_msg* msg);
inline static int t_was_cancelled(struct sip_msg* msg);
inline static int w_t_cancel_branch(struct sip_msg* msg, char *sflags );
inline static int w_t_add_hdrs(struct sip_msg* msg, char *val );
int t_cancel_trans(struct cell *t, str *hdrs);
inline static int w_t_new_request(struct sip_msg* msg, char*, char*, char*, char*, char*, char*);

struct sip_msg* tm_pv_context_request(struct sip_msg* msg);
struct sip_msg* tm_pv_context_reply(struct sip_msg* msg);

/* these values are used when the transaction has not been defined yet */
int fr_timeout;
int fr_inv_timeout;

#define TM_CANCEL_BRANCH_ALL    (1<<0)
#define TM_CANCEL_BRANCH_OTHERS (1<<1)


#define PV_FIELD_DELIM ", "
#define PV_FIELD_DELIM_LEN (sizeof(PV_FIELD_DELIM) - 1)

#define PV_LOCAL_BUF_SIZE	511
static char pv_local_buf[PV_LOCAL_BUF_SIZE+1];

static str uac_ctx_avp = str_init("uac_ctx");
static int uac_ctx_avp_id;


int pv_get_tm_branch_avp(struct sip_msg*, pv_param_t*, pv_value_t*);
int pv_set_tm_branch_avp(struct sip_msg*, pv_param_t*, int, pv_value_t*);
int pv_get_tm_fr_timeout(struct sip_msg*, pv_param_t *, pv_value_t*);
int pv_set_tm_fr_timeout(struct sip_msg*, pv_param_t *, int, pv_value_t*);
int pv_get_tm_fr_inv_timeout(struct sip_msg*, pv_param_t *, pv_value_t*);
int pv_set_tm_fr_inv_timeout(struct sip_msg*, pv_param_t *, int, pv_value_t*);
struct usr_avp** get_bavp_list(void);


/* module parameteres */
int tm_enable_stats = 1;
static int timer_partitions = 1;

/* statistic variables */
stat_var *tm_rcv_rpls;
stat_var *tm_rld_rpls;
stat_var *tm_loc_rpls;
stat_var *tm_uas_trans;
stat_var *tm_uac_trans;
stat_var *tm_trans_2xx;
stat_var *tm_trans_3xx;
stat_var *tm_trans_4xx;
stat_var *tm_trans_5xx;
stat_var *tm_trans_6xx;
stat_var *tm_trans_inuse;


static cmd_export_t cmds[]={
	{"t_newtran",       (cmd_function)w_t_newtran,      0, 0,
		0, REQUEST_ROUTE},
	{"t_reply",         (cmd_function)w_pv_t_reply,     2, fixup_t_send_reply,
		0, REQUEST_ROUTE | FAILURE_ROUTE },
	{"t_replicate",     (cmd_function)w_t_replicate,    1, fixup_t_replicate,
		0, REQUEST_ROUTE},
	{"t_replicate",     (cmd_function)w_t_replicate,    2, fixup_t_replicate,
		0, REQUEST_ROUTE},
	{"t_relay",         (cmd_function)w_t_relay,        0, 0,
		0, REQUEST_ROUTE | FAILURE_ROUTE },
	{"t_relay",         (cmd_function)w_t_relay,        1, fixup_t_relay1,
		0, REQUEST_ROUTE | FAILURE_ROUTE },
	{"t_relay",         (cmd_function)w_t_relay,        2, fixup_t_relay2,
		0, REQUEST_ROUTE | FAILURE_ROUTE },
	{"t_on_failure",    (cmd_function)w_t_on_negative,  1, fixup_froute,
		0, REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"t_on_reply",      (cmd_function)w_t_on_reply,     1, fixup_rroute,
		0, REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"t_on_branch",     (cmd_function)w_t_on_branch,    1, fixup_broute,
		0, REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE },
	{"t_check_status",  (cmd_function)t_check_status,   1, fixup_regexp_null,
		0, REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE },
	{"t_write_req",     (cmd_function)t_write_req,      2, fixup_t_write,
		0, REQUEST_ROUTE | FAILURE_ROUTE | BRANCH_ROUTE },
	{"t_write_unix",    (cmd_function)t_write_unix,     2, fixup_t_write,
		0, REQUEST_ROUTE | FAILURE_ROUTE | BRANCH_ROUTE },
	{"t_flush_flags",   (cmd_function)t_flush_flags,    0, 0,
		0, REQUEST_ROUTE | BRANCH_ROUTE  },
	{"t_local_replied", (cmd_function)t_local_replied,  1, fixup_local_replied,
		0, REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE },
	{"t_check_trans",   (cmd_function)t_check_trans,    0, 0,
		0, REQUEST_ROUTE | BRANCH_ROUTE },
	{"t_was_cancelled", (cmd_function)t_was_cancelled,  0, 0,
		0, FAILURE_ROUTE | ONREPLY_ROUTE },
	{"t_cancel_branch", (cmd_function)w_t_cancel_branch,0, 0,
		0, ONREPLY_ROUTE },
	{"t_cancel_branch", (cmd_function)w_t_cancel_branch,1, fixup_cancel_branch,
		0, ONREPLY_ROUTE },
	{"t_add_hdrs",      (cmd_function)w_t_add_hdrs,     1, fixup_spve_null,
		0, REQUEST_ROUTE },
	{"t_reply_with_body",(cmd_function)w_t_reply_body,  3,fixup_t_send_reply,
		0, REQUEST_ROUTE },
	{"t_new_request",    (cmd_function)w_t_new_request, 4, fixup_t_new_request,
		0, REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"t_new_request",    (cmd_function)w_t_new_request, 5, fixup_t_new_request,
		0, REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"t_new_request",    (cmd_function)w_t_new_request, 6, fixup_t_new_request,
		0, REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"load_tm",         (cmd_function)load_tm,          0, 0,
			0, 0},
	{0,0,0,0,0,0}
};


static param_export_t params[]={
	{"ruri_matching",             INT_PARAM,
		&ruri_matching},
	{"via1_matching",             INT_PARAM,
		&via1_matching},
	{"fr_timeout",                  INT_PARAM,
		&(timer_id2timeout[FR_TIMER_LIST])},
	{"fr_inv_timeout",              INT_PARAM,
		&(timer_id2timeout[FR_INV_TIMER_LIST])},
	{"fr_timer",                  INT_PARAM|USE_FUNC_PARAM,
		__set_fr_timer},
	{"fr_inv_timer",              INT_PARAM|USE_FUNC_PARAM,
		__set_fr_inv_timer},
	{"wt_timer",                  INT_PARAM,
		&(timer_id2timeout[WT_TIMER_LIST])},
	{"delete_timer",              INT_PARAM,
		&(timer_id2timeout[DELETE_LIST])},
	{"T1_timer",                  INT_PARAM,
		&(timer_id2timeout[RT_T1_TO_1])},
	{"T2_timer",                  INT_PARAM,
		&(timer_id2timeout[RT_T2])},
	{"unix_tx_timeout",           INT_PARAM,
		&tm_unix_tx_timeout},
	{"restart_fr_on_each_reply",  INT_PARAM,
		&restart_fr_on_each_reply},
	{"tw_append",                 STR_PARAM|USE_FUNC_PARAM,
		(void*)parse_tw_append },
	{ "enable_stats",             INT_PARAM,
		&tm_enable_stats },
	{ "pass_provisional_replies", INT_PARAM,
		&pass_provisional_replies },
	{ "syn_branch",               INT_PARAM,
		&syn_branch },
	{ "onreply_avp_mode",         INT_PARAM,
		&onreply_avp_mode },
	{ "disable_6xx_block",        INT_PARAM,
		&disable_6xx_block },
	{ "minor_branch_flag",        STR_PARAM,
		&minor_branch_flag_str },
	{ "minor_branch_flag",        INT_PARAM,
		&minor_branch_flag },
	{ "timer_partitions",         INT_PARAM,
		&timer_partitions },
	{ "auto_100trying",           INT_PARAM,
		&auto_100trying },
	{0,0,0}
};


static stat_export_t mod_stats[] = {
	{"received_replies" ,    0,              &tm_rcv_rpls    },
	{"relayed_replies" ,     0,              &tm_rld_rpls    },
	{"local_replies" ,       0,              &tm_loc_rpls    },
	{"UAS_transactions" ,    0,              &tm_uas_trans   },
	{"UAC_transactions" ,    0,              &tm_uac_trans   },
	{"2xx_transactions" ,    0,              &tm_trans_2xx   },
	{"3xx_transactions" ,    0,              &tm_trans_3xx   },
	{"4xx_transactions" ,    0,              &tm_trans_4xx   },
	{"5xx_transactions" ,    0,              &tm_trans_5xx   },
	{"6xx_transactions" ,    0,              &tm_trans_6xx   },
	{"inuse_transactions" ,  STAT_NO_RESET,  &tm_trans_inuse },
	{0,0,0}
};


/**
 * pseudo-variables exported by TM module
 */
static pv_export_t mod_items[] = {
	{ {"T_branch_idx", sizeof("T_branch_idx")-1}, 900, pv_get_tm_branch_idx, 0,
		 0, 0, 0, 0 },
	{ {"T_reply_code", sizeof("T_reply_code")-1}, 901, pv_get_tm_reply_code, 0,
		 0, 0, 0, 0 },
	{ {"T_ruri",       sizeof("T_ruri")-1},       902, pv_get_tm_ruri,       0,
		 0, 0, 0, 0 },
	{ {"bavp",         sizeof("bavp")-1},         903, pv_get_tm_branch_avp,
		pv_set_tm_branch_avp, pv_parse_avp_name, pv_parse_index, 0, 0 },
	{ {"T_fr_timeout", sizeof("T_fr_timeout")-1}, 904, pv_get_tm_fr_timeout,
		pv_set_tm_fr_timeout, 0, 0, 0, 0 },
	{ {"T_fr_inv_timeout", sizeof("T_fr_inv_timeout")-1}, 905,
		pv_get_tm_fr_inv_timeout, pv_set_tm_fr_inv_timeout, 0, 0, 0, 0 },
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};


static mi_export_t mi_cmds [] = {
	{MI_TM_UAC,     0, mi_tm_uac_dlg,   MI_ASYNC_RPL_FLAG,  0,  0 },
	{MI_TM_CANCEL,  0, mi_tm_cancel,    0,                  0,  0 },
	{MI_TM_HASH,    0, mi_tm_hash,      MI_NO_INPUT_FLAG,   0,  0 },
	{MI_TM_REPLY,   0, mi_tm_reply,     0,                  0,  0 },
	{0,0,0,0,0,0}
};


#ifdef STATIC_TM
struct module_exports tm_exports = {
#else
struct module_exports exports= {
#endif
	"tm",      /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	cmds,      /* exported functions */
	NULL,      /* exported async functions */
	params,    /* exported variables */
	mod_stats, /* exported statistics */
	mi_cmds,   /* exported MI functions */
	mod_items, /* exported pseudo-variables */
	0,         /* extra processes */
	mod_init,  /* module initialization function */
	(response_function) reply_received,
	(destroy_function) tm_shutdown,
	child_init /* per-child init function */
};



/**************************** fixup functions ******************************/
static int fixup_froute(void** param, int param_no)
{
	int rt;

	rt = get_script_route_ID_by_name( (char *)*param,
			failure_rlist, FAILURE_RT_NO);
	if (rt==-1) {
		LM_ERR("failure route <%s> does not exist\n",(char *)*param);
		return -1;
	}
	pkg_free(*param);
	*param = (void*)(unsigned long int)rt;
	return 0;
}


static int fixup_rroute(void** param, int param_no)
{
	int rt;

	rt = get_script_route_ID_by_name( (char *)*param,
		onreply_rlist, ONREPLY_RT_NO);
	if (rt==-1) {
		LM_ERR("onreply route <%s> does not exist\n",(char *)*param);
		return -1;
	}
	pkg_free(*param);
	*param = (void*)(unsigned long int)rt;
	return 0;
}


static int fixup_broute(void** param, int param_no)
{
	int rt;

	rt = get_script_route_ID_by_name( (char *)*param,
		branch_rlist, BRANCH_RT_NO);
	if (rt==-1) {
		LM_ERR("branch route <%s> does not exist\n",(char *)*param);
		return -1;
	}
	pkg_free(*param);
	*param = (void*)(unsigned long int)rt;
	return 0;
}


static int flag_fixup(void** param, int param_no)
{
	unsigned int flags;
	str s;

	if (param_no == 1) {
		s.s = (char*)*param;
		s.len = strlen(s.s);
		flags = 0;
		if ( strno2int(&s, &flags )<0 ) {
			return -1;
		}
		pkg_free(*param);
		*param = (void*)(unsigned long int)(flags<<1);
	}
	return 0;
}


static int fixup_t_replicate(void** param, int param_no)
{
	str s;
	pv_elem_t *model;

	if (param_no == 1) {
		s.s = (char*)*param;
		s.len = strlen(s.s);
		model = NULL;

		if(pv_parse_format(&s ,&model) || model==NULL) {
			LM_ERR("wrong format [%s] for param no %d!\n", s.s, param_no);
			return E_CFG;
		}

		*param = (void*)model;
	} else {
		/* flags */
		if (flag_fixup( param, 1)!=0) {
			LM_ERR("bad flags <%s>\n", (char *)(*param));
			return E_CFG;
		}
	}
	return 0;
}


static int fixup_phostport2proxy(void** param, int param_no)
{
	struct proxy_l *proxy;
	char *s;
	int port;
	int proto;
	str host;

	if (param_no!=1) {
		LM_CRIT("called with more than one parameter\n");
		return E_BUG;
	}

	s = (char *) (*param);
	if (s==0 || *s==0) {
		LM_CRIT("empty parameter\n");
		return E_UNSPEC;
	}

	if (parse_phostport( s, strlen(s), &host.s, &host.len, &port, &proto)!=0){
		LM_CRIT("invalid parameter <%s>\n",s);
		return E_UNSPEC;
	}

	proxy = mk_proxy( &host, port, proto, 0);
	if (proxy==0) {
		LM_ERR("failed to resolve <%.*s>\n", host.len, host.s );
		return ser_error;
	}
	*(param)=proxy;
	return 0;
}


static int fixup_t_relay1(void** param, int param_no)
{
	if (flag_fixup( param, 1)==0) {
		/* param is flag -> move it as second param */
		*((void**)(((char*)param)+sizeof(action_elem_t))) = *param;
		*param = 0;
		return 0;
	} else if (fixup_phostport2proxy( param, 1)==0 ) {
		/* param is OBP -> nothing else to do */
		return 0;
	} else {
		LM_ERR("param is neither flag, nor OBP <%s>\n",(char *)(*param));
		return E_CFG;
	}
}


static int fixup_t_relay2(void** param, int param_no)
{
	if (param_no==1) {
		return fixup_phostport2proxy( param, param_no);
	} else if (param_no==2) {
		if (flag_fixup( param, 1)!=0) {
			LM_ERR("bad flags <%s>\n", (char *)(*param));
			return E_CFG;
		}
	}
	return 0;
}


static int fixup_t_send_reply(void** param, int param_no)
{
	pv_elem_t *model=NULL;
	str s;

	/* convert to str */
	s.s = (char*)*param;
	s.len = strlen(s.s);
	if (s.len==0) {
		LM_ERR("param no. %d is empty!\n", param_no);
		return E_CFG;
	}

	model=NULL;
	if (param_no>0 && param_no<4) {
		if(pv_parse_format(&s ,&model) || model==NULL) {
			LM_ERR("wrong format [%s] for param no %d!\n", s.s, param_no);
			return E_CFG;
		}
		if(model->spec.getf==NULL && param_no==1) {
			if(str2int(&s,
			(unsigned int*)&model->spec.pvp.pvn.u.isname.name.n)!=0
			|| model->spec.pvp.pvn.u.isname.name.n<100
			|| model->spec.pvp.pvn.u.isname.name.n>699) {
				LM_ERR("wrong value [%s] for param no %d! - Allowed only"
					" 1xx - 6xx \n", s.s, param_no);
				return E_CFG;
			}
		}
		*param = (void*)model;
	}

	return 0;
}


static int fixup_local_replied(void** param, int param_no)
{
	char *val;
	int n = 0;

	if (param_no==1) {
		val = (char*)*param;
		if (strcasecmp(val,"all")==0) {
			n = 0;
		} else if (strcasecmp(val,"branch")==0) {
			n = 1;
		} else if (strcasecmp(val,"last")==0) {
			n = 2;
		} else {
			LM_ERR("invalid param \"%s\"\n", val);
			return E_CFG;
		}
		/* free string */
		pkg_free(*param);
		/* replace it with the compiled re */
		*param=(void*)(long)n;
	} else {
		LM_ERR("called with parameter != 1\n");
		return E_BUG;
	}
	return 0;
}


static int fixup_cancel_branch(void** param, int param_no)
{
	char *c;
	unsigned int flags;

	c = (char*)*param;
	flags = 0;
	while (*c) {
		switch (*c) {
			case 'a':
			case 'A':
				flags |= TM_CANCEL_BRANCH_ALL;
				break;
			case 'o':
			case 'O':
				flags |= TM_CANCEL_BRANCH_OTHERS;
				break;
			default:
				LM_ERR("unsupported flag '%c'\n",*c);
				return -1;
		}
		c++;
	}
	pkg_free(*param);
	*param = (void*)(unsigned long)flags;
	return 0;
}


static int fixup_t_new_request(void** param, int param_no)
{
	/* static string or pv-format for all parameters */
	return fixup_spve(param);
}



/***************************** init functions *****************************/
int load_tm( struct tm_binds *tmb)
{
	tmb->register_tmcb = register_tmcb;

	/* relay function */
	tmb->t_relay = (cmd_function)w_t_relay;

	/* reply functions */
	tmb->t_reply = (treply_f)w_t_reply;
	tmb->t_reply_with_body = t_reply_with_body;

	/* transaction location/status functions */
	tmb->t_newtran = w_t_newtran;
	tmb->t_is_local = t_is_local;
	tmb->t_check_trans = (cmd_function)t_check_trans;
	tmb->t_get_trans_ident = t_get_trans_ident;
	tmb->t_lookup_ident = t_lookup_ident;
	tmb->t_gett = get_t;
	tmb->t_get_e2eackt = get_e2eack_t;
	tmb->t_get_picked = t_get_picked_branch;

	tmb->t_lookup_original_t = t_lookupOriginalT;
	tmb->unref_cell = t_unref_cell;
	tmb->ref_cell = t_ref_cell;
	tmb->t_setkr = set_kr;

	tmb->t_cancel_trans = t_cancel_trans;
	/* tm uac functions */
	tmb->t_addblind = add_blind_uac;
	tmb->t_request_within = req_within;
	tmb->t_request_outside = req_outside;
	tmb->t_request = request;
	tmb->new_dlg_uac = new_dlg_uac;
	tmb->new_auto_dlg_uac = new_auto_dlg_uac;
	tmb->dlg_add_extra = dlg_add_extra;
	tmb->dlg_response_uac = dlg_response_uac;
	tmb->new_dlg_uas = new_dlg_uas;
	tmb->dlg_request_uas = dlg_request_uas;
	tmb->free_dlg = free_dlg;
	tmb->print_dlg = print_dlg;
	tmb->setlocalTholder = setlocalTholder;
	tmb->get_branch_index = get_branch_index;

	/* tm context functions */
	tmb->t_ctx_register_int = t_ctx_register_int;
	tmb->t_ctx_register_str = t_ctx_register_str;
	tmb->t_ctx_register_ptr = t_ctx_register_ptr;

	tmb->t_ctx_put_int = t_ctx_put_int;
	tmb->t_ctx_put_str = t_ctx_put_str;
	tmb->t_ctx_put_ptr = t_ctx_put_ptr;

	tmb->t_ctx_get_int = t_ctx_get_int;
	tmb->t_ctx_get_str = t_ctx_get_str;
	tmb->t_ctx_get_ptr = t_ctx_get_ptr;

	return 1;
}


static int do_t_cleanup( struct sip_msg *foo, void *bar)
{
	struct cell *t;

	empty_tmcb_list(&tmcb_pending_hl);

	t = get_cancelled_t();
	if (t!=NULL && t!=T_UNDEFINED)
		t_unref_cell(t);

	t = get_e2eack_t();
	if (t!=NULL && t!=T_UNDEFINED)
		t_unref_cell(t);

	reset_e2eack_t();

	return t_unref(foo) == 0 ? SCB_DROP_MSG : SCB_RUN_ALL;
}


static int script_init( struct sip_msg *foo, void *bar)
{
	/* we primarily reset all private memory here to make sure
	 * private values left over from previous message will
	 * not be used again */
	set_t(T_UNDEFINED);
	reset_cancelled_t();
	reset_e2eack_t();
	fr_timeout = timer_id2timeout[FR_TIMER_LIST];
	fr_inv_timeout = timer_id2timeout[FR_INV_TIMER_LIST];

	/* reset the kill reason status */
	reset_kr();

	/* reset the static holders for T routes */
	t_on_negative( 0 );
	t_on_reply(0);
	t_on_branch(0);

	return SCB_RUN_ALL;
}


static int mod_init(void)
{
	unsigned int timer_sets,set;
	unsigned int roundto_init;

	LM_INFO("TM - initializing...\n");

	/* checking if we have sufficient bitmap capacity for given
	   maximum number of  branches */
	if (MAX_BRANCHES+1>31) {
		LM_CRIT("Too many max UACs for UAC branch_bm_t bitmap: %d\n",
			MAX_BRANCHES );
		return -1;
	}

	fix_flag_name(minor_branch_flag_str, minor_branch_flag);

	minor_branch_flag =
		get_flag_id_by_name(FLAG_TYPE_BRANCH, minor_branch_flag_str);

	if (minor_branch_flag!=-1) {
		if (minor_branch_flag > (8*sizeof(int)-1)) {
			LM_CRIT("invalid minor branch flag\n");
			return -1;
		}
		minor_branch_flag = 1<<minor_branch_flag;
	} else {
		minor_branch_flag = 0;
	}

	/* if statistics are disabled, prevent their registration to core */
	if (tm_enable_stats==0)
#ifdef STATIC_TM
		tm_exports.stats = 0;
#else
		exports.stats = 0;
#endif

	if (init_callid() < 0) {
		LM_CRIT("Error while initializing Call-ID generator\n");
		return -1;
	}

	/* how many timer sets do we need to create? */
	timer_sets = (timer_partitions<=1)?1:timer_partitions ;

	/* try first allocating all the structures needed for syncing */
	if (lock_initialize( timer_sets )==-1)
		return -1;

	/* building the hash table*/
	if (!init_hash_table( timer_sets )) {
		LM_ERR("initializing hash_table failed\n");
		return -1;
	}

	/* init static hidden values */
	init_t();

	if (!tm_init_timers( timer_sets ) ) {
		LM_ERR("timer init failed\n");
		return -1;
	}

	/* the ROUNDTO macro taken from the locking interface */
#ifdef ROUNDTO
	roundto_init = ROUNDTO;
#else
	roundto_init = sizeof(void *);
#endif
	while (roundto_init != 1) {
		tm_timer_shift++;
		roundto_init >>= 1;
	}

	LM_DBG("timer set shift is %d\n", tm_timer_shift);


	/* register the timer functions */
	for ( set=0 ; set<timer_sets ; set++ ) {
		if (register_timer( "tm-timer", timer_routine,
		(void*)(long)set, 1, TIMER_FLAG_DELAY_ON_DELAY) < 0 ) {
			LM_ERR("failed to register timer for set %d\n",set);
			return -1;
		}
		if (register_utimer( "tm-utimer", utimer_routine,
		(void*)(long)set, 100*1000, TIMER_FLAG_DELAY_ON_DELAY)<0) {
			LM_ERR("failed to register utimer for set %d\n",set);
			return -1;
		}
	}

	if (uac_init()==-1) {
		LM_ERR("uac_init failed\n");
		return -1;
	}

	if (init_tmcb_lists()!=1) {
		LM_CRIT("failed to init tmcb lists\n");
		return -1;
	}

	tm_init_tags();
	init_twrite_lines();
	if (init_twrite_sock() < 0) {
		LM_ERR("failed to create socket\n");
		return -1;
	}

	/* register post-script clean-up function */
	if (register_script_cb( do_t_cleanup, POST_SCRIPT_CB|REQ_TYPE_CB, 0)<0 ) {
		LM_ERR("failed to register POST request callback\n");
		return -1;
	}
	if (register_script_cb( script_init, PRE_SCRIPT_CB|REQ_TYPE_CB , 0)<0 ) {
		LM_ERR("failed to register PRE request callback\n");
		return -1;
	}

	if(register_pv_context("request", tm_pv_context_request)< 0) {
		LM_ERR("Failed to register pv contexts\n");
		return -1;
	}

	if(register_pv_context("reply", tm_pv_context_reply)< 0) {
		LM_ERR("Failed to register pv contexts\n");
		return -1;
	}

	if ( parse_avp_spec( &uac_ctx_avp, &uac_ctx_avp_id)<0 ) {
		LM_ERR("failed to register AVP name <%s>\n",uac_ctx_avp.s);
		return -1;
	}

	if ( register_async_script_handlers( t_handle_async, t_resume_async )<0 ) {
		LM_ERR("failed to register async handler to core \n");
		return -1;
	}

	return 0;
}


static int child_init(int rank)
{
	if (child_init_callid(rank) < 0) {
		LM_ERR("failed to initialize Call-ID generator\n");
		return -2;
	}

	return 0;
}




/**************************** wrapper functions ***************************/
static int t_check_status(struct sip_msg* msg, char *regexp)
{
	regmatch_t pmatch;
	struct cell *t;
	char *status;
	char backup;
	int branch;
	int n;

	/* first get the transaction */
	t = get_t();
	if ( t==0 || t==T_UNDEFINED ) {
		LM_ERR("cannot check status for a reply which"
				" has no transaction-state established\n");
		return -1;
	}
	backup = 0;

	switch (route_type) {
		case REQUEST_ROUTE:
			/* use the status of the last sent reply */
			status = int2str( t->uas.status, 0);
			break;
		case ONREPLY_ROUTE:
			/* use the status of the current reply */
			status = msg->first_line.u.reply.status.s;
			backup = status[msg->first_line.u.reply.status.len];
			status[msg->first_line.u.reply.status.len] = 0;
			break;
		case FAILURE_ROUTE:
			/* use the status of the winning reply */
			if ( (branch=t_get_picked_branch())<0 ) {
				LM_CRIT("no picked branch (%d) for a final response"
						" in MODE_ONFAILURE\n", branch);
				return -1;
			}
			status = int2str( t->uac[branch].last_received , 0);
			break;
		default:
			LM_ERR("unsupported route_type %d\n", route_type);
			return -1;
	}

	LM_DBG("checked status is <%s>\n",status);
	/* do the checking */
	n = regexec((regex_t*)regexp, status, 1, &pmatch, 0);

	if (backup) status[msg->first_line.u.reply.status.len] = backup;
	if (n!=0) return -1;
	return 1;
}


inline static int t_check_trans(struct sip_msg* msg)
{
	struct cell *trans;

	if (msg->REQ_METHOD==METHOD_CANCEL) {
		/* parse needed hdrs*/
		if (check_transaction_quadruple(msg)==0) {
			LM_ERR("too few headers\n");
			return 0; /*drop request!*/
		}
		if (!msg->hash_index)
			msg->hash_index = tm_hash(msg->callid->body,get_cseq(msg)->number);
		/* performe lookup */
		trans = t_lookupOriginalT(  msg );
		return trans?1:-1;
	} else {
		trans = get_t();
		if (trans==NULL)
			return -1;
		if (trans!=T_UNDEFINED)
			return 1;
		switch ( t_lookup_request( msg , 0) ) {
			case 1:
				/* transaction found -> is it local ACK? */
				if (msg->REQ_METHOD==METHOD_ACK)
					return 1;
				/* .... else -> retransmission */
				trans = get_t();
				t_retransmit_reply(trans);
				UNREF(trans);
				set_t(0);
				return 0;
			case -2:
				/* e2e ACK found */
				return 1;
			default:
				/* notfound */
				return -1;
		}
	}
}


static int t_flush_flags(struct sip_msg* msg)
{
	struct cell *t;

	/* first get the transaction */
	t = get_t();
	if ( t==0 || t==T_UNDEFINED) {
		LM_ERR("failed to flush flags for a message which has"
				" no transaction-state established\n");
		return -1;
	}

	/* do the flush */
	t->uas.request->flags = msg->flags;
	return 1;
}


inline static int t_local_replied(struct sip_msg* msg, char *type)
{
	struct cell *t;
	int branch;
	int i;

	t = get_t();
	if (t==0 || t==T_UNDEFINED) {
		LM_ERR("no trasaction created\n");
		return -1;
	}

	switch ( (int)(long)type ) {
		/* check all */
		case 0:
			for( i=t->first_branch ; i<t->nr_of_outgoings ; i++ ) {
				if (t->uac[i].flags&T_UAC_HAS_RECV_REPLY)
					return -1;
			}
			return 1;
		/* check branch */
		case 1:
			if (route_type==FAILURE_ROUTE) {
				/* use the winning reply */
				if ( (branch=t_get_picked_branch())<0 ) {
					LM_CRIT("no picked branch (%d) for"
						" a final response in MODE_ONFAILURE\n", branch);
					return -1;
				}
				if (t->uac[branch].flags&T_UAC_HAS_RECV_REPLY)
					return -1;
				return 1;
			}
			return -1;
		/* check last */
		case 2:
			if (route_type==FAILURE_ROUTE) {
				/* use the winning reply */
				if ( (branch=t_get_picked_branch())<0 ) {
					LM_CRIT("no picked branch (%d) for"
						" a final response in MODE_ONFAILURE\n", branch);
					return -1;
				}
				if (t->uac[branch].reply==FAKED_REPLY)
					return 1;
				return -1;
			}
			return (t->relaied_reply_branch==-2)?1:-1;
		default:
			return -1;
	}
}


static int t_was_cancelled(struct sip_msg* msg)
{
	struct cell *t;

	/* first get the transaction */
	t = get_t();
	if ( t==0 || t==T_UNDEFINED ) {
		LM_ERR("failed to check cancel flag for a reply"
				" without a transaction\n");
		return -1;
	}
	return was_cancelled(t)?1:-1;
}


inline static int w_t_reply(struct sip_msg* msg, char* code, char* text)
{
	struct cell *t;
	int r;

	if (msg->REQ_METHOD==METHOD_ACK) {
		LM_DBG("ACKs are not replied\n");
		return 0;
	}
	switch (route_type) {
		case FAILURE_ROUTE:
			/* if called from reply_route, make sure that unsafe version
			 * is called; we are already in a mutex and another mutex in
			 * the safe version would lead to a deadlock */
			t=get_t();
			if ( t==0 || t==T_UNDEFINED ) {
				LM_ERR("BUG - no transaction found in Failure Route\n");
				return -1;
			}
			return t_reply_unsafe(t, msg, (unsigned int)(long)code,(str*)text);
		case REQUEST_ROUTE:
			t=get_t();
			if ( t==0 || t==T_UNDEFINED ) {
				r = t_newtran( msg , 0/*no full UAS cloning*/ );
				if (r==0) {
					/* retransmission -> break the script */
					return 0;
				} else if (r<0) {
					LM_ERR("could not create a new transaction\n");
					return -1;
				}
				t=get_t();
			}
			return t_reply( t, msg, (unsigned int)(long)code, (str*)text);
		default:
			LM_CRIT("unsupported route_type (%d)\n", route_type);
			return -1;
	}
}


inline static int w_pv_t_reply(struct sip_msg *msg, char* code, char* text)
{
	str code_s;
	unsigned int code_i;

	if(((pv_elem_p)code)->spec.getf!=NULL) {
		if(pv_printf_s(msg, (pv_elem_p)code, &code_s)!=0)
			return -1;
		if(str2int(&code_s, &code_i)!=0 || code_i<100 || code_i>699)
			return -1;
	} else {
		code_i = ((pv_elem_p)code)->spec.pvp.pvn.u.isname.name.n;
	}

	if(((pv_elem_p)text)->spec.getf!=NULL) {
		if(pv_printf_s(msg, (pv_elem_p)text, &code_s)!=0 || code_s.len <=0)
			return -1;
	} else {
		code_s = ((pv_elem_p)text)->text;
	}

	return w_t_reply(msg, (char*)(unsigned long)code_i, (char*)&code_s);
}


inline static int w_t_newtran( struct sip_msg* p_msg)
{
	/* t_newtran returns 0 on error (negative value means
	   'transaction exists' */
	return t_newtran( p_msg , 0 /*no full UAS cloning*/);
}


inline static int w_t_on_negative( struct sip_msg* msg, char *go_to)
{
	t_on_negative( (unsigned int )(long) go_to );
	return 1;
}


inline static int w_t_on_reply( struct sip_msg* msg, char *go_to)
{
	t_on_reply( (unsigned int )(long) go_to );
	return 1;
}


inline static int w_t_on_branch( struct sip_msg* msg, char *go_to)
{
	t_on_branch( (unsigned int )(long) go_to );
	return 1;
}


inline static int w_t_replicate(struct sip_msg *p_msg, char *dst, char *flags)
{
	str dest;

	if(((pv_elem_p)dst)->spec.getf!=NULL) {
		if(pv_printf_s(p_msg, (pv_elem_p)dst, &dest)!=0 || dest.len <=0)
			return -1;
	} else {
		dest = ((pv_elem_p)dst)->text;
	}

	return t_replicate( p_msg, &dest, (int)(long)flags);
}

static inline int t_relay_inerr2scripterr(void)
{
	switch (ser_error) {
		case E_BAD_URI:
		case E_BAD_REQ:
		case E_BAD_TO:
		case E_INVALID_PARAMS:
			/* bad message */
			return -2;
		case E_NO_DESTINATION:
			/* no available destination */
			return -3;
		case E_BAD_ADDRESS:
			/* bad destination */
			return -4;
		case E_IP_BLOCKED:
			/* destination filtered */
			return -5;
		case E_NO_SOCKET:
		case E_SEND:
			/* send failed */
			return -6;
		default:
			/* generic internal error */
			return -1;
	}
}


inline static int w_t_relay( struct sip_msg  *p_msg , char *proxy, char *flags)
{
	struct proxy_l *p = NULL;
	struct cell *t;
	int ret;

	t=get_t();

	if (proxy && (p=clone_proxy((struct proxy_l*)proxy))==0) {
		LM_ERR("failed to clone proxy, dropping packet\n");
		return -1;
	}

	if (!t || t==T_UNDEFINED) {
		/* no transaction yet */
		if (route_type==FAILURE_ROUTE) {
			LM_CRIT("BUG - undefined transaction in failure route\n");
			return -1;
		}
		ret = t_relay_to( p_msg, p, (int)(long)flags );
		if (ret<0) {
			ret = t_relay_inerr2scripterr();
		}
	} else {
		/* transaction already created */

		if ( route_type!=REQUEST_ROUTE && route_type!=FAILURE_ROUTE )
			goto route_err;

		if (p_msg->REQ_METHOD==METHOD_ACK) {
			/* local ACK*/
			t_release_transaction(t);
			return 1;
		}

		if (((int)(long)flags)&TM_T_REPLY_nodnsfo_FLAG)
			t->flags|=T_NO_DNS_FAILOVER_FLAG;
		if (((int)(long)flags)&TM_T_REPLY_reason_FLAG)
			t->flags|=T_CANCEL_REASON_FLAG;

		update_cloned_msg_from_msg( t->uas.request, p_msg);

		ret = t_forward_nonack( t, p_msg, p);
		if (ret<=0 ) {
			LM_ERR("t_forward_nonack failed\n");
			ret = t_relay_inerr2scripterr();
		}
	}

	if (p) {
		free_proxy(p);
		pkg_free(p);
	}
	return ret?ret:1;

route_err:
	LM_CRIT("unsupported route type: %d\n", route_type);
	return 0;
}

int t_cancel_trans(struct cell *t, str *extra_hdrs)
{
	branch_bm_t cancel_bitmap = 0;

	if (t==NULL || t==T_UNDEFINED) {
		/* no transaction */
		LM_ERR("cannot cancel with no transaction");
		return -1;
	}

	LOCK_REPLIES(t);
	which_cancel( t, &cancel_bitmap );
	UNLOCK_REPLIES(t);

	/* send cancels out */
	if (extra_hdrs)
		set_cancel_extra_hdrs( extra_hdrs->s, extra_hdrs->len);
	cancel_uacs(t, cancel_bitmap);
	set_cancel_extra_hdrs( NULL, 0);

	return 0;
}

extern int _tm_branch_index;
inline static int w_t_cancel_branch(struct sip_msg *msg, char *sflags)
{
	branch_bm_t cancel_bitmap = 0;
	struct cell *t;
	unsigned int flags = (unsigned long)sflags;

	t=get_t();

	if (t==NULL || t==T_UNDEFINED) {
		/* no transaction */
		LM_ERR("cannot cancel a reply with no transaction");
		return -1;
	}
	if (!is_invite(t))
		return -1;

	if (flags&TM_CANCEL_BRANCH_ALL) {
		/* lock and get the branches to cancel */
		if (!onreply_avp_mode) {
			LOCK_REPLIES(t);
			which_cancel( t, &cancel_bitmap );
			UNLOCK_REPLIES(t);
		} else {
			which_cancel( t, &cancel_bitmap );
		}
		if (msg->first_line.u.reply.statuscode>=200)
			/* do not cancel the current branch as we got
			 * a final response here */
			cancel_bitmap &= ~(1<<_tm_branch_index);
	} else if (flags&TM_CANCEL_BRANCH_OTHERS) {
		/* lock and get the branches to cancel */
		if (!onreply_avp_mode) {
			LOCK_REPLIES(t);
			which_cancel( t, &cancel_bitmap );
			UNLOCK_REPLIES(t);
		} else {
			which_cancel( t, &cancel_bitmap );
		}
		/* ignore current branch */
		cancel_bitmap &= ~(1<<_tm_branch_index);
	} else {
		/* cancel only local branch (only if still ongoing) */
		if (msg->first_line.u.reply.statuscode<200)
			cancel_bitmap = 1<<_tm_branch_index;
	}

	/* send cancels out */
	cancel_uacs(t, cancel_bitmap);

	return 1;
}


inline static int w_t_add_hdrs(struct sip_msg* msg, char *p_val )
{
	struct cell *t;
	str val;

	t=get_t();

	if (t==NULL || t==T_UNDEFINED) {
		/* no transaction */
		return -1;
	}
	if (fixup_get_svalue(msg, (gparam_p)p_val, &val)!=0) {
		LM_ERR("invalid value\n");
		return -1;
	}
	if (t->extra_hdrs.s) shm_free(t->extra_hdrs.s);
	t->extra_hdrs.s = (char*)shm_malloc(val.len);
	if (t->extra_hdrs.s==NULL) {
		LM_ERR("no more shm mem\n");
		return -1;
	}
	t->extra_hdrs.len = val.len;
	memcpy( t->extra_hdrs.s , val.s, val.len );

	return 1;
}


inline static int w_t_new_request(struct sip_msg* msg, char *p_method,
			char *p_ruri, char *p_from, char *p_to, char *p_body, char *p_ctx)
{
#define CONTENT_TYPE_HDR      "Content-Type: "
#define CONTENT_TYPE_HDR_LEN  (sizeof(CONTENT_TYPE_HDR)-1)
	static dlg_t dlg;
	struct usr_avp **avp_list;
	str ruri;
	str method;
	str body;
	str headers;
	str s;
	int_str ctx;
	char *p;

	memset( &dlg, 0, sizeof(dlg_t));

	/* evaluate the parameters */

	/* method */
	if ( fixup_get_svalue(msg, (gparam_p)p_method, &method)<0 ) {
		LM_ERR("failed to extract METHOD param\n");
		return -1;
	}
	LM_DBG("setting METHOD to <%.*s>\n", method.len, method.s);

	/* ruri - next hop is the same as RURI */
	dlg.hooks.next_hop = dlg.hooks.request_uri = &ruri;
	if ( fixup_get_svalue(msg, (gparam_p)p_ruri, &ruri)<0 ) {
		LM_ERR("failed to extract RURI param\n");
		return -1;
	}
	LM_DBG("setting RURI to <%.*s>\n",
		dlg.hooks.next_hop->len, dlg.hooks.next_hop->s);

	/* FROM URI + display */
	if ( fixup_get_svalue(msg, (gparam_p)p_from, &s)<0 ) {
		LM_ERR("failed to extract FROM param\n");
		return -1;
	}
	if ( (p=q_memrchr(s.s, ' ', s.len))==NULL ) {
		/* no display, only FROM URI */
		dlg.loc_uri = s;
		dlg.loc_dname.s = NULL;
		dlg.loc_dname.len = 0;
	} else {
		/* display + URI */
		dlg.loc_uri.s = p+1;
		dlg.loc_uri.len = s.s+s.len - dlg.loc_uri.s;
		dlg.loc_dname.s = s.s;
		dlg.loc_dname.len = p - s.s;
	}
	LM_DBG("setting FROM to <%.*s> + <%.*s>\n",
		dlg.loc_dname.len, dlg.loc_dname.s,
		dlg.loc_uri.len, dlg.loc_uri.s);

	/* TO URI + display */
	if ( fixup_get_svalue(msg, (gparam_p)p_to, &s)<0 ) {
		LM_ERR("failed to extract TO param\n");
		return -1;
	}
	if ( (p=q_memrchr(s.s, ' ', s.len))==NULL ) {
		/* no display, only TO URI */
		dlg.rem_uri = s;
		dlg.rem_dname.s = NULL;
		dlg.rem_dname.len = 0;
	} else {
		/* display + URI */
		dlg.rem_uri.s = p+1;
		dlg.rem_uri.len = s.s+s.len - dlg.rem_uri.s;
		dlg.rem_dname.s = s.s;
		dlg.rem_dname.len = p - s.s;
	}
	LM_DBG("setting TO to <%.*s> + <%.*s>\n",
		dlg.rem_dname.len, dlg.rem_dname.s,
		dlg.rem_uri.len, dlg.rem_uri.s);

	/* BODY and Content-Type */
	if (p_body!=NULL) {
		if ( fixup_get_svalue(msg, (gparam_p)p_body, &body)<0 ) {
			LM_ERR("failed to extract BODY param\n");
			return -1;
		}
		if ( (p=q_memchr(body.s, ' ', body.len))==NULL ) {
			LM_ERR("Content Type not found in the beginning of body <%.*s>\n",
				body.len, body.s);
			return -1;
		}
		/* build the Content-type header */
		headers.len = CONTENT_TYPE_HDR_LEN + (p-body.s) + CRLF_LEN;
		if ( (headers.s=(char*)pkg_malloc(headers.len))==NULL ) {
			LM_ERR("failed to get pkg mem (needed %d)\n",headers.len);
			return -1;
		}
		memcpy( headers.s, CONTENT_TYPE_HDR, CONTENT_TYPE_HDR_LEN);
		memcpy( headers.s+CONTENT_TYPE_HDR_LEN, body.s, p-body.s);
		memcpy( headers.s+CONTENT_TYPE_HDR_LEN+(p-body.s), CRLF, CRLF_LEN);
		/* set the body */
		body.len = body.s + body.len - (p+1);
		body.s = p + 1;
		LM_DBG("setting BODY to <%.*s> <%.*s>\n",
			headers.len, headers.s,
			body.len, body.s );
	} else {
		body.s = NULL;
		body.len = 0;
		headers.s = NULL;
		headers.len = 0;
	}

	/* context value */
	if (p_ctx!=NULL) {
		if ( fixup_get_svalue(msg, (gparam_p)p_ctx, &ctx.s)<0 ) {
			LM_ERR("failed to extract BODY param\n");
			if (p_body) pkg_free(headers.s);
			return -1;
		}
		LM_DBG("setting CTX AVP to <%.*s>\n", ctx.s.len, ctx.s.s);
		avp_list = set_avp_list( &dlg.avps );
		if (!add_avp( AVP_VAL_STR, uac_ctx_avp_id, ctx))
			LM_ERR("failed to add ctx AVP, ignorring...\n");
		set_avp_list( avp_list );
	}

	/* add cseq */
	dlg.loc_seq.value = DEFAULT_CSEQ;
	dlg.loc_seq.is_set = 1;

	/* add callid */
	generate_callid(&dlg.id.call_id);

	/* add FROM tag */
	generate_fromtag(&dlg.id.loc_tag, &dlg.id.call_id);
	/* TO tag is empty as this is a initial request */
	dlg.id.rem_tag.s = NULL;
	dlg.id.rem_tag.len = 0;

	/* do the actual sending now */
	if ( t_uac( &method, headers.s?&headers:NULL, body.s?&body:NULL,
	&dlg, 0, 0, 0) <= 0 ) {
		LM_ERR("failed to send the request out\n");
		if (headers.s) pkg_free(headers.s);
		if (dlg.avps) destroy_avp_list(&dlg.avps);
		return -1;
	}

	/* success -> do cleanup */
	if (headers.s) pkg_free(headers.s);
	return 1;
}




/* pseudo-variable functions */
static int pv_get_tm_branch_idx(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	int l = 0;
	char *ch = NULL;

	if(msg==NULL || res==NULL)
		return -1;

	if (route_type!=BRANCH_ROUTE && route_type!=ONREPLY_ROUTE) {
		res->flags = PV_VAL_NULL;
		return 0;
	}

	ch = int2str(_tm_branch_index, &l);

	res->rs.s = ch;
	res->rs.len = l;

	res->ri = _tm_branch_index;
	res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;

	return 0;
}

static int pv_get_tm_reply_code(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct cell *t;
	int code;
	int branch;

	if(msg==NULL || res==NULL)
		return -1;

	/* first get the transaction */
	if (t_check( msg , 0 )==-1) return -1;
	if ( (t=get_t())==0) {
		/* no T */
		code = 0;
	} else {
		switch (route_type) {
			case REQUEST_ROUTE:
				/* use the status of the last sent reply */
				code = t->uas.status;
				break;
			case ONREPLY_ROUTE:
				/* use the status of the current reply */
				code = msg->first_line.u.reply.statuscode;
				break;
			case FAILURE_ROUTE:
				/* use the status of the winning reply */
				if ( (branch=t_get_picked_branch())<0 ) {
					LM_CRIT("no picked branch (%d) for a final response"
							" in MODE_ONFAILURE\n", branch);
					code = 0;
				} else {
					code = t->uac[branch].last_received;
				}
				break;
			default:
				LM_ERR("unsupported route_type %d\n", route_type);
				code = 0;
		}
	}

	LM_DBG("reply code is <%d>\n",code);

	res->rs.s = int2str( code, &res->rs.len);

	res->ri = code;
	res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
	return 0;
}

static int pv_get_tm_ruri(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct cell *t;

	if(msg==NULL || res==NULL)
		return -1;

	/* first get the transaction */
	if (t_check( msg , 0 )==-1) return -1;
	if ( (t=get_t())==0) {
		/* no T */
		if (msg!=NULL&&msg!=FAKED_REPLY && msg->first_line.type==SIP_REQUEST){
			res->rs = *GET_RURI(msg);
			res->flags = PV_VAL_STR;
			return 0;
		}
		return pv_get_null(msg, param,res);
	}

	/* return the RURI for the current branch */
	if (_tm_branch_index>=t->nr_of_outgoings) {
		LM_ERR("BUG: _tm_branch_index greater than nr_of_outgoings\n");
		return -1;
	}

	res->rs = t->uac[_tm_branch_index].uri;

	res->flags = PV_VAL_STR;

	return 0;
}

struct sip_msg* tm_pv_context_reply(struct sip_msg* msg)
{
	struct cell* trans = get_t();
	int branch;

	if(trans == NULL || trans == T_UNDEFINED)
	{
		LM_ERR("No transaction found\n");
		return NULL;
	}

	if ( (branch=t_get_picked_branch())<0 )
	{
		LM_CRIT("no picked branch (%d) for a final response\n", branch);
		return 0;
	}

	return trans->uac[branch].reply;
}


struct sip_msg* tm_pv_context_request(struct sip_msg* msg)
{
	struct cell* trans = get_t();

	LM_DBG("in fct din tm\n");
	if(trans == NULL || trans == T_UNDEFINED)
	{
		LM_ERR("No transaction found\n");
		return NULL;
	}

	return trans->uas.request;
}


int pv_get_tm_branch_avp(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val)
{
	int avp_name;
	int_str avp_value;
	unsigned short name_type;
	int idx, idxf, res=0;
	struct usr_avp **old_list=NULL;
	struct usr_avp **avp_list=NULL;
	struct usr_avp *avp;
	int_str avp_value0;
	struct usr_avp *avp0;
	int n=0;
	char *p;

	if (!msg || !val)
		goto error;

	avp_list = get_bavp_list();
	if (!avp_list) {
		pv_get_null(msg, param, val);
		goto success;
	}

	if (!param) {
		LM_ERR("bad parameters\n");
		goto error;
	}

	if (pv_get_avp_name(msg, param, &avp_name, &name_type)) {
		LM_ALERT("BUG in getting bavp name\n");
		goto error;
	}

	/* get the index */
	if(pv_get_spec_index(msg, param, &idx, &idxf)!=0) {
		LM_ERR("invalid index\n");
		goto error;
	}

	/* setting the avp head */
	old_list = set_avp_list(avp_list);
	if (!old_list) {
		LM_CRIT("no bavp head list found\n");
		goto error;
	}

	if ((avp=search_first_avp(name_type, avp_name, &avp_value, 0))==0) {
		pv_get_null(msg, param, val);
		goto success;
	}
	val->flags = PV_VAL_STR;
	if ( (idxf==0 || idxf==PV_IDX_INT) && idx==0) {
		if(avp->flags & AVP_VAL_STR) {
			val->rs = avp_value.s;
		} else {
			val->rs.s = sint2str(avp_value.n, &val->rs.len);
			val->ri = avp_value.n;
			val->flags |= PV_VAL_INT|PV_TYPE_INT;
		}
		goto success;
	}
	if(idxf==PV_IDX_ALL) {
		p = pv_local_buf;
		do {
			if(avp->flags & AVP_VAL_STR) {
				val->rs = avp_value.s;
			} else {
				val->rs.s = sint2str(avp_value.n, &val->rs.len);
			}

			if(p-pv_local_buf+val->rs.len+1>PV_LOCAL_BUF_SIZE) {
				LM_ERR("local buffer length exceeded!\n");
				pv_get_null(msg, param, val);
				goto success;
			}
			memcpy(p, val->rs.s, val->rs.len);
			p += val->rs.len;
			if(p-pv_local_buf+PV_FIELD_DELIM_LEN+1>PV_LOCAL_BUF_SIZE) {
				LM_ERR("local buffer length exceeded\n");
				pv_get_null(msg, param, val);
				goto success;
			}
			memcpy(p, PV_FIELD_DELIM, PV_FIELD_DELIM_LEN);
			p += PV_FIELD_DELIM_LEN;
		} while ((avp=search_first_avp(name_type, avp_name,
						&avp_value, avp))!=0);
		*p = 0;
		val->rs.s = pv_local_buf;
		val->rs.len = p - pv_local_buf;
		goto success;
	}

	/* we have a numeric index */
	if(idx<0) {
		n = 1;
		avp0 = avp;
		while ((avp0=search_first_avp(name_type, avp_name,
						&avp_value0, avp0))!=0) n++;
		idx = -idx;
		if(idx>n) {
			LM_DBG("index out of range\n");
			pv_get_null(msg, param, val);
			goto success;
		}
		idx = n - idx;
		if(idx==0) {
			if(avp->flags & AVP_VAL_STR) {
				val->rs = avp_value.s;
			} else {
				val->rs.s = sint2str(avp_value.n, &val->rs.len);
				val->ri = avp_value.n;
				val->flags |= PV_VAL_INT|PV_TYPE_INT;
			}
			goto success;
		}
	}
	n=0;
	while(n<idx &&
			(avp=search_first_avp(name_type, avp_name, &avp_value, avp))!=0)
		n++;

	if(avp!=0) {
		if(avp->flags & AVP_VAL_STR) {
			val->rs = avp_value.s;
		} else {
			val->rs.s = sint2str(avp_value.n, &val->rs.len);
			val->ri = avp_value.n;
			val->flags |= PV_VAL_INT|PV_TYPE_INT;
		}
	}

	goto success;

error:
	res = -1;
success:
	if (old_list)
		set_avp_list(old_list);
	return res;
}

int pv_set_tm_branch_avp(struct sip_msg *msg, pv_param_t *param, int op,
		pv_value_t *val)
{
	int avp_name;
	int_str avp_val;
	int flags, res=0;
	unsigned short name_type;
	int idx, idxf;
	struct usr_avp **old_list=NULL;
	struct usr_avp **avp_list=NULL;

	if (!msg || !val)
		goto error;

	avp_list = get_bavp_list();
	if (!avp_list) {
		pv_get_null(msg, param, val);
		goto success;
	}

	if (!param) {
		LM_ERR("bad parameters\n");
		goto error;
	}

	if (pv_get_avp_name(msg, param, &avp_name, &name_type)) {
		LM_ALERT("BUG in getting bavp name\n");
		goto error;
	}

	/* get the index */
	if(pv_get_spec_index(msg, param, &idx, &idxf)!=0) {
		LM_ERR("invalid index\n");
		goto error;
	}

	/* setting the avp head */
	old_list = set_avp_list(avp_list);
	if (!old_list) {
		LM_CRIT("no bavp head list found\n");
		goto error;
	}

	if(val == NULL) {
		if(op == COLONEQ_T || idxf == PV_IDX_ALL)
			destroy_avps(name_type, avp_name, 1);
		else {
			if(idx < 0) {
				LM_ERR("index with negative value\n");
				goto error;
			}
			destroy_index_avp(name_type, avp_name, idx);
		}
		/* restoring head */
		goto success;
	}

	if(op == COLONEQ_T || idxf == PV_IDX_ALL)
		destroy_avps(name_type, avp_name, 1);

	flags = name_type;
	if(val->flags&PV_TYPE_INT) {
		avp_val.n = val->ri;
	} else {
		avp_val.s = val->rs;
		flags |= AVP_VAL_STR;
	}

	if(idxf == PV_IDX_INT || idxf == PV_IDX_PVAR) {
		if(replace_avp(flags, avp_name, avp_val, idx)< 0) {
			LM_ERR("failed to replace bavp\n");
			goto error;
		}
	} else {
		if (add_avp(flags, avp_name, avp_val)<0) {
			LM_ERR("error - cannot add bavp\n");
			goto error;
		}
	}
	goto success;

error:
	res = -1;
success:
	if (old_list)
		set_avp_list(old_list);
	return res;
}


struct usr_avp** get_bavp_list(void)
{
	struct cell* t;

	if (route_type!=BRANCH_ROUTE && route_type!=ONREPLY_ROUTE
			&& route_type!=FAILURE_ROUTE) {
		return NULL;
	}
	/* get the transaction */
	t = get_t();
	if ( t==0 || t==T_UNDEFINED ) {
		return NULL;
	}

	/* setting the avp head */
	return &t->uac[_tm_branch_index].user_avps;
}

int pv_get_tm_fr_timeout(struct sip_msg *msg, pv_param_t *param,
                         pv_value_t *ret)
{
	struct cell *t;

	if (!msg || !ret)
		return -1;

	t = get_t();

	ret->flags = PV_VAL_INT;
	ret->ri = (t && t != T_UNDEFINED) ? t->fr_timeout : fr_timeout;

	return 0;
}

int pv_set_tm_fr_timeout(struct sip_msg *msg, pv_param_t *param, int op,
                         pv_value_t *val)
{
	struct cell *t;
	int timeout;

	if (!msg)
		return -1;

	/* "$T_fr_timer = NULL" will set the default timeout */
	if (!val) {
		timeout = timer_id2timeout[FR_TIMER_LIST];
		goto set_timeout;
	}

	if (!(val->flags & PV_VAL_INT)) {
		LM_ERR("assigning non-int value as a timeout\n");
		return -1;
	}

	timeout = val->ri;

set_timeout:
	t = get_t();
	if (t && t != T_UNDEFINED)
		t->fr_timeout = timeout;
	else
		fr_timeout = timeout;

	return 0;
}

int pv_get_tm_fr_inv_timeout(struct sip_msg *msg,
                             pv_param_t *param, pv_value_t *ret)
{
	struct cell *t;

	if (!msg || !ret)
		return -1;

	t = get_t();

	ret->flags = PV_VAL_INT;
	ret->ri = (t && t != T_UNDEFINED) ? t->fr_inv_timeout : fr_inv_timeout;

	return 0;
}

int pv_set_tm_fr_inv_timeout(struct sip_msg *msg, pv_param_t *param,
                             int op, pv_value_t *val)
{
	struct cell *t;
	int timeout;

	if (!msg)
		return -1;

	/* "$T_fr_inv_timer = NULL" will set the default timeout */
	if (!val) {
		timeout = timer_id2timeout[FR_INV_TIMER_LIST];
		goto set_timeout;
	}

	if (!(val->flags & PV_VAL_INT)) {
		LM_ERR("assigning non-int value as a timeout\n");
		return -1;
	}

	timeout = val->ri;

set_timeout:
	t = get_t();
	if (t && t != T_UNDEFINED)
		t->fr_inv_timeout = timeout;
	else
		fr_inv_timeout = timeout;

	return 0;
}

int __set_fr_timer(modparam_t type, void* val)
{
	LM_WARN("\"fr_timer\" is now deprecated! Use \"fr_timeout\" instead!\n");

	timer_id2timeout[FR_TIMER_LIST] = (int)(long)val;

	return 1;
}

int __set_fr_inv_timer(modparam_t type, void* val)
{
	LM_WARN("\"fr_inv_timer\" is now deprecated! Use \"fr_inv_timeout\" instead!\n");

	timer_id2timeout[FR_INV_TIMER_LIST] = (int)(long)val;

	return 1;
}
