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
#include "cluster.h"


/* item functions */
static int pv_get_tm_branch_idx(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_get_tm_reply_code(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_get_tm_ruri(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_get_t_id(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_get_tm_branch_reply_code(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_get_tm_branch_uri(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_get_tm_branch_duri(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_get_tm_branch_q(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_get_tm_branch_path(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_get_tm_branch_sock(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_get_tm_branch_flags(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_get_tm_branch_flag(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_get_tm_branch_attr(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_get_tm_branch_lastrecv(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_get_tm_branch_type(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_set_tm_branch_flag(struct sip_msg* msg, pv_param_t *param,int op,
		pv_value_t *val);
static int pv_set_tm_branch_attr(struct sip_msg* msg, pv_param_t *param,int op,
		pv_value_t *val);
static int tm_branch_flag_parse_name(pv_spec_p sp, const str *in);
static int pv_parse_branch_index(pv_spec_p sp, const str *in);

/* fixup functions */
static int fixup_local_replied(void** param);
static int fixup_cancel_branch(void** param);
static int fixup_froute(void** param);
static int fixup_rroute(void** param);
static int fixup_broute(void** param);
static int free_fixup_Xroute(void** param);
static int fixup_inject_source(void **param);
static int fixup_inject_flags(void **param);
static int fixup_reply_code(void **param);
static int flag_fixup(void** param);
static int fixup_phostport2proxy(void** param);
static int fixup_free_proxy(void **param);

/* init functions */
static int mod_init(void);
static int child_init(int rank);


/* exported functions */
static int w_t_newtran(struct sip_msg* p_msg);
static int w_t_reply(struct sip_msg* msg, unsigned int code, str* text);
static int w_pv_t_reply(struct sip_msg *msg, unsigned int* code, str* text);
static int w_t_relay( struct sip_msg  *p_msg , void *flags, struct proxy_l *proxy);
static int w_t_replicate(struct sip_msg *p_msg, str *dst, void *flags);
static int w_t_on_negative(struct sip_msg* msg, void *go_to);
static int w_t_on_reply(struct sip_msg* msg, void *go_to);
static int w_t_on_branch(struct sip_msg* msg, void *go_to);
static int t_check_status(struct sip_msg* msg, regex_t *regexp);
static int t_flush_flags(struct sip_msg* msg);
static int t_local_replied(struct sip_msg* msg, void *type);
static int t_check_trans(struct sip_msg* msg);
static int t_was_cancelled(struct sip_msg* msg);
static int w_t_cancel_branch(struct sip_msg* msg, void *sflags);
static int w_t_add_hdrs(struct sip_msg* msg, str *val);
static int t_cancel_trans(struct cell *t, str *hdrs);
static int w_t_new_request(struct sip_msg* msg, str *method,
			str *ruri, str *from, str *to, str *body, str *p_ctx);
static int t_wait_for_new_branches(struct sip_msg* msg,
			unsigned int* br_to_wait);
static int w_t_wait_no_more_branches(struct sip_msg* msg);
static int t_reply_by_callid(struct sip_msg* msg,
		unsigned int* code, str* text, str* callid, str* cseq);
static int t_get_branch_idx_by_attr(struct sip_msg* msg,
		str* attr, str* val_s, int *val_i, pv_spec_t *result, int *offset);

struct sip_msg* tm_pv_context_request(struct sip_msg* msg);
struct sip_msg* tm_pv_context_reply(struct sip_msg* msg);

/* these values are used when the transaction has not been defined yet */
int fr_timeout;
int fr_inv_timeout;

static char* tm_local_reply_route_s;
struct script_route_ref *tm_local_reply_route = NULL;

static char* tm_local_request_route_s;
struct script_route_ref *tm_local_request_route = NULL;

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
static struct usr_avp** pv_get_bavp_list(void);


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

stat_var *tm_retran_req_T11;
stat_var *tm_retran_req_T12;
stat_var *tm_retran_req_T13;
stat_var *tm_retran_req_T2;
stat_var *tm_retran_rpl_T2;
stat_var *tm_timeout_fr;
stat_var *tm_timeout_fr_inv;

stat_var *tm_cluster_reply_tx;
stat_var *tm_cluster_request_tx;
stat_var *tm_cluster_cancel_tx;
stat_var *tm_cluster_reply_rx;
stat_var *tm_cluster_request_rx;
stat_var *tm_cluster_cancel_rx;

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "tm_replication_cluster",	get_deps_clusterer	},
		{ NULL, NULL },
	},
};


static const cmd_export_t cmds[]={
	{"t_newtran", (cmd_function)w_t_newtran, {{0,0,0}},
		REQUEST_ROUTE},
	{"t_reply", (cmd_function)w_pv_t_reply, {
		{CMD_PARAM_INT, fixup_reply_code, 0},
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE | FAILURE_ROUTE},
	{"t_replicate", (cmd_function)w_t_replicate, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, flag_fixup, 0}, {0,0,0}},
		REQUEST_ROUTE | FAILURE_ROUTE},
	{"t_relay", (cmd_function)w_t_relay, {
		{CMD_PARAM_STR|CMD_PARAM_OPT, flag_fixup, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, fixup_phostport2proxy,fixup_free_proxy},
		{0,0,0}},
		REQUEST_ROUTE | FAILURE_ROUTE},
	{"t_on_failure", (cmd_function)w_t_on_negative, {
		{CMD_PARAM_STR, fixup_froute, free_fixup_Xroute}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"t_on_reply", (cmd_function)w_t_on_reply, {
		{CMD_PARAM_STR, fixup_rroute, free_fixup_Xroute}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"t_on_branch", (cmd_function)w_t_on_branch, {
		{CMD_PARAM_STR, fixup_broute, free_fixup_Xroute}, {0,0,0}},
		REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE},
	{"t_check_status", (cmd_function)t_check_status, {
		{CMD_PARAM_REGEX, 0, 0}, {0,0,0}},
		REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE},
	{"t_write_req", (cmd_function)t_write_req, {
		{CMD_PARAM_STR, fixup_t_write, fixup_free_t_write},
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE | FAILURE_ROUTE | BRANCH_ROUTE},
	{"t_write_unix", (cmd_function)t_write_unix, {
		{CMD_PARAM_STR, fixup_t_write, fixup_free_t_write},
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE | FAILURE_ROUTE | BRANCH_ROUTE},
	{"t_flush_flags", (cmd_function)t_flush_flags, {{0,0,0}},
		REQUEST_ROUTE | BRANCH_ROUTE},
	{"t_local_replied", (cmd_function)t_local_replied, {
		{CMD_PARAM_STR, fixup_local_replied, 0}, {0,0,0}},
		REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE},
	{"t_check_trans", (cmd_function)t_check_trans, {{0,0,0}},
		REQUEST_ROUTE | BRANCH_ROUTE},
	{"t_was_cancelled", (cmd_function)t_was_cancelled, {{0,0,0}},
		REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE},
	{"t_cancel_branch", (cmd_function)w_t_cancel_branch, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, fixup_cancel_branch, 0}, {0,0,0}},
		ONREPLY_ROUTE},
	{"t_add_hdrs", (cmd_function)w_t_add_hdrs, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{"t_reply_with_body", (cmd_function)w_t_reply_body, {
		{CMD_PARAM_INT, fixup_reply_code, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"t_new_request", (cmd_function)w_t_new_request, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"t_add_cancel_reason", (cmd_function)t_add_reason, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{"t_inject_branches", (cmd_function)w_t_inject_branches, {
		{CMD_PARAM_STR, fixup_inject_source, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, fixup_inject_flags, 0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE},
	{"t_wait_for_new_branches", (cmd_function)t_wait_for_new_branches, {
		{CMD_PARAM_INT | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{"t_wait_no_more_branches", (cmd_function)w_t_wait_no_more_branches,
		{{0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"t_anycast_replicate", (cmd_function)tm_anycast_replicate, {{0,0,0}},
		REQUEST_ROUTE},
	{"t_reply_by_callid", (cmd_function)t_reply_by_callid, {
		{CMD_PARAM_INT, fixup_reply_code, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{"t_get_branch_idx_by_attr", (cmd_function)t_get_branch_idx_by_attr, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_INT | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_INT | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ONREPLY_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"load_tm", (cmd_function)load_tm, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};

static const param_export_t params[]={
	{"ruri_matching",             INT_PARAM,
		&ruri_matching},
	{"via1_matching",             INT_PARAM,
		&via1_matching},
	{"fr_timeout",                  INT_PARAM,
		&(timer_id2timeout[FR_TIMER_LIST])},
	{"fr_inv_timeout",              INT_PARAM,
		&(timer_id2timeout[FR_INV_TIMER_LIST])},
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
	{ "timer_partitions",         INT_PARAM,
		&timer_partitions },
	{ "auto_100trying",           INT_PARAM,
		&auto_100trying },
	{ "tm_replication_cluster",   INT_PARAM,
		&tm_repl_cluster },
	{ "cluster_param",            STR_PARAM,
		&tm_cluster_param.s },
	{ "cluster_auto_cancel",      INT_PARAM,
		&tm_repl_auto_cancel },
	{ "local_reply_route",        STR_PARAM,
		&tm_local_reply_route_s },
	{ "local_request_route",      STR_PARAM,
		&tm_local_request_route_s },
	{0,0,0}
};


static const stat_export_t mod_stats[] = {
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
	{"cluster_reply_sent" ,  0,              &tm_cluster_reply_tx   },
	{"cluster_request_sent" ,0,              &tm_cluster_request_tx },
	{"cluster_cancel_sent" , 0,              &tm_cluster_cancel_tx },
	{"cluster_reply_recv" ,  0,              &tm_cluster_reply_rx   },
	{"cluster_request_recv" ,0,              &tm_cluster_request_rx },
	{"cluster_cancel_recv" , 0,              &tm_cluster_cancel_rx },
	{"retransmission_req_T1_1"   , 0,        &tm_retran_req_T11 },
	{"retransmission_req_T1_2"   , 0,        &tm_retran_req_T12 },
	{"retransmission_req_T1_3"   , 0,        &tm_retran_req_T13 },
	{"retransmission_req_T2"     , 0,        &tm_retran_req_T2 },
	{"retransmission_rpl_T2"     , 0,        &tm_retran_rpl_T2 },
	{"timeout_finalresponse"     , 0,        &tm_timeout_fr },
	{"timeout_finalresponse_inv" , 0,        &tm_timeout_fr_inv },
	{0,0,0}
};


/**
 * pseudo-variables exported by TM module
 */
static const pv_export_t mod_items[] = {
	{ str_const_init("T_branch_idx"),
		900, pv_get_tm_branch_idx, NULL,
		NULL, NULL, NULL, 0 },
	{ str_const_init("T_reply_code"),
		901, pv_get_tm_reply_code, NULL,
		NULL, NULL, NULL, 0 },
	{ str_const_init("T_ruri"),
		902, pv_get_tm_ruri, NULL,
		NULL, NULL, NULL, 0 },
	{ str_const_init("bavp"),
		903, pv_get_tm_branch_avp, pv_set_tm_branch_avp,
		pv_parse_avp_name, pv_parse_index, NULL, 0 },
	{ str_const_init("T_fr_timeout"),
		904, pv_get_tm_fr_timeout, pv_set_tm_fr_timeout,
		NULL, NULL, NULL, 0 },
	{ str_const_init("T_fr_inv_timeout"),
		905, pv_get_tm_fr_inv_timeout, pv_set_tm_fr_inv_timeout,
		NULL, NULL, NULL, 0 },
	{ str_const_init("T_id"),
		906, pv_get_t_id, NULL,
		NULL, NULL, NULL, 0 },
	{ str_const_init("T_branch_last_reply_code"),
		907, pv_get_tm_branch_reply_code, NULL,
		NULL, pv_parse_index, NULL, 0 },
	{str_const_init("tm.branch.uri"), /* */
		908, pv_get_tm_branch_uri, NULL,
		NULL, pv_parse_branch_index, NULL, 0},
	{str_const_init("tm.branch.duri"), /* */
		909, pv_get_tm_branch_duri, NULL,
		NULL, pv_parse_branch_index, NULL, 0},
	{str_const_init("tm.branch.path"), /* */
		910, pv_get_tm_branch_path, NULL,
		NULL, pv_parse_branch_index, NULL, 0},
	{str_const_init("tm.branch.q"), /* */
		911, pv_get_tm_branch_q, NULL,
		NULL, pv_parse_branch_index, NULL, 0},
	{str_const_init("tm.branch.flags"), /* */
		912, pv_get_tm_branch_flags, NULL,
		NULL, pv_parse_branch_index, NULL, 0},
	{str_const_init("tm.branch.socket"), /* */
		913, pv_get_tm_branch_sock, NULL,
		NULL, pv_parse_branch_index, NULL, 0},
	{str_const_init("tm.branch.flag"), /* */
		914, pv_get_tm_branch_flag, pv_set_tm_branch_flag,
		tm_branch_flag_parse_name, pv_parse_branch_index, NULL, 0},
	{str_const_init("tm.branch.attr"), /* */
		915, pv_get_tm_branch_attr, pv_set_tm_branch_attr,
		pv_parse_avp_name, pv_parse_branch_index, NULL, 0},
	{str_const_init("tm.branch.last_received"), /* */
		916, pv_get_tm_branch_lastrecv, NULL,
		NULL, pv_parse_branch_index, NULL, 0},
	{str_const_init("tm.branch.type"), /* */
		917, pv_get_tm_branch_type, NULL,
		NULL, pv_parse_branch_index, NULL, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};


static const mi_export_t mi_cmds [] = {
	{ MI_TM_UAC, 0, MI_ASYNC_RPL_FLAG|MI_NAMED_PARAMS_ONLY, 0, {
		{mi_tm_uac_dlg_1, {"method", "ruri", "headers", 0}},
		{mi_tm_uac_dlg_2, {"method", "ruri", "headers", "next_hop", 0}},
		{mi_tm_uac_dlg_3, {"method", "ruri", "headers", "socket", 0}},
		{mi_tm_uac_dlg_4, {"method", "ruri", "headers", "body", 0}},
		{mi_tm_uac_dlg_5, {"method", "ruri", "headers", "next_hop", "socket", 0}},
		{mi_tm_uac_dlg_6, {"method", "ruri", "headers", "next_hop", "body", 0}},
		{mi_tm_uac_dlg_7, {"method", "ruri", "headers", "socket", "body", 0}},
		{mi_tm_uac_dlg_8, {"method", "ruri", "headers", "next_hop", "socket",
						   "body", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ MI_TM_CANCEL, 0, 0, 0, {
		{mi_tm_cancel, {"callid", "cseq", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ MI_TM_HASH, 0, 0, 0, {
		{mi_tm_hash, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ MI_TM_REPLY, 0, MI_NAMED_PARAMS_ONLY, 0, {
		{mi_tm_reply_1, {"code", "reason", "trans_id", "to_tag", 0}},
		{mi_tm_reply_2, {"code", "reason", "trans_id", "to_tag",
						   "new_headers", 0}},
		{mi_tm_reply_3, {"code", "reason", "trans_id", "to_tag",
						   "body", 0}},
		{mi_tm_reply_4, {"code", "reason", "trans_id", "to_tag",
						   "new_headers", "body", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
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
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,      /* exported functions */
	NULL,      /* exported async functions */
	params,    /* exported variables */
	mod_stats, /* exported statistics */
	mi_cmds,   /* exported MI functions */
	mod_items, /* exported pseudo-variables */
	0,		   /* exported transformations */
	0,         /* extra processes */
	0,         /* module pre-initialization function */
	mod_init,  /* module initialization function */
	(response_function) reply_received,
	(destroy_function) tm_shutdown,
	child_init,/* per-child init function */
	0          /* reload confirm function */
};



/**************************** fixup functions ******************************/
static int free_fixup_Xroute(void** param)
{
	if (*param)
		unref_script_route( (struct script_route_ref *)*param );
	return 0;
}


static int fixup_froute(void** param)
{
	struct script_route_ref *rt;

	rt = ref_script_route_by_name_str( (str*)*param,
			sroutes->failure, FAILURE_RT_NO, FAILURE_ROUTE, 0);
	if ( !ref_script_route_is_valid(rt) ) {
		LM_ERR("failure route <%.*s> does not exist\n",
			((str*)*param)->len, ((str*)*param)->s);
		return -1;
	}

	*param = (void*)rt;

	return 0;
}


static int fixup_rroute(void** param)
{
	struct script_route_ref *rt;

	rt = ref_script_route_by_name_str( (str*)*param,
			sroutes->onreply, ONREPLY_RT_NO, ONREPLY_ROUTE, 0);
	if ( !ref_script_route_is_valid(rt) ) {
		LM_ERR("onreply route <%.*s> does not exist\n",
			((str*)*param)->len, ((str*)*param)->s);
		return -1;
	}

	*param = (void*)rt;

	return 0;
}


static int fixup_broute(void** param)
{
	struct script_route_ref *rt;

	rt = ref_script_route_by_name_str( (str*)*param,
			sroutes->branch, BRANCH_RT_NO, BRANCH_ROUTE, 0);
	if ( !ref_script_route_is_valid(rt) ) {
		LM_ERR("branch route <%.*s> does not exist\n",
			((str*)*param)->len, ((str*)*param)->s);
		return -1;
	}

	*param = (void*)rt;

	return 0;
}

static str t_relay_flag_names[] = {
	str_init("no-auto-477"),     /* TM_T_RELAY_noerr_FLAG */
	str_init("no-dns-failover"), /* TM_T_RELAY_nodnsfo_FLAG */
	str_init("pass-reason-hdr"), /* TM_T_RELAY_reason_FLAG */
	str_init("allow-no-cancel"), /* TM_T_RELAY_do_cancel_dis_FLAG */
	STR_NULL
};

static int flag_fixup(void** param)
{
	if (fixup_named_flags(param, t_relay_flag_names, NULL, NULL) < 0)
		return -1;

	*param = (void*)((unsigned long)((unsigned int)(unsigned long)*param)<<1);
	return 0;
}


static int fixup_phostport2proxy(void** param)
{
	struct proxy_l *proxy;
	str s = *(str*)*param;
	int port;
	int proto;
	str host;

	if (s.s == NULL || s.len == 0) {
		LM_CRIT("empty parameter\n");
		return E_UNSPEC;
	}

	if (parse_phostport(s.s, s.len, &host.s, &host.len, &port, &proto)!=0){
		LM_CRIT("invalid parameter <%.*s>\n",s.len, s.s);
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

static int fixup_free_proxy(void **param)
{
	free_proxy(*param);
	pkg_free(*param);
	return 0;
}


static int fixup_reply_code(void **param)
{
	if (*(int*)*param < 100 || *(int*)*param > 699) {
		LM_ERR("wrong value [%d] for param! - Allowed only"
			" 1xx - 6xx \n", *(int*)*param);
		return E_CFG;
	}

	return 0;
}

static int fixup_local_replied(void** param)
{
	int n = 0;
	str *s = (str*)*param;

	if (strncasecmp(s->s,"all",3)==0) {
		n = 0;
	} else if (strncasecmp(s->s,"branch",6)==0) {
		n = 1;
	} else if (strncasecmp(s->s,"last",4)==0) {
		n = 2;
	} else {
		LM_ERR("invalid param \"%.*s\"\n", s->len, s->s);
		return E_CFG;
	}

	*param=(void*)(long)n;
	return 0;
}


static int fixup_cancel_branch(void** param)
{
	unsigned int flags = 0;
	str *s = (str*)*param;
	int i;

	for (i=0; i < s->len; i++)
		switch (s->s[i]) {
			case 'a':
			case 'A':
				flags |= TM_CANCEL_BRANCH_ALL;
				break;
			case 'o':
			case 'O':
				flags |= TM_CANCEL_BRANCH_OTHERS;
				break;
			default:
				LM_ERR("unsupported flag '%c'\n",s->s[i]);
				return -1;
		}

	*param = (void*)(unsigned long)flags;
	return 0;
}

static int fixup_inject_source(void **param)
{
	unsigned int flags = 0;
	str *s = (str *)*param;

	if ( strncasecmp(s->s, "msg", 3)==0 || strncasecmp(s->s, "message", 7)==0 ) {
		flags |= TM_INJECT_SRC_MSG;
	} else
	if ( strncasecmp(s->s, "event", 5)==0 || strncasecmp(s->s, "events", 6)==0 ) {
		flags |= TM_INJECT_SRC_EVENT;
	} else {
		LM_ERR("unsupported injection source '%.*s'\n", s->len, s->s);
		return -1;
	}

	*param = (void*)(unsigned long)flags;
	return 0;
}

static int fixup_inject_flags(void **param)
{
	unsigned int i, flags = 0;
	str *s = (str *)*param;

	if ( s->len==6 && strncasecmp(s->s, "cancel", 6)==0 ) {
		flags |= TM_INJECT_FLAG_CANCEL;
	} else {
		for( i=0 ; i<s->len ; i++ )
			switch (s->s[i]) {
				case 'c':
					flags |= TM_INJECT_FLAG_CANCEL;
					break;
				case 'l':
					flags |= TM_INJECT_FLAG_LAST;
					break;
				default:
					LM_ERR("unknown injection flag '%c', ignoring\n",
						s->s[i]);
			}
	}

	LM_DBG("injection flags '%X' detected\n", flags);
	*param = (void*)(unsigned long)flags;
	return 0;
}

/***************************** init functions *****************************/
int load_tm( struct tm_binds *tmb)
{
	tmb->register_tmcb = register_tmcb;

	/* relay function */
	tmb->t_relay = w_t_relay;

	/* reply functions */
	tmb->t_reply = (treply_f)w_t_reply;
	tmb->t_reply_with_body = t_reply_with_body;
	tmb->t_gen_totag = t_gen_totag;

	/* transaction location/status functions */
	tmb->t_newtran = w_t_newtran;
	tmb->t_is_local = t_is_local;
	tmb->t_check_trans = t_check_trans;
	tmb->t_get_trans_ident = t_get_trans_ident;
	tmb->t_lookup_ident = t_lookup_ident;
	tmb->t_gett = get_t;
	tmb->t_sett = set_t;
	tmb->t_get_e2eackt = get_e2eack_t;
	tmb->t_get_picked = t_get_picked_branch;
	tmb->t_set_remote_t = t_set_remote_t;

	tmb->t_lookup_original_t = t_lookupOriginalT;
	tmb->t_release_trans = t_release_transaction;
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
	tmb->free_dlg = free_dlg;
	tmb->print_dlg = print_dlg;
	tmb->setlocalTholder = setlocalTholder;
	tmb->get_branch_index = get_branch_index;
	tmb->t_wait_for_new_branches = w_t_wait_for_new_branches;
	tmb->t_inject_ul_event_branch = t_inject_ul_event_branch;

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


static int do_t_cleanup( struct sip_msg *req, void *bar)
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

	if ( (t=get_t())!=NULL && t!=T_UNDEFINED && /* we have a transaction */
	t->uas.request && req->REQ_METHOD==t->uas.request->REQ_METHOD) {
		/* check the UAS request not yet updated from script msg */
		LOCK_REPLIES(t);
		if (t->uas.request->msg_flags & FL_SHM_UPDATED)
			LM_DBG("transaction %p already updated! Skipping update!\n", t);
		else
			update_cloned_msg_from_msg( t->uas.request, req);
		UNLOCK_REPLIES(t);
	}

	return t_unref(req) == 0 ? SCB_DROP_MSG : SCB_RUN_ALL;
}


static int script_init( struct sip_msg *msg, void *bar)
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

	if (msg->REQ_METHOD == METHOD_CANCEL && is_anycast(msg->rcv.bind_address) &&
			tm_anycast_cancel(msg) == 0)
		return SCB_DROP_MSG;

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

	minor_branch_flag =
		get_flag_id_by_name(FLAG_TYPE_BRANCH, minor_branch_flag_str, 0);

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
		(void*)(long)set, TM_TIMER_ITV_S, TIMER_FLAG_DELAY_ON_DELAY) < 0 ) {
			LM_ERR("failed to register timer for set %d\n",set);
			return -1;
		}
		if (register_utimer( "tm-utimer", utimer_routine,
		(void*)(long)set, TM_UTIMER_ITV_US, TIMER_FLAG_DELAY_ON_DELAY)<0) {
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

	if (tm_init_cluster() < 0) {
		LM_ERR("cannot initialize cluster support for transactions!\n");
		LM_WARN("running without cluster support for transactions!\n");
	}

	if (tm_local_reply_route_s)
	{
		tm_local_reply_route = ref_script_route_by_name(
			tm_local_reply_route_s,
			sroutes->onreply, RT_NO, REQUEST_ROUTE, 0);
		if (!ref_script_route_is_valid(tm_local_reply_route))
		{
			LM_ERR("route <%s> does not exist\n",tm_local_reply_route_s);
			return -1;
		}
	}

	if (tm_local_request_route_s)
	{
		tm_local_request_route = ref_script_route_by_name(
			tm_local_request_route_s,
			sroutes->request, RT_NO, REQUEST_ROUTE, 0);
		if (!ref_script_route_is_valid(tm_local_request_route))
		{
			LM_ERR("route <%s> does not exist\n",tm_local_request_route_s);
			return -1;
		}
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
static int t_check_status(struct sip_msg* msg, regex_t *regexp)
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
	n = regexec(regexp, status, 1, &pmatch, 0);

	if (backup) status[msg->first_line.u.reply.status.len] = backup;
	if (n!=0) return -1;
	return 1;
}


static int t_check_trans(struct sip_msg* msg)
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
				return -2;
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


static int t_local_replied(struct sip_msg* msg, void *type)
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


static int w_t_reply(struct sip_msg* msg, unsigned int code, str* text)
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
			return t_reply_unsafe(t, msg, code, text);
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
			return t_reply( t, msg, code, text);
		default:
			LM_CRIT("unsupported route_type (%d)\n", route_type);
			return -1;
	}
}


static int w_pv_t_reply(struct sip_msg *msg, unsigned int* code, str* text)
{
	return w_t_reply(msg, *code, text);
}


static int w_t_newtran( struct sip_msg* p_msg)
{
	return t_newtran( p_msg , 0 /*no full UAS cloning*/);
}


static int w_t_on_negative( struct sip_msg* msg, void *go_to)
{
	t_on_negative( (struct script_route_ref*) go_to );
	return 1;
}


static int w_t_on_reply( struct sip_msg* msg, void *go_to)
{
	t_on_reply( (struct script_route_ref*) go_to );
	return 1;
}


static int w_t_on_branch( struct sip_msg* msg, void *go_to)
{
	t_on_branch( (struct script_route_ref*) go_to );
	return 1;
}


static int w_t_replicate(struct sip_msg *p_msg, str *dst, void *flags)
{
	return t_replicate( p_msg, dst, (int)(long)flags);
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


static int w_t_relay( struct sip_msg  *p_msg , void *flags, struct proxy_l *proxy)
{
	struct proxy_l *p = NULL;
	struct cell *t;
	int ret;

	t=get_t();

	if (proxy && (p=clone_proxy(proxy))==0) {
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

		if (((int)(long)flags)&TM_T_RELAY_nodnsfo_FLAG)
			t->flags|=T_NO_DNS_FAILOVER_FLAG;
		if (((int)(long)flags)&TM_T_RELAY_reason_FLAG)
			t->flags|=T_CANCEL_REASON_FLAG;
		if ( (((int)(long)flags)&TM_T_RELAY_do_cancel_dis_FLAG) &&
		tm_has_request_disponsition_no_cancel(p_msg)==0 )
			t->flags|=T_MULTI_200OK_FLAG;

		if (route_type==FAILURE_ROUTE) {
			/* If called from failure route we need reset the branch counter to
			 * ignore the previous set of branches (already terminated) */
			ret = t_forward_nonack( t, p_msg, p, 1/*reset*/,1/*locked*/);
		} else {
			/* if called from request route and the transaction was previously
			 * created, better lock here to avoid any overlapping with 
			 * branch injection from other processes */
			LOCK_REPLIES(t);

			/* update the transaction only if in REQUEST route; for other types
			   of routes we do not want to inherit the local changes */
			if (route_type==REQUEST_ROUTE)
				update_cloned_msg_from_msg( t->uas.request, p_msg);

			ret = t_forward_nonack( t, p_msg, p, 1/*reset*/,1/*locked*/);
			UNLOCK_REPLIES(t);
		}
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


static int t_cancel_trans(struct cell *t, str *extra_hdrs)
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
static int w_t_cancel_branch(struct sip_msg *msg, void *sflags)
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


static int w_t_add_hdrs(struct sip_msg* msg, str *val)
{
	struct cell *t;

	t=get_t();

	if (t==NULL || t==T_UNDEFINED) {
		/* no transaction */
		return -1;
	}

	if (t->extra_hdrs.s) shm_free(t->extra_hdrs.s);
	t->extra_hdrs.s = (char*)shm_malloc(val->len);
	if (t->extra_hdrs.s==NULL) {
		LM_ERR("no more shm mem\n");
		return -1;
	}
	t->extra_hdrs.len = val->len;
	memcpy( t->extra_hdrs.s , val->s, val->len );

	return 1;
}


static int w_t_new_request(struct sip_msg* msg, str *method,
			str *ruri, str *from, str *to, str *body, str *p_ctx)
{
#define CONTENT_TYPE_HDR      "Content-Type: "
#define CONTENT_TYPE_HDR_LEN  (sizeof(CONTENT_TYPE_HDR)-1)
	static dlg_t dlg;
	struct usr_avp **avp_list;
	str headers;
	int_str ctx;
	char *p;

	memset( &dlg, 0, sizeof(dlg_t));

	LM_DBG("setting METHOD to <%.*s>\n", method->len, method->s);

	/* ruri - next hop is the same as RURI */
	dlg.hooks.next_hop = dlg.hooks.request_uri = ruri;
	LM_DBG("setting RURI to <%.*s>\n",
		dlg.hooks.next_hop->len, dlg.hooks.next_hop->s);

	/* FROM URI + display */
	if ( (p=q_memrchr(from->s, ' ', from->len))==NULL ) {
		/* no display, only FROM URI */
		dlg.loc_uri = *from;
		dlg.loc_dname.s = NULL;
		dlg.loc_dname.len = 0;
	} else {
		/* display + URI */
		dlg.loc_uri.s = p+1;
		dlg.loc_uri.len = from->s+from->len - dlg.loc_uri.s;
		dlg.loc_dname.s = from->s;
		dlg.loc_dname.len = p - from->s;
	}
	LM_DBG("setting FROM to <%.*s> + <%.*s>\n",
		dlg.loc_dname.len, dlg.loc_dname.s,
		dlg.loc_uri.len, dlg.loc_uri.s);

	/* TO URI + display */
	if ( (p=q_memrchr(to->s, ' ', to->len))==NULL ) {
		/* no display, only TO URI */
		dlg.rem_uri = *to;
		dlg.rem_dname.s = NULL;
		dlg.rem_dname.len = 0;
	} else {
		/* display + URI */
		dlg.rem_uri.s = p+1;
		dlg.rem_uri.len = to->s+to->len - dlg.rem_uri.s;
		dlg.rem_dname.s = to->s;
		dlg.rem_dname.len = p - to->s;
	}
	LM_DBG("setting TO to <%.*s> + <%.*s>\n",
		dlg.rem_dname.len, dlg.rem_dname.s,
		dlg.rem_uri.len, dlg.rem_uri.s);

	/* BODY and Content-Type */
	if (body!=NULL) {
		if ( (p=q_memchr(body->s, ' ', body->len))==NULL ) {
			LM_ERR("Content Type not found in the beginning of body <%.*s>\n",
				body->len, body->s);
			return -1;
		}
		/* build the Content-type header */
		headers.len = CONTENT_TYPE_HDR_LEN + (p-body->s) + CRLF_LEN;
		if ( (headers.s=(char*)pkg_malloc(headers.len))==NULL ) {
			LM_ERR("failed to get pkg mem (needed %d)\n",headers.len);
			return -1;
		}
		memcpy( headers.s, CONTENT_TYPE_HDR, CONTENT_TYPE_HDR_LEN);
		memcpy( headers.s+CONTENT_TYPE_HDR_LEN, body->s, p-body->s);
		memcpy( headers.s+CONTENT_TYPE_HDR_LEN+(p-body->s), CRLF, CRLF_LEN);
		/* set the body */
		body->len = body->s + body->len - (p+1);
		body->s = p + 1;
		LM_DBG("setting BODY to <%.*s> <%.*s>\n",
			headers.len, headers.s,
			body->len, body->s );
	} else {
		headers.s = NULL;
		headers.len = 0;
	}

	/* context value */
	if (p_ctx!=NULL) {
		ctx.s = *p_ctx;
		LM_DBG("setting CTX AVP to <%.*s>\n", ctx.s.len, ctx.s.s);
		avp_list = set_avp_list( &dlg.avps );
		if (add_avp( AVP_VAL_STR, uac_ctx_avp_id, ctx) < 0)
			LM_ERR("failed to add ctx ADP, ignoring...\n");
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
	if ( t_uac(method, headers.s?&headers:NULL, body,
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


int w_t_inject_branches(struct sip_msg* msg, void *source, void *extra_flags)
{
	struct cell *t;
	int is_local=0;
	int rc;
	int flags = ((int)(long)source) | ((int)(long)extra_flags);

	/* first get the transaction */
	t = get_t();
	if (t!=T_NULL_CELL && t!=T_UNDEFINED) {
		/* there is a T in the local processing, use it */
		is_local = 1;
	} else {
		/* no T in this context, look for an remote T ID*/
		if (remote_T==NULL) {
			LM_DBG("no transaction (local or remote) to be used\n");
			return -1;
		}
		if (remote_T->hash==0 && remote_T->label==0) {
			LM_BUG("invalid T ID (bad hexa %d,%d) found in remote_T\n",
				remote_T->hash, remote_T->label);
			return -1;
		}
		/* get the remote transaction */
		if (t_lookup_ident( &t, remote_T->hash, remote_T->label)<0) {
			LM_DBG("transaction %u:%u not found anymore\n",
				remote_T->hash, remote_T->label);
			return -1;
		}
		/* remember that this trasaction is ref++ by us !! */
	}

	if (!is_local)
		LOCK_REPLIES(t);

	/* we have the transaction to operate with, do the stuff now */
	rc = t_inject_branch( t, msg, flags);

	if (!is_local) {
		UNLOCK_REPLIES(t);
		UNREF(t);
		set_t(NULL);
	}

	return rc;
}


int w_t_wait_for_new_branches(struct sip_msg* msg)
{
	return t_wait_for_new_branches(msg, 0);
}


static int t_wait_for_new_branches(struct sip_msg* msg,
													unsigned int* br_to_wait)
{
	struct cell *t;
	int last_branch;

	t=get_t();

	if (t==NULL || t==T_UNDEFINED) {
		/* no transaction */
		return -1;
	}

	if (msg->REQ_METHOD!=METHOD_INVITE) {
		LM_ERR("this function is intended to be used for INVITEs ONLY!!\n");
		return -1;
	}

	/* if we have a branch limit (how many branches to wait for), push into
	 * the br_flags (WARN, this is a reused field) the idx of the last allowed
	 * branch - after that this phony brnach will NOT act anymore as a
	 * delayer for further more branches.
	 */
	last_branch = br_to_wait ? (t->nr_of_outgoings+*br_to_wait+1) : 0;
	if (add_phony_uac(t, last_branch)<0) {
		LM_ERR("failed to add phony UAC\n");
		return -1;
	}

	return 1;
}


static int w_t_wait_no_more_branches(struct sip_msg* msg)
{
	struct cell *t;

	t=get_t();

	if (t==NULL || t==T_UNDEFINED) {
		/* no transaction */
		return -1;
	}

	if (t_wait_no_more_branches(t, 0)<0)
		return -1;

	return 1;
}


static int t_reply_by_callid(struct sip_msg* msg, unsigned int* code, str* text, str* callid, str* cseq_number)
{
	struct cell *trans;
	int n;

	if (!callid && msg->callid==NULL && ((parse_headers(msg, HDR_CALLID_F, 0) ==-1) || (msg->callid==NULL)) ) {
		/* could not get callid */
		return -2;
	}

	if (!cseq_number && !msg->cseq && ((parse_headers(msg, HDR_CSEQ_F, 0) == -1) || !msg->cseq)) {
		/* could not get cseq */
		return -3;
	}

	if(t_lookup_callid( &trans, callid ? *callid : msg->callid->body, cseq_number ? *cseq_number : get_cseq(msg)->number) < 0) {
		/* transaction not found */
		return -4;
	}

	n = t_reply_with_body( trans, *code, text, 0, 0, 0);

	return n;
}


static int t_get_branch_idx_by_attr(struct sip_msg* msg,
			str* attr, str* val_s, int *val_i, pv_spec_t *result, int *offset)
{
	struct cell *t;
	int attr_id;
	int branch;
	struct usr_avp *avp;
	int_str avp_val;
	pv_value_t ret_val, in_val;

	t=get_t();

	if (t==NULL || t==T_UNDEFINED) {
		/* no transaction */
		return -2;
	}

	if ( (attr_id=get_avp_id(attr))<0 ) {
		LM_ERR("failed to get ID for the <%.*s> attribute\n",
			attr->len,attr->s);
		return -2;
	}
	memset(&in_val, 0, sizeof in_val);

	if (val_s) {
		in_val.flags = PV_VAL_STR;
		in_val.rs = *val_s;
	} else if (val_i) {
		in_val.flags = PV_VAL_INT;
		in_val.ri = *val_i;
	} else {
		in_val.flags = PV_VAL_NULL;
	}

	for ( branch=offset?*offset:0 ; branch<t->nr_of_outgoings ; branch++) {
		/* iterate the attrs for matching the name */
		for ( avp=t->uac[branch].battrs ; avp ; avp=avp->next) {
			if (attr_id == avp->id) {
				/* attr name matching */
				if (val_s==NULL && val_i==NULL) {
					/* no value searched , so we have a finding here */
					get_avp_val( avp, &avp_val );
					break;
				} else {
					get_avp_val( avp, &avp_val );
					/* do some complex matching between the pv_value and AVP */
					if ( (avp->flags&AVP_VAL_NULL && in_val.flags&PV_VAL_NULL)
					  ||     /*      ^^^^ both values are null */
					(!(avp->flags&AVP_VAL_STR) && in_val.flags&PV_VAL_INT &&
					avp_val.n==in_val.ri )
					  ||     /*      ^^^^ both values are int */
					(avp->flags&AVP_VAL_STR && in_val.flags&PV_VAL_STR &&
					str_match(&avp_val.s,&in_val.rs)==1)
					)  {    /*      ^^^^ both values are str */
						/* we have a matching */
						break;
					}
				}
			}
		}
		/* anything founds? */
		if (avp) {
			if (result) {
				ret_val.flags = PV_TYPE_INT|PV_VAL_INT;
				ret_val.ri = branch;
				if (pv_set_value(msg, result, 0, &ret_val) != 0) {
					LM_ERR("failed to set the output attr value!\n");
					return -1;
				}
			}

			return 1;
		}
	}

	/* nothing found, return NULL and -1 retcode */
	if (result) {
		ret_val.flags = PV_VAL_NULL;
		if (pv_set_value(msg, result, 0, &ret_val) != 0) {
			LM_ERR("failed to set the output attr value!\n");
			return -1;
		}
	}

	return -1;
}


/******************** pseudo-variable functions *************************/

static int pv_get_tm_branch_idx(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	int l = 0;
	char *ch = NULL;

	if(msg==NULL || res==NULL)
		return -1;

	if (route_type!=BRANCH_ROUTE && route_type!=ONREPLY_ROUTE &&
	route_type!=FAILURE_ROUTE) {
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
	if (!(t = get_t()) || t == T_UNDEFINED) {
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

static int pv_get_tm_branch_reply_code(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct cell *t;
	int code;
	int branch;
	int idxf;

	if(msg==NULL || res==NULL)
		return -1;

	/* first get the transaction */
	if (!(t = get_t()) || t == T_UNDEFINED)
		return pv_get_null(msg, param, res);

	if (param->pvi.type != 0) {
		if(pv_get_spec_index(msg, param, &branch, &idxf)!=0 ||
				idxf == PV_IDX_APPEND || idxf == PV_IDX_APPEND) {
			LM_ERR("invalid index\n");
			return -1;
		}
	} else {
		branch = _tm_branch_index;
	}

	/* it is not our job to find a proper branch, if not explicit asked for */
	code = t->uac[branch].last_received;

	LM_DBG("reply code for branch %d is <%d>\n", branch, code);

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
	if (!(t = get_t()) || t == T_UNDEFINED) {
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

	avp_list = pv_get_bavp_list();
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
	} else
		pv_get_null(msg, param, val);

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

	if (!msg) {
		LM_ERR("bavp set but no msg found!\n");
		goto error;
	}

	if (!param) {
		LM_ERR("bad parameters\n");
		goto error;
	}

	avp_list = pv_get_bavp_list();
	if (!avp_list) {
		LM_DBG("cannot find the branch avp list!\n");
		return -2;
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


static struct usr_avp** pv_get_bavp_list(void)
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

	/* "$T_fr_timeout = NULL" will set the default timeout */
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

static int pv_get_t_id(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
#define INTasHEXA_SIZE (sizeof(int)*2)
	static char buf[INTasHEXA_SIZE+1+INTasHEXA_SIZE];
	struct cell *t;
	char *p;
	int size;

	if (!msg || !res)
		return -1;

	t = get_t();

	if (t==NULL || t==T_UNDEFINED) {
		res->flags = PV_VAL_NULL;
		return 0;
	}

	p = buf;
	size = INTasHEXA_SIZE+1+INTasHEXA_SIZE;
	/* write the label at the end */
	int2reverse_hex( &p, &size, t->label );
	*(p++) = '.';
	size--;
	/* write the hash */
	int2reverse_hex( &p, &size, t->hash_index );

	res->flags = PV_VAL_STR;
	res->rs.s = buf;
	res->rs.len = p-buf;

	return 0;
}


#define BR_URI_ID        1
#define BR_DURI_ID       2
#define BR_Q_ID          3
#define BR_PATH_ID       4
#define BR_FLAGS_ID      5
#define BR_FLAG_ID       6
#define BR_SOCKET_ID     7
#define BR_ATTR_ID       8
#define BR_LASTRECV_ID   9
#define BR_TYPE_ID      10

static int tm_branch_flag_parse_name(pv_spec_p sp, const str *in)
{
	unsigned int idx;
	if (sp==NULL || in==NULL || in->s==NULL || in->len==0)
		return -1;

	if ( (idx=fixup_flag(FLAG_TYPE_BRANCH, in))==NAMED_FLAG_ERROR) {
		LM_ERR("failed to fix the flag <%.*s>\n",in->len,in->s);
		return -1;
	}

	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = 0;

	sp->pvp.pvn.u.isname.name.n = idx;

	return 0;
}


# define BRANCH_IDX_ACTIVE_MASK  (1<<16)
static int pv_parse_branch_index(pv_spec_p sp, const str *in)
{
	#define BRANCH_IDX_SUFFIX_ALL "all"
	#define BRANCH_IDX_SUFFIX_ACTIVE "active"
	char *p;
	str suffix, new_in;
	unsigned int mask = 0;

	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;

	new_in = *in;

	if ( (p=q_memrchr( in->s, '/', in->len))!=NULL) {
		/* we do may have a suffix */
		suffix.s = p+1;
		suffix.len = in->s+in->len - suffix.s;
		if ( (suffix.len==(sizeof(BRANCH_IDX_SUFFIX_ALL)-1)) &&
		strncasecmp(suffix.s,BRANCH_IDX_SUFFIX_ALL,suffix.len)==0) {
			/* ok, this is the default, nothing to change */
			mask = 0;
			new_in.len = p - in->s;
		} else
		if ( (suffix.len==(sizeof(BRANCH_IDX_SUFFIX_ACTIVE)-1)) &&
		strncasecmp(suffix.s,BRANCH_IDX_SUFFIX_ACTIVE,suffix.len)==0) {
			mask = BRANCH_IDX_ACTIVE_MASK;
			new_in.len = p - in->s;
		} else {
			/* just ignore, do not take it into consideration, we do not
			 * know what it is, maybe part of a pvar as index */
		}
	}
	if (pv_parse_index( sp, &new_in)<0)
		return -1;
	sp->pvp.pvi.type |= mask; /* take care and remove this mask BEFORE
	* evaluating the idx with the generic functions (as the type will 
	* not be recognized */
	return 0;
}


static inline int _pv_get_tm_branch_field(struct sip_msg *msg,
								pv_param_t *param, pv_value_t *res, int field)
{
	struct cell *t;
	int idx, idxf;
	int_str attr_val;
	int attr_name;
	unsigned short attr_flags;
	struct usr_avp **old_list, *avp;
	int active_indexing = 0;

	if(msg==NULL || res==NULL)
		return -1;

	t = get_t();
	if (t==NULL || t==T_UNDEFINED)
		return -1;

	/* get the index */
	if (param->pvn.type & BRANCH_IDX_ACTIVE_MASK) {
		active_indexing = 1;
		param->pvn.type &= ~BRANCH_IDX_ACTIVE_MASK;
	}
	if (pv_get_spec_index(msg, param, &idx, &idxf)!=0) {
		LM_ERR("invalid index\n");
		return -1;
	}

	if (idxf==PV_IDX_ALL) {
		LM_ERR("STAR/ALL index not supported\n");
		return -1;
	}

	if (idxf==0 && idx==0) {
		/* no index used at all, return for the current branch */
		idx = get_branch_index();
	} else {
		/* must be numerical index */
		if (active_indexing)
			idx += t->first_branch;
		if (idx<0) {
			/* index from the end */
			if (-idx > t->nr_of_outgoings) /* underflow */
				return pv_get_null(NULL, NULL, res);
			idx = t->nr_of_outgoings + idx;
		} else
		if (idx >= t->nr_of_outgoings) /*overflow*/
			return pv_get_null(NULL, NULL, res);
	}

	/* we have a valid TM-branch index now */
	switch (field) {
		case BR_URI_ID: /* return URI */
			res->rs = t->uac[idx].uri;
			res->flags = PV_VAL_STR;
			break;
		case BR_Q_ID: /* return Q */
			res->rs.s = q2str(t->uac[idx].q, (unsigned int*)&res->rs.len);
			res->flags = PV_VAL_STR;
			break;
		case BR_DURI_ID: /* return DURI */
			if ( ZSTR(t->uac[idx].duri) )
				return pv_get_null(NULL, NULL, res);
			res->rs = t->uac[idx].duri;
			res->flags = PV_VAL_STR;
			break;
		case BR_PATH_ID: /* return PATH */
			if ( ZSTR(t->uac[idx].path_vec) )
				return pv_get_null(NULL, NULL, res);
			res->rs = t->uac[idx].path_vec;
			res->flags = PV_VAL_STR;
			break;
		case BR_FLAGS_ID: /* return all FLAGS */
			if (param->pvn.type==PV_NAME_INTSTR) {
				/* we have the name of a flag */
			}
			res->rs = bitmask_to_flag_list(FLAG_TYPE_BRANCH,
				t->uac[idx].br_flags);
			res->flags = PV_VAL_STR;
			break;
		case BR_FLAG_ID: /* return value of one FLAG */
			if ( t->uac[idx].br_flags & param->pvn.u.isname.name.n ) {
				*res = pv_true;
			} else {
				*res = pv_false;
			}
			break;
		case BR_SOCKET_ID: /* return SOCKET */
			if ( t->uac[idx].request.dst.send_sock==NULL )
				return pv_get_null(NULL, NULL, res);
			res->rs = t->uac[idx].request.dst.send_sock->sock_str;
			res->flags = PV_VAL_STR;
			break;
		case BR_ATTR_ID: /* get one attribute */
			/* get the name of the attribute */
			if (pv_get_avp_name(msg, param, &attr_name, &attr_flags)!=0) {
				LM_ALERT("BUG in getting ATTR name\n");
				return -1;
			}
			/* get the attr now */
			old_list = set_avp_list( &t->uac[idx].battrs );
			avp = search_first_avp( 0, attr_name, &attr_val, 0);
			set_avp_list( old_list );
			/* now return the value */
			if ( avp==NULL || avp->flags&AVP_VAL_NULL)
				return pv_get_null(msg, param, res);
			res->flags = PV_VAL_STR;
			if (avp->flags & AVP_VAL_STR) {
				res->rs = attr_val.s;
			} else {
				res->rs.s = sint2str(attr_val.n, &res->rs.len);
				res->ri = attr_val.n;
				res->flags |= PV_VAL_INT|PV_TYPE_INT;
			}
			break;
		case BR_LASTRECV_ID: /* return LAST RECEIVED */
			if (t->uac[idx].last_received==0)
				return pv_get_null(msg, param, res);
			res->rs.s = sint2str(t->uac[idx].last_received, &res->rs.len);
			res->ri = t->uac[idx].last_received;
			res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
			break;
		case BR_TYPE_ID: /* return TYPE */
			res->flags = PV_VAL_STR;
			if (t->uac[idx].flags | T_UAC_IS_PHONY) {
				res->rs.s = "phony";
				res->rs.len = 5;
			} else {
				res->rs.s = "sip";
				res->rs.len = 3;
			}
			break;

		default:
			LM_CRIT("BUG - unsupported branch ID %d\n",field);
			return pv_get_null(NULL, NULL, res);
	}
	return 0;
}


static int pv_get_tm_branch_uri(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	return _pv_get_tm_branch_field( msg, param, res, BR_URI_ID);
}

static int pv_get_tm_branch_duri(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	return _pv_get_tm_branch_field( msg, param, res, BR_DURI_ID);
}

static int pv_get_tm_branch_q(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	return _pv_get_tm_branch_field( msg, param, res, BR_Q_ID);
}

static int pv_get_tm_branch_path(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	return _pv_get_tm_branch_field( msg, param, res, BR_PATH_ID);
}

static int pv_get_tm_branch_flags(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	return _pv_get_tm_branch_field( msg, param, res, BR_FLAGS_ID);
}

static int pv_get_tm_branch_flag(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	return _pv_get_tm_branch_field( msg, param, res, BR_FLAG_ID);
}

static int pv_get_tm_branch_sock(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	return _pv_get_tm_branch_field( msg, param, res, BR_SOCKET_ID);
}

static int pv_get_tm_branch_attr(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	return _pv_get_tm_branch_field( msg, param, res, BR_ATTR_ID);
}

static int pv_get_tm_branch_lastrecv(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	return _pv_get_tm_branch_field( msg, param, res, BR_LASTRECV_ID);
}

static int pv_get_tm_branch_type(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	return _pv_get_tm_branch_field( msg, param, res, BR_TYPE_ID);
}


static inline int _pv_set_tm_branch_field(struct sip_msg* msg,
						pv_param_t *param,int op, pv_value_t *val, int field)
{
	struct cell *t;
	int idx, idxf;
	int_str attr_val;
	int attr_name;
	unsigned int *flags;
	unsigned short attr_flags;
	struct usr_avp **old_list, *avp;
	int active_indexing = 0;

	if(msg==NULL || param==NULL)
		return -1;

	if (route_type!=BRANCH_ROUTE && route_type!=ONREPLY_ROUTE &&
	route_type!=FAILURE_ROUTE) {
		LM_ERR("illegal route type %d\n",route_type);
		return -1;
	}

	t = get_t();
	if (t==NULL || t==T_UNDEFINED)
		return -1;

	/* get the index */
	if (param->pvn.type & BRANCH_IDX_ACTIVE_MASK) {
		active_indexing = 1;
		param->pvn.type &= ~BRANCH_IDX_ACTIVE_MASK;
	}
	if (pv_get_spec_index(msg, param, &idx, &idxf)!=0) {
		LM_ERR("invalid index\n");
		return -1;
	}

	if (idxf==PV_IDX_ALL) {
		LM_ERR("STAR/ALL index not supported\n");
		return -1;
	}

	if (idxf==0 && idx==0) {
		/* no index used at all, return for the current branch */
		idx = get_branch_index();
	} else {
		/* must be numerical index */
		if (active_indexing)
			idx += t->first_branch;
		if (idx<0) {
			/* index from the end */
			if (-idx > t->nr_of_outgoings) /* underflow */
				return -1;
			idx = t->nr_of_outgoings + idx;
		} else
		if (idx >= t->nr_of_outgoings) /*overflow*/
			return -1;
	}

	/* we have a valid TM-branch index now */
	switch (field) {
		case BR_FLAG_ID: /* set one FLAG */
			if (val==NULL || (val->flags&(PV_VAL_NULL|PV_VAL_NONE))!=0 ||
			(val->flags&PV_TYPE_INT)==0 ) {
				LM_ERR("input for FLAG field found not to be an integer\n");
				return -1;
			}
			/* a bit of a hack, to be able to work on the bflags of the 
			 * current branch in BRANCH route too (as the branch flags are
			 * in MSG, not T->UAC during branch route)*/
			if (route_type==BRANCH_ROUTE && idx==t->nr_of_outgoings)
				flags = &msg->ruri_bflags;
			else
				flags = (unsigned int*)&t->uac[idx].br_flags;
			if (val->ri==0)
				/* reset */
				*flags &=  ~param->pvn.u.isname.name.n;
			else
				/* set */
				*flags |=  param->pvn.u.isname.name.n;
			break;
		case BR_ATTR_ID: /* set one attribute */
			/* get the name of the attribute */
			if (pv_get_avp_name(msg, param, &attr_name, &attr_flags)!=0) {
				LM_ALERT("BUG in getting ATTR name\n");
				return -1;
			}
			/* get ready the value */
			if (!val || val->flags&PV_VAL_NULL) {
				attr_flags |= AVP_VAL_NULL;
			} else
			if(val->flags&PV_TYPE_INT) {
				attr_val.n = val->ri;
			} else {
				attr_val.s = val->rs;
				attr_flags |= AVP_VAL_STR;
			}
			/* set the attr now */
			old_list = set_avp_list( &t->uac[idx].battrs );
			if ( (avp=search_first_avp( 0, attr_name, NULL, 0))!=NULL )
				destroy_avp(avp);
			if ( !(attr_flags&AVP_VAL_NULL) )
				add_avp( attr_flags, attr_name, attr_val);
			set_avp_list( old_list );
			break;
		default:
			LM_CRIT("BUG - unsupported branch ID %d\n",field);
			return -1;
	}
	return 0;
}

static int pv_set_tm_branch_flag(struct sip_msg* msg, pv_param_t *param,
													int op, pv_value_t *val)
{
	return _pv_set_tm_branch_field( msg, param, op, val, BR_FLAG_ID);
}

static int pv_set_tm_branch_attr(struct sip_msg* msg, pv_param_t *param,
													int op, pv_value_t *val)
{
	return _pv_set_tm_branch_field( msg, param, op, val, BR_ATTR_ID);
}

