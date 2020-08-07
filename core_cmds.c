/*
 * Copyright (C) 2019 OpenSIPS Solutions
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
 */

/*
 * Script functions exported by the OpenSIPS core
 */

#include "action.h"
#include "dprint.h"
#include "proxy.h"
#include "forward.h"
#include "parser/msg_parser.h"
#include "parser/parse_uri.h"
#include "ut.h"
#include "mem/mem.h"
#include "globals.h"
#include "dset.h"
#include "flags.h"
#include "serialize.h"
#include "blacklists.h"
#include "cachedb/cachedb.h"
#include "msg_translator.h"
/* needed by tcpconn_add_alias() */
#include "net/tcp_conn_defs.h"

static int fixup_forward_dest(void** param);
static int fixup_destination(void** param);
static int fixup_free_destination(void** param);
static int fixup_mflag(void** param);
static int fixup_bflag(void** param);
static int fixup_qvalue(void** param);
static int fixup_f_send_sock(void** param);
static int fixup_blacklist(void** param);
static int fixup_check_wrvar(void** param);
static int fixup_avp_list(void** param);
static int fixup_check_avp(void** param);
static int fixup_event_name(void** param);
static int fixup_format_string(void** param);
static int fixup_nt_string(void** param);
static int fixup_rewritehost(void **param);
static int fixup_rewritehostport(void **param);
static int fixup_rewriteuser(void **param);
static int fixup_rewriteuserpass(void **param);
static int fixup_rewriteport(void **param);
static int fixup_rewriteuri(void **param);

static int w_forward(struct sip_msg *msg, struct proxy_l *dest);
static int w_send(struct sip_msg *msg, struct proxy_l *dest, str *headers);
static int w_setflag(struct sip_msg *msg, void *flag);
static int w_resetflag(struct sip_msg *msg, void *flag);
static int w_isflagset(struct sip_msg *msg, void *flag);
static int w_setbflag(struct sip_msg *msg, void *flag, int *branch_idx);
static int w_resetbflag(struct sip_msg *msg, void *flag, int *branch_idx);
static int w_isbflagset(struct sip_msg *msg, void *flag, int *branch_idx);
static int w_sethost(struct sip_msg *msg, str *host);
static int w_sethostport(struct sip_msg *msg, str *hostport);
static int w_setuser(struct sip_msg *msg, str *user);
static int w_setuserpass(struct sip_msg *msg, str *userpass);
static int w_setport(struct sip_msg *msg, str *port);
static int w_seturi(struct sip_msg *msg, str *uri);
static int w_prefix(struct sip_msg *msg, str *prefix);
static int w_strip(struct sip_msg *msg, int *nchars);
static int w_strip_tail(struct sip_msg *msg, int *nchars);
static int w_append_branch(struct sip_msg *msg, str *uri, int *qvalue);
static int w_remove_branch(struct sip_msg *msg, int *branch);
static int w_pv_printf(struct sip_msg *msg, pv_spec_t *var, str *fmt_str);
static int w_revert_uri(struct sip_msg *msg);
static int w_setdsturi(struct sip_msg *msg, str *uri);
static int w_resetdsturi(struct sip_msg *msg);
static int w_isdsturiset(struct sip_msg *msg);
static int w_force_rport(struct sip_msg *msg);
static int w_add_local_rport(struct sip_msg *msg);
static int w_force_tcp_alias(struct sip_msg *msg, int *port);
static int w_set_adv_address(struct sip_msg *msg, str *adv_addr);
static int w_set_adv_port(struct sip_msg *msg, str *adv_port);
static int w_f_send_sock(struct sip_msg *msg, struct socket_info *si);
static int w_serialize_branches(struct sip_msg *msg, int *clear_prev,
					int *keep_ord);
static int w_next_branches(struct sip_msg *msg);
static int w_use_blacklist(struct sip_msg *msg, struct bl_head *list);
static int w_unuse_blacklist(struct sip_msg *msg, struct bl_head *list);
static int w_cache_store(struct sip_msg *msg, str *id, str *attr, str *val, 
					int *expire);
static int w_cache_remove(struct sip_msg *msg, str *id, str *attr);
static int w_cache_fetch(struct sip_msg *msg, str *id, str *attr,
					pv_spec_t *res);
static int w_cache_counter_fetch(struct sip_msg *msg, str *id, str *attr,
					pv_spec_t *res);
static int w_cache_add(struct sip_msg *msg, str *id, str *attr,
					int *inc, int *expire, pv_spec_t *new_val);
static int w_cache_sub(struct sip_msg *msg, str *id, str *attr,
					int *dec, int *expire, pv_spec_t *new_val);
static int w_cache_raw_query(struct sip_msg *msg, str *id, str *raw_query,
					pvname_list_t *avp_list);
static int w_raise_event(struct sip_msg *msg, void *ev_id, pv_spec_t *attrs_avp,
					pv_spec_t *vals_avp);
static int w_subscribe_event(struct sip_msg *msg, str *name, str *socket,
					int *expire);
static int w_construct_uri(struct sip_msg *msg, str *proto, str *user,
					str *domain, str *port, str *extra, pv_spec_t *result);
static int w_get_timestamp(struct sip_msg *msg, pv_spec_t *sec_avp,
					pv_spec_t *usec_avp);
static int w_script_trace(struct sip_msg *msg, int *log_level,
					pv_elem_t *fmt_string, void *info_str);
static int w_is_myself(struct sip_msg *msg, str *host, int *port);

static cmd_export_t core_cmds[]={
	{"forward", (cmd_function)w_forward, {
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL,
			fixup_forward_dest, fixup_free_destination}, {0,0,0}},
		ALL_ROUTES},
	{"send", (cmd_function)w_send, {
		{CMD_PARAM_STR, fixup_destination, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"setflag", (cmd_function)w_setflag, {
		{CMD_PARAM_STR|CMD_PARAM_STATIC, fixup_mflag, 0}, {0,0,0}},
		ALL_ROUTES},
	{"resetflag", (cmd_function)w_resetflag, {
		{CMD_PARAM_STR|CMD_PARAM_STATIC, fixup_mflag, 0}, {0,0,0}},
		ALL_ROUTES},
	{"isflagset", (cmd_function)w_isflagset, {
		{CMD_PARAM_STR|CMD_PARAM_STATIC, fixup_mflag, 0}, {0,0,0}},
		ALL_ROUTES},
	{"setbflag", (cmd_function)w_setbflag, {
		{CMD_PARAM_STR|CMD_PARAM_STATIC, fixup_bflag, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"resetbflag", (cmd_function)w_resetbflag, {
		{CMD_PARAM_STR|CMD_PARAM_STATIC, fixup_bflag, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"isbflagset", (cmd_function)w_isbflagset, {
		{CMD_PARAM_STR|CMD_PARAM_STATIC, fixup_bflag, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"sethost", (cmd_function)w_sethost, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"rewritehost", (cmd_function)w_sethost, {
		{CMD_PARAM_STR, fixup_rewritehost, 0}, {0,0,0}},
		ALL_ROUTES},
	{"sethostport", (cmd_function)w_sethostport, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"rewritehostport", (cmd_function)w_sethostport, {
		{CMD_PARAM_STR, fixup_rewritehostport, 0}, {0,0,0}},
		ALL_ROUTES},
	{"setuser", (cmd_function)w_setuser, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"rewriteuser", (cmd_function)w_setuser, {
		{CMD_PARAM_STR, fixup_rewriteuser, 0}, {0,0,0}},
		ALL_ROUTES},
	{"setuserpass", (cmd_function)w_setuserpass, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"rewriteuserpass", (cmd_function)w_setuserpass, {
		{CMD_PARAM_STR, fixup_rewriteuserpass, 0}, {0,0,0}},
		ALL_ROUTES},
	{"setport", (cmd_function)w_setport, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"rewriteport", (cmd_function)w_setport, {
		{CMD_PARAM_STR, fixup_rewriteport, 0}, {0,0,0}},
		ALL_ROUTES},
	{"seturi", (cmd_function)w_seturi, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"rewriteuri", (cmd_function)w_seturi, {
		{CMD_PARAM_STR, fixup_rewriteuri, 0}, {0,0,0}},
		ALL_ROUTES},
	{"prefix", (cmd_function)w_prefix, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"strip", (cmd_function)w_strip, {
		{CMD_PARAM_INT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"strip_tail", (cmd_function)w_strip_tail, {
		{CMD_PARAM_INT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"append_branch", (cmd_function)w_append_branch, {
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL,
			fixup_qvalue, 0}, {0,0,0}},
		ALL_ROUTES},
	{"remove_branch", (cmd_function)w_remove_branch, {
		{CMD_PARAM_INT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"pv_printf", (cmd_function)w_pv_printf, {
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"revert_uri", (cmd_function)w_revert_uri, {
		{0, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"setdsturi", (cmd_function)w_setdsturi, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"resetdsturi", (cmd_function)w_resetdsturi, {
		{0, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"isdsturiset", (cmd_function)w_isdsturiset, {
		{0, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"force_rport", (cmd_function)w_force_rport, {
		{0, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"add_local_rport", (cmd_function)w_add_local_rport, {
		{0, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"force_tcp_alias", (cmd_function)w_force_tcp_alias, {
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"set_advertised_address", (cmd_function)w_set_adv_address, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"set_advertised_port", (cmd_function)w_set_adv_port, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"force_send_socket", (cmd_function)w_f_send_sock, {
		{CMD_PARAM_STR, fixup_f_send_sock, 0}, {0,0,0}},
		ALL_ROUTES},
	{"serialize_branches", (cmd_function)w_serialize_branches, {
		{CMD_PARAM_INT, 0, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"next_branches", (cmd_function)w_next_branches, {
		{0, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"use_blacklist", (cmd_function)w_use_blacklist, {
		{CMD_PARAM_STR, fixup_blacklist, 0}, {0,0,0}},
		ALL_ROUTES},
	{"unuse_blacklist", (cmd_function)w_unuse_blacklist, {
		{CMD_PARAM_STR, fixup_blacklist, 0}, {0,0,0}},
		ALL_ROUTES},
	{"cache_store", (cmd_function)w_cache_store, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"cache_remove", (cmd_function)w_cache_remove, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"cache_fetch", (cmd_function)w_cache_fetch, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR, fixup_check_wrvar, 0}, {0,0,0}},
		ALL_ROUTES},
	{"cache_counter_fetch", (cmd_function)w_cache_counter_fetch, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR, fixup_check_wrvar, 0}, {0,0,0}},
		ALL_ROUTES},
	{"cache_add", (cmd_function)w_cache_add, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_wrvar, 0}, {0,0,0}},
		ALL_ROUTES},
	{"cache_sub", (cmd_function)w_cache_sub, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_wrvar, 0}, {0,0,0}},
		ALL_ROUTES},
	{"cache_raw_query", (cmd_function)w_cache_raw_query, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_NO_EXPAND, fixup_avp_list, 0}, {0,0,0}},
		ALL_ROUTES},
	{"raise_event", (cmd_function)w_raise_event, {
		{CMD_PARAM_STR, fixup_event_name, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0}, {0,0,0}},
		ALL_ROUTES},
	{"subscribe_event", (cmd_function)w_subscribe_event, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"construct_uri", (cmd_function)w_construct_uri, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR, fixup_check_avp, 0}, {0,0,0}},
		ALL_ROUTES},
	{"get_timestamp", (cmd_function)w_get_timestamp, {
		{CMD_PARAM_VAR, fixup_check_avp, 0},
		{CMD_PARAM_VAR, fixup_check_avp, 0}, {0,0,0}},
		ALL_ROUTES},
	{"script_trace", (cmd_function)w_script_trace, {
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_NO_EXPAND, fixup_format_string, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_STATIC, fixup_nt_string, 0},
		{0,0,0}},
		ALL_ROUTES},
	{"is_myself", (cmd_function)w_is_myself, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};


cmd_export_t* find_core_cmd_export_t(char* name, int flags)
{
	cmd_export_t* cmd;

	for(cmd=core_cmds; cmd && cmd->name; cmd++){
		if((strcmp(name, cmd->name)==0)&&((cmd->flags & flags) == flags)){
			LM_DBG("found <%s> core function\n", name);
			return cmd;
		}
	}

	LM_DBG("<%s> not found \n", name);
	return 0;
}


static int fixup_destination(void** param)
{
	str *s = (str*)*param;
	str host;
	int proto=PROTO_NONE, port;

	if (parse_phostport(s->s, s->len, &host.s, &host.len, &port, &proto) != 0) {
		LM_ERR("Failed to parse destination\n");
		return E_CFG;
	}
	*param = mk_proxy(&host,(unsigned short)port, proto, 0);
	if (*param==0) {
		LM_ERR("Failed to create proxy struct\n");
		return E_CFG;
	}

	return 0;
}

static int fixup_free_destination(void** param)
{
	free_proxy(*param);
	pkg_free(*param);
	return 0;
}

static int fixup_forward_dest(void** param)
{
	if (sl_fwd_disabled>0) {
		LM_ERR("stateless forwarding disabled, but forward() "
			"is used!!\n");
		return E_CFG;
	}
	sl_fwd_disabled = 0;

	if (*param == NULL)
		return 0;
	return fixup_destination(param);
}

static int fixup_mflag(void** param)
{
	if ((*param = (void*)(long)fixup_flag(FLAG_TYPE_MSG, (str*)*param)) ==
		(void*)(long)NAMED_FLAG_ERROR) {
		LM_ERR("Fixup flag failed!\n");
		return E_CFG;
	}

	return 0;
}

static int fixup_bflag(void** param)
{
	if ((*param = (void*)(long)fixup_flag(FLAG_TYPE_BRANCH, (str*)*param)) ==
		(void*)(long)NAMED_FLAG_ERROR) {
		LM_ERR("Fixup flag failed!\n");
		return E_CFG;
	}

	return 0;
}

static int fixup_qvalue(void** param)
{
	int rc;
	qvalue_t q;
	str *s = (str*)*param;

	if (s==NULL) {
		*param = (void*)(long)Q_UNSPECIFIED;
		return 0;
	}

	if ((rc = str2q(&q, s->s, s->len)) < 0) {
		LM_ERR("Bad qvalue (%.*s): %s\n", s->len, s->s, qverr2str(rc));
		return E_CFG;
	}

	*param = (void*)(long)q;
	return 0;
}

static int fixup_f_send_sock(void** param)
{
	str *s = (str*)*param;
	str host, host_nt;
	int proto=PROTO_NONE, port;
	struct hostent* he;
	struct socket_info* si;
	struct ip_addr ip;

	if (parse_phostport(s->s, s->len, &host.s, &host.len, &port, &proto) != 0) {
		LM_ERR("Failed to parse socket\n");
		return E_CFG;
	}
	if (pkg_nt_str_dup(&host_nt, &host) < 0) {
		LM_ERR("oom\n");
		return E_OUT_OF_MEM;
	}

	he=resolvehost(host_nt.s,0);
	if (he==0){
		LM_ERR(" could not resolve %s\n", host_nt.s);
		goto error;
	}
	hostent2ip_addr(&ip, he, 0);
	si=find_si(&ip, port, proto);
	if (si==0){
		LM_ERR("bad force_send_socket"
			" argument: %s:%d (opensips doesn't listen on it)\n",
			host_nt.s, port);
		goto error;
	}

	pkg_free(host_nt.s);

	*param = si;
	return 0;

error:
	pkg_free(host_nt.s);
	return E_BAD_ADDRESS;
}

static int fixup_blacklist(void** param)
{
	str *s = (str*)*param;

	if (!str_strcasecmp(s, _str("all")))
		*param = NULL;
	else {
		*param = get_bl_head_by_name(s);
		if (!*param) {
			LM_ERR("[UN]USE_BLACKLIST - list "
				"%.*s not configured\n", s->len, s->s);
			return E_CFG;
		}
	}

	return 0;
}

static int fixup_check_wrvar(void** param)
{
	if (((pv_spec_t *)*param)->setf == NULL) {
		LM_ERR("Output parameter must be a writable variable\n");
		return E_CFG;
	}

	return 0;
}

static int fixup_avp_list(void** param)
{
	str *s = (str*)*param;

	*param = parse_pvname_list(s, PVT_AVP);
	if (!*param) {
		LM_ERR("Failed to parse AVP list\n");
		return E_UNSPEC;
	}

	return 0;
}

static int fixup_check_avp(void** param)
{
	if (((pv_spec_t *)*param)->type != PVT_AVP) {
		LM_ERR("Parameter must be an AVP\n");
		return E_CFG;
	}

	return 0;
}

static int fixup_event_name(void** param)
{
	str *s = (str*)*param;
	event_id_t ev_id;

	ev_id = evi_get_id(s);
	if (ev_id == EVI_ERROR) {
		ev_id = evi_publish_event(*s);
		if (ev_id == EVI_ERROR) {
			LM_ERR("cannot subscribe event\n");
			return E_UNSPEC;
		}
	}

	*param = (void*)(long)ev_id;
	return 0;
}

static int fixup_format_string(void** param)
{
	str *s = (str*)*param;

	if (pv_parse_format(s, (pv_elem_t**)param) < 0) {
		LM_ERR("Failed to parse format string\n");
		return E_CFG;
	}

	return 0;
}

static int fixup_nt_string(void** param)
{
	str *s = (str*)*param;
	str s_nt;

	if (pkg_nt_str_dup(&s_nt, s) < 0) {
		LM_ERR("oom\n");
		return E_OUT_OF_MEM;
	}

	*param = s_nt.s;
	return 0;
}

static int fixup_rewritehost(void **param)
{
	LM_CRIT("'rewritehost()' is deprecated, use sethost() instead\n");
	return -1;
}

static int fixup_rewritehostport(void **param)
{
	LM_CRIT("'rewritehostport()' is deprecated, use sethostport() instead\n");
	return -1;
}

static int fixup_rewriteuser(void **param)
{
	LM_CRIT("'rewriteuser()' is deprecated, use setuser() instead\n");
	return -1;
}

static int fixup_rewriteuserpass(void **param)
{
	LM_CRIT("'rewriteuserpass()' is deprecated, use setuserpass() instead\n");
	return -1;
}

static int fixup_rewriteport(void **param)
{
	LM_CRIT("'rewriteport()' is deprecated, use setport() instead\n");
	return -1;
}

static int fixup_rewriteuri(void **param)
{
	LM_CRIT("'rewriteuri()' is deprecated, use seturi() instead\n");
	return -1;
}


static int w_forward(struct sip_msg *msg, struct proxy_l *dest)
{
	struct sip_uri next_hop, *u;
	struct proxy_l* p;
	int ret;

	if (!dest) {
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
			return E_BAD_ADDRESS;
		}
		/* create a temporary proxy*/
		p=mk_proxy(u->maddr_val.len?&u->maddr_val:&u->host,
			u->port_no, u->proto, (u->type==SIPS_URI_T)?1:0 );
		if (p==0){
			LM_ERR("bad host name in uri, dropping packet\n");
			return E_BAD_ADDRESS;
		}
	} else {
		if (0==(p=clone_proxy(dest))) {
			LM_ERR("failed to clone proxy, dropping packet\n");
			return E_OUT_OF_MEM;
		}
	}

	ret=forward_request(msg, p);
	free_proxy(p); /* frees only p content, not p itself */
	pkg_free(p);

	if (ret==0)
		ret=1;
	return ret;
}

static int w_send(struct sip_msg *msg, struct proxy_l *dest, str *headers)
{
	int ret;
	union sockaddr_union* to;
	struct proxy_l* p;
	int len;
	char* tmp;

	to=(union sockaddr_union*)
			pkg_malloc(sizeof(union sockaddr_union));
	if (to==0){
		LM_ERR("memory allocation failure\n");
		return E_OUT_OF_MEM;
	}
	if (0==(p=clone_proxy(dest))) {
		LM_ERR("failed to clone proxy, dropping packet\n");
		return E_OUT_OF_MEM;
	}
	ret=hostent2su(to, &p->host, p->addr_idx,
				(p->port)?p->port:SIP_PORT );
	if (ret==0){
		if (headers) {
			/* build new msg */
			tmp = pkg_malloc(msg->len + headers->len);
			if (!tmp) {
				LM_ERR("memory allocation failure\n");
				return E_OUT_OF_MEM;
			}
			LM_DBG("searching for first line %d\n",
					msg->first_line.len);
			/* search first line of previous msg */
			/* copy headers */
			len = msg->first_line.len;
			memcpy(tmp, msg->buf, len);
			memcpy(tmp + len, headers->s, headers->len);
			memcpy(tmp + len + headers->len,
					msg->buf + len, msg->len - len);
			ret = msg_send(0/*send_sock*/, p->proto, to, 0/*id*/,
					tmp, msg->len + headers->len, msg);
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
	return ret;
}

static int w_setflag(struct sip_msg *msg, void *flag)
{
	return setflag(msg, (flag_t)(long)flag);
}

static int w_resetflag(struct sip_msg *msg, void *flag)
{
	return resetflag(msg, (flag_t)(long)flag);
}

static int w_isflagset(struct sip_msg *msg, void *flag)
{
	return isflagset(msg, (flag_t)(long)flag);
}

static int w_setbflag(struct sip_msg *msg, void *flag, int *branch_idx)
{
	return setbflag(msg, branch_idx ? *branch_idx : 0, (flag_t)(long)flag);
}

static int w_resetbflag(struct sip_msg *msg, void *flag, int *branch_idx)
{
	return resetbflag(msg, branch_idx ? *branch_idx : 0, (flag_t)(long)flag);	
}

static int w_isbflagset(struct sip_msg *msg, void *flag, int *branch_idx)
{
	return isbflagset(msg, branch_idx ? *branch_idx : 0, (flag_t)(long)flag);
}

static int w_sethost(struct sip_msg *msg, str *host)
{
	return rewrite_ruri(msg, host, 0, RW_RURI_HOST) ? -1 : 1;
}

static int w_sethostport(struct sip_msg *msg, str *hostport)
{
	return rewrite_ruri(msg, hostport, 0, RW_RURI_HOSTPORT) ? -1 : 1;
}

static int w_setuser(struct sip_msg *msg, str *user)
{
	return rewrite_ruri(msg, user, 0, RW_RURI_USER) ? -1 : 1;
}

static int w_setuserpass(struct sip_msg *msg, str *userpass)
{
	return rewrite_ruri(msg, userpass, 0, RW_RURI_USERPASS) ? -1 : 1;
}

static int w_setport(struct sip_msg *msg, str *port)
{
	return rewrite_ruri(msg, port, 0, RW_RURI_PORT) ? -1 : 1;
}

static int w_seturi(struct sip_msg *msg, str *uri)
{
	if (set_ruri(msg, uri) ) {
		LM_ERR("failed to set new RURI\n");
		return E_OUT_OF_MEM;
	}

	return 1;
}

static int w_prefix(struct sip_msg *msg, str *prefix)
{
	return rewrite_ruri(msg, prefix, 0, RW_RURI_PREFIX) ? -1 : 1;
}

static int w_strip(struct sip_msg *msg, int *nchars)
{
	return rewrite_ruri(msg, 0, *nchars, RW_RURI_STRIP) ? -1 : 1;
}

static int w_strip_tail(struct sip_msg *msg, int *nchars)
{
	return rewrite_ruri(msg, 0, *nchars, RW_RURI_STRIP_TAIL) ? -1 : 1;
}

static int w_append_branch(struct sip_msg *msg, str *uri, int *qvalue)
{
	int ret;
	qvalue_t q = (int)(long)qvalue;

	if (!uri) {
		ret = append_branch(msg, 0, &msg->dst_uri, &msg->path_vec,
			(q==Q_UNSPECIFIED) ? get_ruri_q(msg) : q,
			getb0flags(msg), msg->force_send_socket);
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

		return ret;
	} else {
		return append_branch(msg, uri, &msg->dst_uri,
			&msg->path_vec, q, getb0flags(msg),
			msg->force_send_socket);
	}
}

static int w_remove_branch(struct sip_msg *msg, int *branch)
{
	return (remove_branch(*branch)==0)?1:-1;
}

static int w_pv_printf(struct sip_msg *msg, pv_spec_t *var, str *fmt_str)
{
	pv_value_t val;

	if(!pv_is_w(var))
	{
		LM_ERR("read only PV in first parameter of pv_printf\n");
		return -1;
	}

	val.flags = PV_VAL_STR;
	val.rs = *fmt_str;

	if(pv_set_value(msg, var, EQ_T, &val)<0)
	{
		LM_ERR("setting PV failed\n");
		return -1;
	}

	return 1;
}

static int w_revert_uri(struct sip_msg *msg)
{
	if (msg->new_uri.s) {
		pkg_free(msg->new_uri.s);
		msg->new_uri.len=0;
		msg->new_uri.s=0;
		msg->parsed_uri_ok=0; /* invalidate current parsed uri*/
	};

	return 1;
}

static int w_setdsturi(struct sip_msg *msg, str *uri)
{
	if(set_dst_uri(msg, uri)!=0)
		return -1;
	else
		return 1;
}

static int w_resetdsturi(struct sip_msg *msg)
{
	reset_dst_uri(msg);

	return 1;
}

static int w_isdsturiset(struct sip_msg *msg)
{
	if(msg->dst_uri.s==0 || msg->dst_uri.len<=0)
		return -1;
	else
		return 1;

	return 1;
}

static int w_force_rport(struct sip_msg *msg)
{
	msg->msg_flags|=FL_FORCE_RPORT;

	return 1;
}

static int w_add_local_rport(struct sip_msg *msg)
{
	msg->msg_flags|=FL_FORCE_LOCAL_RPORT;
	return 1;

}

static int w_force_tcp_alias(struct sip_msg *msg, int *port)
{
	unsigned short p;

	if (is_tcp_based_proto(msg->rcv.proto)) {
		if (!port)	p=msg->via1->port;
		else
			p=*port;

		if (tcpconn_add_alias(msg->rcv.proto_reserved1, p,
							msg->rcv.proto)!=0){
			LM_WARN("tcp alias failed\n");
			return E_UNSPEC;
		}
	}

	return 1;	
}

static int w_set_adv_address(struct sip_msg *msg, str *adv_addr)
{
	LM_DBG("setting adv address = [%.*s]\n", adv_addr->len, adv_addr->s);

	/* duplicate the advertised address into private memory */
	if (adv_addr->len > msg->set_global_address.len) {
		msg->set_global_address.s = pkg_realloc(msg->set_global_address.s,
											    adv_addr->len);
		if (!msg->set_global_address.s) {
			LM_ERR("out of pkg mem\n");
			return E_OUT_OF_MEM;
		}
	}
	memcpy(msg->set_global_address.s, adv_addr->s, adv_addr->len);
	msg->set_global_address.len = adv_addr->len;

	return 1;
}

static int w_set_adv_port(struct sip_msg *msg, str *adv_port)
{
	LM_DBG("setting adv port '%.*s'\n", adv_port->len, adv_port->s);

	/* duplicate the advertised port into private memory */
	if (adv_port->len > msg->set_global_port.len) {
		msg->set_global_port.s = pkg_realloc(msg->set_global_port.s,
											 adv_port->len);
		if (!msg->set_global_port.s) {
			LM_ERR("out of pkg mem\n");
			return E_OUT_OF_MEM;
		}
	}
	memcpy(msg->set_global_port.s, adv_port->s, adv_port->len);
	msg->set_global_port.len = adv_port->len;

	return 1;
}

static int w_f_send_sock(struct sip_msg *msg, struct socket_info *si)
{
	msg->force_send_socket=si;

	return 1;
}

static int w_serialize_branches(struct sip_msg *msg, int *clear_prev,
							int *keep_ord)
{
	if (serialize_branches(msg,*clear_prev,
			keep_ord ? *keep_ord : 0)!=0) {
		LM_ERR("serialize_branches failed\n");
		return E_UNSPEC;
	}

	return 1;
}

static int w_next_branches(struct sip_msg *msg)
{
	int ret;

	if ((ret = next_branches(msg)) < 0)
		LM_DBG("no more branches\n");

	return ret;
}

static int w_use_blacklist(struct sip_msg *msg, struct bl_head *list)
{
	mark_for_search(list, 1);

	return 1;	
}

static int w_unuse_blacklist(struct sip_msg *msg, struct bl_head *list)
{
	mark_for_search(list, 0);

	return 1;	
}

static int w_cache_store(struct sip_msg *msg, str *id, str *attr, str *val, 
				int *expire)
{
	if (!attr->s || !attr->len) {
		LM_ERR("attribute cannot be empty\n");
		return E_UNSPEC;
	}
	if (!attr->s || !attr->len) {
		LM_ERR("value cannot be empty\n");
		return E_UNSPEC;
	}

	return cachedb_store(id, attr, val, expire ? *expire : 0);
}

static int w_cache_remove(struct sip_msg *msg, str *id, str *attr)
{
	if (!attr->s || !attr->len) {
		LM_ERR("attribute cannot be empty\n");
		return E_UNSPEC;
	}

	return cachedb_remove(id, attr);
}

static int w_cache_fetch(struct sip_msg *msg, str *id, str *attr,
					pv_spec_t *res)
{
	str aux = {0, 0};
	int ret;
	pv_value_t val;

	if (!attr->s || !attr->len) {
		LM_ERR("attribute cannot be empty\n");
		return E_UNSPEC;
	}

	ret = cachedb_fetch(id, attr, &aux);
	if(ret > 0)
	{
		val.rs = aux;
		val.flags = PV_VAL_STR;
		fix_val_str_flags(val);

		if (pv_set_value(msg, res, 0, &val) < 0) {
			LM_ERR("cannot set the variable value\n");
			pkg_free(aux.s);
			return -1;
		}
		pkg_free(aux.s);
	}

	return ret;
}

static int w_cache_counter_fetch(struct sip_msg *msg, str *id, str *attr,
					pv_spec_t *res)
{
	int aux_counter;
	int ret;
	pv_value_t val;

	if (!attr->s || !attr->len) {
		LM_ERR("attribute cannot be empty\n");
		return E_UNSPEC;
	}

	ret = cachedb_counter_fetch(id, attr, &aux_counter);
	if(ret > 0)
	{
		val.ri = aux_counter;
		val.flags = PV_TYPE_INT|PV_VAL_INT;

		if (pv_set_value(msg, res, 0, &val) < 0) {
			LM_ERR("cannot set the variable value\n");
			return -1;
		}
	}

	return ret;
}

static int w_cache_add(struct sip_msg *msg, str *id, str *attr,
				int *inc, int *expire, pv_spec_t *new_val)
{
	int ret;
	pv_value_t val;
	int aux_counter;

	if (!attr->s || !attr->len) {
		LM_ERR("attribute cannot be empty\n");
		return E_UNSPEC;
	}

	ret = cachedb_add(id, attr, *inc, *expire, &aux_counter);

	/* Return the new value */
	if (ret > 0 && new_val) {
		val.ri = aux_counter;
		val.flags = PV_TYPE_INT|PV_VAL_INT;

		if (pv_set_value(msg, new_val, 0, &val) < 0) {
			LM_ERR("cannot set the variable value\n");
			return -1;
		}
	}

	return ret;
}

static int w_cache_sub(struct sip_msg *msg, str *id, str *attr,
				int *dec, int *expire, pv_spec_t *new_val)
{
	int ret;
	pv_value_t val;
	int aux_counter;

	if (!attr->s || !attr->len) {
		LM_ERR("attribute cannot be empty\n");
		return E_UNSPEC;
	}

	ret = cachedb_sub(id, attr, *dec, *expire, &aux_counter);

	/* Return the new value */
	if (ret > 0 && new_val) {
		val.ri = aux_counter;
		val.flags = PV_TYPE_INT|PV_VAL_INT;

		if (pv_set_value(msg, new_val, 0, &val) < 0) {
			LM_ERR("cannot set the variable value\n");
			return -1;
		}
	}

	return ret;
}

static int w_cache_raw_query(struct sip_msg *msg, str *id, str *raw_query_s,
				pvname_list_t *avp_list)
{
	cdb_raw_entry **cdb_reply = NULL;
	int num_cols=0,i,j;
	int num_rows=0;
	pvname_list_t *it;
	int_str avp_val;
	int_str avp_name;
	unsigned short avp_type;
	int ret;

	if (!raw_query_s || !raw_query_s->s || !raw_query_s->len) {
		LM_ERR("raw query cannot be empty\n");
		return E_UNSPEC;
	}

	if (!avp_list)
		return cachedb_raw_query(id, raw_query_s, NULL,0,NULL);

	for (it=avp_list;it;it=it->next)
		num_cols++;

	LM_DBG("The query expects %d fields per result\n", num_cols);

	ret = cachedb_raw_query(id, raw_query_s, &cdb_reply, num_cols, &num_rows);
	if (ret >= 0 && num_cols > 0) {
		for (i=num_rows-1; i>=0;i--) {
			it=avp_list;
			for (j=0;j < num_cols;j++) {
				avp_type = 0;
				if (pv_get_avp_name(msg,&it->sname.pvp,&avp_name.n,
					&avp_type) != 0) {
					LM_ERR("cannot get avp name [%d/%d]\n",i,j);
					goto next_avp;
				}

				switch (cdb_reply[i][j].type) {
					case CDB_INT32:
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
					free_raw_fetch(cdb_reply,num_cols,num_rows);
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
		free_raw_fetch(cdb_reply,num_cols,num_rows);
	}

	return ret;
}

static int w_raise_event(struct sip_msg *msg, void *ev_id, pv_spec_t *attrs_avp,
					pv_spec_t *vals_avp)
{

	if (evi_raise_script_event(msg, (event_id_t)(long)ev_id, attrs_avp,
		vals_avp) <= 0) {
		LM_ERR("cannot raise event\n");
		return E_UNSPEC;
	}

	return 1;
}

static int w_subscribe_event(struct sip_msg *msg, str *name, str *socket,
					int *expire)
{
	return evi_event_subscribe(*name, *socket, expire ? *expire : 0, 0);
}

static int w_construct_uri(struct sip_msg *msg, str *proto, str *user,
					str *domain, str *port, str *extra, pv_spec_t *result_avp)
{
	str result;
	int_str res;
	int avp_name;
	unsigned short avp_type;

	result.s = construct_uri(proto, user, domain, port, extra, &result.len);
	if (result.s)
	{
		if (pv_get_avp_name( msg, &(result_avp->pvp), &avp_name,
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

	return 1;
}

static int w_get_timestamp(struct sip_msg *msg, pv_spec_t *sec_avp,
					pv_spec_t *usec_avp)
{
	int sec,usec;
	int avp_name;
	int_str res;
	unsigned short avp_type;

	if (get_timestamp(&sec,&usec) == 0) {
		if (pv_get_avp_name(msg, &(sec_avp->pvp), &avp_name,
				&avp_type) != 0) {
			LM_CRIT("BUG in getting AVP name\n");
			return -1;
		}

		res.n = sec;
		if (add_avp(avp_type, avp_name, res) < 0) {
			LM_ERR("cannot add AVP\n");
			return -1;
		}

		if (pv_get_avp_name(msg, &(usec_avp->pvp), &avp_name,
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

	return 1;
}

static int w_script_trace(struct sip_msg *msg, int *log_level,
					pv_elem_t *fmt_string, void *info_str)
{
	if (!log_level && !fmt_string && !info_str) {
		use_script_trace = 0;
		return 1;
	} else if (!log_level) {
		LM_ERR("Missing 'log_level' parameter\n");
		return E_CFG;
	} else if (!fmt_string) {
		LM_ERR("Missing 'pv_format_string' parameter\n");
		return E_CFG;
	}

	use_script_trace = 1;

	script_trace_info = (char*)info_str;

	script_trace_log_level = *log_level;
	script_trace_elem = *fmt_string;

	return 1;
}

static int w_is_myself(struct sip_msg *msg, str *host, int *port)
{
	if (check_self(host, port ? *port : 0, 0))
		return 1;
	else
		return -1;
}
