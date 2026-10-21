/*
 * clusterer_controller - script variables, functions, events and messaging
 *
 * Copyright (C) 2026 Yury Kirsanov
 *                          VoIPLine Telecom
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include "cl_ctr.h"

static int cmd_cl_ctr_broadcast_req(struct sip_msg *msg, int *cluster_id,
		str *gen_msg, str *tag, int *reliable);
static int cmd_cl_ctr_send_req(struct sip_msg *msg, int *cluster_id,
		int *node_id, str *gen_msg, str *tag, int *reliable);
static int cmd_cl_ctr_send_req_list(struct sip_msg *msg, int *cluster_id,
		pv_spec_t *nodes, str *gen_msg, str *tag, pv_spec_t *out);
static int cmd_cl_ctr_send_rpl(struct sip_msg *msg, int *cluster_id,
		int *node_id, str *gen_msg, str *tag);

/* The two transmit buffers, sized from cc_max_payload once the MTU is known.
 *
 * They were `char buf[CLCTR_MAX_PAYLOAD]` and `char pkt[CL_CTR_CONSUMER_PKT_MAX]`
 * on the stack, while the length gates in front of them tested against the
 * MTU-derived cc_max_payload - so on any link above MTU 1411 a caller could
 * pass the gate and write past the end. A production gateway logs
 * "interface ens18 MTU=1500, max consumer payload=1389" against a 1300-byte
 * buffer: an 89-byte stack overrun with caller-supplied bytes.
 *
 * pkg, allocated in mod_init, which runs PRE-FORK: every worker inherits its
 * own copy-on-write copy, so there is no sharing between processes and no
 * per-call allocation on the send path (cachedb_perf's pull replies go through
 * the consumer one for every message). Each is written only by the process
 * that owns it, and neither send function can re-enter itself - script
 * functions run to completion inside one route execution, and the consumer
 * send runs in the cluster worker's own loop. */
char *cl_ctr_script_buf;
int   cl_ctr_script_buf_sz;

static str  cl_ctr_script_chan = str_init("_script");
static str  ei_req_name = str_init("E_CL_CTR_REQ_RECEIVED");
static str  ei_rpl_name = str_init("E_CL_CTR_RPL_RECEIVED");
static event_id_t ei_req_id = EVI_ERROR;
static str  ei_maint_name = str_init("E_CL_CTR_MAINTENANCE");
static event_id_t ei_maint_id = EVI_ERROR;
static evi_params_p ei_maint_params;
static evi_param_p  ei_m_clid_p, ei_m_node_p, ei_m_state_p;
static str ei_node_pname  = str_init("node_id");
static str ei_state_pname = str_init("state");
static event_id_t ei_rpl_id = EVI_ERROR;
static evi_params_p ei_params;
static evi_param_p  ei_clid_p, ei_srcid_p, ei_msg_p, ei_tag_p;
static str ei_clid_pname  = str_init("cluster_id");
static str ei_srcid_pname = str_init("src_id");
static str ei_msg_pname   = str_init("msg");
static str ei_tag_pname   = str_init("tag");

/* =========================================================================
 * Read-only script variables ($cl_ctr_*)
 *
 * Nouns, never verbs (actions are script functions / MI).  Each variable
 * optionally takes a cluster id: $cl_ctr_role(2).  The bare form
 * ($cl_ctr_role) resolves to the sole configured cluster; with several
 * clusters it returns NULL and warns once, so nobody silently reads the
 * wrong cluster.  All values are read from the shm peer table under a read
 * lock, so every process (SIP workers included) sees live state.  Read-only:
 * no setter is exported.
 * ========================================================================= */

enum cl_ctr_pv_field {
    CL_CTR_PV_ROLE,        /* master | backup | member | joining               */
    CL_CTR_PV_IS_MASTER,   /* 1 / 0                                            */
    CL_CTR_PV_MASTER_IP,   /* current master's IP, NULL if none                */
    CL_CTR_PV_BACKUP_IP,   /* current backup's IP, NULL if none                */
    CL_CTR_PV_NODE_ID,     /* this node's id in the cluster, NULL if unassigned */
    CL_CTR_PV_MY_IP,       /* controller identity IP                           */
    CL_CTR_PV_MEMBERS,     /* live member count                                */
    CL_CTR_PV_SHTAG_MODE,  /* auto | forced                                    */
    CL_CTR_PV_FORCED_NODE, /* node pinned by clusterer_controller:shtag_force, NULL if auto  */
    CL_CTR_PV_MAINT,       /* this node's maintenance state: none | evicted    */
};

/* Optional (cluster_id) argument; bare form leaves the spec zeroed (cid 0). */
static int cl_ctr_pv_parse_cluster(pv_spec_p sp, const str *in)
{
    unsigned int cid;
    str s;

    if (!sp)
	return -1;
    if (!in || !in->s || in->len == 0) {
	sp->pvp.pvn.u.isname.name.n = 0;   /* bare form -> sole cluster */
	return 0;
    }
    s = *in;
    trim(&s);
    if (s.len == 0) {
	sp->pvp.pvn.u.isname.name.n = 0;
	return 0;
    }
    /* str2int rejects any non-digit (so '-5', 'abc', '1.2' all fail); the
     * length cap keeps a huge value from silently overflowing/wrapping into a
     * valid id (999999999 < INT_MAX). */
    if (s.len > 9 || str2int(&s, &cid) < 0 || cid == 0) {
	LM_ERR("clusterer_controller: invalid cluster id '%.*s' in $cl_ctr_* "
	       "variable (expected a positive integer 1..999999999)\n",
	       in->len, in->s);
	return -1;
    }
    sp->pvp.pvn.u.isname.name.n = (int)cid;
    return 0;
}

static int cl_ctr_pv_get(struct sip_msg *msg, pv_param_t *param, pv_value_t *res,
                     enum cl_ctr_pv_field field)
{
    static char  cl_ctr_pv_ipbuf[INET_ADDRSTRLEN];
    static int   cl_ctr_pv_warned_ambiguous;
    cl_ctr_cluster_t *cl = NULL;
    cl_ctr_peer_t    *me = NULL, *master = NULL, *backup = NULL;
    const char   *sval = NULL;
    int          cid, i, have_int = 0, ival = 0, joining;

    cid = param->pvn.u.isname.name.n;
    if (cid == 0) {
	if (cl_ctr_cluster_count == 1) {
	    cl = &cl_ctr_clusters[0];
	} else {
	    if (!cl_ctr_pv_warned_ambiguous) {
		LM_WARN("clusterer_controller: bare $cl_ctr_* used with %d "
		        "clusters configured - specify the cluster id, e.g. "
		        "$cl_ctr_role(%d)\n", cl_ctr_cluster_count,
		        cl_ctr_cluster_count ? cl_ctr_clusters[0].cluster_id : 1);
		cl_ctr_pv_warned_ambiguous = 1;
	    }
	    return pv_get_null(msg, param, res);
	}
    } else {
	for (i = 0; i < cl_ctr_cluster_count; i++)
	    if (cl_ctr_clusters[i].cluster_id == cid) {
		cl = &cl_ctr_clusters[i];
		break;
	    }
    }
    if (!cl || !cl->peers)
	return pv_get_null(msg, param, res);

    lock_start_read(cl->peers->lock);

    joining = (cl->peers->node_state == CL_CTR_NODE_NEW);
    for (i = 0; i < cl->peers->count; i++) {
	cl_ctr_peer_t *e = &cl->peers->entries[i];
	if (e->is_master)
	    master = e;
	if (e->is_backup)
	    backup = e;
	if (my_ip && strcmp(e->ip, my_ip) == 0)
	    me = e;
    }

    switch (field) {
    case CL_CTR_PV_ROLE:
	if (joining)
	    sval = "joining";
	else if (me && me->is_master)
	    sval = "master";
	else if (me && me->is_backup)
	    sval = "backup";
	else
	    sval = "member";
	break;
    case CL_CTR_PV_IS_MASTER:
	have_int = 1;
	ival = (!joining && me && me->is_master) ? 1 : 0;
	break;
    case CL_CTR_PV_MASTER_IP:
	if (master) {
	    strncpy(cl_ctr_pv_ipbuf, master->ip, sizeof(cl_ctr_pv_ipbuf) - 1);
	    cl_ctr_pv_ipbuf[sizeof(cl_ctr_pv_ipbuf) - 1] = '\0';
	    sval = cl_ctr_pv_ipbuf;
	}
	break;
    case CL_CTR_PV_BACKUP_IP:
	if (backup) {
	    strncpy(cl_ctr_pv_ipbuf, backup->ip, sizeof(cl_ctr_pv_ipbuf) - 1);
	    cl_ctr_pv_ipbuf[sizeof(cl_ctr_pv_ipbuf) - 1] = '\0';
	    sval = cl_ctr_pv_ipbuf;
	}
	break;
    case CL_CTR_PV_NODE_ID:
	if (me && me->node_id > 0) {
	    have_int = 1;
	    ival = me->node_id;
	}
	break;
    case CL_CTR_PV_MY_IP:
	sval = my_ip;   /* resolved in mod_init, constant afterwards */
	break;
    case CL_CTR_PV_MEMBERS:
	have_int = 1;
	ival = cl->peers->count;
	break;
    case CL_CTR_PV_SHTAG_MODE:
	sval = cl->peers->shtag_forced_node_id ? "forced" : "auto";
	break;
    case CL_CTR_PV_FORCED_NODE:
	if (cl->peers->shtag_forced_node_id) {
	    have_int = 1;
	    ival = cl->peers->shtag_forced_node_id;
	}
	break;
    case CL_CTR_PV_MAINT:
	sval = cl_ctr_maint_name(cl->peers->my_maint);
	break;
    }

    lock_stop_read(cl->peers->lock);

    if (have_int)
	return pv_get_uintval(msg, param, res, (unsigned int)ival);
    if (sval) {
	str s = {(char *)sval, (int)strlen(sval)};
	return pv_get_strval(msg, param, res, &s);
    }
    return pv_get_null(msg, param, res);
}

static int cl_ctr_out_str(struct sip_msg *msg, pv_spec_t *out, const char *str_s)
{
    pv_value_t val;
    memset(&val, 0, sizeof val);
    val.flags  = PV_VAL_STR;
    val.rs.s   = (char *)str_s;
    val.rs.len = strlen(str_s);
    return pv_set_value(msg, out, 0, &val);
}

/* cl_ctr_node_is_master(cluster_id, node_id) -> true if that node is master */
static int w_cl_ctr_node_is_master(struct sip_msg *msg, int *cid, int *nid)
{
    int im = 0;
    if (cl_ctr_find_peer(cid ? *cid : 0, nid ? *nid : 0, &im, NULL, NULL, 0) < 0)
	return -1;
    return im ? 1 : -1;
}

/* cl_ctr_node_present(cluster_id, node_id) -> true if node_id is a live member */
static int w_cl_ctr_node_present(struct sip_msg *msg, int *cid, int *nid)
{
    return cl_ctr_find_peer(cid ? *cid : 0, nid ? *nid : 0, NULL, NULL, NULL, 0) == 0
           ? 1 : -1;
}

/* cl_ctr_get_node_role(cluster_id, node_id, out) -> out=master|backup|member */
static int w_cl_ctr_get_node_role(struct sip_msg *msg, int *cid, int *nid,
                                  pv_spec_t *out)
{
    int im = 0, ib = 0;
    if (cl_ctr_find_peer(cid ? *cid : 0, nid ? *nid : 0, &im, &ib, NULL, 0) < 0)
	return -1;
    return cl_ctr_out_str(msg, out, im ? "master" : (ib ? "backup" : "member")) == 0
           ? 1 : -1;
}

/* cl_ctr_get_node_ip(cluster_id, node_id, out) -> out=that node's IP */
static int w_cl_ctr_get_node_ip(struct sip_msg *msg, int *cid, int *nid,
                                pv_spec_t *out)
{
    char ipbuf[INET_ADDRSTRLEN];
    if (cl_ctr_find_peer(cid ? *cid : 0, nid ? *nid : 0, NULL, NULL,
                     ipbuf, sizeof ipbuf) < 0)
	return -1;
    return cl_ctr_out_str(msg, out, ipbuf) == 0 ? 1 : -1;
}

CL_CTR_PV_WRAP(cl_ctr_pv_role,        CL_CTR_PV_ROLE)
CL_CTR_PV_WRAP(cl_ctr_pv_is_master,   CL_CTR_PV_IS_MASTER)
CL_CTR_PV_WRAP(cl_ctr_pv_master_ip,   CL_CTR_PV_MASTER_IP)
CL_CTR_PV_WRAP(cl_ctr_pv_backup_ip,   CL_CTR_PV_BACKUP_IP)
CL_CTR_PV_WRAP(cl_ctr_pv_node_id,     CL_CTR_PV_NODE_ID)

CL_CTR_PV_WRAP(cl_ctr_pv_my_ip,       CL_CTR_PV_MY_IP)
CL_CTR_PV_WRAP(cl_ctr_pv_members,     CL_CTR_PV_MEMBERS)
CL_CTR_PV_WRAP(cl_ctr_pv_shtag_mode,  CL_CTR_PV_SHTAG_MODE)
CL_CTR_PV_WRAP(cl_ctr_pv_forced_node, CL_CTR_PV_FORCED_NODE)
CL_CTR_PV_WRAP(cl_ctr_pv_maint,       CL_CTR_PV_MAINT)

/* cl_ctr_set_maintenance(cluster_id, state): put THIS node in ("evicted")
 * or out ("none") of maintenance.  1 on success, -1 otherwise. */
static int w_cl_ctr_set_maintenance(struct sip_msg *msg, int *cid, str *state)
{
    int i, st = cl_ctr_maint_parse(state->s, state->len);

    if (st < 0) {
	LM_ERR("clusterer_controller: cl_ctr_set_maintenance: state must be "
	       "evicted or none, not '%.*s'\n", state->len, state->s);
	return -1;
    }
    for (i = 0; i < cl_ctr_cluster_count; i++)
	if (cl_ctr_clusters[i].cluster_id == *cid && cl_ctr_clusters[i].peers)
	    return cl_ctr_set_my_maint(&cl_ctr_clusters[i], st) == 0 ? 1 : -1;
    LM_ERR("clusterer_controller: cl_ctr_set_maintenance: no cluster %d\n", *cid);
    return -1;
}

const pv_export_t cl_ctr_mod_vars[] = {
    { {"cl_ctr_role",        sizeof("cl_ctr_role")-1},        1100,
	cl_ctr_pv_role,        0, cl_ctr_pv_parse_cluster, 0, 0, 0 },
    { {"cl_ctr_is_master",   sizeof("cl_ctr_is_master")-1},   1101,
	cl_ctr_pv_is_master,   0, cl_ctr_pv_parse_cluster, 0, 0, 0 },
    { {"cl_ctr_master_ip",   sizeof("cl_ctr_master_ip")-1},   1102,
	cl_ctr_pv_master_ip,   0, cl_ctr_pv_parse_cluster, 0, 0, 0 },
    { {"cl_ctr_backup_ip",   sizeof("cl_ctr_backup_ip")-1},   1103,
	cl_ctr_pv_backup_ip,   0, cl_ctr_pv_parse_cluster, 0, 0, 0 },
    { {"cl_ctr_node_id",     sizeof("cl_ctr_node_id")-1},     1104,
	cl_ctr_pv_node_id,     0, cl_ctr_pv_parse_cluster, 0, 0, 0 },
    { {"cl_ctr_my_ip",       sizeof("cl_ctr_my_ip")-1},       1105,
	cl_ctr_pv_my_ip,       0, cl_ctr_pv_parse_cluster, 0, 0, 0 },
    { {"cl_ctr_members",     sizeof("cl_ctr_members")-1},     1106,
	cl_ctr_pv_members,     0, cl_ctr_pv_parse_cluster, 0, 0, 0 },
    { {"cl_ctr_shtag_mode",  sizeof("cl_ctr_shtag_mode")-1},  1107,
	cl_ctr_pv_shtag_mode,  0, cl_ctr_pv_parse_cluster, 0, 0, 0 },
    { {"cl_ctr_forced_node", sizeof("cl_ctr_forced_node")-1}, 1108,
	cl_ctr_pv_forced_node, 0, cl_ctr_pv_parse_cluster, 0, 0, 0 },
    { {"cl_ctr_maintenance", sizeof("cl_ctr_maintenance")-1}, 1109,
	cl_ctr_pv_maint,       0, cl_ctr_pv_parse_cluster, 0, 0, 0 },
    { {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

/* Script functions: per-peer lookups (two args -> functions, not variables). */
const cmd_export_t cl_ctr_cmds[] = {
    {"cl_ctr_set_maintenance", (cmd_function)w_cl_ctr_set_maintenance, {
	{CMD_PARAM_INT, 0, 0}, {CMD_PARAM_STR, 0, 0}, {0, 0, 0}}, ALL_ROUTES},
    {"cl_ctr_node_is_master", (cmd_function)w_cl_ctr_node_is_master, {
	{CMD_PARAM_INT, 0, 0}, {CMD_PARAM_INT, 0, 0}, {0, 0, 0}}, ALL_ROUTES},
    {"cl_ctr_node_present", (cmd_function)w_cl_ctr_node_present, {
	{CMD_PARAM_INT, 0, 0}, {CMD_PARAM_INT, 0, 0}, {0, 0, 0}}, ALL_ROUTES},
    {"cl_ctr_get_node_role", (cmd_function)w_cl_ctr_get_node_role, {
	{CMD_PARAM_INT, 0, 0}, {CMD_PARAM_INT, 0, 0}, {CMD_PARAM_VAR, 0, 0}, {0, 0, 0}}, ALL_ROUTES},
    {"cl_ctr_get_node_ip", (cmd_function)w_cl_ctr_get_node_ip, {
	{CMD_PARAM_INT, 0, 0}, {CMD_PARAM_INT, 0, 0}, {CMD_PARAM_VAR, 0, 0}, {0, 0, 0}}, ALL_ROUTES},
    {"cl_ctr_broadcast_req", (cmd_function)cmd_cl_ctr_broadcast_req, {
	{CMD_PARAM_INT,0,0},
	{CMD_PARAM_STR,0,0},
	{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
	{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, {0,0,0}},
	ALL_ROUTES},
    {"cl_ctr_send_req", (cmd_function)cmd_cl_ctr_send_req, {
	{CMD_PARAM_INT,0,0},
	{CMD_PARAM_INT,0,0},
	{CMD_PARAM_STR,0,0},
	{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
	{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, {0,0,0}},
	ALL_ROUTES},
    {"cl_ctr_send_req_list", (cmd_function)cmd_cl_ctr_send_req_list, {
	{CMD_PARAM_INT, 0, 0},
	{CMD_PARAM_VAR, 0, 0},
	{CMD_PARAM_STR, 0, 0},
	{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
	{CMD_PARAM_VAR|CMD_PARAM_OPT, 0, 0}, {0, 0, 0}}, ALL_ROUTES},
    {"cl_ctr_send_rpl", (cmd_function)cmd_cl_ctr_send_rpl, {
	{CMD_PARAM_INT,0,0},
	{CMD_PARAM_INT,0,0},
	{CMD_PARAM_STR,0,0},
	{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
	ALL_ROUTES},
    {"load_clctr", (cmd_function)load_clctr, {{0, 0, 0}}, 0},
    {0, 0, {{0, 0, 0}}, 0}
};

/* ---- script tier: receive ---------------------------------------------- */

static void cl_ctr_script_recv(int cluster_id, int src_node_id, str *channel,
		str *payload)
{
	str msg, tag;
	unsigned char kind;
	int taglen;

	if (payload->len < 2)
		goto bad;
	kind = (unsigned char)payload->s[0];
	taglen = (unsigned char)payload->s[1];
	if (payload->len < 2 + taglen)
		goto bad;
	tag.s = payload->s + 2;
	tag.len = taglen;
	msg.s = payload->s + 2 + taglen;
	msg.len = payload->len - 2 - taglen;

	/* free when nobody is listening - the same gate the module's other
	 * events use */
	if (!evi_probe_event(kind == CL_CTR_SCRIPT_RPL ? ei_rpl_id : ei_req_id))
		return;

	if (evi_param_set_int(ei_clid_p, &cluster_id) < 0 ||
	    evi_param_set_int(ei_srcid_p, &src_node_id) < 0 ||
	    evi_param_set_str(ei_msg_p, &msg) < 0 ||
	    evi_param_set_str(ei_tag_p, &tag) < 0) {
		LM_ERR("clusterer_controller: cannot fill the message event\n");
		return;
	}
	if (evi_raise_event(kind == CL_CTR_SCRIPT_RPL ? ei_rpl_id : ei_req_id,
	        ei_params) < 0)
		LM_ERR("clusterer_controller: cannot raise the message event\n");
	return;
bad:
	LM_ERR("clusterer_controller: malformed script message from node %d\n",
		src_node_id);
}

/* ---- script tier: send -------------------------------------------------- */

static int cl_ctr_script_send(int cluster_id, int node_id, str *gen_msg,
		str *tag, unsigned char kind, int flags)
{
	char *buf = cl_ctr_script_buf;
	str pl;
	int taglen = tag ? tag->len : 0;

	if (!gen_msg || gen_msg->len <= 0)
		return -1;
	if (taglen > 255)
		taglen = 255;
	/* Bound against the BUFFER, not only against cc_max_payload. They are
	 * derived from one another at mod_init now, but this function writes
	 * into buf[] and buf[] is what it must answer to - the gap between the
	 * two forms is exactly how a 1500-MTU link turned a 1350-byte script
	 * message into an 89-byte stack overrun. cmd_cl_ctr_send_req_list()
	 * now shares this buffer and this guard. */
	if (!buf || 2 + taglen + gen_msg->len > cl_ctr_script_buf_sz ||
	    2 + taglen + gen_msg->len > cc_max_payload) {
		LM_ERR("clusterer_controller: message of %d bytes is more than the "
			"%d a datagram carries\n", gen_msg->len,
			cc_max_payload < cl_ctr_script_buf_sz ? cc_max_payload
			                                      : cl_ctr_script_buf_sz);
		return -1;
	}
	buf[0] = (char)kind;
	buf[1] = (char)taglen;
	if (taglen)
		memcpy(buf + 2, tag->s, taglen);
	memcpy(buf + 2 + taglen, gen_msg->s, gen_msg->len);
	pl.s = buf;
	pl.len = 2 + taglen + gen_msg->len;

	if (node_id > 0)
		return clctr_send_ucast(cluster_id, node_id, &cl_ctr_script_chan,
			&pl, flags) < 0 ? -1 : 1;
	return clctr_send_mcast(cluster_id, &cl_ctr_script_chan, &pl, flags) < 0
		? -1 : 1;
}

static int cmd_cl_ctr_broadcast_req(struct sip_msg *msg, int *cluster_id,
		str *gen_msg, str *tag, int *reliable)
{
	/* Reliability is asked for per send rather than per channel: most
	 * messages are better off cheap, and the ones that are not know it. */
	return cl_ctr_script_send(*cluster_id, 0, gen_msg, tag,
		CL_CTR_SCRIPT_REQ,
		(reliable && *reliable) ? CLCTR_SEND_RELIABLE : 0);
}

static int cmd_cl_ctr_send_req(struct sip_msg *msg, int *cluster_id,
		int *node_id, str *gen_msg, str *tag, int *reliable)
{
	return cl_ctr_script_send(*cluster_id, *node_id, gen_msg, tag,
		CL_CTR_SCRIPT_REQ,
		(reliable && *reliable) ? CLCTR_SEND_RELIABLE : 0);
}

/**
 * cl_ctr_send_req_list() - send one request to the nodes named in an AVP.
 *
 * The AVP is read as a list of node ids, in the order the script built it.
 * Every target gets its own unicast: a multicast is decrypted by every
 * member, so addressing a subset over one would still hand the payload to
 * the nodes that were not addressed.
 *
 * Returns the number of nodes the message went to, so a script can compare
 * it against the size of its own list; entries that name a node which is
 * not a current member are skipped rather than failing the whole send.
 */
static int cmd_cl_ctr_send_req_list(struct sip_msg *msg, int *cluster_id,
		pv_spec_t *nodes, str *gen_msg, str *tag, pv_spec_t *out)
{
	int  ids[CL_CTR_MAX_PEERS];
	int  n = 0, sent, unknown = 0;
	struct usr_avp *avp = NULL;
	int_str val;

	if (!cluster_id || !nodes || !gen_msg)
		return -1;
	if (nodes->type != PVT_AVP) {
		LM_ERR("clusterer_controller: the node list must be an AVP\n");
		return -1;
	}

	/* search_first_avp/search_next walk newest-first; the script's own
	 * order is not preserved and does not need to be - every named node
	 * gets the same message. */
	avp = search_first_avp(nodes->pvp.pvn.u.isname.type,
	                       nodes->pvp.pvn.u.isname.name.n, &val, NULL);
	while (avp && n < CL_CTR_MAX_PEERS) {
		if (!(avp->flags & AVP_VAL_STR))
			ids[n++] = (int)val.n;
		else
			LM_DBG("clusterer_controller: skipping a non-numeric "
			       "entry in the node list\n");
		avp = search_next_avp(avp, &val);
	}
	if (n == 0) {
		LM_WARN("clusterer_controller: the node list is empty - "
			"nothing sent\n");
		return -1;
	}
	if (avp)
		LM_WARN("clusterer_controller: node list longer than the %d a "
			"cluster can hold - the rest is ignored\n",
			CL_CTR_MAX_PEERS);

	{
		/* The same MTU-derived buffer its two siblings use, not a
		 * CLCTR_MAX_PAYLOAD stack array.  A compile-time 1300 here meant
		 * that on a jumbo link a script could broadcast an 8 KB message
		 * but could not send the same message to a LIST of nodes - the
		 * list form silently stopped at a seventh of what the other two
		 * carried, with an error that blamed "the cluster plane" rather
		 * than the buffer. */
		char *buf  = cl_ctr_script_buf;
		str   pl;
		int   tlen = tag ? tag->len : 0;

		if (tlen > 255)
			tlen = 255;
		if (!buf || 2 + tlen + gen_msg->len > cl_ctr_script_buf_sz ||
		    2 + tlen + gen_msg->len > cc_max_payload) {
			LM_ERR("clusterer_controller: message of %d bytes is more "
			       "than the %d a datagram carries\n", gen_msg->len,
			       cc_max_payload < cl_ctr_script_buf_sz
			           ? cc_max_payload : cl_ctr_script_buf_sz);
			return -1;
		}
		buf[0] = (char)CL_CTR_SCRIPT_REQ;
		buf[1] = (char)tlen;
		if (tlen)
			memcpy(buf + 2, tag->s, tlen);
		memcpy(buf + 2 + tlen, gen_msg->s, gen_msg->len);
		pl.s   = buf;
		pl.len = 2 + tlen + gen_msg->len;

		sent = clctr_send_list(*cluster_id, ids, n, &cl_ctr_script_chan,
		                       &pl, 0, &unknown);
	}
	/* How many nodes it reached goes out through a variable, never through
	 * the return value: the core stops the script when an action returns
	 * zero, and "reached nobody" is a real answer a script must be able to
	 * see rather than a reason to stop.  The return value is therefore only
	 * whether the send could be attempted. */
	if (out) {
		pv_value_t v;

		memset(&v, 0, sizeof v);
		v.flags = PV_TYPE_INT | PV_VAL_INT;
		v.ri    = sent < 0 ? 0 : sent;
		if (pv_set_value(msg, out, 0, &v) < 0)
			LM_ERR("clusterer_controller: cannot write the delivery "
			       "count to the output variable\n");
	}
	if (sent <= 0)
		return -1;
	if (unknown)
		LM_DBG("clusterer_controller: [cluster %d] %d of %d target(s) "
		       "were not reachable members\n", *cluster_id, unknown, n);
	return 1;
}

static int cmd_cl_ctr_send_rpl(struct sip_msg *msg, int *cluster_id,
		int *node_id, str *gen_msg, str *tag)
{
	return cl_ctr_script_send(*cluster_id, *node_id, gen_msg, tag,
		CL_CTR_SCRIPT_RPL, 0);
}

/* Publish the two events and claim the script's channel.  Called from
 * mod_init, before any consumer registers, so the reserved name cannot be
 * taken by a module. */
int cl_ctr_script_init(void)
{
	ei_maint_id = evi_publish_event(ei_maint_name);
	ei_maint_params = pkg_malloc(sizeof *ei_maint_params);
	if (ei_maint_id == EVI_ERROR || !ei_maint_params) {
		LM_ERR("clusterer_controller: cannot publish the maintenance event\n");
		return -1;
	}
	memset(ei_maint_params, 0, sizeof *ei_maint_params);
	if (!(ei_m_clid_p  = evi_param_create(ei_maint_params, &ei_clid_pname)) ||
	    !(ei_m_node_p  = evi_param_create(ei_maint_params, &ei_node_pname)) ||
	    !(ei_m_state_p = evi_param_create(ei_maint_params, &ei_state_pname))) {
		LM_ERR("clusterer_controller: cannot create the maintenance event "
		       "parameters\n");
		return -1;
	}
	ei_req_id = evi_publish_event(ei_req_name);
	ei_rpl_id = evi_publish_event(ei_rpl_name);
	if (ei_req_id == EVI_ERROR || ei_rpl_id == EVI_ERROR) {
		LM_ERR("clusterer_controller: cannot publish the message events\n");
		return -1;
	}
	ei_params = pkg_malloc(sizeof *ei_params);
	if (!ei_params) {
		LM_ERR("clusterer_controller: no pkg for the event parameters\n");
		return -1;
	}
	memset(ei_params, 0, sizeof *ei_params);
	if (!(ei_clid_p  = evi_param_create(ei_params, &ei_clid_pname))  ||
	    !(ei_srcid_p = evi_param_create(ei_params, &ei_srcid_pname)) ||
	    !(ei_msg_p   = evi_param_create(ei_params, &ei_msg_pname))   ||
	    !(ei_tag_p   = evi_param_create(ei_params, &ei_tag_pname))) {
		LM_ERR("clusterer_controller: cannot create the event parameters\n");
		return -1;
	}
	return clctr_register_channel(&cl_ctr_script_chan, cl_ctr_script_recv);
}

/* E_CL_CTR_MAINTENANCE: a node's maintenance state changed (raised on every
 * node that learns of it, for itself included). */
void cl_ctr_raise_maint_event(cl_ctr_cluster_t *cl, int node_id, int st)
{
	int cid = cl->cluster_id;
	str sv;

	if (ei_maint_id == EVI_ERROR || !evi_probe_event(ei_maint_id))
		return;
	sv.s = (char *)cl_ctr_maint_name(st);
	sv.len = strlen(sv.s);
	if (evi_param_set_int(ei_m_clid_p, &cid) < 0 ||
	    evi_param_set_int(ei_m_node_p, &node_id) < 0 ||
	    evi_param_set_str(ei_m_state_p, &sv) < 0) {
		LM_ERR("clusterer_controller: cannot fill the maintenance event\n");
		return;
	}
	if (evi_raise_event(ei_maint_id, ei_maint_params) < 0)
		LM_ERR("clusterer_controller: cannot raise the maintenance event\n");
}
