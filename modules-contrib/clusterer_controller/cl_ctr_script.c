/*
 * clusterer_controller - script variables and functions
 *
 * Copyright (C) 2026 Yury Kirsanov
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
#include "cl_ctr_caps.h"

/* $cl_ctr_*(cluster_id): the bare form needs a sole cluster, else it is NULL
 * with a warning, so nobody silently reads the wrong cluster */

enum cl_ctr_pv_field {
    CL_CTR_PV_ROLE,        /* master | backup | maintenance | member | joining */
    CL_CTR_PV_IS_MASTER,   /* 1 / 0                                            */
    CL_CTR_PV_MASTER_IP,   /* current master's IP, NULL if none                */
    CL_CTR_PV_BACKUP_IP,   /* current backup's IP, NULL if none                */
    CL_CTR_PV_NODE_ID,     /* this node's id in the cluster, NULL if unassigned */
    CL_CTR_PV_MY_IP,       /* controller identity IP                           */
    CL_CTR_PV_MEMBERS,     /* live member count                                */
    CL_CTR_PV_SHTAG_MODE,  /* auto | forced                                    */
    CL_CTR_PV_FORCED_NODE, /* node pinned by clusterer:shtag_force, NULL if auto  */
    CL_CTR_PV_MAINT,       /* this node's maintenance: none | evicted | full   */
};

/* Optional (cluster_id) argument; bare form leaves the spec zeroed (cid 0). */
int cl_ctr_pv_parse_cluster(pv_spec_p sp, const str *in)
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
    /* str2int rejects any non-digit; the length cap keeps a huge value from
     * wrapping into a valid id */
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
	else if (cl->peers->my_maint != CL_CTR_MAINT_NONE)
	    sval = "maintenance";
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

int w_cl_ctr_node_is_master(struct sip_msg *msg, int *cid, int *nid)
{
    int im = 0;
    if (cl_ctr_find_peer(cid ? *cid : 0, nid ? *nid : 0, &im, NULL, NULL, NULL, 0) < 0)
	return -1;
    return im ? 1 : -1;
}

/* cl_ctr_node_present(cluster_id, node_id) -> true if node_id is a live member */
int w_cl_ctr_node_present(struct sip_msg *msg, int *cid, int *nid)
{
    return cl_ctr_find_peer(cid ? *cid : 0, nid ? *nid : 0, NULL, NULL, NULL, NULL, 0) == 0
           ? 1 : -1;
}

/* cl_ctr_get_node_role(cluster_id, node_id, out)
 *   -> out=master|backup|maintenance|member */
int w_cl_ctr_get_node_role(struct sip_msg *msg, int *cid, int *nid,
                                  pv_spec_t *out)
{
    int im = 0, ib = 0, mt = CL_CTR_MAINT_NONE;
    if (cl_ctr_find_peer(cid ? *cid : 0, nid ? *nid : 0, &im, &ib, &mt, NULL, 0) < 0)
	return -1;
    return cl_ctr_out_str(msg, out, im ? "master" : ib ? "backup"
                          : mt != CL_CTR_MAINT_NONE ? "maintenance" : "member") == 0
           ? 1 : -1;
}

/* cl_ctr_get_node_maint(cluster_id, node_id, out) -> out=none|evicted|full */
int w_cl_ctr_get_node_maint(struct sip_msg *msg, int *cid, int *nid,
                                   pv_spec_t *out)
{
    int mt = CL_CTR_MAINT_NONE;
    if (cl_ctr_find_peer(cid ? *cid : 0, nid ? *nid : 0, NULL, NULL, &mt, NULL, 0) < 0)
	return -1;
    return cl_ctr_out_str(msg, out, cl_ctr_maint_name(mt)) == 0 ? 1 : -1;
}

int w_cl_ctr_get_node_ip(struct sip_msg *msg, int *cid, int *nid,
                                pv_spec_t *out)
{
    char ipbuf[INET_ADDRSTRLEN];
    if (cl_ctr_find_peer(cid ? *cid : 0, nid ? *nid : 0, NULL, NULL, NULL,
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

/* cl_ctr_set_maintenance(cluster_id, state): put THIS node in ("evicted" or
 * "full") or out ("none") of maintenance.  1 on success, -1 otherwise. */
int w_cl_ctr_set_maintenance(struct sip_msg *msg, int *cid, str *state)
{
    int i, st = cl_ctr_maint_parse(state->s, state->len);

    if (st < 0) {
	LM_ERR("clusterer_controller: cl_ctr_set_maintenance: state must be "
	       "evicted, full or none, not '%.*s'\n", state->len, state->s);
	return -1;
    }
    for (i = 0; i < cl_ctr_cluster_count; i++)
	if (cl_ctr_clusters[i].cluster_id == *cid && cl_ctr_clusters[i].peers)
	    return cl_ctr_set_my_maint(&cl_ctr_clusters[i], st) == 0 ? 1 : -1;
    LM_ERR("clusterer_controller: cl_ctr_set_maintenance: no cluster %d\n", *cid);
    return -1;
}
