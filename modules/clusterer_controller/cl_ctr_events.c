/*
 * clusterer_controller - events
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
#include "cl_ctr_events.h"
#include "../../evi/evi_modules.h"
#include "../../evi/evi_params.h"

/* -------------------------------------------------------------------------
 * Cluster-state events.  The state changes inside the worker, often with
 * the peers lock held; an event_route runs in the raising process and may
 * read $cl_ctr_*, which takes that lock.  So a change only queues its event
 * here, and the worker raises the queue after each handler returns, when
 * no lock is held.  Each worker serves one cluster, so one queue per
 * process is enough.
 * ------------------------------------------------------------------------- */

enum { CL_CTR_EV_MAINT, CL_CTR_EV_ROLE, CL_CTR_EV_MASTER, CL_CTR_EV_MEMBER,
       CL_CTR_EV_REFUSED, CL_CTR_EV_MERGE, CL_CTR_EV_COUNT };

#define CL_CTR_EV_MAX_PARAMS 5

static struct {
    str           name;
    const char   *pnames[CL_CTR_EV_MAX_PARAMS];
    event_id_t    id;
    evi_params_p  params;
    evi_param_p   p[CL_CTR_EV_MAX_PARAMS];
} cl_ctr_evs[CL_CTR_EV_COUNT] = {
    [CL_CTR_EV_MAINT]   = { .name = str_init("E_CL_CTR_MAINTENANCE"), .id = EVI_ERROR,
                            .pnames = { "cluster_id", "node_id", "state" } },
    [CL_CTR_EV_ROLE]    = { .name = str_init("E_CL_CTR_ROLE"), .id = EVI_ERROR,
                            .pnames = { "cluster_id", "role", "old_role" } },
    [CL_CTR_EV_MASTER]  = { .name = str_init("E_CL_CTR_MASTER"), .id = EVI_ERROR,
                            .pnames = { "cluster_id", "master_ip", "node_id" } },
    [CL_CTR_EV_MEMBER]  = { .name = str_init("E_CL_CTR_MEMBER"), .id = EVI_ERROR,
                            .pnames = { "cluster_id", "node_id", "ip", "state", "reason" } },
    [CL_CTR_EV_REFUSED] = { .name = str_init("E_CL_CTR_REFUSED"), .id = EVI_ERROR,
                            .pnames = { "cluster_id", "ip", "reason" } },
    [CL_CTR_EV_MERGE]   = { .name = str_init("E_CL_CTR_MERGE"), .id = EVI_ERROR,
                            .pnames = { "cluster_id", "master_ip", "was_master" } },
};

/* A queued event: integers and strings by position, in the order of the
 * event's parameters - an int parameter takes the next of i[], a string
 * the next of s[] (s[] points to static text, or to ip). */
typedef struct {
    int         ev;
    int         i[3];
    const char *s[3];
    char        ip[CL_CTR_MAX_IP_LEN + 1];
} cl_ctr_ev_item_t;

/* which parameters are integers, per event (1 bit per parameter) */
static const unsigned char cl_ctr_ev_int_mask[CL_CTR_EV_COUNT] = {
    [CL_CTR_EV_MAINT]   = 0x03,   /* cluster_id, node_id    */
    [CL_CTR_EV_ROLE]    = 0x01,   /* cluster_id             */
    [CL_CTR_EV_MASTER]  = 0x05,   /* cluster_id, node_id    */
    [CL_CTR_EV_MEMBER]  = 0x03,   /* cluster_id, node_id    */
    [CL_CTR_EV_REFUSED] = 0x01,   /* cluster_id             */
    [CL_CTR_EV_MERGE]   = 0x05,   /* cluster_id, was_master */
};

#define CL_CTR_EV_QUEUE 64
static cl_ctr_ev_item_t cl_ctr_evq[CL_CTR_EV_QUEUE];
static int              cl_ctr_evq_head, cl_ctr_evq_len;
static unsigned long    cl_ctr_evq_lost;

int cl_ctr_events_init(void)
{
    int e, k;
    str pn;

    for (e = 0; e < CL_CTR_EV_COUNT; e++) {
        cl_ctr_evs[e].id = evi_publish_event(cl_ctr_evs[e].name);
        cl_ctr_evs[e].params = pkg_malloc(sizeof *cl_ctr_evs[e].params);
        if (cl_ctr_evs[e].id == EVI_ERROR || !cl_ctr_evs[e].params) {
            LM_ERR("clusterer_controller: cannot publish %.*s\n",
                   cl_ctr_evs[e].name.len, cl_ctr_evs[e].name.s);
            return -1;
        }
        memset(cl_ctr_evs[e].params, 0, sizeof *cl_ctr_evs[e].params);
        for (k = 0; k < CL_CTR_EV_MAX_PARAMS && cl_ctr_evs[e].pnames[k]; k++) {
            pn.s   = (char *)cl_ctr_evs[e].pnames[k];
            pn.len = strlen(pn.s);
            if (!(cl_ctr_evs[e].p[k] = evi_param_create(cl_ctr_evs[e].params, &pn))) {
                LM_ERR("clusterer_controller: cannot create the parameters "
                       "of %.*s\n", cl_ctr_evs[e].name.len, cl_ctr_evs[e].name.s);
                return -1;
            }
        }
    }
    return 0;
}

/* a slot at the queue's tail; on overflow the oldest event is lost */
static cl_ctr_ev_item_t *cl_ctr_ev_slot(int ev)
{
    cl_ctr_ev_item_t *it;

    /* nobody listens: nothing to queue */
    if (cl_ctr_evs[ev].id == EVI_ERROR || !evi_probe_event(cl_ctr_evs[ev].id))
        return NULL;
    if (cl_ctr_evq_len == CL_CTR_EV_QUEUE) {
        cl_ctr_evq_head = (cl_ctr_evq_head + 1) % CL_CTR_EV_QUEUE;
        cl_ctr_evq_len--;
        if (cl_ctr_evq_lost++ == 0)
            LM_WARN("clusterer_controller: event queue full - the oldest "
                    "events are dropped\n");
    }
    it = &cl_ctr_evq[(cl_ctr_evq_head + cl_ctr_evq_len++) % CL_CTR_EV_QUEUE];
    memset(it, 0, sizeof *it);
    it->ev = ev;
    return it;
}

static void cl_ctr_ev_copy_ip(cl_ctr_ev_item_t *it, const char *ip)
{
    snprintf(it->ip, sizeof it->ip, "%s", ip ? ip : "");
}

void cl_ctr_ev_maintenance(cl_ctr_cluster_t *cl, int node_id, int st)
{
    cl_ctr_ev_item_t *it = cl_ctr_ev_slot(CL_CTR_EV_MAINT);

    if (!it)
        return;
    it->i[0] = cl->cluster_id;
    it->i[1] = node_id;
    it->s[0] = cl_ctr_maint_name(st);
}

void cl_ctr_ev_role(cl_ctr_cluster_t *cl, int old_role, int new_role)
{
    cl_ctr_ev_item_t *it = cl_ctr_ev_slot(CL_CTR_EV_ROLE);

    if (!it)
        return;
    it->i[0] = cl->cluster_id;
    it->s[0] = cl_ctr_role_name(new_role);
    it->s[1] = cl_ctr_role_name(old_role);
}

void cl_ctr_ev_master(cl_ctr_cluster_t *cl, const char *master_ip, int node_id)
{
    cl_ctr_ev_item_t *it = cl_ctr_ev_slot(CL_CTR_EV_MASTER);

    if (!it)
        return;
    cl_ctr_ev_copy_ip(it, master_ip);
    it->i[0] = cl->cluster_id;
    it->s[0] = it->ip;
    it->i[1] = node_id;
}

void cl_ctr_ev_member(cl_ctr_cluster_t *cl, const char *ip, int node_id,
                      int joined, const char *reason)
{
    cl_ctr_ev_item_t *it = cl_ctr_ev_slot(CL_CTR_EV_MEMBER);

    if (!it)
        return;
    cl_ctr_ev_copy_ip(it, ip);
    it->i[0] = cl->cluster_id;
    it->i[1] = node_id;
    it->s[0] = it->ip;
    it->s[1] = joined ? "joined" : "left";
    it->s[2] = reason;
}

/* Refusals repeat for as long as the cause lasts: one event per address and
 * reason a minute. */
#define CL_CTR_EV_REFUSED_SLOTS 16
#define CL_CTR_EV_REFUSED_IVL   60
static struct {
    char        ip[CL_CTR_MAX_IP_LEN + 1];
    const char *reason;
    time_t      at;
} cl_ctr_ev_refused_seen[CL_CTR_EV_REFUSED_SLOTS];

void cl_ctr_ev_refused(cl_ctr_cluster_t *cl, const char *ip, const char *reason)
{
    cl_ctr_ev_item_t *it;
    time_t now = cl_ctr_now();
    int    k, oldest = 0;

    for (k = 0; k < CL_CTR_EV_REFUSED_SLOTS; k++) {
        if (cl_ctr_ev_refused_seen[k].reason == reason &&
                strcmp(cl_ctr_ev_refused_seen[k].ip, ip) == 0) {
            if (now - cl_ctr_ev_refused_seen[k].at < CL_CTR_EV_REFUSED_IVL)
                return;
            break;
        }
        if (cl_ctr_ev_refused_seen[k].at < cl_ctr_ev_refused_seen[oldest].at)
            oldest = k;
    }
    if (k == CL_CTR_EV_REFUSED_SLOTS)
        k = oldest;
    snprintf(cl_ctr_ev_refused_seen[k].ip, sizeof cl_ctr_ev_refused_seen[k].ip,
             "%s", ip);
    cl_ctr_ev_refused_seen[k].reason = reason;
    cl_ctr_ev_refused_seen[k].at     = now;

    if (!(it = cl_ctr_ev_slot(CL_CTR_EV_REFUSED)))
        return;
    cl_ctr_ev_copy_ip(it, ip);
    it->i[0] = cl->cluster_id;
    it->s[0] = it->ip;
    it->s[1] = reason;
}

void cl_ctr_ev_merge(cl_ctr_cluster_t *cl, const char *master_ip, int was_master)
{
    cl_ctr_ev_item_t *it = cl_ctr_ev_slot(CL_CTR_EV_MERGE);

    if (!it)
        return;
    cl_ctr_ev_copy_ip(it, master_ip);
    it->i[0] = cl->cluster_id;
    it->s[0] = it->ip;
    it->i[1] = was_master ? 1 : 0;
}

static void cl_ctr_ev_raise(cl_ctr_ev_item_t *it)
{
    int   k, ni = 0, ns = 0, rc = 0;
    str   sv;

    for (k = 0; k < CL_CTR_EV_MAX_PARAMS && cl_ctr_evs[it->ev].pnames[k]; k++) {
        if (cl_ctr_ev_int_mask[it->ev] & (1 << k)) {
            rc = evi_param_set_int(cl_ctr_evs[it->ev].p[k], &it->i[ni++]);
        } else {
            sv.s   = (char *)(it->s[ns] ? it->s[ns] : "");
            sv.len = strlen(sv.s);
            ns++;
            rc = evi_param_set_str(cl_ctr_evs[it->ev].p[k], &sv);
        }
        if (rc < 0) {
            LM_ERR("clusterer_controller: cannot fill %.*s\n",
                   cl_ctr_evs[it->ev].name.len, cl_ctr_evs[it->ev].name.s);
            return;
        }
    }
    if (evi_raise_event(cl_ctr_evs[it->ev].id, cl_ctr_evs[it->ev].params) < 0)
        LM_ERR("clusterer_controller: cannot raise %.*s\n",
               cl_ctr_evs[it->ev].name.len, cl_ctr_evs[it->ev].name.s);
}

void cl_ctr_events_flush(void)
{
    cl_ctr_ev_item_t it;
    int              n = 0, k;

    /* an event_route may cause more events; they are raised in this pass
     * too, up to one queue's worth */
    while (cl_ctr_evq_len > 0 && n++ < CL_CTR_EV_QUEUE) {
        it = cl_ctr_evq[cl_ctr_evq_head];
        /* the copy's strings must not point into the slot, which a new
         * event may take while this one is raised */
        for (k = 0; k < 3; k++)
            if (it.s[k] == cl_ctr_evq[cl_ctr_evq_head].ip)
                it.s[k] = it.ip;
        cl_ctr_evq_head = (cl_ctr_evq_head + 1) % CL_CTR_EV_QUEUE;
        cl_ctr_evq_len--;
        cl_ctr_ev_raise(&it);
    }
}
