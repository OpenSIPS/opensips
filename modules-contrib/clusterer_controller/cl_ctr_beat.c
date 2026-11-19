/*
 * clusterer_controller - heartbeats: every member multicasts its ALIVE each
 * second, with its links and capability states; who is heard decides who is up
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
#include "cl_ctr_data.h"
#include "node_info.h"
#include "clusterer.h"
#include "clusterer_ctrl.h"

typedef struct {
    uint16_t id;
    uint8_t  heard;
    char     ip[CL_CTR_MAX_IP_LEN + 1];
} cl_ctr_heard_chg_t;

/* who is heard: silent past dead_ms is gone.  Losing many members at once
 * means this node is the slow one, so it waits longer instead (Lifeguard) */
static void cl_ctr_heard_round(cl_ctr_cluster_t *cl)
{
    static cl_ctr_heard_chg_t chg[CL_CTR_MAX_PEERS];
    long long now = cl_ctr_now_ms();
    int       i, n = 0, lost = 0, live = 0, suspect, stretched = 0;

    if (cl->dead_ms < CL_CTR_DEAD_MS)
        cl->dead_ms = CL_CTR_DEAD_MS;

    lock_start_write(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e = &cl->peers->entries[i];
        uint8_t        h;

        if (e->node_id == 0 || strcmp(e->ip, my_ip) == 0)
            continue;
        /* announced, not heard yet: its silence counts from now */
        if (!e->heard_ms)
            e->heard_ms = now;
        h = (now - e->heard_ms < cl->dead_ms) ? CL_CTR_HEARD_YES : CL_CTR_HEARD_NO;
        /* first look: clusterer took it as heard when it was added */
        if (e->heard == CL_CTR_HEARD_UNSET)
            e->heard = CL_CTR_HEARD_YES;
        live += (e->heard == CL_CTR_HEARD_YES);
        if (h == e->heard)
            continue;
        lost += (h == CL_CTR_HEARD_NO);
        chg[n].id    = e->node_id;
        chg[n].heard = h;
        snprintf(chg[n].ip, sizeof chg[n].ip, "%s", e->ip);
        n++;
    }

    suspect = (lost >= CL_CTR_SUSPECT_MIN && lost * 2 >= live);
    if (suspect && cl->dead_ms < CL_CTR_DEAD_MAX_MS) {
        cl->dead_ms *= 2;
        if (cl->dead_ms > CL_CTR_DEAD_MAX_MS)
            cl->dead_ms = CL_CTR_DEAD_MAX_MS;
        stretched = 1;
    }
    if (lost || suspect) {
        cl->dead_clean = 0;
    } else if (cl->dead_ms > CL_CTR_DEAD_MS &&
               ++cl->dead_clean >= CL_CTR_DEAD_RELAX_ROUNDS) {
        cl->dead_ms /= 2;
        if (cl->dead_ms < CL_CTR_DEAD_MS)
            cl->dead_ms = CL_CTR_DEAD_MS;
        cl->dead_clean = 0;
    }

    /* stretched: the members just lost are kept for the longer wait */
    for (i = 0; i < n; ) {
        if (stretched && chg[i].heard == CL_CTR_HEARD_NO) {
            chg[i] = chg[--n];
            continue;
        }
        i++;
    }
    for (i = 0; i < n; i++) {
        cl_ctr_peer_t *e = cl_ctr_peer_by_ip_locked(cl, chg[i].ip);
        if (e)
            e->heard = chg[i].heard;
    }
    lock_stop_write(cl->peers->lock);

    if (stretched)
        LM_WARN("clusterer_controller: [cluster %d] %d of %d members went "
                "silent at once - this node is more likely the slow one; "
                "waiting up to %d ms for them before reporting them down\n",
                cl->cluster_id, lost, live, cl->dead_ms);

    for (i = 0; i < n; i++) {
        int yes = (chg[i].heard == CL_CTR_HEARD_YES);

        LM_INFO("clusterer_controller: [cluster %d] node %u (%s) %s\n",
                cl->cluster_id, chg[i].id, chg[i].ip,
                yes ? "is heard again" : "went silent - reported down");
        if (clctl_loaded)
            clusterer_ctrl_set_heard(cl->cluster_id, chg[i].id, yes);
    }
}

/* every second while ACTIVE */
void cl_ctr_beat(cl_ctr_cluster_t *cl)
{
    if (cl->have_session_key)
        cl_ctr_send_alive(cl->sock, cl);
    cl_ctr_heard_round(cl);
    cl_ctr_data_round(cl);
}

/* [count 1B] then per capability [name length 1B][name][state 1B] */
int cl_ctr_build_capst(cl_ctr_cluster_t *cl, char *p, int room)
{
    cluster_info_t   *c;
    struct local_cap *cap;
    int               len = 1, n = 0;

    if (room < 1)
        return 0;
    p[0] = 0;
    if (!clctl_loaded || !cl_list_lock)
        return 1;

    lock_start_read(cl_list_lock);
    c = get_cluster_by_id(cl->cluster_id);
    for (cap = c ? c->capabilities : NULL; cap && n < 255; cap = cap->next) {
        int nl = cap->reg.name.len;

        if (nl > 255 || len + 2 + nl > room)
            break;
        p[len] = (char)nl;
        memcpy(p + len + 1, cap->reg.name.s, nl);
        lock_get(c->lock);
        p[len + 1 + nl] = (char)((cap->flags & CAP_STATE_OK) ? 1 : 0);
        lock_release(c->lock);
        len += 2 + nl;
        n++;
    }
    lock_stop_read(cl_list_lock);
    p[0] = (char)n;
    return len;
}

/* a member's capability states from its ALIVE, passed on when they changed */
void cl_ctr_note_capst(cl_ctr_cluster_t *cl, const char *ip,
                       const unsigned char *p, int len)
{
    cl_ctr_peer_t *e;
    uint32_t       sum = 2166136261u;     /* FNV-1a over the section */
    uint16_t       nid = 0;
    int            i, n, off;

    if (len < 1 || !clctl_loaded)
        return;
    for (i = 0; i < len; i++)
        sum = (sum ^ p[i]) * 16777619u;

    lock_start_write(cl->peers->lock);
    e = cl_ctr_peer_by_ip_locked(cl, ip);
    if (e && e->node_id && e->capst_sum != sum) {
        e->capst_sum = sum;
        nid = e->node_id;
    }
    lock_stop_write(cl->peers->lock);
    if (!nid)
        return;

    n = p[0];
    for (i = 0, off = 1; i < n && off < len; i++) {
        int nl = p[off];
        str name;

        if (off + 2 + nl > len)
            break;
        name.s   = (char *)p + off + 1;
        name.len = nl;
        clusterer_ctrl_set_cap_state(cl->cluster_id, nid, &name,
                                     p[off + 1 + nl] == 1);
        off += 2 + nl;
    }
}

/* member, no master heard: may this joiner be told to wait now?  Each joiner
 * at most once in CL_CTR_JW_GIVEN_MS from each member */
int cl_ctr_join_wait_due(cl_ctr_cluster_t *cl, const char *ip)
{
    uint32_t  ipn = ip_to_num(ip);
    long long now = cl_ctr_now_ms();
    int       i, slot = 0;

    for (i = 0; i < CL_CTR_JW_GIVEN_SZ; i++) {
        if (cl->jw_given[i].ip_num == ipn) {
            if (now - cl->jw_given[i].at_ms < CL_CTR_JW_GIVEN_MS)
                return 0;
            slot = i;
            break;
        }
        if (cl->jw_given[i].at_ms < cl->jw_given[slot].at_ms)
            slot = i;
    }
    cl->jw_given[slot].ip_num = ipn;
    cl->jw_given[slot].at_ms  = now;
    return 1;
}
