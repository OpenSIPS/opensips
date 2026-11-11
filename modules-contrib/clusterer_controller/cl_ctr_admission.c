/*
 * clusterer_controller - admission: the master admits a few joiners at a
 * time and holds each CONNECTING until its links to every member are up
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
#include "cl_ctr_stats.h"
#include "node_info.h"
#include "clusterer.h"
#include "clusterer_ctrl.h"

#define CL_CTR_CONN_PAIRS_LOGGED 6    /* down pairs a warning names */

static int cl_ctr_admit_batch(int live)
{
    return live >= CL_CTR_ADMIT_LARGE_FROM ? CL_CTR_ADMIT_BATCH_LARGE
                                           : CL_CTR_ADMIT_BATCH;
}

static int cl_ctr_stuck(const cl_ctr_peer_t *e, long long now_ms)
{
    return e->connecting && e->conn_since_ms &&
           now_ms - e->conn_since_ms >= CL_CTR_CONNECT_MS;
}

static int cl_ctr_parked(const cl_ctr_peer_t *e, long long now_ms)
{
    return e->connecting && e->conn_since_ms &&
           now_ms - e->conn_since_ms >= CL_CTR_PARK_MS;
}

/* master, peers lock held: 0 admit into CONNECTING, else the 1-based queue
 * place (length in @qlen); held while one is stuck and not yet parked */
int cl_ctr_admit_gate_locked(cl_ctr_cluster_t *cl, const char *ip,
                             uint16_t *qlen)
{
    static long long said_ms;   /* worker-local: the mastership last explained */
    time_t        now    = cl_ctr_now();
    long long     win_ms = (long long)query_time * CL_CTR_ELECT_FACTOR * 1000;
    time_t        cutoff = now - (time_t)(win_ms / 1000);
    long long     now_ms = cl_ctr_now_ms();
    cl_ctr_peer_t *self;
    int           i, live = 0, busy = 0, stuck = 0, parked = 0, unheard = 0;
    int           pos = -1, unconfirmed;

    *qlen = 0;

    /* admitted already, its handshake lost: the same admission again */
    self = cl_ctr_peer_by_ip_locked(cl, ip);
    if (self && self->connecting)
        return 0;

    /* admitted members only: a joiner merely heard has no caps yet; a member
     * not heard since this mastership began may be old or follow another */
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e = &cl->peers->entries[i];
        if (e == self || e->node_id == 0)
            continue;
        if (e->last_seen >= cutoff) {
            int me = (strcmp(e->ip, my_ip) == 0);
            live++;
            if (!me && e->caps_ms < cl->master_since_ms)
                unheard++;
        }
        if (cl_ctr_parked(e, now_ms))
            parked++;
        else if (e->connecting) {
            busy++;
            stuck |= cl_ctr_stuck(e, now_ms);
        }
    }

    /* PreVote: a mastership asserted without a raised term may face a live
     * master; one election window without yielding to it settles that */
    unconfirmed = cl->master_unconfirmed && now_ms - cl->master_since_ms < win_ms;
    if ((unheard || unconfirmed) && said_ms != cl->master_since_ms) {
        said_ms = cl->master_since_ms;
        LM_INFO("clusterer_controller: [cluster %d] admitting nobody yet: %s - "
                "joiners wait in the queue\n", cl->cluster_id, unconfirmed
                ? "this mastership is unconfirmed (its term was not raised)"
                : "some members have not been heard since this node became master");
    }

    for (i = 0; i < cl->admq_n; ) {
        if (now - cl->admq[i].last > CL_CTR_ADMQ_IDLE) {
            memmove(&cl->admq[i], &cl->admq[i + 1],
                    (cl->admq_n - i - 1) * sizeof cl->admq[0]);
            cl->admq_n--;
            continue;
        }
        if (strcmp(cl->admq[i].ip, ip) == 0)
            pos = i;
        i++;
    }
    if (pos < 0) {
        if (cl->admq_n >= CL_CTR_MAX_PEERS) {
            *qlen = (uint16_t)cl->admq_n;
            return cl->admq_n;
        }
        pos = cl->admq_n++;
        snprintf(cl->admq[pos].ip, sizeof cl->admq[pos].ip, "%s", ip);
    }
    cl->admq[pos].last = now;

    if (!stuck && parked <= CL_CTR_PARK_MAX && !unheard && !unconfirmed &&
            pos < cl_ctr_admit_batch(live) - busy) {
        memmove(&cl->admq[pos], &cl->admq[pos + 1],
                (cl->admq_n - pos - 1) * sizeof cl->admq[0]);
        cl->admq_n--;
        return 0;
    }
    *qlen = (uint16_t)cl->admq_n;
    return pos + 1;
}

/* payload: [target_ip NUL][position 2B BE][queued 2B BE][nonce 24B], sealed
 * with the bootstrap key; the nonce is the JOIN_REQ's, as in JOIN_REJECT */
void cl_ctr_send_join_wait(int sock, const char *target_ip, cl_ctr_cluster_t *cl,
                           uint16_t pos, uint16_t qlen,
                           const unsigned char *req_nonce,
                           const struct sockaddr *dest, socklen_t destlen)
{
    char      pkt[CL_CTR_SMALL_PKT_SZ + 4 + CL_CTR_NONCE_SZ];
    uint32_t  seq = htonl(++cl->peers->my_seq);
    int       ip_len = (int)strnlen(target_ip, CL_CTR_MAX_IP_LEN);
    uint16_t  v;
    char     *p;

    memcpy(pkt, CL_CTR_BOOTSTRAP_MAGIC, CL_CTR_MAGIC_SZ);
    pkt[CL_CTR_WIRE_HDR_SZ] = (char)CL_CTR_PKT_JOIN_WAIT;
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + 1, &seq, CL_CTR_SEQ_SZ);
    p = pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ;
    memcpy(p, target_ip, ip_len);
    p[ip_len] = '\0';
    p += ip_len + 1;
    v = htons(pos);
    memcpy(p, &v, 2);
    p += 2;
    v = htons(qlen);
    memcpy(p, &v, 2);
    p += 2;
    memcpy(p, req_nonce, CL_CTR_NONCE_SZ);
    p += CL_CTR_NONCE_SZ;

    if (cl_ctr_seal_and_send_to(sock, cl, pkt, (int)(p - (pkt + CL_CTR_WIRE_HDR_SZ)),
                                cl->key, CL_CTR_PKT_JOIN_WAIT, dest, destlen) == 0)
        LM_DBG("clusterer_controller: [cluster %d] %s queued for admission, "
               "position %u of %u\n", cl->cluster_id, target_ip, pos, qlen);
}

/* joiner: a master exists and queued us - keep asking rather than found */
void cl_ctr_handle_join_wait(const char *payload, int payload_len,
                             const char *sender_ip, cl_ctr_cluster_t *cl)
{
    long long now_ms = cl_ctr_now_ms();
    uint16_t  pos, qlen;
    int       l, still_new;

    lock_start_read(cl->peers->lock);
    still_new = (cl->peers->node_state == CL_CTR_NODE_NEW);
    lock_stop_read(cl->peers->lock);
    if (!still_new)
        return;

    l = (int)strnlen(payload, payload_len);
    if (l + 1 + 4 + CL_CTR_NONCE_SZ > payload_len || strcmp(payload, my_ip) != 0 ||
            !cl_ctr_join_nonce_ours(cl, (const unsigned char *)payload + l + 5))
        return;
    pos  = (uint16_t)(((unsigned char)payload[l + 1] << 8) | (unsigned char)payload[l + 2]);
    qlen = (uint16_t)(((unsigned char)payload[l + 3] << 8) | (unsigned char)payload[l + 4]);

    /* it decrypted with the bootstrap key: the password is right, and the
     * session traffic we cannot read yet is this cluster's */
    cl->auth_fail_pkts       = 0;
    cl->auth_defer_count     = 0;
    cl->bootstrap_auth_fails = 0;
    if (now_ms < cl->join_wait_until_ms)
        ;
    else if (pos == 0)
        LM_INFO("clusterer_controller: [cluster %d] member %s says the cluster "
                "has no master right now - waiting for one instead of founding\n",
                cl->cluster_id, sender_ip);
    else
        LM_INFO("clusterer_controller: [cluster %d] master %s queued this node "
                "for admission (position %u of %u) - waiting for it\n",
                cl->cluster_id, sender_ip, pos, qlen);
    cl->join_wait_until_ms = now_ms + CL_CTR_JOIN_WAIT_HOLD_MS;
    cl->join_wait_pos      = pos;
}

void cl_ctr_build_conn_bitmap(cl_ctr_cluster_t *cl, unsigned char *bm)
{
    int i;

    memset(bm, 0, CL_CTR_ALIVE_BITMAP_SZ);
    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e   = &cl->peers->entries[i];
        uint16_t       nid = e->node_id;
        if (nid == 0 || nid > CL_CTR_MAX_PEERS || !e->connecting)
            continue;
        bm[nid >> 3] |= (unsigned char)(1u << (nid & 7));
    }
    lock_stop_read(cl->peers->lock);
}

/* non-master: CONNECTING as the master relays it (NULL: an older master,
 * none), this node's own entry included; how many are CONNECTING */
int cl_ctr_apply_conn_bitmap(cl_ctr_cluster_t *cl, const unsigned char *bm)
{
    int i, online = 0, n = 0;

    lock_start_write(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e   = &cl->peers->entries[i];
        uint16_t       nid = e->node_id;
        uint8_t        c   = 0;
        if (bm && nid != 0 && nid <= CL_CTR_MAX_PEERS)
            c = (bm[nid >> 3] & (unsigned char)(1u << (nid & 7))) ? 1 : 0;
        if (e->connecting && !c && strcmp(e->ip, my_ip) == 0)
            online = 1;
        e->connecting    = c;
        e->conn_since_ms = 0;
        n += c;
    }
    lock_stop_write(cl->peers->lock);

    if (online) {
        /* it may have missed replication over a link that was down */
        LM_INFO("clusterer_controller: [cluster %d] this node is ONLINE - "
                "syncing its data again\n", cl->cluster_id);
        clusterer_ctrl_resync_from(cl->cluster_id, 0);
    }
    return n;
}

/* the nodes this node has a BIN link up with, by node_id, from its own
 * pings: first-hand, unlike the link map flooded between the nodes */
void cl_ctr_build_link_bitmap(cl_ctr_cluster_t *cl, unsigned char *bm)
{
    cluster_info_t *c;
    node_info_t    *nd;

    memset(bm, 0, CL_CTR_ALIVE_BITMAP_SZ);
    lock_start_read(cl_list_lock);
    c = get_cluster_by_id(cl->cluster_id);
    for (nd = c ? c->node_list : NULL; nd; nd = nd->next) {
        if (nd->node_id <= 0 || nd->node_id > CL_CTR_MAX_PEERS)
            continue;
        lock_get(nd->lock);
        if (nd->link_state == LS_UP || (nd->flags & NODE_LINK_HELD))
            bm[nd->node_id >> 3] |= (unsigned char)(1u << (nd->node_id & 7));
        lock_release(nd->lock);
    }
    lock_stop_read(cl_list_lock);
}

void cl_ctr_note_links(cl_ctr_cluster_t *cl, const char *ip, const unsigned char *bm)
{
    cl_ctr_peer_t *e;
    uint16_t       nid = 0;

    lock_start_write(cl->peers->lock);
    e = cl_ctr_peer_by_ip_locked(cl, ip);
    if (e) {
        /* changed links go on to clusterer's topology, for MI only */
        if (!e->links_known || memcmp(e->links, bm, CL_CTR_ALIVE_BITMAP_SZ) != 0)
            nid = e->node_id;
        memcpy(e->links, bm, CL_CTR_ALIVE_BITMAP_SZ);
        e->links_known = 1;
    }
    lock_stop_write(cl->peers->lock);
    if (nid && clctl_loaded)
        clusterer_ctrl_set_links(cl->cluster_id, nid, bm, CL_CTR_ALIVE_BITMAP_SZ);
}

static int cl_ctr_bit(const unsigned char *bm, int id)
{
    return (bm[id >> 3] >> (id & 7)) & 1;
}

typedef struct {
    uint16_t      id;
    char          ip[CL_CTR_MAX_IP_LEN + 1];
    uint8_t       conn, stuck, known;
    long long     since;
    unsigned char links[CL_CTR_ALIVE_BITMAP_SZ];
} cl_ctr_adm_node_t;

/* pairs between @j and the others not up both ways, by what each side
 * reports of its own links; the first few named */
static int cl_ctr_links_down(cl_ctr_adm_node_t *m, int n, int j,
                             char *why, int why_sz)
{
    int i, down = 0, len = 0;

    why[0] = '\0';
    for (i = 0; i < n; i++) {
        int fwd, back;
        /* a joiner already stuck does not hold the others back */
        if (i == j || (m[i].conn && m[i].stuck))
            continue;
        fwd  = m[j].known && cl_ctr_bit(m[j].links, m[i].id);
        back = m[i].known && cl_ctr_bit(m[i].links, m[j].id);
        if (fwd && back)
            continue;
        if (++down <= CL_CTR_CONN_PAIRS_LOGGED && len < why_sz)
            len += snprintf(why + len, why_sz - len, "%s%s %s %s",
                            down > 1 ? ", " : "", m[j].ip,
                            !fwd && !back ? "<->" : !fwd ? "->" : "<-", m[i].ip);
    }
    return down;
}

/* master, each keepalive tick: CONNECTING with every link up both ways -> ONLINE;
 * past CL_CTR_CONNECT_MS it is named with the pairs down and holds the queue */
void cl_ctr_admission_tick(cl_ctr_cluster_t *cl)
{
    static cl_ctr_adm_node_t m[CL_CTR_MAX_PEERS];
    unsigned char mine[CL_CTR_ALIVE_BITMAP_SZ];
    time_t    now    = cl_ctr_now();
    time_t    cutoff = now - (time_t)(query_time * CL_CTR_ELECT_FACTOR);
    long long now_ms = cl_ctr_now_ms();
    char      why[256];
    int       n = 0, i, j, any = 0, down, checked;

    cl_ctr_build_link_bitmap(cl, mine);
    lock_start_write(cl->peers->lock);
    for (i = 0; i < cl->peers->count && n < CL_CTR_MAX_PEERS; i++) {
        cl_ctr_peer_t *e = &cl->peers->entries[i];
        if (e->node_id == 0 || e->node_id > CL_CTR_MAX_PEERS ||
                e->last_seen < cutoff || e->maint == CL_CTR_MAINT_FULL)
            continue;
        if (e->connecting) {
            any = 1;
            if (!e->conn_since_ms)
                e->conn_since_ms = now_ms;
        }
        m[n].id    = e->node_id;
        snprintf(m[n].ip, sizeof m[n].ip, "%s", e->ip);
        m[n].conn  = e->connecting;
        m[n].since = e->conn_since_ms;
        m[n].stuck = cl_ctr_stuck(e, now_ms);
        if (strcmp(e->ip, my_ip) == 0) {
            m[n].known = 1;
            memcpy(m[n].links, mine, CL_CTR_ALIVE_BITMAP_SZ);
        } else {
            m[n].known = e->links_known;
            memcpy(m[n].links, e->links, CL_CTR_ALIVE_BITMAP_SZ);
        }
        n++;
    }
    lock_stop_write(cl->peers->lock);
    if (!any)
        return;

    for (j = 0; j < n; j++) {
        cl_ctr_peer_t *e;
        int            warn = 0, first = 0, park = 0;

        if (!m[j].conn)
            continue;
        down = cl_ctr_links_down(m, n, j, why, sizeof why);
        for (i = 0, checked = 0; i < n; i++)
            checked += (i != j && !(m[i].conn && m[i].stuck));

        lock_start_write(cl->peers->lock);
        e = cl_ctr_peer_by_ip_locked(cl, m[j].ip);
        if (!e || !e->connecting) {
            lock_stop_write(cl->peers->lock);
            continue;
        }
        if (down == 0) {
            e->connecting    = 0;
            e->conn_since_ms = 0;
            e->conn_warned   = 0;
            e->conn_parked   = 0;
        } else {
            if (m[j].stuck &&
                    (!e->conn_warned || now - e->conn_warned >= CL_CTR_CONNECT_WARN_IVL)) {
                first = !e->conn_warned;
                e->conn_warned = now;
                warn = 1;
            }
            if (!e->conn_parked && cl_ctr_parked(e, now_ms))
                park = e->conn_parked = 1;
        }
        lock_stop_write(cl->peers->lock);

        if (down == 0) {
            LM_INFO("clusterer_controller: [cluster %d] %s is ONLINE - its links "
                    "to all %d member(s) are up both ways, %.1f s after admission\n",
                    cl->cluster_id, m[j].ip, checked,
                    (now_ms - m[j].since) / 1000.0);
            cl_ctr_note_admission(cl, m[j].ip, m[j].id, "online");
        } else if (park) {
            LM_WARN("clusterer_controller: [cluster %d] %s is parked: still "
                    "CONNECTING after %d s (%s%s) - it keeps no role or tag, and "
                    "other nodes are admitted past it (up to %d parked)\n",
                    cl->cluster_id, m[j].ip, CL_CTR_PARK_MS / 1000, why,
                    down > CL_CTR_CONN_PAIRS_LOGGED ? ", ..." : "", CL_CTR_PARK_MAX);
            cl_ctr_note_admission(cl, m[j].ip, m[j].id, "parked");
        } else if (warn) {
            LM_WARN("clusterer_controller: [cluster %d] %s is still CONNECTING "
                    "after %lld s: %d of %d link(s) not up both ways (%s%s) - no "
                    "more nodes are admitted until it is ONLINE, gone or parked "
                    "after %d s; check its links, e.g. a full neighbour (ARP) "
                    "table (net.ipv4.neigh.default.gc_thresh1/2/3)\n",
                    cl->cluster_id, m[j].ip, (now_ms - m[j].since) / 1000,
                    down, checked, why,
                    down > CL_CTR_CONN_PAIRS_LOGGED ? ", ..." : "", CL_CTR_PARK_MS / 1000);
            if (first)
                cl_ctr_note_admission(cl, m[j].ip, m[j].id, "stuck");
        }
    }
}
