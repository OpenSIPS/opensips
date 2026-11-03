/*
 * clusterer_controller - ACK and bounded retransmit for 1:1 packets
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

/* raised in mod_init once the MTU is known; the provisional value covers the
 * control plane, all that can be sent before then */
int cl_ctr_retx_pkt_max = CL_CTR_NODE_ASSIGN_MAX_SZ;

/* worker-only, so the retransmit queue needs no lock */

/* Arm a timerfd with microsecond resolution (one-shot; 0/0 disarms). */
static void cl_ctr_arm_tfd_us(int tfd, uint64_t usec_value, uint64_t usec_interval)
{
    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec     = (time_t)(usec_value / 1000000);
    its.it_value.tv_nsec    = (long)((usec_value % 1000000) * 1000);
    its.it_interval.tv_sec  = (time_t)(usec_interval / 1000000);
    its.it_interval.tv_nsec = (long)((usec_interval % 1000000) * 1000);
    if (timerfd_settime(tfd, 0, &its, NULL) < 0)
        LM_WARN("clusterer_controller: timerfd_settime(us): %s\n", strerror(errno));
}

/* every path that clears `used` must come here: otherwise the buffer leaks,
 * as the next enqueue into the slot memsets the pointer away */
static void cl_ctr_retx_release(cl_ctr_cluster_t *cl, cl_ctr_retx_entry_t *e)
{
    if (e->pkt) {
        pkg_free(e->pkt);
        e->pkt = NULL;
    }
    if (e->used) {
        e->used = 0;
        if (cl->retx_count > 0)
            cl->retx_count--;
    }
}

/* too big to cache: sent once, never repaired - a downgraded guarantee, so a
 * warning, rate-limited since the oversize repeats every time */
static void cl_ctr_retx_too_big(cl_ctr_cluster_t *cl, int pkt_len)
{
    static unsigned int last_warn;
    unsigned int now = get_ticks();

    if (last_warn == 0 || now - last_warn >= CL_CTR_RELIABLE_WARN_IVL) {
        last_warn = now;
        LM_WARN("clusterer_controller: [cluster %d] a %d-byte packet asked for "
                "reliable delivery but the retransmit cache holds %d - it was "
                "sent once, best-effort, and will not be repaired. The bound "
                "follows this interface's MTU, so a payload within "
                "cc_max_payload (%d) always fits.\n",
                cl->cluster_id, pkt_len, cl_ctr_retx_pkt_max, cc_max_payload);
    }
}

/* arm for the EARLIEST deadline, always via here: re-arming to now + interval
 * per enqueue starves under load, and a fixed sweep overshoots short gaps */
static void cl_ctr_retx_rearm(cl_ctr_cluster_t *cl)
{
    utime_t now, first = 0;
    int i;

    if (cl->retx_count == 0) {
        cl_ctr_arm_tfd_us(cl->retx_tfd, 0, 0);      /* nothing pending */
        return;
    }

    for (i = 0; i < CL_CTR_RETX_QUEUE_SZ; i++)
        if (cl->retx_q[i].used &&
            (first == 0 || cl->retx_q[i].next_due_us < first))
            first = cl->retx_q[i].next_due_us;

    if (first == 0) {                                /* count/queue disagree */
        cl_ctr_arm_tfd_us(cl->retx_tfd, 0, 0);
        return;
    }

    now = get_uticks();
    /* never 0 us: that disarms timerfd, and a due entry would wait for the next
     * enqueue */
    cl_ctr_arm_tfd_us(cl->retx_tfd, first > now ? (uint64_t)(first - now) : 1, 0);
}

/* on demotion and re-key, so no stale KEY_GRANT/NODE_ASSIGN pushes a joiner
 * onto a dead key; ACKs gate nothing, so dropping only stops resends */
void cl_ctr_retx_flush(cl_ctr_cluster_t *cl)
{
    if (cl->retx_count == 0)
        return;
    LM_DBG("clusterer_controller: [cluster %d] flushing %d pending retransmit(s)\n",
           cl->cluster_id, cl->retx_count);
    {   /* release each, then clear: a bare memset over the array would drop
         * every entry's packet pointer on the floor. */
        int _i;
        for (_i = 0; _i < CL_CTR_RETX_QUEUE_SZ; _i++)
            cl_ctr_retx_release(cl, &cl->retx_q[_i]);
    }
    memset(cl->retx_q, 0, sizeof(cl->retx_q));
    cl->retx_count = 0;
    cl_ctr_arm_tfd_us(cl->retx_tfd, 0, 0);   /* disarm */
}

/* one entry for all members; the expected count is a snapshot - a node joining
 * a moment later never saw the message and is not owed one */
void cl_ctr_retx_enqueue_bcast(cl_ctr_cluster_t *cl, uint32_t seq,
                            const unsigned char *pkt, int pkt_len)
{
    cl_ctr_retx_entry_t *e = NULL;
    int i, n = 0;

    if (pkt_len <= 0 || pkt_len > cl_ctr_retx_pkt_max) {
        cl_ctr_retx_too_big(cl, pkt_len);
        return;
    }

    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++)
        if (cl->peers->entries[i].node_id > 0 &&
            cl->peers->entries[i].node_id <= CL_CTR_MAX_PEERS)
            n++;
    lock_stop_read(cl->peers->lock);

    if (n == 0) {
        LM_DBG("clusterer_controller: [cluster %d] reliable broadcast with no "
               "peers to acknowledge it - nothing to wait for\n",
               cl->cluster_id);
        return;
    }

    for (i = 0; i < CL_CTR_RETX_QUEUE_SZ; i++)
        if (!cl->retx_q[i].used) { e = &cl->retx_q[i]; break; }
    if (!e) {
        LM_DBG("clusterer_controller: [cluster %d] retransmit queue full - the "
               "broadcast went out once, unacknowledged\n", cl->cluster_id);
        return;
    }

    memset(e, 0, sizeof(*e));   /* pkt was NULLed by the release that freed it */
    e->pkt = pkg_malloc(pkt_len);
    if (!e->pkt) {
        LM_ERR("clusterer_controller: [cluster %d] no pkg for a %d-byte "
               "retransmit cache entry - broadcast sent once, best-effort\n",
               cl->cluster_id, pkt_len);
        return;
    }
    e->used         = 1;
    e->seq          = seq;
    e->type         = CL_CTR_PKT_CONSUMER_REL;
    e->is_bcast     = 1;
    e->expect_n     = (uint16_t)n;
    e->retries_left = cl->consumer_retries;
    e->retries_cfg  = (uint8_t)cl->consumer_retries;
    e->retry_ivl_us = (utime_t)cl->consumer_retry_ms * 1000;
    e->next_due_us  = get_uticks() + e->retry_ivl_us;
    e->pkt_len      = pkt_len;
    memcpy(e->pkt, pkt, pkt_len);
    cl->retx_count++;
    cl_ctr_retx_rearm(cl);
}

/* consumer budget, per cluster: the handshake's is pinned to the JOIN_REQ
 * retry interval, which says nothing about how long a consumer should wait */
void cl_ctr_retx_enqueue_consumer(cl_ctr_cluster_t *cl, uint32_t seq,
                            unsigned char type, const unsigned char *pkt,
                            int pkt_len, const struct sockaddr *dest,
                            socklen_t destlen)
{
    int i;

    cl_ctr_retx_enqueue(cl, seq, type, pkt, pkt_len, dest, destlen);
    /* override with the consumer budget; enqueue takes none since every other
     * caller wants the handshake numbers */
    for (i = 0; i < CL_CTR_RETX_QUEUE_SZ; i++)
        if (cl->retx_q[i].used && cl->retx_q[i].seq == seq &&
            cl->retx_q[i].type == type) {
            cl->retx_q[i].retries_left = cl->consumer_retries;
            cl->retx_q[i].retries_cfg  = (uint8_t)cl->consumer_retries;
            cl->retx_q[i].retry_ivl_us = (utime_t)cl->consumer_retry_ms * 1000;
            cl->retx_q[i].next_due_us  = get_uticks()
                                       + cl->retx_q[i].retry_ivl_us;
            break;
        }
    /* The deadline just moved in (consumer gaps are shorter than the
     * handshake's), so the timer enqueue armed has to be pulled forward. */
    cl_ctr_retx_rearm(cl);
}

/* @pkt is already sealed and sent; if the queue is full it went out once and
 * the joiner's JOIN_REQ retry remains the backstop */
void cl_ctr_retx_enqueue(cl_ctr_cluster_t *cl, uint32_t seq, unsigned char type,
                            const unsigned char *pkt, int pkt_len,
                            const struct sockaddr *dest, socklen_t destlen)
{
    cl_ctr_retx_entry_t *e;
    int i, slot = -1;

    if (pkt_len <= 0 || pkt_len > cl_ctr_retx_pkt_max ||
        destlen == 0 || destlen > (socklen_t)sizeof(cl->retx_q[0].dest)) {
        if (pkt_len > cl_ctr_retx_pkt_max)
            cl_ctr_retx_too_big(cl, pkt_len);
        return;
    }

    for (i = 0; i < CL_CTR_RETX_QUEUE_SZ; i++)
        if (!cl->retx_q[i].used) { slot = i; break; }
    if (slot < 0) {
        LM_DBG("clusterer_controller: [cluster %d] retransmit queue full, "
               "0x%02x sent best-effort\n", cl->cluster_id, type);
        return;
    }

    e = &cl->retx_q[slot];
    memset(e, 0, sizeof(*e));   /* pkt was NULLed by the release that freed it */
    e->pkt = pkg_malloc(pkt_len);
    if (!e->pkt) {
        LM_ERR("clusterer_controller: [cluster %d] no pkg for a %d-byte "
               "retransmit cache entry - 0x%02x sent once, best-effort\n",
               cl->cluster_id, pkt_len, type);
        return;
    }
    e->used         = 1;
    e->seq          = seq;
    e->type         = type;
    e->retries_left = CL_CTR_RETX_MAX_RETRIES;
    e->retry_ivl_us = CL_CTR_RETX_INTERVAL_US;
    e->next_due_us  = get_uticks() + e->retry_ivl_us;
    memcpy(&e->dest, dest, destlen);
    e->destlen      = destlen;
    memcpy(e->pkt, pkt, pkt_len);
    e->pkt_len      = pkt_len;
    cl->retx_count++;
    cl_ctr_retx_rearm(cl);
}

/* An ACK arrived: drop the queued packet whose seq it echoes. */
void cl_ctr_handle_ack(const char *payload, int payload_len,
                              cl_ctr_cluster_t *cl, const char *sender_ip)
{
    uint32_t acked_be, acked;
    int      acked_type = -1;          /* -1: an older peer that sent no type */
    in_addr_t sender = inet_addr(sender_ip);
    int i;

    if (payload_len < (int)sizeof(uint32_t))
        return;
    memcpy(&acked_be, payload, sizeof(acked_be));
    acked = ntohl(acked_be);
    if (payload_len >= CL_CTR_ACK_SZ)
        acked_type = (unsigned char)payload[sizeof(acked_be)];

    for (i = 0; i < CL_CTR_RETX_QUEUE_SZ; i++) {
        cl_ctr_retx_entry_t *e = &cl->retx_q[i];
        if (!e->used || e->seq != acked)
            continue;
        /* seq alone is ambiguous: handshake and consumer sequences are
         * independent, and a unicast entry is owed its ACK by one address only */
        if (acked_type >= 0 && e->type != (unsigned char)acked_type)
            continue;
        if (!e->is_bcast && e->dest.ss_family == AF_INET &&
            ((const struct sockaddr_in *)&e->dest)->sin_addr.s_addr != sender)
            continue;

        if (e->is_bcast) {
            /* Every member acknowledges the same sequence number, so this
             * entry lives until they all have (or the budget runs out). */
            uint16_t nid = 0;

            lock_start_read(cl->peers->lock);
            {
                cl_ctr_peer_t *p = cl_ctr_peer_by_ip_locked(cl, sender_ip);
                if (p)
                    nid = p->node_id;
            }
            lock_stop_read(cl->peers->lock);

            if (nid > 0 && nid <= CL_CTR_MAX_PEERS) {
                int byte = (nid - 1) / 8, bit = 1 << ((nid - 1) % 8);

                if (!(e->acked_map[byte] & bit)) {
                    e->acked_map[byte] |= bit;
                    e->acked_n++;
                }
            }
            if (e->acked_n < e->expect_n) {
                LM_DBG("clusterer_controller: [cluster %d] broadcast seq %u "
                       "acknowledged by %u of %u\n", cl->cluster_id, acked,
                       e->acked_n, e->expect_n);
                break;                       /* still waiting on others */
            }
            LM_DBG("clusterer_controller: [cluster %d] broadcast seq %u "
                   "acknowledged by all %u member(s) after %u of the %u "
                   "retries configured for this cluster\n", cl->cluster_id,
                   acked, e->expect_n,
                   (unsigned)(e->retries_cfg - e->retries_left),
                   (unsigned)e->retries_cfg);
        } else {
            /* Same number, same plane, from the address it was sent to:
             * this is the acknowledged packet; drop it. */
            LM_DBG("clusterer_controller: [cluster %d] ACK for 0x%02x seq %u\n",
                   cl->cluster_id, e->type, acked);
        }
        cl_ctr_retx_release(cl, e);
        break;
    }
    /* Dropping an entry can make a LATER one the earliest, so re-arm rather
     * than only disarming on empty. */
    cl_ctr_retx_rearm(cl);
}

/* resend each due entry, one budget step at a time; drop it when spent (the
 * joiner's JOIN_REQ retry is the outer backstop) */
int cl_ctr_on_retx_tfd(int fd, void *param, int was_timeout)
{
    cl_ctr_cluster_t *cl  = (cl_ctr_cluster_t *)param;
    utime_t          now = get_uticks();
    int              i;
    (void)was_timeout;

    cl_ctr_drain_tfd(fd);

    for (i = 0; i < CL_CTR_RETX_QUEUE_SZ; i++) {
        cl_ctr_retx_entry_t *e = &cl->retx_q[i];
        if (!e->used || now < e->next_due_us)
            continue;

        if (e->is_bcast) {
            /* repair by unicast to the nodes that still owe an ACK: a multicast
             * resend would make every member that already has it ACK again */
            int j, repaired = 0;

            lock_start_read(cl->peers->lock);
            for (j = 0; j < cl->peers->count; j++) {
                cl_ctr_peer_t     *p = &cl->peers->entries[j];
                struct sockaddr_in d;
                int byte, bit;

                if (p->node_id == 0 || p->node_id > CL_CTR_MAX_PEERS)
                    continue;
                byte = (p->node_id - 1) / 8;
                bit  = 1 << ((p->node_id - 1) % 8);
                if (e->acked_map[byte] & bit)
                    continue;                    /* this one answered */

                memset(&d, 0, sizeof d);
                d.sin_family = AF_INET;
                d.sin_port   = cl->mcast_dest.sin_port;
                if (inet_pton(AF_INET, p->ip, &d.sin_addr) != 1)
                    continue;
                if (sendto(cl->sock, e->pkt, e->pkt_len, 0,
                           (struct sockaddr *)&d, sizeof d) >= 0)
                    repaired++;
            }
            lock_stop_read(cl->peers->lock);
            LM_DBG("clusterer_controller: [cluster %d] broadcast seq %u: "
                   "repairing %d node(s) that have not acknowledged\n",
                   cl->cluster_id, e->seq, repaired);

        } else if (sendto(cl->sock, e->pkt, e->pkt_len, 0,
                   (struct sockaddr *)&e->dest, e->destlen) < 0 &&
            errno != EAGAIN && errno != EWOULDBLOCK) {
            LM_DBG("clusterer_controller: [cluster %d] retransmit 0x%02x: %s\n",
                   cl->cluster_id, e->type, strerror(errno));
        }

        if (--e->retries_left <= 0) {
            if (e->is_bcast)
                LM_INFO("clusterer_controller: [cluster %d] broadcast seq %u "
                        "reached %u of %u member(s), giving up after %u of the "
                        "%u retries configured for this cluster\n",
                        cl->cluster_id, e->seq, e->acked_n, e->expect_n,
                        (unsigned)e->retries_cfg, (unsigned)e->retries_cfg);
            else
                LM_DBG("clusterer_controller: [cluster %d] 0x%02x (seq %u) unacked "
                   "after %u retransmits, giving up - joiner will re-JOIN_REQ\n",
                   cl->cluster_id, e->type, e->seq,
                   (unsigned)(e->retries_cfg ? e->retries_cfg
                                             : CL_CTR_RETX_MAX_RETRIES));
            cl_ctr_retx_release(cl, e);
        } else {
            e->next_due_us = now + (e->retry_ivl_us ? e->retry_ivl_us
                                                    : CL_CTR_RETX_INTERVAL_US);
        }
    }

    cl_ctr_retx_rearm(cl);
    return 0;
}
