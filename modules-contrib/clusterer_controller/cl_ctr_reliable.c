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

/* the largest packet the cache holds; KEY_GRANT, the one sent reliably, fits */
#define CL_CTR_RETX_PKT_MAX  CL_CTR_NODE_ASSIGN_MAX_SZ

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

/* @pkt is already sealed and sent; if the queue is full it went out once and
 * the joiner's JOIN_REQ retry remains the backstop */
void cl_ctr_retx_enqueue(cl_ctr_cluster_t *cl, uint32_t seq, unsigned char type,
                            const unsigned char *pkt, int pkt_len,
                            const struct sockaddr *dest, socklen_t destlen)
{
    cl_ctr_retx_entry_t *e;
    int i, slot = -1;

    if (pkt_len <= 0 || pkt_len > CL_CTR_RETX_PKT_MAX ||
        destlen == 0 || destlen > (socklen_t)sizeof(cl->retx_q[0].dest)) {
        if (pkt_len > CL_CTR_RETX_PKT_MAX)
            LM_ERR("clusterer_controller: [cluster %d] 0x%02x of %d bytes is "
                   "over the %d the retransmit cache holds - sent once\n",
                   cl->cluster_id, type, pkt_len, CL_CTR_RETX_PKT_MAX);
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
    e->next_due_us  = get_uticks() + CL_CTR_RETX_INTERVAL_US;
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
        /* an entry is owed its ACK by one address only, for its own type */
        if (acked_type >= 0 && e->type != (unsigned char)acked_type)
            continue;
        if (e->dest.ss_family == AF_INET &&
            ((const struct sockaddr_in *)&e->dest)->sin_addr.s_addr != sender)
            continue;

        LM_DBG("clusterer_controller: [cluster %d] ACK for 0x%02x seq %u\n",
               cl->cluster_id, e->type, acked);
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

        if (sendto(cl->sock, e->pkt, e->pkt_len, 0,
                   (struct sockaddr *)&e->dest, e->destlen) < 0 &&
            errno != EAGAIN && errno != EWOULDBLOCK) {
            LM_DBG("clusterer_controller: [cluster %d] retransmit 0x%02x: %s\n",
                   cl->cluster_id, e->type, strerror(errno));
        }

        if (--e->retries_left <= 0) {
            LM_DBG("clusterer_controller: [cluster %d] 0x%02x (seq %u) unacked "
                   "after %u retransmits, giving up - joiner will re-JOIN_REQ\n",
                   cl->cluster_id, e->type, e->seq,
                   (unsigned)CL_CTR_RETX_MAX_RETRIES);
            cl_ctr_retx_release(cl, e);
        } else {
            e->next_due_us = now + CL_CTR_RETX_INTERVAL_US;
        }
    }

    cl_ctr_retx_rearm(cl);
    return 0;
}
