/*
 * clusterer_controller - consumer messaging API (api.h)
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
char *cl_ctr_consumer_pkt;
int   cl_ctr_consumer_pkt_sz;
static struct cl_ctr_channel cl_ctr_channels[CL_CTR_MAX_CHANNELS];
static int cl_ctr_nchannels;
/* clctr_api.get_my_ip - see api.h */
int cl_ctr_get_my_ip(const char **ip, const char **iface, const char **src)
{
	if (!my_ip)
		return -1;              /* mod_init has not resolved it yet */
	if (ip)
		*ip = my_ip;
	if (iface)
		*iface = my_interface_buf[0] ? my_interface_buf : "(unknown)";
	if (src)
		*src = my_ip_src;
	return 0;
}

/* =========================================================================
 * Consumer messaging API (api.h)
 *
 * Other modules ride the controller's encrypted UDP plane: named
 * channels, multicast or per-node unicast, delivered to the registered
 * callback in the cluster worker.  See api.h for the delivery contract.
 * ========================================================================= */

static cl_ctr_cluster_t *cl_ctr_cluster_by_id(int cluster_id)
{
    int i;

    for (i = 0; i < cl_ctr_cluster_count; i++)
        if (cl_ctr_clusters[i].cluster_id == cluster_id)
            return &cl_ctr_clusters[i];
    return NULL;
}

/* Invoke the registered callback for @chan, if any.  Runs in whichever
 * process called it - for wire packets and IPC'd sends that is the
 * cluster worker, which is the documented delivery context. */
static void cl_ctr_consumer_dispatch(cl_ctr_cluster_t *cl, int src_node_id,
        const char *chan, int chan_len, const char *payload, int payload_len)
{
    str ch, pl;
    int i;

    for (i = 0; i < cl_ctr_nchannels; i++) {
        if (cl_ctr_channels[i].len == chan_len &&
                memcmp(cl_ctr_channels[i].name, chan, chan_len) == 0) {
            ch.s = (char *)chan;      ch.len = chan_len;
            pl.s = (char *)payload;   pl.len = payload_len;
            cl_ctr_channels[i].cb(cl->cluster_id, src_node_id, &ch, &pl);
            return;
        }
    }
    /* unknown channel: a mixed-version cluster is normal, drop quietly */
    LM_DBG("clusterer_controller: [cluster %d] no consumer for channel "
           "'%.*s'\n", cl->cluster_id, chan_len, chan);
}

/* Receive path (worker, via cl_ctr_recv_one): already through the magic
 * gate, cluster_id filter, rate limiter, decrypt and seq check. */
void cl_ctr_handle_consumer(const char *payload, int payload_len,
        const char *src_ip, cl_ctr_cluster_t *cl)
{
    uint16_t src_id_be;
    int      chan_len;

    /* our own multicast looped back: self-delivery, when asked for, was
     * already done locally at send time - never accept it off the wire */
    if (strcmp(src_ip, my_ip) == 0)
        return;

    if (payload_len < CL_CTR_CONSUMER_HDR_SZ) {
        LM_DBG("clusterer_controller: [cluster %d] short consumer packet "
               "(%d)\n", cl->cluster_id, payload_len);
        return;
    }
    memcpy(&src_id_be, payload, CL_CTR_NODE_ID_SZ);
    chan_len = (unsigned char)payload[CL_CTR_NODE_ID_SZ];
    if (chan_len == 0 || chan_len > CLCTR_MAX_CHAN_LEN ||
            payload_len < CL_CTR_CONSUMER_HDR_SZ + chan_len) {
        LM_DBG("clusterer_controller: [cluster %d] bad consumer channel "
               "length %d (payload %d)\n", cl->cluster_id, chan_len,
               payload_len);
        return;
    }

    cl_ctr_consumer_dispatch(cl, ntohs(src_id_be),
            payload + CL_CTR_CONSUMER_HDR_SZ, chan_len,
            payload + CL_CTR_CONSUMER_HDR_SZ + chan_len,
            payload_len - CL_CTR_CONSUMER_HDR_SZ - chan_len);
}

/* Runs in the cluster worker.  Builds, seals and sends the consumer
 * packet - and/or dispatches locally for the self-delivery cases. */
static void cl_ctr_rpc_consumer_send(int sender, void *param)
{
    struct cl_ctr_consumer_job *job = (struct cl_ctr_consumer_job *)param;
    cl_ctr_cluster_t *cl = job->cl;
    /* the per-process buffer sized from cc_max_payload at mod_init;
     * a CL_CTR_CONSUMER_PKT_MAX-sized stack array could not hold what
     * the MTU-derived bound in cl_ctr_consumer_submit() admits */
    char     *pkt = cl_ctr_consumer_pkt;
    char      dst_ip[CL_CTR_MAX_IP_LEN + 1];
    uint32_t  seq;
    uint16_t  id_be;
    int       plain_len, i, to_self = 0, on_wire = 1, reliable = 0;

    /* Defence in depth against the two bounds drifting apart again. The
     * admission gate in cl_ctr_consumer_submit() and the buffer allocated in
     * mod_init are both derived from cc_max_payload, so this cannot fire
     * today - which is exactly what was true of the old pair right up until
     * the MTU probe was added and made them disagree. */
    if (!pkt || CL_CTR_PKT_OVERHEAD + job->payload_len > cl_ctr_consumer_pkt_sz) {
        LM_ERR("clusterer_controller: consumer packet of %d bytes does not fit "
               "the %d-byte transmit buffer - dropping\n",
               CL_CTR_PKT_OVERHEAD + job->payload_len, cl_ctr_consumer_pkt_sz);
        shm_free(job);
        return;
    }

    /* unicast to our own id never touches the wire; multicast with
     * CLCTR_SEND_TO_SELF touches it AND dispatches locally */
    if (job->dst_node_id != 0 && job->dst_node_id == my_node_id) {
        to_self = 1;
        on_wire = 0;
    } else if (job->flags & CLCTR_SEND_TO_SELF) {
        to_self = 1;
    }

    /* Reliability is per-recipient: it needs an address to retransmit to and
     * an acknowledgement to stop on.  A multicast has neither, and ACKing one
     * from every member is the implosion the join handshake already refuses -
     * so a reliable send to everyone is N unicasts, which is what send_list
     * and the broadcast helper do before they get here. */
    reliable = (job->flags & CLCTR_SEND_RELIABLE) != 0;

    if (on_wire) {
        if (!cl->have_session_key) {
            LM_DBG("clusterer_controller: [cluster %d] consumer send before "
                   "session key - dropped\n", cl->cluster_id);
            on_wire = 0;
        }
    }

    if (on_wire) {
        seq   = htonl(++cl->peers->my_consumer_seq);
        id_be = htons(my_node_id);

        /* the consumer tag, so the receiver's pre-decrypt rate limiter
         * charges this against the consumer budget rather than the much
         * smaller control-plane one.  Same session key either way - the
         * tag is a routing hint, not a key selector here. */
        memcpy(pkt, CL_CTR_CONSUMER_MAGIC, CL_CTR_MAGIC_SZ);
        pkt[CL_CTR_WIRE_HDR_SZ] = (char)(reliable ? CL_CTR_PKT_CONSUMER_REL
                                                  : CL_CTR_PKT_CONSUMER);
        memcpy(pkt + CL_CTR_WIRE_HDR_SZ + 1, &seq, CL_CTR_SEQ_SZ);
        memcpy(pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ, &id_be,
               CL_CTR_NODE_ID_SZ);
        pkt[CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_NODE_ID_SZ] =
               (char)job->chan_len;
        memcpy(pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ
               + CL_CTR_CONSUMER_HDR_SZ, job->chan, job->chan_len);
        memcpy(pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ
               + CL_CTR_CONSUMER_HDR_SZ + job->chan_len, job->payload,
               job->payload_len);
        plain_len = CL_CTR_PLAIN_HDR_SZ + CL_CTR_CONSUMER_HDR_SZ
                    + job->chan_len + job->payload_len;

        if (job->dst_node_id == 0) {
            cl_ctr_seal_and_send(cl->sock, cl, pkt, plain_len,
                    cl->session_key,
                    reliable ? CL_CTR_PKT_CONSUMER_REL : CL_CTR_PKT_CONSUMER);
            if (reliable)
                /* pkt is a char[] because cl_ctr_seal_and_send() writes
                 * into it in place; the retx queue takes it read-only as
                 * unsigned char, which is the natural type for wire bytes.
                 * The cast is the sign difference only - same address, same
                 * bytes - and silences -Wpointer-sign without retyping the
                 * buffer, which would only move the warning to the
                 * seal_and_send() calls that legitimately need char *. */
                /* The SEALED length.  cl_ctr_seal_and_send() encrypted in
                 * place, so what is on the wire is the wire header, the
                 * ciphertext and the AEAD tag - 44 bytes more than plain_len.
                 * Caching plain_len re-sent a packet truncated by exactly that
                 * much, which every receiver discarded as "short" before it
                 * could be decrypted: consumer retransmission had never
                 * delivered a single byte.  The control plane's own enqueue
                 * (KEY_GRANT) always passed the sealed length, which is why
                 * the join handshake's ARQ worked and this did not. */
                cl_ctr_retx_enqueue_bcast(cl, ntohl(seq),
                        (const unsigned char *)pkt,
                        CL_CTR_WIRE_HDR_SZ + plain_len + CL_CTR_TAG_SZ);
        } else {
            struct sockaddr_in d;

            dst_ip[0] = '\0';
            lock_start_read(cl->peers->lock);
            for (i = 0; i < cl->peers->count; i++) {
                if (cl->peers->entries[i].node_id == job->dst_node_id) {
                    strcpy(dst_ip, cl->peers->entries[i].ip);
                    break;
                }
            }
            lock_stop_read(cl->peers->lock);

            if (!dst_ip[0]) {
                LM_DBG("clusterer_controller: [cluster %d] consumer send to "
                       "unknown node %u - dropped\n", cl->cluster_id,
                       job->dst_node_id);
            } else {
                memset(&d, 0, sizeof d);
                d.sin_family = AF_INET;
                d.sin_port   = cl->mcast_dest.sin_port;
                if (inet_pton(AF_INET, dst_ip, &d.sin_addr) != 1) {
                    LM_ERR("clusterer_controller: [cluster %d] bad peer ip "
                           "'%s'\n", cl->cluster_id, dst_ip);
                } else {
                    cl_ctr_seal_and_send_to(cl->sock, cl, pkt, plain_len,
                            cl->session_key,
                            reliable ? CL_CTR_PKT_CONSUMER_REL
                                     : CL_CTR_PKT_CONSUMER,
                            (const struct sockaddr *)&d, sizeof d);
                    if (reliable)
                        /* same sign-only cast as the broadcast path above */
                        /* sealed length, as above */
                        cl_ctr_retx_enqueue_consumer(cl, ntohl(seq),
                                CL_CTR_PKT_CONSUMER_REL,
                                (const unsigned char *)pkt,
                                CL_CTR_WIRE_HDR_SZ + plain_len + CL_CTR_TAG_SZ,
                                (const struct sockaddr *)&d, sizeof d);
                }
            }
        }
    }

    if (to_self)
        cl_ctr_consumer_dispatch(cl, my_node_id, job->chan, job->chan_len,
                (const char *)job->payload, job->payload_len);

    shm_free(job);
}

int clctr_register_channel(str *channel, clctr_msg_cb_f cb)
{
    int i;

    if (!channel || !channel->s || channel->len <= 0 ||
            channel->len > CLCTR_MAX_CHAN_LEN || !cb) {
        LM_ERR("bad consumer channel registration\n");
        return -1;
    }
    for (i = 0; i < cl_ctr_nchannels; i++) {
        if (cl_ctr_channels[i].len == channel->len &&
                memcmp(cl_ctr_channels[i].name, channel->s, channel->len) == 0) {
            LM_ERR("consumer channel '%.*s' already registered\n",
                   channel->len, channel->s);
            return -1;
        }
    }
    if (cl_ctr_nchannels == CL_CTR_MAX_CHANNELS) {
        LM_ERR("consumer channel table full (%d)\n", CL_CTR_MAX_CHANNELS);
        return -1;
    }
    memcpy(cl_ctr_channels[cl_ctr_nchannels].name, channel->s, channel->len);
    cl_ctr_channels[cl_ctr_nchannels].name[channel->len] = '\0';
    cl_ctr_channels[cl_ctr_nchannels].len = channel->len;
    cl_ctr_channels[cl_ctr_nchannels].cb  = cb;
    cl_ctr_nchannels++;
    LM_DBG("consumer channel '%.*s' registered\n", channel->len, channel->s);
    return 0;
}

/* Common caller side: validate, marshal into shm, hand to the worker. */
static int cl_ctr_consumer_submit(int cluster_id, int dst_node_id,
        str *channel, str *payload, int flags)
{
    struct cl_ctr_consumer_job *job;
    cl_ctr_cluster_t *cl;
    int payload_len = payload ? payload->len : 0;
    int proc_no;

    if (!channel || !channel->s || channel->len <= 0 ||
            channel->len > CLCTR_MAX_CHAN_LEN)
        return -1;
    if (payload_len < 0 || payload_len > cc_max_payload) {
        LM_ERR("consumer payload of %d exceeds the %d-byte datagram bound - "
               "use BIN for bulk data\n", payload_len, cc_max_payload);
        return -1;
    }

    /* Single gate for every sender - the script functions and the consumer API
     * both funnel through here, so the flag cannot survive by another route.
     *
     * enable_reliable_send=0 degrades a reliable send to a plain one rather
     * than failing it: the payload still goes out, it just is not chased. The
     * warning is process-local and rate-limited - several workers may each emit
     * one per interval, the same trade pull_send_failed() makes, because an
     * occasional duplicate line costs less than a lock on a send path. */
    if ((flags & CLCTR_SEND_RELIABLE) && !enable_reliable_send) {
        static unsigned int last_warn;   /* per process, deliberately */
        unsigned int now = get_ticks();

        flags &= ~CLCTR_SEND_RELIABLE;
        if (last_warn == 0 || now - last_warn >= CL_CTR_RELIABLE_WARN_IVL) {
            last_warn = now;
            LM_WARN("clusterer_controller: reliable delivery was requested on "
                    "channel '%.*s' but enable_reliable_send is 0 - sending "
                    "plain, so this message is not acknowledged and not "
                    "retransmitted if it is lost.\n",
                    channel->len, channel->s);
        }
    }

    cl = cl_ctr_cluster_by_id(cluster_id);
    if (!cl) {
        LM_ERR("consumer send to unknown cluster %d\n", cluster_id);
        return -1;
    }
    /* worker_proc_no is written once at worker fork and stable thereafter */
    proc_no = cl->peers ? cl->peers->worker_proc_no : -1;
    if (proc_no < 0)
        return -2;

    job = shm_malloc(sizeof *job + payload_len);
    if (!job) {
        LM_ERR("no shm for a consumer send\n");
        return -1;
    }
    job->cl          = cl;
    job->dst_node_id = (uint16_t)dst_node_id;
    job->flags       = flags;
    job->chan_len    = channel->len;
    job->payload_len = payload_len;
    memcpy(job->chan, channel->s, channel->len);
    if (payload_len)
        memcpy(job->payload, payload->s, payload_len);

    if (ipc_send_rpc(proc_no, cl_ctr_rpc_consumer_send, job) < 0) {
        LM_ERR("cannot dispatch consumer send to the cluster %d worker\n",
               cluster_id);
        shm_free(job);
        return -2;
    }
    return 0;
}

int clctr_send_mcast(int cluster_id, str *channel, str *payload,
        int flags)
{
    return cl_ctr_consumer_submit(cluster_id, 0, channel, payload, flags);
}

int clctr_send_list(int cluster_id, const int *node_ids, int n,
                           str *channel, str *payload, int flags, int *unknown)
{
    int i, sent = 0, missing = 0;

    if (!node_ids || n <= 0)
        return -1;

    /* One unicast per target rather than a multicast the receivers filter:
     * a multicast is decrypted by every member, so "addressed to three of
     * you" would still put the payload in front of all of them.  The cost is
     * linear in the list, which is the honest price of addressing a subset. */
    for (i = 0; i < n; i++) {
        if (node_ids[i] <= 0) {
            missing++;
            continue;
        }
        if (clctr_send_ucast(cluster_id, node_ids[i], channel, payload,
                             flags) < 0)
            missing++;
        else
            sent++;
    }
    if (unknown)
        *unknown = missing;
    if (missing)
        LM_DBG("clusterer_controller: [cluster %d] list send reached %d of "
               "%d node(s)\n", cluster_id, sent, n);
    return sent;
}

int clctr_send_ucast(int cluster_id, int node_id, str *channel,
        str *payload, int flags)
{
    if (node_id <= 0 || node_id > CL_CTR_MAX_PEERS)
        return -1;
    return cl_ctr_consumer_submit(cluster_id, node_id, channel, payload,
            flags);
}

/* Readable from ANY process: the worker-local my_node_id global is only
 * authoritative inside the worker, so read our own entry from the shm
 * peer table instead. */
static int clctr_get_my_node_id(int cluster_id)
{
    cl_ctr_cluster_t *cl = cl_ctr_cluster_by_id(cluster_id);
    int i, id = 0;

    if (!cl || !cl->peers)
        return 0;
    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        if (strcmp(cl->peers->entries[i].ip, my_ip) == 0) {
            id = cl->peers->entries[i].node_id;
            break;
        }
    }
    lock_stop_read(cl->peers->lock);
    return id;
}

/* Consumers must reach cc_max_payload through the bound API, never as an extern
 * - see the note in api.h. */
static int clctr_get_max_payload(void)
{
    return cc_max_payload;
}

int load_clctr(clctr_api_t *api)
{
    if (!api)
        return -1;
    api->register_channel = clctr_register_channel;
    api->send_mcast       = clctr_send_mcast;
    api->send_ucast       = clctr_send_ucast;
    api->send_list        = clctr_send_list;
    api->get_my_node_id   = clctr_get_my_node_id;
    api->get_my_ip        = cl_ctr_get_my_ip;
    api->get_max_payload  = clctr_get_max_payload;
    return 0;
}
