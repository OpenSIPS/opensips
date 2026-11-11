/*
 * clusterer_controller - module broadcasts over multicast
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
 */

#include <poll.h>

#include "cl_ctr.h"
#include "cl_ctr_data.h"
#include "cl_ctr_caps.h"
#include "clusterer_ctrl.h"
#include "../../bin_interface.h"
#include "../../ip_addr.h"

int mcast_broadcasts = 1;
int mcast_workers    = 2;
int mcast_window     = 2048;
int cl_ctr_data_frag_max = CL_CTR_DATA_DGRAM_MAX - CL_CTR_DATA_OVERHEAD;
cl_ctr_data_sink_f cl_ctr_data_sink;

#define CL_CTR_DATA_BIN_MAX  65536

typedef struct {
    uint64_t seq;
    int      len;
    char     buf[CL_CTR_DATA_DGRAM_MAX];
} cl_ctr_slot_t;

/* pkt (shm) = [match][frag i][frag n][BIN bytes] */
typedef struct {
    uint64_t seq;
    char    *pkt;
    int      len;
} cl_ctr_held_t;

/* a TCP message waiting for the broadcasts its sender sent before it */
typedef struct cl_ctr_parked_ {
    struct cl_ctr_parked_ *next;
    uint64_t               barrier;
    long long              deadline_ms;
    struct receive_info    ri;
    int                    len;
    char                   buf[];
} cl_ctr_parked_t;

/* one sender as this node receives it; only the process that set `delivering`
 * dispatches, and it alone touches the reassembly fields */
typedef struct {
    gen_lock_t     lock;
    uint64_t       inc;
    uint64_t       next;        /* next number to dispatch, 0 = not tracking yet */
    uint64_t       top;         /* highest number held or announced */
    uint64_t       skip_upto;   /* missing numbers up to here are given up */
    int            delivering;
    int            held;
    uint64_t       gap_at;
    long long      gap_since_ms, nack_ms, late_warned_ms;
    char          *frag;
    int            frag_len, frag_n, frag_i;
    cl_ctr_parked_t *parked, *parked_tail;
    cl_ctr_held_t  hold[CL_CTR_DATA_HOLD];
} cl_ctr_rx_t;

struct cl_ctr_data_ {
    gen_lock_t     tx_lock;
    uint64_t       tx_seq;      /* last number given out */
    volatile int   usable;
    gen_lock_t     key_lock;
    volatile unsigned int key_gen;
    unsigned char  key[2][32];  /* [0] current, [1] the one before */
    uint32_t       key_id[2];
    int            key_n;
    gen_lock_t     rx_alloc;
    cl_ctr_rx_t   *rx[CL_CTR_MAX_PEERS + 1];
    unsigned long  st_sent, st_received, st_repairs, st_gaps, st_tcp, st_nacks;
    unsigned long  st_barrier_waits, st_barrier_late;
    unsigned long  rep_by[CL_CTR_MAX_PEERS + 1];   /* resent, by the node asking */
    /* worker only: the last check of each node's repair share */
    unsigned long  rd_sent, rd_rep_by[CL_CTR_MAX_PEERS + 1];
    int            rd_rounds;
    time_t         rd_warned;
    int            window;
    cl_ctr_slot_t *ring;
};

/* per process: the keys as last copied from shm */
static struct {
    unsigned int  gen;
    int           n;
    unsigned char key[2][32];
    uint32_t      id[2];
} cl_ctr_kc[CL_CTR_MAX_CLUSTERS];

#define ST_ADD(_f, _n) __sync_fetch_and_add(&(_f), (unsigned long)(_n))

static void put16(char *p, uint16_t v) { v = htons(v); memcpy(p, &v, 2); }
static uint16_t get16(const char *p) { uint16_t v; memcpy(&v, p, 2); return ntohs(v); }

static void put64(char *p, uint64_t v)
{
    int k;
    for (k = 0; k < 8; k++)
	p[k] = (char)(v >> (56 - 8 * k));
}

static uint64_t get64(const char *p)
{
    uint64_t v = 0;
    int      k;
    for (k = 0; k < 8; k++)
	v = (v << 8) | (unsigned char)p[k];
    return v;
}

static int cl_ctr_data_idx(int cluster_id)
{
    int i;

    for (i = 0; i < cl_ctr_cluster_count; i++)
	if (cl_ctr_clusters[i].cluster_id == cluster_id && cl_ctr_clusters[i].data)
	    return i;
    return -1;
}

/* the number of keys this process may use, refreshed when the worker changed them */
static int cl_ctr_data_keys(int idx)
{
    cl_ctr_data_t *d = cl_ctr_clusters[idx].data;

    if (cl_ctr_kc[idx].gen != d->key_gen) {
	lock_get(&d->key_lock);
	cl_ctr_kc[idx].gen = d->key_gen;
	cl_ctr_kc[idx].n   = d->key_n;
	memcpy(cl_ctr_kc[idx].key, d->key, sizeof d->key);
	memcpy(cl_ctr_kc[idx].id, d->key_id, sizeof d->key_id);
	lock_release(&d->key_lock);
    }
    return cl_ctr_kc[idx].n;
}

void cl_ctr_data_set_key(cl_ctr_cluster_t *cl)
{
    cl_ctr_data_t *d = cl->data;
    unsigned char  nk[32], h[crypto_generichash_BYTES_MIN];
    uint32_t       id;

    if (!d)
	return;
    if (cl_ctr_hkdf_sha256((unsigned char *)cl->password, strlen(cl->password),
                           cl->peers->master_salt, CL_CTR_MASTER_SALT_SZ,
                           "cl_ctr_data", nk) < 0) {
	LM_ERR("clusterer_controller: [cluster %d] data key derivation failed\n",
	       cl->cluster_id);
	return;
    }
    crypto_generichash(h, sizeof h, nk, sizeof nk, NULL, 0);
    memcpy(&id, h, sizeof id);

    lock_get(&d->key_lock);
    if (d->key_n && sodium_memcmp(nk, d->key[0], sizeof nk) == 0) {
	lock_release(&d->key_lock);
	sodium_memzero(nk, sizeof nk);
	return;
    }
    memcpy(d->key[1], d->key[0], sizeof nk);
    d->key_id[1] = d->key_id[0];
    memcpy(d->key[0], nk, sizeof nk);
    d->key_id[0] = id;
    if (d->key_n < 2)
	d->key_n++;
    d->key_gen++;
    lock_release(&d->key_lock);
    sodium_memzero(nk, sizeof nk);
}

/* @out holds CL_CTR_DATA_DGRAM_MAX; returns the datagram's length or -1 */
static int cl_ctr_data_seal(cl_ctr_cluster_t *cl, int idx, char *out,
                            uint16_t sender, uint64_t seq, int type, int match,
                            int fi, int fn, const char *body, int blen)
{
    uint16_t           cid = htons((uint16_t)cl->cluster_id);
    char              *p   = out + CL_CTR_DATA_HDR_SZ;
    unsigned long long clen = 0;

    if (CL_CTR_DATA_OVERHEAD + blen > CL_CTR_DATA_DGRAM_MAX)
	return -1;
    out[0] = (char)CL_CTR_WIRE_MAGIC0;
    out[1] = (char)CL_CTR_DATA_TIER;
    memcpy(out + CL_CTR_MAGIC_SZ, &cid, CL_CTR_CLUSTER_ID_SZ);
    memcpy(out + CL_CTR_MAGIC_SZ + CL_CTR_CLUSTER_ID_SZ, &cl_ctr_kc[idx].id[0],
           CL_CTR_DATA_KEYID_SZ);
    randombytes_buf(out + CL_CTR_DATA_AAD_SZ, CL_CTR_NONCE_SZ);

    put16(p, sender);
    put64(p + 2, cl_ctr_incarnation);
    put64(p + 10, seq);
    p[18] = (char)type;
    p[19] = (char)match;
    p[20] = (char)fi;
    p[21] = (char)fn;
    if (blen)
	memcpy(p + CL_CTR_DATA_PLAIN_SZ, body, blen);

    if (crypto_aead_xchacha20poly1305_ietf_encrypt((unsigned char *)p, &clen,
            (const unsigned char *)p, (unsigned long long)(CL_CTR_DATA_PLAIN_SZ + blen),
            (const unsigned char *)out, CL_CTR_DATA_AAD_SZ, NULL,
            (const unsigned char *)out + CL_CTR_DATA_AAD_SZ,
            cl_ctr_kc[idx].key[0]) != 0)
	return -1;
    return CL_CTR_DATA_HDR_SZ + (int)clen;
}

/* in place; the plaintext's length at CL_CTR_DATA_HDR_SZ, or -1 */
static int cl_ctr_data_open(int idx, char *buf, int n)
{
    unsigned long long mlen = 0;
    uint32_t           id;
    int                k, nk;

    nk = cl_ctr_data_keys(idx);
    memcpy(&id, buf + CL_CTR_MAGIC_SZ + CL_CTR_CLUSTER_ID_SZ, sizeof id);
    for (k = 0; k < nk; k++)
	if (cl_ctr_kc[idx].id[k] == id)
	    break;
    if (k == nk)
	return -1;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            (unsigned char *)buf + CL_CTR_DATA_HDR_SZ, &mlen, NULL,
            (const unsigned char *)buf + CL_CTR_DATA_HDR_SZ,
            (unsigned long long)(n - CL_CTR_DATA_HDR_SZ),
            (const unsigned char *)buf, CL_CTR_DATA_AAD_SZ,
            (const unsigned char *)buf + CL_CTR_DATA_AAD_SZ,
            cl_ctr_kc[idx].key[k]) != 0)
	return -1;
    return (int)mlen;
}

int cl_ctr_data_send(int cluster_id, const str *bin, int match_op)
{
    char           out[CL_CTR_DATA_DGRAM_MAX];
    cl_ctr_cluster_t *cl;
    cl_ctr_data_t *d;
    cl_ctr_slot_t *slot;
    uint64_t       first, seq;
    int            idx, sender, nfrag, i, off, blen, n;

    idx = cl_ctr_data_idx(cluster_id);
    if (idx < 0)
	return -1;
    cl = &cl_ctr_clusters[idx];
    d  = cl->data;
    if (!d->usable || bin->len < 3 * (int)sizeof(int) || !cl_ctr_data_keys(idx))
	return -1;
    /* the trailer's source id: what the receiver's BIN path checks */
    memcpy(&sender, bin->s + bin->len - 2 * sizeof(int), sizeof(int));
    if (sender <= 0 || sender > CL_CTR_MAX_PEERS)
	return -1;
    nfrag = (bin->len + cl_ctr_data_frag_max - 1) / cl_ctr_data_frag_max;
    if (nfrag > CL_CTR_DATA_FRAGS_MAX)
	return -1;

    lock_get(&d->tx_lock);
    first = d->tx_seq + 1;
    d->tx_seq += nfrag;
    lock_release(&d->tx_lock);

    for (i = 0; i < nfrag; i++) {
	seq  = first + i;
	off  = i * cl_ctr_data_frag_max;
	blen = bin->len - off < cl_ctr_data_frag_max ? bin->len - off
	                                              : cl_ctr_data_frag_max;
	n = cl_ctr_data_seal(cl, idx, out, (uint16_t)sender, seq,
	                     CL_CTR_DATA_T_DATA, match_op, i, nfrag,
	                     bin->s + off, blen);
	if (n < 0) {
	    LM_ERR("clusterer_controller: [cluster %d] cannot seal a broadcast\n",
	           cl->cluster_id);
	    continue;
	}
	/* kept before it is sent, so a NACK racing the send finds it */
	slot = &d->ring[seq % (uint64_t)d->window];
	lock_get(&d->tx_lock);
	if (slot->seq < seq) {
	    slot->seq = seq;
	    slot->len = n;
	    memcpy(slot->buf, out, n);
	}
	lock_release(&d->tx_lock);
	/* a full send buffer loses it here; the receivers ask for it again */
	sendto(cl->data_sock, out, n, 0, (struct sockaddr *)&cl->data_dest,
	       sizeof cl->data_dest);
    }
    ST_ADD(d->st_sent, nfrag);
    return 0;
}

void cl_ctr_data_count_tcp(int cluster_id)
{
    int idx = cl_ctr_data_idx(cluster_id);

    if (idx >= 0)
	ST_ADD(cl_ctr_clusters[idx].data->st_tcp, 1);
}

uint64_t cl_ctr_data_tx_seq(cl_ctr_cluster_t *cl)
{
    uint64_t s;

    if (!cl->data)
	return 0;
    lock_get(&cl->data->tx_lock);
    s = cl->data->tx_seq;
    lock_release(&cl->data->tx_lock);
    return s;
}

/* published once by cl_ctr_rx_get(), never freed: read it without rx_alloc */
static inline cl_ctr_rx_t *cl_ctr_rx_peek(cl_ctr_data_t *d, int id)
{
    return __atomic_load_n(&d->rx[id], __ATOMIC_ACQUIRE);
}

static cl_ctr_rx_t *cl_ctr_rx_get(cl_ctr_data_t *d, int id)
{
    cl_ctr_rx_t *rx = cl_ctr_rx_peek(d, id);

    if (rx)
	return rx;
    lock_get(&d->rx_alloc);
    if (!d->rx[id]) {
	rx = shm_malloc(sizeof *rx);
	if (rx) {
	    memset(rx, 0, sizeof *rx);
	    lock_init(&rx->lock);
	    __atomic_store_n(&d->rx[id], rx, __ATOMIC_RELEASE);
	} else {
	    LM_ERR("clusterer_controller: no shm for a sender's receive state\n");
	}
    }
    rx = d->rx[id];
    lock_release(&d->rx_alloc);
    return rx;
}

/* a sender's new life: tracking starts at @next */
static void cl_ctr_rx_reset_locked(cl_ctr_rx_t *rx, uint64_t inc, uint64_t next)
{
    int i;

    for (i = 0; i < CL_CTR_DATA_HOLD && rx->held; i++)
	if (rx->hold[i].pkt) {
	    shm_free(rx->hold[i].pkt);
	    rx->hold[i].pkt = NULL;
	    rx->held--;
	}
    rx->inc = inc;
    rx->next = next;
    rx->top = next ? next - 1 : 0;
    rx->skip_upto = 0;
    rx->gap_since_ms = 0;
    rx->frag_n = 0;
    /* what waited on the old life goes at the next drain */
    {
	cl_ctr_parked_t *p;
	for (p = rx->parked; p; p = p->next)
	    p->deadline_ms = 0;
    }
}

static void cl_ctr_data_dispatch(cl_ctr_cluster_t *cl, int sender, int match,
                                 char *bin, int len)
{
    union sockaddr_union su;
    struct receive_info  ri;
    unsigned int         plen;
    int                  src, self = -1;

    if (cl_ctr_data_sink) {
	cl_ctr_data_sink(sender, match, bin, len);
	return;
    }
    if (len < HEADER_SIZE + LEN_FIELD_SIZE + CMD_FIELD_SIZE + 3 * (int)sizeof(int) ||
            memcmp(bin, BIN_PACKET_MARKER, BIN_PACKET_MARKER_SIZE) != 0)
	return;
    memcpy(&plen, bin + BIN_PACKET_MARKER_SIZE, sizeof plen);
    memcpy(&src, bin + len - 2 * sizeof(int), sizeof(int));
    if ((int)plen != len || src != sender)
	return;
    memset(&su, 0, sizeof su);
    if (clusterer_ctrl_data_peer(cl->cluster_id, sender, match, &su, &self) <= 0)
	return;
    /* the destination slot of the trailer, as a TCP send fills it per node */
    memcpy(bin + len - sizeof(int), &self, sizeof(int));

    memset(&ri, 0, sizeof ri);
    ri.src_su = su;
    su2ip_addr(&ri.src_ip, &su);
    ri.src_port = su_getport(&su);
    ri.proto = PROTO_BIN;
    ri.proto_reserved2 = CL_CTR_RI_PASS;
    call_callbacks(bin, &ri);
    ST_ADD(cl->data->st_received, 1);
}

/* the dispatching process only; @body is writable */
static void cl_ctr_data_deliver(cl_ctr_cluster_t *cl, cl_ctr_rx_t *rx, int sender,
                                int match, int fi, int fn, char *body, int blen)
{
    if (fn <= 1) {
	cl_ctr_data_dispatch(cl, sender, match, body, blen);
	return;
    }
    if (fi == 0) {
	rx->frag_len = 0;
	rx->frag_n   = fn;
	rx->frag_i   = 0;
    }
    if (rx->frag_n != fn || rx->frag_i != fi)
	goto drop;          /* a fragment before it was lost */
    if (!rx->frag && !(rx->frag = shm_malloc(CL_CTR_DATA_BIN_MAX))) {
	LM_ERR("clusterer_controller: no shm to reassemble a broadcast\n");
	goto drop;
    }
    if (rx->frag_len + blen > CL_CTR_DATA_BIN_MAX)
	goto drop;
    memcpy(rx->frag + rx->frag_len, body, blen);
    rx->frag_len += blen;
    if (++rx->frag_i < fn)
	return;
    rx->frag_n = 0;
    cl_ctr_data_dispatch(cl, sender, match, rx->frag, rx->frag_len);
    return;
drop:
    rx->frag_n = 0;
}

static void cl_ctr_data_release(cl_ctr_cluster_t *cl, cl_ctr_parked_t *p,
                                int sender, int late)
{
    if (late) {
	ST_ADD(cl->data->st_barrier_late, 1);
	if (late > 1)
	    LM_WARN("clusterer_controller: [cluster %d] a TCP message from node %d "
	            "waited %d ms for broadcasts sent before it and went without them, "
	            "out of order (mcast_barrier_late %lu; one warning a minute per "
	            "node)\n", cl->cluster_id, sender, CL_CTR_DATA_BARRIER_MS,
	            cl->data->st_barrier_late);
    }
    if (cl_ctr_data_sink) {
	cl_ctr_data_sink(sender, -1, p->buf, p->len);
    } else {
	p->ri.proto_reserved2 = CL_CTR_RI_PASS;
	call_callbacks(p->buf, &p->ri);
    }
    shm_free(p);
}

/* lock held, `delivering` ours: dispatch what is in order (TCP messages once the
 * broadcasts before them are out), give up what was declared lost; lost count */
static uint64_t cl_ctr_rx_drain_locked(cl_ctr_cluster_t *cl, cl_ctr_rx_t *rx,
                                       int sender)
{
    cl_ctr_held_t   *h;
    cl_ctr_parked_t *p;
    uint64_t         lost = 0;
    char            *pkt;
    int              len, late;

    for (;;) {
	p = rx->parked;
	if (p && (p->barrier < rx->next || p->deadline_ms <= cl_ctr_now_ms())) {
	    rx->parked = p->next;
	    if (!rx->parked)
		rx->parked_tail = NULL;
	    late = p->barrier >= rx->next;
	    /* waited out its time, not dropped by a sender's restart: warn */
	    if (late && p->deadline_ms &&
	            cl_ctr_now_ms() - rx->late_warned_ms >= CL_CTR_DATA_LATE_WARN_MS) {
		rx->late_warned_ms = cl_ctr_now_ms();
		late = 2;
	    }
	    lock_release(&rx->lock);
	    cl_ctr_data_release(cl, p, sender, late);
	    lock_get(&rx->lock);
	    continue;
	}
	h = &rx->hold[rx->next % CL_CTR_DATA_HOLD];
	if (h->pkt && h->seq == rx->next) {
	    pkt = h->pkt;
	    len = h->len;
	    h->pkt = NULL;
	    rx->held--;
	    rx->next++;
	    lock_release(&rx->lock);
	    cl_ctr_data_deliver(cl, rx, sender, pkt[0], (unsigned char)pkt[1],
	                        (unsigned char)pkt[2], pkt + 3, len - 3);
	    shm_free(pkt);
	    lock_get(&rx->lock);
	    continue;
	}
	if (rx->skip_upto < rx->next)
	    break;
	rx->frag_n = 0;
	if (!rx->held) {
	    lost += rx->skip_upto - rx->next + 1;
	    rx->next = rx->skip_upto + 1;
	    continue;
	}
	lost++;
	rx->next++;
    }
    return lost;
}

uint64_t cl_ctr_data_widen(uint64_t ref, uint32_t low)
{
    uint64_t b = (ref & ~(uint64_t)0xffffffffu) | low;

    if (b > ref + 0x80000000ull && b >= 0x100000000ull)
	b -= 0x100000000ull;
    else if (b + 0x80000000ull < ref)
	b += 0x100000000ull;
    return b;
}

int cl_ctr_data_park(int cluster_id, int sender, unsigned int barrier,
                     const char *bin, int len, const struct receive_info *ri)
{
    cl_ctr_parked_t *p = NULL;
    cl_ctr_rx_t     *rx;
    uint64_t         b;
    int              idx = cl_ctr_data_idx(cluster_id);

    if (idx < 0 || sender <= 0 || sender > CL_CTR_MAX_PEERS ||
            !(rx = cl_ctr_rx_peek(cl_ctr_clusters[idx].data, sender)))
	return 0;
    lock_get(&rx->lock);
    for (;;) {
	if (!rx->next)
	    break;
	b = cl_ctr_data_widen(rx->next - 1, barrier);
	/* while another process delivers, the broadcast it waits for may be out
	 * of the hold but not yet dispatched: that process releases it after */
	if (b < rx->next && !rx->parked && !rx->delivering)
	    break;
	if (!p) {
	    lock_release(&rx->lock);
	    p = shm_malloc(sizeof *p + len);
	    if (!p)
		return 0;       /* delivered now, out of order at worst */
	    memset(p, 0, sizeof *p);
	    p->ri  = *ri;
	    p->len = len;
	    memcpy(p->buf, bin, len);
	    lock_get(&rx->lock);
	    continue;
	}
	p->barrier = b;
	p->deadline_ms = cl_ctr_now_ms() + CL_CTR_DATA_BARRIER_MS;
	if (rx->parked_tail)
	    rx->parked_tail->next = p;
	else
	    rx->parked = p;
	rx->parked_tail = p;
	lock_release(&rx->lock);
	ST_ADD(cl_ctr_clusters[idx].data->st_barrier_waits, 1);
	return 1;
    }
    lock_release(&rx->lock);
    if (p)
	shm_free(p);
    return 0;
}

unsigned long cl_ctr_data_stat(cl_ctr_cluster_t *cl, int which)
{
    cl_ctr_data_t *d = cl->data;

    if (!d)
	return 0;
    switch (which) {
    case CL_CTR_DST_SENT:          return d->st_sent;
    case CL_CTR_DST_RECEIVED:      return d->st_received;
    case CL_CTR_DST_REPAIRS:       return d->st_repairs;
    case CL_CTR_DST_NACKS:         return d->st_nacks;
    case CL_CTR_DST_GAPS:          return d->st_gaps;
    case CL_CTR_DST_TCP:           return d->st_tcp;
    case CL_CTR_DST_BARRIER_WAITS: return d->st_barrier_waits;
    case CL_CTR_DST_BARRIER_LATE:  return d->st_barrier_late;
    }
    return 0;
}

unsigned int cl_ctr_data_barrier(int cluster_id)
{
    int idx = cl_ctr_data_idx(cluster_id);

    return idx < 0 ? 0 : (unsigned int)cl_ctr_data_tx_seq(&cl_ctr_clusters[idx]);
}

static void cl_ctr_data_report_lost(cl_ctr_cluster_t *cl, int sender, uint64_t lost)
{
    int bounced = 0, syncs = 0;

    ST_ADD(cl->data->st_gaps, lost);
    if (!cl_ctr_data_sink) {
	bounced = clusterer_ctrl_node_bounce(cl->cluster_id, sender) == 1;
	syncs = clusterer_ctrl_resync_from(cl->cluster_id, sender);
    }
    LM_WARN("clusterer_controller: [cluster %d] %llu broadcast packet(s) from "
            "node %d were lost and could not be repaired%s; %d capabilit%s "
            "re-sync\n", cl->cluster_id, (unsigned long long)lost, sender,
            bounced ? " - it was reported down and up to this node's modules" : "",
            syncs, syncs == 1 ? "y" : "ies");
}

/* lock held: dispatch now if no other process is; releases the lock */
static void cl_ctr_rx_kick_unlock(cl_ctr_cluster_t *cl, cl_ctr_rx_t *rx, int sender)
{
    uint64_t lost = 0;

    if (!rx->delivering) {
	rx->delivering = 1;
	lost = cl_ctr_rx_drain_locked(cl, rx, sender);
	rx->delivering = 0;
    }
    lock_release(&rx->lock);
    if (lost)
	cl_ctr_data_report_lost(cl, sender, lost);
}

void cl_ctr_data_accept(cl_ctr_cluster_t *cl, int sender, uint64_t inc,
                        uint64_t seq, int match, int fi, int fn,
                        char *body, int blen)
{
    cl_ctr_rx_t   *rx = cl_ctr_rx_get(cl->data, sender);
    cl_ctr_held_t *h;
    char          *pkt = NULL;
    uint64_t       lost;

    if (!rx || !seq)
	return;
    lock_get(&rx->lock);
again:
    if (inc < rx->inc)
	goto out;
    if (inc > rx->inc)
	cl_ctr_rx_reset_locked(rx, inc, seq);
    else if (!rx->next)
	rx->next = seq;
    if (seq < rx->next)
	goto out;                   /* a duplicate, or given up */
    if (seq > rx->top)
	rx->top = seq;
    if (seq - rx->next >= CL_CTR_DATA_HOLD) {
	/* no room: what lies further back than the hold is given up, and this
	 * one is asked for again once the hold has moved */
	if (seq - CL_CTR_DATA_HOLD > rx->skip_upto)
	    rx->skip_upto = seq - CL_CTR_DATA_HOLD;
	if (pkt)
	    shm_free(pkt);
	cl_ctr_rx_kick_unlock(cl, rx, sender);
	return;
    }
    if (seq == rx->next && !rx->delivering) {
	rx->delivering = 1;
	rx->next++;
	lock_release(&rx->lock);
	if (pkt)
	    shm_free(pkt);
	cl_ctr_data_deliver(cl, rx, sender, match, fi, fn, body, blen);
	lock_get(&rx->lock);
	lost = cl_ctr_rx_drain_locked(cl, rx, sender);
	rx->delivering = 0;
	lock_release(&rx->lock);
	if (lost)
	    cl_ctr_data_report_lost(cl, sender, lost);
	return;
    }
    h = &rx->hold[seq % CL_CTR_DATA_HOLD];
    if (h->pkt)
	goto out;
    if (!pkt) {
	lock_release(&rx->lock);
	pkt = shm_malloc(3 + blen);
	if (!pkt) {
	    LM_ERR("clusterer_controller: no shm to hold a broadcast\n");
	    return;
	}
	pkt[0] = (char)match;
	pkt[1] = (char)fi;
	pkt[2] = (char)fn;
	memcpy(pkt + 3, body, blen);
	lock_get(&rx->lock);
	goto again;
    }
    h->seq = seq;
    h->pkt = pkt;
    h->len = 3 + blen;
    rx->held++;
    cl_ctr_rx_kick_unlock(cl, rx, sender);
    return;
out:
    lock_release(&rx->lock);
    if (pkt)
	shm_free(pkt);
}

void cl_ctr_data_note_seq(cl_ctr_cluster_t *cl, int node_id, uint64_t inc,
                          uint64_t seq)
{
    cl_ctr_rx_t *rx;

    if (!cl->data || node_id <= 0 || node_id > CL_CTR_MAX_PEERS || !inc)
	return;
    rx = cl_ctr_rx_get(cl->data, node_id);
    if (!rx)
	return;
    lock_get(&rx->lock);
    if (inc > rx->inc)
	cl_ctr_rx_reset_locked(rx, inc, seq + 1);
    else if (inc == rx->inc) {
	if (!rx->next)
	    rx->next = seq + 1;
	if (seq > rx->top)
	    rx->top = seq;
    }
    lock_release(&rx->lock);
}

/* [target node id][count][from, to]... */
static int cl_ctr_data_ranges(char *p, int target, const uint64_t (*r)[2], int n)
{
    int i;

    put16(p, (uint16_t)target);
    p[2] = (char)n;
    for (i = 0; i < n; i++) {
	put64(p + 3 + 16 * i, r[i][0]);
	put64(p + 3 + 16 * i + 8, r[i][1]);
    }
    return 3 + 16 * n;
}

static void cl_ctr_data_send_ctl(cl_ctr_cluster_t *cl, int idx, int type,
                                 int target, const uint64_t (*r)[2], int n,
                                 const struct sockaddr_in *to)
{
    char out[CL_CTR_DATA_DGRAM_MAX], body[3 + 16 * CL_CTR_DATA_NACK_RANGES];
    int  self, len;

    self = clusterer_ctrl_self_id(cl->cluster_id);
    if (self <= 0 || !cl_ctr_data_keys(idx))
	return;
    len = cl_ctr_data_ranges(body, target, r, n);
    len = cl_ctr_data_seal(cl, idx, out, (uint16_t)self, 0, type, 0, 0, 0, body, len);
    if (len > 0)
	sendto(cl->data_sock, out, len, 0, (const struct sockaddr *)to, sizeof *to);
}

static void cl_ctr_data_on_nack(cl_ctr_cluster_t *cl, int idx, int from,
                                const char *body, int blen,
                                const struct sockaddr_in *src)
{
    cl_ctr_data_t *d = cl->data;
    char           buf[CL_CTR_DATA_DGRAM_MAX];
    uint64_t       gone[CL_CTR_DATA_NACK_RANGES][2], top, a, b, s;
    cl_ctr_slot_t *slot;
    int            n, i, ng = 0, resent = 0, len;

    if (blen < 3 || get16(body) != clusterer_ctrl_self_id(cl->cluster_id))
	return;
    n = (unsigned char)body[2];
    if (n > CL_CTR_DATA_NACK_RANGES || blen < 3 + 16 * n)
	return;
    lock_get(&d->tx_lock);
    top = d->tx_seq;
    lock_release(&d->tx_lock);

    for (i = 0; i < n; i++) {
	a = get64(body + 3 + 16 * i);
	b = get64(body + 3 + 16 * i + 8);
	if (!a || a > b || a > top)
	    continue;
	if (b > top)
	    b = top;
	/* left the ring */
	if (a + (uint64_t)d->window <= top) {
	    s = b + (uint64_t)d->window <= top ? b : top - (uint64_t)d->window;
	    gone[ng][0] = a;
	    gone[ng][1] = s;
	    ng++;
	    a = s + 1;
	}
	for (s = a; s <= b && resent < CL_CTR_DATA_RETX_MAX; s++) {
	    slot = &d->ring[s % (uint64_t)d->window];
	    len = 0;
	    lock_get(&d->tx_lock);
	    if (slot->seq == s) {
		len = slot->len;
		memcpy(buf, slot->buf, len);
	    }
	    lock_release(&d->tx_lock);
	    if (len && sendto(cl->data_sock, buf, len, 0,
	                      (const struct sockaddr *)src, sizeof *src) > 0)
		resent++;
	}
    }
    if (resent) {
	ST_ADD(d->st_repairs, resent);
	ST_ADD(d->rep_by[from], resent);
    }
    if (ng)
	cl_ctr_data_send_ctl(cl, idx, CL_CTR_DATA_T_GONE, from,
	                     (const uint64_t (*)[2])gone, ng, src);
}

static void cl_ctr_data_on_gone(cl_ctr_cluster_t *cl, int from, uint64_t inc,
                                const char *body, int blen)
{
    cl_ctr_rx_t *rx;
    uint64_t     to;
    int          n, i;

    if (blen < 3 || get16(body) != clusterer_ctrl_self_id(cl->cluster_id) ||
            from > CL_CTR_MAX_PEERS || !(rx = cl_ctr_rx_peek(cl->data, from)))
	return;
    n = (unsigned char)body[2];
    if (n > CL_CTR_DATA_NACK_RANGES || blen < 3 + 16 * n)
	return;
    lock_get(&rx->lock);
    if (inc != rx->inc) {
	lock_release(&rx->lock);
	return;
    }
    for (i = 0; i < n; i++) {
	to = get64(body + 3 + 16 * i + 8);
	if (to > rx->skip_upto && to <= rx->top)
	    rx->skip_upto = to;
    }
    cl_ctr_rx_kick_unlock(cl, rx, from);
}

static void cl_ctr_data_recv(char *buf, int n)
{
    cl_ctr_cluster_t *cl;
    struct sockaddr_in to;
    char     *p;
    uint64_t  inc, seq;
    uint16_t  cid;
    int       idx, plen, sender, type, fi, fn;

    if (n < CL_CTR_DATA_OVERHEAD || (unsigned char)buf[0] != CL_CTR_WIRE_MAGIC0 ||
            buf[1] != CL_CTR_DATA_TIER)
	return;
    memcpy(&cid, buf + CL_CTR_MAGIC_SZ, sizeof cid);
    idx = cl_ctr_data_idx(ntohs(cid));
    if (idx < 0)
	return;
    cl = &cl_ctr_clusters[idx];
    plen = cl_ctr_data_open(idx, buf, n);
    if (plen < CL_CTR_DATA_PLAIN_SZ)
	return;
    p      = buf + CL_CTR_DATA_HDR_SZ;
    sender = get16(p);
    inc    = get64(p + 2);
    seq    = get64(p + 10);
    type   = (unsigned char)p[18];
    fi     = (unsigned char)p[20];
    fn     = (unsigned char)p[21];
    if (sender <= 0 || sender > CL_CTR_MAX_PEERS)
	return;

    switch (type) {
    case CL_CTR_DATA_T_DATA:
	if (fn < 1 || fi >= fn || plen == CL_CTR_DATA_PLAIN_SZ)
	    return;
	cl_ctr_data_accept(cl, sender, inc, seq, p[19], fi, fn,
	                   p + CL_CTR_DATA_PLAIN_SZ, plen - CL_CTR_DATA_PLAIN_SZ);
	break;
    case CL_CTR_DATA_T_NACK: {
	char ip[CL_CTR_MAX_IP_LEN + 1];

	/* answered to the address the cluster knows for that node */
	if (cl_ctr_find_peer(cl->cluster_id, sender, NULL, NULL, NULL,
	                     ip, sizeof ip) < 0)
	    return;
	cl_ctr_sockaddr_in(ip, cl->data_port, &to);
	cl_ctr_data_on_nack(cl, idx, sender, p + CL_CTR_DATA_PLAIN_SZ,
	                    plen - CL_CTR_DATA_PLAIN_SZ, &to);
	break;
    }
    case CL_CTR_DATA_T_GONE:
	cl_ctr_data_on_gone(cl, sender, inc, p + CL_CTR_DATA_PLAIN_SZ,
	                    plen - CL_CTR_DATA_PLAIN_SZ);
	break;
    }
}

/* the missing ranges between next and top, as far as the hold reaches */
static int cl_ctr_rx_missing_locked(cl_ctr_rx_t *rx, uint64_t (*r)[2])
{
    uint64_t s, end;
    int      n = 0, in = 0;

    end = rx->top < rx->next + CL_CTR_DATA_HOLD - 1 ? rx->top
                                                   : rx->next + CL_CTR_DATA_HOLD - 1;
    for (s = rx->next; s <= end && n < CL_CTR_DATA_NACK_RANGES; s++) {
	cl_ctr_held_t *h = &rx->hold[s % CL_CTR_DATA_HOLD];
	int missing = !(h->pkt && h->seq == s);

	if (missing && !in) {
	    r[n][0] = s;
	    in = 1;
	}
	if (!missing && in) {
	    r[n++][1] = s - 1;
	    in = 0;
	}
    }
    if (in)
	r[n++][1] = s - 1;
    return n;
}

/* the first held number past next, or top when none is held */
static uint64_t cl_ctr_rx_first_held_locked(cl_ctr_rx_t *rx)
{
    uint64_t s;

    for (s = rx->next + 1; rx->held && s <= rx->top &&
         s < rx->next + CL_CTR_DATA_HOLD; s++) {
	cl_ctr_held_t *h = &rx->hold[s % CL_CTR_DATA_HOLD];
	if (h->pkt && h->seq == s)
	    return s;
    }
    return rx->top + 1;
}

static void cl_ctr_data_tick(int idx)
{
    cl_ctr_cluster_t *cl = &cl_ctr_clusters[idx];
    cl_ctr_data_t    *d  = cl->data;
    struct sockaddr_in to;
    uint64_t          r[CL_CTR_DATA_NACK_RANGES][2];
    long long         now = cl_ctr_now_ms();
    char              ip[CL_CTR_MAX_IP_LEN + 1];
    cl_ctr_rx_t      *rx;
    cl_ctr_held_t    *h;
    int               id, n;

    for (id = 1; id <= CL_CTR_MAX_PEERS; id++) {
	if (!(rx = cl_ctr_rx_peek(d, id)))
	    continue;
	/* the readers change all of it under the lock: decide under it too */
	lock_get(&rx->lock);
	if (rx->parked && !rx->delivering) {
	    cl_ctr_rx_kick_unlock(cl, rx, id);
	    lock_get(&rx->lock);
	}
	if (!rx->next) {
	    lock_release(&rx->lock);
	    continue;
	}
	h = &rx->hold[rx->next % CL_CTR_DATA_HOLD];
	if (rx->next > rx->top || (h->pkt && h->seq == rx->next)) {
	    rx->gap_since_ms = 0;
	    lock_release(&rx->lock);
	    continue;
	}
	if (!rx->gap_since_ms || rx->gap_at != rx->next) {
	    rx->gap_at = rx->next;
	    rx->gap_since_ms = now;
	    rx->nack_ms = 0;
	}
	if (now - rx->gap_since_ms >= CL_CTR_DATA_GIVEUP_MS) {
	    rx->skip_upto = cl_ctr_rx_first_held_locked(rx) - 1;
	    rx->gap_since_ms = 0;
	    cl_ctr_rx_kick_unlock(cl, rx, id);
	    continue;
	}
	if (now - rx->gap_since_ms < CL_CTR_DATA_NACK_AFTER_MS ||
	        (rx->nack_ms && now - rx->nack_ms < CL_CTR_DATA_NACK_IVL_MS)) {
	    lock_release(&rx->lock);
	    continue;
	}
	rx->nack_ms = now;
	n = cl_ctr_rx_missing_locked(rx, r);
	lock_release(&rx->lock);
	if (!n || cl_ctr_find_peer(cl->cluster_id, id, NULL, NULL, NULL,
	                           ip, sizeof ip) < 0)
	    continue;
	cl_ctr_sockaddr_in(ip, cl->data_port, &to);
	cl_ctr_data_send_ctl(cl, idx, CL_CTR_DATA_T_NACK, id,
	                     (const uint64_t (*)[2])r, n, &to);
	ST_ADD(d->st_nacks, 1);
    }
}

void cl_ctr_data_ticks(void)
{
    int i;

    for (i = 0; i < cl_ctr_cluster_count; i++)
	if (cl_ctr_clusters[i].data)
	    cl_ctr_data_tick(i);
}

void cl_ctr_data_round(cl_ctr_cluster_t *cl)
{
    cl_ctr_data_t *d = cl->data;
    unsigned long  sent, rep;
    int            usable, id;

    if (!d)
	return;
    usable = d->key_n > 0 && (cl_ctr_table_caps(cl) & CL_CTR_CAP_MCAST_DATA);
    if (usable != d->usable)
	LM_INFO("clusterer_controller: [cluster %d] broadcasts now go by %s\n",
	        cl->cluster_id, usable ? "multicast"
	        : "TCP: a live member does not take them by multicast, or no key yet");
    d->usable = usable;

    /* a node asking for most of them again: multicast does not reach it */
    if (++d->rd_rounds < CL_CTR_DATA_FILTER_ROUNDS)
	return;
    sent = d->st_sent - d->rd_sent;
    for (id = 1; id <= CL_CTR_MAX_PEERS; id++) {
	rep = d->rep_by[id] - d->rd_rep_by[id];
	d->rd_rep_by[id] = d->rep_by[id];
	if (sent < 100 || rep * 5 <= sent || cl_ctr_now() - d->rd_warned < 60)
	    continue;
	d->rd_warned = cl_ctr_now();
	LM_WARN("clusterer_controller: [cluster %d] node %d asked again for %lu of "
	        "the last %lu broadcast datagrams - is multicast to %s:%d filtered "
	        "on its way?\n", cl->cluster_id, id, rep, sent,
	        cl->multicast_address, cl->data_port);
    }
    d->rd_sent = d->st_sent;
    d->rd_rounds = 0;
}

void cl_ctr_data_proc(int rank)
{
    struct pollfd      pf[CL_CTR_MAX_CLUSTERS];
    static char        buf[CL_CTR_UDP_PAYLOAD_MAX];
    long long          now, next_tick;
    int                nfd = 0, i, k, n, ready;

    for (i = 0; i < cl_ctr_cluster_count; i++)
	if (cl_ctr_clusters[i].data && cl_ctr_clusters[i].data_sock >= 0) {
	    pf[nfd].fd = cl_ctr_clusters[i].data_sock;
	    pf[nfd].events = POLLIN;
	    nfd++;
	}
    if (!nfd)
	return;
    LM_INFO("clusterer_controller: broadcast reader %d started (pid=%d)\n",
            rank, getpid());

    next_tick = cl_ctr_now_ms() + CL_CTR_DATA_TICK_MS;
    for (;;) {
	now = cl_ctr_now_ms();
	ready = poll(pf, nfd, rank == 0 ? (int)(next_tick > now ? next_tick - now : 0)
	                                : 1000);
	if (ready < 0 && errno != EINTR) {
	    LM_ERR("clusterer_controller: poll: %s\n", strerror(errno));
	    sleep(1);
	}
	for (i = 0; ready > 0 && i < nfd; i++) {
	    if (!(pf[i].revents & POLLIN))
		continue;
	    /* the others share the socket: whoever is first takes the datagram */
	    for (k = 0; k < 64; k++) {
		n = recv(pf[i].fd, buf, sizeof buf, MSG_DONTWAIT);
		if (n <= 0)
		    break;
		cl_ctr_data_recv(buf, n);
	    }
	}
	if (rank == 0 && cl_ctr_now_ms() >= next_tick) {
	    cl_ctr_data_ticks();
	    next_tick = cl_ctr_now_ms() + CL_CTR_DATA_TICK_MS;
	}
    }
}

static int cl_ctr_data_socket(cl_ctr_cluster_t *cl)
{
    struct sockaddr_in local;
    struct ip_mreq     mreq;
    struct in_addr     ifa;
    unsigned char      loop = 0, ttl = 32;
    int                sock, yes = 1, sz = CL_CTR_DATA_RCVBUF;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
	LM_ERR("clusterer_controller: data socket(): %s\n", strerror(errno));
	return -1;
    }
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
#ifdef IP_MULTICAST_ALL
    {
	int mc_all = 0;
	setsockopt(sock, IPPROTO_IP, IP_MULTICAST_ALL, &mc_all, sizeof mc_all);
    }
#endif
    memset(&local, 0, sizeof local);
    local.sin_family      = AF_INET;
    local.sin_port        = htons((uint16_t)cl->data_port);
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, (struct sockaddr *)&local, sizeof local) < 0) {
	LM_ERR("clusterer_controller: [cluster %d] data socket bind() port %d: %s\n",
	       cl->cluster_id, cl->data_port, strerror(errno));
	close(sock);
	return -1;
    }
    memset(&mreq, 0, sizeof mreq);
    mreq.imr_multiaddr.s_addr = inet_addr(cl->multicast_address);
    mreq.imr_interface.s_addr = inet_addr(my_ip);
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof mreq) < 0) {
	LM_ERR("clusterer_controller: [cluster %d] data socket IP_ADD_MEMBERSHIP "
	       "(%s): %s\n", cl->cluster_id, cl->multicast_address, strerror(errno));
	close(sock);
	return -1;
    }
    setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof loop);
    setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof ttl);
    ifa.s_addr = inet_addr(my_ip);
    setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &ifa, sizeof ifa);
    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK) < 0)
	LM_WARN("clusterer_controller: data socket O_NONBLOCK: %s\n", strerror(errno));
    return sock;
}

int cl_ctr_data_alloc(cl_ctr_cluster_t *cl, int window)
{
    cl->data = shm_malloc(sizeof *cl->data);
    if (!cl->data)
	return -1;
    memset(cl->data, 0, sizeof *cl->data);
    cl->data->window = window;
    cl->data->ring = shm_malloc(sizeof(cl_ctr_slot_t) * window);
    if (!cl->data->ring) {
	shm_free(cl->data);
	cl->data = NULL;
	return -1;
    }
    memset(cl->data->ring, 0, sizeof(cl_ctr_slot_t) * window);
    lock_init(&cl->data->tx_lock);
    lock_init(&cl->data->key_lock);
    lock_init(&cl->data->rx_alloc);
    return 0;
}

int cl_ctr_data_mod_init(void)
{
    cl_ctr_cluster_t *cl;
    int               i, mtu, dgram, n = 0;

    for (i = 0; i < cl_ctr_cluster_count; i++) {
	cl_ctr_clusters[i].data = NULL;
	cl_ctr_clusters[i].data_sock = -1;
    }
    if (!mcast_broadcasts || !cl_ctr_cluster_count)
	return 0;
    if (mcast_workers < 1 || mcast_workers > 32) {
	LM_ERR("clusterer_controller: mcast_workers must be 1..32\n");
	return -1;
    }
    if (mcast_window < 64 || mcast_window > 65536) {
	LM_ERR("clusterer_controller: mcast_window must be 64..65536\n");
	return -1;
    }
    mtu = cl_ctr_read_iface_mtu();
    dgram = mtu > 0 && mtu - 28 < CL_CTR_DATA_DGRAM_MAX ? mtu - 28
                                                        : CL_CTR_DATA_DGRAM_MAX;
    cl_ctr_data_frag_max = dgram - CL_CTR_DATA_OVERHEAD;
    if (cl_ctr_data_frag_max < 256) {
	LM_ERR("clusterer_controller: MTU %d leaves no room for broadcasts\n", mtu);
	return -1;
    }

    for (i = 0; i < cl_ctr_cluster_count; i++) {
	cl = &cl_ctr_clusters[i];
	if (cl_ctr_data_alloc(cl, mcast_window) < 0) {
	    LM_ERR("clusterer_controller: no shm for the broadcast state "
	           "(mcast_window %d needs about %d KB per cluster)\n", mcast_window,
	           (int)(sizeof(cl_ctr_slot_t) * mcast_window / 1024));
	    return -1;
	}
	cl->data_sock = cl_ctr_data_socket(cl);
	if (cl->data_sock < 0) {
	    LM_WARN("clusterer_controller: [cluster %d] no broadcast socket - its "
	            "broadcasts go by TCP\n", cl->cluster_id);
	    shm_free(cl->data->ring);
	    shm_free(cl->data);
	    cl->data = NULL;
	    continue;
	}
	n++;
	memset(&cl->data_dest, 0, sizeof cl->data_dest);
	cl->data_dest.sin_family      = AF_INET;
	cl->data_dest.sin_port        = htons((uint16_t)cl->data_port);
	cl->data_dest.sin_addr.s_addr = inet_addr(cl->multicast_address);
	LM_INFO("clusterer_controller: [cluster %d] broadcasts on %s:%d, up to %d "
	        "bytes a datagram, %d kept for repair\n", cl->cluster_id,
	        cl->multicast_address, cl->data_port, dgram, mcast_window);
    }
    return n;
}
