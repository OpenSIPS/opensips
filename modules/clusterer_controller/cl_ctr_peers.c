/*
 * clusterer_controller - peer table, node_id allocation and cluster identity
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

/* -------------------------------------------------------------------------
 * Per-peer lookups: query a *specific* node in a cluster.  These are script
 * FUNCTIONS, not pseudo-variables, because they take two arguments
 * (cluster_id, node_id) - a comma inside a pvar's parentheses is ambiguous to
 * the config parser when the pvar is used as a function argument.  Boolean
 * checks return true/false for use in if(); value lookups write an output var.
 * ------------------------------------------------------------------------- */

/* Find peer (cluster_id, node_id); cid<=0 => the sole configured cluster.
 * Returns 0 and fills the requested out params on success, -1 if the cluster
 * or node is unknown.  Caller must not hold the peers lock. */
int cl_ctr_find_peer(int cid, int nid, int *is_master, int *is_backup,
                        char *ipbuf, int ipbuf_sz)
{
    cl_ctr_cluster_t *cl = NULL;
    int i, rc = -1;

    if (cid <= 0) {
	if (cl_ctr_cluster_count == 1)
	    cl = &cl_ctr_clusters[0];
    } else {
	for (i = 0; i < cl_ctr_cluster_count; i++)
	    if (cl_ctr_clusters[i].cluster_id == cid) {
		cl = &cl_ctr_clusters[i];
		break;
	    }
    }
    if (!cl || !cl->peers)
	return -1;

    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
	cl_ctr_peer_t *e = &cl->peers->entries[i];
	if (e->node_id != nid)
	    continue;
	if (is_master) *is_master = e->is_master;
	if (is_backup) *is_backup = e->is_backup;
	if (ipbuf) {
	    strncpy(ipbuf, e->ip, ipbuf_sz - 1);
	    ipbuf[ipbuf_sz - 1] = '\0';
	}
	rc = 0;
	break;
    }
    lock_stop_read(cl->peers->lock);
    return rc;
}

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

unsigned int ip_to_num(const char *ip)
{
    struct in_addr addr;
    if (inet_aton(ip, &addr) == 0)
	return 0;
    return ntohl(addr.s_addr);
}

void cl_ctr_prune_stale(cl_ctr_cluster_t *cl)
{
    time_t cutoff = cl_ctr_now() - (time_t)(query_time * CL_CTR_PURGE_FACTOR);
    int    i;

    for (i = 0; i < cl->peers->count; i++) {
	if (cl->peers->entries[i].last_seen < cutoff) {
	    uint16_t pruned_id = cl->peers->entries[i].node_id;
	    LM_INFO("clusterer_controller: purging timed-out peer %s\n",
	            cl->peers->entries[i].ip);
	    cl_ctr_reserve_id_locked(cl, cl->peers->entries[i].ip, pruned_id);
	    cl->peers->count--;
	    if (i < cl->peers->count)
		cl->peers->entries[i] = cl->peers->entries[cl->peers->count];
	    memset(&cl->peers->entries[cl->peers->count], 0, sizeof(cl_ctr_peer_t));
	    i--;
	    /* cl_list_lock and cl->peers->lock are independent - no deadlock */
	    if (clctl_loaded && pruned_id > 0)
		clctl.remove_node(cl->cluster_id, pruned_id);
	    /* If the operator-forced shtag holder timed out, drop the override
	     * so automatic allocation resumes instead of leaving no active tag. */
	    if (pruned_id != 0 && cl->peers->shtag_forced_node_id == pruned_id) {
		LM_WARN("clusterer_controller: [cluster %d] forced shtag node "
		        "%u timed out - resuming automatic allocation\n",
		        cl->cluster_id, pruned_id);
		cl->peers->shtag_forced_node_id = 0;
	    }
	    /* Re-apply shtag policy (override-aware); inside the lock, so pass
	     * the state directly rather than calling the locking wrapper. */
	    cl_ctr_apply_shtags_decision(cl, cl_ctr_i_am_master_locked(cl),
	                             cl->peers->shtag_forced_node_id);
	}
    }
}

/**
 * cl_ctr_apply_master_from_list_locked() - apply master designation from a
 *                                      received MEMBER_LIST/MEMBER_LIST packet.
 *
 * Zeros all is_master flags in the peer table, then sets is_master=1 for
 * the entry matching master_ip.  Updates last_master accordingly.
 * Must be called with cl->peers->lock held.
 */
void cl_ctr_apply_master_from_list_locked(const char *master_ip, cl_ctr_cluster_t *cl)
{
    int i;

    for (i = 0; i < cl->peers->count; i++) {
	if (strcmp(cl->peers->entries[i].ip, master_ip) == 0) {
	    cl->peers->entries[i].is_master = 1;
	} else {
	    cl->peers->entries[i].is_master = 0;
	}
    }

    /* list ordering is per master: a different master starts afresh */
    if (strcmp(cl->peers->last_master, master_ip) != 0) {
	cl->peers->list_term_seen = 0;
	cl->peers->list_seq_seen  = 0;
    }
    memcpy(cl->peers->last_master, master_ip,
           strnlen(master_ip, CL_CTR_MAX_IP_LEN));
    cl->peers->last_master[strnlen(master_ip, CL_CTR_MAX_IP_LEN)] = '\0';
}

/**
 * cl_ctr_peer_by_ip_locked() - find a peer entry by IP string.
 * Returns the entry pointer, or NULL if not present.
 * Must be called with cl->peers->lock held (read or write).
 */
cl_ctr_peer_t *cl_ctr_peer_by_ip_locked(cl_ctr_cluster_t *cl, const char *ip)
{
    int i;
    for (i = 0; i < cl->peers->count; i++)
        if (strcmp(cl->peers->entries[i].ip, ip) == 0)
            return &cl->peers->entries[i];
    return NULL;
}

/**
 * cl_ctr_learn_peer_locked() - membership WITHOUT a liveness claim.
 *
 * A MEMBER_LIST says who BELONGS to the cluster, not who is reachable now: the
 * master lists a node until it prunes it, whether that node is up or not.
 * Refreshing last_seen from such a list - which is what upsert does - makes
 * every receiver believe it has just heard from peers it has never heard from.
 *
 * That is not cosmetic. cl_ctr_alive_bitmap() is built from last_seen, so a
 * backup holding refreshed timestamps for a dead node asserts that node is
 * alive to the entire cluster the moment it becomes master - and then nobody
 * can age it out. A node survived in a live cluster for about a day that way,
 * across a master change, while every TCP connect to it was refused.
 *
 * So: insert what we did not already know about, and leave last_seen of
 * anything we do track to direct evidence only - cl_ctr_upsert_peer_locked()
 * from a packet actually sent BY that peer, or the master's alive bitmap,
 * which the master derives from its own direct evidence.
 *
 * A newly learned peer is still seeded with last_seen = now, deliberately: it
 * gets one purge window to prove itself rather than being pruned on the next
 * tick. This terminates - once the master prunes a dead node it stops listing
 * it, and every receiver ages it out one window later.
 *
 * Must be called with cl->peers->lock held for write.
 */
void cl_ctr_learn_peer_locked(const char *src_ip, cl_ctr_cluster_t *cl)
{
    if (cl_ctr_peer_by_ip_locked(cl, src_ip))
        return;                 /* already known - membership adds nothing */
    cl_ctr_upsert_peer_locked(src_ip, cl);
}

/**
 * cl_ctr_upsert_peer_locked() - insert or refresh a peer entry.
 * Does NOT call cl_ctr_elect_master(cl); callers do that explicitly.
 * Must be called with cl->peers->lock held.
 */
void cl_ctr_upsert_peer_locked(const char *src_ip, cl_ctr_cluster_t *cl)
{
    unsigned int src_num = ip_to_num(src_ip);
    time_t       now     = cl_ctr_now();
    cl_ctr_peer_t   *found;

    if (src_num == 0) {
	LM_WARN("clusterer_controller: ignoring invalid IP '%s'\n", src_ip);
	return;
    }

    found = cl_ctr_peer_by_ip_locked(cl, src_ip);
    if (found) {
	found->last_seen = now;
	return;   /* updated */
    }

    /* New entry */
    if (cl->peers->count >= CL_CTR_MAX_PEERS) {
	/* Counted always, said once a minute: this runs per packet, and a
	 * flood of new sources (or a misconfiguration) must not turn a full
	 * table into a full disk.  cl_ctr_list_config reports the count. */
	cl->peers->peers_refused++;
	if (cl->peers->peers_refused_warned_at == 0
	        || now - cl->peers->peers_refused_warned_at >= 60) {
	    cl->peers->peers_refused_warned_at = now;
	    LM_WARN("clusterer_controller: [cluster %d] peer table full (%d of "
	            "%d) - ignoring %s and any other new address; %lu refused "
	            "so far\n", cl->cluster_id, cl->peers->count,
	            CL_CTR_MAX_PEERS, src_ip, cl->peers->peers_refused);
	}
	return;
    }
    {
	cl_ctr_peer_t *e = &cl->peers->entries[cl->peers->count];
	memcpy(e->ip, src_ip, strnlen(src_ip, CL_CTR_MAX_IP_LEN));
	e->ip[strnlen(src_ip, CL_CTR_MAX_IP_LEN)] = '\0';
	e->ip_num             = src_num;
	e->last_seen          = now;
	e->is_master          = 0;
	cl->peers->count++;
	LM_INFO("clusterer_controller: new peer %s (total=%d)\n",
	        src_ip, cl->peers->count);
    }
}

/**
 * cl_ctr_reserve_id_locked() - hold @node_id for @ip, which just left.
 * Replaces any older hold for the same address or the same id; when the table
 * is full the hold closest to expiry gives way.
 * Must be called with cl->peers->lock held for write.
 */
void cl_ctr_reserve_id_locked(cl_ctr_cluster_t *cl, const char *ip,
                                     uint16_t node_id)
{
    cl_ctr_id_resv_t *r, *slot = NULL;
    time_t            now = cl_ctr_now();
    int               i;

    if (node_id == 0 || ip[0] == '\0')
        return;
    /* drop any older hold for this address or this id */
    for (i = 0; i < CL_CTR_MAX_PEERS; i++) {
        r = &cl->peers->id_resv[i];
        if (r->ip[0] != '\0' &&
            (strcmp(r->ip, ip) == 0 || r->node_id == node_id))
            r->ip[0] = '\0';
    }
    /* a free or expired slot ... */
    for (i = 0; i < CL_CTR_MAX_PEERS && !slot; i++) {
        r = &cl->peers->id_resv[i];
        if (r->ip[0] == '\0' || r->until <= now)
            slot = r;
    }
    /* ... or else the hold closest to expiry */
    if (!slot) {
        slot = &cl->peers->id_resv[0];
        for (i = 1; i < CL_CTR_MAX_PEERS; i++)
            if (cl->peers->id_resv[i].until < slot->until)
                slot = &cl->peers->id_resv[i];
    }
    snprintf(slot->ip, sizeof(slot->ip), "%s", ip);
    slot->node_id = node_id;
    slot->until   = now + CL_CTR_ID_RESERVE_SECS;
}

/* node_id currently used by a member of the peer table? */
static int cl_ctr_id_in_use_locked(cl_ctr_cluster_t *cl, uint16_t id)
{
    int i;
    for (i = 0; i < cl->peers->count; i++)
        if (cl->peers->entries[i].node_id == id)
            return 1;
    return 0;
}

/**
 * cl_ctr_alloc_node_id_locked() - choose a node_id for @ip.
 *
 * The id @ip held before it left, if that is still reserved for it and free;
 * otherwise the lowest id that is neither in use nor held for another node
 * that left recently; otherwise - every id held - the lowest not in use.
 * Must be called with cl->peers->lock held for write.
 */
uint16_t cl_ctr_alloc_node_id_locked(cl_ctr_cluster_t *cl, const char *ip)
{
    time_t   now = cl_ctr_now();
    uint16_t id;
    int      i, held;

    for (i = 0; i < CL_CTR_MAX_PEERS; i++) {
        cl_ctr_id_resv_t *r = &cl->peers->id_resv[i];
        if (r->ip[0] != '\0' && r->until > now && strcmp(r->ip, ip) == 0) {
            id = r->node_id;
            r->ip[0] = '\0';                      /* claimed */
            if (!cl_ctr_id_in_use_locked(cl, id)) {
                LM_INFO("clusterer_controller: [cluster %d] %s rejoined - "
                        "giving it back node_id %u\n", cl->cluster_id, ip, id);
                return id;
            }
            break;
        }
    }
    for (id = 1; id < 65535; id++) {
        if (cl_ctr_id_in_use_locked(cl, id))
            continue;
        held = 0;
        for (i = 0; i < CL_CTR_MAX_PEERS; i++) {
            cl_ctr_id_resv_t *r = &cl->peers->id_resv[i];
            if (r->ip[0] != '\0' && r->until > now && r->node_id == id) {
                held = 1;
                break;
            }
        }
        if (!held)
            return id;
    }
    for (id = 1; id < 65535; id++)            /* everything is held */
        if (!cl_ctr_id_in_use_locked(cl, id))
            return id;
    return 0;   /* table full (shouldn't happen with CL_CTR_MAX_PEERS=256) */
}

/**
 * cl_ctr_update_peer_bin_locked() - store node_id and BIN sockets for a peer.
 * Must be called with cl->peers->lock held.
 */
void cl_ctr_update_peer_bin_locked(const char *ip, uint16_t node_id,
                                      uint8_t bin_count,
                                      const char (*bin_sockets)[CL_CTR_MAX_BIN_SOCK_LEN],
                                      cl_ctr_cluster_t *cl)
{
    cl_ctr_peer_t *e = cl_ctr_peer_by_ip_locked(cl, ip);
    if (e) {
	e->node_id   = node_id;
	e->bin_count = bin_count;
	if (bin_count > 0)
	    memcpy(e->bin_sockets, bin_sockets, bin_count * CL_CTR_MAX_BIN_SOCK_LEN);
    }
}

/* =========================================================================
 * Founded cluster identity (CL_CTR_CID_*)
 * ========================================================================= */

const char *cl_ctr_cid_state_name(int st)
{
    switch (st) {
    case CL_CTR_CID_PROVISIONAL: return "provisional";
    case CL_CTR_CID_ESTABLISHED: return "established";
    case CL_CTR_CID_PINNED:      return "pinned";
    default:                     return "none";
    }
}

/* "8-4-4-4-12" lowercase into @out (37 bytes) */
void cl_ctr_cid_str(const unsigned char *cid, char *out)
{
    static const char hx[] = "0123456789abcdef";
    int i, o = 0;
    for (i = 0; i < CL_CTR_CID_SZ; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            out[o++] = '-';
        out[o++] = hx[cid[i] >> 4];
        out[o++] = hx[cid[i] & 0x0F];
    }
    out[o] = '\0';
}

int cl_ctr_cid_is_zero(const unsigned char *cid)
{
    int i;
    for (i = 0; i < CL_CTR_CID_SZ; i++)
        if (cid[i])
            return 0;
    return 1;
}

/* uuid= value: a UUID as written, or any other string hashed into a v8 UUID,
 * so a fleet can pin a readable name.  0 ok, -1 empty. */
int cl_ctr_cid_parse_pin(const char *v, unsigned char *out)
{
    int i, n = 0, ok = (strlen(v) == 36);

    for (i = 0; ok && v[i]; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            ok = (v[i] == '-');
            continue;
        }
        if (!isxdigit((unsigned char)v[i])) {
            ok = 0;
            break;
        }
        if (n % 2 == 0)
            out[n / 2] = 0;
        out[n / 2] |= (unsigned char)((isdigit((unsigned char)v[i]) ? v[i] - '0'
                                     : (tolower((unsigned char)v[i]) - 'a' + 10))
                                     << (n % 2 ? 0 : 4));
        n++;
    }
    if (ok && n == 2 * CL_CTR_CID_SZ)
        return 0;
    if (!v[0])
        return -1;
    crypto_generichash(out, CL_CTR_CID_SZ, (const unsigned char *)v, strlen(v),
                       (const unsigned char *)"cl_ctr_cluster_uuid", 19);
    out[6] = (unsigned char)((out[6] & 0x0F) | 0x80);   /* version 8 */
    out[8] = (unsigned char)((out[8] & 0x3F) | 0x80);   /* RFC 9562 variant */
    return 0;
}

/* Take @cid as this cluster's identity, PROVISIONAL.  An established or
 * pinned identity is never replaced. */
void cl_ctr_cid_adopt(cl_ctr_cluster_t *cl, const unsigned char *cid,
                             const char *how)
{
    char s1[37], s2[37];

    if (cl->peers->cid_state == CL_CTR_CID_ESTABLISHED
            || cl->peers->cid_state == CL_CTR_CID_PINNED)
        return;
    if (cl->peers->cid_state != CL_CTR_CID_NONE
            && memcmp(cl->peers->cid, cid, CL_CTR_CID_SZ) == 0)
        return;
    cl_ctr_cid_str(cid, s1);
    if (cl->peers->cid_state == CL_CTR_CID_PROVISIONAL) {
        cl_ctr_cid_str(cl->peers->cid, s2);
        LM_INFO("clusterer_controller: [cluster %d] cluster uuid %s (%s) - "
                "giving up provisional %s\n", cl->cluster_id, s1, how, s2);
    } else {
        LM_INFO("clusterer_controller: [cluster %d] cluster uuid %s (%s)\n",
                cl->cluster_id, s1, how);
    }
    memcpy(cl->peers->cid, cid, CL_CTR_CID_SZ);
    cl->peers->cid_state = CL_CTR_CID_PROVISIONAL;
    cl->peers->cid_since = cl_ctr_now();
}

/* Founding a cluster: into an id we have already heard from authenticated
 * traffic if there is one, otherwise a new UUID v7. */
void cl_ctr_cid_found(cl_ctr_cluster_t *cl)
{
    unsigned char id[CL_CTR_CID_SZ];
    struct timeval tv;
    uint64_t ms;
    int i;

    if (cl->peers->cid_state != CL_CTR_CID_NONE)
        return;
    if (cl->heard_cid_set) {
        cl_ctr_cid_adopt(cl, cl->heard_cid, "founding into the cluster "
                         "already heard on this group");
        return;
    }
    gettimeofday(&tv, NULL);
    ms = (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
    randombytes_buf(id, sizeof id);
    for (i = 0; i < 6; i++)
        id[i] = (unsigned char)(ms >> (40 - 8 * i));
    id[6] = (unsigned char)((id[6] & 0x0F) | 0x70);          /* version 7 */
    id[8] = (unsigned char)((id[8] & 0x3F) | 0x80);          /* variant */
    cl_ctr_cid_adopt(cl, id, "founded here");
}

/* Called on every ALIVE tick: a provisional id that has lasted the grace
 * period becomes permanent for this process. */
void cl_ctr_cid_tick(cl_ctr_cluster_t *cl)
{
    char s1[37];

    if (cl->peers->cid_state != CL_CTR_CID_PROVISIONAL
            || cl_ctr_now() - cl->peers->cid_since < CL_CTR_CID_GRACE_SECS)
        return;
    cl->peers->cid_state = CL_CTR_CID_ESTABLISHED;
    cl_ctr_cid_str(cl->peers->cid, s1);
    LM_INFO("clusterer_controller: [cluster %d] cluster uuid %s established - "
            "traffic from any other cluster is refused from now on\n",
            cl->cluster_id, s1);
}


/*
 * Order-independent digest of the active peer set: the XOR of a per-peer FNV-1a
 * over (node_id, ip_num).  A member that missed a peer's NODE_ASSIGN carries
 * node_id 0 for it and so computes a different hash from the master's - which is
 * how the gap is detected.  Roles are deliberately excluded (they reconcile via
 * MASTER_ALIVE itself) to avoid spurious resyncs on transient role churn.
 * Takes the read lock itself - the caller must NOT hold cl->peers->lock.
 */
void cl_ctr_membership_digest(cl_ctr_cluster_t *cl, uint16_t *count, uint64_t *hash)
{
    uint64_t h = 0;
    uint16_t c = 0;
    time_t   cutoff = cl_ctr_now() - (time_t)(query_time * CL_CTR_ELECT_FACTOR);
    int      i, k;

    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e = &cl->peers->entries[i];
        uint64_t      ph = 1469598103934665603ULL;   /* FNV-1a offset basis */
        unsigned char b[6];
        if (e->last_seen < cutoff)
            continue;
        b[0] = (unsigned char)(e->node_id >> 8);  b[1] = (unsigned char)e->node_id;
        b[2] = (unsigned char)(e->ip_num >> 24);  b[3] = (unsigned char)(e->ip_num >> 16);
        b[4] = (unsigned char)(e->ip_num >> 8);   b[5] = (unsigned char)e->ip_num;
        for (k = 0; k < 6; k++) { ph ^= b[k]; ph *= 1099511628211ULL; }
        h ^= ph;
        c++;
    }
    lock_stop_read(cl->peers->lock);
    *count = c;
    *hash  = h;
}

/* Fill @bm (CL_CTR_ALIVE_BITMAP_SZ bytes) with a bit set for every peer the
 * master has seen inside the election window - the liveness it relays. */
void cl_ctr_build_alive_bitmap(cl_ctr_cluster_t *cl, unsigned char *bm)
{
    time_t cutoff = cl_ctr_now() - (time_t)(query_time * CL_CTR_ELECT_FACTOR);
    int    i;

    memset(bm, 0, CL_CTR_ALIVE_BITMAP_SZ);
    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e   = &cl->peers->entries[i];
        uint16_t       nid = e->node_id;
        if (e->last_seen < cutoff || nid == 0 || nid > CL_CTR_MAX_PEERS)
            continue;
        bm[nid >> 3] |= (unsigned char)(1u << (nid & 7));
    }
    lock_stop_read(cl->peers->lock);
}

/* Refresh last_seen for every peer whose node_id the master reports alive in @bm,
 * so a settled non-master keeps its election window populated without hearing the
 * peers' ALIVEs directly.  Only a non-master applies this. */
void cl_ctr_apply_alive_bitmap(cl_ctr_cluster_t *cl, const unsigned char *bm)
{
    time_t now = cl_ctr_now();
    int    i;

    lock_start_write(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e   = &cl->peers->entries[i];
        uint16_t       nid = e->node_id;
        if (nid == 0 || nid > CL_CTR_MAX_PEERS)
            continue;
        if (bm[nid >> 3] & (unsigned char)(1u << (nid & 7)))
            e->last_seen = now;
    }
    lock_stop_write(cl->peers->lock);
}

/**
 * cl_ctr_drop_peer_locked() - remove a peer from the table by IP.
 *
 * Needed because refusing a JOIN_REQ is not by itself enough to keep a node
 * out: while this node was still NEW it upserts every joiner it hears (the
 * split-brain defer path), so a peer can already be in the table by the time
 * we become master and refuse it.  Without this the master goes on counting a
 * node it just told to go away - and, worse, cl_ctr_mtu_note_reject() would
 * never see the "holding no members" condition that makes it speak up.
 *
 * Same swap-with-last removal cl_ctr_prune_stale uses.  Call WITH the write
 * lock held.
 */
void cl_ctr_drop_peer_locked(const char *ip, cl_ctr_cluster_t *cl)
{
    int i;

    for (i = 0; i < cl->peers->count; i++) {
        uint16_t dropped_id;
        if (strcmp(cl->peers->entries[i].ip, ip) != 0)
            continue;
        dropped_id = cl->peers->entries[i].node_id;
        cl->peers->count--;
        if (i < cl->peers->count)
            cl->peers->entries[i] = cl->peers->entries[cl->peers->count];
        memset(&cl->peers->entries[cl->peers->count], 0, sizeof(cl_ctr_peer_t));
        if (clctl_loaded && dropped_id > 0)
            clctl.remove_node(cl->cluster_id, dropped_id);
        return;
    }
}

/* Fill @bm (CL_CTR_ALIVE_BITMAP_SZ bytes) with a bit set for every node, by
 * node_id, in maintenance - this node's own state included.  Master path. */
void cl_ctr_build_maint_bitmap(cl_ctr_cluster_t *cl, unsigned char *bm)
{
    int i;

    memset(bm, 0, CL_CTR_ALIVE_BITMAP_SZ);
    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e   = &cl->peers->entries[i];
        uint16_t       nid = e->node_id;
        if (nid == 0 || nid > CL_CTR_MAX_PEERS || e->maint == CL_CTR_MAINT_NONE)
            continue;
        bm[nid >> 3] |= (unsigned char)(1u << (nid & 7));
    }
    lock_stop_read(cl->peers->lock);
}

/* Take the master's maintenance relay (@bm, by node_id).  This node's own
 * entry follows its own state, not the relay.  Raises E_CL_CTR_MAINTENANCE
 * for each node whose state changed.  Returns 1 when @master_ip itself has
 * just gone into maintenance.  Non-master path; call WITHOUT cl->peers->lock held. */
int cl_ctr_apply_maint_bitmap(cl_ctr_cluster_t *cl, const unsigned char *bm,
                              const char *master_ip)
{
    uint16_t chg_id[CL_CTR_MAX_PEERS];
    uint8_t  chg_st[CL_CTR_MAX_PEERS];
    int      i, n = 0, master_in = 0, master_chg = 0;

    lock_start_write(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e   = &cl->peers->entries[i];
        uint16_t       nid = e->node_id;
        uint8_t        st;
        if (nid == 0 || nid > CL_CTR_MAX_PEERS || strcmp(e->ip, my_ip) == 0)
            continue;
        st = (bm[nid >> 3] & (unsigned char)(1u << (nid & 7)))
             ? CL_CTR_MAINT_EVICTED : CL_CTR_MAINT_NONE;
        if (st != e->maint) {
            e->maint = st;
            chg_id[n] = nid;
            chg_st[n++] = st;
            if (strcmp(e->ip, master_ip) == 0)
                master_chg = 1;
        }
        if (st != CL_CTR_MAINT_NONE && strcmp(e->ip, master_ip) == 0)
            master_in = 1;
    }
    lock_stop_write(cl->peers->lock);

    for (i = 0; i < n; i++)
        cl_ctr_raise_maint_event(cl, chg_id[i], chg_st[i]);
    return master_in && master_chg;
}

/* How many members this node hears now: entries inside the election window,
 * itself included - the count masters are ranked on (CL_CTR_LIVE_SZ).  For a
 * settled member it follows the master's liveness relay.  A peer only forgiven
 * by a stall check (its last_seen still the value that check gave it) has not
 * been heard and is not vouched for: a node woken from a pause into a
 * partition must not out-count the members that really hear each other. */
uint16_t cl_ctr_live_count(cl_ctr_cluster_t *cl)
{
    time_t   cutoff = cl_ctr_now() - (time_t)(query_time * CL_CTR_ELECT_FACTOR);
    uint16_t n = 0;
    int      i;

    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e = &cl->peers->entries[i];
        if (e->last_seen < cutoff)
            continue;
        if (cl->forgiven_at && e->last_seen == cl->forgiven_at &&
                strcmp(e->ip, my_ip) != 0)
            continue;
        n++;
    }
    lock_stop_read(cl->peers->lock);
    return n;
}
