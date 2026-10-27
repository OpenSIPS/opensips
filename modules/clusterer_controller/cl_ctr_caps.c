/*
 * clusterer_controller - capability bits (CC-11)
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
#include "cl_ctr_caps.h"

/* -------------------------------------------------------------------------
 * Capability bits.  The wire version says whether two nodes can talk at
 * all; within one wire version each node advertises on its ALIVE which
 * optional mechanisms its build implements (CL_CTR_CAP_*).  Only the master
 * hears every member's ALIVE (a settled member unicasts it there), so the
 * master works out what every live member shares and relays it in its
 * MASTER_ALIVE; a member takes the relayed value.  A mechanism that needs
 * the other members' part is used only while every live member has it.  A
 * build older than the field advertises and relays nothing, so it is never
 * asked to do what it cannot, and a rolling upgrade gets each mechanism the
 * moment the last old node is gone.
 * ------------------------------------------------------------------------- */

static const struct {
    uint32_t    bit;
    const char *name;
} cl_ctr_cap_names[] = {
    { CL_CTR_CAP_PROBE,      "probe"      },
    { CL_CTR_CAP_MAINT_SET,  "maint_set"  },
    { CL_CTR_CAP_MAINT_FULL, "maint_full" },
};

#define CL_CTR_CAP_NAMES (int)(sizeof(cl_ctr_cap_names) / sizeof(cl_ctr_cap_names[0]))

/* The live set, as cl_ctr_live_count() counts it.  Caller holds the lock. */
static int cl_ctr_caps_live_locked(cl_ctr_cluster_t *cl, const cl_ctr_peer_t *e,
                                   time_t cutoff)
{
    if (e->last_seen < cutoff)
        return 0;
    if (cl->forgiven_at && e->last_seen == cl->forgiven_at &&
            strcmp(e->ip, my_ip) != 0)
        return 0;
    return 1;
}

/* The election window in force - the worker's adopted query_time is
 * mirrored in shm for the other processes (MI, script). */
static time_t cl_ctr_caps_cutoff(cl_ctr_cluster_t *cl)
{
    int qt = cl->peers->eff_query_time > 0 ? cl->peers->eff_query_time
                                           : query_time;
    return cl_ctr_now() - (time_t)(qt * CL_CTR_ELECT_FACTOR);
}

/* What every live member in this node's table advertises, this node
 * included - meaningful on the master, which hears them all. */
uint32_t cl_ctr_table_caps(cl_ctr_cluster_t *cl)
{
    time_t   cutoff = cl_ctr_caps_cutoff(cl);
    uint32_t caps = CL_CTR_CAPS_MINE;
    int      i;

    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e = &cl->peers->entries[i];
        if (strcmp(e->ip, my_ip) == 0 || !cl_ctr_caps_live_locked(cl, e, cutoff))
            continue;
        caps &= e->caps;
    }
    lock_stop_read(cl->peers->lock);
    return caps;
}

/* What every live member shares: worked out here on the master, as the
 * master last relayed it on a member. */
uint32_t cl_ctr_cluster_caps(cl_ctr_cluster_t *cl)
{
    uint32_t relayed;
    int      im;

    lock_start_read(cl->peers->lock);
    im      = cl_ctr_i_am_master_locked(cl);
    relayed = cl->peers->cluster_caps;
    lock_stop_read(cl->peers->lock);
    return im ? cl_ctr_table_caps(cl) : (relayed & CL_CTR_CAPS_MINE);
}

/* On the master: how many live members do not advertise @cap; the first
 * one's IP goes to @ip.  0 elsewhere - a member does not hear the others. */
static int cl_ctr_live_lacking(cl_ctr_cluster_t *cl, uint32_t cap, char *ip,
                               int ip_sz)
{
    time_t cutoff = cl_ctr_caps_cutoff(cl);
    int    i, n = 0;

    ip[0] = '\0';
    lock_start_read(cl->peers->lock);
    if (!cl_ctr_i_am_master_locked(cl)) {
        lock_stop_read(cl->peers->lock);
        return 0;
    }
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e = &cl->peers->entries[i];
        if (strcmp(e->ip, my_ip) == 0 || !cl_ctr_caps_live_locked(cl, e, cutoff))
            continue;
        if (e->caps & cap)
            continue;
        if (n++ == 0)
            snprintf(ip, ip_sz, "%s", e->ip);
    }
    lock_stop_read(cl->peers->lock);
    return n;
}

/* An MI array @name of the capability names set in @caps. */
int cl_ctr_mi_add_caps(mi_item_t *obj, const char *name, int name_len,
                       uint32_t caps)
{
    mi_item_t *arr = add_mi_array(obj, (char *)name, name_len);
    int        k;

    if (!arr)
        return -1;
    for (k = 0; k < CL_CTR_CAP_NAMES; k++)
        if ((caps & cl_ctr_cap_names[k].bit) &&
                add_mi_string(arr, NULL, 0, cl_ctr_cap_names[k].name,
                              strlen(cl_ctr_cap_names[k].name)) < 0)
            return -1;
    return 0;
}

/* Can a node be put into maintenance state @st from here - this node
 * itself, or another one (@remote)?  Asking another node needs it to apply
 * MAINT_SET; the full level needs every live member to act on it, or
 * replication would stop towards the node from only some of them.  Both
 * are judged on what every live member shares.  0 = yes; -1 with the reason
 * in @why. */
int cl_ctr_maint_supported(cl_ctr_cluster_t *cl, int remote, int st,
                           char *why, int why_sz)
{
    uint32_t have = cl_ctr_cluster_caps(cl);
    char     ip[CL_CTR_MAX_IP_LEN + 1];
    int      n;

    if (remote && !(have & CL_CTR_CAP_MAINT_SET)) {
        n = cl_ctr_live_lacking(cl, CL_CTR_CAP_MAINT_SET, ip, sizeof ip);
        snprintf(why, why_sz, "not every live member runs a build with remote "
                 "maintenance (no maint_set capability%s%s%s) - finish the "
                 "upgrade first", n ? ", " : "", ip, n ? " among them" : "");
        return -1;
    }
    if (st == CL_CTR_MAINT_FULL && !(have & CL_CTR_CAP_MAINT_FULL)) {
        n = cl_ctr_live_lacking(cl, CL_CTR_CAP_MAINT_FULL, ip, sizeof ip);
        snprintf(why, why_sz, "not every live member acts on the full level "
                 "(no maint_full capability%s%s%s) - they would keep "
                 "replicating to the node", n ? ", " : "", ip,
                 n ? " among them" : "");
        return -1;
    }
    return 0;
}
