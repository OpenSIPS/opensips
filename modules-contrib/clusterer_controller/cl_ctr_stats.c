/*
 * clusterer_controller - module statistics
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
#include "cl_ctr_stats.h"
#include "../../statistics.h"
#include "cl_ctr_data.h"
#include "cl_ctr_stats.h"
#include "cl_ctr_events.h"

/* per cluster, named <statistic>-<cluster_id> (members-1); functions over the shm
 * peer table, which only the worker writes - counters only grow, not resettable */

#define CL_CTR_ST(_c)  ((cl_ctr_cluster_t *)(_c))

/* this node's role in the cluster: 2 master, 1 backup, 0 member */
static unsigned long cl_ctr_st_role(void *c)
{
    cl_ctr_cluster_t *cl = CL_CTR_ST(c);
    unsigned long     r = 0;
    int               i;

    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++)
        if (strcmp(cl->peers->entries[i].ip, my_ip) == 0) {
            r = cl->peers->entries[i].is_master ? 2
                : cl->peers->entries[i].is_backup ? 1 : 0;
            break;
        }
    lock_stop_read(cl->peers->lock);
    return r;
}

static unsigned long cl_ctr_st_is_master(void *c)
{
    return cl_ctr_st_role(c) == 2;
}

static unsigned long cl_ctr_st_members(void *c)
{
    return cl_ctr_live_count(CL_CTR_ST(c));
}

#define CL_CTR_ST_FIELD(_name, _field) \
static unsigned long cl_ctr_st_##_name(void *c) \
{ \
    return (unsigned long)CL_CTR_ST(c)->peers->_field; \
}

/* gauges */
CL_CTR_ST_FIELD(maintenance,             my_maint)
CL_CTR_ST_FIELD(term,                    term_seen)
CL_CTR_ST_FIELD(local_health,            local_health)
CL_CTR_ST_FIELD(master_timeout_ms,       ka_timeout_ms)
CL_CTR_ST_FIELD(tag_released,            tag_released)
/* counters the controller keeps anyway */
CL_CTR_ST_FIELD(election_holds,          election_holds)
CL_CTR_ST_FIELD(master_false_suspicions, ka_false_suspicions)
CL_CTR_ST_FIELD(self_stalls,             self_stalls)
CL_CTR_ST_FIELD(terms_refused,           terms_refused)
CL_CTR_ST_FIELD(peers_refused,           peers_refused)
CL_CTR_ST_FIELD(foreign_packets,         foreign_pkts)
CL_CTR_ST_FIELD(rx_kernel_drops,         rx_kernel_drops)
/* counters kept for the statistics */
CL_CTR_ST_FIELD(master_changes,          st_master_changes)
CL_CTR_ST_FIELD(role_changes,            st_role_changes)
CL_CTR_ST_FIELD(members_joined,          st_members_joined)
CL_CTR_ST_FIELD(members_left,            st_members_left)
CL_CTR_ST_FIELD(joins_refused,           st_joins_refused)
CL_CTR_ST_FIELD(config_mismatches,       st_config_mismatches)
CL_CTR_ST_FIELD(auth_failures,           st_auth_failures)
CL_CTR_ST_FIELD(merges,                  st_merges)
CL_CTR_ST_FIELD(admitted,                st_admitted)
CL_CTR_ST_FIELD(admissions_stuck,        st_admit_stuck)

/* broadcasts over multicast (cl_ctr_data.c) */
#define CL_CTR_ST_DATA(_name, _which) \
static unsigned long cl_ctr_st_##_name(void *c) \
{ \
    return cl_ctr_data_stat(CL_CTR_ST(c), _which); \
}
CL_CTR_ST_DATA(mcast_sent,          CL_CTR_DST_SENT)
CL_CTR_ST_DATA(mcast_received,      CL_CTR_DST_RECEIVED)
CL_CTR_ST_DATA(mcast_repairs,       CL_CTR_DST_REPAIRS)
CL_CTR_ST_DATA(mcast_nacks,         CL_CTR_DST_NACKS)
CL_CTR_ST_DATA(mcast_gaps,          CL_CTR_DST_GAPS)
CL_CTR_ST_DATA(mcast_tcp,           CL_CTR_DST_TCP)
CL_CTR_ST_DATA(mcast_barrier_waits, CL_CTR_DST_BARRIER_WAITS)
CL_CTR_ST_DATA(mcast_barrier_late,  CL_CTR_DST_BARRIER_LATE)

/* joiners in CONNECTING, as the master relays them */
static unsigned long cl_ctr_st_connecting(void *c)
{
    cl_ctr_cluster_t *cl = CL_CTR_ST(c);
    unsigned long     n = 0;
    int               i;

    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++)
        n += cl->peers->entries[i].connecting ? 1 : 0;
    lock_stop_read(cl->peers->lock);
    return n;
}

static const struct {
    char          *name;
    stat_function  fn;
} cl_ctr_stat_defs[] = {
    { "role",                    cl_ctr_st_role                    },
    { "is_master",               cl_ctr_st_is_master               },
    { "members",                 cl_ctr_st_members                 },
    { "maintenance",             cl_ctr_st_maintenance             },
    { "term",                    cl_ctr_st_term                    },
    { "local_health",            cl_ctr_st_local_health            },
    { "master_timeout_ms",       cl_ctr_st_master_timeout_ms       },
    { "tag_released",            cl_ctr_st_tag_released            },
    { "master_changes",          cl_ctr_st_master_changes          },
    { "role_changes",            cl_ctr_st_role_changes            },
    { "members_joined",          cl_ctr_st_members_joined          },
    { "members_left",            cl_ctr_st_members_left            },
    { "joins_refused",           cl_ctr_st_joins_refused           },
    { "config_mismatches",       cl_ctr_st_config_mismatches       },
    { "auth_failures",           cl_ctr_st_auth_failures           },
    { "merges",                  cl_ctr_st_merges                  },
    { "connecting",              cl_ctr_st_connecting              },
    { "admitted",                cl_ctr_st_admitted                },
    { "admissions_stuck",        cl_ctr_st_admissions_stuck        },
    { "election_holds",          cl_ctr_st_election_holds          },
    { "master_false_suspicions", cl_ctr_st_master_false_suspicions },
    { "self_stalls",             cl_ctr_st_self_stalls             },
    { "terms_refused",           cl_ctr_st_terms_refused           },
    { "peers_refused",           cl_ctr_st_peers_refused           },
    { "foreign_packets",         cl_ctr_st_foreign_packets         },
    { "rx_kernel_drops",         cl_ctr_st_rx_kernel_drops         },
    { "mcast_sent",              cl_ctr_st_mcast_sent              },
    { "mcast_received",          cl_ctr_st_mcast_received          },
    { "mcast_repairs",           cl_ctr_st_mcast_repairs           },
    { "mcast_nacks",             cl_ctr_st_mcast_nacks             },
    { "mcast_gaps",              cl_ctr_st_mcast_gaps              },
    { "mcast_tcp",               cl_ctr_st_mcast_tcp               },
    { "mcast_barrier_waits",     cl_ctr_st_mcast_barrier_waits     },
    { "mcast_barrier_late",      cl_ctr_st_mcast_barrier_late      },
};

#define CL_CTR_STAT_DEFS (int)(sizeof(cl_ctr_stat_defs) / sizeof(cl_ctr_stat_defs[0]))

int cl_ctr_stats_register(cl_ctr_cluster_t *cl)
{
    char  cid[12];
    char *name;
    str   prefix;
    int   k;

    snprintf(cid, sizeof cid, "%d", cl->cluster_id);
    for (k = 0; k < CL_CTR_STAT_DEFS; k++) {
        prefix.s   = cl_ctr_stat_defs[k].name;
        prefix.len = strlen(prefix.s);
        if ((name = build_stat_name(&prefix, cid)) == NULL ||
                register_stat2("clusterer_controller", name,
                               (stat_var **)cl_ctr_stat_defs[k].fn,
                               STAT_SHM_NAME | STAT_IS_FUNC, cl, 0) != 0) {
            LM_ERR("clusterer_controller: [cluster %d] cannot register the "
                   "%s statistic\n", cl->cluster_id, cl_ctr_stat_defs[k].name);
            return -1;
        }
    }
    return 0;
}

/* safe with the peers lock held: the worker is the counters' one writer, and
 * events are raised after unlock */

void cl_ctr_note_role(cl_ctr_cluster_t *cl, int old_role, int new_role)
{
    cl->peers->st_role_changes++;
    cl_ctr_ev_role(cl, old_role, new_role);
}

void cl_ctr_note_master(cl_ctr_cluster_t *cl, const char *master_ip,
                        uint16_t node_id)
{
    cl->peers->st_master_changes++;
    cl_ctr_ev_master(cl, master_ip, node_id);
}

void cl_ctr_note_member(cl_ctr_cluster_t *cl, const char *ip, uint16_t node_id,
                        int joined, const char *reason)
{
    if (joined)
        cl->peers->st_members_joined++;
    else
        cl->peers->st_members_left++;
    cl_ctr_ev_member(cl, ip, node_id, joined, reason);
}

void cl_ctr_note_admission(cl_ctr_cluster_t *cl, const char *ip, uint16_t node_id,
                           const char *state)
{
    if (strcmp(state, "online") == 0)
        cl->peers->st_admitted++;
    else if (strcmp(state, "stuck") == 0)
        cl->peers->st_admit_stuck++;
    cl_ctr_ev_admission(cl, ip, node_id, state);
}

void cl_ctr_note_join_refused(cl_ctr_cluster_t *cl, const char *ip,
                              const char *reason)
{
    cl->peers->st_joins_refused++;
    cl_ctr_ev_refused(cl, ip, reason);
}

void cl_ctr_note_config_mismatch(cl_ctr_cluster_t *cl, const char *ip)
{
    (void)ip;
    cl->peers->st_config_mismatches++;
}

void cl_ctr_note_auth_failure(cl_ctr_cluster_t *cl, const char *ip)
{
    (void)ip;
    cl->peers->st_auth_failures++;
}

void cl_ctr_note_merge(cl_ctr_cluster_t *cl, const char *superior_ip,
                       int was_master)
{
    cl->peers->st_merges++;
    cl_ctr_ev_merge(cl, superior_ip, was_master);
}
