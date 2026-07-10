/*
 * clusterer_controller - multicast extension for the clusterer module
 *
 * Copyright (C) 10/07/2026 Yury Kirsanov
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
 * =========================================================================
 * MODULE: clusterer_controller
 * =========================================================================
 *
 * PROTOCOL OVERVIEW
 * -----------------
 * All traffic is UDP multicast to multicast_address:multicast_port.
 *
 * Wire format:
 *   [2 bytes: magic 0xCC01, network byte order]
 *   [1 byte:  packet type  CC_PKT_*]
 *   [payload: type-specific, described below]
 *
 * Packet types:
 *
 *   CC_PKT_ALIVE (0x01)
 *     Payload: null-terminated IP string (max 15 chars + NUL).
 *     Sent every query_time seconds by every active node.
 *     Receiving nodes upsert the sender into their peer table and re-elect.
 *
 *   CC_PKT_JOIN_REQ (0x02)
 *     Payload: null-terminated IP string of the joining node.
 *     Sent once by a new node on startup before it begins sending ALIVEs.
 *     — All nodes: upsert the new peer, re-elect.
 *     — Master node only: reply with CC_PKT_MEMBER_LIST (to multicast).
 *     If no MEMBER_LIST is received within query_time seconds, the node
 *     assumes there is no master yet and transitions to active state,
 *     participating in the normal election cycle.
 *
 *   CC_PKT_MEMBER_LIST (0x03)
 *     Payload: [1 byte: count N] [N × 16-byte null-padded IP entries]
 *     Sent by the master in response to a JOIN_REQ (to multicast so that
 *     ALL nodes receive it and re-elect with the same peer set).
 *     — New node (CC_NODE_NEW):  replaces/populates its peer table and
 *       transitions to CC_NODE_ACTIVE.
 *     — Existing nodes: merge the listed peers into their own table and
 *       re-elect.  This is the explicit "trigger re-election on all nodes".
 *
 * NODE STATE MACHINE
 * ------------------
 *
 *   CC_NODE_NEW ──► (MEMBER_LIST received)  ──► CC_NODE_ACTIVE
 *               └─► (join_deadline expired) ──► CC_NODE_ACTIVE
 *
 *   In CC_NODE_NEW:   listen for packets, do NOT yet send ALIVE.
 *   In CC_NODE_ACTIVE: send ALIVE every query_time seconds.
 *
 * MASTER ELECTION
 * ---------------
 * Deterministic: the peer with the numerically highest IP address is master.
 * Uses a QUANTIZED election window so all NTP-synchronized nodes evaluate
 * identical peer sets and always elect the same master.
 *
 * =========================================================================
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>          /* O_NONBLOCK, fcntl()                            */
#include <ifaddrs.h>        /* getifaddrs(), freeifaddrs()                    */
#include <net/if.h>         /* IF_NAMESIZE, struct ifreq, SO_BINDTODEVICE     */

#include "../../sr_module.h"    /* module_exports, MODULE_VERSION, proc_export_t,
                                   PROC_FLAG_*, dep_export_t, DEP_ABORT,
                                   param_export_t, STR_PARAM, INT_PARAM       */
#include "../../dprint.h"       /* LM_ERR / LM_WARN / LM_INFO / LM_DBG       */
#include "../../mem/shm_mem.h"  /* shm_malloc / shm_free                      */
#include "../../locking.h"        /* gen_lock_t — base spinlock primitive         */
#include "../../rw_locking.h"     /* rw_lock_t  — reader-writer lock built on top */
#include "../../mi/mi.h"        /* mi_export_t, mi_response_t, MI helpers     */
#include "../../timer.h"        /* get_uticks(), utime_t — µs since start     */
#include "../../socket_info.h"  /* struct socket_info, PROTO_BIN              */
#include "../../net/api_proto.h" /* protos[] array                            */

#include "../clusterer/clusterer_ctrl.h"  /* set_my_identity, add_node, remove_node */

#include <openssl/evp.h>    /* EVP_aes_256_gcm, EVP_CIPHER_CTX_*, etc.       */
#include <openssl/rand.h>   /* RAND_bytes() — cryptographic nonce generation */

/* =========================================================================
 * Wire-format constants
 * ========================================================================= */

#define CC_PACKET_MAGIC      ((uint16_t)0xCC01)

/* Packet type bytes */
#define CC_PKT_ALIVE            0x01
#define CC_PKT_JOIN_REQ         0x02
#define CC_PKT_MEMBER_LIST      0x03  /* master → joining node: here is the cluster  */
#define CC_PKT_GOODBYE          0x04  /* graceful shutdown notification               */
#define CC_PKT_NODE_ASSIGN      0x05  /* master → multicast: here is your node_id    */

#define CC_MAX_IP_LEN        15   /* "255.255.255.255" without NUL            */
#define CC_IP_ENTRY_SZ       17   /* IP (16 bytes) + is_master flag (1 byte) */
#define CC_LIST_COUNT_SZ      2   /* MEMBER_LIST count field: uint16_t BE     */
#define CC_NODE_ID_SZ         2   /* uint16_t node_id, big-endian             */
#define CC_MAX_BIN_SOCKETS    8   /* max BIN listeners per node               */
#define CC_MAX_BIN_SOCK_LEN  64   /* "bin:255.255.255.255:65535" = 26 chars   */
/* BIN info block: [bin_count 1B][sock1 NUL-term]...[sockN NUL-term]         */
#define CC_BIN_INFO_MAX_SZ   (1 + CC_MAX_BIN_SOCKETS * CC_MAX_BIN_SOCK_LEN)

/* AES-256-GCM encryption constants
 *   wire:      [magic 2B][nonce 12B][ciphertext][GCM tag 16B]
 *   plaintext: [type 1B][timestamp 4B][payload]
 * Total overhead identical to old HMAC scheme (35 bytes).              */
#define CC_NONCE_SZ          12   /* AES-GCM nonce, random per packet         */
#define CC_TAG_SZ            16   /* AES-GCM authentication tag               */
#define CC_TS_SZ              4   /* uint32_t Unix timestamp in plaintext      */
#define CC_TS_WINDOW         30   /* max accepted clock skew in seconds        */
#define CC_WIRE_HDR_SZ       (2 + CC_NONCE_SZ)   /* magic + nonce = 14       */
#define CC_PLAIN_HDR_SZ      (1 + CC_TS_SZ)      /* type + timestamp = 5     */

/* Max packet sizes (all include the GCM nonce + tag overhead):
 *   ALIVE / JOIN_REQ : wire(14) + plain(5) + IP(15+1) + tag(16) = 51 bytes
 *   MEMBER_LIST      : wire(14) + plain(5) + count(2) + 256×17 + tag(16) = 4389 bytes
 *
 * MEMBER_LIST exceeds typical Ethernet MTU (1500 bytes) and will be
 * fragmented by IP on the wire.  This is intentional and fully transparent
 * to the application — the kernel reassembles fragments before delivering
 * the datagram to the UDP socket.  On low-MTU links (e.g. PPP at 128 bytes)
 * the same mechanism applies; IP fragmentation is not disabled anywhere.   */
#define CC_SMALL_PKT_SZ      (CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ + CC_MAX_IP_LEN + 1 + CC_TAG_SZ)
/* JOIN_REQ: [ip NUL][bin_count 1B][sockets...] */
#define CC_JOIN_PKT_MAX_SZ   (CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ + CC_MAX_IP_LEN + 1 \
                              + CC_BIN_INFO_MAX_SZ + CC_TAG_SZ)
/* NODE_ASSIGN: [node_id 2B][ip NUL][bin_count 1B][sockets...] */
#define CC_NODE_ASSIGN_MAX_SZ (CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ + CC_NODE_ID_SZ \
                               + CC_MAX_IP_LEN + 1 + CC_BIN_INFO_MAX_SZ + CC_TAG_SZ)
#define CC_LIST_PKT_MAX_SZ   (CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ + CC_LIST_COUNT_SZ \
                              + CC_MAX_PEERS * CC_IP_ENTRY_SZ + CC_TAG_SZ)
/* Large enough to receive a fully reassembled UDP datagram (max 65507 bytes) */
#define CC_RECV_BUF_SZ       65536

/* =========================================================================
 * Peer-table constants
 * ========================================================================= */

#define CC_MAX_PEERS         256

/*
 * CC_ELECT_FACTOR - election window = query_time × CC_ELECT_FACTOR.
 * QUANTIZED: all nodes evaluate the same cutoff simultaneously.
 *
 * CC_PURGE_FACTOR - memory-cleanup window = query_time × CC_PURGE_FACTOR.
 * Not quantized; only affects when entries are freed, not who is elected.
 */
#define CC_ELECT_FACTOR       3
#define CC_PURGE_FACTOR       6

/* =========================================================================
 * Node-join state machine
 * ========================================================================= */

typedef enum {
    CC_NODE_NEW    = 0,   /* sent JOIN_REQ, awaiting MEMBER_LIST or timeout */
    CC_NODE_ACTIVE = 1    /* fully participating, sends ALIVE               */
} cc_node_state_t;

/* =========================================================================
 * Cluster table
 * ========================================================================= */

#define CC_MAX_CLUSTERS  16  /* max cluster= entries */

/* Forward-declared so cc_cluster_t can embed a pointer */
typedef struct cc_peers_ cc_peers_t;

/**
 * cc_cluster_t - per-cluster runtime state.
 * One instance per "cluster" modparam; one worker process per instance.
 */
typedef struct cc_cluster_ {
    int            cluster_id;
    char           multicast_address[INET_ADDRSTRLEN];
    int            multicast_port;
    char           password[1025];
    unsigned char  key[32];      /* AES-256 key derived from password */
    cc_peers_t    *peers;        /* per-cluster peer table in shm     */
    /* BIN socket resolved at mod_init — advertised in JOIN_REQ/NODE_ASSIGN */
    char           bin_socket[CC_MAX_BIN_SOCK_LEN]; /* "bin:IP:PORT"  */
} cc_cluster_t;

static cc_cluster_t  cc_clusters[CC_MAX_CLUSTERS];
static int           cc_cluster_count = 0;

/* Raw "cluster" strings collected during modparam parsing */
static char *cc_cluster_strs[CC_MAX_CLUSTERS];
static int   cc_cluster_str_count = 0;

/* =========================================================================
 * Module parameters
 * ========================================================================= */

/* Global modparams — apply to all clusters unless overridden per-cluster */
static char *my_ip             = NULL;  /* explicit IP, or NULL for auto-detect */
static char *my_interface      = NULL;  /* explicit interface name, or NULL      */
static int   query_time        = 5;
static char *password          = "3eCrEt*5629"; /* default; falls back per cluster */

/* Resolved at mod_init time — always valid after cc_resolve_local_identity() */
static char my_ip_buf[INET_ADDRSTRLEN];
static char my_interface_buf[IF_NAMESIZE];

/* Local node identity — populated at mod_init by scanning the config file */
static uint16_t my_node_id                              = 0;

/* clusterer integration — loaded at mod_init if clusterer use_controller=1 */
static clusterer_ctrl_binds_t clctl;
static int                    clctl_loaded = 0;
static char     my_bin_sockets[CC_MAX_BIN_SOCKETS][CC_MAX_BIN_SOCK_LEN];
static int      my_bin_count                            = 0;


/**
 * cc_add_cluster_param() - collect "cluster" modparam strings.
 * Actual parsing happens in mod_init() after all params are set.
 */
static int cc_add_cluster_param(modparam_t type, void *val)
{
    if (cc_cluster_str_count >= CC_MAX_CLUSTERS) {
	LM_ERR("clusterer_controller: too many clusters (max %d)\n",
	       CC_MAX_CLUSTERS);
	return -1;
    }
    {
	size_t _len = strlen((char *)val) + 1;
	cc_cluster_strs[cc_cluster_str_count] = pkg_malloc(_len);
	if (!cc_cluster_strs[cc_cluster_str_count]) {
	    LM_ERR("clusterer_controller: pkg_malloc failed\n");
	    return -1;
	}
	memcpy(cc_cluster_strs[cc_cluster_str_count], (char *)val, _len);
    }
    cc_cluster_str_count++;
    return 0;
}

static const param_export_t params[] = {
    {"cluster",    STR_PARAM | USE_FUNC_PARAM, (void *)cc_add_cluster_param},
    {"my_ip",      STR_PARAM, &my_ip},
    {"interface",  STR_PARAM, &my_interface},
    {"query_time", INT_PARAM, &query_time},
    {"password",   STR_PARAM, &password},  /* global default for clusters */
    {0, 0, 0}
};

/* =========================================================================
 * Peer table (shared memory)
 * ========================================================================= */

typedef struct cc_peer_ {
    char         ip[CC_MAX_IP_LEN + 1];
    unsigned int ip_num;
    time_t       last_seen;
    int          is_master;
    int          in_election; /* 1 = currently inside the election window  */
    uint16_t     node_id;     /* allocated by master; 0 = not yet assigned */
    uint8_t      bin_count;   /* number of BIN listeners reported          */
    char         bin_sockets[CC_MAX_BIN_SOCKETS][CC_MAX_BIN_SOCK_LEN];
} cc_peer_t;

struct cc_peers_ {
    cc_peer_t       entries[CC_MAX_PEERS];
    int             count;
    /* rw_lock_t allows concurrent readers (MI, future script functions)
     * while still serialising the single writer (cc_worker).            */
    rw_lock_t      *lock;
    cc_node_state_t node_state;
    time_t          join_deadline;
    /* last elected master IP — used to detect and log master changes */
    char            last_master[CC_MAX_IP_LEN + 1];
};


/* =========================================================================
 * Forward declarations
 * ========================================================================= */

static int  mod_init(void);
static int  cc_child_init(int rank);
static void mod_destroy(void);
static void cc_worker(int rank);
static mi_response_t *mi_cc_members(const mi_params_t *params,
                                     struct mi_handler *hdl);
static void cc_handle_member_list(const char *payload, int payload_len,
                                  const char *sender_ip, cc_cluster_t *cl);
static void cc_handle_join_req(int sock, const char *payload, int payload_len,
                               cc_cluster_t *cl);
static void cc_handle_node_assign(const char *payload, int payload_len,
                                  const char *sender_ip, cc_cluster_t *cl);
static void cc_handle_goodbye(int sock, const char *src_ip, cc_cluster_t *cl);
static mi_response_t *mi_cc_node_info(const mi_params_t *params,
                                      struct mi_handler *hdl);

/* =========================================================================
 * Extra-process export  (layout from mi_fifo.c)
 * ========================================================================= */

static proc_export_t procs[] = {
    {"clusterer_controller worker", 0, 0, cc_worker, 1, PROC_FLAG_INITCHILD},
    {0, 0, 0, 0, 0, 0}
};

/* =========================================================================
 * Module dependency
 * ========================================================================= */

static const dep_export_t deps = {
    {
	/* proto_bin must load before us so its listeners are registered */
	{ MOD_TYPE_DEFAULT, "proto_bin",  DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "clusterer", DEP_ABORT },
	{ MOD_TYPE_NULL, NULL, 0 },
    },
    { { NULL, NULL } },
};

/* =========================================================================
 * MI command export table
 * ========================================================================= */

static const mi_export_t mi_cmds[] = {
    {
	"cc_list_members",
	"List all current cluster members with node_id, status and BIN sockets",
	0, 0,
	{
	    {mi_cc_members, {0}},
	    {EMPTY_MI_RECIPE}
	}
    },
    {
	"cc_node_info",
	"Return full info for a node_id across all clusters",
	0, 0,
	{
	    {mi_cc_node_info, {"node_id", 0}},
	    {EMPTY_MI_RECIPE}
	}
    },
    {EMPTY_MI_EXPORT}
};

/* =========================================================================
 * module_exports
 * ========================================================================= */

struct module_exports exports = {
    "clusterer_controller",
    MOD_TYPE_DEFAULT,
    MODULE_VERSION,
    DEFAULT_DLFLAGS,
    0,
    &deps,
    0,                /* cmds    */
    0,                /* acmds   */
    params,
    0,                /* stats   */
    mi_cmds,
    0,                /* pvs     */
    0,                /* transforms */
    procs,
    0,                /* pre_init_f */
    mod_init,
    0,                /* response_f */
    mod_destroy,
    cc_child_init,    /* child_init_f */
    0                 /* reload_confirm_f */
};

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

static unsigned int ip_to_num(const char *ip)
{
    struct in_addr addr;
    if (inet_aton(ip, &addr) == 0)
	return 0;
    return ntohl(addr.s_addr);
}

/**
 * cc_election_cutoff() - quantized stale cutoff for master election.
 *
 * All NTP-synchronized nodes compute the same value at the same second,
 * so they always evaluate the identical eligible-peer set and elect the
 * same master.
 */
static time_t cc_election_cutoff(void)
{
    time_t now = time(NULL);
    return (now / (time_t)query_time) * (time_t)query_time
           - (time_t)(query_time * CC_ELECT_FACTOR);
}

/**
 * cc_elect_master(cl) - mark the peer with the highest IP as master.
 *
 * Uses the quantized election window so all NTP-synchronized nodes evaluate
 * the same eligible set and elect the same master.
 *
 * Also tracks two state transitions and logs them at INFO:
 *
 *   in_election 1→0  A peer's last_seen fell outside the election window —
 *                    the node is considered down.  Logged immediately so the
 *                    operator sees the event without waiting for cc_prune_stale(cl)
 *                    (which only fires at CC_PURGE_FACTOR × query_time).
 *
 *   last_master      The elected master IP changed — either because the
 *                    previous master went down, or a higher-IP node joined.
 *
 * Must be called with cl->peers->lock held.
 */
static void cc_elect_master(cc_cluster_t *cl)
{
    time_t       cutoff    = cc_election_cutoff();
    unsigned int max_num   = 0;
    int          i, master_idx = -1;

    for (i = 0; i < cl->peers->count; i++) {
	cc_peer_t *e       = &cl->peers->entries[i];
	int        now_in  = (e->last_seen >= cutoff);

	/* Detect peer dropping out of the election window */
	if (e->in_election && !now_in)
	    LM_INFO("clusterer_controller: peer %s went down "
	            "(last seen %lds ago)\n",
	            e->ip, (long)(time(NULL) - e->last_seen));

	e->in_election = now_in;
	e->is_master   = 0;

	if (now_in && e->ip_num > max_num) {
	    max_num    = e->ip_num;
	    master_idx = i;
	}
    }

    if (master_idx >= 0) {
	cl->peers->entries[master_idx].is_master = 1;

	/* Log master changes */
	if (strcmp(cl->peers->last_master,
	           cl->peers->entries[master_idx].ip) != 0) {
	    LM_INFO("clusterer_controller: master changed: %s -> %s\n",
	            cl->peers->last_master[0] ? cl->peers->last_master
	                                     : "(none)",
	            cl->peers->entries[master_idx].ip);
	    memcpy(cl->peers->last_master,
	           cl->peers->entries[master_idx].ip,
	           strnlen(cl->peers->entries[master_idx].ip, CC_MAX_IP_LEN));
	    cl->peers->last_master[
	        strnlen(cl->peers->entries[master_idx].ip, CC_MAX_IP_LEN)] = '\0';

	    if (strcmp(cl->peers->entries[master_idx].ip, my_ip) == 0)
		LM_INFO("clusterer_controller: I am the new master\n");
	}
    } else {
	/* No eligible peer — cluster has no master */
	if (cl->peers->last_master[0] != '\0') {
	    LM_INFO("clusterer_controller: master lost (%s), "
	            "no eligible peers\n", cl->peers->last_master);
	    cl->peers->last_master[0] = '\0';
	}
    }
}

/**
 * cc_i_am_master_locked(cl) - return 1 if my_ip is currently elected master.
 * Must be called with cl->peers->lock held.
 */
static int cc_i_am_master_locked(cc_cluster_t *cl)
{
    time_t cutoff = cc_election_cutoff();
    int    i;

    for (i = 0; i < cl->peers->count; i++) {
	if (cl->peers->entries[i].is_master &&
	    cl->peers->entries[i].last_seen >= cutoff &&
	    strcmp(cl->peers->entries[i].ip, my_ip) == 0)
	    return 1;
    }
    return 0;
}

/**
 * cc_ip_beats_master_locked() - check whether a candidate IP would displace
 *                                the current master in an election.
 *
 * Returns 1 (re-election is worth running) when:
 *   - ip_num is strictly greater than the current master's ip_num, OR
 *   - there is no current master in the election window (no-one to defend).
 *
 * Returns 0 when the current master has a higher or equal IP — it would
 * win the election anyway, so running one is pointless.
 *
 * Must be called with cl->peers->lock held.
 */
static int cc_ip_beats_master_locked(unsigned int ip_num, cc_cluster_t *cl)
{
    time_t cutoff = cc_election_cutoff();
    int    i;

    for (i = 0; i < cl->peers->count; i++) {
	if (cl->peers->entries[i].is_master &&
	    cl->peers->entries[i].last_seen >= cutoff)
	    return (ip_num > cl->peers->entries[i].ip_num);
    }
    return 1;   /* no master in the election window — election is needed */
}

/**
 * cc_prune_stale(cl) - free entries far outside the election window.
 * Memory management only — does not affect election outcomes.
 * Must be called with cl->peers->lock held.
 */
static void cc_prune_stale(cc_cluster_t *cl)
{
    time_t cutoff = time(NULL) - (time_t)(query_time * CC_PURGE_FACTOR);
    int    i;

    for (i = 0; i < cl->peers->count; i++) {
	if (cl->peers->entries[i].last_seen < cutoff) {
	    uint16_t pruned_id = cl->peers->entries[i].node_id;
	    LM_INFO("clusterer_controller: purging timed-out peer %s\n",
	            cl->peers->entries[i].ip);
	    cl->peers->count--;
	    if (i < cl->peers->count)
		cl->peers->entries[i] = cl->peers->entries[cl->peers->count];
	    memset(&cl->peers->entries[cl->peers->count], 0, sizeof(cc_peer_t));
	    i--;
	    /* cl_list_lock and cl->peers->lock are independent — no deadlock */
	    if (clctl_loaded && pruned_id > 0)
		clctl.remove_node(cl->cluster_id, pruned_id);
	}
    }
}

/**
 * cc_apply_master_from_list_locked() - apply master designation from a
 *                                      received MEMBER_LIST/MEMBER_LIST packet.
 *
 * Zeros all is_master flags in the peer table, then sets is_master=1 for
 * the entry matching master_ip.  Updates last_master accordingly.
 * Must be called with cl->peers->lock held.
 */
static void cc_apply_master_from_list_locked(const char *master_ip, cc_cluster_t *cl)
{
    int i;

    for (i = 0; i < cl->peers->count; i++) {
	if (strcmp(cl->peers->entries[i].ip, master_ip) == 0) {
	    cl->peers->entries[i].is_master = 1;
	} else {
	    cl->peers->entries[i].is_master = 0;
	}
    }

    memcpy(cl->peers->last_master, master_ip,
           strnlen(master_ip, CC_MAX_IP_LEN));
    cl->peers->last_master[strnlen(master_ip, CC_MAX_IP_LEN)] = '\0';
}

/**
 * cc_upsert_peer_locked() - insert or refresh a peer entry.
 * Does NOT call cc_elect_master(cl); callers do that explicitly.
 * Must be called with cl->peers->lock held.
 */
static void cc_upsert_peer_locked(const char *src_ip, cc_cluster_t *cl)
{
    int          i;
    unsigned int src_num = ip_to_num(src_ip);
    time_t       now     = time(NULL);

    if (src_num == 0) {
	LM_WARN("clusterer_controller: ignoring invalid IP '%s'\n", src_ip);
	return;
    }

    for (i = 0; i < cl->peers->count; i++) {
	if (strcmp(cl->peers->entries[i].ip, src_ip) == 0) {
	    cl->peers->entries[i].last_seen = now;
	    return;   /* updated */
	}
    }

    /* New entry */
    if (cl->peers->count >= CC_MAX_PEERS) {
	LM_WARN("clusterer_controller: peer table full, ignoring %s\n",
	        src_ip);
	return;
    }
    {
	cc_peer_t *e = &cl->peers->entries[cl->peers->count];
	memcpy(e->ip, src_ip, strnlen(src_ip, CC_MAX_IP_LEN));
	e->ip[strnlen(src_ip, CC_MAX_IP_LEN)] = '\0';
	e->ip_num             = src_num;
	e->last_seen          = now;
	e->is_master          = 0;
	cl->peers->count++;
	LM_INFO("clusterer_controller: new peer %s (total=%d)\n",
	        src_ip, cl->peers->count);
    }
}

/**
 * cc_alloc_node_id_locked() - find the lowest unused node_id >= 1.
 * Must be called with cl->peers->lock held for write.
 */
static uint16_t cc_alloc_node_id_locked(cc_cluster_t *cl)
{
    uint16_t id;
    int      i, used;

    for (id = 1; id < 65535; id++) {
	used = 0;
	for (i = 0; i < cl->peers->count; i++) {
	    if (cl->peers->entries[i].node_id == id) {
		used = 1;
		break;
	    }
	}
	if (!used)
	    return id;
    }
    return 0;   /* table full (shouldn't happen with CC_MAX_PEERS=256) */
}

/**
 * cc_update_peer_bin_locked() - store node_id and BIN sockets for a peer.
 * Must be called with cl->peers->lock held.
 */
static void cc_update_peer_bin_locked(const char *ip, uint16_t node_id,
                                      uint8_t bin_count,
                                      const char (*bin_sockets)[CC_MAX_BIN_SOCK_LEN],
                                      cc_cluster_t *cl)
{
    int i;
    for (i = 0; i < cl->peers->count; i++) {
	if (strcmp(cl->peers->entries[i].ip, ip) == 0) {
	    cl->peers->entries[i].node_id   = node_id;
	    cl->peers->entries[i].bin_count = bin_count;
	    if (bin_count > 0)
		memcpy(cl->peers->entries[i].bin_sockets, bin_sockets,
		       bin_count * CC_MAX_BIN_SOCK_LEN);
	    return;
	}
    }
}

/* =========================================================================
 * AES-256-GCM packet encryption / decryption
 *
 * Every packet is fully encrypted and authenticated with AES-256-GCM.
 * A 12-byte random nonce (generated fresh for each packet with RAND_bytes)
 * ensures that even identical payloads produce different ciphertext, so
 * replaying a captured packet is useless.
 *
 * A 4-byte Unix timestamp is included inside the plaintext.  Receivers
 * reject packets whose timestamp differs from local time by more than
 * CC_TS_WINDOW seconds, closing the replay window entirely.
 *
 * Wire layout:
 *   [magic 2B][nonce 12B][ciphertext][GCM tag 16B]
 * Plaintext:
 *   [type 1B][timestamp 4B][payload]
 * ========================================================================= */

/**
 * cc_derive_key() - derive the 32-byte AES-256 key from the password.
 * SHA-256 of the password gives a fixed-length key regardless of password
 * length.  Must be called once from mod_init() before any send/receive.
 */
static int cc_derive_key(cc_cluster_t *cl)
{
    unsigned int len = sizeof(cl->key);
    if (EVP_Digest(cl->password, strlen(cl->password),
                   cl->key, &len, EVP_sha256(), NULL) != 1) {
	LM_ERR("clusterer_controller: key derivation failed for cluster %d\n",
	       cl->cluster_id);
	return -1;
    }
    return 0;
}

/**
 * cc_encrypt_pkt() - encrypt plaintext in-place and append the GCM tag.
 *
 * On entry:  buf[0..1]           = magic (untouched)
 *            buf[2..13]          = nonce slot (filled with random bytes)
 *            buf[plain_off..]    = plaintext to encrypt
 * On return: buf[2..13]          = random nonce
 *            buf[plain_off..]    = ciphertext (same length)
 *            buf[plain_off+plain_len..+CC_TAG_SZ-1] = GCM tag
 *
 * @return total packet length, or -1 on error
 */
static int cc_encrypt_pkt(char *buf, int plain_off, int plain_len,
                          const unsigned char *key)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char   nonce[CC_NONCE_SZ];
    int             out_len = 0, final_len = 0;

    if (RAND_bytes(nonce, CC_NONCE_SZ) != 1) {
	LM_ERR("clusterer_controller: RAND_bytes failed\n");
	return -1;
    }
    memcpy(buf + 2, nonce, CC_NONCE_SZ);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { LM_ERR("clusterer_controller: EVP_CIPHER_CTX_new\n"); return -1; }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) {
	LM_ERR("clusterer_controller: EVP_EncryptInit_ex failed\n");
	EVP_CIPHER_CTX_free(ctx); return -1;
    }
    if (EVP_EncryptUpdate(ctx,
                          (unsigned char *)buf + plain_off, &out_len,
                          (unsigned char *)buf + plain_off, plain_len) != 1) {
	LM_ERR("clusterer_controller: EVP_EncryptUpdate failed\n");
	EVP_CIPHER_CTX_free(ctx); return -1;
    }
    if (EVP_EncryptFinal_ex(ctx,
                            (unsigned char *)buf + plain_off + out_len,
                            &final_len) != 1) {
	LM_ERR("clusterer_controller: EVP_EncryptFinal_ex failed\n");
	EVP_CIPHER_CTX_free(ctx); return -1;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, CC_TAG_SZ,
                             (unsigned char *)buf + plain_off + out_len + final_len)
            != 1) {
	LM_ERR("clusterer_controller: GCM GET_TAG failed\n");
	EVP_CIPHER_CTX_free(ctx); return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return plain_off + out_len + final_len + CC_TAG_SZ;
}

/**
 * cc_decrypt_pkt() - authenticate and decrypt a received packet in-place.
 *
 * On entry:  buf = [magic 2B][nonce 12B][ciphertext][GCM tag 16B], n = total
 * On return: buf[CC_WIRE_HDR_SZ..] = plaintext (type + timestamp + payload)
 *
 * @return 0 on success, -1 to drop (wrong key, tampered, or too short)
 */
static int cc_decrypt_pkt(char *buf, ssize_t n, const char *sender_ip,
                          const unsigned char *key)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char  *nonce      = (unsigned char *)buf + 2;
    ssize_t         cipher_len = n - CC_WIRE_HDR_SZ - CC_TAG_SZ;
    unsigned char  *tag        = (unsigned char *)buf + n - CC_TAG_SZ;
    int             out_len = 0, final_len = 0, ret;

    if (cipher_len <= 0) {
	LM_INFO("clusterer_controller: packet from %s too short to decrypt "
	        "(%zd bytes)\n", sender_ip, n);
	return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { LM_ERR("clusterer_controller: EVP_CIPHER_CTX_new\n"); return -1; }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) {
	LM_ERR("clusterer_controller: EVP_DecryptInit_ex failed\n");
	EVP_CIPHER_CTX_free(ctx); return -1;
    }
    if (EVP_DecryptUpdate(ctx,
                          (unsigned char *)buf + CC_WIRE_HDR_SZ, &out_len,
                          (unsigned char *)buf + CC_WIRE_HDR_SZ,
                          (int)cipher_len) != 1) {
	LM_ERR("clusterer_controller: EVP_DecryptUpdate failed\n");
	EVP_CIPHER_CTX_free(ctx); return -1;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, CC_TAG_SZ, tag) != 1) {
	LM_ERR("clusterer_controller: GCM SET_TAG failed\n");
	EVP_CIPHER_CTX_free(ctx); return -1;
    }
    ret = EVP_DecryptFinal_ex(ctx,
              (unsigned char *)buf + CC_WIRE_HDR_SZ + out_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
	LM_WARN("clusterer_controller: decryption failed from %s - "
	        "wrong password or tampered packet\n", sender_ip);
	return -1;
    }
    return 0;
}

/**
 * cc_check_timestamp() - reject packets outside the acceptance window.
 * The timestamp is plaintext[1..4] (after type byte), network byte order.
 * @return 0 if within CC_TS_WINDOW seconds, -1 to drop
 */
static int cc_check_timestamp(const char *plaintext, const char *sender_ip)
{
    uint32_t pkt_ts;
    time_t   delta;

    memcpy(&pkt_ts, plaintext + 1, CC_TS_SZ);   /* skip type byte */
    pkt_ts = ntohl(pkt_ts);
    delta  = (time_t)pkt_ts - time(NULL);
    if (delta < 0) delta = -delta;

    if (delta > CC_TS_WINDOW) {
	LM_WARN("clusterer_controller: packet from %s rejected - "
	        "timestamp skew %lds > window %ds (replay or clock drift)\n",
	        sender_ip, (long)delta, CC_TS_WINDOW);
	return -1;
    }
    return 0;
}

/* =========================================================================
 * Socket setup
 * ========================================================================= */

static int cc_setup_socket(cc_cluster_t *cl)
{
    int                sock;
    int                yes = 1;
    unsigned char      loop = 1, ttl = 32;
    struct sockaddr_in local;
    struct ip_mreq     mreq;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
	LM_ERR("clusterer_controller: socket(): %s\n", strerror(errno));
	return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
	LM_ERR("clusterer_controller: SO_REUSEADDR: %s\n", strerror(errno));
	close(sock);
	return -1;
    }

    /* Expand the kernel receive buffer so it can hold a fully reassembled
     * MEMBER_LIST datagram (up to ~4 KB with 256 peers) even when IP
     * fragmentation is in play on a low-MTU link such as PPP at 128 bytes. */
    {
	int rcvbuf = 1 << 20;   /* request 1 MB; kernel may cap lower */
	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
	               &rcvbuf, sizeof(rcvbuf)) < 0)
	    LM_WARN("clusterer_controller: SO_RCVBUF: %s\n", strerror(errno));
    }

    memset(&local, 0, sizeof(local));
    local.sin_family      = AF_INET;
    local.sin_port        = htons((uint16_t)cl->multicast_port);
    local.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
	LM_ERR("clusterer_controller: bind() port %d: %s\n",
	       cl->multicast_port, strerror(errno));
	close(sock);
	return -1;
    }

    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = inet_addr(cl->multicast_address);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   &mreq, sizeof(mreq)) < 0) {
	LM_ERR("clusterer_controller: IP_ADD_MEMBERSHIP (%s): %s\n",
	       cl->multicast_address, strerror(errno));
	close(sock);
	return -1;
    }

    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP,
                   &loop, sizeof(loop)) < 0)
	LM_WARN("clusterer_controller: IP_MULTICAST_LOOP: %s\n",
	        strerror(errno));

    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL,
                   &ttl, sizeof(ttl)) < 0)
	LM_WARN("clusterer_controller: IP_MULTICAST_TTL: %s\n",
	        strerror(errno));

    /* Pin the sending interface to my_ip so that loopback packets carry
     * my_ip as source address — this makes self-loopback detection in
     * cc_handle_member_list() reliable on multi-homed hosts.           */
    {
	struct in_addr local_if;
	local_if.s_addr = inet_addr(my_ip);
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF,
	               &local_if, sizeof(local_if)) < 0)
	    LM_WARN("clusterer_controller: [cluster %d] IP_MULTICAST_IF: %s\n",
	        cl->cluster_id,
	            strerror(errno));
    }

    /* Bind socket to the resolved interface by name for stricter routing.
     * This is more reliable than IP_MULTICAST_IF alone on multi-homed hosts
     * because it works at the socket level regardless of routing tables.   */
    if (my_interface_buf[0] != '\0') {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, my_interface_buf,
	       strnlen(my_interface_buf, IF_NAMESIZE - 1));
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
	               &ifr, sizeof(ifr)) < 0)
	    /* Requires CAP_NET_RAW — not available after privilege drop.
	     * IP_MULTICAST_IF (set above) already pins the interface by
	     * IP, so this is belt-and-suspenders only; failure is safe.  */
	    LM_DBG("clusterer_controller: SO_BINDTODEVICE (%s): %s "
	           "(non-fatal, IP_MULTICAST_IF covers this)\n",
	           my_interface_buf, strerror(errno));
    }

    LM_INFO("clusterer_controller: [cluster %d] socket ready, joined %s:%d\n",
            cl->cluster_id, cl->multicast_address, cl->multicast_port);

    /* Set non-blocking so sendto() never hangs the worker if the kernel
     * UDP send buffer fills up.  recvfrom() already relies on select()
     * for readiness, so O_NONBLOCK is safe and consistent for both.    */
    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK) < 0) {
	LM_WARN("clusterer_controller: fcntl O_NONBLOCK: %s\n",
	        strerror(errno));
	/* non-fatal — we continue; send paths handle EAGAIN explicitly */
    }

    return sock;
}

/* =========================================================================
 * Packet senders
 * ========================================================================= */

/**
 * cc_send_pkt_with_ip() - build and multicast a small (ALIVE/GOODBYE) packet.
 * JOIN_REQ is handled by cc_send_join_req_pkt() which carries BIN socket info.
 *
 *   wire: [magic 2B][nonce 12B][AES-256-GCM([type 1B][ts 4B][ip NUL])][tag 16B]
 */
static void cc_send_pkt_with_ip(int sock, unsigned char type, cc_cluster_t *cl)
{
    char               pkt[CC_SMALL_PKT_SZ];
    uint16_t           magic   = htons(CC_PACKET_MAGIC);
    uint32_t           ts      = htonl((uint32_t)time(NULL));
    int                ip_len  = (int)strlen(my_ip);
    int                plain_len, total_len;
    struct sockaddr_in dest;

    if (ip_len > CC_MAX_IP_LEN)
	ip_len = CC_MAX_IP_LEN;

    /* Wire header: magic at [0..1]; nonce written by cc_encrypt_pkt at [2..13] */
    memcpy(pkt, &magic, 2);

    /* Plaintext at [CC_WIRE_HDR_SZ..]: [type][timestamp][IP NUL] */
    pkt[CC_WIRE_HDR_SZ] = (char)type;
    memcpy(pkt + CC_WIRE_HDR_SZ + 1, &ts, CC_TS_SZ);
    memcpy(pkt + CC_WIRE_HDR_SZ + 1 + CC_TS_SZ, my_ip, ip_len);
    pkt[CC_WIRE_HDR_SZ + 1 + CC_TS_SZ + ip_len] = '\0';
    plain_len = 1 + CC_TS_SZ + ip_len + 1;

    total_len = cc_encrypt_pkt(pkt, CC_WIRE_HDR_SZ, plain_len, cl->key);
    if (total_len < 0)
	return;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons((uint16_t)cl->multicast_port);
    dest.sin_addr.s_addr = inet_addr(cl->multicast_address);

    if (sendto(sock, pkt, total_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
	if (errno == EAGAIN || errno == EWOULDBLOCK)
	    LM_DBG("clusterer_controller: [cluster %d] sendto (type=0x%02x) would block\n",
	           cl->cluster_id, type);
	else
	    LM_ERR("clusterer_controller: [cluster %d] sendto (type=0x%02x): %s\n",
	           cl->cluster_id, type, strerror(errno));
    } else {
	LM_DBG("clusterer_controller: [cluster %d] sent 0x%02x\n", cl->cluster_id, type);
    }
}

#define cc_send_alive(sock, cl)    cc_send_pkt_with_ip((sock), CC_PKT_ALIVE, (cl))
#define cc_send_join_req(sock, cl) cc_send_join_req_pkt((sock), (cl))

/**
 * cc_send_list_pkt() - encrypt and multicast the active peer table.
 *
 * Wire: [magic 2B][nonce 12B][AES-256-GCM([type 1B][ts 4B][count 2B][entries...])][tag 16B]
 */
static void cc_send_list_pkt(int sock, unsigned char type, cc_cluster_t *cl)
{
    char               pkt[CC_LIST_PKT_MAX_SZ];
    uint16_t           magic    = htons(CC_PACKET_MAGIC);
    uint32_t           ts       = htonl((uint32_t)time(NULL));
    uint16_t           count    = 0;
    uint16_t           count_be;
    char              *p;
    time_t             cutoff;
    struct sockaddr_in dest;
    int                i, plain_len, total_len;

    memcpy(pkt, &magic, 2);
    /* nonce at [2..13] written by cc_encrypt_pkt */

    /* Plaintext: [type][timestamp][count BE][entries...] */
    pkt[CC_WIRE_HDR_SZ] = (char)type;
    memcpy(pkt + CC_WIRE_HDR_SZ + 1, &ts, CC_TS_SZ);
    /* count filled after iteration */
    p = pkt + CC_WIRE_HDR_SZ + 1 + CC_TS_SZ + CC_LIST_COUNT_SZ;

    cutoff = time(NULL) - (time_t)(query_time * CC_ELECT_FACTOR);

    lock_start_read(cl->peers->lock);

    for (i = 0; i < cl->peers->count && count < CC_MAX_PEERS; i++) {
	cc_peer_t *e = &cl->peers->entries[i];
	if (e->last_seen < cutoff)
	    continue;
	memset(p, 0, CC_IP_ENTRY_SZ);
	memcpy(p, e->ip, strnlen(e->ip, CC_MAX_IP_LEN));
	p[strnlen(e->ip, CC_MAX_IP_LEN)] = '\0';
	p[CC_IP_ENTRY_SZ - 1] = (char)(e->is_master ? 1 : 0);
	p += CC_IP_ENTRY_SZ;
	count++;
    }

    lock_stop_read(cl->peers->lock);

    count_be = htons(count);
    memcpy(pkt + CC_WIRE_HDR_SZ + 1 + CC_TS_SZ, &count_be, CC_LIST_COUNT_SZ);

    plain_len = 1 + CC_TS_SZ + CC_LIST_COUNT_SZ + count * CC_IP_ENTRY_SZ;
    total_len = cc_encrypt_pkt(pkt, CC_WIRE_HDR_SZ, plain_len, cl->key);
    if (total_len < 0)
	return;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons((uint16_t)cl->multicast_port);
    dest.sin_addr.s_addr = inet_addr(cl->multicast_address);

    if (sendto(sock, pkt, total_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0)
	LM_ERR("clusterer_controller: [cluster %d] sendto MEMBER_LIST: %s\n",
	       cl->cluster_id, strerror(errno));
    else
	LM_INFO("clusterer_controller: [cluster %d] sent MEMBER_LIST (%d members)\n",
	        cl->cluster_id, count);
}

#define cc_send_member_list(sock, cl) cc_send_list_pkt((sock), CC_PKT_MEMBER_LIST, (cl))

/**
 * cc_send_join_req_pkt() - send CC_PKT_JOIN_REQ with BIN socket info.
 *
 * Payload: [ip NUL][bin_count 1B][sock1 NUL]...[sockN NUL]
 */
static void cc_send_join_req_pkt(int sock, cc_cluster_t *cl)
{
    char               pkt[CC_JOIN_PKT_MAX_SZ];
    uint16_t           magic   = htons(CC_PACKET_MAGIC);
    uint32_t           ts      = htonl((uint32_t)time(NULL));
    int                ip_len  = (int)strlen(my_ip);
    char              *p;
    int                plain_len, total_len;
    struct sockaddr_in dest;

    if (ip_len > CC_MAX_IP_LEN)
	ip_len = CC_MAX_IP_LEN;

    memcpy(pkt, &magic, 2);

    /* Plaintext: [type][ts][ip NUL][bin_count][sock1 NUL]...[sockN NUL] */
    pkt[CC_WIRE_HDR_SZ] = (char)CC_PKT_JOIN_REQ;
    memcpy(pkt + CC_WIRE_HDR_SZ + 1, &ts, CC_TS_SZ);
    p = pkt + CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ;

    memcpy(p, my_ip, ip_len);
    p[ip_len] = '\0';
    p += ip_len + 1;

    /* Advertise only the BIN socket resolved for this specific cluster */
    {
	int slen = (int)strnlen(cl->bin_socket, CC_MAX_BIN_SOCK_LEN - 1);
	*p++ = 1;   /* bin_count */
	memcpy(p, cl->bin_socket, slen);
	p[slen] = '\0';
	p += slen + 1;
    }

    plain_len = (int)(p - (pkt + CC_WIRE_HDR_SZ));
    total_len = cc_encrypt_pkt(pkt, CC_WIRE_HDR_SZ, plain_len, cl->key);
    if (total_len < 0)
	return;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons((uint16_t)cl->multicast_port);
    dest.sin_addr.s_addr = inet_addr(cl->multicast_address);

    if (sendto(sock, pkt, total_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0)
	LM_ERR("clusterer_controller: [cluster %d] sendto JOIN_REQ: %s\n",
	       cl->cluster_id, strerror(errno));
    else
	LM_DBG("clusterer_controller: [cluster %d] sent JOIN_REQ bin=%s\n",
	       cl->cluster_id, cl->bin_socket);
}

/**
 * cc_send_node_assign() - send CC_PKT_NODE_ASSIGN to multicast.
 *
 * Payload: [node_id 2B BE][ip NUL][bin_count 1B][sock1 NUL]...[sockN NUL]
 *
 * Sent by master after allocating a node_id.  All cluster members receive
 * it and update their peer tables accordingly.
 */
static void cc_send_node_assign(int sock, const char *ip, uint16_t node_id,
                                uint8_t bin_count,
                                const char (*bin_sockets)[CC_MAX_BIN_SOCK_LEN],
                                cc_cluster_t *cl)
{
    char               pkt[CC_NODE_ASSIGN_MAX_SZ];
    uint16_t           magic    = htons(CC_PACKET_MAGIC);
    uint32_t           ts       = htonl((uint32_t)time(NULL));
    uint16_t           nid_be   = htons(node_id);
    int                ip_len   = (int)strnlen(ip, CC_MAX_IP_LEN);
    char              *p;
    int                i, plain_len, total_len;
    struct sockaddr_in dest;

    memcpy(pkt, &magic, 2);

    pkt[CC_WIRE_HDR_SZ] = (char)CC_PKT_NODE_ASSIGN;
    memcpy(pkt + CC_WIRE_HDR_SZ + 1, &ts, CC_TS_SZ);
    p = pkt + CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ;

    /* node_id (2B BE) */
    memcpy(p, &nid_be, CC_NODE_ID_SZ);
    p += CC_NODE_ID_SZ;

    /* IP NUL */
    memcpy(p, ip, ip_len);
    p[ip_len] = '\0';
    p += ip_len + 1;

    /* BIN sockets */
    *p++ = (char)bin_count;
    for (i = 0; i < bin_count; i++) {
	int slen = (int)strnlen(bin_sockets[i], CC_MAX_BIN_SOCK_LEN - 1);
	memcpy(p, bin_sockets[i], slen);
	p[slen] = '\0';
	p += slen + 1;
    }

    plain_len = (int)(p - (pkt + CC_WIRE_HDR_SZ));
    total_len = cc_encrypt_pkt(pkt, CC_WIRE_HDR_SZ, plain_len, cl->key);
    if (total_len < 0)
	return;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons((uint16_t)cl->multicast_port);
    dest.sin_addr.s_addr = inet_addr(cl->multicast_address);

    if (sendto(sock, pkt, total_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0)
	LM_ERR("clusterer_controller: [cluster %d] sendto NODE_ASSIGN: %s\n",
	       cl->cluster_id, strerror(errno));
    else
	LM_INFO("clusterer_controller: [cluster %d] NODE_ASSIGN node_id=%u ip=%s\n",
	        cl->cluster_id, node_id, ip);
}


/* =========================================================================
 * Packet handlers
 * ========================================================================= */

/**
 * cc_handle_alive() - process a CC_PKT_ALIVE packet.
 *
 * Regular heartbeat path: upsert the sender, re-elect.
 * Only called in CC_NODE_ACTIVE state; ignored while joining (cc_recv_one
 * still dispatches them so the peer table builds up before the timeout).
 */
static void cc_handle_alive(const char *src_ip, cc_cluster_t *cl)
{
    lock_start_write(cl->peers->lock);
    cc_upsert_peer_locked(src_ip, cl);
    cc_elect_master(cl);
    lock_stop_write(cl->peers->lock);
}

/**
 * cc_handle_join_req() - process a CC_PKT_JOIN_REQ packet.
 *
 * Payload: [ip NUL][bin_count 1B][sock1 NUL]...[sockN NUL]
 *
 * Non-masters ignore JOIN_REQ — the master handles discovery exclusively.
 *
 * Master behaviour:
 *   1. Parse joining node's IP and BIN sockets from payload.
 *   2. Upsert peer; store BIN info and allocate a node_id.
 *   3. Send NODE_ASSIGN (joining node + all existing peers) so every
 *      node in the cluster learns the full updated picture.
 *   4. If joining IP > own IP: run election, send MEMBER_LIST.
 *   5. If joining IP <= own IP: send MEMBER_LIST (self still master).
 */
static void cc_handle_join_req(int sock, const char *payload, int payload_len,
                               cc_cluster_t *cl)
{
    const char *p         = payload;
    const char *end       = payload + payload_len;
    char        src_ip[CC_MAX_IP_LEN + 1];
    char        bin_socks[CC_MAX_BIN_SOCKETS][CC_MAX_BIN_SOCK_LEN];
    uint8_t     bin_cnt   = 0;
    int         ip_len, was_master, still_master, i;
    uint16_t    new_id;

    /* --- Parse IP --- */
    ip_len = (int)strnlen(p, CC_MAX_IP_LEN);
    if (p + ip_len >= end) {
	LM_WARN("clusterer_controller: JOIN_REQ payload truncated\n");
	return;
    }
    memcpy(src_ip, p, ip_len);
    src_ip[ip_len] = '\0';
    p += ip_len + 1;

    /* Ignore our own JOIN_REQ via loopback */
    if (strcmp(src_ip, my_ip) == 0)
	return;

    /* --- Parse BIN sockets --- */
    memset(bin_socks, 0, sizeof(bin_socks));
    if (p < end) {
	bin_cnt = (uint8_t)*p++;
	if (bin_cnt > CC_MAX_BIN_SOCKETS)
	    bin_cnt = CC_MAX_BIN_SOCKETS;
	for (i = 0; i < (int)bin_cnt && p < end; i++) {
	    int slen = (int)strnlen(p, CC_MAX_BIN_SOCK_LEN - 1);
	    memcpy(bin_socks[i], p, slen);
	    bin_socks[i][slen] = '\0';
	    p += slen + 1;
	}
    }

    LM_INFO("clusterer_controller: [cluster %d] JOIN_REQ from %s "
            "(%d BIN socket(s))\n", cl->cluster_id, src_ip, bin_cnt);

    lock_start_write(cl->peers->lock);

    was_master = (cl->peers->node_state == CC_NODE_ACTIVE) &&
                 cc_i_am_master_locked(cl);

    if (!was_master) {
	lock_stop_write(cl->peers->lock);
	LM_DBG("clusterer_controller: non-master ignoring JOIN_REQ from %s\n",
	       src_ip);
	return;
    }

    /* Upsert peer and store BIN info + node_id.
     * If this IP already has a node_id (rejoining after crash/restart),
     * reuse it so the id stays stable and clusterer stays in sync.     */
    cc_upsert_peer_locked(src_ip, cl);
    {
	int _i;
	new_id = 0;
	for (_i = 0; _i < cl->peers->count; _i++) {
	    if (strcmp(cl->peers->entries[_i].ip, src_ip) == 0) {
		new_id = cl->peers->entries[_i].node_id;
		break;
	    }
	}
	if (new_id == 0)
	    new_id = cc_alloc_node_id_locked(cl);
    }
    cc_update_peer_bin_locked(src_ip, new_id,
                               bin_cnt,
                               (const char (*)[CC_MAX_BIN_SOCK_LEN])bin_socks,
                               cl);

    /* Send NODE_ASSIGN for joining node */
    cc_send_node_assign(sock, src_ip, new_id, bin_cnt,
                        (const char (*)[CC_MAX_BIN_SOCK_LEN])bin_socks, cl);

    /* Send NODE_ASSIGN for each existing peer so joining node learns
     * all current node_ids and BIN sockets                           */
    for (i = 0; i < cl->peers->count; i++) {
	cc_peer_t *e = &cl->peers->entries[i];
	if (strcmp(e->ip, src_ip) == 0 || e->node_id == 0)
	    continue;
	cc_send_node_assign(sock, e->ip, e->node_id, e->bin_count,
	                    (const char (*)[CC_MAX_BIN_SOCK_LEN])e->bin_sockets,
	                    cl);
    }

    if (cc_ip_beats_master_locked(ip_to_num(src_ip), cl)) {
	cc_elect_master(cl);
	still_master = cc_i_am_master_locked(cl);
	lock_stop_write(cl->peers->lock);
	if (!still_master) {
	    LM_INFO("clusterer_controller: %s has higher IP, "
	            "handing over mastership\n", src_ip);
	    cc_send_member_list(sock, cl);
	} else {
	    cc_send_member_list(sock, cl);
	}
    } else {
	lock_stop_write(cl->peers->lock);
	LM_INFO("clusterer_controller: [cluster %d] I am master, "
	        "new node %s assigned node_id=%u\n",
	        cl->cluster_id, src_ip, new_id);
	cc_send_member_list(sock, cl);
    }
}

/**
 * cc_handle_member_list() - process a CC_PKT_MEMBER_LIST from the master.
 *
 * This is THE authoritative packet for cluster state.  All nodes — both
 * the joining node and existing active members — update their peer tables
 * and master designation directly from this list.  No independent election
 * is run; the master's word is final.
 *
 * Joining node (CC_NODE_NEW):
 *   - Replaces its empty peer table with the master's list.
 *   - Transitions to CC_NODE_ACTIVE.
 *   - If the list designates us as master (our IP has is_master=1): we
 *     accept mastership immediately and log accordingly.
 *
 * Active member / old master (CC_NODE_ACTIVE):
 *   - Upserts any new peers from the list.
 *   - Applies master designation from the list (may demote old master).
 *   - Logs who is now master.
 */
static void cc_handle_member_list(const char *payload, int payload_len,
                                  const char *sender_ip, cc_cluster_t *cl)
{
    uint16_t      count;
    int           i;
    const char   *p;
    char          designated_master[CC_MAX_IP_LEN + 1];

    /* The master is the only sender of MEMBER_LIST.  If we receive one
     * from our own IP (multicast loopback), we are the master and already
     * hold the authoritative data — no need to process it again.        */
    if (strcmp(sender_ip, my_ip) == 0) {
	LM_DBG("clusterer_controller: ignoring own MEMBER_LIST loopback\n");
	return;
    }

    designated_master[0] = '\0';

    if (payload_len < CC_LIST_COUNT_SZ) {
	LM_WARN("clusterer_controller: MEMBER_LIST too short\n");
	return;
    }

    {
	uint16_t count_be;
	memcpy(&count_be, payload, CC_LIST_COUNT_SZ);
	count = ntohs(count_be);
    }

    if (count > CC_MAX_PEERS) {
	LM_WARN("clusterer_controller: MEMBER_LIST count %u exceeds "
	        "max peers %d, dropping\n", count, CC_MAX_PEERS);
	return;
    }

    if (payload_len < CC_LIST_COUNT_SZ + (int)count * CC_IP_ENTRY_SZ) {
	LM_WARN("clusterer_controller: MEMBER_LIST truncated "
	        "(count=%u, got %d bytes)\n", count, payload_len);
	return;
    }

    p = payload + CC_LIST_COUNT_SZ;

    /* First pass: collect designated master IP */
    for (i = 0; i < (int)count; i++) {
	const char   *entry     = p + i * CC_IP_ENTRY_SZ;
	unsigned char is_master = (unsigned char)entry[CC_IP_ENTRY_SZ - 1];
	if (is_master) {
	    memcpy(designated_master, entry, CC_MAX_IP_LEN);
	    designated_master[CC_MAX_IP_LEN] = '\0';
	    break;
	}
    }

    lock_start_write(cl->peers->lock);

    /* Second pass: upsert all peers */
    for (i = 0; i < (int)count; i++, p += CC_IP_ENTRY_SZ) {
	char ip_buf[CC_MAX_IP_LEN + 1];
	memcpy(ip_buf, p, CC_MAX_IP_LEN);
	ip_buf[CC_MAX_IP_LEN] = '\0';
	if (ip_buf[0] == '\0')
	    continue;
	cc_upsert_peer_locked(ip_buf, cl);
    }

    /* Apply the master designation from the list — no local election */
    if (designated_master[0] != '\0')
	cc_apply_master_from_list_locked(designated_master, cl);

    if (cl->peers->node_state == CC_NODE_NEW) {
	cl->peers->node_state = CC_NODE_ACTIVE;
	if (designated_master[0] != '\0'
	        && strcmp(designated_master, my_ip) == 0) {
	    lock_stop_write(cl->peers->lock);
	    LM_INFO("clusterer_controller: received MEMBER_LIST (%u members) "
	            "from existing master %s - taking over mastership "
	            "(my IP %s is higher)\n",
	            count, sender_ip, my_ip);
	} else {
	    lock_stop_write(cl->peers->lock);
	    LM_INFO("clusterer_controller: received MEMBER_LIST (%u members) "
	            "from %s - joined cluster as member, master is %s\n",
	            count, sender_ip,
	            designated_master[0] ? designated_master : "(none)");
	}
    } else {
	/* Active node — log the master update (may be self-demotion) */
	int i_am_master = (designated_master[0] != '\0' &&
	                   strcmp(designated_master, my_ip) == 0);
	lock_stop_write(cl->peers->lock);
	if (i_am_master) {
	    LM_INFO("clusterer_controller: MEMBER_LIST received - "
	            "I am master (%d members)\n", count);
	} else {
	    LM_INFO("clusterer_controller: MEMBER_LIST received  - "
	            "master is %s, my role is member (%d members)\n",
	            designated_master[0] ? designated_master : "(none)",
	            count);
	}
    }
}

/**
 * cc_handle_goodbye() - process a CC_PKT_GOODBYE packet.
 *
 * Remove the departing node from the peer table immediately.
 *
 * Re-election is triggered ONLY when:
 *   1. Only one node remains — we are alone and must assume mastership.
 *   2. Our IP is higher than the current master's IP, or the master entry
 *      no longer exists because the departing node was the master.
 *      cc_ip_beats_master_locked() covers both cases: it returns 1 when
 *      no is_master entry is present (departed master) or when our IP
 *      numerically exceeds the current master's.
 *
 * All other departures (a member leaves while a higher-IP master is alive)
 * require no immediate action — the next periodic ALIVE cycle runs
 * cc_elect_master(cl) within query_time seconds and self-corrects if needed.
 */
static void cc_handle_goodbye(int sock, const char *src_ip, cc_cluster_t *cl)
{
    int      i, i_am_master, master_unchanged, remaining;
    char     prev_master[CC_MAX_IP_LEN + 1];
    uint16_t departed_node_id = 0;

    LM_INFO("clusterer_controller: GOODBYE from %s\n", src_ip);

    lock_start_write(cl->peers->lock);

    for (i = 0; i < cl->peers->count; i++) {
	if (strcmp(cl->peers->entries[i].ip, src_ip) == 0) {
	    departed_node_id = cl->peers->entries[i].node_id;
	    cl->peers->count--;
	    if (i < cl->peers->count)
		cl->peers->entries[i] = cl->peers->entries[cl->peers->count];
	    memset(&cl->peers->entries[cl->peers->count], 0, sizeof(cc_peer_t));
	    break;
	}
    }

    remaining = cl->peers->count;

    /* --- Decide whether re-election is warranted --- */
    if (remaining <= 1) {
	/* We are the only node left — no election needed, promote directly. */
	int was_master = cc_i_am_master_locked(cl);
	cc_apply_master_from_list_locked(my_ip, cl);
	lock_stop_write(cl->peers->lock);
	if (was_master) {
	    LM_INFO("clusterer_controller: %s departed - I am the only "
	            "node remaining, I remain master\n", src_ip);
	} else {
	    LM_INFO("clusterer_controller: %s departed - I am the only "
	            "node remaining, promoted myself to master\n", src_ip);
	}
	if (clctl_loaded && departed_node_id > 0)
	    clctl.remove_node(cl->cluster_id, departed_node_id);
	return;
    }

    if (cc_ip_beats_master_locked(ip_to_num(my_ip), cl)) {
	/* Two sub-cases both return 1 from cc_ip_beats_master_locked:
	 *   a) departing node was the master (no master entry remains)
	 *   b) our IP is genuinely higher than the current master (anomaly) */
	if (strcmp(src_ip, cl->peers->last_master) == 0) {
	    LM_INFO("clusterer_controller: %s departed - it was the master, "
	            "triggering re-election\n", src_ip);
	} else {
	    LM_INFO("clusterer_controller: %s departed - our IP %s is higher "
	            "than current master %s, triggering re-election\n",
	            src_ip, my_ip,
	            cl->peers->last_master[0] ? cl->peers->last_master : "(none)");
	}
    } else {
	lock_stop_write(cl->peers->lock);
	LM_INFO("clusterer_controller: %s departed - master %s still "
	        "active, no re-election needed (%d node(s) remaining)\n",
	        src_ip,
	        cl->peers->last_master[0] ? cl->peers->last_master : "(none)",
	        remaining);
	if (clctl_loaded && departed_node_id > 0)
	    clctl.remove_node(cl->cluster_id, departed_node_id);
	return;
    }

    memcpy(prev_master, cl->peers->last_master,
           strnlen(cl->peers->last_master, CC_MAX_IP_LEN));
    prev_master[strnlen(cl->peers->last_master, CC_MAX_IP_LEN)] = '\0';

    cc_elect_master(cl);

    master_unchanged = (strcmp(prev_master, cl->peers->last_master) == 0);
    i_am_master      = cc_i_am_master_locked(cl);

    lock_stop_write(cl->peers->lock);

    if (i_am_master) {
	if (master_unchanged) {
	    LM_INFO("clusterer_controller: re-election complete - "
	            "I remain master (%d node(s) in cluster)\n", remaining);
	} else {
	    /* Send MEMBER_LIST so all nodes immediately learn the new master
	     * rather than waiting for the next periodic ALIVE cycle.        */
	    LM_INFO("clusterer_controller: re-election complete - "
	            "I reclaimed mastership after %s departed "
	            "(%d node(s) remaining) - sending MEMBER_LIST\n",
	            src_ip, remaining);
	    cc_send_member_list(sock, cl);
	}
    } else {
	LM_INFO("clusterer_controller: re-election complete - "
	        "master is %s, my role is member (%d node(s) remaining)\n",
	        cl->peers->last_master[0] ? cl->peers->last_master : "(none)",
	        remaining);
    }
    if (clctl_loaded && departed_node_id > 0)
	clctl.remove_node(cl->cluster_id, departed_node_id);
}

/**
 * cc_handle_node_assign() - process a CC_PKT_NODE_ASSIGN from the master.
 *
 * Payload: [node_id 2B BE][ip NUL][bin_count 1B][sock1 NUL]...[sockN NUL]
 *
 * All nodes (including master via loopback) apply the assignment:
 *   - Upsert the peer entry if not already present.
 *   - Store node_id and BIN sockets.
 *   - If ip == my_ip: record my_node_id.
 */
static void cc_handle_node_assign(const char *payload, int payload_len,
                                  const char *sender_ip, cc_cluster_t *cl)
{
    const char *p   = payload;
    const char *end = payload + payload_len;
    uint16_t    node_id;
    char        ip[CC_MAX_IP_LEN + 1];
    char        bin_socks[CC_MAX_BIN_SOCKETS][CC_MAX_BIN_SOCK_LEN];
    uint8_t     bin_cnt = 0;
    int         ip_len, i;

    if (payload_len < (int)(CC_NODE_ID_SZ + 2)) {
	LM_WARN("clusterer_controller: NODE_ASSIGN payload too short\n");
	return;
    }

    /* node_id (2B BE) */
    memcpy(&node_id, p, CC_NODE_ID_SZ);
    node_id = ntohs(node_id);
    p += CC_NODE_ID_SZ;

    /* IP */
    ip_len = (int)strnlen(p, CC_MAX_IP_LEN);
    memcpy(ip, p, ip_len);
    ip[ip_len] = '\0';
    p += ip_len + 1;

    /* BIN sockets */
    memset(bin_socks, 0, sizeof(bin_socks));
    if (p < end) {
	bin_cnt = (uint8_t)*p++;
	if (bin_cnt > CC_MAX_BIN_SOCKETS)
	    bin_cnt = CC_MAX_BIN_SOCKETS;
	for (i = 0; i < (int)bin_cnt && p < end; i++) {
	    int slen = (int)strnlen(p, CC_MAX_BIN_SOCK_LEN - 1);
	    memcpy(bin_socks[i], p, slen);
	    bin_socks[i][slen] = '\0';
	    p += slen + 1;
	}
    }

    lock_start_write(cl->peers->lock);
    cc_upsert_peer_locked(ip, cl);
    cc_update_peer_bin_locked(ip, node_id, bin_cnt,
                               (const char (*)[CC_MAX_BIN_SOCK_LEN])bin_socks,
                               cl);
    lock_stop_write(cl->peers->lock);

    /* Record our own node_id — also the first signal that a master exists */
    if (strcmp(ip, my_ip) == 0) {
	/* Always our own entry — update identity regardless of my_node_id */
	if (my_node_id == 0) {
	    int is_joining;
	    lock_start_read(cl->peers->lock);
	    is_joining = (cl->peers->node_state == CC_NODE_NEW);
	    lock_stop_read(cl->peers->lock);
	    if (is_joining)
		LM_INFO("clusterer_controller: [cluster %d] found existing master "
		        "at %s - receiving cluster state\n",
		        cl->cluster_id, sender_ip);
	}
	my_node_id = node_id;
	LM_INFO("clusterer_controller: [cluster %d] master %s assigned us "
	        "node_id=%u\n", cl->cluster_id, sender_ip, node_id);
	/* Correct the optimistic node_id=1 set at startup if needed */
	if (clctl_loaded) {
	    str url = {cl->bin_socket, (int)strlen(cl->bin_socket)};
	    clctl.update_identity(cl->cluster_id, node_id, &url);
	}
    } else {
	LM_INFO("clusterer_controller: [cluster %d] master %s assigned "
	        "node_id=%u to %s\n", cl->cluster_id, sender_ip, node_id, ip);
	/* Add peer to clusterer */
	if (clctl_loaded && bin_cnt > 0) {
	    str url = {bin_socks[0], (int)strlen(bin_socks[0])};
	    clctl.add_node(cl->cluster_id, node_id, &url);
	}
    }
}

/* =========================================================================
 * Receive dispatcher
 * ========================================================================= */

/**
 * cc_recv_one() - read one datagram, validate header, dispatch by type.
 */
static void cc_recv_one(int sock, cc_cluster_t *cl)
{
    /* Static buffer: avoids a 64 KB stack frame; safe because cc_recv_one
     * is called only from the single-threaded cc_worker process.         */
    static char        buf[CC_RECV_BUF_SZ];
    struct sockaddr_in src_addr;
    socklen_t          src_len = sizeof(src_addr);
    ssize_t            n;
    uint16_t           magic;
    unsigned char      pkt_type;
    const char        *payload;
    int                payload_len;

    n = recvfrom(sock, buf, sizeof(buf) - 1, 0,
                 (struct sockaddr *)&src_addr, &src_len);
    if (n < 0) {
	if (errno != EAGAIN && errno != EWOULDBLOCK)
	    LM_ERR("clusterer_controller: recvfrom(): %s\n", strerror(errno));
	return;
    }

    /* Minimum: magic(2)+nonce(12)+type(1)+ts(4)+1 payload+tag(16) = 36 */
    if (n < CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ + CC_TAG_SZ + 1) {
	LM_WARN("clusterer_controller: short packet (%zd bytes), dropping\n",
	        n);
	return;
    }

    memcpy(&magic, buf, 2);
    if (ntohs(magic) != CC_PACKET_MAGIC) {
	LM_WARN("clusterer_controller: bad magic 0x%04x, dropping\n",
	        ntohs(magic));
	return;
    }

    /* Resolve sender IP once — used for HMAC warning and MEMBER_LIST dispatch */
    {
	char sender_ip_buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &src_addr.sin_addr,
	          sender_ip_buf, sizeof(sender_ip_buf));

	/* Decrypt and authenticate.  cc_decrypt_pkt() writes plaintext
	 * in-place at buf[CC_WIRE_HDR_SZ..].  Layout after decryption:
	 *   buf[CC_WIRE_HDR_SZ]     = type
	 *   buf[CC_WIRE_HDR_SZ+1..4] = timestamp (uint32_t BE)
	 *   buf[CC_WIRE_HDR_SZ+5..] = protocol payload             */
	if (cc_decrypt_pkt(buf, n, sender_ip_buf, cl->key) < 0)
	    return;

	if (cc_check_timestamp(buf + CC_WIRE_HDR_SZ, sender_ip_buf) < 0)
	    return;

	pkt_type    = (unsigned char)buf[CC_WIRE_HDR_SZ];
	payload     = buf + CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ;
	payload_len = (int)(n - CC_WIRE_HDR_SZ - CC_PLAIN_HDR_SZ - CC_TAG_SZ);

	if (payload_len < 0) {
	    LM_WARN("clusterer_controller: empty payload from %s, dropping\n",
	            sender_ip_buf);
	    return;
	}


	switch (pkt_type) {

	case CC_PKT_ALIVE: {
	    char ip_buf[CC_MAX_IP_LEN + 1];
	    int  ip_len = payload_len > CC_MAX_IP_LEN ? CC_MAX_IP_LEN : payload_len;
	    memcpy(ip_buf, payload, ip_len);
	    ip_buf[ip_len] = '\0';
	    cc_handle_alive(ip_buf, cl);
	    break;
	}

	case CC_PKT_JOIN_REQ:
	    cc_handle_join_req(sock, payload, payload_len, cl);
	    break;

	case CC_PKT_MEMBER_LIST:
	    cc_handle_member_list(payload, payload_len, sender_ip_buf, cl);
	    break;

	case CC_PKT_GOODBYE: {
	    char ip_buf[CC_MAX_IP_LEN + 1];
	    int  ip_len = payload_len > CC_MAX_IP_LEN ? CC_MAX_IP_LEN : payload_len;
	    memcpy(ip_buf, payload, ip_len);
	    ip_buf[ip_len] = '\0';
	    cc_handle_goodbye(sock, ip_buf, cl);
	    break;
	}

	case CC_PKT_NODE_ASSIGN:
	    cc_handle_node_assign(payload, payload_len, sender_ip_buf, cl);
	    break;

	default:
	    LM_WARN("clusterer_controller: unknown packet type 0x%02x "
	            "from %s, dropping\n", pkt_type, sender_ip_buf);
	    break;
	}
    }
}

/* =========================================================================
 * Background worker process
 * ========================================================================= */

/**
 * cc_worker() - the single dedicated background process.
 *
 * JOIN PROTOCOL:
 *   1. Open socket, join multicast group.
 *   2. Send CC_PKT_JOIN_REQ and set state = CC_NODE_NEW with a deadline
 *      of (now + query_time).
 *   3. Listen for incoming packets.  If CC_PKT_MEMBER_LIST arrives:
 *        → cc_handle_member_list() sets state = CC_NODE_ACTIVE.
 *      If deadline expires with no MEMBER_LIST:
 *        → no master exists yet; transition to CC_NODE_ACTIVE and
 *          join the normal election cycle.
 *
 * ACTIVE LOOP:
 *   Every query_time seconds: send CC_PKT_ALIVE and prune stale entries.
 *   Every 100 ms: check for incoming packets with select().
 *   ALIVE interval is tracked with get_uticks() (µs precision) so heartbeats
 *   fire at the configured interval regardless of select() wake-up jitter.
 */
static void cc_worker(int rank)
{
    cc_cluster_t   *cl;
    int             sock;
    utime_t         last_alive_us    = 0;
    utime_t         last_join_req_us = 0;
    cc_node_state_t cur_state;
    int             identity_registered = 0; /* tracks clusterer set_my_identity */

    if (rank >= cc_cluster_count) {
	/* Extra process slot — no cluster assigned, exit cleanly */
	return;
    }
    cl = &cc_clusters[rank];

    LM_INFO("clusterer_controller: [cluster %d] worker started (pid=%d)\n",
            cl->cluster_id, getpid());

    sock = cc_setup_socket(cl);
    if (sock < 0) {
	LM_CRIT("clusterer_controller: [cluster %d] cannot open multicast socket, "
	        "worker exits\n", cl->cluster_id);
	exit(-1);
    }

    /* ---- Phase 1: join protocol ---- */
    cc_send_join_req(sock, cl);
    last_join_req_us = get_uticks();

    lock_start_write(cl->peers->lock);
    cl->peers->node_state    = CC_NODE_NEW;
    cl->peers->join_deadline = time(NULL) + (time_t)query_time;
    lock_stop_write(cl->peers->lock);

    LM_INFO("clusterer_controller: [cluster %d] sent JOIN_REQ, waiting up to %ds "
            "for master response\n", cl->cluster_id, query_time);

    /* ---- Main loop ---- */
    for (;;) {
	fd_set         rfds;
	struct timeval tv;
	int            ret;
	utime_t        now_us = get_uticks(); /* µs since OpenSIPS start — for ALIVE interval */
	time_t         now    = time(NULL);   /* Unix timestamp — for join_deadline comparison */

	/* Read current state under lock */
	lock_start_write(cl->peers->lock);
	cur_state = cl->peers->node_state;

	if (cur_state == CC_NODE_NEW && now >= cl->peers->join_deadline) {
	    /* No master responded — we are the first node.
	     * Bootstrap our own peer entry with node_id and BIN sockets
	     * before transitioning, so the MI table is populated from the
	     * start and cc_alloc_node_id_locked() works correctly.       */
	    LM_INFO("clusterer_controller: [cluster %d] join deadline expired, "
	            "no master found - transitioning to CC_NODE_ACTIVE\n",
	            cl->cluster_id);
	    cc_upsert_peer_locked(my_ip, cl);
	    my_node_id = cc_alloc_node_id_locked(cl);
	    {
		/* Register only the BIN socket for this cluster */
		char self_sock[1][CC_MAX_BIN_SOCK_LEN];
		memcpy(self_sock[0], cl->bin_socket, CC_MAX_BIN_SOCK_LEN);
		cc_update_peer_bin_locked(my_ip, my_node_id, 1,
		                          (const char (*)[CC_MAX_BIN_SOCK_LEN])
		                          self_sock, cl);
	    }
	    cl->peers->node_state = CC_NODE_ACTIVE;
	    cur_state = CC_NODE_ACTIVE;
	}
	lock_stop_write(cl->peers->lock);

	/* Confirm or correct identity once we know our real node_id */
	if (cur_state == CC_NODE_ACTIVE && !identity_registered
	    && clctl_loaded && my_node_id > 0) {
	    str url = {cl->bin_socket, (int)strlen(cl->bin_socket)};
	    clctl.update_identity(cl->cluster_id, my_node_id, &url);
	    identity_registered = 1;
	}

	/* While waiting for a master: resend JOIN_REQ every second.
	 * An existing master responds with MEMBER_LIST within one second
	 * instead of waiting up to query_time seconds for the first one.
	 * Once MEMBER_LIST is received, cc_handle_member_list() transitions
	 * to CC_NODE_ACTIVE and this branch is no longer taken.            */
	if (cur_state == CC_NODE_NEW &&
	    now_us - last_join_req_us >= 1000000ULL) {
	    cc_send_join_req(sock, cl);
	    last_join_req_us = now_us;
	    LM_DBG("clusterer_controller: [cluster %d] resending JOIN_REQ "
	           "(no master yet)\n", cl->cluster_id);
	}

	/* Send periodic ALIVE only when active.
	 * get_uticks() gives µs precision so the heartbeat fires at
	 * exactly query_time seconds regardless of select() wake-up jitter. */
	if (cur_state == CC_NODE_ACTIVE &&
	    now_us - last_alive_us >= (utime_t)query_time * 1000000ULL) {
	    cc_send_alive(sock, cl);
	    last_alive_us = now_us;

	    lock_start_write(cl->peers->lock);
	    cc_prune_stale(cl);
	    /* Proactive re-election: catches nodes that went silent
	     * even when no incoming packet triggers cc_handle_alive() */
	    cc_elect_master(cl);
	    lock_stop_write(cl->peers->lock);
	}

	/* Wait up to 100 ms for an incoming packet.
	 * 100 ms gives 10 wake-ups per second — enough to stay responsive
	 * while the ALIVE interval is tracked independently via get_uticks(). */
	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	tv.tv_sec  = 0;
	tv.tv_usec = 100000;   /* 100 ms */

	ret = select(sock + 1, &rfds, NULL, NULL, &tv);
	if (ret < 0) {
	    if (errno == EINTR)
		continue;
	    LM_ERR("clusterer_controller: select(): %s\n", strerror(errno));
	    break;
	}

	if (ret > 0 && FD_ISSET(sock, &rfds))
	    cc_recv_one(sock, cl);
    }

    close(sock);
}

/* =========================================================================
 * MI command handlers
 * ========================================================================= */

/**
 * mi_cc_members() - list active cluster members with their role.
 *
 *   opensips-cli -x mi cc_list_members
 *
 *   [
 *     {"ip": "10.0.0.3", "status": "master"},
 *     {"ip": "10.0.0.1", "status": "member"},
 *     {"ip": "10.0.0.2", "status": "member"}
 *   ]
 *
 * Only peers within the current quantized election window are shown,
 * consistent with what cc_elect_master(cl) considers.
 */
static mi_response_t *mi_cc_members(const mi_params_t *params,
                                     struct mi_handler *hdl)
{
    mi_response_t  *resp;
    mi_item_t      *arr, *cl_obj, *members_arr, *peer_obj, *bin_arr;
    int             i, j, ci;
    cc_cluster_t   *cl;

    resp = init_mi_result_array(&arr);
    if (!resp)
	return NULL;

    for (ci = 0; ci < cc_cluster_count; ci++) {
	cl = &cc_clusters[ci];
	if (!cl->peers)
	    continue;

	cl_obj = add_mi_object(arr, NULL, 0);
	if (!cl_obj) goto error;

	if (add_mi_number(cl_obj, MI_SSTR("cluster_id"), cl->cluster_id) < 0)
	    goto error;

	members_arr = add_mi_array(cl_obj, MI_SSTR("members"));
	if (!members_arr) goto error;

	lock_start_read(cl->peers->lock);

	for (i = 0; i < cl->peers->count; i++) {
	    cc_peer_t *e = &cl->peers->entries[i];

	    peer_obj = add_mi_object(members_arr, NULL, 0);
	    if (!peer_obj) {
		lock_stop_read(cl->peers->lock);
		goto error;
	    }
	    if (add_mi_string(peer_obj, MI_SSTR("ip"),
	                      e->ip, strlen(e->ip)) < 0 ||
	        add_mi_number(peer_obj, MI_SSTR("node_id"), e->node_id) < 0 ||
	        add_mi_string(peer_obj, MI_SSTR("status"),
	                      e->is_master ? "master" : "member", 6) < 0) {
		lock_stop_read(cl->peers->lock);
		goto error;
	    }

	    bin_arr = add_mi_array(peer_obj, MI_SSTR("bin_sockets"));
	    if (!bin_arr) {
		lock_stop_read(cl->peers->lock);
		goto error;
	    }
	    for (j = 0; j < (int)e->bin_count; j++) {
		if (add_mi_string(bin_arr, NULL, 0,
		                  e->bin_sockets[j],
		                  strlen(e->bin_sockets[j])) < 0) {
		    lock_stop_read(cl->peers->lock);
		    goto error;
		}
	    }
	}

	lock_stop_read(cl->peers->lock);
    }

    return resp;

error:
    LM_ERR("clusterer_controller: mi_cc_members: failed to build response\n");
    free_mi_response(resp);
    return NULL;
}

/**
 * mi_cc_node_info() - return full info for a specific node_id.
 *
 *   opensips-cli -x mi cc_node_info node_id=2
 */
static mi_response_t *mi_cc_node_info(const mi_params_t *params,
                                      struct mi_handler *hdl)
{
    mi_response_t  *resp;
    mi_item_t      *root, *bin_arr;
    int             target_id;
    int             i, j, ci;
    cc_cluster_t   *cl;
    cc_peer_t      *e;

    if (get_mi_int_param(params, "node_id", &target_id) < 0)
	return init_mi_param_error();

    for (ci = 0; ci < cc_cluster_count; ci++) {
	cl = &cc_clusters[ci];
	if (!cl->peers)
	    continue;

	lock_start_read(cl->peers->lock);
	for (i = 0; i < cl->peers->count; i++) {
	    e = &cl->peers->entries[i];
	    if ((int)e->node_id != target_id)
		continue;

	    resp = init_mi_result_object(&root);
	    if (!resp) {
		lock_stop_read(cl->peers->lock);
		return NULL;
	    }
	    if (add_mi_number(root, MI_SSTR("node_id"),    e->node_id)             < 0 ||
	        add_mi_string(root, MI_SSTR("ip"),         e->ip, strlen(e->ip))   < 0 ||
	        add_mi_number(root, MI_SSTR("cluster_id"), cl->cluster_id)          < 0 ||
	        add_mi_string(root, MI_SSTR("status"),
	                      e->is_master ? "master" : "member", 6)                < 0) {
		lock_stop_read(cl->peers->lock);
		goto error_node;
	    }
	    bin_arr = add_mi_array(root, MI_SSTR("bin_sockets"));
	    if (!bin_arr) {
		lock_stop_read(cl->peers->lock);
		goto error_node;
	    }
	    for (j = 0; j < (int)e->bin_count; j++) {
		if (add_mi_string(bin_arr, NULL, 0,
		                  e->bin_sockets[j],
		                  strlen(e->bin_sockets[j])) < 0) {
		    lock_stop_read(cl->peers->lock);
		    goto error_node;
		}
	    }
	    lock_stop_read(cl->peers->lock);
	    return resp;
	}
	lock_stop_read(cl->peers->lock);
    }

    return init_mi_error(404, MI_SSTR("node_id not found"));

error_node:
    LM_ERR("clusterer_controller: mi_cc_node_info: failed to build response\n");
    free_mi_response(resp);
    return NULL;
}
/* =========================================================================
 * Lifecycle
 * ========================================================================= */

/**
 * cc_resolve_local_identity() - determine my_ip and my_interface_buf.
 *
 * Three modes depending on which modparams were provided:
 *
 *   Mode 1 — ip= only:
 *     Walk getifaddrs() to find the interface that owns the given IP.
 *     Fails if no interface owns it.
 *
 *   Mode 2 — interface= only:
 *     Walk getifaddrs() to find the interface and take its first IPv4 address.
 *     Warns if the interface has multiple IPv4 addresses; uses the first one
 *     (the kernel's enumeration order matches `ip addr show`).
 *
 *   Mode 3 — neither:
 *     Connect a throw-away UDP socket to the multicast group (no data sent).
 *     getsockname() returns the source IP the kernel would select.
 *     Reverse-look up the interface name via getifaddrs().
 *
 * On success: my_ip points to a valid dotted-decimal IPv4 string and
 *             my_interface_buf holds the interface name (may be empty if the
 *             reverse lookup failed in mode 3 — non-fatal).
 */
/**
 * cc_parse_cluster_str() - parse one "cluster" modparam string into cl.
 *
 * Format: "id=N,multicast=A.B.C.D:PORT[,password=STRING][,bin_socket=bin:IP:PORT]"
 * - id= required, positive integer
 * - multicast= required, IPv4:port
 * - password= optional, falls back to global password modparam
 * - bin_socket= optional, BIN socket for this cluster; falls back to
 *   first discovered socket (or only socket if one exists)
 */
static int cc_parse_cluster_str(const char *str, cc_cluster_t *cl)
{
    char        buf[2048];
    char       *p, *tok, *key, *val, *colon;
    struct in_addr addr;
    unsigned char  first_octet;
    int         has_id = 0, has_mcast = 0;

    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Defaults */
    cl->multicast_port = 3333;
    strncpy(cl->password, password, sizeof(cl->password) - 1);
    cl->password[sizeof(cl->password) - 1] = '\0';

    for (tok = strtok_r(buf, ",", &p); tok; tok = strtok_r(NULL, ",", &p)) {
	while (*tok == ' ' || *tok == '\t') tok++;
	key = tok;
	val = strchr(tok, '=');
	if (!val) continue;
	*val++ = '\0';

	if (strcmp(key, "id") == 0) {
	    cl->cluster_id = atoi(val);
	    if (cl->cluster_id <= 0) {
		LM_ERR("clusterer_controller: cluster id must be positive int\n");
		return -1;
	    }
	    has_id = 1;

	} else if (strcmp(key, "multicast") == 0) {
	    colon = strrchr(val, ':');
	    if (colon) {
		*colon = '\0';
		cl->multicast_port = atoi(colon + 1);
		if (cl->multicast_port <= 0 || cl->multicast_port > 65535) {
		    LM_ERR("clusterer_controller: invalid port in cluster '%s'\n", str);
		    return -1;
		}
	    }
	    strncpy(cl->multicast_address, val, INET_ADDRSTRLEN - 1);
	    cl->multicast_address[INET_ADDRSTRLEN - 1] = '\0';
	    if (inet_aton(cl->multicast_address, &addr) == 0) {
		LM_ERR("clusterer_controller: invalid multicast address '%s'\n", val);
		return -1;
	    }
	    first_octet = (unsigned char)((ntohl(addr.s_addr) >> 24) & 0xFF);
	    if (first_octet < 224 || first_octet > 239) {
		LM_ERR("clusterer_controller: '%s' is not a multicast address\n", val);
		return -1;
	    }
	    has_mcast = 1;

	} else if (strcmp(key, "password") == 0) {
	    strncpy(cl->password, val, sizeof(cl->password) - 1);
	    cl->password[sizeof(cl->password) - 1] = '\0';

	} else if (strcmp(key, "bin_socket") == 0) {
	    if (strlen(val) >= CC_MAX_BIN_SOCK_LEN) {
		LM_ERR("clusterer_controller: bin_socket value too long\n");
		return -1;
	    }
	    strncpy(cl->bin_socket, val, CC_MAX_BIN_SOCK_LEN - 1);
	    cl->bin_socket[CC_MAX_BIN_SOCK_LEN - 1] = '\0';
	}
    }

    if (!has_id) {
	LM_ERR("clusterer_controller: cluster string missing id= in '%s'\n", str);
	return -1;
    }
    if (!has_mcast) {
	LM_ERR("clusterer_controller: cluster string missing multicast= in '%s'\n", str);
	return -1;
    }
    return 0;
}

static int cc_resolve_local_identity(void)
{
    struct ifaddrs *ifap = NULL, *ifa;
    int             found = 0;

    if (getifaddrs(&ifap) < 0) {
	LM_ERR("clusterer_controller: getifaddrs() failed: %s\n",
	       strerror(errno));
	return -1;
    }

    if (my_ip && *my_ip) {
	/* ---- Mode 1: ip= explicitly provided — find owning interface ---- */
	struct in_addr target;

	if (inet_aton(my_ip, &target) == 0) {
	    LM_ERR("clusterer_controller: cannot parse 'my_ip' '%s'\n", my_ip);
	    freeifaddrs(ifap);
	    return -1;
	}
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
		continue;
	    if (((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr
	            == target.s_addr) {
		strncpy(my_interface_buf, ifa->ifa_name, IF_NAMESIZE - 1);
		my_interface_buf[IF_NAMESIZE - 1] = '\0';
		found = 1;
		break;
	    }
	}
	if (!found) {
	    LM_ERR("clusterer_controller: no local interface owns IP '%s'\n",
	           my_ip);
	    freeifaddrs(ifap);
	    return -1;
	}
	LM_INFO("clusterer_controller: using IP %s on interface %s\n",
	        my_ip, my_interface_buf);

    } else if (my_interface && *my_interface) {
	/* ---- Mode 2: interface= provided — derive IP from it ---- */
	int addr_count = 0;

	strncpy(my_interface_buf, my_interface, IF_NAMESIZE - 1);
	my_interface_buf[IF_NAMESIZE - 1] = '\0';

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
		continue;
	    if (strcmp(ifa->ifa_name, my_interface) != 0)
		continue;
	    addr_count++;
	    if (addr_count == 1) {
		struct in_addr a =
		    ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
		inet_ntop(AF_INET, &a, my_ip_buf, sizeof(my_ip_buf));
		my_ip = my_ip_buf;
		found = 1;
	    }
	}
	if (!found) {
	    LM_ERR("clusterer_controller: interface '%s' not found or "
	           "has no IPv4 address\n", my_interface);
	    freeifaddrs(ifap);
	    return -1;
	}
	if (addr_count > 1)
	    LM_WARN("clusterer_controller: interface '%s' has %d IPv4 "
	            "addresses, using %s (first returned by kernel) - "
	            "use 'my_ip' modparam to override\n",
	            my_interface, addr_count, my_ip);
	else
	    LM_INFO("clusterer_controller: using IP %s on interface %s\n",
	            my_ip, my_interface_buf);

    } else {
	/* ---- Mode 3: neither — auto-detect via kernel routing table ---- */
	struct sockaddr_in dest, local;
	socklen_t          local_len = sizeof(local);
	int                probe;

	memset(&dest, 0, sizeof(dest));
	dest.sin_family      = AF_INET;
	dest.sin_port        = htons((uint16_t)cc_clusters[0].multicast_port);
	dest.sin_addr.s_addr = inet_addr(cc_clusters[0].multicast_address);

	probe = socket(AF_INET, SOCK_DGRAM, 0);
	if (probe < 0) {
	    LM_ERR("clusterer_controller: auto-detect socket: %s\n",
	           strerror(errno));
	    freeifaddrs(ifap);
	    return -1;
	}
	if (connect(probe, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
	    LM_ERR("clusterer_controller: auto-detect connect: %s\n",
	           strerror(errno));
	    close(probe);
	    freeifaddrs(ifap);
	    return -1;
	}
	memset(&local, 0, sizeof(local));
	if (getsockname(probe, (struct sockaddr *)&local, &local_len) < 0) {
	    LM_ERR("clusterer_controller: auto-detect getsockname: %s\n",
	           strerror(errno));
	    close(probe);
	    freeifaddrs(ifap);
	    return -1;
	}
	close(probe);

	inet_ntop(AF_INET, &local.sin_addr, my_ip_buf, sizeof(my_ip_buf));
	my_ip = my_ip_buf;

	/* Reverse-look up the interface name */
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
		continue;
	    if (((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr
	            == local.sin_addr.s_addr) {
		strncpy(my_interface_buf, ifa->ifa_name, IF_NAMESIZE - 1);
		my_interface_buf[IF_NAMESIZE - 1] = '\0';
		found = 1;
		break;
	    }
	}
	if (found)
	    LM_INFO("clusterer_controller: auto-detected IP %s on "
	            "interface %s\n", my_ip, my_interface_buf);
	else
	    LM_WARN("clusterer_controller: auto-detected IP %s but could "
	            "not determine interface name\n", my_ip);
    }

    freeifaddrs(ifap);
    return 0;
}

/**
 * cc_discover_bin_sockets() - enumerate BIN listeners via proto_bin.
 *
 * Walks the protos[PROTO_BIN].listeners list and collects every
 * entry with proto == PROTO_BIN.  proto_bin must be loaded before this
 * module so the listeners are already registered when mod_init() runs.
 *
 * Populates my_bin_sockets[] and my_bin_count.
 * Returns 0 on success, -1 if no BIN sockets are found.
 */
static int cc_discover_bin_sockets(void)
{
    struct socket_info *si;
    char                buf[CC_MAX_BIN_SOCK_LEN];
    int                 len;

    for (si = protos[PROTO_BIN].listeners; si; si = si->next) {
	/* all entries here are PROTO_BIN by construction */
	if (si->proto != PROTO_BIN)
	    continue;
	/* Reject wildcard — clusterer needs an explicit IP to set send_sock.
	 * Use socket=bin:IP:PORT instead of socket=bin:*:PORT.             */
	if (si->address_str.len == 0
	    || (si->address_str.len == 1 && si->address_str.s[0] == '*')
	    || (si->address_str.len == 7
	        && memcmp(si->address_str.s, "0.0.0.0", 7) == 0)) {
	    LM_ERR("clusterer_controller: wildcard BIN socket "
	           "(bin:*:%u) is not allowed — use an explicit IP "
	           "(e.g. socket=bin:%s:%u)\n",
	           si->port_no, my_ip ? my_ip : "YOUR_IP", si->port_no);
	    return -1;
	}
	if (my_bin_count >= CC_MAX_BIN_SOCKETS) {
	    LM_WARN("clusterer_controller: more than %d BIN sockets, "
	            "ignoring the rest\n", CC_MAX_BIN_SOCKETS);
	    break;
	}
	len = snprintf(buf, sizeof(buf), "bin:%.*s:%u",
	               si->address_str.len, si->address_str.s,
	               si->port_no);
	if (len <= 0 || len >= CC_MAX_BIN_SOCK_LEN) {
	    LM_WARN("clusterer_controller: BIN socket name too long, "
	            "skipping\n");
	    continue;
	}
	memcpy(my_bin_sockets[my_bin_count], buf, len + 1);
	LM_INFO("clusterer_controller: found BIN socket: %s\n", buf);
	my_bin_count++;
    }

    if (my_bin_count == 0) {
	LM_ERR("clusterer_controller: no BIN sockets found — "
	       "is proto_bin loaded and socket=bin: configured?\n");
	return -1;
    }

    return 0;
}

static int mod_init(void)
{
    struct in_addr addr;
    int            i, j;

    LM_INFO("clusterer_controller: initialising\n");

    /* ---- Require at least one cluster ---------------------------------- */

    if (cc_cluster_str_count == 0) {
	LM_ERR("clusterer_controller: no 'cluster' modparam defined\n");
	return -1;
    }

    /* ---- Global param validation --------------------------------------- */

    if (query_time < 1) {
	LM_WARN("clusterer_controller: 'query_time' %d below min, clamping to 1s\n",
	        query_time);
	query_time = 1;
    } else if (query_time > 60) {
	LM_WARN("clusterer_controller: 'query_time' %d exceeds max, clamping to 60s\n",
	        query_time);
	query_time = 60;
    }

    /* ---- Parse and validate all cluster strings ------------------------ */

    for (i = 0; i < cc_cluster_str_count; i++) {
	if (cc_parse_cluster_str(cc_cluster_strs[i], &cc_clusters[i]) < 0)
	    return -1;
	cc_cluster_count++;
    }

    /* Validate cluster_id uniqueness and (multicast, port) uniqueness */
    for (i = 0; i < cc_cluster_count; i++) {
	for (j = i + 1; j < cc_cluster_count; j++) {
	    if (cc_clusters[i].cluster_id == cc_clusters[j].cluster_id) {
		LM_ERR("clusterer_controller: duplicate cluster_id %d\n",
		       cc_clusters[i].cluster_id);
		return -1;
	    }
	    if (strcmp(cc_clusters[i].multicast_address,
	               cc_clusters[j].multicast_address) == 0 &&
	        cc_clusters[i].multicast_port == cc_clusters[j].multicast_port) {
		LM_ERR("clusterer_controller: duplicate multicast %s:%d\n",
		       cc_clusters[i].multicast_address,
		       cc_clusters[i].multicast_port);
		return -1;
	    }
	}
    }

    /* ---- Discover BIN sockets from opensips config file --------------- */
    /* Called after cc_resolve_local_identity() so my_ip is available for  */
    /* wildcard substitution (bin:*:PORT → bin:my_ip:PORT).               */

    /* ---- Resolve local identity using first cluster for Mode 3 probe --- */

    if (cc_resolve_local_identity() < 0)
	return -1;

    if (cc_discover_bin_sockets() < 0)
	return -1;

    if (strlen(my_ip) > CC_MAX_IP_LEN) {
	LM_ERR("clusterer_controller: resolved my_ip too long\n");
	return -1;
    }
    if (inet_aton(my_ip, &addr) == 0) {
	LM_ERR("clusterer_controller: cannot parse resolved my_ip '%s'\n", my_ip);
	return -1;
    }

    /* ---- Multi-cluster: each cluster must name its BIN socket ---------- */

    if (cc_cluster_count > 1) {
	for (i = 0; i < cc_cluster_count; i++) {
	    if (cc_clusters[i].bin_socket[0] == '\0') {
		LM_ERR("clusterer_controller: cluster %d has no bin_socket= "
		       "defined — required when multiple clusters are configured "
		       "(e.g. id=%d,multicast=...,bin_socket=bin:IP:PORT)\n",
		       cc_clusters[i].cluster_id, cc_clusters[i].cluster_id);
		return -1;
	    }
	}
    }

    /* ---- Per-cluster: resolve BIN socket, derive key, allocate peers --- */

    for (i = 0; i < cc_cluster_count; i++) {
	cc_cluster_t *cl = &cc_clusters[i];

	/* Resolve which BIN socket to use for this cluster.
	 * Priority: explicit bin_socket= in cluster string >
	 *           sole discovered socket >
	 *           first discovered socket (warn if multiple) */
	if (cl->bin_socket[0] != '\0') {
	    /* Explicit override — validate it was actually discovered */
	    int found_bs = 0, bi;
	    for (bi = 0; bi < my_bin_count; bi++) {
		if (strcmp(my_bin_sockets[bi], cl->bin_socket) == 0) {
		    found_bs = 1;
		    break;
		}
	    }
	    if (!found_bs)
		LM_WARN("clusterer_controller: cluster %d bin_socket='%s' "
		        "not found in discovered sockets — using anyway\n",
		        cl->cluster_id, cl->bin_socket);
	} else if (my_bin_count == 1) {
	    /* Only one socket — unambiguous */
	    {
		size_t _l = strnlen(my_bin_sockets[0], CC_MAX_BIN_SOCK_LEN - 1);
		memcpy(cl->bin_socket, my_bin_sockets[0], _l);
		cl->bin_socket[_l] = '\0';
	    }
	} else {
	    /* Multiple sockets, no explicit override — use first, warn */
	    {
		size_t _l = strnlen(my_bin_sockets[0], CC_MAX_BIN_SOCK_LEN - 1);
		memcpy(cl->bin_socket, my_bin_sockets[0], _l);
		cl->bin_socket[_l] = '\0';
	    }
	    LM_WARN("clusterer_controller: cluster %d has no bin_socket= override "
	            "and multiple BIN sockets exist — using %s; add bin_socket= "
	            "to the cluster string to be explicit\n",
	            cl->cluster_id, cl->bin_socket);
	}
	LM_INFO("clusterer_controller: cluster %d: bin_socket=%s\n",
	        cl->cluster_id, cl->bin_socket);

	if (cc_derive_key(cl) < 0)
	    return -1;

	cl->peers = shm_malloc(sizeof(cc_peers_t));
	if (!cl->peers) {
	    LM_ERR("clusterer_controller: no shm memory for cluster %d peer table\n",
	           cl->cluster_id);
	    return -1;
	}
	memset(cl->peers, 0, sizeof(cc_peers_t));
	cl->peers->node_state = CC_NODE_NEW;

	cl->peers->lock = lock_init_rw();
	if (!cl->peers->lock) {
	    LM_ERR("clusterer_controller: lock_init_rw() failed for cluster %d\n",
	           cl->cluster_id);
	    shm_free(cl->peers);
	    cl->peers = NULL;
	    return -1;
	}

	LM_INFO("clusterer_controller: cluster %d: multicast=%s:%d bin=%s\n",
	        cl->cluster_id, cl->multicast_address, cl->multicast_port,
	        cl->bin_socket);
    }

    LM_INFO("clusterer_controller: my_ip=%s interface=%s query_time=%ds "
            "clusters=%d bin_sockets=%d encryption=AES-256-GCM\n",
            my_ip, my_interface_buf[0] ? my_interface_buf : "(unknown)",
            query_time, cc_cluster_count, my_bin_count);

    /* Set worker process count dynamically — one per cluster */
    procs[0].no = cc_cluster_count;

    /* Load clusterer controller API if clusterer.so is present and
     * use_controller=1 is set.  Soft dependency — controller works
     * standalone even without clusterer loaded.                     */
    {
	load_clusterer_ctrl_binds_f load_fn;
	load_fn = (load_clusterer_ctrl_binds_f)
	          find_export("load_clusterer_ctrl_binds", 0);
	if (load_fn && load_fn(&clctl) == 0) {
	    clctl_loaded = 1;
	    LM_INFO("clusterer_controller: clusterer API loaded — "
	            "topology will be driven dynamically\n");

	} else {
	    LM_DBG("clusterer_controller: clusterer not loaded or "
	           "use_controller not set — running standalone\n");
	}
    }

    return 0;
}

static int cc_child_init(int rank)
{
	/* Sync current_id from shared memory in every child process.
	 * The global current_id diverges after fork — each process needs
	 * to re-read the correct value from cluster->current_node.      */
	if (clctl_loaded && clctl.sync_current_id)
		clctl.sync_current_id();
	return 0;
}

static void mod_destroy(void)
{
    int            i, sock;
    unsigned char  ttl = 32;
    cc_cluster_t  *cl;

    if (!my_ip)
	goto cleanup;

    /* Send GOODBYE on each cluster's multicast group so peers re-elect */
    for (i = 0; i < cc_cluster_count; i++) {
	cl = &cc_clusters[i];
	if (!cl->peers)
	    continue;
	if (cl->peers->count <= 1) {
	    LM_INFO("clusterer_controller: [cluster %d] sole node, "
	            "skipping GOODBYE\n", cl->cluster_id);
	    continue;
	}
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
	    LM_ERR("clusterer_controller: [cluster %d] goodbye socket(): %s\n",
	           cl->cluster_id, strerror(errno));
	    continue;
	}
	setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
	cc_send_pkt_with_ip(sock, CC_PKT_GOODBYE, cl);
	close(sock);
	LM_INFO("clusterer_controller: [cluster %d] GOODBYE sent\n",
	        cl->cluster_id);
    }

cleanup:
    for (i = 0; i < cc_cluster_count; i++) {
	cl = &cc_clusters[i];
	if (!cl->peers)
	    continue;
	if (cl->peers->lock) {
	    lock_destroy_rw(cl->peers->lock);
	    cl->peers->lock = NULL;
	}
	shm_free(cl->peers);
	cl->peers = NULL;
    }
    LM_INFO("clusterer_controller: shut down\n");
}
