/*
 * clusterer_controller - multicast extension for the clusterer module
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

#ifndef CL_CTR_H
#define CL_CTR_H


#include <stdlib.h>
#include <string.h>
#include <strings.h>       /* strcasecmp()                                   */
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
#include <sys/ioctl.h>      /* ioctl, SIOCGIFMTU                              */

#include "../../sr_module.h"    /* module_exports, proc/param/dep_export_t    */
#include "../../dprint.h"       /* LM_ERR / LM_WARN / LM_INFO / LM_DBG       */
#include "../../mem/shm_mem.h"  /* shm_malloc / shm_free                      */
#include "../../locking.h"        /* gen_lock_t - base spinlock primitive         */
#include "../../rw_locking.h"     /* rw_lock_t  - reader-writer lock built on top */
#include "../../mi/mi.h"        /* mi_export_t, mi_response_t, MI helpers     */
#include "../../timer.h"        /* get_uticks(), utime_t - us since start     */
#include "../../socket_info.h"  /* struct socket_info, PROTO_BIN              */
#include "../../net/api_proto.h" /* protos[] array                            */
#include "../../globals.h"      /* process_no - this process's index          */
#include "../../ipc.h"          /* ipc_send_rpc() - cross-process job dispatch */
#include "clctr_api.h"           /* consumer messaging API contract */
#include "cl_ctr_mod.h"           /* the module exports: parameters, functions */
#include "../../pvar.h"         /* pv_export_t - read-only $cl_ctr_* variables */

#include "clusterer_ctrl.h"  /* set_my_identity, add_node, remove_node */
#include "api.h"   /* set_state() - the 'full' maintenance level */

#include <sys/timerfd.h>    /* timerfd_create(), timerfd_settime()            */
#include "../../reactor_proc.h" /* reactor_proc_init/add_fd/loop              */

/* all crypto is libsodium, a hard requirement (the Makefile fails without it) */
#include <sodium.h>

/* seconds for every elapsed-time check: monotonic, so a wall-clock step cannot
 * expire every peer at once; biased so a last_seen of 0 never looks fresh */
#define CL_CTR_CLOCK_BIAS  1000000
static inline time_t cl_ctr_now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (time_t)ts.tv_sec + CL_CTR_CLOCK_BIAS;
}

/* the same clock in ms, for the worker's stall check */
static inline long long cl_ctr_now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* a term this far above every known one is a bug or corrupt sender: refused
 * (cl_ctr_term_sane()), else it would make every later MEMBER_LIST look stale */
#define CL_CTR_TERM_JUMP_MAX  1000000u
/* other clusters (different uuid) heard on this group, for list_config; LRU
 * and small, as the uuid comes from the unauthenticated header */
#define CL_CTR_FOREIGN_MAX    16
/* a worker loop gap over CL_CTR_STALL_MS means this process was paused or
 * starved, not that the peers it failed to hear died */
#define CL_CTR_STALL_TICK_MS  500
#define CL_CTR_STALL_MS       2000
#define CL_CTR_STALL_GRACE_MS 2000   /* control traffic not rate-limited after */
#define CL_CTR_CRYPTO_SUITE "XChaCha20-Poly1305 + Argon2id + Noise_NNpsk0"

/* ==== wire-format constants ==== */

/* cleartext key selector, in the AAD: byte 0 = CL_CTR_MAGIC_BASE + wire version,
 * byte 1 = key tier; another version is refused at the magic gate */
#define CL_CTR_MAGIC_SZ          2
/* bump when a change alters how an existing field is read; a length-gated
 * appended field (as config, MTU, term are) needs no bump */
#define CL_CTR_WIRE_VERSION      3
#define CL_CTR_MAGIC_BASE        0xCB
#define CL_CTR_WIRE_MAGIC0       (CL_CTR_MAGIC_BASE + CL_CTR_WIRE_VERSION)
/* highest key-tier byte in use - lets the gate recognise another version's
 * packet as ours-but-different rather than as noise */
#define CL_CTR_MAGIC_TIER_MAX    0x02
/* how often one cluster may repeat the wire-version warning, in seconds */
#define CL_CTR_WIRE_WARN_IVL     60

/* Packet type bytes */
#define CL_CTR_PKT_ALIVE            0x01
#define CL_CTR_PKT_JOIN_REQ         0x02
#define CL_CTR_PKT_MEMBER_LIST      0x03  /* master -> joining node: here is the cluster  */
#define CL_CTR_PKT_GOODBYE          0x04  /* graceful shutdown notification               */
#define CL_CTR_PKT_NODE_ASSIGN      0x05  /* master -> multicast: here is your node_id    */
#define CL_CTR_PKT_MASTER_ALIVE     0x06  /* master-only keepalive; ~1 s interval         */
#define CL_CTR_PKT_KEY_GRANT        0x07  /* master -> joiner: ECDH-wrapped master_salt    */
#define CL_CTR_PKT_KEY_HANDOFF      0x08  /* outgoing master -> next master: salt handoff  */
#define CL_CTR_PKT_JOIN_REJECT      0x09  /* master -> joiner: authentication rejected     */
#define CL_CTR_PKT_ACK              0x0B  /* receiver -> sender: ack of a 1:1 handshake pkt */
/* ACK payload: [acked seq 4B BE][acked type 1B]; the type tells the planes
 * apart, as my_seq and my_consumer_seq are independent counters */
#define CL_CTR_ACK_SZ               5
#define CL_CTR_PKT_RESYNC           0x0C  /* member -> master: my view differs, resend state */
#define CL_CTR_PKT_CONSUMER         0x0D  /* consumer API message: [src_id][chan][data] */
/* consumer message ACKed and retransmitted; a type of its own so receive tells
 * it apart before parsing, and an old build drops it */
#define CL_CTR_PKT_CONSUMER_REL     0x0E
/* member -> group, master silent: who still hears [master ip]? answered by
 * unicast; an older build drops it (cl_ctr_probe_step()) */
#define CL_CTR_PKT_MASTER_PROBE     0x0F
#define CL_CTR_PKT_MASTER_PROBE_ACK 0x10
#define CL_CTR_PROBE_CONFIRM        2     /* silent answers that elect at once */
#define CL_CTR_PROBE_WAIT_MS        1000  /* how long the answers are awaited  */
#define CL_CTR_PROBE_FRESH_MS       2000  /* "still hears it" = within this    */
#define CL_CTR_PROBE_HOLD_MAX_S     30    /* longest an election is held for   */
#define CL_CTR_PROBE_NOT_HEARD      0xFFFFFFFFu
/* maintenance: still a member, never master or backup, holds no sharing tag;
 * announced in the node's ALIVE, relayed by the master in MASTER_ALIVE */
#define CL_CTR_MAINT_NONE           0
#define CL_CTR_MAINT_EVICTED        1
/* full: evicted, and every other node marks it down in its own clusterer
 * (set_state STATE_DISABLED), so replication stops routing work to it */
#define CL_CTR_MAINT_FULL           2
/* any node -> group: put node [node_id 2B BE] into maintenance [state 1B];
 * only the node named applies it, to itself, and announces it as usual */
#define CL_CTR_PKT_MAINT_SET        0x11

/* consumer payload after the plain header: [src_node_id u16 BE][chan_len u8]
 * [channel][data]; one sub-MTU datagram, bulk goes over BIN (api.h) */
#define CL_CTR_MAX_CHANNELS         8
#define CL_CTR_CONSUMER_HDR_SZ      (CL_CTR_NODE_ID_SZ + 1)
/* all a consumer datagram carries besides the payload; the buffer itself is
 * sized at runtime from cc_max_payload, so jumbo links carry more */
#define CL_CTR_PKT_OVERHEAD         (CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ \
                                     + CL_CTR_CONSUMER_HDR_SZ + CLCTR_MAX_CHAN_LEN \
                                     + CL_CTR_TAG_SZ)
#define CL_CTR_CONSUMER_PKT_MAX     (CL_CTR_PKT_OVERHEAD + CLCTR_MAX_PAYLOAD)
/* how often one process may repeat the reliable-send refusal */
#define CL_CTR_RELIABLE_WARN_IVL    60
/* UDP payload limit whatever the MTU says (loopback reports 65536) */
#define CL_CTR_UDP_PAYLOAD_MAX      65507
#define CL_CTR_PKT_MASTER_BEACON    0x0A  /* master-only, BOOTSTRAP key: masters with
                                           * divergent session keys still meet */
#define CL_CTR_BEACON_SZ            (2 + 4 + 4 + 2) /* count BE, term BE, config, MTU BE */
/* live members, appended to MASTER_ALIVE/BEACON: ranking on it (else on table
 * counts) keeps an isolated master's stale table from out-counting the majority */
#define CL_CTR_LIVE_SZ              2
/* seconds to ignore a master that refused us in a merge: the refusal is about
 * config, which does not change without a restart */
#define CL_CTR_MERGE_REFUSE_SECS    60

/* Number of consecutive bootstrap-decrypt failures before a JOIN_REJECT is sent */
#define CL_CTR_JOIN_FAIL_LIMIT      3
#define CL_CTR_JOIN_FAIL_TABLE_SZ   8   /* max simultaneous rejected IPs tracked by master */
#define CL_CTR_JOIN_NONCES          8   /* our last JOIN_REQs a JOIN_REJECT may answer */
#define CL_CTR_BOOT_SEEN           64   /* JOIN_REQs and beacons remembered, by nonce */

#define CL_CTR_MAX_IP_LEN        15   /* "255.255.255.255" without NUL            */
#define CL_CTR_PUBKEY_SZ         32   /* X25519 public key                        */
#define CL_CTR_MASTER_SALT_SZ    32   /* random salt generated by each new master */
/* MEMBER_LIST entry: IP 16B NUL-padded + is_master 1B; pubkeys come from
 * ALIVE instead, to keep the list small */
#define CL_CTR_IP_ENTRY_SZ       17
#define CL_CTR_LIST_COUNT_SZ      2   /* MEMBER_LIST count field: uint16_t BE     */
#define CL_CTR_NODE_ID_SZ         2   /* uint16_t node_id, big-endian             */
#define CL_CTR_MAX_BIN_SOCKETS    8   /* max BIN listeners per node               */
#define CL_CTR_MAX_BIN_SOCK_LEN  64   /* "bin:255.255.255.255:65535" = 26 chars   */
/* BIN info block: [bin_count 1B][sock1 NUL-term]...[sockN NUL-term]         */
#define CL_CTR_BIN_INFO_MAX_SZ   (1 + CL_CTR_MAX_BIN_SOCKETS * CL_CTR_MAX_BIN_SOCK_LEN)

/* wire: [magic][cluster_id BE][cluster uuid][nonce][ciphertext][tag]; cleartext
 * cluster_id drops foreign traffic before decryption, not as an auth failure */
#define CL_CTR_NONCE_SZ          24   /* XChaCha20-Poly1305 nonce (192-bit)       */
#define CL_CTR_TAG_SZ            16   /* Poly1305 AEAD tag                        */
#define CL_CTR_SEQ_SZ             4   /* uint32_t monotonic sequence in plaintext  */
#define CL_CTR_CLUSTER_ID_SZ      2   /* cleartext uint16 cluster_id (BE) selector */
/* founded cluster identity (CL_CTR_CID_*): cleartext and in the AAD;
 * all zeros = the sender is in no cluster yet */
#define CL_CTR_CID_SZ            16
#define CL_CTR_CID_OFF           (CL_CTR_MAGIC_SZ + CL_CTR_CLUSTER_ID_SZ)
#define CL_CTR_NONCE_OFF         (CL_CTR_CID_OFF + CL_CTR_CID_SZ)  /* nonce starts here */
#define CL_CTR_AAD_SZ            CL_CTR_NONCE_OFF  /* magic + cluster_id + cluster uuid */
#define CL_CTR_WIRE_HDR_SZ       (CL_CTR_NONCE_OFF + CL_CTR_NONCE_SZ) /* 44 */
/* process start time in us (CLOCK_REALTIME): a higher one resets the sender's
 * replay window, a lower one is from a previous life and refused */
#define CL_CTR_INC_SZ             8

/* founded cluster id: a UUID v7 minted by the founder and adopted from KEY_GRANT,
 * so deployments sharing group, password and cluster_id do not merge; not persisted */
#define CL_CTR_CID_NONE           0   /* in no cluster: sends zeros, accepts any */
#define CL_CTR_CID_PROVISIONAL    1   /* under GRACE_SECS old: may still be merged */
#define CL_CTR_CID_ESTABLISHED    2   /* fixed for the life of the process */
#define CL_CTR_CID_PINNED         3   /* uuid= in the cluster string */
#define CL_CTR_CID_GRACE_SECS    30
/* sender's IPv4, network order, sealed: receivers go by it, not by the
 * unauthenticated datagram source (it keys the replay window) */
#define CL_CTR_SENDER_SZ          4
#define CL_CTR_SENDER_OFF        (CL_CTR_WIRE_HDR_SZ + 1 + CL_CTR_SEQ_SZ + CL_CTR_INC_SZ)
#define CL_CTR_PLAIN_HDR_SZ      (1 + CL_CTR_SEQ_SZ + CL_CTR_INC_SZ + CL_CTR_SENDER_SZ) /* type + seq + incarnation + sender = 17 */

/* Argon2id bootstrap key (also the Noise PSK), derived once in mod_init before
 * fork (~64 MiB, transient); fixed so every node derives the same key */
#define CL_CTR_ARGON2_OPSLIMIT     3UL
#define CL_CTR_ARGON2_MEMLIMIT     (64UL * 1024 * 1024)
/* Minimum estimated password entropy (bits) before a startup warning fires.  */
#define CL_CTR_MIN_PASSWORD_BITS  80
#define CL_CTR_DEFAULT_PASSWORD  "3eCrEt*5629"   /* insecure placeholder; warn if used */

#define CL_CTR_MASTER_KA_INTERVAL   1   /* seconds between MASTER_ALIVE sends       */
#define CL_CTR_MASTER_KA_MISSED     3   /* missed keepalives before re-election     */
#define CL_CTR_MASTER_KA_TIMEOUT    (CL_CTR_MASTER_KA_INTERVAL * CL_CTR_MASTER_KA_MISSED)
/* adaptive master watchdog (cl_ctr_master_timeout_ms()): mean + DEV_K deviations
 * of the keepalive gaps plus a margin, within [3 s, KA_TIMEOUT_MAX_MS] */
#define CL_CTR_KA_TIMEOUT_MIN_MS    (CL_CTR_MASTER_KA_TIMEOUT * 1000)
#define CL_CTR_KA_TIMEOUT_MAX_MS    15000
#define CL_CTR_KA_DEV_K             4
#define CL_CTR_KA_MARGIN_STEP_MS    1000   /* added per false suspicion */
#define CL_CTR_KA_MARGIN_DECAY      256    /* -1/256 per keepalive: ~3 min to halve */
/* Local Health Multiplier (Lifeguard): this node's own trouble, 0..LHM_MAX;
 * scales its watchdog and purge window (not the election's) by LHM + 1 */
#define CL_CTR_LHM_MAX              8
#define CL_CTR_LHM_TIMEOUT_CAP_MS   (2 * CL_CTR_KA_TIMEOUT_MAX_MS)
#define CL_CTR_LATE_MS              1000   /* a loop gap this long is "late" */

/* the only traffic masters with divergent keys can both read: bounds split-brain
 * convergence to ~5 s while keeping bootstrap-key use rare */
#define CL_CTR_MASTER_BEACON_EVERY  5   /* MASTER_ALIVE ticks between beacons (~5 s) */

/* split-brain prevention: at the join deadline a node that saw a higher-IP
 * starter defers (re-sending JOIN_REQ) so that one becomes the single master */
#define CL_CTR_JOIN_DEFER_SECS      1   /* seconds per deferral round               */
#define CL_CTR_JOIN_DEFER_MAX       4   /* consecutive deferrals for a *silent*      */
                                    /* higher-IP peer before we promote anyway  */
#define CL_CTR_JOIN_DEFER_HARDMAX  20   /* absolute cap on deferrals incl. resets - */
                                    /* a peer stuck joining can't stall forever */
#define CL_CTR_JOIN_REQ_MIN_US 500000   /* min microseconds between JOIN_REQ sends   */

/* ACK + bounded retransmit for 1:1 handshake packets only (group packets are
 * healed by the membership digest); the budget fits in one JOIN_REQ retry */
#define CL_CTR_RETX_INTERVAL_US  (CL_CTR_JOIN_REQ_MIN_US / 2)  /* 250 ms          */
#define CL_CTR_RETX_MAX_RETRIES  3      /* then drop it: an ACK never gates state */
#define CL_CTR_RETX_QUEUE_SZ     128  /* max outstanding unacked 1:1 packets      */
#if (CL_CTR_RETX_MAX_RETRIES * CL_CTR_RETX_INTERVAL_US) >= (CL_CTR_JOIN_DEFER_SECS * 1000000)
#error "retransmit budget must stay shorter than the JOIN_REQ retry interval"
#endif

/* membership digest in MASTER_ALIVE, [member_count 2B BE][set_hash 8B BE]: a
 * mismatch sends a RESYNC, the repair for a lost (multicast) NODE_ASSIGN */
#define CL_CTR_DIGEST_SZ      (2 + 8)
#define CL_CTR_RESYNC_MIN_US  1000000  /* member: min between RESYNCs; master:      */
                                       /* min between full-state re-broadcasts (1 s) */
/* MASTER_ALIVE liveness bitmap, a bit per node_id seen in the election window:
 * non-masters unicast ALIVE to the master and refresh peers from this - O(N) */
#define CL_CTR_ALIVE_BITMAP_SZ  ((CL_CTR_MAX_PEERS / 8) + 1)
/* Mastership term (uint32 BE), carried after the bitmap in MASTER_ALIVE and
 * after the member count in MASTER_BEACON - see cl_ctr_master_outranks(). */
#define CL_CTR_TERM_SZ          4

/* Per-source-IP rate limiter: checked before decryption to shed floods cheaply.
 * Tracks up to CL_CTR_RATE_TBL_SZ source IPs with a 1-second sliding window. */
#define CL_CTR_RATE_TBL_SZ  256    /* one slot per peer; matches max cluster size */
#define CL_CTR_RATE_LIMIT    20    /* max packets per second per source IP        */
/* consumer packets/s per source, counted apart from control traffic so
 * neither class can starve the other */
#define CL_CTR_CONSUMER_RATE_DEFAULT 1000
/* resends of an unACKed consumer message and the gap between them; modest on
 * purpose, both per-cluster overridable */
#define CL_CTR_CONSUMER_RETRIES_DEFAULT   2
#define CL_CTR_CONSUMER_RETRY_MS_DEFAULT 40

typedef struct {
    uint32_t ip;           /* network byte order; 0 = empty slot */
    time_t   window_start;
    int      count;
    int      consumer_count;
} cl_ctr_rate_entry_t;

/* A refusal anyone on the group can provoke is reported once a minute, with
 * the count it stands for, not once a datagram (worker-local). */
typedef struct {
    unsigned long pkts;          /* refused so far                      */
    unsigned long pkts_reported; /* of which a report already counted   */
    time_t        reported_at;   /* 0: never                            */
} cl_ctr_warn_t;

#define CL_CTR_SMALL_PKT_SZ      (CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_MAX_IP_LEN + 1 + CL_CTR_TAG_SZ)
/* settings that must match cluster-wide, advertised in ALIVE:
 * manage_shtags 1B, master_stickiness 1B, query_time 2B BE */
#define CL_CTR_CONFIG_SZ          4
/* cluster-plane MTU, 2B BE in JOIN_REQ/ALIVE: checked always, not by
 * on_config_mismatch; 0 = older build, admitted with a warning (rolling upgrade) */
#define CL_CTR_MTU_SZ             2
#define CL_CTR_PROPOSAL_SZ        2   /* JOIN_REQ: the node id the joiner asks for */
/* consecutive polls off the joined MTU before the link counts as changed: a bond
 * failover or driver reset can show a transient value (~15 s at query_time=5) */
#define CL_CTR_MTU_DRIFT_STRIKES  3
/* Distinct peers a master may refuse on MTU before it says out loud that IT is
 * the likely misconfiguration.  See cl_ctr_mtu_note_reject(). */
#define CL_CTR_MTU_SUSPECT_PEERS  2
/* same for the config gate: a memberless master refusing this many peers is
 * probably the misconfigured one (cl_ctr_cfg_note_reject()) */
#define CL_CTR_CFG_SUSPECT_PEERS  2
/* unreadable MTU polls between complaints after the first (~1/min at query_time=5) */
#define CL_CTR_MTU_READ_FAIL_LOUD 12
/* Noise NNpsk0: msg1 = ephemeral + tag (empty payload), msg2 = ephemeral +
 * AEAD(master_salt) */
#define CL_CTR_NOISE_MSG1_SZ     (32 + CL_CTR_TAG_SZ)
#define CL_CTR_NOISE_MSG2_SZ     (32 + CL_CTR_MASTER_SALT_SZ + CL_CTR_TAG_SZ)
/* JOIN_REQ: [ip NUL][bin_count 1B][sockets...][noise_msg1][config][mtu][proposal] */
#define CL_CTR_JOIN_PKT_MAX_SZ   (CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_MAX_IP_LEN + 1 \
                              + CL_CTR_BIN_INFO_MAX_SZ + CL_CTR_NOISE_MSG1_SZ \
                              + CL_CTR_CONFIG_SZ + CL_CTR_MTU_SZ + CL_CTR_PROPOSAL_SZ \
                              + CL_CTR_TAG_SZ)
/* KEY_GRANT: [target_ip NUL][noise_msg2 80B] */
#define CL_CTR_KEY_GRANT_SZ      (CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_MAX_IP_LEN + 1 \
                              + CL_CTR_NOISE_MSG2_SZ + CL_CTR_TAG_SZ)
/* KEY_HANDOFF: [target_ip NUL][crypto_box_seal(master_salt)] */
#define CL_CTR_KEY_HANDOFF_SZ    (CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_MAX_IP_LEN + 1 \
                              + crypto_box_SEALBYTES + CL_CTR_MASTER_SALT_SZ + CL_CTR_TAG_SZ)
/* NODE_ASSIGN: [node_id 2B][ip NUL][bin_count 1B][sockets...][incarnation 8B] */
#define CL_CTR_NODE_ASSIGN_MAX_SZ (CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_NODE_ID_SZ \
                               + CL_CTR_MAX_IP_LEN + 1 + CL_CTR_BIN_INFO_MAX_SZ \
                               + CL_CTR_INC_SZ + CL_CTR_TAG_SZ)
/* MEMBER_LIST stamp after the entries, [master term 4B BE][list seq 4B BE]:
 * applied only if newer than the last from that mastership */
#define CL_CTR_LIST_STAMP_SZ      8
/* over a 1500 MTU: fragmented locally (DF clear), so a firewall dropping UDP
 * fragments blocks joins; datagrams that fit go with DF set (Linux default) */
#define CL_CTR_LIST_PKT_MAX_SZ   (CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_LIST_COUNT_SZ \
                              + CL_CTR_NODE_ID_SZ /* forced-shtag node_id */ \
                              + CL_CTR_MAX_PEERS * CL_CTR_IP_ENTRY_SZ \
                              + CL_CTR_LIST_STAMP_SZ + CL_CTR_TAG_SZ)
/* Large enough to receive a fully reassembled UDP datagram (max 65507 bytes) */
#define CL_CTR_RECV_BUF_SZ       65536

/* ==== peer-table constants ==== */

#define CL_CTR_MAX_PEERS         256

#define CL_CTR_ELECT_FACTOR       3   /* x query_time; quantized: one cutoff for all */
#define CL_CTR_PURGE_FACTOR       6   /* x query_time; only when entries are freed */

/* ==== node-join state machine ==== */

typedef enum {
    CL_CTR_NODE_NEW    = 0,   /* sent JOIN_REQ, awaiting MEMBER_LIST or timeout */
    CL_CTR_NODE_ACTIVE = 1    /* fully participating, sends ALIVE               */
} cl_ctr_node_state_t;

/* ==== cluster table ==== */

#define CL_CTR_MAX_CLUSTERS  16  /* max cluster= entries */
/* Minimum seconds between the shared-port misdelivery warnings; the drop
 * they report can otherwise recur per packet. */
#define CL_CTR_FWD_WARN_IVL  30

typedef struct cl_ctr_peers_ cl_ctr_peers_t;

/* Noise handshake state; cl_ctr_cluster_t holds the initiator's half */
#define CL_CTR_NOISE_HASHLEN 32
typedef struct { unsigned char k[32]; uint64_t n; int has_key; } cl_ctr_cipherstate_t;
typedef struct {
    unsigned char    ck[CL_CTR_NOISE_HASHLEN];
    unsigned char    h[CL_CTR_NOISE_HASHLEN];
    cl_ctr_cipherstate_t cs;
} cl_ctr_symstate_t;

/* this node's role, tracked so cl_ctr_elect_master() logs each transition */
enum cl_ctr_role { CL_CTR_ROLE_MEMBER = 0, CL_CTR_ROLE_BACKUP, CL_CTR_ROLE_MASTER };

static inline const char *cl_ctr_role_name(int r)
{
    switch (r) {
    case CL_CTR_ROLE_MASTER: return "master";
    case CL_CTR_ROLE_BACKUP: return "backup";
    default:             return "member";
    }
}

/* one unACKed packet, kept sealed: a resend reuses its seq/nonce and the replay
 * window makes a receiver that had it just re-ACK; worker-local, no lock */
typedef struct {
    int                     used;
    uint32_t                seq;          /* packet seq, echoed by the ACK        */
    unsigned char           type;         /* packet type: matched against the ACK  */
    int                     retries_left;
    utime_t                 next_due_us;   /* get_uticks() deadline for next send  */
    /* gap to the next send: per entry, as handshake and consumer packets share
     * the queue at different cadences */
    utime_t                 retry_ivl_us;
    struct sockaddr_storage dest;         /* unicast destination                  */
    socklen_t               destlen;
    int                     pkt_len;      /* sealed length                        */
    /* a reliable broadcast: one multicast entry, only members still owing an
     * ACK (acked_map) repaired by unicast, addresses looked up at repair time */
    int                     is_bcast;
    uint8_t                 retries_cfg;  /* initial budget, to report the spend */
    uint16_t                expect_n;     /* members at send time            */
    uint16_t                acked_n;
    unsigned char           acked_map[(CL_CTR_MAX_PEERS + 7) / 8];
    unsigned char          *pkt;         /* cached sealed bytes, pkg, owned by
                                          * the entry; NULL when released    */
} cl_ctr_retx_entry_t;

/* per-cluster state: one per "cluster" modparam, each with its own worker */
typedef struct cl_ctr_cluster_ {
    int            cluster_id;
    char           multicast_address[INET_ADDRSTRLEN];
    int            multicast_port;
    struct sockaddr_in mcast_dest;   /* resolved once in cl_ctr_setup_socket */
    char           password[1025];
    unsigned char  key[32];         /* bootstrap key (Argon2id of the password) */
    unsigned char  session_key[32]; /* group key = HKDF(password, master_salt)     */
    int            manage_shtags; /* per-cluster override; defaults to global manage_shtags */
    /* Packets refused at the magic gate for carrying another wire version,
     * and when that was last reported (worker-local). */
    unsigned long  wire_refused_pkts;
    time_t         wire_warned_at;
    /* datagrams too short to be a packet, bootstrap packets that did not
     * decrypt, packets over the per-source rate limit (control, consumer) */
    cl_ctr_warn_t  warn_short, warn_bootstrap, warn_rate[2];
    /* uuid= from the cluster string (pinned identity), parsed at startup */
    unsigned char  cid_pin[CL_CTR_CID_SZ];
    int            cid_pinned;
    /* an id heard on an authenticated packet while we had none (worker) */
    unsigned char  heard_cid[CL_CTR_CID_SZ];
    int            heard_cid_set;
    time_t         foreign_warned_at;
    /* a master we will not merge into (it refused our admission), and until
     * when; plus when we last warned about a master whose settings differ */
    char           merge_refused_ip[INET_ADDRSTRLEN];
    time_t         merge_refused_until;
    time_t         merge_warned_at;
    /* consumer-plane policy per cluster, as links differ; -1 = unset, the global
     * default resolved in mod_init */
    int            consumer_retries;    /* extra sends of an unacked message */
    int            consumer_retry_ms;   /* gap between those sends           */
    int            consumer_rate;       /* per-source packets/s for consumers */
    int            master_stickiness; /* per-cluster override; -1 = inherit global */
    cl_ctr_peers_t    *peers;        /* per-cluster peer table in shm     */
    /* BIN socket resolved at mod_init - advertised in JOIN_REQ/NODE_ASSIGN */
    char           bin_socket[CL_CTR_MAX_BIN_SOCK_LEN]; /* "bin:IP:PORT"  */
    /* Worker-process fds and state - valid only inside cl_ctr_worker after fork */
    int            sock;               /* multicast UDP socket          */
    int            alive_tfd;          /* periodic ALIVE timer          */
    int            join_tfd;           /* one-shot join deadline        */
    int            rejoin_tfd;         /* 1-second JOIN_REQ retry       */
    int            master_alive_tfd;   /* master sends MASTER_ALIVE 1/s */
    int            master_dead_tfd;    /* non-master: fires on ka miss  */
    long long      master_heard_ms;    /* when the followed master was last heard */
    /* keepalive rhythm of the followed master (cl_ctr_ka_sample()), worker-local */
    char           ka_master[CL_CTR_MAX_IP_LEN + 1];
    long long      ka_last_ms;
    long long      ka_mean_ms;
    long long      ka_dev_ms;
    long long      ka_margin_ms;
    int            ka_samples;
    /* the maintenance state this worker last applied and announces */
    uint8_t        maint_adv;
    /* consecutive MASTER_ALIVEs whose liveness relay left this node out */
    int            unlisted;
    /* indirect probe before electing (cl_ctr_probe_step()), worker-local */
    int            probing;
    int            probe_heard;     /* answers: heard the master recently   */
    int            probe_silent;    /* answers: did not hear it either      */
    int            probe_peers;     /* live peers that could answer         */
    int            probe_quiet_rounds; /* rounds too few answered, this outage */
    /* PreVote (cl_ctr_arm_master_timers()): set once the followed master is
     * confirmed gone, so a mastership asserted now may raise the term */
    int            term_confirmed;
    /* isolation watch (cl_ctr_isolation_round()): live membership last held
     * steady, rounds below it, since when under half, tag released for it */
    uint16_t       stable_live;
    int            below_rounds;
    long long      isolated_since_ms;
    int            tag_released;
    /* LHM, trouble since the last ALIVE round, kernel drops already counted */
    int            lhm;
    int            lhm_trouble;
    unsigned long  lhm_drops_seen;
    char           probe_master[CL_CTR_MAX_IP_LEN + 1]; /* the master probed */
    long long      hold_since_ms;      /* when the current election hold began */
    int            identity_registered; /* 1 once update_identity called */
    int            shtag_bootstrapped;  /* -1 = eligible, 1 = done       */
    /* long-lived X25519 keypair, made in the worker after fork: advertised in
     * ALIVE, used for KEY_HANDOFF (Noise uses a fresh ephemeral) */
    unsigned char  my_privkey[CL_CTR_PUBKEY_SZ];
    unsigned char  my_pubkey[CL_CTR_PUBKEY_SZ];
    /* initiator state between our JOIN_REQ and KEY_GRANT; a new JOIN_REQ
     * overwrites it, so a grant for a superseded attempt fails to decrypt */
    cl_ctr_symstate_t  noise_hs;
    unsigned char  noise_e_priv[32];
    int            noise_hs_valid;   /* 1 after a JOIN_REQ, until KEY_GRANT/reset */
    /* nonces of our last JOIN_REQs: a JOIN_REJECT must echo one, as bootstrap
     * packets have no replay window */
    unsigned char  join_nonces[CL_CTR_JOIN_NONCES][CL_CTR_NONCE_SZ];
    int            join_nonces_n, join_nonce_next;
    /* nonces of recently accepted JOIN_REQs and beacons, to catch exact
     * repeats (cl_ctr_boot_replayed()) */
    unsigned char  boot_seen[CL_CTR_BOOT_SEEN][CL_CTR_NONCE_SZ];
    int            boot_seen_n, boot_seen_next;
    /* Set while a re-key JOIN_REQ is in flight; cleared on KEY_GRANT success
     * or master transition to prevent nonce stomping under packet flood.    */
    int            join_pending;
    /* set once a session key is generated or adopted; never act as master
     * before it, as no member could decrypt */
    int            have_session_key;
    /* Reliable-delivery queue for 1:1 handshake packets (worker-local, no lock).
     * retx_tfd sweeps it every CL_CTR_RETX_INTERVAL_US while retx_count > 0.    */
    int                 retx_tfd;
    int                 retx_count;
    /* Stall check (worker-local): a CL_CTR_STALL_TICK_MS tick, and when the
     * worker's loop last ran (cl_ctr_stall_check()). */
    int                 stall_tfd;
    long long           loop_seen_ms;
    /* after a stall, control traffic is not rate-limited until this time:
     * what arrives in a burst then is this node's own backlog */
    long long           rate_grace_until_ms;
    /* last_seen a stall check gave forgiven peers: one still at it was not
     * heard since and is not live (cl_ctr_live_count()) */
    time_t              forgiven_at;
    cl_ctr_retx_entry_t retx_q[CL_CTR_RETX_QUEUE_SZ];
    /* RESYNC and full-state throttles, CL_CTR_RESYNC_MIN_US each (worker-local) */
    utime_t             last_resync_us;
    utime_t             last_full_state_us;
    /* a coalesced full-state announcement still owed (master), flushed on the
     * keepalive tick: unlike a RESYNC, a join is not repeated by its sender */
    int                 full_state_pending;
    char                full_state_why[64];
    /* master: bootstrap-decrypt failures per source (worker-local); JOIN_REJECT
     * after CL_CTR_JOIN_FAIL_LIMIT */
    struct {
        uint32_t ip_num;
        char     ip[CL_CTR_MAX_IP_LEN + 1];
        int      count;
        int      rejected;   /* 1 = JOIN_REJECT already sent; suppress repeats */
    }              join_fail_tbl[CL_CTR_JOIN_FAIL_TABLE_SZ];
    /* Joiner-side auth-failure detection - no lock needed (worker-local). */
    int              bootstrap_auth_fails; /* consecutive bootstrap decrypt failures
                                             during CL_CTR_NODE_NEW; reset on KEY_GRANT */
    int              join_attempt_count;   /* rejoin_tfd fires since last KEY_GRANT  */
    /* undecryptable packets from others while NEW: only evidence of a wrong
     * password, so the join defers rather than terminates; KEY_GRANT resets it */
    int              auth_fail_pkts;
    /* join rounds deferred for failing to authenticate; shut down only after
     * CL_CTR_JOIN_DEFER_MAX, so a slow grant or noise cannot kill a good node */
    int              auth_defer_count;
    /* Per-source-IP rate limiter table - pkg_malloc'd in cl_ctr_worker after fork */
    cl_ctr_rate_entry_t  *rate_tbl;
    /* last shtag decision applied (-1 unknown, 0 backup, 1 active) and its
     * forced node_id, so the reason is logged only on a change */
    int              shtag_last_active;
    uint16_t         shtag_last_forced;
    /* Counts MASTER_ALIVE ticks so a beacon is emitted every
     * CL_CTR_MASTER_BEACON_EVERY of them.  Worker-local (master path only).       */
    unsigned int     beacon_tick;
    /* join-deadline deferrals to a higher-IP joiner; reset by each fresh
     * JOIN_REQ from it and on leaving NEW */
    int              join_defer_count;
    /* deferrals across those resets, capped by CL_CTR_JOIN_DEFER_HARDMAX */
    int              join_defer_total;
    /* the master whose KEY_GRANT we hold while joining ("" if none) and rounds
     * waited for its NODE_ASSIGN: proof a cluster exists, so wait, do not found */
    char             granted_by[CL_CTR_MAX_IP_LEN + 1];
    int              grant_wait_count;
    /* distinct peers refused on MTU as master, and whether we blamed ourselves
     * (cl_ctr_mtu_note_reject()) */
    uint32_t         mtu_reject_ips[CL_CTR_MTU_SUSPECT_PEERS * 2];
    int              mtu_reject_n;
    int              mtu_suspect_said;
    /* Same, for peers we have refused on config settings.  See
     * cl_ctr_cfg_note_reject() - the config analogue of the MTU one above. */
    uint32_t         cfg_reject_ips[CL_CTR_CFG_SUSPECT_PEERS * 2];
    int              cfg_reject_n;
    int              cfg_suspect_said;
    /* when our last JOIN_REQ went out (us), for the JOIN_REQ_MIN_US throttle;
     * 0 = never */
    utime_t          last_join_req_utime;
    /* set while our MASTER_ALIVE timer runs: cl_ctr_elect_master() keeps "armed
     * <=> elected", else a demoted node keeps broadcasting and peers flap */
    int              master_ka_armed;
    int              my_role;   /* enum cl_ctr_role, for transition logs */
} cl_ctr_cluster_t;

/* on_config_mismatch: a node's settings differ from a live master's */
#define CL_CTR_CFGMISMATCH_WARN    0   /* admit, log a warning */
#define CL_CTR_CFGMISMATCH_REJECT  1   /* JOIN_REJECT, the node shuts down (default) */
#define CL_CTR_CFGMISMATCH_ADOPT   2   /* adopt the master's settings at runtime */
/* JOIN_REJECT reason codes (1 byte after the target IP in the payload). */
#define CL_CTR_REJECT_GENERIC      0   /* wrong password / unauthorized / table full */
#define CL_CTR_REJECT_CONFIG       1   /* different cluster settings (reject policy)  */
#define CL_CTR_REJECT_MTU          2   /* different cluster-plane MTU (never optional) */

/* the MTU on the wire is 16 bits; clamp, as loopback reports 65536 */
static inline uint16_t cl_ctr_mtu_wire(int mtu)
{
    if (mtu <= 0)      return 0;
    if (mtu > 0xFFFF)  return 0xFFFF;
    return (uint16_t)mtu;
}

/* Outcome of a single MTU poll. */
#define CL_CTR_MTU_STEP_STEADY      0   /* reads what we joined at            */
#define CL_CTR_MTU_STEP_UNREADABLE  1   /* the read failed - nothing learned  */
#define CL_CTR_MTU_STEP_DRIFTING    2   /* differs, not yet confirmed         */
#define CL_CTR_MTU_STEP_CONFIRMED   3   /* differs, confirmed - stand down    */
#define CL_CTR_MTU_STEP_RECOVERED   4   /* agrees again after >=1 strike      */

/* ---- consumer messaging API (api.h) ----------------------------------- */

/* Channel registry: filled PRE-FORK by consumers' mod_init, inherited
 * read-only by every process afterwards - no lock needed. */
struct cl_ctr_channel {
    char            name[CLCTR_MAX_CHAN_LEN + 1];
    int             len;
    clctr_msg_cb_f  cb;
};

/* a send marshalled to the worker over IPC: keeps the seq space single-writer
 * and uses the worker-local socket and session key */
struct cl_ctr_consumer_job {
    cl_ctr_cluster_t *cl;
    uint16_t          dst_node_id;   /* 0 = multicast */
    int               flags;
    int               chan_len;
    int               payload_len;
    char              chan[CLCTR_MAX_CHAN_LEN];
    unsigned char     payload[];
};

/* ---- the script's own channel: clusterer's generic messaging, same
 * names, over this transport; wire [u8 kind][u8 tag_len][tag][message] ---- */
#define CL_CTR_SCRIPT_REQ  1
#define CL_CTR_SCRIPT_RPL  2

/* ==== peer table (shared memory) ==== */

/* anti-replay: high-water mark + circular bitmap (RFC 4303 A.2), so a resend or
 * reordered packet is accepted once; size > peak per-peer rate x retx horizon */
#define CL_CTR_REPLAY_WIN_BITS   1024   /* ~12,800 msg/s at the consumer defaults */
#define CL_CTR_REPLAY_WIN_WORDS  (CL_CTR_REPLAY_WIN_BITS / 64)
/* largest forward step believed (serial arithmetic, as 32-bit seqs wrap): well
 * above any loss burst, well below 2^31 where a replay would read as fresh */
#define CL_CTR_REPLAY_MAX_JUMP   (1u << 24)

/* forward jumps in a row, each within a window of the last, that re-anchor
 * the window: a live stream, as replays land behind the mark */
#define CL_CTR_REPLAY_REANCHOR   3

typedef struct {
    uint32_t last;                            /* highest seq accepted so far  */
    uint64_t win[CL_CTR_REPLAY_WIN_WORDS];    /* circular, slot = seq % BITS  */
    int      anchored;                        /* 0: the next packet sets last */
    uint32_t jump_seq;                        /* the last refused forward jump */
    int      jumps;                           /* ... and how many in a row     */
} cl_ctr_replay_t;

#define CL_CTR_RP_WORD(s)  ((((uint32_t)(s)) % CL_CTR_REPLAY_WIN_BITS) / 64)
#define CL_CTR_RP_MASK(s)  (1ULL << ((((uint32_t)(s)) % CL_CTR_REPLAY_WIN_BITS) % 64))

/* cl_ctr_check_and_update_seq() verdicts: DUP must be re-ACKed on the reliable
 * path, OLD must not */
#define CL_CTR_SEQ_OK     0   /* fresh: accept and deliver                    */
#define CL_CTR_SEQ_DUP  (-1)  /* inside the window, bit already set: drop     */
#define CL_CTR_SEQ_OLD  (-2)  /* below the window: unknown if we ever had it  */
#define CL_CTR_SEQ_JUMP (-3)  /* implausibly far ahead: wrapped replay or     */
                              /* far too much loss - refuse either way        */
#define CL_CTR_SEQ_STALE (-4) /* from an earlier incarnation of the sender    */

/* start afresh (sender restarted or first learned, new key): unanchored, so the
 * next packet sets the mark whatever its seq, not refused as a jump from 0 */
static inline void cl_ctr_replay_reset(cl_ctr_replay_t *r)
{
    r->last     = 0;
    memset(r->win, 0, sizeof r->win);
    r->anchored = 0;
    r->jumps    = 0;
}

/* accept @seq at most once; not thread-safe, only the cluster's worker calls it */
static inline int cl_ctr_replay_check(cl_ctr_replay_t *r, uint32_t seq)
{
    int32_t  fwd = (int32_t)(seq - r->last);   /* serial-number difference */
    uint32_t d, s;

    if (!r->anchored) {                  /* first packet since a reset        */
        memset(r->win, 0, sizeof r->win);
        r->last     = seq;
        r->anchored = 1;
        r->jumps    = 0;
        r->win[CL_CTR_RP_WORD(seq)] |= CL_CTR_RP_MASK(seq);
        return CL_CTR_SEQ_OK;
    }

    if (fwd > 0) {                       /* forward: the common case          */
        d = (uint32_t)fwd;
        if (d >= CL_CTR_REPLAY_MAX_JUMP) {
            /* refused, unless REANCHOR close jumps in a row show the mark is
             * wrong (e.g. set by a replayed old packet first after a reset) */
            if (r->jumps > 0 && (uint32_t)(seq - r->jump_seq) - 1
                                    < CL_CTR_REPLAY_WIN_BITS)
                r->jumps++;
            else
                r->jumps = 1;
            r->jump_seq = seq;
            if (r->jumps < CL_CTR_REPLAY_REANCHOR)
                return CL_CTR_SEQ_JUMP;
            r->anchored = 0;
            return cl_ctr_replay_check(r, seq);
        }
        r->jumps = 0;
        if (d >= CL_CTR_REPLAY_WIN_BITS) {
            memset(r->win, 0, sizeof r->win);
        } else {
            /* clear the slots the window moved onto: they hold bits of seqs
             * a full window older */
            for (s = r->last + 1; s != seq; s++)
                r->win[CL_CTR_RP_WORD(s)] &= ~CL_CTR_RP_MASK(s);
            r->win[CL_CTR_RP_WORD(seq)] &= ~CL_CTR_RP_MASK(seq);
        }
        r->last = seq;
        r->win[CL_CTR_RP_WORD(seq)] |= CL_CTR_RP_MASK(seq);
        return CL_CTR_SEQ_OK;
    }

    /* At or below the mark.  Unsigned subtraction gives the exact backward
     * distance even across a wrap, and avoids negating INT32_MIN. */
    d = r->last - seq;
    if (d >= CL_CTR_REPLAY_WIN_BITS)
        return CL_CTR_SEQ_OLD;
    if (r->win[CL_CTR_RP_WORD(seq)] & CL_CTR_RP_MASK(seq))
        return CL_CTR_SEQ_DUP;

    r->win[CL_CTR_RP_WORD(seq)] |= CL_CTR_RP_MASK(seq);
    return CL_CTR_SEQ_OK;
}

typedef struct cl_ctr_peer_ {
    char         ip[CL_CTR_MAX_IP_LEN + 1];
    unsigned int ip_num;
    time_t       last_seen;
    int          is_master;
    int          is_backup;   /* 1 = standby master (highest-IP non-master) */
    int          in_election; /* 1 = currently inside the election window  */
    uint16_t     node_id;     /* allocated by master; 0 = not yet assigned */
    uint8_t      maint;       /* CL_CTR_MAINT_*: as the node announced it  */
    uint32_t     caps;        /* CL_CTR_CAP_* from its ALIVE (first-hand on the
                                 master); 0 = none, older build or not heard */
    uint8_t      bin_count;   /* number of BIN listeners reported          */
    char         bin_sockets[CL_CTR_MAX_BIN_SOCKETS][CL_CTR_MAX_BIN_SOCK_LEN];
    unsigned char pubkey[CL_CTR_PUBKEY_SZ];           /* long-lived X25519 pubkey (from ALIVE);
                                                     zero if unknown; used for KEY_HANDOFF */
    cl_ctr_replay_t replay;                        /* control-plane anti-replay */
    /* the consumer plane's own window: a reordered consumer packet must not
     * make a MASTER_ALIVE behind it look like a replay */
    cl_ctr_replay_t replay_consumer;
    /* The sender incarnation both windows above belong to; 0 = not seen yet. */
    uint64_t      incarnation;
    /* settings advertised in its ALIVE; cfg_known 0 until heard, cfg_warned
     * dedups the mismatch warning */
    int           cfg_known;
    int           cfg_manage_shtags;
    int           cfg_master_stickiness;
    int           cfg_query_time;
    int           cfg_warned;
    /* Peer's advertised cluster-plane MTU (0 = never advertised, i.e. a build
     * older than the field).  mtu_warned deduplicates the drift warning. */
    int           mtu;
    int           mtu_warned;
} cl_ctr_peer_t;

/* a node_id held for the member that last used it, so it keeps its id across a
 * restart: a new id re-adds it in clusterer and misdirects a forced sharing tag */
typedef struct {
    char     ip[CL_CTR_MAX_IP_LEN + 1];   /* "" = free slot             */
    uint16_t node_id;
    time_t   until;                       /* held until this time      */
} cl_ctr_id_resv_t;
#define CL_CTR_ID_RESERVE_SECS   3600

struct cl_ctr_peers_ {
    cl_ctr_peer_t       entries[CL_CTR_MAX_PEERS];
    int             count;
    /* rw_lock_t allows concurrent readers (MI, future script functions)
     * while still serialising the single writer (cl_ctr_worker).            */
    rw_lock_t      *lock;
    cl_ctr_node_state_t node_state;
    time_t          join_deadline;
    /* last elected master IP - used to detect and log master changes */
    char            last_master[CL_CTR_MAX_IP_LEN + 1];
    /* master_salt: generated by each new master, shared here so mod_destroy
     * (running in main process) can derive session_key for GOODBYE.    */
    unsigned char   master_salt[CL_CTR_MASTER_SALT_SZ];
    /* control-plane send counter, in shm so mod_destroy's GOODBYE continues it */
    uint32_t        my_seq;
    uint32_t        my_consumer_seq;   /* the consumer plane's own counter */
    /* 0 = automatic shtag allocation, else the node_id forced active by
     * clusterer:shtag_force until shtag_auto; carried in MEMBER_LIST */
    uint16_t        shtag_forced_node_id;
    /* this node's maintenance state as requested (MI or script, any
     * process); the worker applies and announces it (cl_ctr_maint_sync()) */
    uint8_t         my_maint;
    /* mastership terms (cl_ctr_master_outranks()), written by the worker only */
    uint32_t        term_seen;        /* highest heard from any master */
    uint32_t        my_term;          /* of our own mastership; 0 = not master */
    uint32_t        master_term;      /* as the followed master announced */
    uint16_t        master_count;     /* ... and its member count */
    uint16_t        master_live;      /* its live count; 0 = not announced */
    /* ids held for departed members (cl_ctr_reserve_id_locked()), kept by every
     * node so the next master has them */
    cl_ctr_id_resv_t id_resv[CL_CTR_MAX_PEERS];
    /* This cluster's founded identity (see CL_CTR_CID_*), in shm so the
     * GOODBYE sent from mod_destroy carries it and MI can report it. */
    unsigned char   cid[CL_CTR_CID_SZ];
    int             cid_state;
    time_t          cid_since;
    unsigned long   foreign_pkts;     /* refused for carrying another id */
    /* new addresses turned away because the peer table was full, and when
     * that was last logged (see cl_ctr_upsert_peer_locked()) */
    unsigned long   peers_refused;
    time_t          peers_refused_warned_at;
    /* times this node's own worker was found stalled, and the longest stall */
    unsigned long   self_stalls;
    long long       self_stall_max_ms;
    /* terms refused as absurd jumps (cl_ctr_term_sane()) and when that was
     * last logged */
    unsigned long   terms_refused;
    time_t          terms_refused_warned_at;
    unsigned long   election_holds;   /* elections held: peers still heard the master */
    /* the keepalive rhythm learned of the master followed, for MI */
    int             ka_mean_ms, ka_dev_ms, ka_margin_ms, ka_timeout_ms;
    unsigned long   ka_false_suspicions;
    int             local_health;     /* this node's LHM, for MI */
    int             tag_released;     /* the active tag released while cut off */
    /* the receive buffer the kernel granted, and datagrams it dropped for
     * this socket because that buffer was full (SO_RXQ_OVFL, cumulative) */
    int             rcvbuf_bytes;
    unsigned long   rx_kernel_drops;
    time_t          rx_drops_warned_at;
    struct {
        unsigned char uuid[CL_CTR_CID_SZ];
        char          last_ip[CL_CTR_MAX_IP_LEN + 1];
        time_t        first_seen, last_seen;
        unsigned long pkts;
    }               foreign[CL_CTR_FOREIGN_MAX];
    int             foreign_n;
    time_t          foreign_new_logged_at;
    /* MEMBER_LIST ordering: the sequence this node stamps on the lists it
     * sends as master, and the (term, seq) of the last list it applied. */
    uint32_t        list_seq;
    uint32_t        list_term_seen;
    uint32_t        list_seq_seen;
    /* process index of this cluster's worker, for ipc_send_rpc() from MI;
     * -1 until set */
    int             worker_proc_no;
    /* settings in force (after on_config_mismatch=adopt), mirrored by the
     * worker for MI in other processes */
    int             eff_manage_shtags;
    int             eff_master_stickiness;
    int             eff_query_time;
    /* CL_CTR_CAP_* all live members share, relayed by the master in
     * MASTER_ALIVE; 0 from an older master (cl_ctr_caps.c) */
    uint32_t        cluster_caps;
    /* counters for the statistics (cl_ctr_stats.c); the worker is their
     * one writer, through the cl_ctr_note_*() calls */
    unsigned long   st_master_changes;  /* the master changed, as this node saw it */
    unsigned long   st_role_changes;    /* this node's own role changed      */
    unsigned long   st_members_joined;  /* nodes entering this node's table  */
    unsigned long   st_members_left;    /* ... and leaving it                */
    unsigned long   st_joins_refused;   /* JOIN_REJECTs sent as master       */
    unsigned long   st_config_mismatches;
    unsigned long   st_auth_failures;   /* packets failing authentication    */
    unsigned long   st_merges;          /* partitions left for a superior one */
};

#define cl_ctr_send_alive(sock, cl)    cl_ctr_send_pkt_with_ip((sock), CL_CTR_PKT_ALIVE, (cl), NULL, 0)
#define cl_ctr_send_alive_to(sock, cl, dest, dlen) \
        cl_ctr_send_pkt_with_ip((sock), CL_CTR_PKT_ALIVE, (cl), (dest), (dlen))
#define cl_ctr_send_join_req(sock, cl) cl_ctr_send_join_req_pkt((sock), (cl))

#define cl_ctr_send_member_list(sock, cl) cl_ctr_send_list_pkt((sock), CL_CTR_PKT_MEMBER_LIST, (cl), NULL, 0)

#define CL_CTR_PV_WRAP(_fn, _field) \
int _fn(struct sip_msg *msg, pv_param_t *param, pv_value_t *res) \
{ return cl_ctr_pv_get(msg, param, res, _field); }


/* ==== shared between the module's source files ==== */

/* cl_ctr_mod.c - the parameters are in cl_ctr_mod.h */
extern cl_ctr_cluster_t cl_ctr_clusters[CL_CTR_MAX_CLUSTERS];
extern int cl_ctr_cluster_count;
extern int on_config_mismatch;
extern const char *my_ip_src;
extern char my_interface_buf[IF_NAMESIZE];
extern uint16_t my_node_id;
extern uint64_t cl_ctr_incarnation;
extern struct clusterer_binds cl_api;     /* the public clusterer API */
extern int cl_api_loaded;
extern int clctl_loaded;

/* cl_ctr_crypto.c */
int cl_ctr_random_bytes(unsigned char *buf, size_t len);
int cl_ctr_hkdf_sha256(const unsigned char *ikm,  size_t ikm_len,
                           const unsigned char *salt, size_t salt_len,
                           const char          *info,
                           unsigned char        out[32]);
int cl_ctr_gen_ecdh_keypair(unsigned char *privkey, unsigned char *pubkey);
int cl_ctr_noise_write1(cl_ctr_symstate_t *s, unsigned char e_priv[32],
                           const unsigned char psk[32],
                           const unsigned char *payload, size_t pl_len,
                           unsigned char *out);
int cl_ctr_noise_respond(const unsigned char psk[32],
                            const unsigned char *msg1, size_t msg1_len,
                            const unsigned char *payload, size_t pl_len,
                            unsigned char *out);
int cl_ctr_noise_read2(cl_ctr_symstate_t *s, const unsigned char e_priv[32],
                          const unsigned char *msg2, size_t msg2_len,
                          unsigned char *payload_out);
int cl_ctr_derive_session_key(cl_ctr_cluster_t *cl);
int cl_ctr_derive_key(cl_ctr_cluster_t *cl);
int cl_ctr_encrypt_pkt(char *buf, int plain_off, int plain_len,
                          const unsigned char *key, int cluster_id,
                          const unsigned char *cid);
int cl_ctr_decrypt_pkt(char *buf, ssize_t n, const char *sender_ip,
                          const unsigned char *key, int is_bootstrap);

/* cl_ctr_wire.c */
extern const unsigned char CL_CTR_PACKET_MAGIC[CL_CTR_MAGIC_SZ];
extern const unsigned char CL_CTR_BOOTSTRAP_MAGIC[CL_CTR_MAGIC_SZ];
extern const unsigned char CL_CTR_CONSUMER_MAGIC[CL_CTR_MAGIC_SZ];
extern int cc_max_payload;
extern int cc_mtu;
extern int cc_mtu_now;
extern int cc_mtu_drift_strikes;
extern int cc_mtu_read_fails;
int cl_ctr_read_iface_mtu(void);
int cl_ctr_mtu_step(int now_mtu, int joined_mtu, int *strikes, int *fails);
int cl_ctr_check_and_update_seq(const char *sender_ip, uint32_t pkt_seq,
                                   uint64_t pkt_inc, cl_ctr_cluster_t *cl,
                                   int is_consumer);
int cl_ctr_setup_socket(cl_ctr_cluster_t *cl);
int cl_ctr_seal_and_send_to(int sock, cl_ctr_cluster_t *cl, char *pkt,
                               int plain_len, const unsigned char *key,
                               unsigned char type,
                               const struct sockaddr *dest, socklen_t destlen);
int cl_ctr_seal_and_send(int sock, cl_ctr_cluster_t *cl, char *pkt, int plain_len,
                            const unsigned char *key, unsigned char type);
void cl_ctr_send_ack(int sock, cl_ctr_cluster_t *cl, uint32_t acked_seq,
                        unsigned char acked_type, int use_bootstrap,
                        const struct sockaddr *dest, socklen_t destlen);
void cl_ctr_send_pkt_with_ip(int sock, unsigned char type, cl_ctr_cluster_t *cl,
                                const struct sockaddr *dest, socklen_t destlen);
void cl_ctr_send_list_pkt(int sock, unsigned char type, cl_ctr_cluster_t *cl,
                             const struct sockaddr *dest, socklen_t destlen);
void cl_ctr_send_join_req_pkt(int sock, cl_ctr_cluster_t *cl);
void cl_ctr_send_node_assign(int sock, const char *ip, uint16_t node_id,
                                uint8_t bin_count,
                                const char (*bin_sockets)[CL_CTR_MAX_BIN_SOCK_LEN],
                                uint64_t inc, cl_ctr_cluster_t *cl,
                                const struct sockaddr *dest, socklen_t destlen);
void cl_ctr_sockaddr_in(const char *ip, int port, struct sockaddr_in *out);
void cl_ctr_send_master_alive(int sock, cl_ctr_cluster_t *cl);
void cl_ctr_send_resync(int sock, cl_ctr_cluster_t *cl,
                           const struct sockaddr *dest, socklen_t destlen);
void cl_ctr_send_master_beacon(int sock, cl_ctr_cluster_t *cl);
void cl_ctr_send_key_grant(int sock, const char *target_ip, cl_ctr_cluster_t *cl,
                              const unsigned char *msg1, int msg1_len,
                              const struct sockaddr *dest, socklen_t destlen);
void cl_ctr_send_key_handoff(int sock, const char *next_master_ip,
                                const unsigned char *next_master_pubkey,
                                cl_ctr_cluster_t *cl);

/* cl_ctr_reliable.c */
extern int cl_ctr_retx_pkt_max;   /* max(NODE_ASSIGN, MTU-derived consumer pkt) */
void cl_ctr_retx_flush(cl_ctr_cluster_t *cl);
void cl_ctr_retx_enqueue_bcast(cl_ctr_cluster_t *cl, uint32_t seq,
                            const unsigned char *pkt, int pkt_len);
void cl_ctr_retx_enqueue_consumer(cl_ctr_cluster_t *cl, uint32_t seq,
                            unsigned char type, const unsigned char *pkt,
                            int pkt_len, const struct sockaddr *dest,
                            socklen_t destlen);
void cl_ctr_retx_enqueue(cl_ctr_cluster_t *cl, uint32_t seq, unsigned char type,
                            const unsigned char *pkt, int pkt_len,
                            const struct sockaddr *dest, socklen_t destlen);
void cl_ctr_handle_ack(const char *payload, int payload_len,
                              cl_ctr_cluster_t *cl, const char *sender_ip);
int cl_ctr_on_retx_tfd(int fd, void *param, int was_timeout);

/* cl_ctr_peers.c */
int cl_ctr_find_peer(int cid, int nid, int *is_master, int *is_backup,
                        int *maint, char *ipbuf, int ipbuf_sz);
unsigned int ip_to_num(const char *ip);
int cl_ctr_ip_valid(const char *ip);
int cl_ctr_node_addr(const cl_ctr_cluster_t *cl, const char *ip,
                     struct sockaddr_in *to);
void cl_ctr_prune_stale(cl_ctr_cluster_t *cl);
void cl_ctr_apply_master_from_list_locked(const char *master_ip, cl_ctr_cluster_t *cl);
cl_ctr_peer_t *cl_ctr_peer_by_ip_locked(cl_ctr_cluster_t *cl, const char *ip);
void cl_ctr_learn_peer_locked(const char *src_ip, cl_ctr_cluster_t *cl);
void cl_ctr_upsert_peer_locked(const char *src_ip, cl_ctr_cluster_t *cl);
void cl_ctr_reserve_id_locked(cl_ctr_cluster_t *cl, const char *ip,
                                     uint16_t node_id);
uint16_t cl_ctr_alloc_node_id_locked(cl_ctr_cluster_t *cl, const char *ip,
                                     uint16_t proposal);
void cl_ctr_update_peer_bin_locked(const char *ip, uint16_t node_id,
                                      uint8_t bin_count,
                                      const char (*bin_sockets)[CL_CTR_MAX_BIN_SOCK_LEN],
                                      cl_ctr_cluster_t *cl);
const char *cl_ctr_cid_state_name(int st);
void cl_ctr_cid_str(const unsigned char *cid, char *out);
int cl_ctr_cid_is_zero(const unsigned char *cid);
int cl_ctr_cid_parse_pin(const char *v, unsigned char *out);
void cl_ctr_cid_adopt(cl_ctr_cluster_t *cl, const unsigned char *cid,
                             const char *how);
void cl_ctr_cid_found(cl_ctr_cluster_t *cl);
void cl_ctr_cid_tick(cl_ctr_cluster_t *cl);
void cl_ctr_membership_digest(cl_ctr_cluster_t *cl, uint16_t *count, uint64_t *hash);
uint16_t cl_ctr_live_count(cl_ctr_cluster_t *cl);
void cl_ctr_build_alive_bitmap(cl_ctr_cluster_t *cl, unsigned char *bm);
void cl_ctr_apply_alive_bitmap(cl_ctr_cluster_t *cl, const unsigned char *bm);
void cl_ctr_drop_peer_locked(const char *ip, cl_ctr_cluster_t *cl);

/* cl_ctr_election.c */
int cl_ctr_master_outranks(uint16_t c1, uint32_t t1, const char *ip1,
                                  uint16_t c2, uint32_t t2, const char *ip2);
void cl_ctr_note_term(cl_ctr_cluster_t *cl, uint32_t term);
int cl_ctr_term_sane(cl_ctr_cluster_t *cl, uint32_t term, const char *from);
const char *cl_ctr_maint_name(int st);
int  cl_ctr_maint_parse(const char *s, int len);
void cl_ctr_maint_sync(cl_ctr_cluster_t *cl);
void cl_ctr_rpc_maint(int sender, void *param);
int  cl_ctr_set_my_maint(cl_ctr_cluster_t *cl, int st);
int  cl_ctr_set_node_maint(cl_ctr_cluster_t *cl, uint16_t node_id, int st);
void cl_ctr_build_maint_bitmap(cl_ctr_cluster_t *cl, unsigned char *bm);
int  cl_ctr_apply_maint_bitmap(cl_ctr_cluster_t *cl, const unsigned char *bm,
                               const unsigned char *bm_full,
                               const char *master_ip);
void cl_ctr_build_maint_full_bitmap(cl_ctr_cluster_t *cl, unsigned char *bm);
void cl_ctr_maint_peer_changed(cl_ctr_cluster_t *cl, uint16_t node_id, int st);
void cl_ctr_maint_changed(cl_ctr_cluster_t *cl, uint16_t node_id, int old_st,
                          int st);
int  cl_ctr_send_maint_set(cl_ctr_cluster_t *cl, uint16_t node_id, int st);
void cl_ctr_handle_maint_set(const char *sender_ip, const char *payload,
                             int payload_len, cl_ctr_cluster_t *cl);
void cl_ctr_reelect_now(cl_ctr_cluster_t *cl, const char *why);
long long cl_ctr_master_timeout_ms(cl_ctr_cluster_t *cl);
void cl_ctr_arm_master_watchdog(cl_ctr_cluster_t *cl);
void cl_ctr_ka_sample(cl_ctr_cluster_t *cl, const char *master_ip);
void cl_ctr_ka_false_suspicion(cl_ctr_cluster_t *cl, const char *why);
void cl_ctr_lhm_event(cl_ctr_cluster_t *cl, const char *why);
void cl_ctr_lhm_round(cl_ctr_cluster_t *cl);
void cl_ctr_isolation_round(cl_ctr_cluster_t *cl, int i_am_master);
void cl_ctr_send_master_probe(cl_ctr_cluster_t *cl, const char *master_ip);
void cl_ctr_send_master_probe_ack(cl_ctr_cluster_t *cl, const char *master_ip,
                                  uint32_t heard_ms_ago,
                                  const struct sockaddr *dest, socklen_t destlen);
void cl_ctr_handle_master_probe(const char *sender_ip, const char *payload,
                                int payload_len, cl_ctr_cluster_t *cl,
                                const struct sockaddr *src, socklen_t src_len);
void cl_ctr_handle_master_probe_ack(const char *sender_ip, const char *payload,
                                    int payload_len, cl_ctr_cluster_t *cl);
void cl_ctr_elect_master(cl_ctr_cluster_t *cl);
int cl_ctr_i_am_master_locked(cl_ctr_cluster_t *cl);
int cl_ctr_ip_beats_master_locked(unsigned int ip_num, cl_ctr_cluster_t *cl);
void cl_ctr_apply_shtags_decision(cl_ctr_cluster_t *cl, int i_am_master,
                                     uint16_t forced);
void cl_ctr_apply_shtags(cl_ctr_cluster_t *cl);
void cl_ctr_on_became_master(cl_ctr_cluster_t *cl);
void cl_ctr_arm_master_timers(cl_ctr_cluster_t *cl, int i_am_master);
void cl_ctr_request_rekey(cl_ctr_cluster_t *cl);

/* cl_ctr_join.c */
void cl_ctr_transition_to_active(cl_ctr_cluster_t *cl);
void cl_ctr_fmt_cfg_diff(char *out, int outsz, const char *la, const char *lb,
                            int a_manage, int b_manage, int a_stick, int b_stick,
                            int a_qt, int b_qt);
void cl_ctr_adopt_config(cl_ctr_cluster_t *cl, int new_manage, int new_stick,
                            int new_qt, int is_active);
void cl_ctr_handle_join_req(int sock, const char *payload, int payload_len,
                               uint64_t pkt_inc, const unsigned char *req_nonce,
                               const char *sender_ip, cl_ctr_cluster_t *cl,
                               const struct sockaddr *src, socklen_t src_len);
void cl_ctr_handle_member_list(const char *payload, int payload_len,
                                  const char *sender_ip, cl_ctr_cluster_t *cl);
void cl_ctr_handle_node_assign(const char *payload, int payload_len,
                                  const char *sender_ip, cl_ctr_cluster_t *cl);
void cl_ctr_handle_key_grant(const char *payload, int payload_len,
                                const char *sender_ip, cl_ctr_cluster_t *cl,
                                uint32_t in_seq, const unsigned char *pkt_cid,
                                const struct sockaddr *src, socklen_t src_len);
void cl_ctr_handle_key_handoff(const char *payload, int payload_len,
                                  const char *sender_ip, cl_ctr_cluster_t *cl);
int cl_ctr_join_fail_check(const char *src_ip, cl_ctr_cluster_t *cl);
void cl_ctr_send_join_reject(int sock, const char *target_ip, cl_ctr_cluster_t *cl,
                                int reason, const unsigned char *req_nonce);
void cl_ctr_handle_join_reject(const char *payload, int payload_len,
                                   const char *sender_ip, cl_ctr_cluster_t *cl);

/* cl_ctr_liveness.c */
void cl_ctr_announce_full_state(cl_ctr_cluster_t *cl, const char *why);
void cl_ctr_handle_resync(const char *sender_ip, cl_ctr_cluster_t *cl);
void cl_ctr_handle_alive(const char *src_ip,
                            const unsigned char *pubkey, /* may be NULL */
                            int cfg_present, int peer_manage,
                            int peer_stick, int peer_qt,
                            int peer_mtu, int peer_maint,
                            uint32_t peer_caps,
                            cl_ctr_cluster_t *cl);
void cl_ctr_handle_goodbye(int sock, const char *src_ip, cl_ctr_cluster_t *cl);
void cl_ctr_handle_master_alive(const char *sender_ip, cl_ctr_cluster_t *cl,
                                   const char *payload, int payload_len,
                                   const struct sockaddr *src, socklen_t src_len);
void cl_ctr_handle_master_beacon(const char *sender_ip, const char *payload,
                                    int payload_len, cl_ctr_cluster_t *cl);

/* cl_ctr_recv.c */
void cl_ctr_recv_one(int sock, cl_ctr_cluster_t *cl,
                        const char *fwd_buf, int fwd_n,
                        const struct sockaddr_in *fwd_src);

/* cl_ctr_worker.c */
uint64_t cl_ctr_drain_tfd(int tfd);
void cl_ctr_arm_tfd(int tfd, time_t sec_value, time_t sec_interval);
void cl_ctr_worker(int rank);

/* cl_ctr_script.c */
extern char *cl_ctr_script_buf;
extern int cl_ctr_script_buf_sz;
int cl_ctr_script_init(void);

/* cl_ctr_consumer.c */
extern char *cl_ctr_consumer_pkt;
extern int cl_ctr_consumer_pkt_sz;
void cl_ctr_handle_consumer(const char *payload, int payload_len,
        const char *src_ip, cl_ctr_cluster_t *cl);
int clctr_register_channel(str *channel, clctr_msg_cb_f cb);
int clctr_send_mcast(int cluster_id, str *channel, str *payload,
        int flags);
int clctr_send_list(int cluster_id, const int *node_ids, int n,
                           str *channel, str *payload, int flags, int *unknown);
int clctr_send_ucast(int cluster_id, int node_id, str *channel,
        str *payload, int flags);

#endif /* CL_CTR_H */
