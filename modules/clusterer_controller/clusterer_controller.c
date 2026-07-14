/*
 * clusterer_controller - multicast extension for the clusterer module
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
 * =========================================================================
 * MODULE: clusterer_controller
 * =========================================================================
 *
 * PROTOCOL OVERVIEW
 * -----------------
 * All traffic is UDP multicast to multicast_address:multicast_port.  Every
 * packet's payload is encrypted and authenticated with an AEAD.  The cleartext
 * framing that precedes it - a 2-byte magic (key selector, must be readable
 * before decryption) and a 2-byte cluster_id - is bound into the AEAD tag as
 * additional authenticated data (AAD), so it cannot be altered undetected (this
 * blocks re-stamping a captured packet onto a different cluster_id when two
 * clusters share a multicast group and password).
 *
 * CRYPTO SUITE (build-time choice; every node in a cluster must match):
 *   - Default (WolfSSL):   AES-256-GCM   payload AEAD, 12-byte nonce;
 *                          scrypt        bootstrap-key KDF (N=2^16, r=8, p=1).
 *   - If libsodium is detected on the build host (-DCC_HAVE_SODIUM, see the
 *     Makefile): XChaCha20-Poly1305 payload AEAD, 24-byte nonce (its 192-bit
 *     nonce removes any random-nonce collision worry); Argon2id bootstrap KDF.
 *   The two wire formats are NOT interoperable (nonce size and primitives
 *   differ).  The active suite is logged at startup ("crypto=...").
 *
 * Two key types are used, selected by the 2-byte magic:
 *
 *   Bootstrap key - KDF(password, salt="...v1:"+multicast)  [scrypt or Argon2id]
 *     Used for the admission handshake (JOIN_REQ, KEY_GRANT, JOIN_REJECT) and
 *     the split-brain MASTER_BEACON - i.e. traffic that must be readable before
 *     a session key exists, or by masters holding different session keys.
 *     Memory-hard KDF (derived once at startup) so a password captured from a
 *     bootstrap packet cannot be brute-forced cheaply offline.
 *
 *   Session key   - HKDF-SHA256 over an X25519-ECDH-agreed random master_salt.
 *     Used for all normal traffic.  Generated once when the first node
 *     bootstraps the cluster and then preserved across every master change:
 *     a new master reuses the key that every member already holds, so master
 *     transitions require no re-keying.
 *
 * Wire format (all packets):
 *   [2B magic] [2B cluster_id] [12B|24B nonce] [ciphertext] [16B tag]
 *   AAD = magic || cluster_id.  A node drops packets whose cluster_id does not
 *   match its own BEFORE decryption, so foreign-cluster traffic sharing the
 *   group never counts as an authentication failure.
 *
 * Authenticated plaintext layout:
 *   [1B: packet type]  [4B: seq BE]  [payload]
 *
 * The 32-bit monotonic sequence number is per-sender and validated per source
 * IP for session-key packets.  Prevents replay without any dependency on clock
 * synchronisation.
 *
 * PACKET TYPES
 * ------------
 *   ALIVE         - session key, multicast
 *     Every active node every query_time seconds.
 *     Payload: IP(16B) + pubkey(32B).  Peers learn X25519 pubkeys here.
 *
 *   JOIN_REQ      - bootstrap key, multicast
 *     Sent by a new node on startup.
 *     Payload: IP(16B) + bin_info + pubkey(32B) + join_nonce(16B)
 *     join_nonce is random per-exchange; folded into the KEY_GRANT wrap key.
 *
 *   MEMBER_LIST   - session key, multicast
 *     Master -> all: member count, the operator-forced sharing-tag holder
 *     node_id (0 = automatic), and the full peer IP list, so all nodes elect
 *     identically.  Only accepted from the current master (CC_NODE_NEW aside).
 *
 *   GOODBYE       - session key, multicast
 *     Graceful shutdown.  Peers remove sender immediately without timeout.
 *
 *   NODE_ASSIGN   - session key, multicast
 *     Master -> all: allocate node_id + BIN socket for a joining node.
 *
 *   MASTER_ALIVE  - session key, multicast
 *     Master-only keepalive every CC_MASTER_KA_INTERVAL seconds.  Peers declare
 *     the master dead after CC_MASTER_KA_TIMEOUT seconds of silence and trigger
 *     re-election.  Two masters that share a session key resolve split-brain
 *     here: the lower-IP one yields.
 *
 *   KEY_GRANT     - bootstrap key, unicast to joiner
 *     Master reply to JOIN_REQ.
 *     Payload: IP(16B) + master_pubkey(32B) + join_nonce(16B) + wrapped_salt(32B)
 *     wrapped_salt = master_salt XOR HKDF(ECDH(shared) || password || join_nonce)
 *
 *   KEY_HANDOFF   - session key, unicast to next master
 *     Outgoing master on graceful shutdown -> next-highest-IP peer.  Transfers
 *     master_salt so the new master avoids a full re-join cycle.
 *     Payload: IP(16B) + sender_pubkey(32B) + wrapped_salt(32B)
 *
 *   JOIN_REJECT   - bootstrap key, multicast
 *     Master -> a source whose bootstrap packets repeatedly fail to decrypt
 *     (wrong password).  Encrypted, so only a correctly-configured node can
 *     read it; a wrong-password joiner also self-terminates at its deadline.
 *
 *   MASTER_BEACON - bootstrap key, multicast
 *     Master-only, every CC_MASTER_BEACON_EVERY keepalive ticks.  Because it
 *     uses the bootstrap key it is readable even by a master holding a
 *     DIFFERENT session key, which is how a split brain between independently
 *     bootstrapped partitions is detected and merged.  Payload: member count.
 *
 * NODE STATE MACHINE
 * ------------------
 *   CC_NODE_NEW --> (MEMBER_LIST or KEY_GRANT received) --> CC_NODE_ACTIVE
 *               --> (join_deadline expired)             --> CC_NODE_ACTIVE
 *
 *   CC_NODE_NEW:    receive only; do NOT send ALIVE or MASTER_ALIVE.
 *   CC_NODE_ACTIVE: send ALIVE every query_time seconds.
 *                   Master also sends MASTER_ALIVE every CC_MASTER_KA_INTERVAL s.
 *
 * MASTER ELECTION
 * ---------------
 * Three roles per cluster: MASTER (active coordinator), BACKUP (standby, always
 * the highest-IP non-master) and MEMBER.  Election uses a quantized window so
 * all nodes evaluate identical peer sets and reach the same result
 * deterministically.  No NTP synchronisation required.
 *
 * master_stickiness (modparam, default 1): a live master keeps the role - a
 * higher-IP node that joins becomes the BACKUP instead of preempting the
 * master, so handovers are minimised.  With master_stickiness=0 the highest-IP
 * node always becomes master.
 *
 * Fast failure detection: MASTER_ALIVE at 1 s; 3 s timeout.  On master failure
 * the silent master is aged out of the election window and the BACKUP
 * (highest-IP survivor) is promoted immediately - it already holds the
 * preserved session key, so there is no re-keying and no re-JOIN cycle.
 * Graceful handoff: KEY_HANDOFF + GOODBYE before shutdown.
 *
 * SPLIT-BRAIN HANDLING (three layers)
 * -----------------------------------
 *   1. Prevention at join time: simultaneously-starting nodes see each other's
 *      JOIN_REQs, so at the join deadline a node that has seen a higher-IP
 *      starter DEFERS self-promotion (bounded) and joins that node instead of
 *      everyone becoming an independent-key lone master.
 *   2. Same-key yield: two masters that share a session key see each other's
 *      MASTER_ALIVE; the lower-IP one yields (see MASTER_ALIVE above).
 *   3. Divergent-key merge: masters that DO NOT share a session key cannot read
 *      each other's MASTER_ALIVE, so each emits a bootstrap-key MASTER_BEACON.
 *      On hearing a superior beacon (larger member count, ties broken by higher
 *      IP) a node re-joins that master and adopts its key.
 *
 * SHARING TAGS (manage_shtags, default 1)
 * ---------------------------------------
 * The controller drives clusterer sharing tags: normally the MASTER is the sole
 * active holder and every other node is backup.  An operator can override this
 * with the cl_ctr_shtag_force MI command (pin the active tag to a chosen node) and
 * revert with cl_ctr_shtag_auto; the override is carried in MEMBER_LIST, survives
 * master fail-over, and auto-clears if the forced node departs.  cl_ctr_list_config
 * reports the current mode (auto / override:<node_id>).
 *
 * =========================================================================
 */

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

#include "../../sr_module.h"    /* module_exports, MODULE_VERSION, proc_export_t,
                                   PROC_FLAG_*, dep_export_t, DEP_ABORT,
                                   param_export_t, STR_PARAM, INT_PARAM       */
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
#include "../../pvar.h"         /* pv_export_t - read-only $cl_ctr_* variables */

#include "../clusterer/clusterer_ctrl.h"  /* set_my_identity, add_node, remove_node */

#include <wolfssl/options.h>             /* must be first: build-time feature flags */
#include <wolfssl/wolfcrypt/aes.h>       /* Aes, wc_AesGcmSetKey/Encrypt/Decrypt    */
#include <wolfssl/wolfcrypt/random.h>    /* WC_RNG, wc_RNG_GenerateBlock            */
#include <wolfssl/wolfcrypt/kdf.h>       /* wc_HKDF                                 */
#include <wolfssl/wolfcrypt/curve25519.h>/* curve25519_key, wc_curve25519_*         */
#include <wolfssl/wolfcrypt/sha256.h>    /* wc_Sha256Hash                           */
#include <wolfssl/wolfcrypt/pwdbased.h>  /* wc_scrypt (bootstrap key hardening)     */
#include <sys/timerfd.h>    /* timerfd_create(), timerfd_settime()            */
#include "../../reactor_proc.h" /* reactor_proc_init/add_fd/loop              */

/* Optional stronger crypto suite.  Selected at BUILD time: if libsodium is
 * detected on the build host (see the module Makefile -> -DCC_HAVE_SODIUM), the
 * payload AEAD becomes XChaCha20-Poly1305 (192-bit nonce -> no random-nonce
 * collision worry, even for the static bootstrap key) and the bootstrap KDF
 * becomes Argon2id.  Otherwise we fall back to WolfSSL AES-256-GCM + scrypt.
 * NOTE: the wire formats are NOT interoperable (nonce size and primitives
 * differ), so every node in a cluster must be built with the same suite. */
#ifdef CC_HAVE_SODIUM
#include <sodium.h>
#define CC_CRYPTO_SUITE "XChaCha20-Poly1305 + Argon2id"
#else
#define CC_CRYPTO_SUITE "AES-256-GCM + scrypt"
#endif

/* =========================================================================
 * Wire-format constants
 * ========================================================================= */

/* 2-byte wire magic - a cleartext key-selector at the start of every packet
 * (it must be readable before decryption to choose bootstrap vs session key).
 * Both share the 0xCC prefix; the second byte distinguishes the key tier.
 * Only a sanity/routing tag on a dedicated multicast group:port - the real
 * confidentiality and integrity come from the AES-256-GCM payload.          */
#define CC_MAGIC_SZ          2
static const unsigned char CC_PACKET_MAGIC[CC_MAGIC_SZ]    = { 0xCC, 0x00 };
static const unsigned char CC_BOOTSTRAP_MAGIC[CC_MAGIC_SZ] = { 0xCC, 0x01 };

/* Packet type bytes */
#define CC_PKT_ALIVE            0x01
#define CC_PKT_JOIN_REQ         0x02
#define CC_PKT_MEMBER_LIST      0x03  /* master -> joining node: here is the cluster  */
#define CC_PKT_GOODBYE          0x04  /* graceful shutdown notification               */
#define CC_PKT_NODE_ASSIGN      0x05  /* master -> multicast: here is your node_id    */
#define CC_PKT_MASTER_ALIVE     0x06  /* master-only keepalive; ~1 s interval         */
#define CC_PKT_KEY_GRANT        0x07  /* master -> joiner: ECDH-wrapped master_salt    */
#define CC_PKT_KEY_HANDOFF      0x08  /* outgoing master -> next master: salt handoff  */
#define CC_PKT_JOIN_REJECT      0x09  /* master -> joiner: authentication rejected     */
#define CC_PKT_MASTER_BEACON    0x0A  /* master-only announce (BOOTSTRAP key) so
                                       * masters with divergent session keys can
                                       * still discover each other and merge a
                                       * split brain; payload = member count 2B BE  */

/* Number of consecutive bootstrap-decrypt failures before a JOIN_REJECT is sent */
#define CC_JOIN_FAIL_LIMIT      3
#define CC_JOIN_FAIL_TABLE_SZ   8   /* max simultaneous rejected IPs tracked by master */

#define CC_MAX_IP_LEN        15   /* "255.255.255.255" without NUL            */
#define CC_PUBKEY_SZ         32   /* X25519 public key                        */
#define CC_JOIN_NONCE_SZ     16   /* per-exchange nonce in JOIN_REQ/KEY_GRANT */
#define CC_MASTER_SALT_SZ    32   /* random salt generated by each new master */
/* MEMBER_LIST entry: IP (16B null-padded) + is_master (1B) = 17B.
 * Pubkeys are NOT carried here - nodes learn them from ALIVE packets,
 * keeping MEMBER_LIST small enough to avoid excessive IP fragmentation. */
#define CC_IP_ENTRY_SZ       17
#define CC_LIST_COUNT_SZ      2   /* MEMBER_LIST count field: uint16_t BE     */
#define CC_NODE_ID_SZ         2   /* uint16_t node_id, big-endian             */
#define CC_MAX_BIN_SOCKETS    8   /* max BIN listeners per node               */
#define CC_MAX_BIN_SOCK_LEN  64   /* "bin:255.255.255.255:65535" = 26 chars   */
/* BIN info block: [bin_count 1B][sock1 NUL-term]...[sockN NUL-term]         */
#define CC_BIN_INFO_MAX_SZ   (1 + CC_MAX_BIN_SOCKETS * CC_MAX_BIN_SOCK_LEN)

/* AES-256-GCM encryption constants
 *   wire:      [magic 2B][cluster_id 2B BE][nonce 12B][ciphertext][GCM tag 16B]
 *   plaintext: [type 1B][seq 4B][payload]
 * The cluster_id is cleartext (like the magic) so a node can drop packets that
 * belong to a different cluster sharing the same multicast group WITHOUT its
 * key - before decryption, so foreign traffic never counts as an auth failure. */
#ifdef CC_HAVE_SODIUM
#define CC_NONCE_SZ          24   /* XChaCha20-Poly1305 nonce (192-bit)       */
#else
#define CC_NONCE_SZ          12   /* AES-GCM nonce, random per packet         */
#endif
#define CC_TAG_SZ            16   /* AEAD tag (16 for both AES-GCM & XChaCha)  */
#define CC_SEQ_SZ             4   /* uint32_t monotonic sequence in plaintext  */
#define CC_CLUSTER_ID_SZ      2   /* cleartext uint16 cluster_id (BE) selector */
#define CC_NONCE_OFF         (CC_MAGIC_SZ + CC_CLUSTER_ID_SZ)  /* nonce starts here */
#define CC_WIRE_HDR_SZ       (CC_MAGIC_SZ + CC_CLUSTER_ID_SZ + CC_NONCE_SZ) /* 16 (GCM) / 28 (XChaCha) */
#define CC_PLAIN_HDR_SZ      (1 + CC_SEQ_SZ)     /* type + seq = 5           */

/* Bootstrap-key hardening: the join/admission key is derived from the shared
 * password with scrypt (memory-hard) instead of a single SHA-256, so a
 * password captured from a JOIN_REQ cannot be brute-forced cheaply offline.
 * Derived ONCE in mod_init (main process, before fork), so the cost is a
 * transient startup cost only - cost=16/r=8 is ~64 MiB for ~0.3 s, freed
 * immediately; workers inherit the 32-byte key and never run scrypt.  (Argon2id
 * would be preferable but this WolfSSL build does not provide it.)            */
#define CC_SCRYPT_COST        16   /* log2(N): N = 65536 (2x offline cost)      */
#define CC_SCRYPT_BLOCKSIZE    8   /* r                                        */
#define CC_SCRYPT_PARALLEL     1   /* p                                        */
#ifdef CC_HAVE_SODIUM
/* Argon2id parameters (libsodium crypto_pwhash).  Fixed so every node derives
 * the same key; ~64 MiB to match the scrypt fallback's memory hardness.       */
#define CC_ARGON2_OPSLIMIT     3UL
#define CC_ARGON2_MEMLIMIT     (64UL * 1024 * 1024)
#endif
/* Minimum estimated password entropy (bits) before a startup warning fires.  */
#define CC_MIN_PASSWORD_BITS  80
#define CC_DEFAULT_PASSWORD  "3eCrEt*5629"   /* insecure placeholder; warn if used */

/* Master keepalive: master sends CC_PKT_MASTER_ALIVE every CC_MASTER_KA_INTERVAL
 * seconds.  Peers declare master dead after CC_MASTER_KA_MISSED missed packets. */
#define CC_MASTER_KA_INTERVAL   1   /* seconds between MASTER_ALIVE sends       */
#define CC_MASTER_KA_MISSED     3   /* missed keepalives before re-election     */
#define CC_MASTER_KA_TIMEOUT    (CC_MASTER_KA_INTERVAL * CC_MASTER_KA_MISSED)

/* Split-brain merge: a master emits a CC_PKT_MASTER_BEACON (bootstrap key) once
 * every CC_MASTER_BEACON_EVERY MASTER_ALIVE ticks.  This is the only traffic two
 * masters with divergent session keys can both read, so it bounds split-brain
 * convergence to ~CC_MASTER_BEACON_EVERY seconds while keeping bootstrap-key use
 * (and thus exposure) rare compared with the 1 s session keepalive.            */
#define CC_MASTER_BEACON_EVERY  5   /* MASTER_ALIVE ticks between beacons (~5 s) */

/* Split-brain PREVENTION at join time.  When several nodes cold-start together
 * they all exchange (bootstrap-decryptable) JOIN_REQs, so each learns the other
 * starters.  At the join deadline a node that has seen a higher-IP starter does
 * NOT self-promote; it defers (re-sending JOIN_REQ) so the highest-IP starter
 * becomes the single master and everyone joins it - no divergent keys ever form.
 * Bounded so a higher-IP node that heard-then-died cannot stall us forever.    */
#define CC_JOIN_DEFER_SECS      1   /* seconds per deferral round               */
#define CC_JOIN_DEFER_MAX       4   /* consecutive deferrals for a *silent*      */
                                    /* higher-IP peer before we promote anyway  */
#define CC_JOIN_DEFER_HARDMAX  20   /* absolute cap on deferrals incl. resets - */
                                    /* a peer stuck joining can't stall forever */
#define CC_JOIN_REQ_MIN_US 500000   /* min microseconds between JOIN_REQ sends   */

/* Per-source-IP rate limiter: checked before decryption to shed floods cheaply.
 * Tracks up to CC_RATE_TBL_SZ source IPs with a 1-second sliding window. */
#define CC_RATE_TBL_SZ  256    /* one slot per peer; matches max cluster size */
#define CC_RATE_LIMIT    20    /* max packets per second per source IP        */

typedef struct {
    uint32_t ip;           /* network byte order; 0 = empty slot */
    time_t   window_start;
    int      count;
} cc_rate_entry_t;

/* Max packet sizes: wire(20) = magic(8) + nonce(12); plain(5) = type(1) + seq(4)
 *   MASTER_ALIVE     : wire(20) + plain(5) + tag(16) = 41 bytes
 *   ALIVE            : wire(20) + plain(5) + IP(16) + pubkey(32) + tag(16) = 89 bytes
 *   GOODBYE          : wire(20) + plain(5) + IP(16) + tag(16) = 57 bytes
 *   KEY_GRANT        : wire(20) + plain(5) + IP(16) + master_pubkey(32)
 *                      + join_nonce(16) + wrapped_salt(32) + tag(16) = 137 bytes
 *   KEY_HANDOFF      : wire(20) + plain(5) + IP(16) + sender_pubkey(32)
 *                      + wrapped_salt(32) + tag(16) = 121 bytes
 *   JOIN_REQ max     : wire(20) + plain(5) + IP(16) + bin_info(513) + pubkey(32)
 *                      + join_nonce(16) + tag(16) = 618 bytes
 *   NODE_ASSIGN max  : wire(20) + plain(5) + node_id(2) + IP(16) + bin_info(513)
 *                      + tag(16) = 572 bytes
 *   MEMBER_LIST max  : wire(20) + plain(5) + count(2) + 256x17 + tag(16) = 4395 bytes
 *
 * Pubkeys are distributed via ALIVE (89 bytes) rather than MEMBER_LIST so that
 * MEMBER_LIST payload stays bounded to 256x17=4352 bytes max.
 *
 * Fragmentation note: all packets except MEMBER_LIST fit in a single datagram
 * on any standard link (Ethernet 1472B payload budget).  MEMBER_LIST at 4395B
 * requires IP fragmentation:
 *   - Standard Ethernet (1500 MTU): 3 fragments
 *   - IPsec ESP tunnel (~1400 MTU): 4 fragments
 *   - GRE-over-IPsec (~1350 MTU):  4-5 fragments
 * Firewalls that block fragmented UDP packets will silently drop MEMBER_LIST,
 * preventing new nodes from joining.  The DF bit is not set so fragmentation
 * occurs transparently where the network allows it. */
#define CC_SMALL_PKT_SZ      (CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ + CC_MAX_IP_LEN + 1 + CC_TAG_SZ)
/* Consistency-critical settings advertised in ALIVE so peers can detect
 * accidental per-node config drift for the same cluster:
 * manage_shtags(1B) + master_stickiness(1B) + query_time(2B BE). */
#define CC_CONFIG_SZ          4
/* JOIN_REQ: [ip NUL][bin_count 1B][sockets...][pubkey 32B][join_nonce 16B] */
#define CC_JOIN_PKT_MAX_SZ   (CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ + CC_MAX_IP_LEN + 1 \
                              + CC_BIN_INFO_MAX_SZ + CC_PUBKEY_SZ + CC_JOIN_NONCE_SZ \
                              + CC_CONFIG_SZ + CC_TAG_SZ)
/* KEY_GRANT: [target_ip NUL][master_pubkey 32B][join_nonce 16B][wrapped_salt 32B] */
#define CC_KEY_GRANT_SZ      (CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ + CC_MAX_IP_LEN + 1 \
                              + CC_PUBKEY_SZ + CC_JOIN_NONCE_SZ + CC_MASTER_SALT_SZ + CC_TAG_SZ)
/* KEY_HANDOFF: [target_ip NUL][sender_pubkey 32B][wrapped_salt 32B] */
#define CC_KEY_HANDOFF_SZ    (CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ + CC_MAX_IP_LEN + 1 \
                              + CC_PUBKEY_SZ + CC_MASTER_SALT_SZ + CC_TAG_SZ)
/* NODE_ASSIGN: [node_id 2B][ip NUL][bin_count 1B][sockets...] */
#define CC_NODE_ASSIGN_MAX_SZ (CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ + CC_NODE_ID_SZ \
                               + CC_MAX_IP_LEN + 1 + CC_BIN_INFO_MAX_SZ + CC_TAG_SZ)
#define CC_LIST_PKT_MAX_SZ   (CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ + CC_LIST_COUNT_SZ \
                              + CC_NODE_ID_SZ /* forced-shtag node_id */ \
                              + CC_MAX_PEERS * CC_IP_ENTRY_SZ + CC_TAG_SZ)
/* Large enough to receive a fully reassembled UDP datagram (max 65507 bytes) */
#define CC_RECV_BUF_SZ       65536

/* =========================================================================
 * Peer-table constants
 * ========================================================================= */

#define CC_MAX_PEERS         256

/*
 * CC_ELECT_FACTOR - election window = query_time x CC_ELECT_FACTOR.
 * QUANTIZED: all nodes evaluate the same cutoff simultaneously.
 *
 * CC_PURGE_FACTOR - memory-cleanup window = query_time x CC_PURGE_FACTOR.
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

/* TODO: maintenance mode
 *
 * Add CC_NODE_MAINTENANCE = 2 to cc_node_state_t.  A node in maintenance
 * must never become master, must not participate in elections (treated as
 * absent from cc_elect_master), and must not become active shtag holder for
 * any cluster even when manage_shtags=1.
 *
 * Entry / exit: new MI command  cc_maintenance {on|off}  sets the flag on the
 * local node.  Advertise the state in the ALIVE payload so all peers know to
 * exclude this node from elections without waiting for a MEMBER_LIST refresh.
 * The maintenance flag should survive MEMBER_LIST resets (it is local policy,
 * not part of the cluster-wide peer table - store it in cc_cluster_t, not
 * cc_peer_t).
 *
 * In cc_elect_master: skip any peer whose ALIVE-advertised maintenance flag
 * is set (treat it as not in the election window even if last_seen is fresh).
 *
 * In cc_transition_to_active and shtag activation paths: gate all
 * activate_backup_shtags / set_active_shtag calls behind
 *   if (cl->peers->node_state != CC_NODE_MAINTENANCE)
 *
 * TODO: shtag override mode
 *
 * Add MI command  cc_set_shtag_holder <cluster_id> <node_ip>  to force a
 * specific non-maintenance node to be the active shtag holder for a cluster,
 * overriding the normal master-drives-shtag logic.  Persist the override in
 * a new field  cc_peers_t.shtag_override_ip[CC_MAX_IP_LEN+1]  (in shm so
 * it is visible across processes).
 *
 * When shtag_override_ip is set for a cluster:
 *   - the designated node calls set_active_shtag regardless of mastership
 *   - all other nodes stay in backup shtag state
 *   - the override is NOT cleared on MEMBER_LIST or key rotation - it is
 *     explicit operator intent and must be cleared only by
 *     cc_clear_shtag_override (see below) or automatically when the
 *     overridden node enters maintenance mode
 *   - if the overridden node is put into maintenance mode, the override is
 *     automatically cleared and normal master-driven shtag logic resumes
 *
 * TODO: shtag override clear
 *
 * Add MI command  cc_clear_shtag_override <cluster_id>  to cancel a
 * previously set shtag override and return the cluster to normal mode where
 * the elected master drives shtag activation.
 *
 * Implementation:
 *   - zero cc_peers_t.shtag_override_ip for the cluster
 *   - the current master immediately calls set_active_shtag on itself and
 *     activate_backup_shtags on all other nodes, restoring normal state
 *   - non-master nodes that were held in backup shtag state due to the
 *     override need no explicit action - the next election cycle reapplies
 *     correct shtag assignments automatically
 *   - log at INFO: "shtag override cleared for cluster <id>, resuming
 *     normal master-driven shtag assignment (master: <ip>)"
 *   - return error if no override is active for the given cluster_id
 *
 * TODO: MI status commands
 *
 * cc_list_shtags  - list all clusters with their active shtag holder,
 *   whether the holder was elected normally or overridden, and which nodes
 *   are in maintenance mode.  Output columns: cluster_id, shtag, holder_ip,
 *   status in {elected | overridden | maintenance | no_holder}.
 *
 * cl_ctr_list_members should be extended to include a 'mode' field per node:
 *   active | maintenance, and an 'shtag_status' field: holder | backup |
 *   overridden | n/a (when manage_shtags=0 for that cluster).
 */

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
    unsigned char  key[32];         /* bootstrap key = SHA256(password); JOIN only */
    unsigned char  session_key[32]; /* group key = HKDF(password, master_salt)     */
    int            manage_shtags; /* per-cluster override; defaults to global manage_shtags */
    int            master_stickiness; /* per-cluster override; -1 = inherit global */
    cc_peers_t    *peers;        /* per-cluster peer table in shm     */
    /* BIN socket resolved at mod_init - advertised in JOIN_REQ/NODE_ASSIGN */
    char           bin_socket[CC_MAX_BIN_SOCK_LEN]; /* "bin:IP:PORT"  */
    /* Worker-process fds and state - valid only inside cc_worker after fork */
    int            sock;               /* multicast UDP socket          */
    int            alive_tfd;          /* periodic ALIVE timer          */
    int            join_tfd;           /* one-shot join deadline        */
    int            rejoin_tfd;         /* 1-second JOIN_REQ retry       */
    int            master_alive_tfd;   /* master sends MASTER_ALIVE 1/s */
    int            master_dead_tfd;    /* non-master: fires on ka miss  */
    int            identity_registered; /* 1 once update_identity called */
    int            shtag_bootstrapped;  /* -1 = eligible, 1 = done       */
    /* ECDH keypair - generated in cc_worker after fork, never leaves process */
    unsigned char  my_privkey[CC_PUBKEY_SZ];
    unsigned char  my_pubkey[CC_PUBKEY_SZ];
    /* Per-exchange nonce sent in our JOIN_REQ; used to verify/unwrap KEY_GRANT */
    unsigned char  my_join_nonce[CC_JOIN_NONCE_SZ];
    /* Set while a re-key JOIN_REQ is in flight; cleared on KEY_GRANT success
     * or master transition to prevent nonce stomping under packet flood.    */
    int            join_pending;
    /* 1 once a valid session_key has been established - either generated at
     * cluster bootstrap (cc_on_became_master) or adopted from the current master
     * master via KEY_GRANT / KEY_HANDOFF.  A node must NOT act as master
     * (broadcast MASTER_ALIVE) while this is 0, or it would encrypt with an
     * underived key that no member can decrypt.                             */
    int            have_session_key;
    /* Master-side per-IP table tracking bootstrap-decrypt failures.
     * Worker-local (no shm, no lock needed).  After CC_JOIN_FAIL_LIMIT
     * failures from the same source IP the master sends JOIN_REJECT.       */
    struct {
        uint32_t ip_num;
        char     ip[CC_MAX_IP_LEN + 1];
        int      count;
        int      rejected;   /* 1 = JOIN_REJECT already sent; suppress repeats */
    }              join_fail_tbl[CC_JOIN_FAIL_TABLE_SZ];
    /* Joiner-side auth-failure detection - no lock needed (worker-local). */
    int              bootstrap_auth_fails; /* consecutive bootstrap decrypt failures
                                             during CC_NODE_NEW; reset on KEY_GRANT */
    int              join_attempt_count;   /* rejoin_tfd fires since last KEY_GRANT  */
    /* Count of packets from OTHER peers during CC_NODE_NEW that we could not
     * decrypt (any magic).  Non-zero means a cluster (or rogue) whose key we do
     * not share exists on the group - evidence we may have the wrong password.
     * This is only *evidence*: cc_on_join_tfd never self-terminates on it
     * immediately (that would let start-up noise or a flood kill a healthy
     * node); it defers and re-joins, and a KEY_GRANT resets this counter.  Only
     * a correct-password joiner ever receives a KEY_GRANT, so persistence of
     * this counter across the whole defer budget is what marks a real
     * wrong-password / foreign-cluster condition.                             */
    int              auth_fail_pkts;
    /* Number of join rounds we have already deferred because we still could not
     * authenticate.  We only give up (shut down) after CC_JOIN_DEFER_MAX such
     * rounds, so a KEY_GRANT that is merely slow, or a brief burst of start-up
     * noise or crafted garbage, never self-terminates a correctly-configured
     * node.  Reset on successful authentication.                              */
    int              auth_defer_count;
    /* master_salt lives in cl->peers->master_salt (shm) so mod_destroy can
     * read it.  session_key is the worker-local derived key cache. */
    /* Per-source-IP rate limiter table - pkg_malloc'd in cc_worker after fork */
    cc_rate_entry_t  *rate_tbl;
    /* Last shtag decision this worker applied, so cc_apply_shtags_decision()
     * logs the *reason* only when the decision (or its cause) actually
     * changes - not on every idempotent re-apply.  Worker-local.
     *   shtag_last_active: -1 unknown, 0 backup, 1 active.
     *   shtag_last_forced: the forced node_id in effect at that time.        */
    int              shtag_last_active;
    uint16_t         shtag_last_forced;
    /* Counts MASTER_ALIVE ticks so a beacon is emitted every
     * CC_MASTER_BEACON_EVERY of them.  Worker-local (master path only).       */
    unsigned int     beacon_tick;
    /* How many times we have deferred self-promotion at the join deadline
     * because a higher-IP node was also still joining (split-brain
     * prevention).  Reset to 0 whenever a fresh JOIN_REQ from a higher-IP peer
     * arrives (it is demonstrably still alive and joining, so we keep waiting
     * for it rather than self-promoting into a divergent-key split brain).
     * Worker-local; reset once we leave the NEW state.                        */
    int              join_defer_count;
    /* Total deferrals across resets - an absolute cap (CC_JOIN_DEFER_HARDMAX)
     * so a peer that keeps sending JOIN_REQ yet never becomes master cannot
     * defer us forever.  Worker-local; reset once we leave the NEW state.     */
    int              join_defer_total;
    /* utime (us since start) of the last JOIN_REQ we transmitted, for a
     * minimum-interval throttle so a key-mismatch/split-brain burst cannot
     * flood the group with JOIN_REQs.  0 = never sent.  Worker-local.         */
    utime_t          last_join_req_utime;
    /* 1 while our MASTER_ALIVE keepalive timer is armed (i.e. we are acting as
     * master and broadcasting).  Set by cc_arm_master_timers().  Lets
     * cc_elect_master() enforce the invariant "keepalive armed <=> I am the
     * elected master": an election that demotes us (clears is_master) without
     * going through a yield/member-list path must still stop the keepalive,
     * otherwise a demoted node keeps broadcasting MASTER_ALIVE and lower-IP
     * peers oscillate between two masters.  Worker-local.                     */
    int              master_ka_armed;
} cc_cluster_t;

static cc_cluster_t  cc_clusters[CC_MAX_CLUSTERS];
static int           cc_cluster_count = 0;

/* Raw "cluster" strings collected during modparam parsing */
static char *cc_cluster_strs[CC_MAX_CLUSTERS];
static int   cc_cluster_str_count = 0;

/* =========================================================================
 * Module parameters
 * ========================================================================= */

/* Global modparams - apply to all clusters unless overridden per-cluster */
static char *my_ip             = NULL;  /* explicit IP, or NULL for auto-detect */
static char *my_interface      = NULL;  /* explicit interface name, or NULL      */
static int   query_time        = 5;
static char *password          = CC_DEFAULT_PASSWORD; /* default; falls back per cluster */

/* Policy when a node's consistency-critical settings (manage_shtags/
 * master_stickiness/query_time) differ from the running cluster (a master is
 * alive).  Set via the on_config_mismatch modparam string:
 *   "warn"   - admit/keep the node but log a CONFIG MISMATCH warning;
 *   "reject" - the master refuses the join (JOIN_REJECT) and the node shuts
 *              down with a clear message (default);
 *   "adopt"  - the node adopts the master's (authoritative) settings at
 *              runtime and continues. */
#define CC_CFGMISMATCH_WARN    0
#define CC_CFGMISMATCH_REJECT  1
#define CC_CFGMISMATCH_ADOPT   2
/* JOIN_REJECT reason codes (1 byte after the target IP in the payload). */
#define CC_REJECT_GENERIC      0   /* wrong password / unauthorized / table full */
#define CC_REJECT_CONFIG       1   /* different cluster settings (reject policy)  */
static char *on_config_mismatch_s = NULL;              /* raw modparam string   */
static int   on_config_mismatch   = CC_CFGMISMATCH_REJECT; /* resolved; default reject */

/* Resolved at mod_init time - always valid after cc_resolve_local_identity() */
static char my_ip_buf[INET_ADDRSTRLEN];
static char my_interface_buf[IF_NAMESIZE];

static WC_RNG cc_rng;

/* Local node identity - populated at mod_init by scanning the config file */
static uint16_t my_node_id                              = 0;

/* clusterer integration - loaded at mod_init if clusterer use_controller=1 */
static clusterer_ctrl_binds_t clctl;
static int                    clctl_loaded  = 0;
static int                    manage_shtags = 1;
/* master_stickiness (global default; per-cluster override via "cluster" string):
 *   1 (default) = the master is "sticky": a live master keeps the role and is
 *                 NOT displaced when a higher-IP node joins.  The highest-IP
 *                 non-master is designated BACKUP and takes over only when the
 *                 master fails.  A higher-IP joiner just replaces the backup.
 *                 Result: fewer master handovers.
 *   0           = not sticky - pure highest-IP election, so a higher-IP node
 *                 takes over as master as soon as it appears (more handovers). */
static int                    master_stickiness = 1;
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
    {"password",      STR_PARAM, &password},
    {"manage_shtags", INT_PARAM, &manage_shtags},
    {"master_stickiness", INT_PARAM, &master_stickiness},
    {"on_config_mismatch", STR_PARAM, &on_config_mismatch_s},
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
    int          is_backup;   /* 1 = standby master (highest-IP non-master) */
    int          in_election; /* 1 = currently inside the election window  */
    uint16_t     node_id;     /* allocated by master; 0 = not yet assigned */
    uint8_t      bin_count;   /* number of BIN listeners reported          */
    char         bin_sockets[CC_MAX_BIN_SOCKETS][CC_MAX_BIN_SOCK_LEN];
    unsigned char pubkey[CC_PUBKEY_SZ];           /* X25519 public key; zero if unknown */
    unsigned char join_nonce[CC_JOIN_NONCE_SZ];   /* per-exchange nonce from JOIN_REQ   */
    uint32_t      last_seq;                        /* highest seq accepted from this peer */
    /* Peer's advertised consistency-critical config (from ALIVE), used to warn
     * on accidental per-node config drift.  cfg_known=0 until first advertised;
     * cfg_warned deduplicates the mismatch warning. */
    int           cfg_known;
    int           cfg_manage_shtags;
    int           cfg_master_stickiness;
    int           cfg_query_time;
    int           cfg_warned;
} cc_peer_t;

struct cc_peers_ {
    cc_peer_t       entries[CC_MAX_PEERS];
    int             count;
    /* rw_lock_t allows concurrent readers (MI, future script functions)
     * while still serialising the single writer (cc_worker).            */
    rw_lock_t      *lock;
    cc_node_state_t node_state;
    time_t          join_deadline;
    /* last elected master IP - used to detect and log master changes */
    char            last_master[CC_MAX_IP_LEN + 1];
    /* master_salt: generated by each new master, shared here so mod_destroy
     * (running in main process) can derive session_key for GOODBYE.    */
    unsigned char   master_salt[CC_MASTER_SALT_SZ];
    /* my_seq: monotonic send counter; in shm so mod_destroy can use it for
     * GOODBYE without needing the worker's private state.  Reset to 0 on
     * every session key rotation so last_seq counters reset cleanly.   */
    uint32_t        my_seq;
    /* Sharing-tag override: 0 = automatic (master-driven) allocation; nonzero =
     * an operator has forced this node_id to be the active shtag holder for the
     * cluster (cl_ctr_shtag_force MI), suspending automatic allocation until
     * cl_ctr_shtag_auto clears it.  Propagated to all nodes in the MEMBER_LIST.  */
    uint16_t        shtag_forced_node_id;
    /* worker_proc_no: OpenSIPS process index of this cluster's cc_worker,
     * published here (shm) after fork so MI handlers running in a different
     * process can target the worker with ipc_send_rpc().  -1 until set.  */
    int             worker_proc_no;
    /* Effective (possibly adopted) consistency-critical settings, mirrored in
     * shm so MI handlers in another process (cl_ctr_list_config) report the value
     * actually in force after an on_config_mismatch=adopt.  The worker keeps
     * these in sync with its own cl->manage_shtags / master_stickiness /
     * query_time.  Initialised from the resolved config at mod_init.        */
    int             eff_manage_shtags;
    int             eff_master_stickiness;
    int             eff_query_time;
};


/* =========================================================================
 * timerfd helpers
 * ========================================================================= */

/* Drain the expiration counter so the fd stops being readable. */
static void cc_drain_tfd(int tfd)
{
    uint64_t exp;
    if (read(tfd, &exp, sizeof(exp)) < 0 && errno != EAGAIN)
        LM_WARN("clusterer_controller: timerfd read: %s\n", strerror(errno));
}

/* Arm a timerfd.  Pass sec_value=0 to disarm. */
static void cc_arm_tfd(int tfd, time_t sec_value, time_t sec_interval)
{
    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec    = sec_value;
    its.it_interval.tv_sec = sec_interval;
    if (timerfd_settime(tfd, 0, &its, NULL) < 0)
        LM_WARN("clusterer_controller: timerfd_settime: %s\n", strerror(errno));
}

/* =========================================================================
 * Forward declarations
 * ========================================================================= */

static int  mod_init(void);
static int  cc_child_init(int rank);
static void mod_destroy(void);
static void cc_worker(int rank);
static int  cc_on_sock(int fd, void *param, int was_timeout);
static int  cc_on_alive_tfd(int fd, void *param, int was_timeout);
static void cc_arm_master_timers(cc_cluster_t *cl, int i_am_master);
static int  cc_on_join_tfd(int fd, void *param, int was_timeout);
static int  cc_on_rejoin_tfd(int fd, void *param, int was_timeout);
static int  cc_on_master_alive_tfd(int fd, void *param, int was_timeout);
static int  cc_on_master_dead_tfd(int fd, void *param, int was_timeout);
static mi_response_t *mi_cl_ctr_members(const mi_params_t *params,
                                     struct mi_handler *hdl);
static void cc_handle_member_list(const char *payload, int payload_len,
                                  const char *sender_ip, cc_cluster_t *cl);
static void cc_handle_join_req(int sock, const char *payload, int payload_len,
                               cc_cluster_t *cl);
static void cc_handle_node_assign(const char *payload, int payload_len,
                                  const char *sender_ip, cc_cluster_t *cl);
static void cc_handle_goodbye(int sock, const char *src_ip, cc_cluster_t *cl);
static void cc_handle_master_alive(const char *sender_ip, cc_cluster_t *cl);
static void cc_handle_key_grant(const char *payload, int payload_len,
                                const char *sender_ip, cc_cluster_t *cl);
static void cc_handle_key_handoff(const char *payload, int payload_len,
                                  const char *sender_ip, cc_cluster_t *cl);
static void cc_handle_join_reject(const char *payload, int payload_len,
                                  const char *sender_ip, cc_cluster_t *cl);
static void cc_send_join_reject(int sock, const char *target_ip, cc_cluster_t *cl,
                                int reason);
static mi_response_t *mi_cl_ctr_node_info(const mi_params_t *params,
                                      struct mi_handler *hdl);
static mi_response_t *mi_cl_ctr_config(const mi_params_t *params,
                                     struct mi_handler *hdl);
static mi_response_t *mi_cl_ctr_shtag_force(const mi_params_t *params,
                                        struct mi_handler *hdl);
static mi_response_t *mi_cl_ctr_shtag_auto(const mi_params_t *params,
                                       struct mi_handler *hdl);

/* =========================================================================
 * Extra-process export  (layout from mi_fifo.c)
 * ========================================================================= */

static proc_export_t procs[] = {
    {"clusterer_controller worker", 0, 0, cc_worker, 1,
        PROC_FLAG_INITCHILD | PROC_FLAG_HAS_IPC},
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
	"cl_ctr_list_members",
	"List all current cluster members with node_id, status and BIN sockets",
	0, 0,
	{
	    {mi_cl_ctr_members, {0}},
	    {EMPTY_MI_RECIPE}
	}
    },
    {
	"cl_ctr_node_info",
	"Return full info for a node_id across all clusters",
	0, 0,
	{
	    {mi_cl_ctr_node_info, {"node_id", 0}},
	    {EMPTY_MI_RECIPE}
	}
    },
    {
	"cl_ctr_list_config",
	"List all configured clusters and their resolved settings",
	0, 0,
	{
	    {mi_cl_ctr_config, {0}},
	    {EMPTY_MI_RECIPE}
	}
    },
    {
	"cl_ctr_shtag_force",
	"Force a node to hold the active sharing tag (master only); "
	"suspends automatic allocation until cl_ctr_shtag_auto",
	0, 0,
	{
	    {mi_cl_ctr_shtag_force, {"cluster_id", "node_id", 0}},
	    {EMPTY_MI_RECIPE}
	}
    },
    {
	"cl_ctr_shtag_auto",
	"Resume automatic master-driven sharing-tag allocation (master only)",
	0, 0,
	{
	    {mi_cl_ctr_shtag_auto, {"cluster_id", 0}},
	    {EMPTY_MI_RECIPE}
	}
    },
    {EMPTY_MI_EXPORT}
};

/* =========================================================================
 * Read-only script variables ($cl_ctr_*)
 *
 * Nouns, never verbs (actions are script functions / MI).  Each variable
 * optionally takes a cluster id: $cl_ctr_role(2).  The bare form
 * ($cl_ctr_role) resolves to the sole configured cluster; with several
 * clusters it returns NULL and warns once, so nobody silently reads the
 * wrong cluster.  All values are read from the shm peer table under a read
 * lock, so every process (SIP workers included) sees live state.  Read-only:
 * no setter is exported.
 * ========================================================================= */

enum cc_pv_field {
    CC_PV_ROLE,        /* master | backup | member | joining               */
    CC_PV_IS_MASTER,   /* 1 / 0                                            */
    CC_PV_MASTER_IP,   /* current master's IP, NULL if none                */
    CC_PV_BACKUP_IP,   /* current backup's IP, NULL if none                */
    CC_PV_NODE_ID,     /* this node's id in the cluster, NULL if unassigned */
    CC_PV_MY_IP,       /* controller identity IP                           */
    CC_PV_MEMBERS,     /* live member count                                */
    CC_PV_SHTAG_MODE,  /* auto | forced                                    */
    CC_PV_FORCED_NODE, /* node pinned by cl_ctr_shtag_force, NULL if auto  */
};

/* Optional (cluster_id) argument; bare form leaves the spec zeroed (cid 0). */
static int cc_pv_parse_cluster(pv_spec_p sp, const str *in)
{
    unsigned int cid;
    str s;

    if (!sp)
	return -1;
    if (!in || !in->s || in->len == 0) {
	sp->pvp.pvn.u.isname.name.n = 0;   /* bare form -> sole cluster */
	return 0;
    }
    s = *in;
    trim(&s);
    if (s.len == 0) {
	sp->pvp.pvn.u.isname.name.n = 0;
	return 0;
    }
    /* str2int rejects any non-digit (so '-5', 'abc', '1.2' all fail); the
     * length cap keeps a huge value from silently overflowing/wrapping into a
     * valid id (999999999 < INT_MAX). */
    if (s.len > 9 || str2int(&s, &cid) < 0 || cid == 0) {
	LM_ERR("clusterer_controller: invalid cluster id '%.*s' in $cl_ctr_* "
	       "variable (expected a positive integer 1..999999999)\n",
	       in->len, in->s);
	return -1;
    }
    sp->pvp.pvn.u.isname.name.n = (int)cid;
    return 0;
}

static int cc_pv_get(struct sip_msg *msg, pv_param_t *param, pv_value_t *res,
                     enum cc_pv_field field)
{
    static char  cc_pv_ipbuf[INET_ADDRSTRLEN];
    static int   cc_pv_warned_ambiguous;
    cc_cluster_t *cl = NULL;
    cc_peer_t    *me = NULL, *master = NULL, *backup = NULL;
    const char   *sval = NULL;
    int          cid, i, have_int = 0, ival = 0, joining;

    cid = param->pvn.u.isname.name.n;
    if (cid == 0) {
	if (cc_cluster_count == 1) {
	    cl = &cc_clusters[0];
	} else {
	    if (!cc_pv_warned_ambiguous) {
		LM_WARN("clusterer_controller: bare $cl_ctr_* used with %d "
		        "clusters configured - specify the cluster id, e.g. "
		        "$cl_ctr_role(%d)\n", cc_cluster_count,
		        cc_cluster_count ? cc_clusters[0].cluster_id : 1);
		cc_pv_warned_ambiguous = 1;
	    }
	    return pv_get_null(msg, param, res);
	}
    } else {
	for (i = 0; i < cc_cluster_count; i++)
	    if (cc_clusters[i].cluster_id == cid) {
		cl = &cc_clusters[i];
		break;
	    }
    }
    if (!cl || !cl->peers)
	return pv_get_null(msg, param, res);

    lock_start_read(cl->peers->lock);

    joining = (cl->peers->node_state == CC_NODE_NEW);
    for (i = 0; i < cl->peers->count; i++) {
	cc_peer_t *e = &cl->peers->entries[i];
	if (e->is_master)
	    master = e;
	if (e->is_backup)
	    backup = e;
	if (my_ip && strcmp(e->ip, my_ip) == 0)
	    me = e;
    }

    switch (field) {
    case CC_PV_ROLE:
	if (joining)
	    sval = "joining";
	else if (me && me->is_master)
	    sval = "master";
	else if (me && me->is_backup)
	    sval = "backup";
	else
	    sval = "member";
	break;
    case CC_PV_IS_MASTER:
	have_int = 1;
	ival = (!joining && me && me->is_master) ? 1 : 0;
	break;
    case CC_PV_MASTER_IP:
	if (master) {
	    strncpy(cc_pv_ipbuf, master->ip, sizeof(cc_pv_ipbuf) - 1);
	    cc_pv_ipbuf[sizeof(cc_pv_ipbuf) - 1] = '\0';
	    sval = cc_pv_ipbuf;
	}
	break;
    case CC_PV_BACKUP_IP:
	if (backup) {
	    strncpy(cc_pv_ipbuf, backup->ip, sizeof(cc_pv_ipbuf) - 1);
	    cc_pv_ipbuf[sizeof(cc_pv_ipbuf) - 1] = '\0';
	    sval = cc_pv_ipbuf;
	}
	break;
    case CC_PV_NODE_ID:
	if (me && me->node_id > 0) {
	    have_int = 1;
	    ival = me->node_id;
	}
	break;
    case CC_PV_MY_IP:
	sval = my_ip;   /* resolved in mod_init, constant afterwards */
	break;
    case CC_PV_MEMBERS:
	have_int = 1;
	ival = cl->peers->count;
	break;
    case CC_PV_SHTAG_MODE:
	sval = cl->peers->shtag_forced_node_id ? "forced" : "auto";
	break;
    case CC_PV_FORCED_NODE:
	if (cl->peers->shtag_forced_node_id) {
	    have_int = 1;
	    ival = cl->peers->shtag_forced_node_id;
	}
	break;
    }

    lock_stop_read(cl->peers->lock);

    if (have_int)
	return pv_get_uintval(msg, param, res, (unsigned int)ival);
    if (sval) {
	str s = {(char *)sval, (int)strlen(sval)};
	return pv_get_strval(msg, param, res, &s);
    }
    return pv_get_null(msg, param, res);
}

#define CC_PV_WRAP(_fn, _field) \
static int _fn(struct sip_msg *msg, pv_param_t *param, pv_value_t *res) \
{ return cc_pv_get(msg, param, res, _field); }

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
static int cc_find_peer(int cid, int nid, int *is_master, int *is_backup,
                        char *ipbuf, int ipbuf_sz)
{
    cc_cluster_t *cl = NULL;
    int i, rc = -1;

    if (cid <= 0) {
	if (cc_cluster_count == 1)
	    cl = &cc_clusters[0];
    } else {
	for (i = 0; i < cc_cluster_count; i++)
	    if (cc_clusters[i].cluster_id == cid) {
		cl = &cc_clusters[i];
		break;
	    }
    }
    if (!cl || !cl->peers)
	return -1;

    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
	cc_peer_t *e = &cl->peers->entries[i];
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

static int cc_out_str(struct sip_msg *msg, pv_spec_t *out, const char *str_s)
{
    pv_value_t val;
    memset(&val, 0, sizeof val);
    val.flags  = PV_VAL_STR;
    val.rs.s   = (char *)str_s;
    val.rs.len = strlen(str_s);
    return pv_set_value(msg, out, 0, &val);
}

/* cl_ctr_node_is_master(cluster_id, node_id) -> true if that node is master */
static int w_cl_ctr_node_is_master(struct sip_msg *msg, int *cid, int *nid)
{
    int im = 0;
    if (cc_find_peer(cid ? *cid : 0, nid ? *nid : 0, &im, NULL, NULL, 0) < 0)
	return -1;
    return im ? 1 : -1;
}

/* cl_ctr_node_present(cluster_id, node_id) -> true if node_id is a live member */
static int w_cl_ctr_node_present(struct sip_msg *msg, int *cid, int *nid)
{
    return cc_find_peer(cid ? *cid : 0, nid ? *nid : 0, NULL, NULL, NULL, 0) == 0
           ? 1 : -1;
}

/* cl_ctr_get_node_role(cluster_id, node_id, out) -> out=master|backup|member */
static int w_cl_ctr_get_node_role(struct sip_msg *msg, int *cid, int *nid,
                                  pv_spec_t *out)
{
    int im = 0, ib = 0;
    if (cc_find_peer(cid ? *cid : 0, nid ? *nid : 0, &im, &ib, NULL, 0) < 0)
	return -1;
    return cc_out_str(msg, out, im ? "master" : (ib ? "backup" : "member")) == 0
           ? 1 : -1;
}

/* cl_ctr_get_node_ip(cluster_id, node_id, out) -> out=that node's IP */
static int w_cl_ctr_get_node_ip(struct sip_msg *msg, int *cid, int *nid,
                                pv_spec_t *out)
{
    char ipbuf[INET_ADDRSTRLEN];
    if (cc_find_peer(cid ? *cid : 0, nid ? *nid : 0, NULL, NULL,
                     ipbuf, sizeof ipbuf) < 0)
	return -1;
    return cc_out_str(msg, out, ipbuf) == 0 ? 1 : -1;
}

CC_PV_WRAP(cc_pv_role,        CC_PV_ROLE)
CC_PV_WRAP(cc_pv_is_master,   CC_PV_IS_MASTER)
CC_PV_WRAP(cc_pv_master_ip,   CC_PV_MASTER_IP)
CC_PV_WRAP(cc_pv_backup_ip,   CC_PV_BACKUP_IP)
CC_PV_WRAP(cc_pv_node_id,     CC_PV_NODE_ID)
CC_PV_WRAP(cc_pv_my_ip,       CC_PV_MY_IP)
CC_PV_WRAP(cc_pv_members,     CC_PV_MEMBERS)
CC_PV_WRAP(cc_pv_shtag_mode,  CC_PV_SHTAG_MODE)
CC_PV_WRAP(cc_pv_forced_node, CC_PV_FORCED_NODE)

static const pv_export_t cc_mod_vars[] = {
    { {"cl_ctr_role",        sizeof("cl_ctr_role")-1},        1100,
	cc_pv_role,        0, cc_pv_parse_cluster, 0, 0, 0 },
    { {"cl_ctr_is_master",   sizeof("cl_ctr_is_master")-1},   1101,
	cc_pv_is_master,   0, cc_pv_parse_cluster, 0, 0, 0 },
    { {"cl_ctr_master_ip",   sizeof("cl_ctr_master_ip")-1},   1102,
	cc_pv_master_ip,   0, cc_pv_parse_cluster, 0, 0, 0 },
    { {"cl_ctr_backup_ip",   sizeof("cl_ctr_backup_ip")-1},   1103,
	cc_pv_backup_ip,   0, cc_pv_parse_cluster, 0, 0, 0 },
    { {"cl_ctr_node_id",     sizeof("cl_ctr_node_id")-1},     1104,
	cc_pv_node_id,     0, cc_pv_parse_cluster, 0, 0, 0 },
    { {"cl_ctr_my_ip",       sizeof("cl_ctr_my_ip")-1},       1105,
	cc_pv_my_ip,       0, cc_pv_parse_cluster, 0, 0, 0 },
    { {"cl_ctr_members",     sizeof("cl_ctr_members")-1},     1106,
	cc_pv_members,     0, cc_pv_parse_cluster, 0, 0, 0 },
    { {"cl_ctr_shtag_mode",  sizeof("cl_ctr_shtag_mode")-1},  1107,
	cc_pv_shtag_mode,  0, cc_pv_parse_cluster, 0, 0, 0 },
    { {"cl_ctr_forced_node", sizeof("cl_ctr_forced_node")-1}, 1108,
	cc_pv_forced_node, 0, cc_pv_parse_cluster, 0, 0, 0 },
    { {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

/* Script functions: per-peer lookups (two args -> functions, not variables). */
static const cmd_export_t cc_cmds[] = {
    {"cl_ctr_node_is_master", (cmd_function)w_cl_ctr_node_is_master, {
	{CMD_PARAM_INT, 0, 0}, {CMD_PARAM_INT, 0, 0}, {0, 0, 0}}, ALL_ROUTES},
    {"cl_ctr_node_present", (cmd_function)w_cl_ctr_node_present, {
	{CMD_PARAM_INT, 0, 0}, {CMD_PARAM_INT, 0, 0}, {0, 0, 0}}, ALL_ROUTES},
    {"cl_ctr_get_node_role", (cmd_function)w_cl_ctr_get_node_role, {
	{CMD_PARAM_INT, 0, 0}, {CMD_PARAM_INT, 0, 0}, {CMD_PARAM_VAR, 0, 0}, {0, 0, 0}}, ALL_ROUTES},
    {"cl_ctr_get_node_ip", (cmd_function)w_cl_ctr_get_node_ip, {
	{CMD_PARAM_INT, 0, 0}, {CMD_PARAM_INT, 0, 0}, {CMD_PARAM_VAR, 0, 0}, {0, 0, 0}}, ALL_ROUTES},
    {0, 0, {{0, 0, 0}}, 0}
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
    cc_cmds,          /* cmds - per-peer lookup functions */
    0,                /* acmds   */
    params,
    0,                /* stats   */
    mi_cmds,
    cc_mod_vars,      /* pvs - read-only $cl_ctr_* variables */
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
 *   in_election 1->0  A peer's last_seen fell outside the election window -
 *                    the node is considered down.  Logged immediately so the
 *                    operator sees the event without waiting for cc_prune_stale(cl)
 *                    (which only fires at CC_PURGE_FACTOR x query_time).
 *
 *   last_master      The elected master IP changed - either because the
 *                    previous master went down, or a higher-IP node joined.
 *
 * Must be called with cl->peers->lock held.
 */
static void cc_elect_master(cc_cluster_t *cl)
{
    time_t       cutoff    = cc_election_cutoff();
    unsigned int top_num   = 0;
    int          i, n_in = 0, top_idx = -1, cur_master_idx = -1, master_idx = -1;
    int          i_am_elected = 0;
    char         prev_master[CC_MAX_IP_LEN + 1];
    char         prev_backup[CC_MAX_IP_LEN + 1];

    prev_backup[0] = '\0';
    /* Snapshot the master we had before this election, for change reporting. */
    {
	size_t _l = strnlen(cl->peers->last_master, CC_MAX_IP_LEN);
	memcpy(prev_master, cl->peers->last_master, _l);
	prev_master[_l] = '\0';
    }

    for (i = 0; i < cl->peers->count; i++) {
	cc_peer_t *e       = &cl->peers->entries[i];
	int        now_in  = (e->last_seen >= cutoff);

	/* Detect peer dropping out of the election window */
	if (e->in_election && !now_in)
	    LM_INFO("clusterer_controller: peer %s went down "
	            "(last seen %lds ago)\n",
	            e->ip, (long)(time(NULL) - e->last_seen));

	e->in_election = now_in;

	/* Remember the live current master and the previous backup before
	 * clearing the flags - used for sticky election and change logging. */
	if (e->is_master && now_in)
	    cur_master_idx = i;
	if (e->is_backup) {
	    size_t _l = strnlen(e->ip, CC_MAX_IP_LEN);
	    memcpy(prev_backup, e->ip, _l);
	    prev_backup[_l] = '\0';
	}

	e->is_master = 0;
	e->is_backup = 0;

	if (now_in) {
	    n_in++;
	    if (e->ip_num > top_num) {
		top_num = e->ip_num;
		top_idx = i;
	    }
	}
    }

    /* Choose the master:
     *   master_stickiness == 1 (default, sticky): a live current master keeps the
     *     role - a higher-IP peer does NOT preempt it (fewer handovers).  Only
     *     when there is no live master do we elect the highest-IP peer.
     *   master_stickiness == 0: pure highest-IP election - the highest-IP peer
     *     always wins, preempting any lower-IP current master.
     * Split-brain (two live masters, e.g. after a partition heal) is resolved
     * separately in cc_handle_master_alive by yielding to the highest IP.   */
    if (cl->master_stickiness == 1 && cur_master_idx >= 0)
	master_idx = cur_master_idx;
    else
	master_idx = top_idx;

    if (master_idx >= 0) {
	const char  *m_ip, *b_ip, *why;
	int          b_idx = -1, master_changed, backup_changed;
	unsigned int b_num = 0;
	int          j;

	cl->peers->entries[master_idx].is_master = 1;
	m_ip = cl->peers->entries[master_idx].ip;
	i_am_elected = (strcmp(m_ip, my_ip) == 0);

	/* Designate the BACKUP: the highest-IP in-window peer that is not the
	 * master.  Deterministic across all nodes, so everyone agrees who takes
	 * over next; on master failure cc_elect_master (no live current master)
	 * promotes exactly this node.                                         */
	for (j = 0; j < cl->peers->count; j++) {
	    cc_peer_t *e = &cl->peers->entries[j];
	    if (j == master_idx || !e->in_election)
		continue;
	    if (e->ip_num > b_num) {
		b_num = e->ip_num;
		b_idx = j;
	    }
	}
	if (b_idx >= 0)
	    cl->peers->entries[b_idx].is_backup = 1;
	b_ip = (b_idx >= 0) ? cl->peers->entries[b_idx].ip : NULL;

	master_changed = (strcmp(prev_master, m_ip) != 0);
	backup_changed = (strcmp(prev_backup, b_ip ? b_ip : "") != 0);

	/* Persist the elected master for the next round / other handlers. */
	{
	    size_t _l = strnlen(m_ip, CC_MAX_IP_LEN);
	    memcpy(cl->peers->last_master, m_ip, _l);
	    cl->peers->last_master[_l] = '\0';
	}

	/* One clear line whenever the master or backup role changes, stating
	 * who holds each role, which is this node, and WHY the master was
	 * chosen (highest IP, sticky current master kept over a higher-IP peer, or
	 * sole surviving node).                                               */
	if (master_changed || backup_changed) {
	    if (n_in <= 1)
		why = "sole node in window";
	    else if (cl->master_stickiness == 1 && master_idx == cur_master_idx &&
	             top_idx >= 0 && top_idx != master_idx)
		why = "sticky: current master kept over higher-IP node";
	    else
		why = "highest IP in window";

	    LM_INFO("clusterer_controller: [cluster %d] roles: MASTER=%s%s (%s); "
	            "BACKUP=%s%s (highest-IP non-master); %d node(s) in window\n",
	            cl->cluster_id,
	            m_ip,
	            strcmp(m_ip, my_ip) == 0 ? " [me]" : "",
	            why,
	            b_ip ? b_ip : "(none)",
	            (b_ip && strcmp(b_ip, my_ip) == 0) ? " [me]" : "",
	            n_in);
	}
    } else {
	/* No eligible peer - cluster has no master */
	if (cl->peers->last_master[0] != '\0') {
	    LM_INFO("clusterer_controller: [cluster %d] master lost (%s), "
	            "no eligible peers in election window\n",
	            cl->cluster_id, cl->peers->last_master);
	    cl->peers->last_master[0] = '\0';
	}
    }

    /* Invariant: MASTER_ALIVE keepalive armed <=> I am the elected master.
     * If this election demoted us (someone else won, or no master at all) but
     * our keepalive is still running, stop it now - otherwise we keep
     * broadcasting MASTER_ALIVE as a phantom master and lower-IP peers
     * oscillate between two masters.  Only disarm here: promoting a new master
     * (arming) is done by the became-master paths, which also establish the
     * session key.  cc_arm_master_timers() only issues timerfd syscalls, so it
     * is safe under cl->peers->lock. */
    if (!i_am_elected && cl->master_ka_armed)
	cc_arm_master_timers(cl, 0);
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
 * Returns 0 when the current master has a higher or equal IP - it would
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
    return 1;   /* no master in the election window - election is needed */
}

/**
 * cc_apply_shtags_decision() - (de)activate this node's sharing tags per policy.
 *
 * Decides whether THIS node should be the active sharing-tag holder for the
 * cluster and calls clusterer accordingly.  Idempotent (activate/force-backup
 * are no-ops when already in that state), so it is safe to call on any relevant
 * event.  Takes NO lock - the caller passes the state it already read, so this
 * is safe both inside and outside cl->peers->lock (clctl uses its own locks).
 *
 *   forced != 0 : the operator pinned node_id 'forced' as the active holder
 *                 (cl_ctr_shtag_force).  Only that node activates; all others go
 *                 to backup.  Automatic allocation is suspended.
 *   forced == 0 : automatic mode - the current master is the active holder.
 */
static void cc_apply_shtags_decision(cc_cluster_t *cl, int i_am_master,
                                     uint16_t forced)
{
    int activate;

    if (!cl->manage_shtags || !clctl_loaded || !clctl.activate_backup_shtags)
        return;

    if (forced != 0)
        activate = (my_node_id != 0 && (uint16_t)my_node_id == forced);
    else
        activate = i_am_master;

    /* Log the reason on this node, but only when the decision or its cause
     * changes - cc_apply_shtags_decision() is called on every relevant event
     * and clusterer's own activate/force calls are idempotent, so logging
     * unconditionally would flood.  This makes the "why" visible on EVERY
     * node (master, forced holder, and passive backups alike).             */
    if (activate != cl->shtag_last_active || forced != cl->shtag_last_forced) {
        if (activate && forced != 0)
            LM_INFO("clusterer_controller: [cluster %d] activating sharing tags "
                    "- operator forced this node (node_id %u) as active holder\n",
                    cl->cluster_id, forced);
        else if (activate)
            LM_INFO("clusterer_controller: [cluster %d] activating sharing tags "
                    "- this node is the cluster master\n", cl->cluster_id);
        else if (forced != 0)
            LM_INFO("clusterer_controller: [cluster %d] keeping sharing tags in "
                    "backup - operator forced node_id %u as active holder\n",
                    cl->cluster_id, forced);
        else
            LM_INFO("clusterer_controller: [cluster %d] keeping sharing tags in "
                    "backup - active holder is the cluster master\n",
                    cl->cluster_id);
        cl->shtag_last_active = activate;
        cl->shtag_last_forced = forced;
    }

    if (activate)
        clctl.activate_backup_shtags(cl->cluster_id);
    else if (clctl.force_backup_shtags)
        clctl.force_backup_shtags(cl->cluster_id);
}

/**
 * cc_apply_shtags() - convenience wrapper that reads the current state under a
 * read lock and applies the shtag decision.  Call WITHOUT cl->peers->lock held.
 */
static void cc_apply_shtags(cc_cluster_t *cl)
{
    int      i_am_master;
    uint16_t forced;

    lock_start_read(cl->peers->lock);
    i_am_master = cc_i_am_master_locked(cl);
    forced      = cl->peers->shtag_forced_node_id;
    lock_stop_read(cl->peers->lock);

    cc_apply_shtags_decision(cl, i_am_master, forced);
}

/**
 * cc_prune_stale(cl) - free entries far outside the election window.
 * Memory management only - does not affect election outcomes.
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
	    cc_apply_shtags_decision(cl, cc_i_am_master_locked(cl),
	                             cl->peers->shtag_forced_node_id);
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
 * A 12-byte random nonce (generated fresh for each packet via WolfSSL RNG)
 * ensures that even identical payloads produce different ciphertext.
 *
 * A 4-byte monotonic sequence number is included inside the plaintext.
 * Receivers track the highest sequence seen from each peer and reject any
 * packet whose sequence is not strictly greater.  This stops replays
 * without requiring NTP-synchronised clocks or a finite nonce cache.
 * The counter resets to 0 on every session key rotation; old packets
 * encrypted with the previous key fail AES-GCM authentication anyway.
 * Bootstrap-key packets (CC_BOOTSTRAP_MAGIC) skip the sequence check -
 * their per-exchange join_nonce provides equivalent replay protection.
 *
 * Wire layout:
 *   [magic 2B][cluster_id 2B][nonce 12B][ciphertext][GCM tag 16B]
 * Plaintext:
 *   [type 1B][seq 4B][payload]
 * ========================================================================= */

static int cc_hkdf_sha256(const unsigned char *ikm,  size_t ikm_len,
                           const unsigned char *salt, size_t salt_len,
                           const char          *info,
                           unsigned char        out[32])
{
    size_t info_len = info ? strlen(info) : 0;
    return wc_HKDF(WC_SHA256,
                   ikm,  (word32)ikm_len,
                   salt, (word32)salt_len,
                   (const byte *)info, (word32)info_len,
                   out, 32) == 0 ? 0 : -1;
}

static int cc_gen_ecdh_keypair(unsigned char *privkey, unsigned char *pubkey)
{
    curve25519_key k;
    word32         len = CC_PUBKEY_SZ;
    int            rc  = -1;

    if (wc_curve25519_init(&k) != 0) goto done;
    if (wc_curve25519_make_key(&cc_rng, 32, &k) != 0) goto free;
    if (wc_curve25519_export_private_raw(&k, privkey, &len) != 0) goto free;
    len = CC_PUBKEY_SZ;
    if (wc_curve25519_export_public(&k, pubkey, &len) != 0) goto free;
    rc = 0;
free:
    wc_curve25519_free(&k);
done:
    if (rc < 0)
        LM_ERR("clusterer_controller: X25519 keygen failed\n");
    return rc;
}

static int cc_ecdh_shared(const unsigned char *my_priv,
                           const unsigned char *peer_pub,
                           unsigned char        out[CC_PUBKEY_SZ])
{
    curve25519_key priv_k, pub_k;
    word32         len = CC_PUBKEY_SZ;
    int            rc  = -1;

    if (wc_curve25519_init(&priv_k) != 0) return -1;
    if (wc_curve25519_init(&pub_k)  != 0) { wc_curve25519_free(&priv_k); return -1; }

    if (wc_curve25519_import_private(my_priv,  CC_PUBKEY_SZ, &priv_k) != 0) goto done;
    if (wc_curve25519_import_public(peer_pub,  CC_PUBKEY_SZ, &pub_k)  != 0) goto done;
    if (wc_curve25519_shared_secret(&priv_k, &pub_k, out, &len)           != 0) goto done;
    rc = 0;
done:
    wc_curve25519_free(&priv_k);
    wc_curve25519_free(&pub_k);
    if (rc < 0)
        LM_ERR("clusterer_controller: X25519 derive failed\n");
    return rc;
}

/**
 * cc_wrap_salt() - XOR-encrypt master_salt for a specific peer using ECDH.
 * wrap_key = HKDF(ECDH(my_priv, peer_pub) || password [|| nonce], info)
 * wrapped   = master_salt XOR wrap_key
 *
 * nonce/nonce_len are optional (pass NULL/0 for KEY_HANDOFF).
 * For KEY_GRANT, nonce is the per-exchange join_nonce from the JOIN_REQ,
 * making every wrap_key unique even if the password is later compromised.
 */
static int cc_wrap_salt(const unsigned char *my_priv,
                        const unsigned char *peer_pub,
                        const char          *password,
                        const unsigned char *master_salt,
                        const char          *info,
                        const unsigned char *nonce,
                        size_t               nonce_len,
                        unsigned char        wrapped[CC_MASTER_SALT_SZ])
{
    unsigned char ss[CC_PUBKEY_SZ];
    unsigned char ikm[CC_PUBKEY_SZ + 1024 + CC_JOIN_NONCE_SZ];
    size_t        pass_len = strlen(password);
    size_t        ikm_len;
    unsigned char wrap_key[32];
    int i;

    if (cc_ecdh_shared(my_priv, peer_pub, ss) < 0)
        return -1;

    /* IKM = ss || password [|| nonce] */
    memcpy(ikm, ss, CC_PUBKEY_SZ);
    if (pass_len > 1024) pass_len = 1024;
    memcpy(ikm + CC_PUBKEY_SZ, password, pass_len);
    ikm_len = CC_PUBKEY_SZ + pass_len;
    if (nonce && nonce_len > 0) {
        if (nonce_len > CC_JOIN_NONCE_SZ) nonce_len = CC_JOIN_NONCE_SZ;
        memcpy(ikm + ikm_len, nonce, nonce_len);
        ikm_len += nonce_len;
    }

    if (cc_hkdf_sha256(ikm, ikm_len,
                        ss, CC_PUBKEY_SZ,   /* use ss as salt too */
                        info, wrap_key) < 0)
        return -1;

    for (i = 0; i < CC_MASTER_SALT_SZ; i++)
        wrapped[i] = master_salt[i] ^ wrap_key[i];
    return 0;
}

/**
 * cc_derive_session_key() - derive group key from password + master_salt.
 * Reads master_salt from cl->peers->master_salt (shm, caller holds write lock).
 * Stores result in cl->session_key (worker-local cache).
 * Must be called with cl->peers->lock held for WRITE.
 */
static int cc_derive_session_key(cc_cluster_t *cl)
{
    int i;
    size_t pass_len = strlen(cl->password);
    if (cc_hkdf_sha256((unsigned char *)cl->password, pass_len,
                        cl->peers->master_salt, CC_MASTER_SALT_SZ,
                        "cc_session", cl->session_key) < 0) {
        LM_ERR("clusterer_controller: [cluster %d] session key derivation failed\n",
               cl->cluster_id);
        return -1;
    }
    /* Reset sequence counters: old packets encrypted with the previous key
     * fail AES-GCM authentication, so starting from 0 is safe. */
    cl->peers->my_seq = 0;
    for (i = 0; i < cl->peers->count; i++)
        cl->peers->entries[i].last_seq = 0;
    cl->have_session_key = 1;   /* a valid group key now exists */
    return 0;
}


/**
 * cc_password_entropy_bits() - conservative estimate of a password's entropy.
 * bits ~= length * floor(log2(charset)), where charset is the union of the
 * character classes present.  floor() makes it a slight under-estimate, so the
 * weak-password warning errs toward firing.  No libm dependency.
 */
static int cc_password_entropy_bits(const char *p)
{
    int    have_lower = 0, have_upper = 0, have_digit = 0, have_sym = 0;
    int    charset, bits_per_char = 0, tmp;
    size_t i, len = strlen(p);

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)p[i];
        if      (c >= 'a' && c <= 'z') have_lower = 1;
        else if (c >= 'A' && c <= 'Z') have_upper = 1;
        else if (c >= '0' && c <= '9') have_digit = 1;
        else                           have_sym   = 1;
    }
    charset = have_lower * 26 + have_upper * 26 + have_digit * 10 + have_sym * 33;
    if (charset < 2)
        charset = 2;
    for (tmp = charset; tmp > 1; tmp >>= 1)
        bits_per_char++;
    return (int)(len * (size_t)bits_per_char);
}

/**
 * cc_derive_key() - derive the 32-byte bootstrap (admission) key from the
 * shared password.  Used only for the join handshake (JOIN_REQ / KEY_GRANT /
 * JOIN_REJECT); normal traffic uses the ECDH-agreed session key.
 *
 * Uses scrypt (memory-hard) rather than a single SHA-256 so that a password
 * captured from a JOIN packet cannot be brute-forced cheaply offline.  Called
 * once per cluster from mod_init() in the main process before fork, so the
 * ~64 MiB scrypt working set is a transient startup cost only; workers inherit
 * the derived key and never run scrypt.
 */
static int cc_derive_key(cc_cluster_t *cl)
{
    char salt[64];
    int  saltlen, bits;

    /* Warn on a weak or default admission password.  scrypt raises the cost of
     * each offline guess, but only a high-entropy secret removes the risk. */
    if (strcmp(cl->password, CC_DEFAULT_PASSWORD) == 0) {
        LM_WARN("clusterer_controller: [cluster %d] using the built-in default "
                "password - set a strong 'password' (e.g. `openssl rand -base64 32`)\n",
                cl->cluster_id);
    } else {
        bits = cc_password_entropy_bits(cl->password);
        if (bits < CC_MIN_PASSWORD_BITS)
            LM_WARN("clusterer_controller: [cluster %d] weak password (~%d bits "
                    "of entropy) - an attacker who captures a JOIN packet can "
                    "brute-force it offline; use a long random string, e.g. "
                    "`openssl rand -base64 32`\n", cl->cluster_id, bits);
    }

    /* Per-cluster salt: a fixed domain-separation label plus the multicast
     * address, so the same password on different clusters yields different
     * bootstrap keys.  The salt is public by design - scrypt's work factor,
     * not salt secrecy, is what defeats brute force.                        */
    saltlen = snprintf(salt, sizeof(salt), "opensips-cc-bootstrap-v1:%s",
                       cl->multicast_address);
    if (saltlen < 0 || saltlen >= (int)sizeof(salt))
        saltlen = (int)strlen(salt);

#ifdef CC_HAVE_SODIUM
    /* Argon2id.  crypto_pwhash needs a fixed-length 16-byte salt, so fold our
     * variable-length domain-separation salt into one with BLAKE2b.           */
    {
        unsigned char salt16[crypto_pwhash_SALTBYTES];
        crypto_generichash(salt16, sizeof(salt16),
                           (const unsigned char *)salt, (size_t)saltlen, NULL, 0);
        if (crypto_pwhash(cl->key, 32,
                          cl->password, strlen(cl->password),
                          salt16, CC_ARGON2_OPSLIMIT, CC_ARGON2_MEMLIMIT,
                          crypto_pwhash_ALG_ARGON2ID13) != 0) {
            LM_ERR("clusterer_controller: key derivation (Argon2id) failed for "
                   "cluster %d (out of memory?)\n", cl->cluster_id);
            return -1;
        }
    }
#else
    if (wc_scrypt(cl->key, (const byte *)cl->password, (int)strlen(cl->password),
                  (const byte *)salt, saltlen,
                  CC_SCRYPT_COST, CC_SCRYPT_BLOCKSIZE, CC_SCRYPT_PARALLEL,
                  32) != 0) {
	LM_ERR("clusterer_controller: key derivation (scrypt) failed for "
	       "cluster %d\n", cl->cluster_id);
	return -1;
    }
#endif
    return 0;
}

/**
 * cc_encrypt_pkt() - encrypt plaintext in-place and append the GCM tag.
 *
 * On entry:  buf[0..CC_MAGIC_SZ-1]   = magic (set by caller)
 *            buf[plain_off..]        = plaintext to encrypt
 * On return: buf[CC_MAGIC_SZ..]      = cleartext cluster_id (BE)
 *            buf[CC_NONCE_OFF..]     = random nonce
 *            buf[plain_off..]        = ciphertext (same length)
 *            buf[plain_off+plain_len..+CC_TAG_SZ-1] = GCM tag
 *
 * @return total packet length, or -1 on error
 */
static int cc_encrypt_pkt(char *buf, int plain_off, int plain_len,
                          const unsigned char *key, int cluster_id)
{
    uint16_t      cid_be = htons((uint16_t)cluster_id);

    memcpy(buf + CC_MAGIC_SZ, &cid_be, CC_CLUSTER_ID_SZ);  /* cleartext selector */

    /* AAD = cleartext header (magic + cluster_id): binding it to the tag stops
     * a captured packet being re-stamped with another cluster_id on a shared
     * multicast+password group (cross-cluster injection).  The nonce is the
     * AEAD IV, already bound.  Random nonces are safe here: at this volume the
     * AES-GCM 96-bit collision bound is unreachable, and XChaCha20's 192-bit
     * nonce removes the concern outright.                                     */
#ifdef CC_HAVE_SODIUM
    {
        unsigned char      nonce[CC_NONCE_SZ];
        unsigned long long clen = 0;
        randombytes_buf(nonce, CC_NONCE_SZ);
        memcpy(buf + CC_NONCE_OFF, nonce, CC_NONCE_SZ);
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                (unsigned char *)buf + plain_off, &clen,
                (const unsigned char *)buf + plain_off, (unsigned long long)plain_len,
                (const unsigned char *)buf, CC_MAGIC_SZ + CC_CLUSTER_ID_SZ,
                NULL, nonce, key) != 0) {
            LM_ERR("clusterer_controller: XChaCha20-Poly1305 encrypt failed\n");
            return -1;
        }
        return plain_off + (int)clen;   /* clen = plain_len + CC_TAG_SZ */
    }
#else
    {
        Aes           aes;
        unsigned char nonce[CC_NONCE_SZ];
        unsigned char tag[CC_TAG_SZ];
        if (wc_RNG_GenerateBlock(&cc_rng, nonce, CC_NONCE_SZ) != 0) {
            LM_ERR("clusterer_controller: RNG failed\n");
            return -1;
        }
        memcpy(buf + CC_NONCE_OFF, nonce, CC_NONCE_SZ);
        if (wc_AesGcmSetKey(&aes, key, 32) != 0) {
            LM_ERR("clusterer_controller: AesGcmSetKey failed\n");
            return -1;
        }
        if (wc_AesGcmEncrypt(&aes,
                             (byte *)buf + plain_off,
                             (const byte *)buf + plain_off, (word32)plain_len,
                             nonce, CC_NONCE_SZ,
                             tag, CC_TAG_SZ,
                             (const byte *)buf, CC_MAGIC_SZ + CC_CLUSTER_ID_SZ) != 0) {
            LM_ERR("clusterer_controller: AesGcmEncrypt failed\n");
            wc_AesFree(&aes);
            return -1;
        }
        wc_AesFree(&aes);
        memcpy(buf + plain_off + plain_len, tag, CC_TAG_SZ);
        return plain_off + plain_len + CC_TAG_SZ;
    }
#endif
}

/**
 * cc_decrypt_pkt() - authenticate and decrypt a received packet in-place.
 *
 * On entry:  buf = [magic 2B][cluster_id 2B][nonce][ciphertext][tag 16B]
 * On return: buf[CC_WIRE_HDR_SZ..] = plaintext (type + seq + payload)
 *
 * AAD must match cc_encrypt_pkt(): the cleartext header (magic+cluster_id), so
 * a packet re-stamped with another cluster_id fails authentication.
 *
 * @return 0 on success, -1 to drop (wrong key, tampered, or too short)
 */
static int cc_decrypt_pkt(char *buf, ssize_t n, const char *sender_ip,
                          const unsigned char *key, int is_bootstrap)
{
    ssize_t cipher_len = n - CC_WIRE_HDR_SZ - CC_TAG_SZ;   /* plaintext length */

    if (cipher_len <= 0) {
	LM_INFO("clusterer_controller: packet from %s too short to decrypt "
	        "(%zd bytes)\n", sender_ip, n);
	return -1;
    }

#ifdef CC_HAVE_SODIUM
    {
        unsigned char     *nonce = (unsigned char *)buf + CC_NONCE_OFF;
        unsigned long long mlen  = 0;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                (unsigned char *)buf + CC_WIRE_HDR_SZ, &mlen, NULL,
                (const unsigned char *)buf + CC_WIRE_HDR_SZ,
                (unsigned long long)(cipher_len + CC_TAG_SZ),
                (const unsigned char *)buf, CC_MAGIC_SZ + CC_CLUSTER_ID_SZ,
                nonce, key) != 0) {
            if (is_bootstrap)
                LM_WARN("clusterer_controller: bootstrap decryption failed "
                        "from %s - wrong password, foreign cluster, or "
                        "tampered packet\n", sender_ip);
            else
                LM_DBG("clusterer_controller: session packet from %s did not "
                       "decrypt - transient key mismatch during (re)key or "
                       "split-brain heal\n", sender_ip);
            return -1;
        }
    }
#else
    {
        Aes            aes;
        unsigned char *nonce = (unsigned char *)buf + CC_NONCE_OFF;
        unsigned char *tag   = (unsigned char *)buf + n - CC_TAG_SZ;
        int            ret;
        if (wc_AesGcmSetKey(&aes, key, 32) != 0) {
            LM_ERR("clusterer_controller: AesGcmSetKey failed\n");
            return -1;
        }
        ret = wc_AesGcmDecrypt(&aes,
                               (byte *)buf + CC_WIRE_HDR_SZ,
                               (const byte *)buf + CC_WIRE_HDR_SZ, (word32)cipher_len,
                               nonce, CC_NONCE_SZ,
                               tag, CC_TAG_SZ,
                               (const byte *)buf, CC_MAGIC_SZ + CC_CLUSTER_ID_SZ);
        wc_AesFree(&aes);
        if (ret != 0) {
            if (is_bootstrap)
                LM_WARN("clusterer_controller: bootstrap decryption failed "
                        "from %s - wrong password, foreign cluster, or "
                        "tampered packet\n", sender_ip);
            else
                LM_DBG("clusterer_controller: session packet from %s did not "
                       "decrypt - transient key mismatch during (re)key or "
                       "split-brain heal\n", sender_ip);
            return -1;
        }
    }
#endif
    return 0;
}

/**
 * cc_check_and_update_seq() - reject replayed or reordered packets.
 * Looks up sender_ip in the peer table; requires pkt_seq > last_seq.
 * Updates last_seq on accept.  Unknown senders (new nodes not yet in
 * the peer table) are accepted so their first packet (ALIVE/JOIN_REQ)
 * can populate the table.
 * Only called for CC_PACKET_MAGIC packets; bootstrap packets use join_nonce.
 * Single-threaded caller (cc_worker reactor); no lock needed for the check.
 * @return 0 to accept, -1 to drop.
 */
static int cc_check_and_update_seq(const char *sender_ip, uint32_t pkt_seq,
                                   cc_cluster_t *cl)
{
    int i;
    for (i = 0; i < cl->peers->count; i++) {
        if (strcmp(cl->peers->entries[i].ip, sender_ip) == 0) {
            if (pkt_seq <= cl->peers->entries[i].last_seq) {
                LM_WARN("clusterer_controller: replay from %s seq=%u last=%u, dropping\n",
                        sender_ip, pkt_seq, cl->peers->entries[i].last_seq);
                return -1;
            }
            cl->peers->entries[i].last_seq = pkt_seq;
            return 0;
        }
    }
    return 0;   /* unknown sender: accept, handler will upsert into peer table */
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
     * my_ip as source address - this makes self-loopback detection in
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
	    /* Requires CAP_NET_RAW - not available after privilege drop.
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
	/* non-fatal - we continue; send paths handle EAGAIN explicitly */
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
 * ALIVE: [type 1B][seq 4B][ip NUL][pubkey 32B]   - peers learn our pubkey here
 * GOODBYE: [type 1B][seq 4B][ip NUL]              - no pubkey needed
 */
static void cc_send_pkt_with_ip(int sock, unsigned char type, cc_cluster_t *cl)
{
    /* Sized for ALIVE which carries an extra pubkey + config descriptor */
    char               pkt[CC_SMALL_PKT_SZ + CC_PUBKEY_SZ + CC_CONFIG_SZ];
    uint32_t           seq     = htonl(++cl->peers->my_seq);
    int                ip_len  = (int)strlen(my_ip);
    int                plain_len, total_len;
    struct sockaddr_in dest;

    if (ip_len > CC_MAX_IP_LEN)
	ip_len = CC_MAX_IP_LEN;

    memcpy(pkt, CC_PACKET_MAGIC, CC_MAGIC_SZ);

    pkt[CC_WIRE_HDR_SZ] = (char)type;
    memcpy(pkt + CC_WIRE_HDR_SZ + 1, &seq, CC_SEQ_SZ);
    memcpy(pkt + CC_WIRE_HDR_SZ + 1 + CC_SEQ_SZ, my_ip, ip_len);
    pkt[CC_WIRE_HDR_SZ + 1 + CC_SEQ_SZ + ip_len] = '\0';
    plain_len = 1 + CC_SEQ_SZ + ip_len + 1;

    /* ALIVE appends our X25519 public key so peers accumulate pubkeys
     * without bloating MEMBER_LIST (avoids excessive IP fragmentation). */
    if (type == CC_PKT_ALIVE) {
	memcpy(pkt + CC_WIRE_HDR_SZ + plain_len, cl->my_pubkey, CC_PUBKEY_SZ);
	plain_len += CC_PUBKEY_SZ;
	/* Advertise our effective consistency-critical config so peers can
	 * detect accidental per-node config drift for the same cluster. */
	{
	    char    *c  = pkt + CC_WIRE_HDR_SZ + plain_len;
	    uint16_t qt = htons((uint16_t)(query_time & 0xFFFF));
	    c[0] = (char)(cl->manage_shtags ? 1 : 0);
	    c[1] = (char)(cl->master_stickiness ? 1 : 0);
	    memcpy(c + 2, &qt, 2);
	    plain_len += CC_CONFIG_SZ;
	}
    }

    total_len = cc_encrypt_pkt(pkt, CC_WIRE_HDR_SZ, plain_len, cl->session_key, cl->cluster_id);
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
 * Wire: [magic 2B][cluster_id 2B][nonce 12B][AES-256-GCM([type 1B][seq 4B][count 2B][entries...])][tag 16B]
 */
static void cc_send_list_pkt(int sock, unsigned char type, cc_cluster_t *cl)
{
    char               pkt[CC_LIST_PKT_MAX_SZ];
    uint32_t           seq      = htonl(++cl->peers->my_seq);
    uint16_t           count    = 0;
    uint16_t           count_be;
    char              *p;
    time_t             cutoff;
    struct sockaddr_in dest;
    int                i, plain_len, total_len;

    memcpy(pkt, CC_PACKET_MAGIC, CC_MAGIC_SZ);
    /* nonce at [8..19] written by cc_encrypt_pkt */

    /* Plaintext: [type][seq][count BE][forced_shtag_node_id BE][entries...] */
    pkt[CC_WIRE_HDR_SZ] = (char)type;
    memcpy(pkt + CC_WIRE_HDR_SZ + 1, &seq, CC_SEQ_SZ);
    /* count filled after iteration; forced_shtag_node_id filled below */
    p = pkt + CC_WIRE_HDR_SZ + 1 + CC_SEQ_SZ + CC_LIST_COUNT_SZ + CC_NODE_ID_SZ;

    cutoff = time(NULL) - (time_t)(query_time * CC_ELECT_FACTOR);

    lock_start_read(cl->peers->lock);
    {
	uint16_t forced_be = htons(cl->peers->shtag_forced_node_id);
	memcpy(pkt + CC_WIRE_HDR_SZ + 1 + CC_SEQ_SZ + CC_LIST_COUNT_SZ,
	       &forced_be, CC_NODE_ID_SZ);
    }

    for (i = 0; i < cl->peers->count && count < CC_MAX_PEERS; i++) {
	cc_peer_t *e = &cl->peers->entries[i];
	if (e->last_seen < cutoff)
	    continue;
	/* Entry layout: [ip 16B null-padded][is_master 1B] = 17B */
	memset(p, 0, CC_IP_ENTRY_SZ);
	memcpy(p, e->ip, strnlen(e->ip, CC_MAX_IP_LEN));
	p[CC_IP_ENTRY_SZ - 1] = (char)(e->is_master ? 1 : 0);
	p += CC_IP_ENTRY_SZ;
	count++;
    }

    lock_stop_read(cl->peers->lock);

    count_be = htons(count);
    memcpy(pkt + CC_WIRE_HDR_SZ + 1 + CC_SEQ_SZ, &count_be, CC_LIST_COUNT_SZ);

    plain_len = 1 + CC_SEQ_SZ + CC_LIST_COUNT_SZ + CC_NODE_ID_SZ
                + count * CC_IP_ENTRY_SZ;
    total_len = cc_encrypt_pkt(pkt, CC_WIRE_HDR_SZ, plain_len, cl->session_key, cl->cluster_id);
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
    uint32_t           seq;

    /* Rate-limit JOIN_REQ transmissions.  During a key-mismatch / split-brain
     * heal several code paths (defer timer, session-mismatch re-key, rejoin
     * timer) can each ask to (re)send a JOIN_REQ within the same second.  A
     * JOIN_REQ is idempotent - the master answers whichever one arrives - so
     * drop any that lands within CC_JOIN_REQ_MIN_US of the previous send; the
     * next timer tick resends if the join is still pending.  The very first
     * send (last_join_req_utime == 0) is never throttled.                     */
    {
        utime_t now_us = get_uticks();
        if (cl->last_join_req_utime != 0 &&
            (utime_t)(now_us - cl->last_join_req_utime) < CC_JOIN_REQ_MIN_US)
            return;
        cl->last_join_req_utime = now_us;
    }

    seq = htonl(++cl->peers->my_seq);
    int                ip_len  = (int)strlen(my_ip);
    char              *p;
    int                plain_len, total_len;
    struct sockaddr_in dest;

    if (ip_len > CC_MAX_IP_LEN)
	ip_len = CC_MAX_IP_LEN;

    memcpy(pkt, CC_BOOTSTRAP_MAGIC, CC_MAGIC_SZ);  /* JOIN_REQ uses bootstrap key */

    /* Plaintext: [type][seq][ip NUL][bin_count][sock1 NUL]...[sockN NUL][pubkey 32B] */
    pkt[CC_WIRE_HDR_SZ] = (char)CC_PKT_JOIN_REQ;
    memcpy(pkt + CC_WIRE_HDR_SZ + 1, &seq, CC_SEQ_SZ);
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

    /* Append our X25519 public key so master can wrap the session salt for us */
    memcpy(p, cl->my_pubkey, CC_PUBKEY_SZ);
    p += CC_PUBKEY_SZ;

    /* Append per-exchange nonce; master echoes it in KEY_GRANT to bind the
     * ECDH wrap to this specific exchange even if password is later compromised */
    if (wc_RNG_GenerateBlock(&cc_rng, cl->my_join_nonce, CC_JOIN_NONCE_SZ) != 0) {
	LM_ERR("clusterer_controller: RNG for join_nonce failed\n");
	return;
    }
    memcpy(p, cl->my_join_nonce, CC_JOIN_NONCE_SZ);
    p += CC_JOIN_NONCE_SZ;

    /* Advertise our consistency-critical config so the master can reject (or
     * warn about) a join with settings that differ from the running cluster. */
    {
	uint16_t qt = htons((uint16_t)(query_time & 0xFFFF));
	*p++ = (char)(cl->manage_shtags ? 1 : 0);
	*p++ = (char)(cl->master_stickiness ? 1 : 0);
	memcpy(p, &qt, 2);
	p += 2;
    }

    plain_len = (int)(p - (pkt + CC_WIRE_HDR_SZ));
    total_len = cc_encrypt_pkt(pkt, CC_WIRE_HDR_SZ, plain_len, cl->key, cl->cluster_id);
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
    uint32_t           seq      = htonl(++cl->peers->my_seq);
    uint16_t           nid_be   = htons(node_id);
    int                ip_len   = (int)strnlen(ip, CC_MAX_IP_LEN);
    char              *p;
    int                i, plain_len, total_len;
    struct sockaddr_in dest;

    memcpy(pkt, CC_PACKET_MAGIC, CC_MAGIC_SZ);

    pkt[CC_WIRE_HDR_SZ] = (char)CC_PKT_NODE_ASSIGN;
    memcpy(pkt + CC_WIRE_HDR_SZ + 1, &seq, CC_SEQ_SZ);
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
    /* NODE_ASSIGN carries the CC_PACKET_MAGIC session magic, so the receiver
     * decrypts it with session_key.  It MUST therefore be encrypted with
     * session_key, not the bootstrap key - otherwise every NODE_ASSIGN fails
     * GCM auth on receipt ("session key mismatch"), driving a JOIN_REQ storm.
     * KEY_GRANT is sent before NODE_ASSIGN so the joiner already holds the
     * session key by the time this arrives. */
    total_len = cc_encrypt_pkt(pkt, CC_WIRE_HDR_SZ, plain_len, cl->session_key, cl->cluster_id);
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


/**
 * cc_send_master_alive() - master-only keepalive, no payload beyond the header.
 * Encrypted with session_key (CC_PACKET_MAGIC).
 */
static void cc_send_master_alive(int sock, cc_cluster_t *cl)
{
    char               pkt[CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ + CC_TAG_SZ];
    uint32_t           seq   = htonl(++cl->peers->my_seq);
    int                total_len;
    struct sockaddr_in dest;

    memcpy(pkt, CC_PACKET_MAGIC, CC_MAGIC_SZ);
    pkt[CC_WIRE_HDR_SZ]     = (char)CC_PKT_MASTER_ALIVE;
    memcpy(pkt + CC_WIRE_HDR_SZ + 1, &seq, CC_SEQ_SZ);
    /* no payload beyond type+seq */

    total_len = cc_encrypt_pkt(pkt, CC_WIRE_HDR_SZ, CC_PLAIN_HDR_SZ,
                               cl->session_key, cl->cluster_id);
    if (total_len < 0) return;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons((uint16_t)cl->multicast_port);
    dest.sin_addr.s_addr = inet_addr(cl->multicast_address);

    if (sendto(sock, pkt, total_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0)
        LM_ERR("clusterer_controller: [cluster %d] sendto MASTER_ALIVE: %s\n",
               cl->cluster_id, strerror(errno));
}

/**
 * cc_send_master_beacon() - master-only split-brain merge announcement.
 *
 * Encrypted with the BOOTSTRAP key (CC_BOOTSTRAP_MAGIC) - unlike MASTER_ALIVE,
 * which uses the per-cluster session key.  Every correctly-configured node
 * shares the bootstrap key, so two masters that hold *different* session keys
 * (e.g. after an all-node simultaneous cold start) can still read each other's
 * beacon and reconcile.  Payload is this partition's member count (2B BE); the
 * sender IP comes from the datagram source.  See cc_handle_master_beacon().
 */
static void cc_send_master_beacon(int sock, cc_cluster_t *cl)
{
    char               pkt[CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ + 2 + CC_TAG_SZ];
    uint32_t           seq   = htonl(++cl->peers->my_seq);
    uint16_t           cnt_be;
    int                total_len;
    struct sockaddr_in dest;

    lock_start_read(cl->peers->lock);
    cnt_be = htons((uint16_t)cl->peers->count);
    lock_stop_read(cl->peers->lock);

    memcpy(pkt, CC_BOOTSTRAP_MAGIC, CC_MAGIC_SZ);
    pkt[CC_WIRE_HDR_SZ] = (char)CC_PKT_MASTER_BEACON;
    memcpy(pkt + CC_WIRE_HDR_SZ + 1, &seq, CC_SEQ_SZ);
    memcpy(pkt + CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ, &cnt_be, 2);

    total_len = cc_encrypt_pkt(pkt, CC_WIRE_HDR_SZ, CC_PLAIN_HDR_SZ + 2,
                               cl->key, cl->cluster_id);
    if (total_len < 0) return;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons((uint16_t)cl->multicast_port);
    dest.sin_addr.s_addr = inet_addr(cl->multicast_address);

    if (sendto(sock, pkt, total_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0)
        LM_ERR("clusterer_controller: [cluster %d] sendto MASTER_BEACON: %s\n",
               cl->cluster_id, strerror(errno));
}

/**
 * cc_send_key_grant() - send ECDH-wrapped master_salt to a joining node.
 * Encrypted with bootstrap key (CC_BOOTSTRAP_MAGIC) so the joining node
 * can read it before having the session key.
 *
 * Payload: [target_ip NUL][my_pubkey 32B][join_nonce 16B][wrapped_salt 32B]
 *
 * join_nonce is the per-exchange nonce from the JOIN_REQ.  It is echoed back
 * here (inside the authenticated GCM envelope) and folded into cc_wrap_salt's
 * IKM so the wrap_key is unique per exchange even if the password leaks.
 */
static void cc_send_key_grant(int sock, const char *target_ip, cc_cluster_t *cl,
                              const unsigned char *joiner_pubkey,
                              const unsigned char *joiner_nonce)
{
    char               pkt[CC_KEY_GRANT_SZ];
    uint32_t           seq     = htonl(++cl->peers->my_seq);
    unsigned char      wrapped[CC_MASTER_SALT_SZ];
    char              *p;
    int                ip_len, plain_len, total_len;
    struct sockaddr_in dest;

    if (cc_wrap_salt(cl->my_privkey, joiner_pubkey, cl->password,
                     cl->peers->master_salt, "cc_key_grant",
                     joiner_nonce, CC_JOIN_NONCE_SZ, wrapped) < 0)
        return;

    ip_len = (int)strnlen(target_ip, CC_MAX_IP_LEN);

    memcpy(pkt, CC_BOOTSTRAP_MAGIC, CC_MAGIC_SZ);
    pkt[CC_WIRE_HDR_SZ] = (char)CC_PKT_KEY_GRANT;
    memcpy(pkt + CC_WIRE_HDR_SZ + 1, &seq, CC_SEQ_SZ);
    p = pkt + CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ;

    memcpy(p, target_ip, ip_len); p[ip_len] = '\0'; p += ip_len + 1;
    memcpy(p, cl->my_pubkey,  CC_PUBKEY_SZ);          p += CC_PUBKEY_SZ;
    memcpy(p, joiner_nonce,   CC_JOIN_NONCE_SZ);       p += CC_JOIN_NONCE_SZ;
    memcpy(p, wrapped,        CC_MASTER_SALT_SZ);      p += CC_MASTER_SALT_SZ;

    plain_len = (int)(p - (pkt + CC_WIRE_HDR_SZ));
    total_len = cc_encrypt_pkt(pkt, CC_WIRE_HDR_SZ, plain_len, cl->key, cl->cluster_id);
    if (total_len < 0) return;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons((uint16_t)cl->multicast_port);
    dest.sin_addr.s_addr = inet_addr(cl->multicast_address);

    if (sendto(sock, pkt, total_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0)
        LM_ERR("clusterer_controller: [cluster %d] sendto KEY_GRANT: %s\n",
               cl->cluster_id, strerror(errno));
    else
        LM_INFO("clusterer_controller: [cluster %d] sent KEY_GRANT to %s\n",
                cl->cluster_id, target_ip);
}

/**
 * cc_send_key_handoff() - send master_salt to the next master before departing.
 * Encrypted with session_key (CC_PACKET_MAGIC); only next master can unwrap.
 *
 * Payload: [next_master_ip NUL][my_pubkey 32B][wrapped_salt 32B]
 */
static void cc_send_key_handoff(int sock, const char *next_master_ip,
                                const unsigned char *next_master_pubkey,
                                cc_cluster_t *cl)
{
    char               pkt[CC_KEY_HANDOFF_SZ];
    uint32_t           seq     = htonl(++cl->peers->my_seq);
    unsigned char      wrapped[CC_MASTER_SALT_SZ];
    char              *p;
    int                ip_len, plain_len, total_len;
    struct sockaddr_in dest;

    if (cc_wrap_salt(cl->my_privkey, next_master_pubkey, cl->password,
                     cl->peers->master_salt, "cc_key_handoff",
                     NULL, 0, wrapped) < 0)
        return;

    ip_len = (int)strnlen(next_master_ip, CC_MAX_IP_LEN);

    memcpy(pkt, CC_PACKET_MAGIC, CC_MAGIC_SZ);
    pkt[CC_WIRE_HDR_SZ] = (char)CC_PKT_KEY_HANDOFF;
    memcpy(pkt + CC_WIRE_HDR_SZ + 1, &seq, CC_SEQ_SZ);
    p = pkt + CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ;

    memcpy(p, next_master_ip, ip_len); p[ip_len] = '\0'; p += ip_len + 1;
    memcpy(p, cl->my_pubkey,  CC_PUBKEY_SZ);              p += CC_PUBKEY_SZ;
    memcpy(p, wrapped,        CC_MASTER_SALT_SZ);          p += CC_MASTER_SALT_SZ;

    plain_len = (int)(p - (pkt + CC_WIRE_HDR_SZ));
    total_len = cc_encrypt_pkt(pkt, CC_WIRE_HDR_SZ, plain_len, cl->session_key, cl->cluster_id);
    if (total_len < 0) return;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons((uint16_t)cl->multicast_port);
    dest.sin_addr.s_addr = inet_addr(cl->multicast_address);

    if (sendto(sock, pkt, total_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0)
        LM_ERR("clusterer_controller: [cluster %d] sendto KEY_HANDOFF: %s\n",
               cl->cluster_id, strerror(errno));
    else
        LM_INFO("clusterer_controller: [cluster %d] sent KEY_HANDOFF to %s\n",
                cl->cluster_id, next_master_ip);
}

/* =========================================================================
 * State transition helper
 * ========================================================================= */

/**
 * cc_on_became_master() - side effects when this node wins an election.
 * Generates fresh master_salt, derives session_key, arms MASTER_ALIVE timer,
 * disarms master_dead watchdog.  Must be called with cl->peers->lock held WRITE.
 */
static void cc_on_became_master(cc_cluster_t *cl)
{
    cl->join_pending = 0;   /* any pending re-key join is now moot */
    if (wc_RNG_GenerateBlock(&cc_rng, cl->peers->master_salt, CC_MASTER_SALT_SZ) != 0) {
        LM_ERR("clusterer_controller: [cluster %d] RNG for master_salt failed\n",
               cl->cluster_id);
        return;
    }
    cc_derive_session_key(cl);   /* reads cl->peers->master_salt */
    LM_INFO("clusterer_controller: [cluster %d] became master - "
            "new master_salt generated, session key rotated\n", cl->cluster_id);
    /* Timer ops outside lock (timerfd is worker-local, no shm concern) */
}

/**
 * cc_arm_master_timers() - arm/disarm keepalive timers after election.
 * Call WITHOUT cl->peers->lock held.
 * i_am_master: 1 = we won, arm MASTER_ALIVE, disarm dead-watchdog.
 *              0 = we lost, arm dead-watchdog, disarm MASTER_ALIVE.
 */
static void cc_arm_master_timers(cc_cluster_t *cl, int i_am_master)
{
    cl->master_ka_armed = i_am_master ? 1 : 0;
    if (i_am_master) {
        cc_arm_tfd(cl->master_alive_tfd, CC_MASTER_KA_INTERVAL, CC_MASTER_KA_INTERVAL);
        cc_arm_tfd(cl->master_dead_tfd,  0, 0);   /* disarm watchdog */
    } else {
        cc_arm_tfd(cl->master_alive_tfd, 0, 0);   /* disarm sender   */
        cc_arm_tfd(cl->master_dead_tfd,  CC_MASTER_KA_TIMEOUT, 0);
    }
}

/**
 * cc_request_rekey() - ask the current key-holder for the session key.
 * Sends a single JOIN_REQ (bootstrap key), guarded by join_pending so a fresh
 * nonce is not stomped while one exchange is in flight.  Used when a node is
 * elected master but has not yet adopted the cluster key (KEY_GRANT lost).
 * Call WITHOUT cl->peers->lock held.
 */
static void cc_request_rekey(cc_cluster_t *cl)
{
    if (cl->join_pending)
        return;
    cl->join_pending = 1;
    cc_send_join_req(cl->sock, cl);
}

/**
 * cc_transition_to_active() - switch from CC_NODE_NEW to CC_NODE_ACTIVE.
 *
 * Disarms the join-phase timers, sends the first ALIVE immediately, then
 * arms the periodic ALIVE timer.  Called from both:
 *   - the join_tfd handler (deadline expired, fresh cluster), and
 *   - cc_handle_member_list (master responded before deadline).
 * Must be called with cl->peers->lock NOT held.
 */
static void cc_transition_to_active(cc_cluster_t *cl)
{
    cc_arm_tfd(cl->join_tfd,   0, 0);              /* disarm one-shot deadline */
    cc_arm_tfd(cl->rejoin_tfd, 0, 0);              /* disarm JOIN_REQ retry    */
    cc_send_alive(cl->sock, cl);                    /* first heartbeat now      */
    cc_arm_tfd(cl->alive_tfd, query_time, query_time); /* periodic from here   */
}

/* =========================================================================
 * Packet handlers
 * ========================================================================= */

/**
 * cc_fmt_cfg_diff() - render only the consistency-critical settings that
 * actually DIFFER into 'out' (e.g. "manage_shtags cluster=1 node=0"), so a
 * mismatch log names just the offending setting(s) rather than all three.
 * 'la'/'lb' are the labels for the local/peer sides ("cluster"/"node" or
 * "local"/"peer").
 */
static void cc_fmt_cfg_diff(char *out, int outsz, const char *la, const char *lb,
                            int a_manage, int b_manage, int a_stick, int b_stick,
                            int a_qt, int b_qt)
{
    int n = 0;
    out[0] = '\0';
#define CC_DIFF_APPEND(cond, name, av, bv)                                     \
    do {                                                                       \
        if (cond) {                                                            \
            int _w = snprintf(out + n, (n < outsz) ? (outsz - n) : 0,          \
                              "%s" name " %s=%d %s=%d",                         \
                              n ? ", " : "", la, (av), lb, (bv));              \
            if (_w > 0) { n += _w; if (n > outsz) n = outsz; }                 \
        }                                                                      \
    } while (0)
    CC_DIFF_APPEND(a_manage != b_manage, "manage_shtags",     a_manage, b_manage);
    CC_DIFF_APPEND(a_stick  != b_stick,  "master_stickiness", a_stick,  b_stick);
    CC_DIFF_APPEND(a_qt     != b_qt,     "query_time",        a_qt,     b_qt);
#undef CC_DIFF_APPEND
}

/**
 * cc_adopt_config() - adopt the running cluster's consistency-critical settings
 * (on_config_mismatch=adopt).  Called on a non-master node when the master's
 * advertised config differs from ours.  Call WITHOUT cl->peers->lock held.
 */
static void cc_adopt_config(cc_cluster_t *cl, int new_manage, int new_stick,
                            int new_qt, int is_active)
{
    int old_manage = cl->manage_shtags ? 1 : 0;

    LM_INFO("clusterer_controller: [cluster %d] adopting cluster settings from "
            "master (manage_shtags %d->%d, master_stickiness %d->%d, "
            "query_time %d->%d)\n",
            cl->cluster_id, old_manage, new_manage ? 1 : 0,
            cl->master_stickiness ? 1 : 0, new_stick ? 1 : 0, query_time, new_qt);

    cl->master_stickiness = new_stick ? 1 : 0;

    /* query_time is declared global but is a per-process copy after fork, and
     * there is one worker process per cluster, so updating it here affects only
     * THIS cluster's worker - never another cluster on a multi-cluster node.
     * Re-arm the periodic ALIVE timer if we are already active; the election
     * window and purge derive from query_time dynamically and need no re-arm. */
    if (new_qt >= 1 && new_qt != query_time) {
        query_time = new_qt;
        if (is_active)
            cc_arm_tfd(cl->alive_tfd, query_time, query_time);
    }

    /* Mirror the effective values into shm so cl_ctr_list_config (MI process)
     * reports what is actually in force after adoption. */
    cl->peers->eff_manage_shtags     = new_manage ? 1 : 0;
    cl->peers->eff_master_stickiness = cl->master_stickiness;
    cl->peers->eff_query_time        = query_time;

    if ((new_manage ? 1 : 0) != old_manage) {
        cl->manage_shtags = new_manage ? 1 : 0;
        if (clctl_loaded) {
            if (cl->manage_shtags) {
                if (clctl.set_shtag_managed)
                    clctl.set_shtag_managed(cl->cluster_id);
            } else if (clctl.unset_shtag_managed) {
                clctl.unset_shtag_managed(cl->cluster_id);
            }
        }
        /* Reconcile tag state under the new policy (no-op when now unmanaged). */
        cc_apply_shtags(cl);
    }
}

/**
 * cc_handle_alive() - process a CC_PKT_ALIVE packet.
 *
 * Regular heartbeat path: upsert the sender, re-elect.
 * Only called in CC_NODE_ACTIVE state; ignored while joining (cc_recv_one
 * still dispatches them so the peer table builds up before the timeout).
 */
static void cc_handle_alive(const char *src_ip,
                            const unsigned char *pubkey, /* may be NULL */
                            int cfg_present, int peer_manage,
                            int peer_stick, int peer_qt,
                            cc_cluster_t *cl)
{
    int  prev_master, now_master;
    int  warn = 0, adopt = 0, is_active = 0, ent = -1;
    char warn_ip[CC_MAX_IP_LEN + 1] = "";
    int  loc_manage = cl->manage_shtags ? 1 : 0;
    int  loc_stick  = cl->master_stickiness ? 1 : 0;
    int  loc_qt     = query_time;
    int  mism = 0, changed = 0;

    lock_start_write(cl->peers->lock);
    prev_master = cc_i_am_master_locked(cl);
    cc_upsert_peer_locked(src_ip, cl);
    {
        int _i;
        for (_i = 0; _i < cl->peers->count; _i++) {
            cc_peer_t *e = &cl->peers->entries[_i];
            if (strcmp(e->ip, src_ip) != 0)
                continue;
            ent = _i;
            /* Store pubkey so master can use it for KEY_HANDOFF / KEY_GRANT */
            if (pubkey)
                memcpy(e->pubkey, pubkey, CC_PUBKEY_SZ);
            if (cfg_present) {
                changed = (!e->cfg_known
                           || e->cfg_manage_shtags     != peer_manage
                           || e->cfg_master_stickiness != peer_stick
                           || e->cfg_query_time        != peer_qt);
                mism = (peer_manage != loc_manage
                        || peer_stick != loc_stick
                        || peer_qt   != loc_qt);
                e->cfg_known             = 1;
                e->cfg_manage_shtags     = peer_manage;
                e->cfg_master_stickiness = peer_stick;
                e->cfg_query_time        = peer_qt;
            }
            break;
        }
    }
    cc_elect_master(cl);
    now_master = cc_i_am_master_locked(cl);
    is_active  = (cl->peers->node_state == CC_NODE_ACTIVE);
    /* Config-consistency handling, decided once the master is known.  In
     * 'adopt' mode a non-master node takes the master's settings; otherwise a
     * mismatch is logged once per peer (re-logged only if the peer's advertised
     * config changes, cleared when it matches).  cc_elect_master does not
     * reorder entries, so the captured index stays valid. */
    if (cfg_present && ent >= 0) {
        cc_peer_t *e = &cl->peers->entries[ent];
        int sender_is_master = (cl->peers->last_master[0] != '\0'
                                && strcmp(src_ip, cl->peers->last_master) == 0);
        if (!mism) {
            e->cfg_warned = 0;
        } else if (on_config_mismatch == CC_CFGMISMATCH_ADOPT
                   && sender_is_master && !now_master) {
            adopt = 1;
            e->cfg_warned = 0;
        } else if (changed || !e->cfg_warned) {
            warn = 1;
            e->cfg_warned = 1;
            memcpy(warn_ip, e->ip, sizeof(warn_ip));
        }
    }
    lock_stop_write(cl->peers->lock);

    if (warn) {
        char diff[160];
        cc_fmt_cfg_diff(diff, sizeof(diff), "local", "peer",
                        loc_manage, peer_manage, loc_stick, peer_stick,
                        loc_qt, peer_qt);
        LM_WARN("clusterer_controller: [cluster %d] CONFIG MISMATCH with peer %s "
                "- all nodes of a cluster MUST use identical settings; mismatched "
                "values cause inconsistent failover/sharing-tag behaviour (%s)\n",
                cl->cluster_id, warn_ip, diff);
    }
    if (adopt)
        cc_adopt_config(cl, peer_manage, peer_stick, peer_qt, is_active);
    /* Defer acting as master until we hold the cluster key.  In normal
     * operation a higher-IP joiner has already adopted the key via KEY_GRANT
     * before winning here, so this only guards the pathological case where the
     * KEY_GRANT was lost during the join.  Request a re-key instead of
     * broadcasting an undecryptable MASTER_ALIVE. */
    if (now_master && !cl->have_session_key) {
        cc_request_rekey(cl);
        return;
    }
    if (prev_master != now_master)
        cc_arm_master_timers(cl, now_master);
}

/**
 * cc_handle_join_req() - process a CC_PKT_JOIN_REQ packet.
 *
 * Payload: [ip NUL][bin_count 1B][sock1 NUL]...[sockN NUL]
 *
 * Non-masters ignore JOIN_REQ - the master handles discovery exclusively.
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
    const char    *p         = payload;
    const char    *end       = payload + payload_len;
    char           src_ip[CC_MAX_IP_LEN + 1];
    char           bin_socks[CC_MAX_BIN_SOCKETS][CC_MAX_BIN_SOCK_LEN];
    unsigned char  joiner_pubkey[CC_PUBKEY_SZ];
    unsigned char  joiner_nonce[CC_JOIN_NONCE_SZ];
    uint8_t        bin_cnt   = 0;
    int            ip_len, was_master, i;
    int            j_cfg_present = 0, j_manage = 0, j_stick = 0, j_qt = 0;
    uint16_t       new_id;

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

    /* --- Parse X25519 public key (appended after BIN info) --- */
    memset(joiner_pubkey, 0, CC_PUBKEY_SZ);
    if (p + CC_PUBKEY_SZ <= end) {
	memcpy(joiner_pubkey, p, CC_PUBKEY_SZ);
	p += CC_PUBKEY_SZ;
    }

    /* --- Parse per-exchange join_nonce (appended after pubkey) --- */
    memset(joiner_nonce, 0, CC_JOIN_NONCE_SZ);
    if (p + CC_JOIN_NONCE_SZ <= end) {
	memcpy(joiner_nonce, p, CC_JOIN_NONCE_SZ);
	p += CC_JOIN_NONCE_SZ;
    }

    /* --- Parse the joiner's consistency-critical config (after join_nonce) --- */
    if (p + CC_CONFIG_SZ <= end) {
	uint16_t qt_be;
	j_manage = (unsigned char)p[0];
	j_stick  = (unsigned char)p[1];
	memcpy(&qt_be, p + 2, 2);
	j_qt          = ntohs(qt_be);
	j_cfg_present = 1;
	p += CC_CONFIG_SZ;
    }

    LM_INFO("clusterer_controller: [cluster %d] JOIN_REQ from %s "
            "(%d BIN socket(s))\n", cl->cluster_id, src_ip, bin_cnt);

    lock_start_write(cl->peers->lock);

    was_master = (cl->peers->node_state == CC_NODE_ACTIVE) &&
                 cc_i_am_master_locked(cl);

    if (!was_master) {
	/* Split-brain prevention: while we are ourselves still joining, record
	 * the other joiner so the join-deadline election can defer to the
	 * highest-IP starter instead of every node self-promoting into a
	 * divergent-key lone master.  (An active non-master simply ignores it;
	 * the master drives discovery.)                                        */
	if (cl->peers->node_state == CC_NODE_NEW) {
	    cc_upsert_peer_locked(src_ip, cl);
	    /* A fresh JOIN_REQ from a *higher-IP* peer proves it is still alive
	     * and joining, so reset our split-brain defer budget: keep waiting
	     * for it to become master instead of prematurely self-promoting into
	     * a divergent-key split brain.  join_defer_total still grows (hard
	     * cap) so a peer that is stuck forever cannot stall us indefinitely. */
	    if (ip_to_num(src_ip) > ip_to_num(my_ip))
		cl->join_defer_count = 0;
	}
	lock_stop_write(cl->peers->lock);
	LM_DBG("clusterer_controller: non-master ignoring JOIN_REQ from %s\n",
	       src_ip);
	return;
    }

    /* Config-consistency gate (master side): if the joiner advertises
     * consistency-critical settings that differ from the running cluster and
     * the policy is 'reject', refuse the join so the node shuts down rather
     * than joining and behaving inconsistently.  (warn/adopt admit the node;
     * the joiner then warns or adopts on the master's ALIVE.) */
    if (j_cfg_present && on_config_mismatch == CC_CFGMISMATCH_REJECT) {
	int loc_manage = cl->manage_shtags ? 1 : 0;
	int loc_stick  = cl->master_stickiness ? 1 : 0;
	if (j_manage != loc_manage || j_stick != loc_stick || j_qt != query_time) {
	    char diff[160];
	    lock_stop_write(cl->peers->lock);
	    cc_fmt_cfg_diff(diff, sizeof(diff), "cluster", "node",
	                    loc_manage, j_manage, loc_stick, j_stick,
	                    query_time, j_qt);
	    LM_WARN("clusterer_controller: [cluster %d] rejecting JOIN_REQ from %s: "
	            "different settings than the running cluster (%s)\n",
	            cl->cluster_id, src_ip, diff);
	    cc_send_join_reject(sock, src_ip, cl, CC_REJECT_CONFIG);
	    return;
	}
    }

    /* Reject JOIN_REQ from an unknown IP when the peer table is full.
     * Known peers (reconnecting after restart) are still allowed through
     * since they already occupy a slot.                                   */
    if (cl->peers->count >= CC_MAX_PEERS) {
	int _found = 0, _fi;
	for (_fi = 0; _fi < cl->peers->count; _fi++) {
	    if (strcmp(cl->peers->entries[_fi].ip, src_ip) == 0) {
		_found = 1;
		break;
	    }
	}
	if (!_found) {
	    lock_stop_write(cl->peers->lock);
	    LM_WARN("clusterer_controller: [cluster %d] peer table full "
	            "(%d/%d), rejecting JOIN_REQ from %s\n",
	            cl->cluster_id, cl->peers->count, CC_MAX_PEERS, src_ip);
	    cc_send_join_reject(sock, src_ip, cl, CC_REJECT_GENERIC);
	    return;
	}
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

    /* Store joiner's public key, join_nonce, and reset last_seq in peer table.
     * Resetting last_seq is essential: a restarted node begins its seq counter
     * from 0, and without this reset peers would permanently reject its new
     * packets (old last_seq > new seq) until the next key rotation. */
    {
	int _k;
	for (_k = 0; _k < cl->peers->count; _k++) {
	    if (strcmp(cl->peers->entries[_k].ip, src_ip) == 0) {
		memcpy(cl->peers->entries[_k].pubkey,     joiner_pubkey, CC_PUBKEY_SZ);
		memcpy(cl->peers->entries[_k].join_nonce, joiner_nonce,  CC_JOIN_NONCE_SZ);
		cl->peers->entries[_k].last_seq = 0;
		break;
	    }
	}
    }

    lock_stop_write(cl->peers->lock);

    /* JOIN_REQ decrypted successfully - clear any failure record for this IP
     * so a node that fixes its password isn't immediately rejected again. */
    {
        uint32_t _ip_num = ip_to_num(src_ip);
        int _fi;
        for (_fi = 0; _fi < CC_JOIN_FAIL_TABLE_SZ; _fi++) {
            if (cl->join_fail_tbl[_fi].ip_num == _ip_num) {
                memset(&cl->join_fail_tbl[_fi], 0, sizeof(cl->join_fail_tbl[_fi]));
                break;
            }
        }
    }

    /* Send KEY_GRANT first (bootstrap key) so joiner can derive session_key,
     * then NODE_ASSIGN + MEMBER_LIST (session key). */
    if (joiner_pubkey[0] || joiner_pubkey[1])   /* non-zero pubkey present */
        cc_send_key_grant(sock, src_ip, cl, joiner_pubkey, joiner_nonce);

    lock_start_write(cl->peers->lock);

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

    /* A current master NEVER hands mastership to a joining node during the
     * join handshake - doing so forced the joiner to broadcast MASTER_ALIVE
     * before it had adopted the cluster key, producing a key-mismatch loop.
     *
     * Instead we stay master and designate ourselves in the MEMBER_LIST.  The
     * joiner adopts our session key via the KEY_GRANT sent above and joins as
     * a member.  If it has a higher IP it will win the very next ALIVE-driven
     * election (cc_handle_alive) - but by then it holds the key, so when it
     * takes over it broadcasts with a key every member already has.  This
     * keeps the deterministic "highest IP is master" outcome while deferring
     * the actual takeover until after the key has been transferred.         */
    lock_stop_write(cl->peers->lock);
    LM_INFO("clusterer_controller: [cluster %d] I am master, "
            "new node %s assigned node_id=%u\n",
            cl->cluster_id, src_ip, new_id);
    cc_send_member_list(sock, cl);
}

/**
 * cc_handle_member_list() - process a CC_PKT_MEMBER_LIST from the master.
 *
 * This is THE authoritative packet for cluster state.  All nodes - both
 * the joining node and existing active members - update their peer tables
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
    uint16_t      forced_node_id;
    int           i;
    const char   *p;
    char          designated_master[CC_MAX_IP_LEN + 1];

    /* MEMBER_LIST is authoritative cluster state and must only come from the
     * current master.  Any cluster member holding the session key could forge
     * one; accepting it would let an insider demote the real master, inject
     * fake peers, or trigger spurious re-elections.
     * Own loopback (sender == my_ip) is allowed when we are the master. */
    if (strcmp(sender_ip, my_ip) == 0) {
	LM_DBG("clusterer_controller: ignoring own MEMBER_LIST loopback\n");
	return;
    }
    {
	int _from_master;
	lock_start_read(cl->peers->lock);
	_from_master = (cl->peers->last_master[0] != '\0' &&
	                strcmp(sender_ip, cl->peers->last_master) == 0);
	lock_stop_read(cl->peers->lock);
	if (!_from_master) {
	    /* Also allow during CC_NODE_NEW: we have no master yet, so any
	     * MEMBER_LIST is our first authoritative view of the cluster.  */
	    int _is_new;
	    lock_start_read(cl->peers->lock);
	    _is_new = (cl->peers->node_state == CC_NODE_NEW);
	    lock_stop_read(cl->peers->lock);
	    if (!_is_new) {
		LM_WARN("clusterer_controller: MEMBER_LIST from non-master %s "
		        "(master is %s), dropping\n",
		        sender_ip,
		        cl->peers->last_master[0] ? cl->peers->last_master : "(none)");
		return;
	    }
	}
    }

    designated_master[0] = '\0';

    if (payload_len < CC_LIST_COUNT_SZ + CC_NODE_ID_SZ) {
	LM_WARN("clusterer_controller: MEMBER_LIST too short\n");
	return;
    }

    {
	uint16_t count_be, forced_be;
	memcpy(&count_be, payload, CC_LIST_COUNT_SZ);
	count = ntohs(count_be);
	/* forced-shtag node_id follows the count (0 = automatic allocation) */
	memcpy(&forced_be, payload + CC_LIST_COUNT_SZ, CC_NODE_ID_SZ);
	forced_node_id = ntohs(forced_be);
    }

    if (count > CC_MAX_PEERS) {
	LM_WARN("clusterer_controller: MEMBER_LIST count %u exceeds "
	        "max peers %d, dropping\n", count, CC_MAX_PEERS);
	return;
    }

    if (payload_len < CC_LIST_COUNT_SZ + CC_NODE_ID_SZ
                      + (int)count * CC_IP_ENTRY_SZ) {
	LM_WARN("clusterer_controller: MEMBER_LIST truncated "
	        "(count=%u, got %d bytes)\n", count, payload_len);
	return;
    }

    p = payload + CC_LIST_COUNT_SZ + CC_NODE_ID_SZ;

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

    /* Second pass: upsert all peers and reset their last_seq.
     * Resetting last_seq here covers the case where a peer restarted and
     * sent JOIN_REQ: the MEMBER_LIST is the broadcast announcement that a
     * join event occurred.  Without the reset, non-master peers would reject
     * the restarted node's new packets (old last_seq > new low seq). */
    for (i = 0; i < (int)count; i++, p += CC_IP_ENTRY_SZ) {
	char ip_buf[CC_MAX_IP_LEN + 1];
	int  _j;
	memcpy(ip_buf, p, CC_MAX_IP_LEN);
	ip_buf[CC_MAX_IP_LEN] = '\0';
	if (ip_buf[0] == '\0')
	    continue;
	cc_upsert_peer_locked(ip_buf, cl);
	for (_j = 0; _j < cl->peers->count; _j++) {
	    if (strcmp(cl->peers->entries[_j].ip, ip_buf) == 0) {
		cl->peers->entries[_j].last_seq = 0;
		break;
	    }
	}
    }

    /* Snapshot master status BEFORE cc_apply_master_from_list_locked clears it */
    int was_master_before = cc_i_am_master_locked(cl);

    /* Apply the master designation from the list - no local election */
    if (designated_master[0] != '\0')
	cc_apply_master_from_list_locked(designated_master, cl);

    /* The master is authoritative for the shtag override too. */
    cl->peers->shtag_forced_node_id = forced_node_id;

    int was_new = (cl->peers->node_state == CC_NODE_NEW);
    if (was_new) {
	/* Only act as master if the list designates us AND we already hold the
	 * cluster key.  Incumbent masters no longer hand over during a join, so
	 * in normal operation a MEMBER_LIST never designates a NEW node - this
	 * guard is defensive: without a key we would broadcast MASTER_ALIVE that
	 * no member can decrypt.  Without the key we join as a plain member and
	 * let a later election promote us once KEY_GRANT has landed.           */
	int _taking_over = (designated_master[0] != '\0'
	                    && strcmp(designated_master, my_ip) == 0
	                    && cl->have_session_key);
	cl->peers->node_state = CC_NODE_ACTIVE;
	if (_taking_over) {
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
	cc_transition_to_active(cl);
	if (_taking_over)
	    cc_arm_master_timers(cl, 1);  /* start MASTER_ALIVE, disarm dead watchdog */
    } else {
	/* Active node - log the master update (may be self-demotion) */
	int i_am_master = (designated_master[0] != '\0' &&
	                   strcmp(designated_master, my_ip) == 0);
	lock_stop_write(cl->peers->lock);
	if (i_am_master) {
	    LM_INFO("clusterer_controller: MEMBER_LIST received - "
	            "I am master (%d members)\n", count);
	} else if (was_master_before) {
	    /* A genuine demotion: we held mastership until this MEMBER_LIST. */
	    LM_INFO("clusterer_controller: demoted to member - new master is %s "
	            "(%d members in cluster)\n",
	            designated_master[0] ? designated_master : "(none)",
	            count);
	    /* Fix up keepalive timers: stop sending MASTER_ALIVE, arm watchdog. */
	    cc_arm_master_timers(cl, 0);
	} else {
	    /* Already a member - this is just a routine MEMBER_LIST refresh (e.g.
	     * a periodic re-broadcast or a shtag-override update).  No role change,
	     * so don't cry "demoted"; log quietly at debug level. */
	    LM_DBG("clusterer_controller: MEMBER_LIST refreshed - master is %s "
	           "(%d members)\n",
	           designated_master[0] ? designated_master : "(none)", count);
	}
    }

    /* (Re)apply the shtag decision now that the forced-node override and the
     * master designation from this MEMBER_LIST have both been stored. */
    cc_apply_shtags(cl);
}

/**
 * cc_handle_goodbye() - process a CC_PKT_GOODBYE packet.
 *
 * Remove the departing node from the peer table immediately.
 *
 * Re-election is triggered ONLY when:
 *   1. Only one node remains - we are alone and must assume mastership.
 *   2. Our IP is higher than the current master's IP, or the master entry
 *      no longer exists because the departing node was the master.
 *      cc_ip_beats_master_locked() covers both cases: it returns 1 when
 *      no is_master entry is present (departed master) or when our IP
 *      numerically exceeds the current master's.
 *
 * All other departures (a member leaves while a higher-IP master is alive)
 * require no immediate action - the next periodic ALIVE cycle runs
 * cc_elect_master(cl) within query_time seconds and self-corrects if needed.
 */
static void cc_handle_goodbye(int sock, const char *src_ip, cc_cluster_t *cl)
{
    int      i, i_am_master, master_unchanged, remaining;
    char     prev_master[CC_MAX_IP_LEN + 1];
    char     new_master[CC_MAX_IP_LEN + 1];
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

    /* If the operator-forced shtag holder departed, drop the override so
     * automatic allocation resumes rather than leaving no active holder. */
    if (departed_node_id != 0 &&
        cl->peers->shtag_forced_node_id == departed_node_id) {
	LM_WARN("clusterer_controller: [cluster %d] forced shtag node %u "
	        "departed - resuming automatic allocation\n",
	        cl->cluster_id, departed_node_id);
	cl->peers->shtag_forced_node_id = 0;
    }

    remaining = cl->peers->count;

    /* --- Decide whether re-election is warranted --- */
    if (remaining <= 1) {
	/* We are the only node left - no election needed, promote directly. */
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
	cc_apply_shtags(cl);
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
	/* Snapshot before releasing - must not read last_master after unlock */
	{
	    size_t _l = strnlen(cl->peers->last_master, CC_MAX_IP_LEN);
	    memcpy(prev_master, cl->peers->last_master, _l);
	    prev_master[_l] = '\0';
	}
	lock_stop_write(cl->peers->lock);
	LM_INFO("clusterer_controller: %s departed - master %s still "
	        "active, no re-election needed (%d node(s) remaining)\n",
	        src_ip,
	        prev_master[0] ? prev_master : "(none)",
	        remaining);
	if (clctl_loaded && departed_node_id > 0)
	    clctl.remove_node(cl->cluster_id, departed_node_id);
	/* Re-apply shtag policy: the still-active master takes over the
	 * departed node's tags, unless an operator override is in effect. */
	cc_apply_shtags(cl);
	return;
    }

    memcpy(prev_master, cl->peers->last_master,
           strnlen(cl->peers->last_master, CC_MAX_IP_LEN));
    prev_master[strnlen(cl->peers->last_master, CC_MAX_IP_LEN)] = '\0';

    {
        cc_elect_master(cl);
        i_am_master = cc_i_am_master_locked(cl);
    }

    master_unchanged = (strcmp(prev_master, cl->peers->last_master) == 0);
    i_am_master      = cc_i_am_master_locked(cl);
    /* Snapshot post-election master before releasing - used in member log */
    {
	size_t _l = strnlen(cl->peers->last_master, CC_MAX_IP_LEN);
	memcpy(new_master, cl->peers->last_master, _l);
	new_master[_l] = '\0';
    }

    lock_stop_write(cl->peers->lock);

    if (i_am_master) {
	if (master_unchanged) {
	    LM_INFO("clusterer_controller: re-election complete - "
	            "I remain master (%d node(s) in cluster)\n", remaining);
	} else {
	    LM_INFO("clusterer_controller: re-election complete - "
	            "I reclaimed mastership after %s departed "
	            "(%d node(s) remaining) - sending MEMBER_LIST\n",
	            src_ip, remaining);
	    cc_arm_master_timers(cl, 1);
	    cc_send_member_list(sock, cl);
	}
    } else {
	LM_INFO("clusterer_controller: re-election complete - "
	        "master is %s, my role is member (%d node(s) remaining)\n",
	        new_master[0] ? new_master : "(none)",
	        remaining);
    }
    if (clctl_loaded && departed_node_id > 0)
	clctl.remove_node(cl->cluster_id, departed_node_id);
    cc_apply_shtags(cl);
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

    /* Record our own node_id - also the first signal that a master exists */
    if (strcmp(ip, my_ip) == 0) {
	/* Always our own entry - update identity regardless of my_node_id */
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

/**
 * cc_handle_master_alive() - process a master keepalive.
 *
 * Beyond rearming the master-dead watchdog, this keeps every node agreeing on
 * the master's identity (the 1s keepalive is more frequent than MEMBER_LIST,
 * so it is the authoritative "who is master" signal) and resolves split-brain:
 * if this node also believes it is master and the announcing node has a higher
 * IP, it yields.  Highest-IP-wins is the deterministic tiebreak in BOTH
 * preemption modes, so two masters (e.g. after a network partition heals) can
 * never both stick.
 */
static void cc_handle_master_alive(const char *sender_ip, cc_cluster_t *cl)
{
    int i_am_master, yielded = 0;
    int from_self = (strcmp(sender_ip, my_ip) == 0);

    lock_start_write(cl->peers->lock);
    i_am_master = cc_i_am_master_locked(cl);

    if (i_am_master) {
        if (!from_self && ip_to_num(sender_ip) > ip_to_num(my_ip)) {
            /* Split-brain: a higher-IP node also claims mastership - yield. */
            cc_upsert_peer_locked(sender_ip, cl);
            cc_apply_master_from_list_locked(sender_ip, cl);
            yielded = 1;
        }
        /* else: my own loopback, or a lower-IP claimant that will yield to us */
    } else if (!from_self) {
        /* Track the announcing node as the current master so all nodes agree
         * even if a MEMBER_LIST was missed, and so sticky cc_elect_master
         * preserves the correct current master. */
        cc_upsert_peer_locked(sender_ip, cl);
        cc_apply_master_from_list_locked(sender_ip, cl);
    }
    lock_stop_write(cl->peers->lock);

    if (yielded) {
        LM_INFO("clusterer_controller: [cluster %d] yielding mastership to "
                "higher-IP master %s (split-brain resolution)\n",
                cl->cluster_id, sender_ip);
        cc_arm_master_timers(cl, 0);   /* stop MASTER_ALIVE, arm dead watchdog */
    }

    /* Non-masters (including a node that just yielded) watch the keepalive. */
    if (!i_am_master || yielded)
        cc_arm_tfd(cl->master_dead_tfd, CC_MASTER_KA_TIMEOUT, 0);
}

/**
 * cc_rejoin_superior_master() - abandon our current allegiance and merge into
 * the partition led by 'superior_ip', adopting its session key.
 *
 * Used by the split-brain merge (cc_handle_master_beacon): our node - whether a
 * lone/independent master or a member of a smaller partition - records
 * superior_ip as master, stops asserting mastership, and issues a JOIN_REQ so
 * the superior master answers with NODE_ASSIGN + KEY_GRANT.  Once the KEY_GRANT
 * lands we can decrypt the superior partition's session traffic and are fully
 * merged.  Call WITHOUT cl->peers->lock held.
 */
static void cc_rejoin_superior_master(cc_cluster_t *cl, const char *superior_ip)
{
    int was_master;

    lock_start_write(cl->peers->lock);
    was_master = cc_i_am_master_locked(cl);
    cc_upsert_peer_locked(superior_ip, cl);
    cc_apply_master_from_list_locked(superior_ip, cl);
    cl->peers->node_state = CC_NODE_ACTIVE;
    lock_stop_write(cl->peers->lock);

    if (was_master) {
        LM_INFO("clusterer_controller: [cluster %d] superior master %s found via "
                "beacon - demoting and merging (split-brain resolution)\n",
                cl->cluster_id, superior_ip);
        cc_arm_master_timers(cl, 0);   /* stop MASTER_ALIVE, arm dead watchdog */
    } else {
        LM_INFO("clusterer_controller: [cluster %d] moving to superior master %s "
                "via beacon (split-brain merge)\n", cl->cluster_id, superior_ip);
    }

    /* Drop any locally-held active shtag now that we are no longer master. */
    cc_apply_shtags(cl);

    /* Fetch the superior master's session key.  join_pending guards the nonce
     * so a beacon storm cannot stomp an exchange already in flight. */
    if (!cl->join_pending) {
        cl->join_pending = 1;
        cc_send_join_req(cl->sock, cl);
    }
    cc_arm_tfd(cl->master_dead_tfd, CC_MASTER_KA_TIMEOUT, 0);
}

/**
 * cc_handle_master_beacon() - process a CC_PKT_MASTER_BEACON (bootstrap key).
 *
 * A master announced itself on the bootstrap layer.  If it outranks our own
 * partition we merge into it; otherwise we ignore it (that master will yield to
 * us when it hears our beacon).  Ranking: larger member count wins, ties broken
 * by higher IP - the same deterministic tiebreak used elsewhere, so exactly one
 * master survives.  A healthy single-master cluster sees only its own master's
 * beacon (sender == our master) and never acts, so this adds no churn.
 */
static void cc_handle_master_beacon(const char *sender_ip, uint16_t sender_count,
                                    cc_cluster_t *cl)
{
    int  i_am_master, is_new, our_count, superior;
    char our_master[CC_MAX_IP_LEN + 1];

    if (strcmp(sender_ip, my_ip) == 0)
        return;                     /* our own beacon looped back */

    lock_start_read(cl->peers->lock);
    is_new      = (cl->peers->node_state == CC_NODE_NEW);
    i_am_master = cc_i_am_master_locked(cl);
    our_count   = cl->peers->count;
    if (i_am_master) {
        size_t l = strnlen(my_ip, CC_MAX_IP_LEN);
        memcpy(our_master, my_ip, l); our_master[l] = '\0';
    } else {
        size_t l = strnlen(cl->peers->last_master, CC_MAX_IP_LEN);
        memcpy(our_master, cl->peers->last_master, l); our_master[l] = '\0';
    }
    lock_stop_read(cl->peers->lock);

    /* Still running the join protocol - a JOIN_REQ is already outstanding. */
    if (is_new)
        return;

    /* Already following the beacon's sender: normal steady state, nothing to do. */
    if (our_master[0] != '\0' && strcmp(sender_ip, our_master) == 0)
        return;

    /* Rank the sender's partition against ours. */
    if (our_master[0] == '\0')
        superior = 1;                                   /* we have no master yet */
    else if (sender_count != (uint16_t)our_count)
        superior = (sender_count > (uint16_t)our_count);/* larger partition wins */
    else
        superior = (ip_to_num(sender_ip) > ip_to_num(our_master)); /* IP tiebreak */

    if (!superior)
        return;   /* we outrank the sender; it will yield to us on our beacon */

    cc_rejoin_superior_master(cl, sender_ip);
}

/**
 * cc_handle_key_grant() - process CC_PKT_KEY_GRANT from master.
 * Payload: [target_ip NUL][master_pubkey 32B][join_nonce 16B][wrapped_salt 32B]
 *
 * Recover master_salt via ECDH unwrap, derive session_key, update shm.
 * Only processed if target_ip == my_ip (multicast - all nodes receive it).
 */
static void cc_handle_key_grant(const char *payload, int payload_len,
                                const char *sender_ip, cc_cluster_t *cl)
{
    const char    *p         = payload;
    const char    *end       = payload + payload_len;
    char           target_ip[CC_MAX_IP_LEN + 1];
    unsigned char  master_pubkey[CC_PUBKEY_SZ];
    unsigned char  echoed_nonce[CC_JOIN_NONCE_SZ];
    unsigned char  wrapped[CC_MASTER_SALT_SZ];
    unsigned char  ss[CC_PUBKEY_SZ];
    unsigned char  ikm[CC_PUBKEY_SZ + 1024 + CC_JOIN_NONCE_SZ];
    unsigned char  wrap_key[32];
    unsigned char  new_salt[CC_MASTER_SALT_SZ];
    size_t         pass_len, ikm_len;
    int            ip_len, i;

    /* Parse target_ip */
    ip_len = (int)strnlen(p, CC_MAX_IP_LEN);
    if (p + ip_len >= end) return;
    memcpy(target_ip, p, ip_len); target_ip[ip_len] = '\0';
    p += ip_len + 1;

    /* Only process if addressed to us */
    if (strcmp(target_ip, my_ip) != 0) return;

    /* Masters are the key source - they never accept KEY_GRANTs.
     * Without this guard a stale KEY_GRANT (from the previous master,
     * responding to a JOIN_REQ we sent while CC_NODE_NEW) can arrive
     * after we self-promoted via cc_on_join_tfd and overwrite the
     * session key we just generated, causing a key-mismatch loop. */
    {
        int _im;
        lock_start_read(cl->peers->lock);
        _im = cc_i_am_master_locked(cl);
        lock_stop_read(cl->peers->lock);
        if (_im) {
            LM_DBG("clusterer_controller: KEY_GRANT from %s ignored - "
                   "I am master\n", sender_ip);
            return;
        }
    }

    if (p + CC_PUBKEY_SZ + CC_JOIN_NONCE_SZ + CC_MASTER_SALT_SZ > end) {
        LM_WARN("clusterer_controller: KEY_GRANT too short\n");
        return;
    }
    memcpy(master_pubkey, p, CC_PUBKEY_SZ);    p += CC_PUBKEY_SZ;
    memcpy(echoed_nonce,  p, CC_JOIN_NONCE_SZ); p += CC_JOIN_NONCE_SZ;
    memcpy(wrapped,       p, CC_MASTER_SALT_SZ);

    /* Verify echoed nonce matches what we sent in JOIN_REQ */
    if (memcmp(echoed_nonce, cl->my_join_nonce, CC_JOIN_NONCE_SZ) != 0) {
        LM_WARN("clusterer_controller: KEY_GRANT join_nonce mismatch - dropping\n");
        /* Clear join_pending so the next decryption failure or rejoin_tfd
         * can issue a fresh JOIN_REQ.  Without this the node stays blocked
         * on a nonce that will never match (e.g. overwritten by rejoin
         * timer or a master-election cycle between send and receipt).    */
        cl->join_pending = 0;
        return;
    }

    /* Recover master_salt: XOR wrapped with HKDF(ECDH(my_priv, master_pub) || password || nonce) */
    if (cc_ecdh_shared(cl->my_privkey, master_pubkey, ss) < 0) return;
    pass_len = strlen(cl->password);
    if (pass_len > 1024) pass_len = 1024;
    memcpy(ikm, ss, CC_PUBKEY_SZ);
    memcpy(ikm + CC_PUBKEY_SZ, cl->password, pass_len);
    memcpy(ikm + CC_PUBKEY_SZ + pass_len, echoed_nonce, CC_JOIN_NONCE_SZ);
    ikm_len = CC_PUBKEY_SZ + pass_len + CC_JOIN_NONCE_SZ;
    if (cc_hkdf_sha256(ikm, ikm_len,
                        ss, CC_PUBKEY_SZ, "cc_key_grant", wrap_key) < 0) return;
    for (i = 0; i < CC_MASTER_SALT_SZ; i++)
        new_salt[i] = wrapped[i] ^ wrap_key[i];

    /* Apply: write to shm, derive session_key */
    lock_start_write(cl->peers->lock);
    memcpy(cl->peers->master_salt, new_salt, CC_MASTER_SALT_SZ);
    cc_derive_session_key(cl);
    lock_stop_write(cl->peers->lock);

    cl->join_pending           = 0;
    cl->bootstrap_auth_fails   = 0;
    cl->join_attempt_count     = 0;
    cl->auth_fail_pkts         = 0;   /* authenticated: clear wrong-password evidence */
    cl->auth_defer_count       = 0;
    LM_INFO("clusterer_controller: [cluster %d] KEY_GRANT from %s - "
            "session key updated\n", cl->cluster_id, sender_ip);
}

/**
 * cc_handle_key_handoff() - process CC_PKT_KEY_HANDOFF.
 * Only acted on by the node that wins the next election (highest IP).
 * Payload: [next_master_ip NUL][sender_pubkey 32B][wrapped_salt 32B]
 */
static void cc_handle_key_handoff(const char *payload, int payload_len,
                                  const char *sender_ip, cc_cluster_t *cl)
{
    const char    *p         = payload;
    const char    *end       = payload + payload_len;
    char           target_ip[CC_MAX_IP_LEN + 1];
    unsigned char  sender_pubkey[CC_PUBKEY_SZ];
    unsigned char  wrapped[CC_MASTER_SALT_SZ];
    unsigned char  ss[CC_PUBKEY_SZ];
    unsigned char  ikm[CC_PUBKEY_SZ + 1024];
    unsigned char  wrap_key[32];
    unsigned char  new_salt[CC_MASTER_SALT_SZ];
    size_t         pass_len;
    int            ip_len, i;

    ip_len = (int)strnlen(p, CC_MAX_IP_LEN);
    if (p + ip_len >= end) return;
    memcpy(target_ip, p, ip_len); target_ip[ip_len] = '\0';
    p += ip_len + 1;

    /* Only the intended next master unwraps this */
    if (strcmp(target_ip, my_ip) != 0) return;

    if (p + CC_PUBKEY_SZ + CC_MASTER_SALT_SZ > end) {
        LM_WARN("clusterer_controller: KEY_HANDOFF too short\n");
        return;
    }
    memcpy(sender_pubkey, p, CC_PUBKEY_SZ); p += CC_PUBKEY_SZ;
    memcpy(wrapped,       p, CC_MASTER_SALT_SZ);

    if (cc_ecdh_shared(cl->my_privkey, sender_pubkey, ss) < 0) return;
    pass_len = strlen(cl->password);
    if (pass_len > 1024) pass_len = 1024;
    memcpy(ikm, ss, CC_PUBKEY_SZ);
    memcpy(ikm + CC_PUBKEY_SZ, cl->password, pass_len);
    if (cc_hkdf_sha256(ikm, CC_PUBKEY_SZ + pass_len,
                        ss, CC_PUBKEY_SZ, "cc_key_handoff", wrap_key) < 0) return;
    for (i = 0; i < CC_MASTER_SALT_SZ; i++)
        new_salt[i] = wrapped[i] ^ wrap_key[i];

    /* Store salt and re-derive so session_key is guaranteed consistent with
     * the adopted salt (the incoming master's salt may differ from ours). */
    lock_start_write(cl->peers->lock);
    memcpy(cl->peers->master_salt, new_salt, CC_MASTER_SALT_SZ);
    cc_derive_session_key(cl);   /* sets have_session_key = 1 */
    lock_stop_write(cl->peers->lock);

    LM_INFO("clusterer_controller: [cluster %d] KEY_HANDOFF from %s - "
            "master_salt preserved for seamless transition\n",
            cl->cluster_id, sender_ip);
}

/* =========================================================================
 * Receive dispatcher
 * ========================================================================= */

/**
 * cc_rate_check() - per-source-IP rate limiter, called before decryption.
 * Finds or creates a 1-second sliding-window counter for src_ip.
 * @return 0 if within CC_RATE_LIMIT packets/s, -1 to drop.
 */
static int cc_rate_check(cc_cluster_t *cl, uint32_t src_ip)
{
    time_t            now     = time(NULL);
    cc_rate_entry_t  *oldest  = NULL;
    int               i;

    for (i = 0; i < CC_RATE_TBL_SZ; i++) {
        cc_rate_entry_t *e = &cl->rate_tbl[i];
        if (e->ip == 0) {
            if (!oldest) oldest = e;             /* prefer empty slot  */
            continue;
        }
        if (e->ip == src_ip) {
            if (now > e->window_start) {         /* new second         */
                e->window_start = now;
                e->count        = 1;
                return 0;
            }
            if (++e->count > CC_RATE_LIMIT)
                return -1;
            return 0;
        }
        /* track oldest entry for eviction when table is full */
        if (!oldest || e->window_start < oldest->window_start)
            oldest = e;
    }

    /* new source IP - claim oldest/empty slot */
    oldest->ip           = src_ip;
    oldest->window_start = now;
    oldest->count        = 1;
    return 0;
}

/* -- Join-reject helpers ----------------------------------------------------
 *
 * Security model: JOIN_REJECT is sent as a normal CC_BOOTSTRAP_MAGIC packet
 * (AES-256-GCM authenticated with the bootstrap key).  An attacker without
 * the cluster password cannot forge a GCM-authenticated reject, so they
 * cannot kick nodes out or block joins.  cc_handle_join_reject() also guards
 * on CC_NODE_NEW state so that even a legitimate cluster member with the
 * correct password cannot send a JOIN_REJECT to an already-active node.
 *
 * cc_join_fail_check() - master: track per-IP BOOTSTRAP_MAGIC decrypt failures.
 * Returns 1 the first time a source IP reaches CC_JOIN_FAIL_LIMIT failures.
 *
 * cc_send_join_reject() - master: send encrypted JOIN_REJECT via BOOTSTRAP_MAGIC.
 * Wire payload: [target_ip NUL]
 *
 * cc_handle_join_reject() - joiner: stop OpenSIPS if the reject is for us and
 * we are still in CC_NODE_NEW (i.e., have not successfully joined yet).
 *
 * WRONG-PASSWORD fallback: if the joiner has the wrong password it cannot
 * decrypt the encrypted JOIN_REJECT.  Instead it detects the situation
 * through bootstrap_auth_fails (incremented on any BOOTSTRAP_MAGIC decrypt
 * failure during CC_NODE_NEW) combined with join_attempt_count.  After
 * CC_JOIN_FAIL_LIMIT rejoin retries with at least one bootstrap failure
 * observed, the joiner concludes the master rejected it and exits.
 */

static int cc_join_fail_check(const char *src_ip, cc_cluster_t *cl)
{
    uint32_t ip_num = ip_to_num(src_ip);
    int      evict  = 0;   /* index of lowest-count slot for eviction */
    int      i;

    if (ip_num == 0)
        return 0;

    for (i = 0; i < CC_JOIN_FAIL_TABLE_SZ; i++) {
        if (cl->join_fail_tbl[i].ip_num != ip_num)
            continue;
        if (cl->join_fail_tbl[i].rejected)
            return 0;   /* reject already sent; don't repeat */
        cl->join_fail_tbl[i].count++;
        if (cl->join_fail_tbl[i].count >= CC_JOIN_FAIL_LIMIT) {
            cl->join_fail_tbl[i].rejected = 1;
            return 1;
        }
        return 0;
    }

    /* Not found - insert, evicting the slot with the smallest count */
    for (i = 1; i < CC_JOIN_FAIL_TABLE_SZ; i++) {
        if (cl->join_fail_tbl[i].count < cl->join_fail_tbl[evict].count)
            evict = i;
    }
    memset(&cl->join_fail_tbl[evict], 0, sizeof(cl->join_fail_tbl[evict]));
    cl->join_fail_tbl[evict].ip_num = ip_num;
    snprintf(cl->join_fail_tbl[evict].ip, sizeof(cl->join_fail_tbl[evict].ip),
             "%s", src_ip);
    cl->join_fail_tbl[evict].count = 1;
    return 0;
}

static void cc_send_join_reject(int sock, const char *target_ip, cc_cluster_t *cl,
                                int reason)
{
    char               pkt[CC_SMALL_PKT_SZ + 1];   /* +1 for the reason byte */
    uint32_t           seq = htonl(++cl->peers->my_seq);
    int                ip_len, plain_len, total_len;
    struct sockaddr_in dest;

    ip_len = (int)strnlen(target_ip, CC_MAX_IP_LEN);

    memcpy(pkt, CC_BOOTSTRAP_MAGIC, CC_MAGIC_SZ);
    pkt[CC_WIRE_HDR_SZ] = (char)CC_PKT_JOIN_REJECT;
    memcpy(pkt + CC_WIRE_HDR_SZ + 1, &seq, CC_SEQ_SZ);
    memcpy(pkt + CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ, target_ip, ip_len);
    pkt[CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ + ip_len]     = '\0';
    /* reason byte follows the NUL-terminated target IP */
    pkt[CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ + ip_len + 1] = (char)reason;

    plain_len = CC_PLAIN_HDR_SZ + ip_len + 1 + 1;
    total_len = cc_encrypt_pkt(pkt, CC_WIRE_HDR_SZ, plain_len, cl->key, cl->cluster_id);
    if (total_len < 0) return;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons((uint16_t)cl->multicast_port);
    dest.sin_addr.s_addr = inet_addr(cl->multicast_address);

    if (sendto(sock, pkt, total_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0)
        LM_ERR("clusterer_controller: [cluster %d] sendto JOIN_REJECT failed: %s\n",
               cl->cluster_id, strerror(errno));
    else
        LM_WARN("clusterer_controller: [cluster %d] sent JOIN_REJECT to %s (%s)\n",
                cl->cluster_id, target_ip,
                reason == CC_REJECT_CONFIG ? "different cluster settings"
                                           : "repeated auth failure - wrong password?");
}

static void cc_handle_join_reject(const char *payload, int payload_len,
                                   const char *sender_ip, cc_cluster_t *cl)
{
    char target_ip[CC_MAX_IP_LEN + 1];
    int  l, still_new;

    /* Only act during the initial join phase.  An active member receiving a
     * JOIN_REJECT (e.g. from a cluster peer with the correct password who
     * wanted to test the mechanism, or a stale in-flight packet) must ignore
     * it - this prevents any cluster member from silently evicting another. */
    lock_start_read(cl->peers->lock);
    still_new = (cl->peers->node_state == CC_NODE_NEW);
    lock_stop_read(cl->peers->lock);
    if (!still_new) return;

    l = (int)strnlen(payload, CC_MAX_IP_LEN);
    if (l >= payload_len) return;
    memcpy(target_ip, payload, l);
    target_ip[l] = '\0';

    if (strcmp(target_ip, my_ip) != 0)
        return;   /* not addressed to this node */

    /* reason byte follows the NUL-terminated target IP (older senders omit it) */
    {
        int reason = CC_REJECT_GENERIC;
        if (payload_len > l + 1)
            reason = (unsigned char)payload[l + 1];
        if (reason == CC_REJECT_CONFIG)
            LM_CRIT("clusterer_controller: [cluster %d] JOIN_REJECT from %s - the "
                    "running cluster has different settings than this node; fix the "
                    "local config (manage_shtags/master_stickiness/query_time) to "
                    "match and restart; shutting down\n",
                    cl->cluster_id, sender_ip);
        else
            LM_CRIT("clusterer_controller: [cluster %d] JOIN_REJECT from %s - "
                    "wrong password or unauthorized node; shutting down\n",
                    cl->cluster_id, sender_ip);
    }
    exit(-1);
}

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

    /* Minimum: magic(2)+cluster_id(2)+nonce(12)+type(1)+seq(4)+tag(16) = 37 */
    if (n < CC_WIRE_HDR_SZ + CC_PLAIN_HDR_SZ + CC_TAG_SZ) {
	LM_WARN("clusterer_controller: short packet (%zd bytes), dropping\n",
	        n);
	return;
    }

    if (memcmp(buf, CC_PACKET_MAGIC,   CC_MAGIC_SZ) != 0 &&
        memcmp(buf, CC_BOOTSTRAP_MAGIC, CC_MAGIC_SZ) != 0) {
	LM_DBG("clusterer_controller: bad magic, dropping\n");
	return;
    }

    /* Cleartext cluster_id filter: silently ignore packets for a different
     * cluster sharing this multicast group.  Done BEFORE decryption so foreign
     * traffic never counts as an auth failure (auth_fail_pkts) - a wrong-cluster
     * packet is not a wrong-password attempt.                                */
    {
	uint16_t pkt_cid_be;
	memcpy(&pkt_cid_be, buf + CC_MAGIC_SZ, CC_CLUSTER_ID_SZ);
	if (ntohs(pkt_cid_be) != (uint16_t)cl->cluster_id) {
	    LM_DBG("clusterer_controller: [cluster %d] ignoring packet for "
	           "cluster %u on shared group\n", cl->cluster_id,
	           ntohs(pkt_cid_be));
	    return;
	}
    }

    /* Rate-limit before any crypto work to shed floods cheaply. */
    if (cc_rate_check(cl, src_addr.sin_addr.s_addr) < 0)
	return;

    /* Resolve sender IP once - used for HMAC warning and MEMBER_LIST dispatch */
    {
	char sender_ip_buf[INET_ADDRSTRLEN];
	const unsigned char *dec_key;
	inet_ntop(AF_INET, &src_addr.sin_addr,
	          sender_ip_buf, sizeof(sender_ip_buf));

	/* Select decryption key by magic:
	 *   CC_BOOTSTRAP_MAGIC -> bootstrap key (JOIN_REQ, KEY_GRANT)
	 *   CC_PACKET_MAGIC    -> session key   (all normal traffic)
	 * If session key decryption fails, schedule a re-JOIN to refresh it. */
	int is_bootstrap = (memcmp(buf, CC_BOOTSTRAP_MAGIC, CC_MAGIC_SZ) == 0);
	dec_key = is_bootstrap ? cl->key : cl->session_key;

	if (cc_decrypt_pkt(buf, n, sender_ip_buf, dec_key, is_bootstrap) < 0) {
	    int  _im, _new;
	    char _lm[CC_MAX_IP_LEN + 1];
	    lock_start_read(cl->peers->lock);
	    _im  = cc_i_am_master_locked(cl);
	    _new = (cl->peers->node_state == CC_NODE_NEW);
	    memcpy(_lm, cl->peers->last_master, sizeof(_lm));
	    lock_stop_read(cl->peers->lock);

	    /* A packet from another peer we cannot decrypt, seen while still
	     * joining, means a cluster (or rogue) whose key we do not share is
	     * present on this group.  We count it (any magic) as evidence that we
	     * may not belong here: session-key failures matter too, because a
	     * running cluster's steady traffic (MASTER_ALIVE/MEMBER_LIST) is
	     * session-encrypted, so a wrong-password joiner would otherwise see too
	     * little bootstrap traffic to notice the cluster and would self-promote
	     * into a split-brain lone master.  This is only *evidence*, never an
	     * immediate death sentence: cc_on_join_tfd defers and keeps re-joining,
	     * and a KEY_GRANT arriving in the grace window resets this counter, so a
	     * healthy node whose key is merely slow is not affected.  Our own
	     * loopback decrypts fine, so guard on my_ip. */
	    if (_new && strcmp(sender_ip_buf, my_ip) != 0)
		cl->auth_fail_pkts++;

	    if (memcmp(buf, CC_BOOTSTRAP_MAGIC, CC_MAGIC_SZ) == 0) {

		/* Master: track per-IP bootstrap failures; send JOIN_REJECT on limit.
		 * JOIN_REJECT is encrypted (BOOTSTRAP_MAGIC/GCM) so only nodes with
		 * the correct password can read it.  Forgeries are impossible without
		 * the bootstrap key.                                                  */
		if (_im && cc_join_fail_check(sender_ip_buf, cl))
		    cc_send_join_reject(sock, sender_ip_buf, cl, CC_REJECT_GENERIC);

		/* Joiner fallback: count bootstrap decrypt failures during CC_NODE_NEW
		 * only when the packet came from the known master.  This filters out
		 * rogue nodes on the multicast group whose JOIN_REQs (encrypted with
		 * their own wrong key) would otherwise increment this counter and
		 * trigger a spurious exit on a legitimate joining node.
		 * If last_master is empty we have no master reference yet, so we
		 * conservatively skip counting - no master means no rejection.      */
		if (_new && _lm[0] != '\0' && strcmp(sender_ip_buf, _lm) == 0)
		    cl->bootstrap_auth_fails++;
	    }
	    if (memcmp(buf, CC_PACKET_MAGIC, CC_MAGIC_SZ) == 0 && !cl->join_pending) {
		/* Session key mismatch: request a re-key ONLY when the packet we
		 * could not decrypt came from OUR current master (a legitimate key
		 * rotation).  Undecryptable session packets from any other source
		 * are rogue or stale traffic (e.g. a wrong-password node broadcasting
		 * on the group); reacting to them would drive an endless re-JOIN
		 * churn across the whole cluster.  Masters never re-JOIN.           */
		if (!_im && _lm[0] != '\0' && strcmp(sender_ip_buf, _lm) == 0) {
		    LM_INFO("clusterer_controller: [cluster %d] session key mismatch "
		            "from master %s - sending JOIN_REQ to re-key\n",
		            cl->cluster_id, sender_ip_buf);
		    cl->join_pending = 1;
		    cc_send_join_req(cl->sock, cl);
		}
	    }
	    return;
	}

	/* Sequence check: reject replays for all session-key packets including
	 * GOODBYE.  my_seq lives in shm so mod_destroy increments the same
	 * counter the worker uses - GOODBYE gets a valid monotonic seq number
	 * without any special-casing.
	 * Bootstrap packets (CC_BOOTSTRAP_MAGIC) use join_nonce instead. */
	if (memcmp(buf, CC_PACKET_MAGIC, CC_MAGIC_SZ) == 0) {
	    uint32_t pkt_seq;
	    memcpy(&pkt_seq, buf + CC_WIRE_HDR_SZ + 1, CC_SEQ_SZ);
	    pkt_seq = ntohl(pkt_seq);
	    if (cc_check_and_update_seq(sender_ip_buf, pkt_seq, cl) < 0)
		return;
	}

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
	    char           ip_buf[CC_MAX_IP_LEN + 1];
	    int            ip_len = (int)strnlen(payload, CC_MAX_IP_LEN);
	    const unsigned char *pubkey = NULL;
	    int            cfg_present = 0, p_manage = 0, p_stick = 0, p_qt = 0;
	    memcpy(ip_buf, payload, ip_len);
	    ip_buf[ip_len] = '\0';
	    /* Pubkey appended after NUL-terminated IP */
	    if (payload_len >= ip_len + 1 + (int)CC_PUBKEY_SZ)
		pubkey = (const unsigned char *)payload + ip_len + 1;
	    /* Config descriptor appended after the pubkey (optional) */
	    if (payload_len >= ip_len + 1 + (int)CC_PUBKEY_SZ + CC_CONFIG_SZ) {
		const char *c = payload + ip_len + 1 + CC_PUBKEY_SZ;
		uint16_t    qt_be;
		p_manage    = (unsigned char)c[0];
		p_stick     = (unsigned char)c[1];
		memcpy(&qt_be, c + 2, 2);
		p_qt        = ntohs(qt_be);
		cfg_present = 1;
	    }
	    cc_handle_alive(ip_buf, pubkey, cfg_present, p_manage, p_stick, p_qt, cl);
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

	case CC_PKT_MASTER_ALIVE:
	    cc_handle_master_alive(sender_ip_buf, cl);
	    break;

	case CC_PKT_KEY_GRANT:
	    cc_handle_key_grant(payload, payload_len, sender_ip_buf, cl);
	    break;

	case CC_PKT_KEY_HANDOFF:
	    cc_handle_key_handoff(payload, payload_len, sender_ip_buf, cl);
	    break;

	case CC_PKT_JOIN_REJECT:
	    cc_handle_join_reject(payload, payload_len, sender_ip_buf, cl);
	    break;

	case CC_PKT_MASTER_BEACON: {
	    uint16_t cnt_be, sender_count = 0;
	    if (payload_len >= 2) {
		memcpy(&cnt_be, payload, 2);
		sender_count = ntohs(cnt_be);
	    }
	    cc_handle_master_beacon(sender_ip_buf, sender_count, cl);
	    break;
	}

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

/* =========================================================================
 * Reactor callbacks - one per event source
 * ========================================================================= */

static int cc_on_sock(int fd, void *param, int was_timeout)
{
    cc_recv_one(fd, (cc_cluster_t *)param);
    return 0;
}

static int cc_on_alive_tfd(int fd, void *param, int was_timeout)
{
    cc_cluster_t *cl = (cc_cluster_t *)param;
    int prev_master, now_master;
    cc_drain_tfd(fd);
    cc_send_alive(cl->sock, cl);
    lock_start_write(cl->peers->lock);
    prev_master = cc_i_am_master_locked(cl);
    cc_prune_stale(cl);
    cc_elect_master(cl);
    now_master = cc_i_am_master_locked(cl);
    lock_stop_write(cl->peers->lock);
    /* Do not broadcast MASTER_ALIVE before we hold the cluster key -
     * request a re-key from the current key-holder instead. */
    if (now_master && !cl->have_session_key) {
        cc_request_rekey(cl);
        return 0;
    }
    if (prev_master != now_master)
        cc_arm_master_timers(cl, now_master);

    /* Belt-and-suspenders identity registration (covers paths where
     * cc_handle_node_assign has not yet run).                      */
    if (!cl->identity_registered && clctl_loaded && my_node_id > 0) {
	str url = {cl->bin_socket, (int)strlen(cl->bin_socket)};
	clctl.update_identity(cl->cluster_id, my_node_id, &url);
	cl->identity_registered = 1;
    }

    /* Bootstrap shtag activation: only for fresh clusters
     * (shtag_bootstrapped == -1).  Retries until we are master. */
    if (cl->manage_shtags && clctl_loaded && cl->shtag_bootstrapped == -1
        && clctl.activate_backup_shtags) {
	int _im;
	lock_start_read(cl->peers->lock);
	_im = cc_i_am_master_locked(cl);
	lock_stop_read(cl->peers->lock);
	if (_im) {
	    cc_apply_shtags(cl);   /* override-aware */
	    cl->shtag_bootstrapped = 1;
	}
    }
    return 0;
}

static int cc_on_join_tfd(int fd, void *param, int was_timeout)
{
    cc_cluster_t *cl = (cc_cluster_t *)param;
    cc_drain_tfd(fd);

    int was_new, auth_fails;
    lock_start_write(cl->peers->lock);
    was_new    = (cl->peers->node_state == CC_NODE_NEW);
    auth_fails = cl->auth_fail_pkts;

    /* Wrong-password / unauthorized guard: if we are still joining at the
     * deadline AND we received packets from peers we could not decrypt, then a
     * cluster whose key we do not share exists on this multicast group.
     * Self-promoting would create a split-brain lone master (and, with managed
     * shtags, a duplicate active tag).  A wrong-password node also cannot read
     * the master's JOIN_REJECT, so this is where it must shut down.          */
    if (was_new && auth_fails >= CC_JOIN_FAIL_LIMIT) {
	/* We could not decrypt traffic from peers on our cluster_id: a cluster
	 * using a different password (or we do) shares this group.  Do NOT
	 * self-terminate on the first deadline - a KEY_GRANT that is merely slow, a
	 * brief burst of start-up noise, or a flood of crafted garbage would
	 * otherwise kill a healthy node.  Defer and keep re-joining: a real
	 * KEY_GRANT arriving in the grace window resets auth_fail_pkts
	 * (cc_handle_key_grant) and we join normally.  Only give up after
	 * CC_JOIN_DEFER_MAX rounds still short of authentication - by then the
	 * wrong-password / foreign-cluster condition is sustained, not transient,
	 * and self-promoting would create a split-brain lone master.             */
	if (cl->auth_defer_count < CC_JOIN_DEFER_MAX) {
	    cl->auth_defer_count++;
	    lock_stop_write(cl->peers->lock);
	    LM_WARN("clusterer_controller: [cluster %d] %d undecryptable packet(s) "
	            "on cluster_id %d (%s:%d) - cannot authenticate yet, deferring "
	            "self-promotion (%d/%d); a slow KEY_GRANT would clear this\n",
	            cl->cluster_id, auth_fails, cl->cluster_id,
	            cl->multicast_address, cl->multicast_port,
	            cl->auth_defer_count, CC_JOIN_DEFER_MAX);
	    cl->join_pending = 0;
	    cc_send_join_req(cl->sock, cl);
	    cc_arm_tfd(cl->join_tfd, CC_JOIN_DEFER_SECS, 0);
	    return 0;
	}
	lock_stop_write(cl->peers->lock);
	LM_CRIT("clusterer_controller: [cluster %d] cannot authenticate on %s:%d - "
	        "%d packet(s) stayed undecryptable and no KEY_GRANT arrived across %d "
	        "re-join round(s) (wrong password, or a foreign cluster on "
	        "cluster_id %d). Shutting down.\n",
	        cl->cluster_id, cl->multicast_address, cl->multicast_port,
	        auth_fails, cl->auth_defer_count, cl->cluster_id);
	exit(-1);
    }

    /* Split-brain PREVENTION: if a higher-IP node is also still joining (we
     * learned it from its JOIN_REQ), defer self-promotion so it becomes the
     * single master and we join it, rather than both self-promoting with
     * independent session keys.  Bounded by CC_JOIN_DEFER_MAX so a higher-IP
     * node that was heard but never finished starting cannot stall us.        */
    if (was_new && cl->join_defer_count < CC_JOIN_DEFER_MAX
                && cl->join_defer_total < CC_JOIN_DEFER_HARDMAX) {
	unsigned int my_ipn = ip_to_num(my_ip);
	int          higher_seen = 0, _i;
	for (_i = 0; _i < cl->peers->count; _i++) {
	    if (strcmp(cl->peers->entries[_i].ip, my_ip) == 0)
		continue;
	    if (cl->peers->entries[_i].ip_num > my_ipn) {
		higher_seen = 1;
		break;
	    }
	}
	if (higher_seen) {
	    cl->join_defer_count++;
	    cl->join_defer_total++;
	    lock_stop_write(cl->peers->lock);
	    LM_INFO("clusterer_controller: [cluster %d] join deadline: a higher-IP "
	            "node is still joining - deferring self-promotion (%d/%d) to "
	            "avoid split brain\n",
	            cl->cluster_id, cl->join_defer_count, CC_JOIN_DEFER_MAX);
	    /* Re-send a JOIN_REQ now (clear join_pending so it is not suppressed)
	     * so the higher-IP node answers as soon as it becomes master, then
	     * extend the join window for one more short round. */
	    cl->join_pending = 0;
	    cc_send_join_req(cl->sock, cl);
	    cc_arm_tfd(cl->join_tfd, CC_JOIN_DEFER_SECS, 0);
	    return 0;
	}
    }

    if (was_new) {
	LM_INFO("clusterer_controller: [cluster %d] join deadline expired, "
	        "no master found - transitioning to CC_NODE_ACTIVE\n",
	        cl->cluster_id);
	cl->join_defer_count = 0;     /* leaving NEW state */
	cl->join_defer_total = 0;
	cl->shtag_bootstrapped = -1; /* fresh cluster: eligible to claim active */
	cc_upsert_peer_locked(my_ip, cl);
	my_node_id = cc_alloc_node_id_locked(cl);
	{
	    char self_sock[1][CC_MAX_BIN_SOCK_LEN];
	    memcpy(self_sock[0], cl->bin_socket, CC_MAX_BIN_SOCK_LEN);
	    cc_update_peer_bin_locked(my_ip, my_node_id, 1,
	                              (const char (*)[CC_MAX_BIN_SOCK_LEN])
	                              self_sock, cl);
	}
	cl->peers->node_state = CC_NODE_ACTIVE;
	/* Run election first so is_master and last_master are set before
	 * cc_on_became_master.  Without this, cc_handle_alive would see
	 * is_master=0 on the loopback ALIVE and call cc_on_became_master
	 * a second time, regenerating the session key unnecessarily.     */
	cc_elect_master(cl);
	cc_on_became_master(cl);
    }
    lock_stop_write(cl->peers->lock);
    if (!was_new)
	return 0;  /* already active via MEMBER_LIST - nothing to do */
    cc_transition_to_active(cl);
    cc_arm_master_timers(cl, 1);

    if (!cl->identity_registered && clctl_loaded && my_node_id > 0) {
	str url = {cl->bin_socket, (int)strlen(cl->bin_socket)};
	clctl.update_identity(cl->cluster_id, my_node_id, &url);
	cl->identity_registered = 1;
    }
    return 0;
}

static int cc_on_rejoin_tfd(int fd, void *param, int was_timeout)
{
    cc_cluster_t *cl = (cc_cluster_t *)param;
    int still_new;

    cc_drain_tfd(fd);
    lock_start_read(cl->peers->lock);
    still_new = (cl->peers->node_state == CC_NODE_NEW);
    lock_stop_read(cl->peers->lock);
    if (still_new && !cl->join_pending) {
	cl->join_attempt_count++;

	/* Wrong-password fallback: if the master keeps sending bootstrap
	 * packets we cannot decrypt (bootstrap_auth_fails > 0) and we have
	 * already retried CC_JOIN_FAIL_LIMIT times, give up.  This fires when
	 * the encrypted JOIN_REJECT from the master was lost in transit (if it
	 * arrived intact, cc_handle_join_reject would have already exited).   */
	if (cl->join_attempt_count >= CC_JOIN_FAIL_LIMIT
	        && cl->bootstrap_auth_fails > 0) {
	    LM_CRIT("clusterer_controller: [cluster %d] join failed after %d "
	            "attempts with %d bootstrap auth error(s) - wrong password? "
	            "Shutting down.\n",
	            cl->cluster_id, cl->join_attempt_count,
	            cl->bootstrap_auth_fails);
	    exit(-1);
	}

	cc_send_join_req(cl->sock, cl);
	cl->join_pending = 1;
	LM_DBG("clusterer_controller: [cluster %d] resending JOIN_REQ "
	       "(attempt %d)\n", cl->cluster_id, cl->join_attempt_count);
    }
    return 0;
}

static int cc_on_master_alive_tfd(int fd, void *param, int was_timeout)
{
    cc_cluster_t *cl = (cc_cluster_t *)param;
    cc_drain_tfd(fd);
    cc_send_master_alive(cl->sock, cl);
    /* Emit a bootstrap-key beacon every CC_MASTER_BEACON_EVERY ticks so any
     * peer master holding a different session key can find us and merge. */
    if (++cl->beacon_tick >= CC_MASTER_BEACON_EVERY) {
        cl->beacon_tick = 0;
        cc_send_master_beacon(cl->sock, cl);
    }
    return 0;
}

static int cc_on_master_dead_tfd(int fd, void *param, int was_timeout)
{
    cc_cluster_t *cl     = (cc_cluster_t *)param;
    int           now_master;
    char          dead_master[CC_MAX_IP_LEN + 1];

    cc_drain_tfd(fd);

    dead_master[0] = '\0';

    lock_start_write(cl->peers->lock);
    /* The master has been silent for CC_MASTER_KA_TIMEOUT (3s).  Age the silent
     * master OUT of the election window before re-electing, otherwise
     * cc_elect_master would just re-select it: the election window is
     * query_time * CC_ELECT_FACTOR (~15s), far longer than the keepalive
     * timeout, so a just-declared-dead master stays "eligible" and keeps
     * winning - delaying real failover by ~12s.  Zeroing its last_seen makes
     * the immediate re-election pick the next-highest LIVE peer.  If the
     * master was only briefly unreachable, its next MASTER_ALIVE/ALIVE
     * refreshes last_seen and the normal highest-IP election restores it. */
    {
        int _i;
        for (_i = 0; _i < cl->peers->count; _i++) {
            if (cl->peers->entries[_i].is_master &&
                strcmp(cl->peers->entries[_i].ip, my_ip) != 0) {
                size_t _l = strnlen(cl->peers->entries[_i].ip, CC_MAX_IP_LEN);
                memcpy(dead_master, cl->peers->entries[_i].ip, _l);
                dead_master[_l] = '\0';
                cl->peers->entries[_i].last_seen   = 0;
                cl->peers->entries[_i].in_election = 0;
            }
            cl->peers->entries[_i].is_master = 0;
        }
        cl->peers->last_master[0] = '\0';
    }

    LM_INFO("clusterer_controller: [cluster %d] master %s went silent "
            "(no keepalive for %ds) - re-electing\n",
            cl->cluster_id,
            dead_master[0] ? dead_master : "(unknown)",
            CC_MASTER_KA_TIMEOUT);

    /* cc_elect_master logs the resulting MASTER/BACKUP roles and why. */
    cc_elect_master(cl);
    now_master = cc_i_am_master_locked(cl);
    lock_stop_write(cl->peers->lock);

    /* Preserve-key recovery: every surviving member already holds the session
     * key, so the winner has it too.  Guard defensively against the impossible
     * keyless-winner case rather than broadcasting an undecryptable MEMBER_LIST. */
    if (now_master && !cl->have_session_key) {
        LM_WARN("clusterer_controller: [cluster %d] elected master after "
                "keepalive timeout but hold no session key - deferring\n",
                cl->cluster_id);
        return 0;
    }

    cc_arm_master_timers(cl, now_master);

    /* The new master announces itself; all members already hold the session
     * key so no re-keying is needed. */
    if (now_master)
        cc_send_member_list(cl->sock, cl);
    return 0;
}

/**
 * cc_worker() - the single dedicated background process.
 *
 * JOIN PROTOCOL:
 *   1. Open socket, join multicast group.
 *   2. Send CC_PKT_JOIN_REQ and set state = CC_NODE_NEW with a deadline
 *      of (now + query_time).
 *   3. Listen for incoming packets.  If CC_PKT_MEMBER_LIST arrives:
 *        -> cc_handle_member_list() sets state = CC_NODE_ACTIVE.
 *      If deadline expires with no MEMBER_LIST:
 *        -> no master exists yet; transition to CC_NODE_ACTIVE and
 *          join the normal election cycle.
 *
 * ACTIVE LOOP:
 *   Fully event-driven via OpenSIPS reactor (epoll by default).
 *   Each event source is a registered fd with a dedicated callback:
 *     cc_on_sock       - incoming UDP packet
 *     cc_on_alive_tfd  - periodic ALIVE heartbeat (query_time seconds)
 *     cc_on_join_tfd   - one-shot join deadline
 *     cc_on_rejoin_tfd - 1-second JOIN_REQ retry while in CC_NODE_NEW
 *   reactor_proc_init() also wires in IPC (shutdown, load stats, reload).
 */
static void cc_worker(int rank)
{
    cc_cluster_t *cl;

    if (rank >= cc_cluster_count) {
	/* Extra process slot - no cluster assigned, exit cleanly */
	return;
    }
    cl = &cc_clusters[rank];

    LM_INFO("clusterer_controller: [cluster %d] worker started (pid=%d)\n",
            cl->cluster_id, getpid());

    /* Publish our process index so MI handlers (other processes) can reach us
     * via ipc_send_rpc() to apply operator-driven shtag overrides promptly. */
    cl->peers->worker_proc_no = process_no;

    cl->shtag_last_active = -1;   /* unknown - first decision logs its reason */
    cl->shtag_last_forced = 0;

    cl->sock = cc_setup_socket(cl);
    if (cl->sock < 0) {
	LM_CRIT("clusterer_controller: [cluster %d] cannot open multicast socket, "
	        "worker exits\n", cl->cluster_id);
	exit(-1);
    }

    /* Generate ephemeral X25519 keypair - private key never leaves this process */
    if (cc_gen_ecdh_keypair(cl->my_privkey, cl->my_pubkey) < 0) {
	LM_CRIT("clusterer_controller: [cluster %d] ECDH keypair generation failed\n",
	        cl->cluster_id);
	exit(-1);
    }

    /* Store our pubkey in peer table entry for ourselves so MEMBER_LIST broadcasts it */
    lock_start_write(cl->peers->lock);
    {
        int _i;
        for (_i = 0; _i < cl->peers->count; _i++) {
            if (strcmp(cl->peers->entries[_i].ip, my_ip) == 0) {
                memcpy(cl->peers->entries[_i].pubkey, cl->my_pubkey, CC_PUBKEY_SZ);
                break;
            }
        }
    }
    lock_stop_write(cl->peers->lock);

    cl->alive_tfd        = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    cl->join_tfd         = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    cl->rejoin_tfd       = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    cl->master_alive_tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    cl->master_dead_tfd  = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (cl->alive_tfd < 0 || cl->join_tfd < 0 || cl->rejoin_tfd < 0 ||
        cl->master_alive_tfd < 0 || cl->master_dead_tfd < 0) {
	LM_CRIT("clusterer_controller: [cluster %d] timerfd_create: %s\n",
	        cl->cluster_id, strerror(errno));
	exit(-1);
    }

    cl->rate_tbl = pkg_malloc(CC_RATE_TBL_SZ * sizeof(cc_rate_entry_t));
    if (!cl->rate_tbl) {
	LM_CRIT("clusterer_controller: [cluster %d] no pkg memory for rate table\n",
	        cl->cluster_id);
	exit(-1);
    }
    memset(cl->rate_tbl, 0, CC_RATE_TBL_SZ * sizeof(cc_rate_entry_t));

    /* ---- Phase 1: join protocol ---- */
    lock_start_write(cl->peers->lock);
    cl->peers->node_state    = CC_NODE_NEW;
    cl->peers->join_deadline = time(NULL) + (time_t)query_time;
    lock_stop_write(cl->peers->lock);

    cc_send_join_req(cl->sock, cl);
    cc_arm_tfd(cl->join_tfd,   (time_t)query_time, 0); /* one-shot deadline  */
    cc_arm_tfd(cl->rejoin_tfd, 1, 1);                  /* retry every 1 s    */
    /* alive_tfd left disarmed - armed by cc_transition_to_active() */

    LM_INFO("clusterer_controller: [cluster %d] sent JOIN_REQ, waiting up to %ds "
            "for master response\n", cl->cluster_id, query_time);

    /* ---- Register with reactor and enter event loop ---- */
    if (reactor_proc_init("clusterer_controller worker") < 0) {
	LM_CRIT("clusterer_controller: [cluster %d] reactor_proc_init failed\n",
	        cl->cluster_id);
	exit(-1);
    }

    if (reactor_proc_add_fd(cl->sock,            cc_on_sock,            cl) < 0 ||
        reactor_proc_add_fd(cl->alive_tfd,       cc_on_alive_tfd,       cl) < 0 ||
        reactor_proc_add_fd(cl->join_tfd,        cc_on_join_tfd,        cl) < 0 ||
        reactor_proc_add_fd(cl->rejoin_tfd,      cc_on_rejoin_tfd,      cl) < 0 ||
        reactor_proc_add_fd(cl->master_alive_tfd, cc_on_master_alive_tfd, cl) < 0 ||
        reactor_proc_add_fd(cl->master_dead_tfd,  cc_on_master_dead_tfd,  cl) < 0) {
	LM_CRIT("clusterer_controller: [cluster %d] reactor_proc_add_fd failed\n",
	        cl->cluster_id);
	exit(-1);
    }

    reactor_proc_loop();

    /* ---- Graceful shutdown epilogue ---- */
    {
        int i_am_master;
        lock_start_read(cl->peers->lock);
        i_am_master = cc_i_am_master_locked(cl);
        lock_stop_read(cl->peers->lock);

        if (i_am_master && cl->peers->count > 1) {
            /* Find the peer that will win the next election (highest IP, not us) */
            unsigned int  best_ip   = 0;
            int           best_idx  = -1;
            int           _i;
            lock_start_read(cl->peers->lock);
            for (_i = 0; _i < cl->peers->count; _i++) {
                cc_peer_t *e = &cl->peers->entries[_i];
                if (strcmp(e->ip, my_ip) == 0) continue;
                if (e->ip_num > best_ip) { best_ip = e->ip_num; best_idx = _i; }
            }
            if (best_idx >= 0) {
                char           next_ip[CC_MAX_IP_LEN + 1];
                unsigned char  next_pub[CC_PUBKEY_SZ];
                memcpy(next_ip, cl->peers->entries[best_idx].ip, CC_MAX_IP_LEN + 1);
                memcpy(next_pub, cl->peers->entries[best_idx].pubkey, CC_PUBKEY_SZ);
                lock_stop_read(cl->peers->lock);
                cc_send_key_handoff(cl->sock, next_ip, next_pub, cl);
            } else {
                lock_stop_read(cl->peers->lock);
            }
        }
    }

    close(cl->sock);
    close(cl->alive_tfd);
    close(cl->join_tfd);
    close(cl->rejoin_tfd);
    close(cl->master_alive_tfd);
    close(cl->master_dead_tfd);
}

/* =========================================================================
 * MI command handlers
 * ========================================================================= */

/**
 * mi_cl_ctr_members() - list active cluster members with their role.
 *
 *   opensips-cli -x mi cl_ctr_list_members
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
static mi_response_t *mi_cl_ctr_members(const mi_params_t *params,
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
	                      e->is_master ? "master" : (e->is_backup ? "backup" : "member"),
	                      6) < 0) {
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
    LM_ERR("clusterer_controller: mi_cl_ctr_members: failed to build response\n");
    free_mi_response(resp);
    return NULL;
}

/**
 * mi_cl_ctr_node_info() - return full info for a specific node_id.
 *
 *   opensips-cli -x mi cl_ctr_node_info node_id=2
 */
static mi_response_t *mi_cl_ctr_node_info(const mi_params_t *params,
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
	                      e->is_master ? "master" : (e->is_backup ? "backup" : "member"),
	                      6)                                                     < 0) {
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
    LM_ERR("clusterer_controller: mi_cl_ctr_node_info: failed to build response\n");
    free_mi_response(resp);
    return NULL;
}

/**
 * mi_cl_ctr_config() - list all configured clusters and their resolved settings.
 *
 *   opensips-cli -x mi cl_ctr_list_config
 *
 * Reports per cluster: id, multicast endpoint, master_stickiness,
 * manage_shtags, query_time, this node's BIN socket and current member count.
 * The password is intentionally NOT exposed.
 */
static mi_response_t *mi_cl_ctr_config(const mi_params_t *params,
                                     struct mi_handler *hdl)
{
    mi_response_t  *resp;
    mi_item_t      *arr, *cl_obj;
    int             ci, members;
    char            mcast[INET_ADDRSTRLEN + 8];  /* "IP:PORT" */
    char            shtag_mode[24];              /* "auto" / "override:<id>" */
    cc_cluster_t   *cl;

    resp = init_mi_result_array(&arr);
    if (!resp)
	return NULL;

    for (ci = 0; ci < cc_cluster_count; ci++) {
	cl = &cc_clusters[ci];

	cl_obj = add_mi_object(arr, NULL, 0);
	if (!cl_obj) goto error;

	snprintf(mcast, sizeof(mcast), "%s:%d",
	         cl->multicast_address, cl->multicast_port);

	members = 0;
	/* Report the EFFECTIVE (possibly adopted) settings from shm, so the
	 * values reflect what is actually in force after on_config_mismatch=
	 * adopt (the worker mirrors them there).  Fall back to the configured
	 * values if the peer table is not up yet. */
	int eff_manage = cl->manage_shtags, eff_stick = cl->master_stickiness,
	    eff_qt = query_time;
	{
	    uint16_t forced = 0;
	    if (cl->peers) {
		lock_start_read(cl->peers->lock);
		members    = cl->peers->count;
		forced     = cl->peers->shtag_forced_node_id;
		eff_manage = cl->peers->eff_manage_shtags;
		eff_stick  = cl->peers->eff_master_stickiness;
		eff_qt     = cl->peers->eff_query_time;
		lock_stop_read(cl->peers->lock);
	    }
	    /* Current shtag allocation mode: "auto" = master-driven automatic
	     * allocation; "override:<node_id>" = operator forced a fixed holder
	     * via cl_ctr_shtag_force.  ("manual" is reserved for the future
	     * maintenance mode.)                                              */
	    if (forced)
		snprintf(shtag_mode, sizeof(shtag_mode), "override:%u", forced);
	    else
		snprintf(shtag_mode, sizeof(shtag_mode), "auto");
	}

	if (add_mi_number(cl_obj, MI_SSTR("cluster_id"),   cl->cluster_id)        < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("multicast"),    mcast, strlen(mcast))  < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("my_ip"),        my_ip, strlen(my_ip))  < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("bin_socket"),
	                  cl->bin_socket, strlen(cl->bin_socket))                 < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("query_time"),   eff_qt)                < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("master_stickiness"), eff_stick)        < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("manage_shtags"), eff_manage)           < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("shtag_mode"),
	                  shtag_mode, strlen(shtag_mode))                         < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("member_count"), members)               < 0)
	    goto error;
    }

    return resp;

error:
    LM_ERR("clusterer_controller: mi_cl_ctr_config: failed to build response\n");
    free_mi_response(resp);
    return NULL;
}

/**
 * cc_rpc_apply_shtags() - IPC job run inside the cc_worker process.
 *
 * An MI handler (running in a different process) has already updated
 * cl->peers->shtag_forced_node_id in shm; this job makes the change take
 * effect promptly: it re-applies the local shtag decision and, if we are the
 * master, re-broadcasts the MEMBER_LIST so every member learns the new
 * override without waiting for the next periodic announcement.
 */
static void cc_rpc_apply_shtags(int sender, void *param)
{
    cc_cluster_t *cl = (cc_cluster_t *)param;
    int i_am_master;

    (void)sender;
    if (!cl || !cl->peers)
	return;

    cc_apply_shtags(cl);

    lock_start_read(cl->peers->lock);
    i_am_master = cc_i_am_master_locked(cl);
    lock_stop_read(cl->peers->lock);

    if (i_am_master && cl->sock >= 0)
	cc_send_member_list(cl->sock, cl);
}

/**
 * cc_mi_find_cluster() - locate a configured cluster by its cluster_id.
 * Returns NULL if no cluster matches.
 */
static cc_cluster_t *cc_mi_find_cluster(int cluster_id)
{
    int ci;
    for (ci = 0; ci < cc_cluster_count; ci++)
	if (cc_clusters[ci].cluster_id == cluster_id)
	    return &cc_clusters[ci];
    return NULL;
}

/**
 * mi_cl_ctr_shtag_force() - force a specific node to hold the active sharing tag.
 *
 *   opensips-cli -x mi cl_ctr_shtag_force cluster_id=1 node_id=2
 *
 * Must be issued on the current master.  Suspends automatic (master-driven)
 * shtag allocation until cl_ctr_shtag_auto is called; the chosen node becomes the
 * sole active shtag holder cluster-wide.  The override is propagated to every
 * member via the MEMBER_LIST and survives master fail-over, but is cleared
 * automatically if the forced node leaves or times out.
 */
static mi_response_t *mi_cl_ctr_shtag_force(const mi_params_t *params,
                                        struct mi_handler *hdl)
{
    int            cluster_id, node_id;
    cc_cluster_t  *cl;
    int            i_am_master, found = 0, proc_no;

    if (get_mi_int_param(params, "cluster_id", &cluster_id) < 0 ||
        get_mi_int_param(params, "node_id",    &node_id)    < 0)
	return init_mi_param_error();

    if (node_id <= 0 || node_id > 0xFFFF)
	return init_mi_error(400, MI_SSTR("node_id out of range"));

    cl = cc_mi_find_cluster(cluster_id);
    if (!cl || !cl->peers)
	return init_mi_error(404, MI_SSTR("cluster_id not found"));

    if (!cl->manage_shtags)
	return init_mi_error(409,
	        MI_SSTR("shtag management is disabled for this cluster"));

    lock_start_write(cl->peers->lock);
    i_am_master = cc_i_am_master_locked(cl);
    if (i_am_master) {
	int i;
	for (i = 0; i < cl->peers->count; i++) {
	    if ((int)cl->peers->entries[i].node_id == node_id) {
		found = 1;
		break;
	    }
	}
	/* TODO(maintenance-mode): once node maintenance mode lands, reject
	 * forcing the shtag onto a node that is currently in maintenance. */
	if (found)
	    cl->peers->shtag_forced_node_id = (uint16_t)node_id;
    }
    proc_no = cl->peers->worker_proc_no;
    lock_stop_write(cl->peers->lock);

    if (!i_am_master)
	return init_mi_error(409,
	        MI_SSTR("not the master - issue cl_ctr_shtag_force on the master node"));
    if (!found)
	return init_mi_error(404, MI_SSTR("node_id not a member of this cluster"));

    /* Apply locally and broadcast the new override from the worker process. */
    if (proc_no >= 0)
	ipc_send_rpc(proc_no, cc_rpc_apply_shtags, cl);

    LM_INFO("clusterer_controller: [cluster %d] operator forced shtag onto "
            "node %d\n", cluster_id, node_id);
    return init_mi_result_ok();
}

/**
 * mi_cl_ctr_shtag_auto() - resume automatic (master-driven) shtag allocation.
 *
 *   opensips-cli -x mi cl_ctr_shtag_auto cluster_id=1
 *
 * Clears any operator override set by cl_ctr_shtag_force so the active shtag
 * follows the master again.  Must be issued on the current master.
 */
static mi_response_t *mi_cl_ctr_shtag_auto(const mi_params_t *params,
                                       struct mi_handler *hdl)
{
    int            cluster_id;
    cc_cluster_t  *cl;
    int            i_am_master, proc_no;

    if (get_mi_int_param(params, "cluster_id", &cluster_id) < 0)
	return init_mi_param_error();

    cl = cc_mi_find_cluster(cluster_id);
    if (!cl || !cl->peers)
	return init_mi_error(404, MI_SSTR("cluster_id not found"));

    lock_start_write(cl->peers->lock);
    i_am_master = cc_i_am_master_locked(cl);
    if (i_am_master)
	cl->peers->shtag_forced_node_id = 0;
    proc_no = cl->peers->worker_proc_no;
    lock_stop_write(cl->peers->lock);

    if (!i_am_master)
	return init_mi_error(409,
	        MI_SSTR("not the master - issue cl_ctr_shtag_auto on the master node"));

    if (proc_no >= 0)
	ipc_send_rpc(proc_no, cc_rpc_apply_shtags, cl);

    LM_INFO("clusterer_controller: [cluster %d] operator resumed automatic "
            "shtag allocation\n", cluster_id);
    return init_mi_result_ok();
}
/* =========================================================================
 * Lifecycle
 * ========================================================================= */

/**
 * cc_resolve_local_identity() - determine my_ip and my_interface_buf.
 *
 * Three modes depending on which modparams were provided:
 *
 *   Mode 1 - ip= only:
 *     Walk getifaddrs() to find the interface that owns the given IP.
 *     Fails if no interface owns it.
 *
 *   Mode 2 - interface= only:
 *     Walk getifaddrs() to find the interface and take its first IPv4 address.
 *     Warns if the interface has multiple IPv4 addresses; uses the first one
 *     (the kernel's enumeration order matches `ip addr show`).
 *
 *   Mode 3 - neither:
 *     Connect a throw-away UDP socket to the multicast group (no data sent).
 *     getsockname() returns the source IP the kernel would select.
 *     Reverse-look up the interface name via getifaddrs().
 *
 * On success: my_ip points to a valid dotted-decimal IPv4 string and
 *             my_interface_buf holds the interface name (may be empty if the
 *             reverse lookup failed in mode 3 - non-fatal).
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
    cl->manage_shtags = -1; /* sentinel: inherit global default in mod_init */
    cl->master_stickiness = -1; /* sentinel: inherit global default in mod_init */

    for (tok = strtok_r(buf, ",", &p); tok; tok = strtok_r(NULL, ",", &p)) {
	while (*tok == ' ' || *tok == '\t') tok++;
	key = tok;
	val = strchr(tok, '=');
	if (!val) continue;
	*val++ = '\0';

	if (strcmp(key, "id") == 0) {
	    cl->cluster_id = atoi(val);
	    if (cl->cluster_id <= 0 || cl->cluster_id > 65535) {
		LM_ERR("clusterer_controller: cluster id must be 1..65535 "
		       "(carried as a 2-byte field on the wire)\n");
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

	} else if (strcmp(key, "manage_shtags") == 0) {
	    cl->manage_shtags = atoi(val) ? 1 : 0;

	} else if (strcmp(key, "master_stickiness") == 0) {
	    cl->master_stickiness = atoi(val) ? 1 : 0;
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
	/* ---- Mode 1: ip= explicitly provided - find owning interface ---- */
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
	/* ---- Mode 2: interface= provided - derive IP from it ---- */
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
	/* ---- Mode 3: neither - auto-detect via kernel routing table ---- */
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
    struct socket_info_full *sif;
    struct socket_info *si;
    char                buf[CC_MAX_BIN_SOCK_LEN];
    int                 len;

    /* On devel, protos[].listeners is a list of socket_info_full (next/prev),
     * each embedding the socket_info as its first member. */
    for (sif = protos[PROTO_BIN].listeners; sif; sif = sif->next) {
	si = &sif->socket_info;
	/* all entries here are PROTO_BIN by construction */
	if (si->proto != PROTO_BIN)
	    continue;
	/* Reject wildcard - clusterer needs an explicit IP to set send_sock.
	 * Use socket=bin:IP:PORT instead of socket=bin:*:PORT.             */
	if (si->address_str.len == 0
	    || (si->address_str.len == 1 && si->address_str.s[0] == '*')
	    || (si->address_str.len == 7
	        && memcmp(si->address_str.s, "0.0.0.0", 7) == 0)) {
	    LM_ERR("clusterer_controller: wildcard BIN socket "
	           "(bin:*:%u) is not allowed - use an explicit IP "
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
	LM_ERR("clusterer_controller: no BIN sockets found - "
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

    if (wc_InitRng(&cc_rng) != 0) {
	LM_ERR("clusterer_controller: wc_InitRng failed\n");
	return -1;
    }

#ifdef CC_HAVE_SODIUM
    if (sodium_init() < 0) {
	LM_ERR("clusterer_controller: sodium_init() failed\n");
	return -1;
    }
#endif

    /* Resolve the on_config_mismatch policy string. */
    if (on_config_mismatch_s) {
	if (strcasecmp(on_config_mismatch_s, "warn") == 0)
	    on_config_mismatch = CC_CFGMISMATCH_WARN;
	else if (strcasecmp(on_config_mismatch_s, "reject") == 0)
	    on_config_mismatch = CC_CFGMISMATCH_REJECT;
	else if (strcasecmp(on_config_mismatch_s, "adopt") == 0)
	    on_config_mismatch = CC_CFGMISMATCH_ADOPT;
	else {
	    LM_ERR("clusterer_controller: invalid on_config_mismatch '%s' "
	           "(expected warn|reject|adopt)\n", on_config_mismatch_s);
	    return -1;
	}
    }

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
	pkg_free(cc_cluster_strs[i]);
	cc_cluster_strs[i] = NULL;
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
    /* wildcard substitution (bin:*:PORT -> bin:my_ip:PORT).               */

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
		       "defined - required when multiple clusters are configured "
		       "(e.g. id=%d,multicast=...,bin_socket=bin:IP:PORT)\n",
		       cc_clusters[i].cluster_id, cc_clusters[i].cluster_id);
		return -1;
	    }
	}
    }

    /* ---- Per-cluster: resolve BIN socket, derive key, allocate peers --- */

    for (i = 0; i < cc_cluster_count; i++) {
	cc_cluster_t *cl = &cc_clusters[i];

	/* Resolve sentinels to the global default when the cluster string did
	 * not set them explicitly.  Done here (unconditionally, before workers
	 * fork and before any MI query) so every cl->* setting always holds a
	 * concrete 0/1 value regardless of whether clusterer is loaded - a mix
	 * of global and per-cluster overrides always reports correctly.        */
	if (cl->master_stickiness == -1)
	    cl->master_stickiness = master_stickiness ? 1 : 0;
	if (cl->manage_shtags == -1)
	    cl->manage_shtags = manage_shtags ? 1 : 0;

	/* Resolve which BIN socket to use for this cluster.
	 * Priority: explicit bin_socket= in cluster string >
	 *           sole discovered socket >
	 *           first discovered socket (warn if multiple) */
	if (cl->bin_socket[0] != '\0') {
	    /* Explicit override - validate it was actually discovered */
	    int found_bs = 0, bi;
	    for (bi = 0; bi < my_bin_count; bi++) {
		if (strcmp(my_bin_sockets[bi], cl->bin_socket) == 0) {
		    found_bs = 1;
		    break;
		}
	    }
	    if (!found_bs) {
	    	char _disc[CC_MAX_BIN_SOCKETS * (CC_MAX_BIN_SOCK_LEN + 2)];
	    	int  _o = 0, _b;
	    	_disc[0] = '\0';
	    	for (_b = 0; _b < my_bin_count; _b++)
	    		_o += snprintf(_disc + _o, sizeof(_disc) - _o, "%s%s",
	    		               _b ? ", " : "", my_bin_sockets[_b]);
	    	LM_ERR("clusterer_controller: cluster %d bin_socket='%s' does not "
	    	       "match any configured BIN listener (discovered: %s) - peers "
	    	       "cannot connect and clusterer replication would silently "
	    	       "fail; fix bin_socket= or the socket=bin: line\n",
	    	       cl->cluster_id, cl->bin_socket, _disc);
	    	return -1;
	    }
	} else if (my_bin_count == 1) {
	    /* Only one socket - unambiguous */
	    {
		size_t _l = strnlen(my_bin_sockets[0], CC_MAX_BIN_SOCK_LEN - 1);
		memcpy(cl->bin_socket, my_bin_sockets[0], _l);
		cl->bin_socket[_l] = '\0';
	    }
	} else {
	    /* Multiple sockets, no explicit override - use first, warn */
	    {
		size_t _l = strnlen(my_bin_sockets[0], CC_MAX_BIN_SOCK_LEN - 1);
		memcpy(cl->bin_socket, my_bin_sockets[0], _l);
		cl->bin_socket[_l] = '\0';
	    }
	    LM_WARN("clusterer_controller: cluster %d has no bin_socket= override "
	            "and multiple BIN sockets exist - using %s; add bin_socket= "
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
	cl->peers->worker_proc_no = -1;   /* published by cc_worker after fork */
	cl->peers->eff_manage_shtags     = cl->manage_shtags;
	cl->peers->eff_master_stickiness = cl->master_stickiness;
	cl->peers->eff_query_time        = query_time;

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
            "clusters=%d bin_sockets=%d crypto=%s\n",
            my_ip, my_interface_buf[0] ? my_interface_buf : "(unknown)",
            query_time, cc_cluster_count, my_bin_count, CC_CRYPTO_SUITE);

    /* Set worker process count dynamically - one per cluster */
    procs[0].no = cc_cluster_count;

    /* Load clusterer controller API if clusterer.so is present and
     * use_controller=1 is set.  Soft dependency - controller works
     * standalone even without clusterer loaded.                     */
    {
	load_clusterer_ctrl_binds_f load_fn;
	load_fn = (load_clusterer_ctrl_binds_f)
	          find_export("load_clusterer_ctrl_binds", 0);
	if (load_fn && load_fn(&clctl) == 0) {
	    clctl_loaded = 1;
	    LM_INFO("clusterer_controller: clusterer API loaded - "
	            "topology will be driven dynamically\n");

	    /* The controller is only meaningful when the clusterer module is told
	     * to expect it (use_controller=1, a global switch): that is what
	     * pre-creates the controller-managed cluster stubs, sets each one's
	     * controller_managed flag (so they never touch the DB), and arms the
	     * guard that stops the controller from hijacking a native cluster of the
	     * same id.  With use_controller=0 there is no controller-managed cluster
	     * at all and those safety mechanisms are off, so refuse to start rather
	     * than run the control plane against clusters clusterer never authorised
	     * us to drive.  (Hybrid setups keep use_controller=1 - only the per-
	     * cluster kind differs - so this never trips them.) */
	    if (!clctl.use_controller) {
		LM_ERR("clusterer_controller: loaded but the clusterer module has "
		       "use_controller=0 - there is no controller-managed cluster and "
		       "the controller's safety guards are disabled. Set "
		       "modparam(\"clusterer\", \"use_controller\", 1), or remove the "
		       "clusterer_controller module.\n");
		return -1;
	    }

	    /* When we manage sharing tags, start every tag as BACKUP and
	     * lock out MI/script changes - the controller master decides
	     * who becomes active.  (manage_shtags sentinels were already
	     * resolved to concrete 0/1 in the unconditional loop above.)  */
	    {
		int _ci;
		for (_ci = 0; _ci < cc_cluster_count; _ci++) {
		    if (!cc_clusters[_ci].manage_shtags)
			continue;
		    if (clctl.force_backup_shtags)
			clctl.force_backup_shtags(cc_clusters[_ci].cluster_id);
		    if (clctl.set_shtag_managed)
			clctl.set_shtag_managed(cc_clusters[_ci].cluster_id);
		}
	    }

	} else {
	    LM_DBG("clusterer_controller: clusterer not loaded or "
	           "use_controller not set - running standalone\n");
	}
    }

    return 0;
}

static int cc_child_init(int rank)
{
	/* Re-seed RNG after fork - each worker must have independent state. */
	wc_FreeRng(&cc_rng);
	if (wc_InitRng(&cc_rng) != 0) {
		LM_ERR("clusterer_controller: wc_InitRng failed in child\n");
		return -1;
	}

	/* Sync current_id from shared memory in every child process.
	 * The global current_id diverges after fork - each process needs
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
	/* Derive session_key locally from master_salt in shm so we can encrypt
	 * GOODBYE - the worker's cl->session_key is in a different process. */
	{
	    size_t plen = strlen(cl->password);
	    cc_hkdf_sha256((unsigned char *)cl->password, plen,
	                   cl->peers->master_salt, CC_MASTER_SALT_SZ,
	                   "cc_session", cl->session_key);
	}
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
