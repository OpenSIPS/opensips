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
 * CRYPTO SUITE (all libsodium; libsodium is a hard build requirement):
 *   - XChaCha20-Poly1305 payload AEAD, 24-byte nonce (its 192-bit nonce space
 *     removes any random-nonce collision worry).
 *   - Argon2id bootstrap-key KDF.
 *   - Noise_NNpsk0_25519_ChaChaPoly_SHA256 for the join handshake (PSK = the
 *     Argon2id bootstrap key); crypto_box for the KEY_HANDOFF salt delivery.
 *   The active suite is logged at startup ("crypto=...").
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
 *     Payload: IP(16B) + bin_info + noise_msg1(48B) + config(4B)
 *     noise_msg1 is Noise_NNpsk0 message 1 (fresh ephemeral + AEAD tag).
 *
 *   MEMBER_LIST   - session key, multicast
 *     Master -> all: member count, the operator-forced sharing-tag holder
 *     node_id (0 = automatic), and the full peer IP list, so all nodes elect
 *     identically.  Only accepted from the current master (CL_CTR_NODE_NEW aside).
 *
 *   GOODBYE       - session key, multicast
 *     Graceful shutdown.  Peers remove sender immediately without timeout.
 *
 *   NODE_ASSIGN   - session key, multicast
 *     Master -> all: allocate node_id + BIN socket for a joining node.
 *
 *   MASTER_ALIVE  - session key, multicast
 *     Master-only keepalive every CL_CTR_MASTER_KA_INTERVAL seconds.  Peers declare
 *     the master dead after CL_CTR_MASTER_KA_TIMEOUT seconds of silence and trigger
 *     re-election.  Two masters that share a session key resolve split-brain
 *     here: the lower-IP one yields.
 *
 *   KEY_GRANT     - bootstrap key, multicast (addressed to joiner)
 *     Master reply to JOIN_REQ.
 *     Payload: IP(16B) + noise_msg2(80B)
 *     noise_msg2 is Noise_NNpsk0 message 2; its AEAD payload is the master_salt.
 *
 *   KEY_HANDOFF   - session key, multicast (addressed to next master)
 *     Outgoing master on graceful shutdown -> next-highest-IP peer.  Transfers
 *     master_salt so the new master avoids a full re-join cycle.
 *     Payload: IP(16B) + crypto_box_seal(master_salt) sealed to the next
 *     master's long-lived X25519 key (learned from its ALIVE).
 *
 *   JOIN_REJECT   - bootstrap key, multicast
 *     Master -> a source whose bootstrap packets repeatedly fail to decrypt
 *     (wrong password).  Encrypted, so only a correctly-configured node can
 *     read it; a wrong-password joiner also self-terminates at its deadline.
 *
 *   MASTER_BEACON - bootstrap key, multicast
 *     Master-only, every CL_CTR_MASTER_BEACON_EVERY keepalive ticks.  Because it
 *     uses the bootstrap key it is readable even by a master holding a
 *     DIFFERENT session key, which is how a split brain between independently
 *     bootstrapped partitions is detected and merged.  Payload: member count.
 *
 * NODE STATE MACHINE
 * ------------------
 *   CL_CTR_NODE_NEW --> (MEMBER_LIST or KEY_GRANT received) --> CL_CTR_NODE_ACTIVE
 *               --> (join_deadline expired)             --> CL_CTR_NODE_ACTIVE
 *
 *   CL_CTR_NODE_NEW:    receive only; do NOT send ALIVE or MASTER_ALIVE.
 *   CL_CTR_NODE_ACTIVE: send ALIVE every query_time seconds.
 *                   Master also sends MASTER_ALIVE every CL_CTR_MASTER_KA_INTERVAL s.
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
#include "api.h"                 /* consumer messaging API contract */
#include "../../pvar.h"         /* pv_export_t - read-only $cl_ctr_* variables */

#include "../clusterer/clusterer_ctrl.h"  /* set_my_identity, add_node, remove_node */

#include <sys/timerfd.h>    /* timerfd_create(), timerfd_settime()            */
#include "../../reactor_proc.h" /* reactor_proc_init/add_fd/loop              */

/* All cryptography is provided by libsodium, which is a hard requirement (the
 * module Makefile fails the build if it is not found).  The payload AEAD is
 * XChaCha20-Poly1305 (192-bit nonce -> no random-nonce collision worry, even for
 * the static bootstrap key), the bootstrap KDF is Argon2id, the join handshake
 * is Noise_NNpsk0_25519_ChaChaPoly_SHA256, and X25519 / HKDF-SHA256 / RNG also
 * come from libsodium. */
#include <sodium.h>

/* Clock for everything in this module that measures ELAPSED time - peer
 * liveness, election and purge windows, grace periods, back-offs, warning
 * rate limits.  CLOCK_MONOTONIC, not time(NULL): a wall-clock step (NTP
 * correcting a drifted VM, an operator setting the date) would otherwise
 * expire every peer at once and start an election storm, or - stepping back -
 * keep dead peers "alive" until the clock caught up.  Nothing here needs a
 * date; the one wall-clock value, the incarnation, is set separately.
 *
 * Biased by a constant because CLOCK_MONOTONIC counts from boot: on a node
 * started seconds after boot, "now minus the purge window" would go negative
 * and make a last_seen of 0 (never seen, or aged out by the master watchdog)
 * look fresh.  The value is only ever compared with itself, so the bias is
 * invisible otherwise.  The clock is system-wide, so values written by the
 * worker and read by MI processes stay comparable. */
#define CL_CTR_CLOCK_BIAS  1000000
static inline time_t cl_ctr_now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (time_t)ts.tv_sec + CL_CTR_CLOCK_BIAS;
}
#define CL_CTR_CRYPTO_SUITE "XChaCha20-Poly1305 + Argon2id + Noise_NNpsk0"

/* =========================================================================
 * Wire-format constants
 * ========================================================================= */

/* 2-byte wire magic - a cleartext key-selector at the start of every packet
 * (it must be readable before decryption to choose bootstrap vs session key).
 * The first byte carries the WIRE VERSION (0xCB + version: 0xCC was version 1,
 * 0xCD is version 2); the second byte distinguishes the key tier.  Only a
 * sanity/routing tag on a dedicated multicast group:port - the real
 * confidentiality and integrity come from the XChaCha20-Poly1305 payload, and
 * the magic is part of the AEAD's associated data, so it cannot be re-stamped.
 *
 * Bump CL_CTR_WIRE_VERSION whenever a change alters how an existing field is
 * read - a header layout, a field's meaning, a packet's mandatory content.  A
 * field APPENDED to a payload and read only when present (length-gated, as
 * the config, MTU and term fields are) does not need a bump.  A peer on
 * another version is refused at the magic gate, before any key is used, with
 * a warning that names it: every member of a cluster must run one version.
 *
 *   1  0xCC  header [magic][cluster_id 2B][nonce 24B]
 *            plaintext [type 1B][seq 4B]
 *   2  0xCD  header [magic][cluster_id 2B][cluster uuid 16B][nonce 24B]
 *            plaintext [type 1B][seq 4B][incarnation 8B]                     */
#define CL_CTR_MAGIC_SZ          2
#define CL_CTR_WIRE_VERSION      2
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
/* ACK payload: [acked seq 4B BE][acked packet type 1B].  The type is what keeps
 * the planes apart: control packets and consumer messages are numbered by two
 * independent counters (my_seq, my_consumer_seq), both starting from 1, so a
 * sequence number alone does not say which packet is being acknowledged. */
#define CL_CTR_ACK_SZ               5
#define CL_CTR_PKT_RESYNC           0x0C  /* member -> master: my view differs, resend state */
#define CL_CTR_PKT_CONSUMER         0x0D  /* consumer API message: [src_id][chan][data] */
/* Same payload, but the receiver acknowledges it and the sender retransmits
 * until it does.  A separate type rather than a flag in the payload so the
 * receive path can tell them apart before it parses anything, and so an old
 * build simply does not recognise it instead of half-understanding it. */
#define CL_CTR_PKT_CONSUMER_REL     0x0E

/* Consumer messaging (api.h): plaintext payload layout after type+seq is
 * [src_node_id u16 BE][chan_len u8][channel bytes][consumer payload].
 * Bounded to one comfortably-under-MTU datagram; bulk data is the
 * consumer's problem (the API contract says fall back to BIN for bulk). */
#define CL_CTR_MAX_CHANNELS         8
#define CL_CTR_CONSUMER_HDR_SZ      (CL_CTR_NODE_ID_SZ + 1)
/* Everything a consumer datagram carries BESIDES the payload. Split out from
 * the old CL_CTR_CONSUMER_PKT_MAX because the packet buffer is now sized at
 * runtime from cc_max_payload: a jumbo-frame link is meant to carry a bigger
 * payload, and a buffer fixed at CLCTR_MAX_PAYLOAD could not - it just let the
 * MTU-derived bound run off the end of it. */
#define CL_CTR_PKT_OVERHEAD         (CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ \
                                     + CL_CTR_CONSUMER_HDR_SZ + CLCTR_MAX_CHAN_LEN \
                                     + CL_CTR_TAG_SZ)
#define CL_CTR_CONSUMER_PKT_MAX     (CL_CTR_PKT_OVERHEAD + CLCTR_MAX_PAYLOAD)
/* how often one process may repeat the reliable-send refusal */
#define CL_CTR_RELIABLE_WARN_IVL    60
/* A datagram cannot exceed the UDP payload maximum no matter what the MTU
 * says - loopback reports 65536, which would otherwise compute a payload one
 * byte past what sendto() can accept. */
#define CL_CTR_UDP_PAYLOAD_MAX      65507
#define CL_CTR_PKT_MASTER_BEACON    0x0A  /* master-only announce (BOOTSTRAP key) so
                                       * masters with divergent session keys can
                                       * still discover each other and merge a
                                       * split brain; payload = member count 2B BE,
                                       * term 4B BE, config 4B, MTU 2B BE          */
#define CL_CTR_BEACON_SZ            (2 + 4 + 4 + 2)
/* After a master has refused to admit us during a merge, how long to ignore
 * it (its keepalives and beacons) instead of trying again, in seconds.  The
 * refusal is about configuration, which does not change without a restart;
 * the beacon re-checks it every time it is heard anyway. */
#define CL_CTR_MERGE_REFUSE_SECS    60

/* Number of consecutive bootstrap-decrypt failures before a JOIN_REJECT is sent */
#define CL_CTR_JOIN_FAIL_LIMIT      3
#define CL_CTR_JOIN_FAIL_TABLE_SZ   8   /* max simultaneous rejected IPs tracked by master */

#define CL_CTR_MAX_IP_LEN        15   /* "255.255.255.255" without NUL            */
#define CL_CTR_PUBKEY_SZ         32   /* X25519 public key                        */
#define CL_CTR_MASTER_SALT_SZ    32   /* random salt generated by each new master */
/* MEMBER_LIST entry: IP (16B null-padded) + is_master (1B) = 17B.
 * Pubkeys are NOT carried here - nodes learn them from ALIVE packets,
 * keeping MEMBER_LIST small enough to avoid excessive IP fragmentation. */
#define CL_CTR_IP_ENTRY_SZ       17
#define CL_CTR_LIST_COUNT_SZ      2   /* MEMBER_LIST count field: uint16_t BE     */
#define CL_CTR_NODE_ID_SZ         2   /* uint16_t node_id, big-endian             */
#define CL_CTR_MAX_BIN_SOCKETS    8   /* max BIN listeners per node               */
#define CL_CTR_MAX_BIN_SOCK_LEN  64   /* "bin:255.255.255.255:65535" = 26 chars   */
/* BIN info block: [bin_count 1B][sock1 NUL-term]...[sockN NUL-term]         */
#define CL_CTR_BIN_INFO_MAX_SZ   (1 + CL_CTR_MAX_BIN_SOCKETS * CL_CTR_MAX_BIN_SOCK_LEN)

/* AEAD encryption constants
 *   wire:      [magic 2B][cluster_id 2B BE][nonce 24B][ciphertext][tag 16B]
 *   plaintext: [type 1B][seq 4B][payload]
 * The cluster_id is cleartext (like the magic) so a node can drop packets that
 * belong to a different cluster sharing the same multicast group WITHOUT its
 * key - before decryption, so foreign traffic never counts as an auth failure. */
#define CL_CTR_NONCE_SZ          24   /* XChaCha20-Poly1305 nonce (192-bit)       */
#define CL_CTR_TAG_SZ            16   /* Poly1305 AEAD tag                        */
#define CL_CTR_SEQ_SZ             4   /* uint32_t monotonic sequence in plaintext  */
#define CL_CTR_CLUSTER_ID_SZ      2   /* cleartext uint16 cluster_id (BE) selector */
/* The cluster's founded identity (see cl_ctr_cid_*) - cleartext, so a foreign
 * cluster's traffic is refused before decryption, and part of the AAD, so it
 * cannot be re-stamped.  All zeros = the sender belongs to no cluster yet. */
#define CL_CTR_CID_SZ            16
#define CL_CTR_CID_OFF           (CL_CTR_MAGIC_SZ + CL_CTR_CLUSTER_ID_SZ)
#define CL_CTR_NONCE_OFF         (CL_CTR_CID_OFF + CL_CTR_CID_SZ)  /* nonce starts here */
#define CL_CTR_AAD_SZ            CL_CTR_NONCE_OFF  /* magic + cluster_id + cluster uuid */
#define CL_CTR_WIRE_HDR_SZ       (CL_CTR_NONCE_OFF + CL_CTR_NONCE_SZ) /* 44 */
/* Incarnation: this process's start time in microseconds (CLOCK_REALTIME),
 * stamped into every packet.  The replay window is keyed on (sender,
 * incarnation): a higher incarnation means the sender restarted and its
 * counters began again, so its window is reset; a lower one is a packet from
 * a previous life and is refused.  Before this, a restarted node's fresh low
 * sequence numbers were "older than the replay window" to every peer until
 * someone reset that window for them - which only a MEMBER_LIST did, and
 * resetting on every MEMBER_LIST re-admitted one replayed packet per peer per
 * list. */
#define CL_CTR_INC_SZ             8

/* Founded cluster identity.  cluster_id is a number an operator configures, and
 * two deployments that share a multicast group, a password and a cluster_id
 * were indistinguishable: their masters met, ranked each other and merged the
 * two into one - a lab copied from production on the same VLAN would join
 * production and could take its sharing tags.  Now the node that FOUNDS a
 * cluster mints a 16-byte id (a UUID v7: its founding time, then random),
 * every member adopts it from its KEY_GRANT, every packet carries it, and a
 * node holding an established id refuses packets carrying any other.
 *
 *   NONE         not in a cluster yet: sends zeros, accepts any id
 *   PROVISIONAL  minted on founding, or adopted on joining, less than
 *                CL_CTR_CID_GRACE_SECS ago.  A simultaneous cold start can
 *                have two founders before either hears the other, so for a
 *                while a node still hears other ids and can be merged into
 *                one, adopting its id from that master's KEY_GRANT.
 *   ESTABLISHED  held for the grace period; never changes again in this
 *                process
 *   PINNED       configured with uuid= in the cluster string: established
 *                from the start, and the same on every restart
 *
 * Nothing persists: a whole-cluster restart founds a new id, which is
 * harmless, and a rolling restart adopts the running cluster's id.  A JOIN_REQ
 * always carries zeros, so a node merging into another cluster's master is
 * admitted on its key, not refused on its old id.  A node that must found
 * while it has heard an authenticated packet from an existing cluster founds
 * into THAT id rather than minting one its members would refuse. */
#define CL_CTR_CID_NONE           0
#define CL_CTR_CID_PROVISIONAL    1
#define CL_CTR_CID_ESTABLISHED    2
#define CL_CTR_CID_PINNED         3
#define CL_CTR_CID_GRACE_SECS    30
#define CL_CTR_PLAIN_HDR_SZ      (1 + CL_CTR_SEQ_SZ + CL_CTR_INC_SZ) /* type + seq + incarnation = 13 */

/* Bootstrap-key hardening: the join/admission key (also the Noise PSK) is
 * derived from the shared password with Argon2id (memory-hard) instead of a
 * single SHA-256, so a password captured from a JOIN_REQ cannot be brute-forced
 * cheaply offline.  Derived ONCE in mod_init (main process, before fork), so the
 * ~64 MiB working set is a transient startup cost; workers inherit the 32-byte
 * key.  Fixed parameters so every node derives the same key.                   */
#define CL_CTR_ARGON2_OPSLIMIT     3UL
#define CL_CTR_ARGON2_MEMLIMIT     (64UL * 1024 * 1024)
/* Minimum estimated password entropy (bits) before a startup warning fires.  */
#define CL_CTR_MIN_PASSWORD_BITS  80
#define CL_CTR_DEFAULT_PASSWORD  "3eCrEt*5629"   /* insecure placeholder; warn if used */

/* Master keepalive: master sends CL_CTR_PKT_MASTER_ALIVE every CL_CTR_MASTER_KA_INTERVAL
 * seconds.  Peers declare master dead after CL_CTR_MASTER_KA_MISSED missed packets. */
#define CL_CTR_MASTER_KA_INTERVAL   1   /* seconds between MASTER_ALIVE sends       */
#define CL_CTR_MASTER_KA_MISSED     3   /* missed keepalives before re-election     */
#define CL_CTR_MASTER_KA_TIMEOUT    (CL_CTR_MASTER_KA_INTERVAL * CL_CTR_MASTER_KA_MISSED)

/* Split-brain merge: a master emits a CL_CTR_PKT_MASTER_BEACON (bootstrap key) once
 * every CL_CTR_MASTER_BEACON_EVERY MASTER_ALIVE ticks.  This is the only traffic two
 * masters with divergent session keys can both read, so it bounds split-brain
 * convergence to ~CL_CTR_MASTER_BEACON_EVERY seconds while keeping bootstrap-key use
 * (and thus exposure) rare compared with the 1 s session keepalive.            */
#define CL_CTR_MASTER_BEACON_EVERY  5   /* MASTER_ALIVE ticks between beacons (~5 s) */

/* Split-brain PREVENTION at join time.  When several nodes cold-start together
 * they all exchange (bootstrap-decryptable) JOIN_REQs, so each learns the other
 * starters.  At the join deadline a node that has seen a higher-IP starter does
 * NOT self-promote; it defers (re-sending JOIN_REQ) so the highest-IP starter
 * becomes the single master and everyone joins it - no divergent keys ever form.
 * Bounded so a higher-IP node that heard-then-died cannot stall us forever.    */
#define CL_CTR_JOIN_DEFER_SECS      1   /* seconds per deferral round               */
#define CL_CTR_JOIN_DEFER_MAX       4   /* consecutive deferrals for a *silent*      */
                                    /* higher-IP peer before we promote anyway  */
#define CL_CTR_JOIN_DEFER_HARDMAX  20   /* absolute cap on deferrals incl. resets - */
                                    /* a peer stuck joining can't stall forever */
#define CL_CTR_JOIN_REQ_MIN_US 500000   /* min microseconds between JOIN_REQ sends   */

/*
 * Reliable delivery (ACK + bounded retransmit) for the strictly 1:1 packets of
 * the join handshake - KEY_GRANT today, the joiner's NODE_ASSIGN burst next.
 * The receiver ACKs each one (CL_CTR_PKT_ACK, echoing the packet's seq); the
 * sender retransmits the cached bytes until ACKed or the budget runs out.
 *
 * Multicast/group packets are deliberately NOT ACKed - ACKing from every member
 * is ACK implosion; their loss is healed by the periodic membership digest.
 *
 * The budget is pinned to the join timers so master-side ARQ nests inside one
 * JOIN_REQ retry cycle: CL_CTR_RETX_MAX_RETRIES x CL_CTR_RETX_INTERVAL_US of
 * retransmit (750 ms), then give up and let the joiner's own JOIN_REQ retry
 * (~1 s) restart the handshake with fresh packets.  ACKs are ONLY retransmit
 * accounting - a never-ACKed packet is dropped, never gating a join or any
 * cluster state, so a lost ACK or a dead joiner can never stall anything.
 */
#define CL_CTR_RETX_INTERVAL_US  (CL_CTR_JOIN_REQ_MIN_US / 2)  /* 250 ms          */
#define CL_CTR_RETX_MAX_RETRIES  3                             /* then give up     */
#define CL_CTR_RETX_QUEUE_SZ     128  /* max outstanding unacked 1:1 packets      */
/* The cached packet is either a control-plane handshake packet, whose largest
 * is NODE_ASSIGN, or a consumer message, whose largest is set by the MTU at
 * mod_init.  So the bound is a RUNTIME value (cl_ctr_retx_pkt_max), not a
 * constant: a fixed cache would either be sized for NODE_ASSIGN (~580 B, which
 * silently excluded any reliable consumer send above ~540 B) or for the
 * compile-time CLCTR_MAX_PAYLOAD (1300), which on a jumbo-frame link would cap
 * repair at a seventh of what the link and cc_max_payload happily carry. Same
 * trap the transmit buffers had before they were sized from cc_max_payload.
 *
 * Each entry's buffer is allocated for the packet actually being held and
 * freed when the entry is released, so the cost tracks outstanding reliable
 * messages rather than reserving queue x MTU up front - which at a 9000 MTU
 * would be 1.1 MB per cluster sitting idle, and far more on a link that
 * reports more. */
#if (CL_CTR_RETX_MAX_RETRIES * CL_CTR_RETX_INTERVAL_US) >= (CL_CTR_JOIN_DEFER_SECS * 1000000)
#error "retransmit budget must stay shorter than the JOIN_REQ retry interval"
#endif

/*
 * Membership digest, carried in every MASTER_ALIVE so a member can notice it is
 * out of sync and pull a resend.  A peer's node_id/BIN mapping travels only in
 * NODE_ASSIGN, which is multicast (best-effort) - a member that dropped one
 * knows the peer exists (from its ALIVE) but not its node_id, so its clusterer
 * BIN mesh to that peer is incomplete with no other repair.  The digest closes
 * that: [member_count 2B BE][set_hash 8B BE] over the active peers; a mismatch
 * triggers a rate-limited RESYNC, to which the master re-broadcasts the full
 * NODE_ASSIGN set + MEMBER_LIST.  Multicast/group packets stay unacked - this
 * is their anti-entropy repair, the counterpart to the 1:1 ACK path.
 */
#define CL_CTR_DIGEST_SZ      (2 + 8)
#define CL_CTR_RESYNC_MIN_US  1000000  /* member: min between RESYNCs; master:      */
                                       /* min between full-state re-broadcasts (1 s) */
/*
 * Liveness bitmap relayed by the master in every MASTER_ALIVE: one bit per
 * node_id.  A settled non-master unicasts its ALIVE to the master and no longer
 * hears peers' ALIVEs directly, so the master reports which node_ids it has seen
 * within the election window and non-masters refresh those peers' last_seen from
 * it - turning the old all-to-all O(N^2) liveness gossip into O(N).  Built from
 * the ELECTION-window cutoff (not the purge window) so a departed node drops out
 * of the bitmap on the same schedule it drops out of an election.  Sized to
 * cover node_id 1..CL_CTR_MAX_PEERS.
 */
#define CL_CTR_ALIVE_BITMAP_SZ  ((CL_CTR_MAX_PEERS / 8) + 1)
/* Mastership term (uint32 BE), carried after the bitmap in MASTER_ALIVE and
 * after the member count in MASTER_BEACON - see cl_ctr_master_outranks(). */
#define CL_CTR_TERM_SZ          4

/* Per-source-IP rate limiter: checked before decryption to shed floods cheaply.
 * Tracks up to CL_CTR_RATE_TBL_SZ source IPs with a 1-second sliding window. */
#define CL_CTR_RATE_TBL_SZ  256    /* one slot per peer; matches max cluster size */
#define CL_CTR_RATE_LIMIT    20    /* max packets per second per source IP        */
/* Consumer data is bulk by nature - one pull is a packet each way - so it
 * gets a far larger allowance than the handful of control packets a peer
 * sends per second.  Separate counters, so neither can starve the other:
 * a flood of consumer traffic can never crowd out JOIN/ALIVE, and a busy
 * consumer is not throttled at the control plane's rate. */
#define CL_CTR_CONSUMER_RATE_DEFAULT 1000
/* Reliable consumer delivery: how many times an unacknowledged message is
 * sent again, and how long to wait between attempts.  Deliberately modest -
 * a consumer that needs more than this wants a different design, not a
 * longer queue.  Both are per-cluster overridable. */
#define CL_CTR_CONSUMER_RETRIES_DEFAULT   2
#define CL_CTR_CONSUMER_RETRY_MS_DEFAULT 40

typedef struct {
    uint32_t ip;           /* network byte order; 0 = empty slot */
    time_t   window_start;
    int      count;
    /* consumer traffic is counted apart from control traffic, against its
     * own budget, so neither class can exhaust the other's allowance */
    int      consumer_count;
} cl_ctr_rate_entry_t;

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
 * preventing new nodes from joining.
 *
 * WHY THAT FRAGMENTATION IS ALLOWED TO HAPPEN, precisely - an earlier version
 * of this comment said "the DF bit is not set", which is false and was never
 * measured.  The socket sets no IP_MTU_DISCOVER at all, so Linux's default
 * applies (IP_PMTUDISC_WANT, per-route), and that default DOES set DF - on
 * unicast AND on multicast alike, verified on the wire.  What actually carries
 * MEMBER_LIST across a 1500-byte link is that 4395 bytes EXCEEDS THE LOCAL MTU,
 * and a datagram the kernel must fragment locally cannot also be doing path-MTU
 * discovery, so those fragments leave with DF clear.  The old wording happened
 * to describe the right outcome for the wrong reason, and the reason matters:
 * a datagram that FITS the local MTU goes out with DF SET, so if it later meets
 * a smaller-MTU hop it is dropped with an ICMP "fragmentation needed" that is
 * routinely filtered - it is not fragmented and does not arrive.
 *
 * That is left exactly as it is, deliberately.  Clearing DF would let a jumbo
 * node reach a peer across a narrow ROUTED hop, but this module's contract is
 * about the interface it runs on, not about how the operator has chosen to
 * carry multicast between segments.  Enforcing a uniform MTU across the cluster
 * is what makes the local bound meaningful; getting the packets between
 * segments is the network's job. */
#define CL_CTR_SMALL_PKT_SZ      (CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_MAX_IP_LEN + 1 + CL_CTR_TAG_SZ)
/* Consistency-critical settings advertised in ALIVE so peers can detect
 * accidental per-node config drift for the same cluster:
 * manage_shtags(1B) + master_stickiness(1B) + query_time(2B BE). */
#define CL_CTR_CONFIG_SZ          4
/* The node's cluster-plane MTU, advertised in JOIN_REQ and ALIVE as 2 bytes BE.
 *
 * Deliberately NOT folded into CL_CTR_CONFIG_SZ above.  That block is governed
 * by the on_config_mismatch modparam, and two of its three modes would be wrong
 * here: "warn" would quietly demote MTU enforcement to a log line, and "adopt"
 * is meaningless - a node cannot adopt a peer's MTU, the kernel owns it.  There
 * is deliberately NO modparam for the MTU at all, because a configured value is
 * a second source of truth that can disagree with the interface: the config
 * says 1500, the link says 9000, and the node refuses to start while being
 * perfectly consistent with its own segment.  So the MTU gets its own field and
 * its own unconditional check.
 *
 * 0 means "not advertised" - a peer built before this field existed.  Such a
 * peer is admitted with a warning rather than rejected, because rejecting it
 * would make a rolling upgrade impossible: every not-yet-upgraded node would be
 * refused by the first upgraded master and would self-terminate. */
#define CL_CTR_MTU_SZ             2
/* Consecutive polls that must disagree with the MTU we joined on before this
 * node accepts that its own link really changed.  A single reading is not
 * enough: bond failover, a driver reset or a VLAN parent bounce can show a
 * transient value, and acting on the first sample would kill a healthy node
 * over a blip.  At query_time=5 the default is a ~15 s confirmation. */
#define CL_CTR_MTU_DRIFT_STRIKES  3
/* Distinct peers a master may refuse on MTU before it says out loud that IT is
 * the likely misconfiguration.  See cl_ctr_mtu_note_reject(). */
#define CL_CTR_MTU_SUSPECT_PEERS  2
/* Same idea for the config gate: a master refusing this many DIFFERENT peers on
 * settings while holding no members is probably the misconfigured one, because
 * election ignores the settings just as it ignores the MTU.  See
 * cl_ctr_cfg_note_reject(). */
#define CL_CTR_CFG_SUSPECT_PEERS  2
/* Consecutive unreadable MTU polls between complaints.  The first failure is
 * always reported; after that this keeps a blind poll from being silent
 * without letting it flood. At query_time=5 this is about once a minute. */
#define CL_CTR_MTU_READ_FAIL_LOUD 12
/* Noise handshake message sizes (NNpsk0, X25519, ChaChaPoly, SHA-256):
 *   msg 1 = e(32) + tag over empty payload(16)                 = 48
 *   msg 2 = e(32) + AEAD(master_salt 32 + tag 16)              = 80             */
#define CL_CTR_NOISE_MSG1_SZ     (32 + CL_CTR_TAG_SZ)
#define CL_CTR_NOISE_MSG2_SZ     (32 + CL_CTR_MASTER_SALT_SZ + CL_CTR_TAG_SZ)
/* JOIN_REQ: [ip NUL][bin_count 1B][sockets...][noise_msg1 48B][config 4B] */
#define CL_CTR_JOIN_PKT_MAX_SZ   (CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_MAX_IP_LEN + 1 \
                              + CL_CTR_BIN_INFO_MAX_SZ + CL_CTR_NOISE_MSG1_SZ \
                              + CL_CTR_CONFIG_SZ + CL_CTR_MTU_SZ + CL_CTR_TAG_SZ)
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
/* MEMBER_LIST stamp, after the entries: [master term 4B BE][list seq 4B BE].
 * A receiver applies a list only if it is newer than the last one it applied
 * from that mastership - see cl_ctr_handle_member_list(). */
#define CL_CTR_LIST_STAMP_SZ      8
#define CL_CTR_LIST_PKT_MAX_SZ   (CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_LIST_COUNT_SZ \
                              + CL_CTR_NODE_ID_SZ /* forced-shtag node_id */ \
                              + CL_CTR_MAX_PEERS * CL_CTR_IP_ENTRY_SZ \
                              + CL_CTR_LIST_STAMP_SZ + CL_CTR_TAG_SZ)
/* Large enough to receive a fully reassembled UDP datagram (max 65507 bytes) */
#define CL_CTR_RECV_BUF_SZ       65536

/* =========================================================================
 * Peer-table constants
 * ========================================================================= */

#define CL_CTR_MAX_PEERS         256

/*
 * CL_CTR_ELECT_FACTOR - election window = query_time x CL_CTR_ELECT_FACTOR.
 * QUANTIZED: all nodes evaluate the same cutoff simultaneously.
 *
 * CL_CTR_PURGE_FACTOR - memory-cleanup window = query_time x CL_CTR_PURGE_FACTOR.
 * Not quantized; only affects when entries are freed, not who is elected.
 */
#define CL_CTR_ELECT_FACTOR       3
#define CL_CTR_PURGE_FACTOR       6

/* =========================================================================
 * Node-join state machine
 * ========================================================================= */

typedef enum {
    CL_CTR_NODE_NEW    = 0,   /* sent JOIN_REQ, awaiting MEMBER_LIST or timeout */
    CL_CTR_NODE_ACTIVE = 1    /* fully participating, sends ALIVE               */
} cl_ctr_node_state_t;

/* Planned: node maintenance mode (see the module documentation roadmap).
 *
 * A CL_CTR_NODE_MAINTENANCE state would let a node be drained without leaving the
 * cluster: never elected master, excluded from cl_ctr_elect_master (advertised in
 * the ALIVE payload so peers drop it from the election window without waiting
 * for a MEMBER_LIST refresh), and never the active sharing-tag holder even
 * with manage_shtags=1.  It is local policy, so it would live in cl_ctr_cluster_t
 * (not the shared peer table) and survive MEMBER_LIST resets, toggled by a
 * local MI command.
 *
 * It would build on what is already here: the sharing-tag override
 * (cl_ctr_shtag_force / cl_ctr_shtag_auto) would auto-clear when the forced
 * node enters maintenance, and cl_ctr_list_members / cl_ctr_list_config would
 * gain a per-node maintenance indicator alongside the existing shtag_mode.
 */

/* =========================================================================
 * Cluster table
 * ========================================================================= */

#define CL_CTR_MAX_CLUSTERS  16  /* max cluster= entries */
/* Minimum seconds between the shared-port misdelivery warnings; the drop
 * they report can otherwise recur per packet. */
#define CL_CTR_FWD_WARN_IVL  30

/* Forward-declared so cl_ctr_cluster_t can embed a pointer */
typedef struct cl_ctr_peers_ cl_ctr_peers_t;

/* Noise handshake state (definitions with the Noise core further below).
 * HASHLEN = 32 (SHA-256).  cl_ctr_cluster_t embeds a cl_ctr_symstate_t for the
 * initiator half of the join handshake. */
#define CL_CTR_NOISE_HASHLEN 32
typedef struct { unsigned char k[32]; uint64_t n; int has_key; } cl_ctr_cipherstate_t;
typedef struct {
    unsigned char    ck[CL_CTR_NOISE_HASHLEN];
    unsigned char    h[CL_CTR_NOISE_HASHLEN];
    cl_ctr_cipherstate_t cs;
} cl_ctr_symstate_t;

/* This node's own role in a cluster.  Tracked across elections so
 * cl_ctr_elect_master() can log an explicit transition (member->backup,
 * backup->master, master->member, ...) whenever it changes. */
enum cl_ctr_role { CL_CTR_ROLE_MEMBER = 0, CL_CTR_ROLE_BACKUP, CL_CTR_ROLE_MASTER };

static inline const char *cl_ctr_role_name(int r)
{
    switch (r) {
    case CL_CTR_ROLE_MASTER: return "master";
    case CL_CTR_ROLE_BACKUP: return "backup";
    default:             return "member";
    }
}

/*
 * One outstanding 1:1 handshake packet awaiting an ACK.  The full sealed bytes
 * are cached so a retransmit is a single sendto() with no re-encryption: the
 * same seq/nonce is resent, and the receiver's replay window sorts out which
 * is which - a peer that already got it (and ACKed) finds the bit set and only
 * re-ACKs, while one that lost it finds the bit clear and accepts it, however
 * many of its peer's later messages arrived in between.  Worker-local (only
 * the controller worker touches the queue), so no lock.
 */
typedef struct {
    int                     used;
    uint32_t                seq;          /* packet seq, echoed by the ACK        */
    unsigned char           type;         /* packet type: matched against the ACK  */
    int                     retries_left;
    utime_t                 next_due_us;   /* get_uticks() deadline for next send  */
    /* Gap to the NEXT send after this one.  Per entry, not a constant, because
     * the control plane and the consumer plane share this queue and want
     * different cadences - the handshake's is pinned to the JOIN_REQ retry,
     * the consumer's is the per-cluster consumer_retry_ms.  Holding it here is
     * what lets one sweep serve both without either inheriting the other's
     * timing. */
    utime_t                 retry_ivl_us;
    struct sockaddr_storage dest;         /* unicast destination                  */
    socklen_t               destlen;
    int                     pkt_len;      /* sealed length                        */
    /* A broadcast that asked to be acknowledged is one entry, not one per
     * member: the message goes out once as a multicast - which is the whole
     * point of having a multicast - and only the nodes that fail to answer
     * are repaired individually.  Sending N unicasts up front would be about
     * twice the packets for the same delivery, and at two hundred and fifty
     * nodes that is the difference between a message and an event.
     *
     * Who still owes an ACK is a bitmap by node id.  The addresses to repair
     * to are not stored: they are looked up from current membership when the
     * repair runs, so a node that left in the meantime is simply not chased,
     * and one that joined is not expected to answer for something sent
     * before it arrived. */
    int                     is_bcast;
    uint8_t                 retries_cfg;  /* the budget this started with,
                                           * so a report can say how much of
                                           * it was actually spent          */
    uint16_t                expect_n;     /* members at send time            */
    uint16_t                acked_n;
    unsigned char           acked_map[(CL_CTR_MAX_PEERS + 7) / 8];
    unsigned char          *pkt;         /* cached sealed bytes, pkg, owned by
                                          * the entry; NULL when released    */
} cl_ctr_retx_entry_t;

/**
 * cl_ctr_cluster_t - per-cluster runtime state.
 * One instance per "cluster" modparam; one worker process per instance.
 */
typedef struct cl_ctr_cluster_ {
    int            cluster_id;
    char           multicast_address[INET_ADDRSTRLEN];
    int            multicast_port;
    struct sockaddr_in mcast_dest;   /* resolved once in cl_ctr_setup_socket */
    char           password[1025];
    unsigned char  key[32];         /* bootstrap key = SHA256(password); JOIN only */
    unsigned char  session_key[32]; /* group key = HKDF(password, master_salt)     */
    int            manage_shtags; /* per-cluster override; defaults to global manage_shtags */
    /* Packets refused at the magic gate for carrying another wire version,
     * and when that was last reported (worker-local). */
    unsigned long  wire_refused_pkts;
    time_t         wire_warned_at;
    /* A master we will not merge into (it refused our admission), and until
     * when; plus when we last warned about a master whose settings differ. */
    /* uuid= from the cluster string (pinned identity), parsed at startup */
    unsigned char  cid_pin[CL_CTR_CID_SZ];
    int            cid_pinned;
    /* an id heard on an authenticated packet while we had none (worker) */
    unsigned char  heard_cid[CL_CTR_CID_SZ];
    int            heard_cid_set;
    time_t         foreign_warned_at;
    char           merge_refused_ip[INET_ADDRSTRLEN];
    time_t         merge_refused_until;
    time_t         merge_warned_at;
    /* Consumer-plane policy, per cluster: a fleet may run one cluster over a
     * quiet management VLAN and another across a link where retries matter,
     * and one global number cannot be right for both.  -1 means "not set
     * here", resolved to the global default in mod_init. */
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
    int            identity_registered; /* 1 once update_identity called */
    int            shtag_bootstrapped;  /* -1 = eligible, 1 = done       */
    /* Long-lived X25519 keypair - generated in cl_ctr_worker after fork, never
     * leaves the process.  Advertised in ALIVE and used by crypto_box KEY_HANDOFF
     * (NOT the Noise join handshake, which uses a fresh ephemeral per attempt).  */
    unsigned char  my_privkey[CL_CTR_PUBKEY_SZ];
    unsigned char  my_pubkey[CL_CTR_PUBKEY_SZ];
    /* Noise (initiator) handshake state carried between our JOIN_REQ (msg 1) and
     * the master's KEY_GRANT (msg 2): the SymmetricState and the fresh ephemeral
     * private key.  A new JOIN_REQ overwrites both, so a KEY_GRANT for a
     * superseded attempt simply fails to decrypt and is dropped.  Worker-local. */
    cl_ctr_symstate_t  noise_hs;
    unsigned char  noise_e_priv[32];
    int            noise_hs_valid;   /* 1 after a JOIN_REQ, until KEY_GRANT/reset */
    /* Set while a re-key JOIN_REQ is in flight; cleared on KEY_GRANT success
     * or master transition to prevent nonce stomping under packet flood.    */
    int            join_pending;
    /* 1 once a valid session_key has been established - either generated at
     * cluster bootstrap (cl_ctr_on_became_master) or adopted from the current master
     * master via KEY_GRANT / KEY_HANDOFF.  A node must NOT act as master
     * (broadcast MASTER_ALIVE) while this is 0, or it would encrypt with an
     * underived key that no member can decrypt.                             */
    int            have_session_key;
    /* Reliable-delivery queue for 1:1 handshake packets (worker-local, no lock).
     * retx_tfd sweeps it every CL_CTR_RETX_INTERVAL_US while retx_count > 0.    */
    int                 retx_tfd;
    int                 retx_count;
    cl_ctr_retx_entry_t retx_q[CL_CTR_RETX_QUEUE_SZ];
    /* Membership-digest resync throttles (worker-local): a member sends at most
     * one RESYNC, and a master re-broadcasts full state at most once, per
     * CL_CTR_RESYNC_MIN_US. */
    utime_t             last_resync_us;
    utime_t             last_full_state_us;
    /* A full-state announcement that cl_ctr_announce_full_state() had to
     * coalesce away, still owed to the cluster.  Only the master sets it; the
     * keepalive tick flushes it once the window has passed.  A join must never
     * be merely dropped the way a RESYNC can be: RESYNC is a repair request
     * that its sender will repeat, while a join is a one-shot event whose
     * whole point is telling the OTHER members that this node restarted. */
    int                 full_state_pending;
    char                full_state_why[64];
    /* Master-side per-IP table tracking bootstrap-decrypt failures.
     * Worker-local (no shm, no lock needed).  After CL_CTR_JOIN_FAIL_LIMIT
     * failures from the same source IP the master sends JOIN_REJECT.       */
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
    /* Count of packets from OTHER peers during CL_CTR_NODE_NEW that we could not
     * decrypt (any magic).  Non-zero means a cluster (or rogue) whose key we do
     * not share exists on the group - evidence we may have the wrong password.
     * This is only *evidence*: cl_ctr_on_join_tfd never self-terminates on it
     * immediately (that would let start-up noise or a flood kill a healthy
     * node); it defers and re-joins, and a KEY_GRANT resets this counter.  Only
     * a correct-password joiner ever receives a KEY_GRANT, so persistence of
     * this counter across the whole defer budget is what marks a real
     * wrong-password / foreign-cluster condition.                             */
    int              auth_fail_pkts;
    /* Number of join rounds we have already deferred because we still could not
     * authenticate.  We only give up (shut down) after CL_CTR_JOIN_DEFER_MAX such
     * rounds, so a KEY_GRANT that is merely slow, or a brief burst of start-up
     * noise or crafted garbage, never self-terminates a correctly-configured
     * node.  Reset on successful authentication.                              */
    int              auth_defer_count;
    /* master_salt lives in cl->peers->master_salt (shm) so mod_destroy can
     * read it.  session_key is the worker-local derived key cache. */
    /* Per-source-IP rate limiter table - pkg_malloc'd in cl_ctr_worker after fork */
    cl_ctr_rate_entry_t  *rate_tbl;
    /* Last shtag decision this worker applied, so cl_ctr_apply_shtags_decision()
     * logs the *reason* only when the decision (or its cause) actually
     * changes - not on every idempotent re-apply.  Worker-local.
     *   shtag_last_active: -1 unknown, 0 backup, 1 active.
     *   shtag_last_forced: the forced node_id in effect at that time.        */
    int              shtag_last_active;
    uint16_t         shtag_last_forced;
    /* Counts MASTER_ALIVE ticks so a beacon is emitted every
     * CL_CTR_MASTER_BEACON_EVERY of them.  Worker-local (master path only).       */
    unsigned int     beacon_tick;
    /* How many times we have deferred self-promotion at the join deadline
     * because a higher-IP node was also still joining (split-brain
     * prevention).  Reset to 0 whenever a fresh JOIN_REQ from a higher-IP peer
     * arrives (it is demonstrably still alive and joining, so we keep waiting
     * for it rather than self-promoting into a divergent-key split brain).
     * Worker-local; reset once we leave the NEW state.                        */
    int              join_defer_count;
    /* Total deferrals across resets - an absolute cap (CL_CTR_JOIN_DEFER_HARDMAX)
     * so a peer that keeps sending JOIN_REQ yet never becomes master cannot
     * defer us forever.  Worker-local; reset once we leave the NEW state.     */
    int              join_defer_total;
    /* A master answered our JOIN_REQ with a KEY_GRANT while we were still
     * joining (its address, empty if none), and how many deadline rounds we
     * have waited since for the NODE_ASSIGN that follows it.  A node holding
     * a master's KEY_GRANT has proof the cluster exists, so at the join
     * deadline it waits for its id instead of founding a cluster of its own
     * under an id it picked itself.  Worker-local; reset once we leave NEW. */
    char             granted_by[CL_CTR_MAX_IP_LEN + 1];
    int              grant_wait_count;
    /* Distinct peers we have refused on MTU while acting as master, and whether
     * we have already said we are probably the one at fault.  Worker-local and
     * diagnostic only - see cl_ctr_mtu_note_reject().                         */
    uint32_t         mtu_reject_ips[CL_CTR_MTU_SUSPECT_PEERS * 2];
    int              mtu_reject_n;
    int              mtu_suspect_said;
    /* Same, for peers we have refused on config settings.  See
     * cl_ctr_cfg_note_reject() - the config analogue of the MTU one above. */
    uint32_t         cfg_reject_ips[CL_CTR_CFG_SUSPECT_PEERS * 2];
    int              cfg_reject_n;
    int              cfg_suspect_said;
    /* utime (us since start) of the last JOIN_REQ we transmitted, for a
     * minimum-interval throttle so a key-mismatch/split-brain burst cannot
     * flood the group with JOIN_REQs.  0 = never sent.  Worker-local.         */
    utime_t          last_join_req_utime;
    /* 1 while our MASTER_ALIVE keepalive timer is armed (i.e. we are acting as
     * master and broadcasting).  Set by cl_ctr_arm_master_timers().  Lets
     * cl_ctr_elect_master() enforce the invariant "keepalive armed <=> I am the
     * elected master": an election that demotes us (clears is_master) without
     * going through a yield/member-list path must still stop the keepalive,
     * otherwise a demoted node keeps broadcasting MASTER_ALIVE and lower-IP
     * peers oscillate between two masters.  Worker-local.                     */
    int              master_ka_armed;
    /* This node's last-known role in the cluster (enum cl_ctr_role).  Compared in
     * cl_ctr_elect_master() to emit a one-line transition log on every change.
     * Zero-initialised to CL_CTR_ROLE_MEMBER, which matches a not-yet-joined node.
     * Worker-local. */
    int              my_role;
} cl_ctr_cluster_t;

/* Policy when a node's consistency-critical settings (manage_shtags/
 * master_stickiness/query_time) differ from the running cluster (a master is
 * alive).  Set via the on_config_mismatch modparam string:
 *   "warn"   - admit/keep the node but log a CONFIG MISMATCH warning;
 *   "reject" - the master refuses the join (JOIN_REJECT) and the node shuts
 *              down with a clear message (default);
 *   "adopt"  - the node adopts the master's (authoritative) settings at
 *              runtime and continues. */
#define CL_CTR_CFGMISMATCH_WARN    0
#define CL_CTR_CFGMISMATCH_REJECT  1
#define CL_CTR_CFGMISMATCH_ADOPT   2
/* JOIN_REJECT reason codes (1 byte after the target IP in the payload). */
#define CL_CTR_REJECT_GENERIC      0   /* wrong password / unauthorized / table full */
#define CL_CTR_REJECT_CONFIG       1   /* different cluster settings (reject policy)  */
#define CL_CTR_REJECT_MTU          2   /* different cluster-plane MTU (never optional) */

/* The MTU travels the wire as an unsigned 16-bit value.  Loopback reports
 * 65536, one past what that holds, so clamp - two nodes both on loopback still
 * agree, and no real cluster link is anywhere near it. */
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

/* A send marshalled to the cluster worker over IPC.  Routing every send
 * through the worker keeps the anti-replay sequence space single-writer
 * (cl_ctr_check_and_update_seq is strictly monotonic per sender IP, so
 * concurrent senders in different processes would trip it) and reuses
 * the worker's socket and session key, which are worker-local state. */
struct cl_ctr_consumer_job {
    cl_ctr_cluster_t *cl;
    uint16_t          dst_node_id;   /* 0 = multicast */
    int               flags;
    int               chan_len;
    int               payload_len;
    char              chan[CLCTR_MAX_CHAN_LEN];
    unsigned char     payload[];
};

/* ---- the script's own channel (S2c-API, second tier) -------------------
 *
 * The messaging API's other half: a channel the module registers for
 * itself, so a script can exchange messages with its peers without a
 * module in between.  It mirrors clusterer's generic messaging exactly -
 * same three functions, same two events, same parameters - so a script
 * moves between them by renaming, and the reason to move is what the
 * transport underneath does: one multicast packet rather than a send per
 * peer, over an encrypted channel rather than a plaintext one.
 *
 * Wire: [u8 kind][u8 tag_len][tag][message].
 */
#define CL_CTR_SCRIPT_REQ  1
#define CL_CTR_SCRIPT_RPL  2

/* =========================================================================
 * Peer table (shared memory)
 * ========================================================================= */

/*
 * Anti-replay window - a high-water mark PLUS a bitmap of what has already
 * been accepted at or below it, which is the standard construction (IPsec
 * RFC 4303 A.2, DTLS RFC 6347 4.1.2.6).
 *
 * A bare high-water mark cannot tell "already delivered" from "delivered out
 * of order", so it has to reject both, and that breaks two things at once:
 *
 *   - a retransmit carries its ORIGINAL seq, so once any later message has
 *     been accepted the repair copy is discarded - the reliable-send defect;
 *   - ordinary reordering, which any multipath network produces, silently
 *     drops consumer payloads that were never duplicated at all.
 *
 * The bitmap separates the two.  A seq below the mark is accepted exactly
 * once: the first copy is delivered and its bit set, and every later copy of
 * that same seq finds the bit set and is a genuine duplicate.  Replay
 * protection is unchanged - no seq is ever accepted twice - while loss repair
 * and reordering now work.
 *
 * The bitmap is circular: the slot for seq s is s % CL_CTR_REPLAY_WIN_BITS,
 * so advancing the mark clears only the slots the window moved onto (one, in
 * the in-order case) instead of shifting 128 bytes per packet.
 *
 * SIZING.  The window has to span the longest interval over which a repair for
 * seq s can still arrive, expressed in messages from that peer on that plane:
 *
 *     window > peak per-peer send rate x retransmit horizon
 *
 * The consumer horizon is consumer_retries x consumer_retry_ms = 80 ms with
 * the defaults, so 1024 slots hold out to ~12,800 msg/s from a single peer -
 * two orders above anything this plane carries (the cross-node cache pull
 * channel measures ~0.3/s).  The control plane's horizon is longer, 3 x 250 ms,
 * but it sends a handful of packets a second.  mod_init logs the derived
 * ceiling because both horizon terms are admin-settable and a config that
 * narrows it should say so rather than wait to be discovered as loss.
 *
 * Cost is 128 bytes per peer per plane: 64 KB of shm for a full 256-peer table.
 *
 * WRAP.  The comparison is serial-number arithmetic - (int32_t)(seq - last) -
 * not plain unsigned, because the 32-bit counters do wrap inside one key
 * epoch and a plain comparison rejects everything after the wrap until the
 * next rotation.  That is fail-closed but silent, and the rotation it waits
 * for may never come: a fresh master_salt is generated only in
 * cl_ctr_on_became_master(), so a cluster with a stable master never rekeys
 * on its own.  Nor is the wrap far off - every ACK bumps my_seq, so the
 * control plane advances at the rate of the CONSUMER traffic it acknowledges,
 * and at the window's own 12,800 msg/s ceiling 2^32 is under four days.
 *
 * Serial arithmetic alone would trade that outage for something worse: a
 * packet captured 2^31 or more messages ago has a difference that reads back
 * as a large POSITIVE, so it would be accepted as fresh.  Hence the forward
 * jump is bounded as well - a step of CL_CTR_REPLAY_MAX_JUMP or more is
 * refused as implausible rather than believed.  Real gaps stay far below it
 * (it is 16.7M messages, ~22 minutes of one peer's output at that ceiling),
 * and a peer that somehow exceeds it is recovered by the window reset that
 * already runs when it re-joins or reappears in a MEMBER_LIST.
 *
 * What remains, and is inherent to a 32-bit counter: a packet held across a
 * FULL 2^32 cycle lands back inside the window and is accepted. That needs
 * 2^32 messages in one key epoch with the attacker holding the packet
 * throughout.
 */
#define CL_CTR_REPLAY_WIN_BITS   1024
#define CL_CTR_REPLAY_WIN_WORDS  (CL_CTR_REPLAY_WIN_BITS / 64)
/* Largest forward step believed to be a real gap rather than a wrapped-around
 * replay.  Must sit well above any credible burst of loss from one peer and
 * well below 2^31, where serial arithmetic stops being able to tell the two
 * apart. */
#define CL_CTR_REPLAY_MAX_JUMP   (1u << 24)

typedef struct {
    uint32_t last;                            /* highest seq accepted so far  */
    uint64_t win[CL_CTR_REPLAY_WIN_WORDS];    /* circular, slot = seq % BITS  */
} cl_ctr_replay_t;

#define CL_CTR_RP_WORD(s)  ((((uint32_t)(s)) % CL_CTR_REPLAY_WIN_BITS) / 64)
#define CL_CTR_RP_MASK(s)  (1ULL << ((((uint32_t)(s)) % CL_CTR_REPLAY_WIN_BITS) % 64))

/* Verdicts from cl_ctr_check_and_update_seq().  Three, not two: "seen this
 * exact packet before" and "too old to have an opinion about" call for
 * opposite handling on the reliable path - one must be re-ACKed, the other
 * must not be. */
#define CL_CTR_SEQ_OK     0   /* fresh: accept and deliver                    */
#define CL_CTR_SEQ_DUP  (-1)  /* inside the window, bit already set: drop     */
#define CL_CTR_SEQ_OLD  (-2)  /* below the window: drop, and we cannot know   */
                              /* whether we ever had it                       */
#define CL_CTR_SEQ_JUMP (-3)  /* implausibly far ahead: a wrapped-around      */
                              /* replay, or a peer we have lost far too much  */
                              /* of - refuse either way                       */
#define CL_CTR_SEQ_STALE (-4) /* from an EARLIER incarnation of the sender:   */
                              /* a replay from before it restarted - refuse   */

static inline void cl_ctr_replay_reset(cl_ctr_replay_t *r)
{
    r->last = 0;
    memset(r->win, 0, sizeof r->win);
}

/*
 * Accept @seq at most once.  Not thread-safe by design: the only caller is the
 * cluster's single worker reactor, same as the counter it replaces.
 */
static inline int cl_ctr_replay_check(cl_ctr_replay_t *r, uint32_t seq)
{
    int32_t  fwd = (int32_t)(seq - r->last);   /* serial-number difference */
    uint32_t d, s;

    if (fwd > 0) {                       /* forward: the common case          */
        d = (uint32_t)fwd;
        if (d >= CL_CTR_REPLAY_MAX_JUMP)
            return CL_CTR_SEQ_JUMP;
        if (d >= CL_CTR_REPLAY_WIN_BITS) {
            memset(r->win, 0, sizeof r->win);
        } else {
            /* Clear the slots the window has just moved onto.  These hold
             * bits for seqs a full window older, which must not be mistaken
             * for the fresh ones now mapping to the same slots. */
            for (s = r->last + 1; s != seq; s++)
                r->win[CL_CTR_RP_WORD(s)] &= ~CL_CTR_RP_MASK(s);
            r->win[CL_CTR_RP_WORD(seq)] &= ~CL_CTR_RP_MASK(seq);
        }
        r->last = seq;
        r->win[CL_CTR_RP_WORD(seq)] |= CL_CTR_RP_MASK(seq);
        return CL_CTR_SEQ_OK;
    }

    /* At or below the mark.  Unsigned subtraction gives the exact backward
     * distance even across a wrap, and avoids negating INT32_MIN.  Note
     * seq == last == 0 with an empty window is the untouched state and falls
     * out here as a legitimate first accept - it costs nothing to allow, and
     * every sender in fact starts at 1 (++my_seq). */
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
    uint8_t      bin_count;   /* number of BIN listeners reported          */
    char         bin_sockets[CL_CTR_MAX_BIN_SOCKETS][CL_CTR_MAX_BIN_SOCK_LEN];
    unsigned char pubkey[CL_CTR_PUBKEY_SZ];           /* long-lived X25519 pubkey (from ALIVE);
                                                     zero if unknown; used for KEY_HANDOFF */
    cl_ctr_replay_t replay;                        /* control-plane anti-replay */
    /* Consumer traffic is counted separately from the control plane.  They
     * share a session key and a socket but not a sequence space: a consumer
     * may send thousands of packets a second where the control plane sends a
     * handful, and one counter for both means a reordered consumer packet can
     * make a MASTER_ALIVE arriving behind it look like a replay - which is a
     * missed liveness beacon, not a dropped cache reply. */
    cl_ctr_replay_t replay_consumer;
    /* The sender incarnation both windows above belong to; 0 = not seen yet. */
    uint64_t      incarnation;
    /* Peer's advertised consistency-critical config (from ALIVE), used to warn
     * on accidental per-node config drift.  cfg_known=0 until first advertised;
     * cfg_warned deduplicates the mismatch warning. */
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

/* A node_id held for the member that last used it.  A node that leaves -
 * cleanly with GOODBYE, or by being purged - used to free its id at once, so
 * the next allocation handed it to whoever joined next, and the node came
 * back from a restart under a different id.  A changed id is not cosmetic:
 * clusterer removes and re-adds the node under the new one, and a sharing tag
 * forced onto the old id now names a different machine.  Measured in the
 * daemon that shares this design: one address went through ids 518, 846 and
 * 771 across three clean restarts. */
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
    /* my_seq: monotonic send counter; in shm so mod_destroy can use it for
     * GOODBYE without needing the worker's private state.  Reset to 0 on
     * every session key rotation so peers' replay windows reset cleanly. */
    uint32_t        my_seq;
    uint32_t        my_consumer_seq;   /* the consumer plane's own counter */
    /* Sharing-tag override: 0 = automatic (master-driven) allocation; nonzero =
     * an operator has forced this node_id to be the active shtag holder for the
     * cluster (cl_ctr_shtag_force MI), suspending automatic allocation until
     * cl_ctr_shtag_auto clears it.  Propagated to all nodes in the MEMBER_LIST.  */
    uint16_t        shtag_forced_node_id;
    /* Mastership terms (see cl_ctr_master_outranks()).  term_seen is the
     * highest term this node has heard from any master; my_term is the term
     * of our own current mastership (0 = not master); master_term and
     * master_count are what the master we follow last announced.  In shm so
     * cl_ctr_list_config can report them; written by the worker only. */
    uint32_t        term_seen;
    uint32_t        my_term;
    uint32_t        master_term;
    uint16_t        master_count;
    /* node_ids held for members that left (see cl_ctr_reserve_id_locked()).
     * Kept by EVERY node, since every node sees the GOODBYE or purge, so
     * whichever node is master next already has them. */
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
    /* MEMBER_LIST ordering: the sequence this node stamps on the lists it
     * sends as master, and the (term, seq) of the last list it applied. */
    uint32_t        list_seq;
    uint32_t        list_term_seen;
    uint32_t        list_seq_seen;
    /* worker_proc_no: OpenSIPS process index of this cluster's cl_ctr_worker,
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

#define CL_CTR_PV_WRAP(_fn, _field) \
static int _fn(struct sip_msg *msg, pv_param_t *param, pv_value_t *res) \
{ return cl_ctr_pv_get(msg, param, res, _field); }

#define cl_ctr_send_alive(sock, cl)    cl_ctr_send_pkt_with_ip((sock), CL_CTR_PKT_ALIVE, (cl), NULL, 0)
#define cl_ctr_send_alive_to(sock, cl, dest, dlen) \
        cl_ctr_send_pkt_with_ip((sock), CL_CTR_PKT_ALIVE, (cl), (dest), (dlen))
#define cl_ctr_send_join_req(sock, cl) cl_ctr_send_join_req_pkt((sock), (cl))

#define cl_ctr_send_member_list(sock, cl) cl_ctr_send_list_pkt((sock), CL_CTR_PKT_MEMBER_LIST, (cl), NULL, 0)


/* =========================================================================
 * Shared between the module's source files
 * ========================================================================= */

/* cl_ctr_liveness.c */
void cl_ctr_announce_full_state(cl_ctr_cluster_t *cl, const char *why);
void cl_ctr_handle_resync(const char *sender_ip, cl_ctr_cluster_t *cl);
void cl_ctr_handle_alive(const char *src_ip,
                            const unsigned char *pubkey, /* may be NULL */
                            int cfg_present, int peer_manage,
                            int peer_stick, int peer_qt,
                            int peer_mtu,
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
void cl_ctr_drain_tfd(int tfd);
void cl_ctr_arm_tfd(int tfd, time_t sec_value, time_t sec_interval);
void cl_ctr_worker(int rank);

/* cl_ctr_mi.c */
extern const mi_export_t mi_cmds[];

/* cl_ctr_script.c */
extern char *cl_ctr_script_buf;
extern int cl_ctr_script_buf_sz;
extern const pv_export_t cl_ctr_mod_vars[];
extern const cmd_export_t cl_ctr_cmds[];
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
int load_clctr(clctr_api_t *api);

/* clusterer_controller.c */
extern const unsigned char CL_CTR_PACKET_MAGIC[CL_CTR_MAGIC_SZ];
extern const unsigned char CL_CTR_BOOTSTRAP_MAGIC[CL_CTR_MAGIC_SZ];
extern const unsigned char CL_CTR_CONSUMER_MAGIC[CL_CTR_MAGIC_SZ];
extern cl_ctr_cluster_t cl_ctr_clusters[CL_CTR_MAX_CLUSTERS];
extern int cl_ctr_cluster_count;
extern char *my_ip;
extern int query_time;
extern int on_config_mismatch;
extern const char *my_ip_src;
extern char my_interface_buf[IF_NAMESIZE];
extern int cc_max_payload;
extern int cc_mtu;
extern int cc_mtu_now;
extern int cc_mtu_drift_strikes;
extern int cc_mtu_read_fails;
extern uint16_t my_node_id;
extern uint64_t cl_ctr_incarnation;
extern clusterer_ctrl_binds_t clctl;
extern int clctl_loaded;
extern int manage_shtags;
extern int consumer_retries;
extern int consumer_retry_ms;
extern int enable_reliable_send;
extern int master_stickiness;
int cl_ctr_read_iface_mtu(void);
int cl_ctr_mtu_step(int now_mtu, int joined_mtu, int *strikes, int *fails);
int cl_ctr_find_peer(int cid, int nid, int *is_master, int *is_backup,
                        char *ipbuf, int ipbuf_sz);
unsigned int ip_to_num(const char *ip);
int cl_ctr_master_outranks(uint16_t c1, uint32_t t1, const char *ip1,
                                  uint16_t c2, uint32_t t2, const char *ip2);
void cl_ctr_note_term(cl_ctr_cluster_t *cl, uint32_t term);
void cl_ctr_elect_master(cl_ctr_cluster_t *cl);
int cl_ctr_i_am_master_locked(cl_ctr_cluster_t *cl);
int cl_ctr_ip_beats_master_locked(unsigned int ip_num, cl_ctr_cluster_t *cl);
void cl_ctr_apply_shtags(cl_ctr_cluster_t *cl);
void cl_ctr_prune_stale(cl_ctr_cluster_t *cl);
void cl_ctr_apply_master_from_list_locked(const char *master_ip, cl_ctr_cluster_t *cl);
void cl_ctr_upsert_peer_locked(const char *src_ip, cl_ctr_cluster_t *cl);
void cl_ctr_reserve_id_locked(cl_ctr_cluster_t *cl, const char *ip,
                                     uint16_t node_id);
uint16_t cl_ctr_alloc_node_id_locked(cl_ctr_cluster_t *cl, const char *ip);
void cl_ctr_update_peer_bin_locked(const char *ip, uint16_t node_id,
                                      uint8_t bin_count,
                                      const char (*bin_sockets)[CL_CTR_MAX_BIN_SOCK_LEN],
                                      cl_ctr_cluster_t *cl);
int cl_ctr_gen_ecdh_keypair(unsigned char *privkey, unsigned char *pubkey);
const char *cl_ctr_cid_state_name(int st);
void cl_ctr_cid_str(const unsigned char *cid, char *out);
int cl_ctr_cid_is_zero(const unsigned char *cid);
void cl_ctr_cid_found(cl_ctr_cluster_t *cl);
void cl_ctr_cid_tick(cl_ctr_cluster_t *cl);
int cl_ctr_decrypt_pkt(char *buf, ssize_t n, const char *sender_ip,
                          const unsigned char *key, int is_bootstrap);
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
void cl_ctr_retx_enqueue_bcast(cl_ctr_cluster_t *cl, uint32_t seq,
                            const unsigned char *pkt, int pkt_len);
void cl_ctr_retx_enqueue_consumer(cl_ctr_cluster_t *cl, uint32_t seq,
                            unsigned char type, const unsigned char *pkt,
                            int pkt_len, const struct sockaddr *dest,
                            socklen_t destlen);
void cl_ctr_handle_ack(const char *payload, int payload_len,
                              cl_ctr_cluster_t *cl, const char *sender_ip);
int cl_ctr_on_retx_tfd(int fd, void *param, int was_timeout);
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
void cl_ctr_membership_digest(cl_ctr_cluster_t *cl, uint16_t *count, uint64_t *hash);
void cl_ctr_sockaddr_in(const char *ip, int port, struct sockaddr_in *out);
void cl_ctr_apply_alive_bitmap(cl_ctr_cluster_t *cl, const unsigned char *bm);
void cl_ctr_send_master_alive(int sock, cl_ctr_cluster_t *cl);
void cl_ctr_send_resync(int sock, cl_ctr_cluster_t *cl,
                           const struct sockaddr *dest, socklen_t destlen);
void cl_ctr_send_master_beacon(int sock, cl_ctr_cluster_t *cl);
void cl_ctr_send_key_handoff(int sock, const char *next_master_ip,
                                const unsigned char *next_master_pubkey,
                                cl_ctr_cluster_t *cl);
void cl_ctr_on_became_master(cl_ctr_cluster_t *cl);
void cl_ctr_arm_master_timers(cl_ctr_cluster_t *cl, int i_am_master);
void cl_ctr_request_rekey(cl_ctr_cluster_t *cl);
void cl_ctr_transition_to_active(cl_ctr_cluster_t *cl);
void cl_ctr_fmt_cfg_diff(char *out, int outsz, const char *la, const char *lb,
                            int a_manage, int b_manage, int a_stick, int b_stick,
                            int a_qt, int b_qt);
void cl_ctr_adopt_config(cl_ctr_cluster_t *cl, int new_manage, int new_stick,
                            int new_qt, int is_active);
void cl_ctr_handle_join_req(int sock, const char *payload, int payload_len,
                               uint64_t pkt_inc, cl_ctr_cluster_t *cl,
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
                                int reason);
void cl_ctr_handle_join_reject(const char *payload, int payload_len,
                                   const char *sender_ip, cl_ctr_cluster_t *cl);

#endif /* CL_CTR_H */
