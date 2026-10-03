---
title: "CLUSTERER_CONTROLLER Module"
description: "Zero-config high availability for the clusterer module: nodes discover each other over encrypted UDP multicast, elect a master, receive node IDs and BIN addresses, and fail sharing tags over automatically."
---

## Admin Guide


### Overview

The *clusterer_controller* module provides automatic peer discovery and topology management for the *clusterer* module via authenticated, encrypted UDP multicast. It eliminates the need for static node configuration or a database — nodes discover each other automatically at startup and the cluster topology is maintained dynamically at runtime.

When a cluster is registered as controller-managed via *modparam("clusterer", "cluster_options", "cluster_id=N, use_controller=1")*, the *clusterer_controller* module takes over all topology management: it allocates unique node IDs, discovers peer BIN socket addresses, and calls the clusterer internal API to add or remove nodes as they join or leave the cluster.

By default (*manage_shtags=1*), the module also provides fully automatic sharing tag failover. The controller master node is the single decision point for which node holds the active tag — no event routes, MI commands, or *seed_fallback_interval* configuration is needed. Sharing tags are forced to backup at startup regardless of the *=active* config value, and the active tag is claimed by the controller master automatically when the cluster forms or when the active node departs. An operator can override this automatic allocation and pin the active tag to a chosen node with the *cl_ctr_shtag_force* MI command, reverting to automatic allocation with *cl_ctr_shtag_auto*.

The minimal configuration per node is a single multicast group address. No IP addresses, node IDs, BIN URLs, or sharing tag management scripts need to be hardcoded or maintained. Any number of nodes can join or leave without any configuration change on the remaining nodes.

### Discovery Protocol

All traffic uses UDP multicast to the configured *multicast* address and port. Clusters are kept apart in two independent ways: by the multicast endpoint (two clusters may use different IP addresses, or the same address with different UDP ports), and by the *id* (*cluster_id*) carried in the cleartext of every packet. A node silently ignores any packet whose cluster_id differs from its own, so several clusters can safely share one multicast group and port. Two clusters merge only if they share *all* of the multicast address, the UDP port, the cluster_id and the password — i.e. they are configured identically, which is the operator's responsibility to avoid. Even then they do not merge once each holds its own established [cluster identity](#cluster-identity), and two masters whose consistency-critical settings or MTU differ refuse to merge and say so in the log (see *Split-brain handling*).

Every packet is encrypted and authenticated with the XChaCha20-Poly1305 AEAD (see the *Security Architecture* section). Two distinct encryption keys are used depending on the communication phase:

- **Bootstrap key** — derived from the configured *password* with the *Argon2id* memory-hard KDF (per-cluster salt), so a password captured from a bootstrap packet cannot be brute-forced cheaply offline. Derived once at startup. It is both the outer AEAD key for the admission handshake (JOIN_REQ, KEY_GRANT, JOIN_REJECT) and the split-brain MASTER_BEACON — traffic that must be readable before a session key exists, or by masters holding different session keys — and the pre-shared key for the Noise join handshake.
- **Session key** — derived via HKDF-SHA256 from the password and a 32-byte master salt generated once when the cluster first bootstraps. All normal cluster traffic uses this key. It is preserved across master changes (a new master reuses the key every member already holds), so failover needs no re-keying.

Each packet begins with a 2-byte magic value, a 2-byte cluster_id and the 16-byte cluster identity, all in cleartext (they must be readable before decryption to select the key and to filter foreign clusters), followed by a random 24-byte AEAD nonce and the ciphertext. The first magic byte carries the **wire version** (0xCB + version; this build speaks version 2), the second selects the key. The magic, cluster_id and identity are additionally bound into the authentication tag as AAD, so they cannot be altered undetected. The authenticated plaintext begins with a 1-byte packet type, a 4-byte sequence number and the sender's 8-byte *incarnation* (its process start time), which together drive replay protection. A 16-byte authentication tag follows the ciphertext.

```text
[magic 2B][cluster_id 2B][cluster uuid 16B][nonce 24B] [type 1B][seq 4B][incarnation 8B][payload...] [tag 16B]
 '---------------- cleartext, AAD ----------------'      '---------------- encrypted -----------------'
```

Packets for a different cluster_id are dropped before decryption; packets encrypted with a different password fail authentication and are silently discarded; a packet from another wire version is refused before decryption, with a warning naming the sender (see [Upgrading](#upgrading)).

The following packet types are defined:

- **ALIVE** — periodic heartbeat sent by every active node every *query_time* seconds. Carries the sender IP, its X25519 public key (so peers can prepare for key agreement) and a small descriptor of the sender's consistency-critical settings (*manage_shtags*, *master_stickiness*, *query_time*) used for configuration-drift detection (see Security Architecture). Encrypted with the session key.
- **JOIN_REQ** — sent at startup by a new node, carrying its IP, BIN socket list, and Noise message 1 (the initiator's fresh ephemeral public key). Encrypted with the bootstrap key so it can be sent before a session key exists.
- **MEMBER_LIST** — sent by the master in response to a JOIN_REQ, carrying the member count, the operator-forced sharing-tag holder node_id (0 = automatic), and the full peer IP list so the joining node can participate in elections. Only accepted from the current master (except during initial join when no master is yet known).
- **NODE_ASSIGN** — sent by the master to multicast, allocating a node_id and BIN socket record for a joining node, together with the incarnation the master admitted it at. All cluster members receive and apply it.
- **GOODBYE** — sent on graceful shutdown so peers can remove the node immediately without waiting for timeout. Uses the sender's monotonic sequence counter to prevent forgery.
- **MASTER_ALIVE** — keepalive sent by the master every 1 second (independent of *query_time*). Used by all peers to detect master failure quickly (3-second timeout). Carries the membership digest, the liveness bitmap and the master's *term*. Encrypted with the session key.
- **KEY_GRANT** — the master's response to a JOIN_REQ, addressed to the joining node. Carries Noise message 2 (the master's ephemeral plus the AEAD-encrypted master salt), completing the Noise_NNpsk0 handshake. Encrypted with the bootstrap key.
- **KEY_HANDOFF** — sent by the outgoing master on graceful shutdown to the next-highest-IP peer, delivering the master salt (as an anonymous crypto_box sealed to that peer's long-lived X25519 key, learned from its ALIVE) so it can become the new master without a full re-join cycle. Encrypted with the session key.
- **JOIN_REJECT** — sent by the master to a joining node whose JOIN_REQ repeatedly fails authentication (wrong password). After *CL_CTR_JOIN_FAIL_LIMIT* (3) consecutive bootstrap-key decryption failures from the same source IP the master sends a JOIN_REJECT to that IP. Encrypted with the bootstrap key so it cannot be forged by a node that does not know the cluster password. A node that has not joined anything yet logs a critical error and shuts down OpenSIPS on receipt; an established node that was merging partitions abandons the merge instead (see *Split-brain handling*).
- **MASTER_BEACON** — a master-only announcement multicast every few MASTER_ALIVE ticks, carrying this partition's member count, the master's term, its consistency-critical settings and its MTU. Unlike MASTER_ALIVE it is encrypted with the *bootstrap* key, so it is readable even by a master that holds a different session key. This is how a split brain between two independently bootstrapped partitions is detected and merged (see *Master Election*).

### Cluster identity

The *cluster_id* is a number an operator configures, so two separate deployments that share a multicast group, a password and a cluster_id — a lab cloned from production onto the same VLAN, say — would otherwise be indistinguishable, and their masters would merge them into one. To prevent that, each cluster has an **identity**: a 16-byte UUID carried in every packet's authenticated header.

- The node that *founds* a cluster (the first master, at the join deadline) mints it as a UUID v7: its founding time, then random. A node that must found while it has already heard authenticated traffic from an existing cluster founds into that cluster's identity instead.
- A joining node adopts the master's identity from its KEY_GRANT.
- For the first 30 seconds the identity is *provisional*: a simultaneous cold start can produce two founders before either hears the other, so during that window a node still hears other identities and can be merged, adopting the winner's. After that the identity is *established* and never changes for the life of the process.
- A node with an established identity refuses every packet stamped with another one, before decrypting it, and logs once a minute who it refused and both identities. Packets with no identity (a node not yet in any cluster, and every JOIN_REQ) always pass, which is how new and restarted nodes join.
- The identity lives in memory only. A rolling restart keeps it (each restarted node adopts it on rejoining); a whole-cluster restart founds a new one, which is harmless. To keep one identity across whole-cluster restarts, pin it with *uuid=* in the [cluster](#cluster-string) string.

*cl_ctr_list_config* reports the identity, its state (*none*, *provisional*, *established* or *pinned*) and how many foreign packets have been refused.

### Master Election

Each cluster has three roles: **master** (the active coordinator), **backup** (the standby promoted when the master fails, always the highest-IP non-master) and **member**. The election uses a quantized time window so that all nodes evaluate the same eligible peer set and reach the same result deterministically. No NTP synchronisation between nodes is required for correct election results.

The *master_stickiness* parameter (default 1) controls whether a live master is kept when a higher-IP node joins. With stickiness enabled, the master stays put and the higher-IP joiner becomes the backup, minimising handovers; with stickiness disabled the highest-IP node always becomes master. In either mode two live masters are reconciled deterministically (see *Split-brain handling* below). See the *master_stickiness* parameter for details.

Only the master handles JOIN_REQ packets, allocates node_ids, and sends NODE_ASSIGN and MEMBER_LIST packets. Non-master nodes are passive during join events. A joining node receives the current session key from the master (via KEY_GRANT) and joins as a member or backup; it never seizes mastership during the join handshake.

**Preserved session key:** the session key is generated once, when the first node bootstraps the cluster, and is then preserved across every master change. A new master does not re-key; because every member already holds the key (obtained when it joined), master transitions require no re-keying and no re-JOIN cycle.

**Fast master failure detection:** the master sends MASTER_ALIVE packets every 1 second. All non-master peers maintain a 3-second watchdog timer that fires if no MASTER_ALIVE is received. On expiry the silent master is aged out of the election window and each peer immediately re-elects, promoting the backup (highest-IP survivor) — which already holds the session key, so it starts serving within one keepalive interval.

**Graceful master handoff:** when the current master shuts down cleanly, it sends a KEY_HANDOFF packet directly to the next-highest-IP peer before sending GOODBYE to multicast. This confirms the master salt to the incoming master so it can assume control immediately.

**Split-brain handling.** A split brain (more than one node believing it is master) is prevented and, if it still occurs, healed by three cooperating mechanisms:

- **Prevention at join time.** When several nodes start simultaneously they all exchange (bootstrap-decryptable) JOIN_REQs and thus learn about each other. At the join deadline, a node that has seen a higher-IP node also still joining defers its own self-promotion (for a few bounded rounds) and joins that node instead, so only the highest-IP starter becomes master and no independent-key lone masters are created.
- **Same-key yield.** Two masters that share a session key (for example after a network partition heals) can read each other's MASTER_ALIVE; the one that is outranked (see below) yields immediately.
- **Divergent-key merge.** Two masters that were bootstrapped independently hold different session keys and so cannot read each other's MASTER_ALIVE. Each therefore emits a MASTER_BEACON encrypted with the shared bootstrap key. On hearing a beacon from a master that outranks it, a node abandons its partition, re-joins that master and adopts its session key, converging the whole cluster onto a single master and key.

**Which master survives.** Both paths rank two masters by one ordering, so the two ends always reach the same verdict and can never each yield to the other:

1. **member count** — the larger partition wins, so a heal disturbs as few nodes as possible;
2. **term** — the more recently established mastership wins. A node that starts asserting mastership takes a term one above the highest it has heard from any master, and announces it in MASTER_ALIVE and MASTER_BEACON; this is what lets a node that takes over (with *master_stickiness=0*, or after a failover) win against the master it replaces;
3. **IP** — the higher address, as a total tiebreak.

Member count deliberately comes before the term: a node whose link flaps promotes itself every time it is cut off, each time with a higher term, and ranking the term first would hand the cluster — and its sharing tags — to the least reliable node in it. The current term is reported by *cl_ctr_list_config*.

**Partitions that must not merge.** A master compares the settings and MTU carried in another master's beacon with its own *before* ranking. If they differ — the settings only under *on_config_mismatch=reject*, the MTU always, exactly the checks a JOIN_REQ would meet — neither master merges, whichever would have won, and both log a warning naming the other master and the values that differ. The two partitions remain separate until an operator makes the configuration identical. Should a merge still be refused by the other master's JOIN_REJECT, the merging node does **not** shut down: it is a running member with an intact partition, so it forgets the refusing master, re-elects within its own partition and ignores that master for 60 seconds. Only a node that has not joined anything yet still shuts down on a refusal.

### Security Architecture

The module uses a two-phase key agreement to provide forward secrecy and replay protection for all cluster traffic.

**Payload encryption and header binding:** every packet's payload is sealed with an AEAD. The 2-byte magic (a key selector that must be readable before decryption) and the 2-byte cluster_id that precede the nonce are cleartext framing, but they are bound into the AEAD tag as additional authenticated data (AAD): a captured packet cannot be re-stamped with a different cluster_id and still authenticate, which matters when two clusters share one multicast group and password. A node also drops any packet whose cluster_id does not match its own *before* attempting decryption, so foreign-cluster traffic on the group never counts as an authentication failure.

**Crypto (all libsodium; a hard requirement):** the payload AEAD is *XChaCha20-Poly1305* (24-byte nonce, whose 192-bit nonce space removes any random-nonce collision concern); the bootstrap-key KDF is *Argon2id*; and X25519 / HKDF-SHA256 / RNG also come from libsodium. The active suite is reported in the startup log (*crypto=...*).

**Phase 1 — join handshake (JOIN_REQ / KEY_GRANT):** the join is a *Noise_NNpsk0_25519_ChaChaPoly_SHA256* handshake with the pre-shared key set to the Argon2id bootstrap key:

```opensips
-> psk, e     JOIN_REQ  carries Noise message 1 (a fresh ephemeral)
<- e, ee      KEY_GRANT carries Noise message 2; its AEAD payload = master_salt
```

Authentication comes from the shared PSK, forward secrecy from the ephemeral-ephemeral DH, and the Noise handshake hash binds the whole transcript — so a stale KEY_GRANT for a superseded JOIN_REQ simply fails to decrypt. Both handshake messages also travel inside the bootstrap-key AEAD envelope, so a wrong-password node is rejected at the envelope before the handshake is even reached. This replaces the earlier hand-rolled ECDH-and-XOR salt wrap.

**Phase 2 — session (all other packets):** once the master salt is known, all nodes derive the session key as:

```opensips
session_key = HKDF-SHA256(IKM=password, salt=master_salt, info="cc-session-key")
```

The session key is generated once, when the first node bootstraps the cluster, and preserved across every master change: a new master reuses the key that every member already holds, so master transitions require no re-keying. All normal cluster traffic (ALIVE, MEMBER_LIST, NODE_ASSIGN, GOODBYE, MASTER_ALIVE, KEY_HANDOFF) is encrypted with this key.

**Replay protection:** each sender numbers its session-key packets with a 32-bit sequence (control and consumer traffic are numbered separately) and stamps every packet with its *incarnation* — its process start time in microseconds — inside the authenticated plaintext. Each receiver keeps a sliding window per sender and plane that accepts every sequence number exactly once, and keys that window on the sender's incarnation: a packet carrying a *higher* incarnation means the sender restarted and numbers from 1 again, so its windows start afresh on that packet; one carrying a *lower* incarnation is a packet from a previous life and is refused. A restarted node is therefore heard by every peer from its first packet, without depending on any broadcast reaching them. The master also records the incarnation it admitted a node at and carries it in NODE_ASSIGN, which covers a node whose clock was stepped back across its restart (its new incarnation would otherwise read older than the old one). Sequence counters also restart whenever the session key is (re)derived. Replay protection does not depend on clock synchronisation between nodes.

**Rate limiting:** a per-source rate limiter (256 slots, 20 packets/second limit) is applied before any decryption attempt. This prevents CPU exhaustion from packet floods directed at the multicast group.

**Join authentication and rejection:** the master tracks consecutive bootstrap-key decryption failures per source IP in a small worker-local table (*CL_CTR_JOIN_FAIL_TABLE_SZ* = 8 slots). When any source IP accumulates *CL_CTR_JOIN_FAIL_LIMIT* (3) consecutive failures — indicating a node attempting to join with the wrong password — the master sends an encrypted JOIN_REJECT packet and stops responding to further JOIN_REQs from that IP.

On the joining side, a received JOIN_REJECT is acted on only if it is addressed to this node *and* this node currently has an admission request outstanding (*join_pending*). A member that is not asking to be admitted ignores JOIN_REJECT unconditionally, so a node with the correct password can never be evicted by a peer.

The guard is deliberately the pending request and not the *CL_CTR_NODE_NEW* state. After a simultaneous cold start both nodes can reach the join deadline and self-promote, and the loser then merges into the winner by sending a fresh JOIN_REQ *from the active state*. Keying on the state label would have that node discard the refusal of a join it had just made. It acts on the refusal, but differently from a joining node: a node still joining shuts down, while an established node abandons the merge and stays with its own partition (see *Split-brain handling*).

**What a JOIN_REJECT carries, and why.** Beyond the target IP and a reason byte, the refusal carries the *master's own* cluster-plane MTU and its consistency-critical settings (*manage_shtags*, *master_stickiness*, *query_time*), encoded exactly as JOIN_REQ carries the joiner's. Both are diagnostic, not state the joiner adopts, and they buy two things. First, the node that is about to stop can name *both* sides in its own log - it is the node an operator looks at first, and "the settings differ" without values sends them off to read two config files by hand. Second, the joiner can check the refusal against what it holds and *refuse a refusal that contradicts itself*: a reject quoting this node's own MTU, or its own config triple, is either a stale packet or a peer asserting something untrue, since a real master sends those reasons only when the values differ. Without that check any holder of the cluster password could end a merging master's process by assertion alone. Older senders omit both fields; the parse is by length, and a reject without them is still honoured, just with the generic message.

**Uniform cluster MTU:** every member of a cluster runs at the same cluster-plane MTU, and the master enforces it at admission. The value is *detected* from the interface that owns the cluster-plane IP (*SIOCGIFMTU*) and there is deliberately no modparam for it: the kernel already owns that fact, and a configured copy could only ever disagree with it. A node that cannot read its own MTU refuses to start.

Each node advertises its *current* reading in JOIN_REQ and ALIVE. A master that receives a JOIN_REQ whose MTU differs from its own answers with a JOIN_REJECT carrying reason *CL_CTR_REJECT_MTU*, and the joiner stands down. This is not covered by *on_config_mismatch* and is never optional - that parameter governs genuinely configured settings, whereas a mismatched MTU means the two nodes cannot exchange full-size packets at all. (A node old enough not to advertise an MTU is admitted unchanged.)

The rule needs nothing on the wire beyond that check, by induction: the master admits only equal-MTU nodes, so every member carries the master's MTU, so the backup that is promoted on handover already carries it too. A cluster's MTU therefore cannot change through an election, and there is no inherited MTU field in MEMBER_LIST.

After joining, each node polls its own interface. What it joined at is what it is judged against; what the kernel says now is what it advertises - the two are tracked separately, or a node whose link changed would keep announcing its old value and no peer could ever see the difference. *CL_CTR_MTU_DRIFT_STRIKES* (3) consecutive disagreeing readings confirm a local change, and the node then logs a critical message and shuts itself down: it can no longer receive full-size cluster traffic, and it would otherwise keep sending heartbeats and look healthy while silently missing membership updates. A single odd reading, or a reading that agrees again, clears the strikes. A failed *SIOCGIFMTU* is not a strike, is not advertised, and does not reset one - it is reported on the first failure and then every *CL_CTR_MTU_READ_FAIL_LOUD* (12) failures, so a persistently blind poll cannot pass for a quiet healthy one.

A node never acts on a *peer's* reading. Seeing a peer advertise a different MTU produces a warning only - that peer detects its own change and removes itself, and terminating on someone else's reading would turn one *ip link* command into a fleet outage. One case does need a louder signal: master election is by highest IP and ignores the MTU, so a single wrongly-configured host that wins it will refuse an otherwise healthy fleet. A master that has refused *CL_CTR_MTU_SUSPECT_PEERS* (2) distinct peers while holding no members of its own logs a critical message naming *itself* as the probable misconfiguration. The same safety net exists for the CONFIG gate (*CL_CTR_CFG_SUSPECT_PEERS*, also 2): election ignores *manage_shtags* / *master_stickiness* / *query_time* exactly as it ignores the MTU, so a master that has refused two distinct peers on settings while holding no members names itself the probable culprit too.

A node joining with the *wrong* password cannot decrypt the JOIN_REJECT (it is encrypted with the master's bootstrap key), so it relies on a self-contained signal instead: while joining it counts packets received from other peers that it cannot decrypt. If, at the join deadline, the node is still unjoined and has seen *CL_CTR_JOIN_FAIL_LIMIT* or more such undecryptable packets, it concludes that a cluster it cannot authenticate to exists on the group and shuts down OpenSIPS with a critical log message — rather than promoting itself into a lone, split-brain master (which, with managed sharing tags, would create a duplicate active tag). This counter is reset the moment a KEY_GRANT is successfully processed, so a legitimate joiner that briefly saw an undecryptable packet before receiving its key is never affected.

**Rogue traffic isolation:** a node requests a re-key in response to an undecryptable session-key packet only when that packet came from its current master (a legitimate key rotation). Undecryptable session packets from any other source — for example a wrong-password or malicious node broadcasting on the multicast group — are ignored, so such traffic cannot drive the cluster into a re-JOIN churn.

**Peer table exhaustion defence:** the peer table is bounded at *CL_CTR_MAX_PEERS* (256) entries. When the table is full, the master rejects JOIN_REQ packets from unknown IPs with a JOIN_REJECT response. Known peers that are reconnecting after a restart continue to be admitted regardless of the table count, since they already own a slot. This prevents an attacker with the cluster password from exhausting the peer table by flooding JOIN_REQs from spoofed source addresses.

**Configuration-consistency enforcement:** all nodes of a cluster must use identical consistency-critical settings (*manage_shtags*, *master_stickiness* and *query_time*); a per-node mismatch would otherwise cause silent, inconsistent failover and sharing-tag behaviour (for example, a master with *manage_shtags=0* would leave no node holding the active tag). Each node advertises these effective settings in its ALIVE heartbeat and in its JOIN_REQ, so mismatches are detected. What happens then is controlled by the *on_config_mismatch* modparam:

- *reject* (default) - when a node tries to join an established cluster (a master is alive) with different settings, the master logs the attempt and returns a JOIN_REJECT; the joining node logs the offending settings and shuts down, so a misconfigured node never joins.
- *warn* - the node is allowed to join, but any peer that observes a different value logs a single loud *CONFIG MISMATCH* warning (repeated only if the peer's advertised configuration changes, cleared once it matches).
- *adopt* - the joining node adopts the running cluster's (master's) settings at runtime and continues; the adopted values are what *cl_ctr_list_config* reports.

This turns an easy-to-miss misconfiguration into an obvious log line, a refused join, or a self-correction rather than a hard-to-diagnose HA failure.

**Node identity and node_id allocation:** *node_id* values are allocated exclusively by the current master, serialised under the peer-table lock, and a joining node never picks its own id. The master hands out the lowest unused id by scanning the live peer table, so a node that has failed but is not yet timed out still occupies its slot and its id is never handed to a different joiner — new nodes always receive a distinct id even during the failure-detection window. A node that restarts and rejoins from the same address reuses its previous id, so ids stay stable across restarts — including after a *clean* departure: when a node leaves (GOODBYE) or is purged, every node holds its id for that address for an hour, and the master hands it back when the node returns instead of giving it to whoever joined in the meantime. A changed id is not cosmetic: clusterer would remove and re-add the node, and a sharing tag forced onto the old id would name a different machine. Because peers are keyed by source IP address, every node in a cluster must present a stable, unique source IP: two distinct nodes that appear behind the same address (for example through NAT) would share a single peer slot and *node_id*. Deploy the cluster on a network where each member has its own routable address on the BIN/multicast interface.

**Trust model — shared secret, not per-node identity:** the cluster is a single shared-secret trust domain. Authentication proves only that a peer holds the cluster password; it does not bind a cryptographic identity to an individual node, and there is no per-node authorisation or revocation. Consequently any party in possession of the password is a fully trusted member and can legitimately win the highest-IP master election and assume the master role — there is no distinction between "may be a member" and "may be master". An attacker *without* the password cannot affect the election at all: forged or replayed *MASTER_ALIVE* and beacon packets fail AEAD authentication (or the strict per-source sequence check) and are dropped before any election logic runs. The residual exposure is therefore a malicious or compromised *insider* that already holds the shared key. Protect the password accordingly, and rotate it if a node is decommissioned or suspected compromised. Removing this limitation — per-node keypairs with enrolment and revocation, so a single node can be distrusted without re-keying the whole cluster — is planned future work.

### Dependencies

#### OpenSIPS Modules

The following modules are required by this module:

- *proto_bin* — required so that BIN listeners are registered and available for discovery when *clusterer_controller* initialises and scans the proto_bin listener list.
- *clusterer* — required, and it *must* register every controller-managed cluster with *modparam("clusterer", "cluster_options", "cluster_id=N, use_controller=1")*. That per-cluster parameter is what pre-creates the controller-managed cluster stubs, marks them so they never touch the database, and arms the guard that stops the controller from driving a native cluster of the same id. The controller-managed ids declared here and the *cluster* entries configured in *clusterer_controller* must match *exactly*: if either side names a cluster the other does not, the controller refuses to start with an error naming the offending id — a managed id with no controller config has no BIN socket or crypto parameters, and a controller config for an unmanaged id has nothing to drive.

Both dependencies are declared in the module's *dep_export_t*. OpenSIPS will refuse to start if either dependency is not satisfied. This does *not* imply that the modules must appear in a particular order in the configuration file — OpenSIPS resolves the dependency at runtime and will initialize the required modules first regardless of *loadmodule* order.

This is also checked from the other side: if a *cluster_options* entry sets *use_controller=1* but the *clusterer_controller* module is not loaded at all, clusterer logs an error at startup, since the controller-managed cluster stubs would never obtain a node identity or form. clusterer itself keeps running, so any native or DB-backed clusters are unaffected.

**Hybrid deployments are unaffected.** *use_controller* is a per-cluster option carried in *cluster_options*, defaulting to *0*. In a hybrid instance (native and controller-managed clusters side by side), the controller-managed clusters each get a *cluster_options* line with *use_controller=1*, while the native ones are defined the usual way (DB rows or static *my_node_info*/*neighbor_node_info*) and need no *cluster_options* line. The exact-match check above compares only the controller-managed ids against the controller's *cluster* entries, so it never fires on a native cluster.

All other modules that use the clusterer interface (*tm*, *dialog*, *dispatcher*, *usrloc* etc.) may be loaded in any order relative to *clusterer_controller*. The clusterer module automatically creates a cluster stub when a *cluster_options* entry sets *use_controller=1* and a module attempts to register a capability for that cluster.

Because a controller-managed node receives its *node_id* at runtime (after it joins) rather than from static configuration at startup, any module that stamps this node's id into on-the-wire data must read it live per message instead of caching it once at initialisation — a value read at startup would be the not-yet-assigned placeholder, and it may also change on a re-election. In particular *tm*'s anycast support (*tm_replication_cluster* / *t_anycast_replicate()*) stamps this node's id into the *cid* Via parameter so that a reply landing on a different anycast member can be relayed to the node holding the transaction; it renders that parameter from the current id on each request, so anycast reply routing works unchanged under a controller-managed cluster.

#### External Libraries or Applications

libsodium is required:

- *libsodium* (required) — provides the payload AEAD (XChaCha20-Poly1305), the bootstrap-key KDF (Argon2id), the Noise_NNpsk0 join handshake, and X25519 / HKDF-SHA256 / RNG. The build fails with a clear error if libsodium development files are not found. It is linked dynamically, so each target host also needs the libsodium runtime package (for example *libsodium23*). No other crypto library is used or linked.

The active suite is printed in the startup log (*crypto=...*).

### Building the Module

*clusterer_controller* is **excluded from the default build** (it is listed in *exclude_modules* in `Makefile.conf.template`), like the other modules that depend on external libraries. A stock OpenSIPS build therefore does not include it. To build it, add it to *include_modules* in your `Makefile.conf`:

```opensips
include_modules= clusterer_controller
```

then rebuild (*make all* / *make modules*). libsodium development files must be present on the build host or the build fails — see *External Libraries or Applications*.

**The clusterer module is unmodified when clusterer_controller is not built.** The controller integration on the *clusterer* side (the *clusterer_ctrl* API, the *cluster_options* modparam and all controller hooks) is compiled only when clusterer_controller is part of the build: the top-level Makefile detects this and passes *-DCLUSTERER_CTRL_SUPPORT* to the clusterer module. A build without clusterer_controller produces the stock clusterer module, unchanged in behaviour and exported interface - in particular the *cluster_options* parameter does not exist and is rejected as unknown. Enabling clusterer_controller automatically rebuilds clusterer with the support compiled in; the two are always a matched pair.

### Exported Parameters

#### cluster (string)

Define a cluster to participate in. The value is a comma-separated key=value string with the following fields:

- **id** (required) — positive integer cluster identifier, must match the *cluster_id* used by clusterer consumers (dialog, usrloc, dispatcher, etc.).
- **multicast** (required) — IPv4 multicast address and UDP port in the form *A.B.C.D:PORT*. The address must be in the 224.0.0.0/4 range.
- **password** (optional) — XChaCha20-Poly1305 encryption key material. All nodes in the same cluster must use the same password. Falls back to the global *password* modparam if not set.
- **bin_socket** (optional) — BIN socket to advertise for this cluster, in the form *bin:IP:PORT*. Required when multiple clusters are defined (so the controller knows which listener to advertise), but it need *not* be distinct — several clusters may share the same BIN socket. When only one cluster is defined and only one BIN socket exists, the socket is auto-detected from the *proto_bin* listeners.
- **manage_shtags** (optional) — per-cluster override for the global *manage_shtags* modparam. Set to *1* to enable automatic sharing tag failover for this cluster, or *0* to disable it. When omitted, the global *manage_shtags* value applies, regardless of the order in which *cluster* and *manage_shtags* modparams appear in the config file.
- **master_stickiness**, **consumer_rate_limit**, **consumer_retries**, **consumer_retry_ms** (optional) — per-cluster overrides of the global parameters of the same names.
- **uuid** (optional) — pins this cluster's *identity* (see [Cluster identity](#cluster-identity)): a UUID as written, or any other string, which is hashed into a UUID, so a readable name works (*uuid=billing-prod*). Every node of the cluster must pin the same value. Without it, the node that founds the cluster mints the identity at runtime.

This parameter may be set multiple times to participate in multiple clusters simultaneously. Each cluster runs its own independent worker process.

*No default value. At least one cluster must be defined.*

```opensips title="Set cluster parameter — single cluster"
...
modparam("clusterer_controller", "cluster",
    "id=1,multicast=239.0.90.1:3333")
...
```

```opensips title="Set cluster parameter — multiple clusters on separate networks (one BIN socket per network)"
...
modparam("clusterer_controller", "cluster",
    "id=1,multicast=239.0.90.1:3333,bin_socket=bin:10.0.1.10:5566")
modparam("clusterer_controller", "cluster",
    "id=2,multicast=239.0.90.2:3333,bin_socket=bin:10.0.2.10:5566")
...
```

```opensips title="Set cluster parameter — multiple clusters sharing a single BIN socket (recommended default)"
...
# one proto_bin listener serves both clusters; the cluster_id in each
# BIN packet keeps their replication traffic separate
modparam("clusterer_controller", "cluster",
    "id=1,multicast=239.0.90.1:3333,bin_socket=bin:10.0.0.10:5566")
modparam("clusterer_controller", "cluster",
    "id=2,multicast=239.0.90.2:3333,bin_socket=bin:10.0.0.10:5566")
...
```

> **Note:** **One BIN socket can serve any number of clusters.** Every clusterer BIN packet carries its *cluster_id*, so a single *proto_bin* listener demultiplexes traffic for all clusters. Unless you specifically want different clusters on different interfaces or networks, set the *same* *bin_socket* value on every *cluster* entry (it is mandatory once more than one cluster is defined, but need not be distinct). Using multiple BIN sockets is for network/interface segregation, *not* throughput: the replication data plane runs over BIN (TCP) and scales with the shared TCP worker pool (*tcp_children*) and IPC dispatch, independent of the number of BIN sockets. What does scale with the number of clusters is the controller's own worker set — it spawns one lightweight control worker (UDP multicast: discovery, election, keepalives) per cluster — so it is the *cluster count*, not the BIN-socket count, that adds processes.

> **Note:** **Each cluster needs a distinct multicast endpoint, but clusters may share one BIN socket.** The two sockets play opposite roles. The controller's *multicast* endpoint is its control plane: every cluster defined in one instance must use a *different* multicast address:port — two *cluster* entries with the same *multicast* value are rejected at startup (*duplicate multicast*). Use a different port (e.g. `:3333` and `:3334`) or a different group per cluster. The *bin_socket* is the replication data plane and is the opposite: it may be freely shared across clusters, since every BIN packet carries its *cluster_id*. (The *cluster_id* filter on the multicast wire header is for a different purpose: letting *separate* deployments coexist on a shared multicast group, not two clusters inside one instance.)

#### my_ip (string)

Explicitly set the local IPv4 address used by the controller for its own node identity and master election. This is the IP that the controller advertises to peers in JOIN_REQ and NODE_ASSIGN packets and uses for the highest-IP master election algorithm.

Note: this parameter controls the controller's identity only. The BIN socket address advertised to clusterer peers is discovered separately from the *proto_bin* listener list and is independent of this setting. Do not confuse *my_ip* with the BIN socket IP defined by the *socket=bin:IP:PORT* core parameter.

When set, the module walks the interface list to find which local interface owns this address and uses that interface for multicast traffic. Startup fails if no local interface owns the given address.

The module supports three identity resolution modes depending on which modparams are provided:

**Mode 1 — my_ip set:** The given IP is used directly. The owning interface is resolved automatically from the system interface list. Use this mode on multi-homed hosts where you want to pin the controller identity to a specific IP.

**Mode 2 — interface set, my_ip not set:** The first IPv4 address on the named interface is used as the controller identity IP. A warning is logged if the interface has multiple IPv4 addresses.

**Mode 3 — neither set (default):** A throw-away UDP socket is connected to the multicast group and *getsockname()* is called to determine which source IP the kernel would select. The interface name is resolved from the returned IP. Suitable for single-homed hosts.

*Default: auto-detected (Mode 3).*

```opensips title="Set my_ip parameter"
...
modparam("clusterer_controller", "my_ip", "10.22.23.191")
...
```

#### interface (string)

Explicitly set the network interface name to use for multicast traffic (e.g. *eth0*, *enp6s18*). The module takes the first IPv4 address assigned to this interface as the controller's identity IP. This corresponds to Mode 2 described in the *my_ip* parameter documentation above.

Like *my_ip*, this parameter affects the controller's own identity only and has no effect on the BIN socket addresses advertised to clusterer peers.

If the interface has more than one IPv4 address, a warning is logged and the first address (in the order returned by the kernel) is used. Set *my_ip* explicitly to avoid ambiguity on multi-address interfaces.

Ignored if *my_ip* is also set — *my_ip* takes precedence.

*Default: auto-detected (Mode 3 — see *my_ip*).*

```opensips title="Set interface parameter"
...
modparam("clusterer_controller", "interface", "eth0")
...
```

#### query_time (integer)

How often (in seconds) each active node sends an ALIVE heartbeat to the multicast group. This value also controls the election window (*3 × query_time*) and the peer purge window (*6 × query_time*).

Smaller values mean faster failure detection but higher multicast traffic. Valid range: 1–60.

*Default value is "5".*

```opensips title="Set query_time parameter"
...
modparam("clusterer_controller", "query_time", 5)
...
```

#### password (string)

Global default encryption password for all clusters. All nodes in a cluster must use the same password. The password serves two purposes:

- **Bootstrap key** — the password is stretched with *Argon2id* (memory-hard, per-cluster salt); it is the pre-shared key for the Noise join handshake (JOIN_REQ / KEY_GRANT) and the AEAD key for bootstrap traffic before a session key exists.
- **Session key material** — the password is fed into HKDF-SHA256 together with the master salt to derive the session key used for all normal cluster traffic.

Can be overridden per cluster using the *password=* key in the *cluster* parameter.

*Default value is "3eCrEt*5629". Change this in production.* Use a long, high-entropy secret rather than a memorable phrase — Argon2id raises the cost of an offline guess, but only a strong secret removes the risk. A generated key is ideal, e.g. `openssl rand -base64 32`. The module logs a startup warning if the configured password is the default or has an estimated entropy below 80 bits.

```opensips title="Set password parameter"
...
modparam("clusterer_controller", "password", "MyStr0ngPassw0rd!")
...
```

#### manage_shtags (integer)

When set to **1** (the default), the controller master node automatically manages sharing tag failover for all clusters. The controller becomes the single decision point for which node holds the active tag, eliminating races between nodes and requiring no script-level event routes or MI commands to handle failover. While active, the *clusterer_set_tag_active* MI command and the *$shtag()* script variable setter are blocked for controller-managed clusters, returning an error to the caller.

Behaviour when *manage_shtags=1*:

**Startup:** all local sharing tags are forced to *backup* state during module initialisation, regardless of the *=active* value in the clusterer *sharing_tag* modparam. The deferred BIN broadcast flag is also cleared so no *SHTAG_ACTIVE* packet is ever sent at startup. This ensures that no node can steal the active tag from an existing cluster member simply by restarting.

**Bootstrap:** when the first node starts alone and no existing master responds within *query_time* seconds (join deadline), it elects itself master and activates all local backup tags exactly once. Nodes that join an existing cluster are never eligible for this bootstrap path and never self-activate.

**Failover:** when any node departs (graceful shutdown via GOODBYE packet, or timeout-based removal), the controller master activates its own backup tags for that cluster. This covers all departure scenarios: last node standing, master still present, and post re-election.

**Rejoin:** a node rejoining an existing cluster always starts in backup state and never reclaims the active tag from the current holder, even if *=active* appears in its config.

When set to **0**, the controller does not touch sharing tag state at all. The *=active* config value, *seed_fallback_interval*, and external MI/event-route scripts behave exactly as in stock clusterer without the controller. Use this when you have existing tag management scripts and want to opt out of automatic failover.

*Default value is "1".*

**Global vs per-cluster scope:** This modparam sets a global default that applies to every cluster defined via the *cluster* modparam. Individual clusters can override it by including *manage_shtags=0* or *manage_shtags=1* directly in the cluster string. The global default is resolved at startup after all modparams are processed, so the order of *manage_shtags* and *cluster* lines in the config file does not matter.

```opensips title="Global manage_shtags — applies to all clusters"
...
# clusters 1 and 2 registered as controller-managed on the clusterer side
modparam("clusterer", "cluster_options", "cluster_id=1, use_controller=1")
modparam("clusterer", "cluster_options", "cluster_id=2, use_controller=1")

# Enable automatic failover for every cluster (this is also the default)
modparam("clusterer_controller", "manage_shtags", 1)
modparam("clusterer_controller", "cluster", "id=1,multicast=239.0.90.1:3333")
modparam("clusterer_controller", "cluster", "id=2,multicast=239.0.90.2:3333")
...
```

```opensips title="Per-cluster override — opt one cluster out of automatic failover"
...
# clusters 1 and 2 registered as controller-managed on the clusterer side
modparam("clusterer", "cluster_options", "cluster_id=1, use_controller=1")
modparam("clusterer", "cluster_options", "cluster_id=2, use_controller=1")

# manage_shtags=1 globally, but cluster 2 uses its own MI/event-route scripts
modparam("clusterer_controller", "manage_shtags", 1)
modparam("clusterer_controller", "cluster",
    "id=1,multicast=239.0.90.1:3333")
modparam("clusterer_controller", "cluster",
    "id=2,multicast=239.0.90.2:3333,manage_shtags=0")
...
```

```opensips title="Global opt-out with one cluster opting in"
...
# clusters 1 and 2 registered as controller-managed on the clusterer side
modparam("clusterer", "cluster_options", "cluster_id=1, use_controller=1")
modparam("clusterer", "cluster_options", "cluster_id=2, use_controller=1")

# Disable automatic failover globally; enable it only for cluster 1
modparam("clusterer_controller", "manage_shtags", 0)
modparam("clusterer_controller", "cluster",
    "id=1,multicast=239.0.90.1:3333,manage_shtags=1")
modparam("clusterer_controller", "cluster",
    "id=2,multicast=239.0.90.2:3333")
...
```

```opensips title="Typical full configuration with manage_shtags=1 (default)"
# All nodes use identical config — only the BIN socket IP differs per node.
# The =active tag value in sharing_tag is ignored by the controller;
# it is kept in the config only for compatibility with manage_shtags=0.

socket=bin:10.22.23.191:3857

loadmodule "proto_bin.so"

loadmodule "clusterer.so"
modparam("clusterer", "cluster_options", "cluster_id=1, use_controller=1")
modparam("clusterer", "sharing_tag",   "vip1/1=active")
modparam("clusterer", "ping_interval", 4)
modparam("clusterer", "ping_timeout",  1500)

loadmodule "clusterer_controller.so"
modparam("clusterer_controller", "cluster",  "id=1,multicast=239.0.90.1:3333")
modparam("clusterer_controller", "password", "MyStr0ngPassw0rd!")
# manage_shtags defaults to 1 — no need to set it explicitly
```

#### master_stickiness (integer)

Controls whether a live master keeps its role when a higher-IP node joins. Default *1* (sticky).

The module recognises three roles per cluster: **master** (the active coordinator), **backup** (the standby that takes over when the master fails), and **member** (all other nodes). The backup is always the highest-IP node that is not the master.

- **master_stickiness=1** (default): the master is *sticky* — a live master keeps the role and is not displaced when a higher-IP node joins. The newly joined node becomes the backup (replacing the previous backup if it has a higher IP); the master only changes when the current master actually fails, at which point the backup is promoted. This minimises the number of master handovers.
- **master_stickiness=0**: pure highest-IP election — a higher-IP node takes over as master as soon as it appears. This produces more handovers but always keeps the highest-IP node as master.

In both modes a split-brain (two nodes each believing they are master, e.g. after a network partition heals) is resolved deterministically: the lower-IP master yields to the higher-IP one.

**Global vs per-cluster scope:** like *manage_shtags*, this sets a global default that individual clusters can override with *master_stickiness=0* or *master_stickiness=1* in the *cluster* string. Resolution happens at startup regardless of modparam order.

```opensips title="Set master_stickiness parameter"
...
# both clusters registered as controller-managed on the clusterer side
modparam("clusterer", "cluster_options", "cluster_id=1, use_controller=1")
modparam("clusterer", "cluster_options", "cluster_id=2, use_controller=1")

# Global default (sticky) — omit entirely for the same effect
modparam("clusterer_controller", "master_stickiness", 1)

# Per-cluster override: cluster 2 always promotes the highest-IP node
modparam("clusterer_controller", "cluster",
    "id=1,multicast=239.0.90.1:3333")
modparam("clusterer_controller", "cluster",
    "id=2,multicast=239.0.90.2:3333,master_stickiness=0")
...
```

#### on_config_mismatch (string)

Policy applied when a node's consistency-critical settings (*manage_shtags*, *master_stickiness*, *query_time*) differ from those of the running cluster. All nodes of a cluster are expected to use identical values; this parameter decides what happens when they do not. One of:

- *reject* (default) - the master refuses the join with a JOIN_REJECT and the joining node shuts down after logging which settings differ. Two partitions whose masters' settings differ are not merged (see *Split-brain handling*).
- *warn* - the node is allowed to join; a single *CONFIG MISMATCH* warning is logged per mismatching peer.
- *adopt* - the joining node adopts the running cluster's settings at runtime and continues.

Global only (not per-cluster). Default: *reject*.

```opensips title="Set on_config_mismatch parameter"
...
modparam("clusterer_controller", "on_config_mismatch", "reject")
...
```

#### consumer_rate_limit (int)

How many packets a second this node accepts from any one source address on the messaging API described in [Messaging Between Nodes](#messaging-between-nodes), before it starts dropping them. Separate from the control plane's own much smaller budget, which a busy consumer would otherwise exhaust: the two are counted apart so neither can starve the other.

Set it per cluster in the *cluster* string to override this default for that cluster alone.

*Default value is "1000".*

#### consumer_retries (int)

How many times a message sent with acknowledgement ([What delivery guarantees](#what-delivery-guarantees)) is sent again while it has not been acknowledged. Zero disables retransmission and leaves only the acknowledgement itself, which is still worth having: it is how the sender learns the message arrived.

Set it per cluster in the *cluster* string. A node can belong to several clusters and they are not alike - one may run over a quiet management network where a lost packet is a curiosity, another across a link where it is routine - so one number for all of them is rarely right.

When a reliable send finishes, the log says how much of this budget it actually needed, so the configured value can be judged against what the network does:

```text
broadcast seq 41 acknowledged by all 3 member(s) after 0 of the 2 retries
configured for this cluster
```

and when it gives up, how far it got:

```text
broadcast seq 44 reached 2 of 3 member(s), giving up after 2 of the 2 retries
configured for this cluster
```

*Default value is "2".*

#### consumer_retry_ms (int)

Milliseconds between those attempts. Accepted range is 5 to 5000. Set it per cluster in the *cluster* string, for the same reason as [consumer_retries (int)](#consumer_retries-int).

*Default value is "40".*

#### enable_reliable_send (int)

Whether the *CLCTR_SEND_RELIABLE* flag is honoured. On by default. Set it to 0 to turn the acknowledge-and-retransmit machinery off fleet-wide: a send that asks for reliability then gets an ordinary best-effort one - the payload still goes out, it is simply not acknowledged and not repeated if it is lost - and the module logs one rate-limited warning.

The reason to want that is cost rather than doubt. A reliable broadcast draws one acknowledgement back from every member, so on a large cluster one message becomes an event; a fleet that would rather not pay for it can decline here without editing the consumers that ask.

*Default value is "1".*

### Exported MI Functions

#### cl_ctr_list_members

List all current cluster members with their node_id, status and BIN socket addresses. Status is one of *master*, *backup* (the standby that will be promoted if the master fails) or *member*. Only peers within the current election window are shown.

Parameters: *none*

```bash title="cl_ctr_list_members usage"
opensips-cli -x mi cl_ctr_list_members
[
    {
        "cluster_id": 1,
        "members": [
            {
                "ip": "10.22.23.191",
                "node_id": 1,
                "status": "master",
                "bin_sockets": [ "bin:10.22.23.191:3857" ]
            },
            {
                "ip": "10.22.23.193",
                "node_id": 2,
                "status": "backup",
                "bin_sockets": [ "bin:10.22.23.193:3857" ]
            },
            {
                "ip": "10.22.23.192",
                "node_id": 3,
                "status": "member",
                "bin_sockets": [ "bin:10.22.23.192:3857" ]
            }
        ]
    }
]
```

#### cl_ctr_node_info

Return full information for a specific node identified by its allocated node_id.

Parameters:

- *node_id* — the integer node_id to look up.

```bash title="cl_ctr_node_info usage"
opensips-cli -x mi cl_ctr_node_info node_id=2
{
    "node_id": 2,
    "ip": "10.22.23.192",
    "cluster_id": 1,
    "status": "backup",
    "bin_sockets": [ "bin:10.22.23.192:3857" ]
}
```

#### cl_ctr_list_config

List all configured clusters and their resolved settings — the effective values actually in use after global defaults and per-cluster overrides have been applied. Useful for confirming that a per-cluster *master_stickiness* or *manage_shtags* override took effect. The cluster password is never exposed.

The *shtag_mode* field reports the current sharing-tag allocation policy: *auto* when the active tag follows the master automatically, or *override:<node_id>* when an operator has pinned a fixed holder with *cl_ctr_shtag_force*. *term* is the term of the current mastership (see *Split-brain handling*), *mtu* the cluster-plane MTU this node joined at, and *cluster_uuid*, *cluster_uuid_state* and *foreign_packets* describe the [cluster identity](#cluster-identity).

Parameters: *none*

```bash title="cl_ctr_list_config usage"
opensips-cli -x mi cl_ctr_list_config
[
    {
        "cluster_id": 1,
        "multicast": "239.0.90.1:3333",
        "my_ip": "10.22.23.191",
        "bin_socket": "bin:10.22.23.191:3857",
        "mtu": 1500,
        "interface": "eth0",
        "query_time": 5,
        "master_stickiness": 1,
        "manage_shtags": 1,
        "shtag_mode": "auto",
        "member_count": 3,
        "term": 4,
        "cluster_uuid": "019a1f3c-7b2e-7d41-9c55-3e8f0a6b21d4",
        "cluster_uuid_state": "established",
        "foreign_packets": 0
    }
]
```

#### cl_ctr_shtag_force

Force a specific node to hold the active sharing tag, overriding the normal master-driven allocation. This is useful for planned maintenance or manual traffic steering: the chosen node becomes the sole active shtag holder cluster-wide while every other node — including the master — is put into backup for that tag.

The command must be issued on the current *master* (it returns an error otherwise). The override is propagated to all members in the MEMBER_LIST and *survives master fail-over*: a newly elected master keeps honouring it rather than reclaiming the tag. Automatic allocation stays suspended until *cl_ctr_shtag_auto* is called. If the forced node leaves the cluster or times out, the override is cleared automatically and automatic allocation resumes.

Parameters:

- *cluster_id* — the target cluster.
- *node_id* — the node that must hold the active tag; it must be a current member of the cluster.

```bash title="cl_ctr_shtag_force usage"
opensips-cli -x mi cl_ctr_shtag_force cluster_id=1 node_id=3
```

#### cl_ctr_shtag_auto

Clear any override set by *cl_ctr_shtag_force* and resume automatic, master-driven sharing-tag allocation — the active tag follows the master again. Must be issued on the current master.

Parameters:

- *cluster_id* — the target cluster.

```bash title="cl_ctr_shtag_auto usage"
opensips-cli -x mi cl_ctr_shtag_auto cluster_id=1
```

### Exported Pseudo-Variables

These read-only pseudo-variables expose live cluster state to the routing script, so a decision such as "only the master runs this job" can be made without an MI call. They read directly from shared memory and are therefore available in every process (SIP workers included).

Each variable optionally takes a cluster id as its argument, e.g. *$cl_ctr_role(2)*. The bare form (*$cl_ctr_role*) resolves to the only configured cluster; when several clusters are defined the bare form returns NULL and logs a one-time warning, so the cluster must be named explicitly. An unknown cluster id, or a value that is not currently known (e.g. no master yet), returns NULL. All of them are read-only - assigning to them fails.

- **$cl_ctr_role** — this node's role in the cluster: *master*, *backup*, *member*, or *joining* (still authenticating / before the first election).
- **$cl_ctr_is_master** — 1 if this node is the cluster master, 0 otherwise. A fast path for the most common check.
- **$cl_ctr_master_ip** — IP of the current master (NULL if none is elected yet).
- **$cl_ctr_backup_ip** — IP of the current backup / standby master (NULL if none).
- **$cl_ctr_node_id** — this node's *node_id* within that cluster (NULL until assigned). A node may hold different ids in different clusters.
- **$cl_ctr_my_ip** — the controller identity IP of this node.
- **$cl_ctr_members** — number of live members currently in the cluster.
- **$cl_ctr_shtag_mode** — *auto* (tags follow the elected master) or *forced* (an operator pinned them with *cl_ctr_shtag_force*).
- **$cl_ctr_forced_node** — the *node_id* the active sharing tag is pinned to (NULL when in *auto* mode).

```opensips title="Using $cl_ctr_* in the script"
# single cluster: run a periodic job only on the master
if ($cl_ctr_is_master)
    route(do_master_only_work);

# several clusters: name the one you mean
xlog("cluster 2 master is $cl_ctr_master_ip(2), I am $cl_ctr_role(2)\n");
```

### Exported Functions


Per-peer lookups take two arguments *(cluster_id, node_id)* and are therefore script functions rather than pseudo-variables: a comma inside a variable's parentheses is ambiguous when the variable is itself a function argument.


#### cl_ctr_node_is_master(cluster_id, node_id)


Checks whether a node is the current master of a cluster.


Meaning of the parameters is as follows:


- *cluster_id* (int) - the cluster;
- *node_id* (int) - the node.


Returns *1* if that node is the master, *-1* otherwise.


This function can be used from any route.


```opensips title="cl_ctr_node_is_master() usage"
...
if (cl_ctr_node_is_master(1, 3))
    xlog("node 3 leads cluster 1\n");
...
```


#### cl_ctr_node_present(cluster_id, node_id)


Checks whether a node id is a live member of a cluster.


Meaning of the parameters is as follows:


- *cluster_id* (int) - the cluster;
- *node_id* (int) - the node.


Returns *1* if the node is a live member, *-1* otherwise.


This function can be used from any route.


```opensips title="cl_ctr_node_present() usage"
...
if (!cl_ctr_node_present(1, $var(peer)))
    xlog("node $var(peer) is not in cluster 1\n");
...
```


#### cl_ctr_get_node_role(cluster_id, node_id, role_var)


Writes a node's role - *master*, *backup* or *member* - into a variable.


Meaning of the parameters is as follows:


- *cluster_id* (int) - the cluster;
- *node_id* (int) - the node;
- *role_var* (var) - receives the role.


Returns *1* on success, *-1* if the node is not a member.


This function can be used from any route.


```opensips title="cl_ctr_get_node_role() usage"
...
if (cl_ctr_get_node_role(1, 3, $var(role)))
    xlog("node 3 is $var(role)\n");
...
```


#### cl_ctr_get_node_ip(cluster_id, node_id, ip_var)


Writes a node's controller IP into a variable.


Meaning of the parameters is as follows:


- *cluster_id* (int) - the cluster;
- *node_id* (int) - the node;
- *ip_var* (var) - receives the IP.


Returns *1* on success, *-1* if the node is not a member.


This function can be used from any route.


```opensips title="cl_ctr_get_node_ip() usage"
...
if (cl_ctr_node_present(1, 3) && cl_ctr_node_is_master(1, 3)) {
    cl_ctr_get_node_ip(1, 3, $var(ip));
    xlog("node 3 ($var(ip)) leads cluster 1\n");
}
...
```


#### cl_ctr_broadcast_req(cluster_id, msg, [tag], [reliable])


Sends a request to every other member of the cluster as one multicast packet, over the controller's encrypted plane (see [Messaging Between Nodes](#messaging-between-nodes)). The sender does not receive its own broadcast. Receivers raise [E_CL_CTR_REQ_RECEIVED](#e_cl_ctr_req_received).


Meaning of the parameters is as follows:


- *cluster_id* (int) - the cluster;
- *msg* (string) - the message payload;
- *tag* (string, optional) - carried through to the receiving event route, where it can be used to correlate a reply;
- *reliable* (int, optional) - *1* asks every member to acknowledge the message, and repairs a member that does not with up to [consumer_retries](#consumer_retries-int) retransmissions.


Returns *1* when the message was accepted for sending, *-1* on bad arguments, a message too large for one datagram, or a cluster that has not formed yet.


This function can be used from any route.


```opensips title="cl_ctr_broadcast_req() usage"
...
# to everyone, cheaply
cl_ctr_broadcast_req(1, "cache flushed");

# to everyone, with a tag, and ask to be told it arrived
cl_ctr_broadcast_req(1, "config changed", "cfg", 1);
...
```


#### cl_ctr_send_req(cluster_id, node_id, msg, [tag], [reliable])


Sends a request to one node. Parameters and return values are as for [cl_ctr_broadcast_req()](#cl_ctr_broadcast_reqcluster_id-msg-tag-reliable), plus:


- *node_id* (int) - the destination node.


This function can be used from any route.


```opensips title="cl_ctr_send_req() usage"
...
cl_ctr_send_req(1, 3, "check user $fU", "q1");
...
```


#### cl_ctr_send_req_list(cluster_id, nodes_avp, msg, [tag], [sent_var])


Sends a request to the nodes named in an AVP, one unicast each - deliberately not a multicast that every member would decrypt only to discard.


Meaning of the parameters is as follows:


- *cluster_id* (int) - the cluster;
- *nodes_avp* (var) - an AVP holding the destination node ids;
- *msg* (string) - the message payload;
- *tag* (string, optional) - as for [cl_ctr_broadcast_req()](#cl_ctr_broadcast_reqcluster_id-msg-tag-reliable);
- *sent_var* (var, optional) - receives how many nodes the message was sent to. Entries naming a node that is no longer a member are skipped rather than failing the send for the rest.


Returns *1* if the message was sent to at least one node, *-1* otherwise.


The count comes back in a variable and the function itself is only true or false, because OpenSIPS stops the route when a function returns zero - a function returning the count would halt the script on the day it reached nobody, which is an answer a script must be able to see. And the count is how many nodes the message was *sent to*: how many *acknowledged* is only known later, so for a reliable send it is reported to the log as it completes.


This function can be used from any route.


```opensips title="cl_ctr_send_req_list() usage"
...
# Assigning to the same AVP again adds a value rather than replacing it, so
# this names two nodes (stored newest first: read back 5, then 2).
$avp(nodes) = 2;
$avp(nodes) = 5;
if (cl_ctr_send_req_list(1, $avp(nodes), "just for you", "mytag", $var(sent)))
    xlog("sent to $var(sent) node(s)\n");
...
```


#### cl_ctr_send_rpl(cluster_id, node_id, msg, [tag])


Sends a reply to a node, normally from inside an [E_CL_CTR_REQ_RECEIVED](#e_cl_ctr_req_received) route back to *$param(src_id)*. The receiver raises [E_CL_CTR_RPL_RECEIVED](#e_cl_ctr_rpl_received).


Meaning of the parameters is as follows:


- *cluster_id* (int) - the cluster;
- *node_id* (int) - the destination node;
- *msg* (string) - the reply payload;
- *tag* (string, optional) - normally the *tag* of the request being answered.


Returns *1* when the reply was accepted for sending, *-1* otherwise.


This function can be used from any route.


```opensips title="cl_ctr_send_rpl() usage"
...
event_route[E_CL_CTR_REQ_RECEIVED] {
    cl_ctr_send_rpl($param(cluster_id), $param(src_id), "ack", $param(tag));
}
...
```


### Exported Events


#### E_CL_CTR_REQ_RECEIVED


Raised when a request sent by another node's script (*cl_ctr_broadcast_req()*, *cl_ctr_send_req()* or *cl_ctr_send_req_list()*) is received.


Parameters:


- *cluster_id* - the cluster the message was sent on;
- *src_id* - the node id of the sender (*0* if the sender had not been assigned one yet);
- *msg* - the message payload;
- *tag* - the sender's tag, to be passed back to *cl_ctr_send_rpl()* when replying.


#### E_CL_CTR_RPL_RECEIVED


Raised when a reply sent with *cl_ctr_send_rpl()* is received.


Parameters:


- *cluster_id* - the cluster the reply was sent on;
- *src_id* - the node id of the sender;
- *msg* - the reply payload;
- *tag* - the tag the reply carries, matching the request it answers.


### Messaging Between Nodes

The channel the controller keeps for its own membership traffic is also available to carry other people's messages: a script can talk to its peers, and so can another module. The surface deliberately mirrors the generic messaging the *clusterer* module offers - the same shapes, the same event parameters - so moving between them is familiar. What differs is underneath, and it differs in both directions: one multicast packet instead of a send per peer, over an encrypted channel rather than a plaintext one, but by datagram rather than over a stream, which is the subject of [What delivery guarantees](#what-delivery-guarantees) below.

A message must fit one datagram, so its size limit follows the cluster interface's MTU: 1365 bytes on a standard 1500-byte link, more with jumbo frames, and the value in force is logged at startup. A channel name is limited to 31 characters. The module reserves the channel it uses for script traffic during startup, before any consumer can register, so a module cannot claim it by accident.

#### From the script


The script sends with [cl_ctr_broadcast_req()](#cl_ctr_broadcast_reqcluster_id-msg-tag-reliable), [cl_ctr_send_req()](#cl_ctr_send_reqcluster_id-node_id-msg-tag-reliable), [cl_ctr_send_req_list()](#cl_ctr_send_req_listcluster_id-nodes_avp-msg-tag-sent_var) and [cl_ctr_send_rpl()](#cl_ctr_send_rplcluster_id-node_id-msg-tag), and arriving messages are raised as [E_CL_CTR_REQ_RECEIVED](#e_cl_ctr_req_received) and [E_CL_CTR_RPL_RECEIVED](#e_cl_ctr_rpl_received):


```opensips title="Talking to the other nodes"
event_route[E_CL_CTR_REQ_RECEIVED] {
    xlog("node $param(src_id) says: $param(msg)\n");
    cl_ctr_send_rpl($param(cluster_id), $param(src_id), "ack", $param(tag));
}

event_route[E_CL_CTR_RPL_RECEIVED] {
    xlog("node $param(src_id) answered $param(tag): $param(msg)\n");
}

route[announce] {
    cl_ctr_broadcast_req(1, "config changed", "cfg", 1);
}
```


#### From another module

A module binds the API with *load_clctr()* and gets *register_channel()* to claim a name and receive what arrives on it, *send_mcast()* to reach every member, *send_ucast()* to reach one, *send_list()* to reach a named set, and *get_my_node_id()*. Sends are handed to the controller's worker, so any process may call them.

Two flags. *CLCTR_SEND_TO_SELF* also delivers the message to this node, without putting a packet on the wire, so a consumer can treat itself the same as its peers. *CLCTR_SEND_RELIABLE* is described next.

#### What delivery guarantees

By default: best effort, unordered, and at most once. A message is sent and not spoken of again. That suits anything the sender can afford to repeat - a cache that will be asked a second time, a hint that is worth having and not worth waiting for - and it is the cheapest thing the network can do.

It is also weaker than what *clusterer* gives you over a stream, and that is worth saying plainly rather than leaving to be discovered: a script moved across without further thought has quietly traded reliable, ordered delivery for neither.

*CLCTR_SEND_RELIABLE*, or a 1 in the last argument of *cl_ctr_broadcast_req()*, asks for the message to be acknowledged and sent again while it is not, up to [consumer_retries (int)](#consumer_retries-int) times at [consumer_retry_ms (int)](#consumer_retry_ms-int) intervals. It is chosen per send rather than per channel, because most messages are better off cheap and the ones that are not know who they are.

What that buys is at-most-once delivery, on any channel - including one carrying several messages to the same peer at the same time. The receiver accepts each sequence number exactly once and keeps a window of the recent ones, so it can tell a repair (never delivered: accept it, acknowledge it) from a duplicate (already delivered: acknowledge again, because our first answer evidently went missing, but do not hand the payload up twice). Consumers are not asked to deduplicate.

The window spans a fixed number of messages rather than a fixed time, so a peer sending faster than that window divided by its retransmit horizon - [consumer_retries (int)](#consumer_retries-int) multiplied by [consumer_retry_ms (int)](#consumer_retry_ms-int) - can outrun it. A repair that arrives that late is dropped and deliberately *not* acknowledged, because at that point the receiver genuinely cannot say whether it ever had the message, and an acknowledgement it cannot justify is worse than none. Both ends log it. With the default timings the ceiling is around 12,800 messages a second from any one peer, and the module reports the figure in force at startup.

The cost is one acknowledgement per recipient. On a large cluster a reliable broadcast is therefore one packet out and one back from every member, where an ordinary one is a single packet and no answer at all. It remains a multicast - sending it as one unicast per member would be roughly twice the packets for the same delivery - and only the members that fail to answer are then repaired individually.

Addressing a set of nodes is the other way round: those go out as one unicast each, because a multicast is decrypted by every member, so a message "addressed" to three of them over a multicast would still be handed to all the others. Filtering after decryption is not addressing.

### Multiple Clusters

A single OpenSIPS instance can participate in multiple clusters simultaneously by repeating the *cluster* modparam. Each cluster runs an independent worker process with its own multicast socket, peer table, master election, and node_id space.

Clusters are distinguished by the combination of their multicast IP address and UDP port. Two useful topologies are possible:

- **Different ports, same multicast IP** — convenient when all clusters share the same L2 segment. The port number alone separates traffic for each cluster. Each cluster's *password* should also differ to provide an additional encryption barrier.
- **Different multicast IPs** — useful when clusters span different network segments or when multicast routing is scoped differently per cluster. The clusters may also share one UDP port: each socket receives only the group it joined (the module clears Linux's default *IP_MULTICAST_ALL*, which would otherwise deliver every group joined on that port to every socket bound to it), and a unicast reply the kernel delivers to the wrong cluster's socket is handed to the right one internally.

When multiple clusters are defined and the node has more than one BIN socket, the *bin_socket=* key must be specified in each cluster string to indicate which BIN socket to advertise for that cluster. If only one BIN socket exists, it is used for all clusters automatically.

Each cluster has its own independent clusterer *cluster_id*, allowing different OpenSIPS subsystems to replicate on different clusters:

```opensips title="Multiple clusters — dialog on cluster 1, usrloc on cluster 2"
# Two BIN sockets, one per cluster
socket=bin:10.0.1.10:5566
socket=bin:10.0.2.10:5566

loadmodule "proto_bin.so"

loadmodule "clusterer.so"
modparam("clusterer", "cluster_options", "cluster_id=1, use_controller=1")
modparam("clusterer", "cluster_options", "cluster_id=2, use_controller=1")

loadmodule "clusterer_controller.so"
# Cluster 1 — dialog replication group, LAN segment 10.0.1.0/24
modparam("clusterer_controller", "cluster",
    "id=1,multicast=239.0.90.1:3333,bin_socket=bin:10.0.1.10:5566")
# Cluster 2 — usrloc replication group, LAN segment 10.0.2.0/24
modparam("clusterer_controller", "cluster",
    "id=2,multicast=239.0.90.1:3334,bin_socket=bin:10.0.2.10:5566")

loadmodule "dialog.so"
modparam("dialog", "dialog_replication_cluster", 1)

loadmodule "usrloc.so"
modparam("usrloc", "cluster_id", 2)
```

```opensips title="Multiple clusters — same multicast IP, different ports"
socket=bin:10.22.23.191:3857

loadmodule "proto_bin.so"

loadmodule "clusterer.so"
modparam("clusterer", "cluster_options", "cluster_id=1, use_controller=1")
modparam("clusterer", "cluster_options", "cluster_id=2, use_controller=1")

loadmodule "clusterer_controller.so"
modparam("clusterer_controller", "cluster",
    "id=1,multicast=239.0.90.1:3333,password=ClusterOneSecret")
modparam("clusterer_controller", "cluster",
    "id=2,multicast=239.0.90.1:3334,password=ClusterTwoSecret")

loadmodule "dialog.so"
modparam("dialog", "dialog_replication_cluster", 1)

loadmodule "dispatcher.so"
modparam("dispatcher", "cluster_id", 2)
```

### Hybrid Topologies (native + controller clusters)

A single OpenSIPS instance can run *native* clusterer clusters (defined in the database or statically via *my_node_info*/*neighbor_node_info*) and *controller-managed* clusters side by side. This allows, for example, a fixed, DB-provisioned replication cluster to coexist with a zero-config controller-driven HA cluster on the same node.

Which kind a cluster is follows from how it is declared:

- **Controller-managed** — every *cluster_id* registered with the clusterer module via *modparam("clusterer", "cluster_options", "cluster_id=N, use_controller=1")* (and matched by a *cluster* entry in this module). Its topology and this node's *node_id* are driven at runtime by the controller; it never touches the database and always behaves as *db_mode=0*, regardless of the global *db_mode*.
- **Native** — every cluster loaded from the clusterer database (*db_mode!=0*) or provisioned statically. It behaves exactly as classic clusterer: fixed *my_node_id*, DB persistence (when DB-backed), script/MI-managed sharing tags.

The rules that keep the two kinds apart:

- A *cluster_id* is *exclusively* controller-managed or native — declaring the same id both ways is rejected at startup.
- *my_node_id* identifies this node in its *native* clusters only and is required only when native clusters exist; controller clusters get their node id assigned at runtime, and this node may well hold *different* node ids in different clusters.
- *db_url*/*db_mode* apply to native clusters only. A controller-only deployment needs neither.
- Sharing tags: only tags of controller-managed clusters are forced to backup at startup and driven by the controller master; tags of native clusters keep their configured state (*=active* included) and stay script/MI-managed.
- Native and controller clusters may share the same BIN socket - the *cluster_id* carried in every BIN packet keeps their traffic apart.

```opensips title="Hybrid — DB-native cluster 10 + controller cluster 1"
socket=bin:10.0.0.10:5566

loadmodule "db_mysql.so"
loadmodule "proto_bin.so"

loadmodule "clusterer.so"
# native side: cluster 10 is defined entirely by rows in the clusterer DB
# table (one row per node, including a row whose node_id = my_node_id below
# for THIS node) - there is no cluster_id modparam for native clusters.
modparam("clusterer", "db_mode", 1)
modparam("clusterer", "db_url", "mysql://opensips:pass@localhost/opensips")
modparam("clusterer", "my_node_id", 5)      # this node's id in its native/DB clusters (global)
# controller side: cluster 1 is dynamic (no DB, no static rows)
modparam("clusterer", "cluster_options", "cluster_id=1, use_controller=1")

loadmodule "clusterer_controller.so"
modparam("clusterer_controller", "cluster",
    "id=1,multicast=239.0.90.1:3333,bin_socket=bin:10.0.0.10:5566,password=S3cret")

loadmodule "dialog.so"
modparam("dialog", "dialog_replication_cluster", 1)   # controller-managed

loadmodule "dispatcher.so"
modparam("dispatcher", "cluster_id", 10)              # DB-native
```

```opensips title="Hybrid, no DB — static native cluster 7 + controller cluster 1"
socket=bin:10.0.0.10:5566

loadmodule "proto_bin.so"

loadmodule "clusterer.so"
# native side: cluster 7 is provisioned statically (no DB).
# db_mode=0 is REQUIRED, otherwise my_node_info/neighbor_node_info are ignored.
modparam("clusterer", "db_mode", 0)
modparam("clusterer", "my_node_id", 5)               # this node's id in native cluster 7
modparam("clusterer", "my_node_info",       "cluster_id=7, url=bin:10.0.0.10:5566")
modparam("clusterer", "neighbor_node_info", "cluster_id=7, node_id=6, url=bin:10.0.0.11:5566")
# controller side: cluster 1 is dynamic
modparam("clusterer", "cluster_options", "cluster_id=1, use_controller=1")

loadmodule "clusterer_controller.so"
modparam("clusterer_controller", "cluster",
    "id=1,multicast=239.0.90.1:3333,bin_socket=bin:10.0.0.10:5566,password=S3cret")

loadmodule "dialog.so"
modparam("dialog", "dialog_replication_cluster", 1)   # controller-managed (cluster 1)

loadmodule "dispatcher.so"
modparam("dispatcher", "cluster_id", 7)              # native (cluster 7)
```

Here *my_node_id=5* is this node's id in the native cluster 7; in cluster 1 the controller assigns an id at runtime, which may differ.

### Configuration Example

The following example shows a minimal two-module configuration for zero-config HA clustering with dialog replication. The *loadmodule* order does not matter — the dependency system enforces correct initialization order automatically.

```opensips title="Minimal HA cluster configuration"
# Each node needs an explicit BIN socket (no wildcard)
socket=bin:10.22.23.191:3857

loadmodule "proto_bin.so"

loadmodule "clusterer.so"
modparam("clusterer", "cluster_options", "cluster_id=1, use_controller=1")
modparam("clusterer", "sharing_tag",   "vip1/1=active")
modparam("clusterer", "ping_interval", 4)
modparam("clusterer", "ping_timeout",  1500)

loadmodule "clusterer_controller.so"
modparam("clusterer_controller", "cluster",
    "id=1,multicast=239.0.90.1:3333")
modparam("clusterer_controller", "password", "MyStr0ngPassw0rd!")

loadmodule "tm.so"
modparam("tm", "tm_replication_cluster", 1)

loadmodule "dialog.so"
modparam("dialog", "dialog_replication_cluster", 1)
modparam("dialog", "cluster_auto_sync", 1)

loadmodule "dispatcher.so"
modparam("dispatcher", "cluster_id",           1)
modparam("dispatcher", "cluster_probing_mode", "distributed")
```

The same configuration file (with the node-specific *socket=bin:IP:PORT* line changed per node) is used on every node. No other per-node customization is required.

### Upgrading

This version of the module speaks **wire version 2**: every packet carries the cluster identity and its sender's incarnation, and the master's announcements carry its term, settings and MTU. Nodes on different wire versions do not understand each other, so the module refuses the other version's packets before decrypting them, and logs one warning a minute naming the sender, for example:

```text
clusterer_controller: [cluster 1] 10.0.0.14 speaks wire version 1, this node
speaks 2 - refused (12 packet(s) from other versions so far). Every member of a
cluster must run the same clusterer_controller wire version; upgrade the
cluster as a whole.
```

Upgrade a cluster **as a whole**: stop every node, upgrade them, start them again. A rolling upgrade across a wire-version change does not work. While both versions run, each side sees the other as absent, both sides elect a master, and with *manage_shtags=1* both masters hold the active sharing tags.

### Limitations

- IPv4 only. IPv6 multicast is not currently supported.
- The module pre-allocates approximately 240 KB of shared memory (*-m*) per cluster and 6 KB of private memory (*-M*) per worker process at startup. If either allocation fails, OpenSIPS will refuse to start with an error in the log.
- Wildcard BIN sockets (`bin:*:PORT`) are rejected at startup. An explicit IP address must be used in the *socket=* line.
- Node IDs are not persistent across a full cluster restart (all nodes down simultaneously). IDs are reallocated starting from 1 when the cluster reforms. This has no operational impact as long as at least one node remains up during rolling restarts.
- The multicast network must support IP multicast routing between all cluster nodes. Nodes on different L3 segments require PIM or similar multicast routing.
- **PIM-DM networks:** PIM Dense Mode periodically re-floods multicast traffic (prune state typically expires every 3 minutes). On slow or congested networks this brief re-flood/prune cycle could cause a gap in MASTER_ALIVE delivery and trigger a spurious master re-election. If this occurs, increase the effective timeout by raising *CL_CTR_MASTER_KA_MISSED* in the source from 3 to 5 or higher. PIM Sparse Mode (PIM-SM) or networks with IGMP snooping do not have this issue.
- **L2 overlay tunnels (Geneve, VXLAN, GRE):** if the overlay presents a flat L2 segment with multicast support, the controller works transparently. However, some VXLAN deployments disable multicast entirely (no underlay multicast group, no BUM replication) — in that case the controller will not function, as it has no unicast fallback. Encapsulation overhead also adds latency and jitter; on high-latency overlays consider raising *CL_CTR_MASTER_KA_MISSED* to avoid spurious re-elections.
- **IPsec-protected links:** native IPsec multicast requires GDOI/GET VPN (RFC 6407), which is rarely deployed. The recommended approach is to run multicast inside an inner tunnel (GRE-over-IPsec, Geneve-over-IPsec) that presents a multicast-capable interface. Running the controller over such a setup results in double encryption (application-layer XChaCha20-Poly1305 plus IPsec ESP), which is harmless but adds minor CPU overhead. IPsec ESP tunnel mode also reduces the effective MTU by approximately 50 bytes, which compounds the MEMBER_LIST fragmentation issue described below.
- **MEMBER_LIST fragmentation:** the MEMBER_LIST packet grows with cluster size and reaches approximately 4.4 KB at the maximum of 256 nodes. This exceeds the 1472-byte UDP payload budget of a standard 1500-byte MTU Ethernet link and requires IP fragmentation:

  - Standard Ethernet (1500 MTU): 3 fragments
  - IPsec ESP tunnel (~1400 MTU): 4 fragments
  - GRE-over-IPsec (~1350 MTU): 4–5 fragments

  All other packet types (ALIVE, JOIN_REQ, KEY_GRANT, GOODBYE, etc.) fit comfortably within a single datagram on any of these links. Because every member runs at the same MTU (see the uniform-MTU rule above), the fragment count is the same on every node, and a host on a narrower link is refused admission rather than left fragmenting differently from the rest. The socket sets no *IP_MTU_DISCOVER* option, so Linux's default (*IP_PMTUDISC_WANT*) applies and DF *is* set - on multicast as well as unicast, verified on the wire. What lets MEMBER_LIST through is that it exceeds the LOCAL MTU: a datagram the kernel must fragment locally is not also doing path-MTU discovery, so those fragments leave with DF clear. A datagram that fits the local MTU goes out with DF set, and if it later meets a narrower routed hop it is dropped with an ICMP "fragmentation needed" that is routinely filtered. This is left as it is deliberately: the module's contract is the interface it runs on, not how the operator chose to carry multicast between segments. However, firewalls or stateless middleboxes that silently drop fragmented UDP will prevent new nodes from joining, since MEMBER_LIST is required to complete the join sequence. Verify that fragmented UDP is permitted on all paths between cluster nodes, particularly over VPN tunnels and across datacenter firewalls.

### Planned Features

The following features are planned for future releases:

- **Node maintenance mode** — take a node out of duty for a rolling upgrade while it stays in the cluster. A node in maintenance keeps replicating and answering pings and stays visible in *cl_ctr_list_members*, but is excluded from election (never master or backup; if it is master it hands over gracefully first) and sheds its sharing tags (a *cl_ctr_shtag_force* pin on it auto-clears). Two levels are planned:

  - *evicted* — out of election and tags; the routing script refuses new work while established dialogs finish.
  - *full* — additionally marks the node down for clusterer consumers so peers stop routing replication work to it.

  The state is cluster-wide (carried in the ALIVE/MEMBER_LIST control plane, so every node agrees and it survives master failover) and runtime-only — a restart brings the node back in service.

  Interfaces (following the read-only variables and MI commands above):

  - MI *cl_ctr_maintenance* (any node, the master propagates it) sets a target node's state *evicted*/*full*/*off*; *cl_ctr_list_members* gains a maintenance column.
  - Script function *cl_ctr_set_maintenance()* (a verb - an action) for a node to put itself in or out of maintenance from the routing logic.
  - Read-only variables *$cl_ctr_maintenance* (this node: none/evicted/full) and *$cl_ctr_node_maint(cluster_id, node_id)* (any peer); *$cl_ctr_role* gains a *maintenance* value.
  - Event *E_CL_CTR_MAINTENANCE* raised on every node when any member's maintenance state changes, so an *event_route* can react (e.g. shift dispatcher weights).
- **Statistics** — module statistics (current role, member count, master changes, nodes joined/left, JOIN_REJECTs, decrypt failures, config mismatches, split-brain merges) exposed via *get_statistics* and monitoring exporters.
- **Events** — events raised on state transitions (became master, demoted, node joined/left, split-brain merged, config mismatch, authentication reject), named `E_CL_CTR_*` and consumable from an *event_route* or any event subscriber transport.
- **IPv6 multicast** — the control plane currently uses IPv4 multicast (groups in *224.0.0.0/4*). Add IPv6 multicast support (*ff00::/8* groups, *AF_INET6* sockets and membership) so the controller can run on IPv6-only or dual-stack deployments.

Read-only script variables for cluster state (*$cl_ctr_role*, *$cl_ctr_is_master*, and the rest) are already available - see [Exported Pseudo-Variables](#exported-pseudo-variables).


## HA Behaviour Tests


The following tests were performed on a three-node cluster (nodes *A*=10.22.23.191, *B*=10.22.23.192, *C*=10.22.23.193) to verify correct failover, tag stability, and no-steal-on-join behaviour. The sharing tag under test is *vip1* in cluster 1. All nodes run with *manage_shtags=1*.

Tag state was queried after each operation via:

```bash
opensips-cli -x mi clusterer_list_shtags
```

### Baseline

All three nodes running. B holds the active tag; A and C are backup.

```opensips
A (10.22.23.191)  svc=active  tag=backup
B (10.22.23.192)  svc=active  tag=active
C (10.22.23.193)  svc=active  tag=backup
```

### Test 1 — Stop the active node

B (active) is stopped. The remaining nodes must elect a new active holder. B must rejoin as backup and must not steal the tag from whichever node became active.

```opensips
# Stop B
A  svc=active  tag=backup
B  svc=inactive tag=(down)
C  svc=active  tag=active   <-- C promoted

# Start B
A  svc=active  tag=backup
B  svc=active  tag=backup   <-- rejoined as backup
C  svc=active  tag=active   <-- C retains active
```

**Result: PASS.** Failover within the dead-node detection window; rejoining node did not steal the active tag.

### Test 2 — Stop a backup node

A (backup) is stopped. The active tag must remain on C without any transition. A must rejoin as backup.

```opensips
# Stop A
A  svc=inactive tag=(down)
B  svc=active  tag=backup
C  svc=active  tag=active   <-- unchanged

# Start A
A  svc=active  tag=backup   <-- rejoined as backup
B  svc=active  tag=backup
C  svc=active  tag=active   <-- still active
```

**Result: PASS.** Removing a backup node causes no tag movement; rejoining node started in backup state.

### Test 3 — Stop both backup nodes

A and B (both backup) are stopped simultaneously. The lone remaining node C must retain the active tag. A and B must rejoin as backup.

```opensips
# Stop A and B
A  svc=inactive tag=(down)
B  svc=inactive tag=(down)
C  svc=active  tag=active   <-- unchanged, lone node

# Start A, then B
A  svc=active  tag=backup   <-- rejoined as backup
B  svc=active  tag=backup   <-- rejoined as backup
C  svc=active  tag=active   <-- still active
```

**Result: PASS.** Active node remained stable while running alone; both rejoining nodes came up in backup state.

### Test 4 — Stop active node and one backup

B (active) and C (backup) are stopped. The sole remaining node A must become active. B and C must rejoin as backup.

```opensips
# Stop B and C
A  svc=active  tag=active   <-- A promoted, now lone node
B  svc=inactive tag=(down)
C  svc=inactive tag=(down)

# Start B
A  svc=active  tag=active   <-- retains active
B  svc=active  tag=backup   <-- rejoined as backup
C  svc=inactive tag=(down)

# Start C
A  svc=active  tag=active   <-- retains active
B  svc=active  tag=backup
C  svc=active  tag=backup   <-- rejoined as backup
```

**Result: PASS.** The surviving node correctly claimed the active tag; each rejoining node started in backup state without challenging the active holder.

### Test 5 — Full cluster restart

All three nodes are stopped (full outage). Nodes are then started one at a time. The first node up must self-elect as active (no peers available to sync from). Subsequent nodes must join as backup and must not steal the active tag.

```opensips
# All stopped
A  svc=inactive tag=(down)
B  svc=inactive tag=(down)
C  svc=inactive tag=(down)

# Start A first
A  svc=active  tag=active   <-- first/lone seed, self-synced
B  svc=inactive tag=(down)
C  svc=inactive tag=(down)

# Start B
A  svc=active  tag=active   <-- retains active
B  svc=active  tag=backup   <-- joined as backup, did not steal
C  svc=inactive tag=(down)

# Start C
A  svc=active  tag=active   <-- retains active
B  svc=active  tag=backup
C  svc=active  tag=backup   <-- joined as backup, did not steal
```

**Result: PASS.** The first node to start elected itself active and no spurious sync errors were logged. Each subsequent node joined as backup without challenging the active holder.

### Test 6 — Multiple clusters over one BIN socket

Two controller clusters (*id=1* and *id=2*) are configured on all three nodes. Each cluster has its own multicast endpoint (a distinct port is required - two clusters on the same multicast address:port are rejected at startup with *duplicate multicast*), but both advertise the *same* BIN socket (*bin:IP:3857*). Each cluster must form independently and its replication must stay isolated over the shared socket.

```opensips
modparam("clusterer", "cluster_options", "cluster_id=1, use_controller=1")
modparam("clusterer", "cluster_options", "cluster_id=2, use_controller=1")
modparam("clusterer_controller", "cluster",
    "id=1,multicast=239.0.90.1:3333,bin_socket=bin:IP:3857")
modparam("clusterer_controller", "cluster",
    "id=2,multicast=239.0.90.1:3334,bin_socket=bin:IP:3857")

# both clusters converge, each with its own master/backup/member roles;
# clusterer_list shows cluster 1 and cluster 2 both using bin:IP:3857
```

**Result: PASS.** Both clusters formed independently (each `member_count=3` with consistent roles), the BIN links of both were `Up` over the single shared socket, and there were zero decrypt / cross-talk / foreign-cluster errors on any node - the *cluster_id* in each BIN packet keeps the two clusters' replication traffic separate. A control test confirmed that configuring both clusters on the same multicast address:port is refused at startup.

### Summary

| Test | Scenario | Result |
|---|---|---|
| 1 | Stop active node; rejoin | PASS |
| 2 | Stop backup node; rejoin | PASS |
| 3 | Stop both backups simultaneously; rejoin | PASS |
| 4 | Stop active + one backup; rejoin | PASS |
| 5 | Full cluster restart; sequential startup | PASS |
| 6 | Two clusters sharing one BIN socket (distinct multicast) | PASS |

In all five failover tests (1–5): exactly one node held the active sharing tag at all times (including during the failure window), and no rejoining node stole the active tag from the current holder. Test 6 additionally confirmed that two clusters can share a single BIN socket with fully isolated replication.

<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
