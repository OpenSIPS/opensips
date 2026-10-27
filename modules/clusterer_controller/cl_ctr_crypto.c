/*
 * clusterer_controller - key derivation, AEAD and the Noise_NNpsk0 join handshake
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

/* =========================================================================
 * Packet encryption / decryption (AEAD)
 *
 * Every packet is fully encrypted and authenticated with XChaCha20-Poly1305
 * (libsodium).  A fresh random nonce per packet ensures that even identical
 * payloads produce different ciphertext.
 *
 * The plaintext carries a 4-byte sequence number, the sender's 8-byte
 * incarnation and its 4-byte address.  Receivers run session-key packets
 * through a sliding window per sealed sender and plane that accepts each sequence number once, started
 * afresh when the sender's incarnation changes, when it is first learned and
 * when this node takes a new key (see cl_ctr_replay_check() in cl_ctr.h).
 * Bootstrap-key packets (CL_CTR_BOOTSTRAP_MAGIC) have no window: a KEY_GRANT
 * is bound to its JOIN_REQ by the Noise handshake, a JOIN_REJECT by the
 * nonce it echoes, and a beacon is checked before it is ranked.
 *
 * Wire layout:
 *   [magic 2B][cluster_id 2B][cluster uuid 16B][nonce 24B][ciphertext][tag 16B]
 * Plaintext:
 *   [type 1B][seq 4B][incarnation 8B][sender 4B][payload]
 * ========================================================================= */

/* cl_ctr_random_bytes() - fill buf with cryptographically secure random bytes
 * (libsodium's randombytes draws from the kernel CSPRNG). */
int cl_ctr_random_bytes(unsigned char *buf, size_t len)
{
    randombytes_buf(buf, len);
    return 0;
}

/* RFC 5869 HKDF-SHA256 built on libsodium's HMAC-SHA256 (libsodium 1.0.18 has
 * no native HKDF; crypto_auth_hmacsha256_init accepts any key length).  Every
 * use in this module needs exactly 32 output bytes (= HashLen), so the expand
 * phase is a single iteration: OKM = HMAC(PRK, info || 0x01). */
int cl_ctr_hkdf_sha256(const unsigned char *ikm,  size_t ikm_len,
                           const unsigned char *salt, size_t salt_len,
                           const char          *info,
                           unsigned char        out[32])
{
    crypto_auth_hmacsha256_state st;
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    static const unsigned char zeros[crypto_auth_hmacsha256_BYTES];
    const unsigned char ctr = 0x01;
    size_t info_len = info ? strlen(info) : 0;

    /* extract: PRK = HMAC(salt, IKM); an absent salt is HashLen zero bytes */
    if (crypto_auth_hmacsha256_init(&st, salt_len ? salt : zeros,
                                    salt_len ? salt_len : sizeof(zeros)) != 0)
        return -1;
    crypto_auth_hmacsha256_update(&st, ikm, (unsigned long long)ikm_len);
    crypto_auth_hmacsha256_final(&st, prk);

    /* expand: T(1) = HMAC(PRK, info || 0x01) */
    if (crypto_auth_hmacsha256_init(&st, prk, sizeof(prk)) != 0)
        return -1;
    if (info_len)
        crypto_auth_hmacsha256_update(&st, (const unsigned char *)info,
                                      (unsigned long long)info_len);
    crypto_auth_hmacsha256_update(&st, &ctr, 1);
    crypto_auth_hmacsha256_final(&st, out);
    return 0;
}

int cl_ctr_gen_ecdh_keypair(unsigned char *privkey, unsigned char *pubkey)
{
    randombytes_buf(privkey, CL_CTR_PUBKEY_SZ);
    if (crypto_scalarmult_base(pubkey, privkey) != 0) {
        LM_ERR("clusterer_controller: X25519 keygen failed\n");
        return -1;
    }
    return 0;
}

/* =========================================================================
 * Noise_NNpsk0_25519_ChaChaPoly_SHA256 - the join handshake.
 *
 * NNpsk0: ephemeral-only, mutual authentication via a pre-shared key (the
 * Argon2id bootstrap key), forward secrecy via the ephemeral-ephemeral DH.
 *   -> psk, e         (JOIN_REQ carries msg 1)
 *   <- e, ee          (KEY_GRANT carries msg 2, whose AEAD payload = master_salt)
 * Both endpoints run this identical code, so byte-for-byte interop with other
 * Noise libraries is not required; the module verifies self-consistency and the
 * security properties in its own test harness.  See RFC "The Noise Protocol
 * Framework" rev 34.  HASHLEN = 32 (SHA-256), DHLEN = 32 (X25519).
 * ========================================================================= */
#define CL_CTR_NOISE_PROTO "Noise_NNpsk0_25519_ChaChaPoly_SHA256"

static void cl_ctr_hmac256(const unsigned char *key, size_t keylen,
                       const unsigned char *data, size_t datalen,
                       unsigned char out[CL_CTR_NOISE_HASHLEN])
{
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, keylen);
    crypto_auth_hmacsha256_update(&st, data, datalen);
    crypto_auth_hmacsha256_final(&st, out);
}

/* Noise HKDF: chained HMAC outputs (num_outputs of 1..3, each HASHLEN bytes). */
static void cl_ctr_noise_hkdf(const unsigned char ck[CL_CTR_NOISE_HASHLEN],
                          const unsigned char *ikm, size_t ikm_len, int num_outputs,
                          unsigned char o1[CL_CTR_NOISE_HASHLEN],
                          unsigned char o2[CL_CTR_NOISE_HASHLEN],
                          unsigned char o3[CL_CTR_NOISE_HASHLEN])
{
    unsigned char tempkey[CL_CTR_NOISE_HASHLEN], buf[CL_CTR_NOISE_HASHLEN + 1];
    cl_ctr_hmac256(ck, CL_CTR_NOISE_HASHLEN, ikm, ikm_len, tempkey);   /* extract */
    buf[0] = 0x01;
    cl_ctr_hmac256(tempkey, CL_CTR_NOISE_HASHLEN, buf, 1, o1);
    if (num_outputs >= 2) {
        memcpy(buf, o1, CL_CTR_NOISE_HASHLEN); buf[CL_CTR_NOISE_HASHLEN] = 0x02;
        cl_ctr_hmac256(tempkey, CL_CTR_NOISE_HASHLEN, buf, CL_CTR_NOISE_HASHLEN + 1, o2);
    }
    if (num_outputs >= 3) {
        memcpy(buf, o2, CL_CTR_NOISE_HASHLEN); buf[CL_CTR_NOISE_HASHLEN] = 0x03;
        cl_ctr_hmac256(tempkey, CL_CTR_NOISE_HASHLEN, buf, CL_CTR_NOISE_HASHLEN + 1, o3);
    }
    sodium_memzero(tempkey, sizeof tempkey);
}

static void cl_ctr_cs_nonce(uint64_t n, unsigned char out[12])
{
    int i;
    memset(out, 0, 4);                          /* 32 bits of zeros            */
    for (i = 0; i < 8; i++) out[4 + i] = (unsigned char)(n >> (8 * i)); /* LE64 */
}
static int cl_ctr_cs_encrypt(cl_ctr_cipherstate_t *cs, const unsigned char *ad, size_t ad_len,
                         const unsigned char *pt, size_t pt_len, unsigned char *ct)
{
    unsigned char nonce[12]; unsigned long long clen = 0;
    /* pt may legitimately be NULL for an empty payload (Noise msg 1 sends
     * one); memcpy() is nonnull even for a zero length, so guard it. */
    if (!cs->has_key) { if (pt_len) memcpy(ct, pt, pt_len); return (int)pt_len; }
    cl_ctr_cs_nonce(cs->n, nonce);
    crypto_aead_chacha20poly1305_ietf_encrypt(ct, &clen, pt, pt_len,
                                              ad, ad_len, NULL, nonce, cs->k);
    cs->n++;
    return (int)clen;
}
static int cl_ctr_cs_decrypt(cl_ctr_cipherstate_t *cs, const unsigned char *ad, size_t ad_len,
                         const unsigned char *ct, size_t ct_len, unsigned char *pt)
{
    unsigned char nonce[12]; unsigned long long plen = 0;
    if (!cs->has_key) { if (ct_len) memcpy(pt, ct, ct_len); return (int)ct_len; }
    cl_ctr_cs_nonce(cs->n, nonce);
    if (crypto_aead_chacha20poly1305_ietf_decrypt(pt, &plen, NULL, ct, ct_len,
                                                  ad, ad_len, nonce, cs->k) != 0)
        return -1;
    cs->n++;
    return (int)plen;
}

static void cl_ctr_ss_mixhash(cl_ctr_symstate_t *s, const unsigned char *data, size_t len)
{
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, s->h, CL_CTR_NOISE_HASHLEN);
    crypto_hash_sha256_update(&st, data, len);
    crypto_hash_sha256_final(&st, s->h);
}
static void cl_ctr_ss_init(cl_ctr_symstate_t *s)
{
    size_t nl = strlen(CL_CTR_NOISE_PROTO);           /* <= HASHLEN, so pad it */
    memset(s->h, 0, CL_CTR_NOISE_HASHLEN);
    memcpy(s->h, CL_CTR_NOISE_PROTO, nl);
    memcpy(s->ck, s->h, CL_CTR_NOISE_HASHLEN);
    s->cs.has_key = 0; s->cs.n = 0;
}
static void cl_ctr_ss_mixkey(cl_ctr_symstate_t *s, const unsigned char *ikm, size_t ikm_len)
{
    unsigned char o1[CL_CTR_NOISE_HASHLEN], o2[CL_CTR_NOISE_HASHLEN], o3[CL_CTR_NOISE_HASHLEN];
    cl_ctr_noise_hkdf(s->ck, ikm, ikm_len, 2, o1, o2, o3);
    memcpy(s->ck, o1, CL_CTR_NOISE_HASHLEN);
    memcpy(s->cs.k, o2, 32); s->cs.n = 0; s->cs.has_key = 1;
}
static void cl_ctr_ss_mixkeyhash(cl_ctr_symstate_t *s, const unsigned char *ikm, size_t ikm_len)
{
    unsigned char o1[CL_CTR_NOISE_HASHLEN], o2[CL_CTR_NOISE_HASHLEN], o3[CL_CTR_NOISE_HASHLEN];
    cl_ctr_noise_hkdf(s->ck, ikm, ikm_len, 3, o1, o2, o3);
    memcpy(s->ck, o1, CL_CTR_NOISE_HASHLEN);
    cl_ctr_ss_mixhash(s, o2, CL_CTR_NOISE_HASHLEN);
    memcpy(s->cs.k, o3, 32); s->cs.n = 0; s->cs.has_key = 1;
}
static int cl_ctr_ss_encrypt_hash(cl_ctr_symstate_t *s, const unsigned char *pt, size_t pt_len,
                              unsigned char *ct)
{
    int cl = cl_ctr_cs_encrypt(&s->cs, s->h, CL_CTR_NOISE_HASHLEN, pt, pt_len, ct);
    cl_ctr_ss_mixhash(s, ct, cl);
    return cl;
}
static int cl_ctr_ss_decrypt_hash(cl_ctr_symstate_t *s, const unsigned char *ct, size_t ct_len,
                              unsigned char *pt)
{
    int pl = cl_ctr_cs_decrypt(&s->cs, s->h, CL_CTR_NOISE_HASHLEN, ct, ct_len, pt);
    if (pl < 0) return -1;
    cl_ctr_ss_mixhash(s, ct, ct_len);
    return pl;
}

/* Initiator: write msg 1 (-> psk, e).  Stores e keypair in @e_priv for msg 2. */
int cl_ctr_noise_write1(cl_ctr_symstate_t *s, unsigned char e_priv[32],
                           const unsigned char psk[32],
                           const unsigned char *payload, size_t pl_len,
                           unsigned char *out)
{
    unsigned char e_pub[32];
    cl_ctr_ss_init(s);
    cl_ctr_ss_mixkeyhash(s, psk, 32);                 /* psk token (psk0) */
    randombytes_buf(e_priv, 32); crypto_scalarmult_base(e_pub, e_priv); /* e */
    memcpy(out, e_pub, 32); cl_ctr_ss_mixhash(s, e_pub, 32); cl_ctr_ss_mixkey(s, e_pub, 32);
    return 32 + cl_ctr_ss_encrypt_hash(s, payload, pl_len, out + 32);
}
/* Responder: read msg 1, then write msg 2 (<- e, ee) with @payload.  One-shot,
 * so no responder state is retained afterwards.  @out gets msg 2. */
int cl_ctr_noise_respond(const unsigned char psk[32],
                            const unsigned char *msg1, size_t msg1_len,
                            const unsigned char *payload, size_t pl_len,
                            unsigned char *out)
{
    cl_ctr_symstate_t s;
    unsigned char re[32], e_priv[32], e_pub[32], dh[32], scratch[64];
    if (msg1_len < 32) return -1;
    cl_ctr_ss_init(&s);
    cl_ctr_ss_mixkeyhash(&s, psk, 32);
    memcpy(re, msg1, 32); cl_ctr_ss_mixhash(&s, re, 32); cl_ctr_ss_mixkey(&s, re, 32);
    if (cl_ctr_ss_decrypt_hash(&s, msg1 + 32, msg1_len - 32, scratch) < 0)
        return -1;                                /* bad msg 1 (wrong psk/tamper) */
    randombytes_buf(e_priv, 32); crypto_scalarmult_base(e_pub, e_priv);
    memcpy(out, e_pub, 32); cl_ctr_ss_mixhash(&s, e_pub, 32); cl_ctr_ss_mixkey(&s, e_pub, 32);
    if (crypto_scalarmult(dh, e_priv, re) != 0) return -1;   /* ee */
    cl_ctr_ss_mixkey(&s, dh, 32);
    return 32 + cl_ctr_ss_encrypt_hash(&s, payload, pl_len, out + 32);
}
/* Initiator: read msg 2 (-> e, ee), recover @payload (master_salt). */
int cl_ctr_noise_read2(cl_ctr_symstate_t *s, const unsigned char e_priv[32],
                          const unsigned char *msg2, size_t msg2_len,
                          unsigned char *payload_out)
{
    unsigned char re2[32], dh[32], scratch[64];
    int pl;
    /* decrypt into a scratch large enough for the max ciphertext (mirrors
     * the scratch[64] on the write2 side), then hand back exactly the
     * master_salt.  Bounding the decrypt output here keeps a malformed or
     * oversized KEY_GRANT from ever writing past payload_out. */
    if (msg2_len < 32 || msg2_len - 32 > sizeof scratch) return -1;
    memcpy(re2, msg2, 32); cl_ctr_ss_mixhash(s, re2, 32); cl_ctr_ss_mixkey(s, re2, 32);
    if (crypto_scalarmult(dh, e_priv, re2) != 0) return -1;
    cl_ctr_ss_mixkey(s, dh, 32);
    pl = cl_ctr_ss_decrypt_hash(s, msg2 + 32, msg2_len - 32, scratch);
    if (pl != CL_CTR_MASTER_SALT_SZ) return -1;
    memcpy(payload_out, scratch, CL_CTR_MASTER_SALT_SZ);
    return pl;
}

/**
 * cl_ctr_derive_session_key() - derive group key from password + master_salt.
 * Reads master_salt from cl->peers->master_salt (shm, caller holds write lock).
 * Stores result in cl->session_key (worker-local cache).
 * Must be called with cl->peers->lock held for WRITE.
 */
int cl_ctr_derive_session_key(cl_ctr_cluster_t *cl)
{
    int i;
    unsigned char nk[sizeof(cl->session_key)];
    size_t pass_len = strlen(cl->password);
    if (cl_ctr_hkdf_sha256((unsigned char *)cl->password, pass_len,
                        cl->peers->master_salt, CL_CTR_MASTER_SALT_SZ,
                        "cl_ctr_session", nk) < 0) {
        LM_ERR("clusterer_controller: [cluster %d] session key derivation failed\n",
               cl->cluster_id);
        return -1;
    }
    /* The key is kept across master changes, so most derivations - a
     * KEY_GRANT to a member re-joining, a re-key after a mismatch - produce
     * the key already in use.  Then nothing changes: resetting the replay
     * windows would accept replays of packets sealed with this very key, and
     * this node's own sequence never restarts within an incarnation - peers
     * keep one window per (sender, incarnation), not per key, and refused
     * everything it sent as a replay until the counter caught up again,
     * which cut it off as silently as a dead link.  A new key resets the
     * receive windows (packets under the old key no longer authenticate,
     * and an older build restarts its sequence with a new key). */
    if (cl->have_session_key &&
        sodium_memcmp(nk, cl->session_key, sizeof(nk)) == 0) {
        sodium_memzero(nk, sizeof(nk));
        return 0;
    }
    memcpy(cl->session_key, nk, sizeof(nk));
    sodium_memzero(nk, sizeof(nk));
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_replay_reset(&cl->peers->entries[i].replay);
        cl_ctr_replay_reset(&cl->peers->entries[i].replay_consumer);
    }
    cl->have_session_key = 1;   /* a valid group key now exists */
    /* The key just changed, so any queued retransmit is now stale. */
    cl_ctr_retx_flush(cl);
    return 0;
}


/**
 * cl_ctr_password_entropy_bits() - conservative estimate of a password's entropy.
 * bits ~= length * floor(log2(charset)), where charset is the union of the
 * character classes present.  floor() makes it a slight under-estimate, so the
 * weak-password warning errs toward firing.  No libm dependency.
 */
static int cl_ctr_password_entropy_bits(const char *p)
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
 * cl_ctr_derive_key() - derive the 32-byte bootstrap (admission) key from the
 * shared password.  Used only for the join handshake (JOIN_REQ / KEY_GRANT /
 * JOIN_REJECT); normal traffic uses the ECDH-agreed session key.
 *
 * Uses scrypt (memory-hard) rather than a single SHA-256 so that a password
 * captured from a JOIN packet cannot be brute-forced cheaply offline.  Called
 * once per cluster from mod_init() in the main process before fork, so the
 * ~64 MiB scrypt working set is a transient startup cost only; workers inherit
 * the derived key and never run scrypt.
 */
int cl_ctr_derive_key(cl_ctr_cluster_t *cl)
{
    char salt[64];
    int  saltlen, bits;

    /* Warn on a weak or default admission password.  scrypt raises the cost of
     * each offline guess, but only a high-entropy secret removes the risk. */
    if (strcmp(cl->password, CL_CTR_DEFAULT_PASSWORD) == 0) {
        LM_WARN("clusterer_controller: [cluster %d] using the built-in default "
                "password - set a strong 'password' (e.g. `openssl rand -base64 32`)\n",
                cl->cluster_id);
    } else {
        bits = cl_ctr_password_entropy_bits(cl->password);
        if (bits < CL_CTR_MIN_PASSWORD_BITS)
            LM_WARN("clusterer_controller: [cluster %d] weak password (~%d bits "
                    "of entropy) - an attacker who captures a JOIN packet can "
                    "brute-force it offline; use a long random string, e.g. "
                    "`openssl rand -base64 32`\n", cl->cluster_id, bits);
    }

    /* Per-cluster salt: a fixed domain-separation label plus the multicast
     * address, so the same password on different clusters yields different
     * bootstrap keys.  The salt is public by design - Argon2id's work factor,
     * not salt secrecy, is what defeats brute force.                        */
    saltlen = snprintf(salt, sizeof(salt), "opensips-cl-ctr-bootstrap-v1:%s",
                       cl->multicast_address);
    if (saltlen < 0 || saltlen >= (int)sizeof(salt))
        saltlen = (int)strlen(salt);

    /* Argon2id.  crypto_pwhash needs a fixed-length 16-byte salt, so fold our
     * variable-length domain-separation salt into one with BLAKE2b.           */
    {
        unsigned char salt16[crypto_pwhash_SALTBYTES];
        crypto_generichash(salt16, sizeof(salt16),
                           (const unsigned char *)salt, (size_t)saltlen, NULL, 0);
        if (crypto_pwhash(cl->key, 32,
                          cl->password, strlen(cl->password),
                          salt16, CL_CTR_ARGON2_OPSLIMIT, CL_CTR_ARGON2_MEMLIMIT,
                          crypto_pwhash_ALG_ARGON2ID13) != 0) {
            LM_ERR("clusterer_controller: key derivation (Argon2id) failed for "
                   "cluster %d (out of memory?)\n", cl->cluster_id);
            return -1;
        }
    }
    return 0;
}

/**
 * cl_ctr_encrypt_pkt() - encrypt plaintext in-place and append the Poly1305 tag.
 *
 * On entry:  buf[0..CL_CTR_MAGIC_SZ-1]   = magic (set by caller)
 *            buf[plain_off..]        = plaintext to encrypt; its incarnation
 *                                      field is filled in here
 * On return: buf[CL_CTR_MAGIC_SZ..]      = cleartext cluster_id (BE)
 *            buf[CL_CTR_NONCE_OFF..]     = random nonce
 *            buf[plain_off..]        = ciphertext (same length)
 *            buf[plain_off+plain_len..+CL_CTR_TAG_SZ-1] = Poly1305 tag
 *
 * @return total packet length, or -1 on error
 */
int cl_ctr_encrypt_pkt(char *buf, int plain_off, int plain_len,
                          const unsigned char *key, int cluster_id,
                          const unsigned char *cid)
{
    uint16_t      cid_be = htons((uint16_t)cluster_id);
    unsigned char *inc   = (unsigned char *)buf + plain_off + 1 + CL_CTR_SEQ_SZ;
    static struct in_addr me;            /* my_ip, parsed once */
    int           k;

    memcpy(buf + CL_CTR_MAGIC_SZ, &cid_be, CL_CTR_CLUSTER_ID_SZ);  /* cleartext selector */
    if (cid)
        memcpy(buf + CL_CTR_CID_OFF, cid, CL_CTR_CID_SZ);
    else
        memset(buf + CL_CTR_CID_OFF, 0, CL_CTR_CID_SZ);
    /* Every packet carries this process's incarnation, stamped here - the
     * single path all packets take - so no builder can forget it. */
    for (k = 0; k < CL_CTR_INC_SZ; k++)
        inc[k] = (unsigned char)(cl_ctr_incarnation >> (56 - 8 * k));
    /* ... and who sends it: sealed, the sender's address is what receivers
     * go by (wire version 3) */
    if (!me.s_addr && my_ip && inet_pton(AF_INET, my_ip, &me) != 1)
        me.s_addr = 0;
    memcpy(inc + CL_CTR_INC_SZ, &me.s_addr, CL_CTR_SENDER_SZ);

    /* AAD = cleartext header (magic + cluster_id + cluster uuid): binding it
     * to the tag stops
     * a captured packet being re-stamped with another cluster_id on a shared
     * multicast+password group (cross-cluster injection).  The nonce is the
     * AEAD IV, already bound.  XChaCha20's 192-bit nonce makes random nonces
     * collision-safe outright.                                                */
    {
        unsigned char      nonce[CL_CTR_NONCE_SZ];
        unsigned long long clen = 0;
        randombytes_buf(nonce, CL_CTR_NONCE_SZ);
        memcpy(buf + CL_CTR_NONCE_OFF, nonce, CL_CTR_NONCE_SZ);
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                (unsigned char *)buf + plain_off, &clen,
                (const unsigned char *)buf + plain_off, (unsigned long long)plain_len,
                (const unsigned char *)buf, CL_CTR_AAD_SZ,
                NULL, nonce, key) != 0) {
            LM_ERR("clusterer_controller: XChaCha20-Poly1305 encrypt failed\n");
            return -1;
        }
        return plain_off + (int)clen;   /* clen = plain_len + CL_CTR_TAG_SZ */
    }
}

/**
 * cl_ctr_decrypt_pkt() - authenticate and decrypt a received packet in-place.
 *
 * On entry:  buf = [magic 2B][cluster_id 2B][nonce][ciphertext][tag 16B]
 * On return: buf[CL_CTR_WIRE_HDR_SZ..] = plaintext (type + seq + payload)
 *
 * AAD must match cl_ctr_encrypt_pkt(): the cleartext header (magic, cluster_id
 * and cluster uuid), so
 * a packet re-stamped with another cluster_id fails authentication.
 *
 * @return 0 on success, -1 to drop (wrong key, tampered, or too short)
 */
int cl_ctr_decrypt_pkt(char *buf, ssize_t n, const char *sender_ip,
                          const unsigned char *key, int is_bootstrap)
{
    ssize_t cipher_len = n - CL_CTR_WIRE_HDR_SZ - CL_CTR_TAG_SZ;   /* plaintext length */

    if (cipher_len <= 0) {
	LM_INFO("clusterer_controller: packet from %s too short to decrypt "
	        "(%zd bytes)\n", sender_ip, n);
	return -1;
    }

    {
        unsigned char     *nonce = (unsigned char *)buf + CL_CTR_NONCE_OFF;
        unsigned long long mlen  = 0;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                (unsigned char *)buf + CL_CTR_WIRE_HDR_SZ, &mlen, NULL,
                (const unsigned char *)buf + CL_CTR_WIRE_HDR_SZ,
                (unsigned long long)(cipher_len + CL_CTR_TAG_SZ),
                (const unsigned char *)buf, CL_CTR_AAD_SZ,
                nonce, key) != 0) {
            /* the caller reports a bootstrap failure, once a minute */
            LM_DBG("clusterer_controller: %s packet from %s did not "
                   "decrypt\n", is_bootstrap ? "bootstrap" : "session",
                   sender_ip);
            return -1;
        }
    }
    return 0;
}
