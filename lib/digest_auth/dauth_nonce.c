/*
 * Nonce related functions
 *
 * Copyright (C) 2020 Maksym Sobolyev
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */


#include <assert.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "../../dprint.h"
#include "../../ut.h"
#include "../../parser/digest/digest_parser.h"
#include "../../lib/dassert.h"

#include "dauth_nonce.h"

#define RAND_SECRET_LEN 32
/*
 * Length of nonce string in bytes
 */
#define NONCE_LEN       44

_Static_assert((NONCE_LEN * 6) % 8 == 0, "NONCE_LEN should not be padded");
_Static_assert((NONCE_LEN * 6) / 8 >= RAND_SECRET_LEN, "NONCE_LEN is too small");

struct nonce_context_priv {
	struct nonce_context pub;
	char* sec_rand;
	EVP_CIPHER_CTX *ectx, *dctx;
};

_Static_assert(offsetof(struct nonce_context_priv, pub) == 0,
    "nonce_context_priv.pub has to be the first member");

struct nonce_payload {
	int index;
	uint64_t qop:2;
	uint64_t alg:3;
	uint64_t expires_sec:34;
	uint64_t expires_usec:20;
} __attribute__((__packed__));

_Static_assert(sizeof(struct nonce_payload) <= RAND_SECRET_LEN / 2,
    "struct nonce_payload is too big");
_Static_assert(RAND_SECRET_LEN % sizeof(uint64_t) == 0,
    "RAND_SECRET_LEN is not multiple of sizeof(uint64_t)");

static int Base64Encode(const str_const *message, char* b64buffer);
static int Base64Decode(const str_const *b64message, unsigned char* obuffer);

static void
xor_bufs(unsigned char *rb, const unsigned char *ib1, const unsigned char *ib2,
    int iblen)
{
	uint64_t ebin[iblen / sizeof(uint64_t)];
	int i, j = 0;

	for (i = 0; i < sizeof(ebin); i+= sizeof(uint64_t), j++) {
		uint64_t iw1, iw2;
		memcpy(&iw1, ib1 + i, sizeof(iw1));
		memcpy(&iw2, ib2 + i, sizeof(iw2));
		ebin[j] = iw1 ^ iw2;
	}
	memcpy(rb, ebin, iblen);
}

/*
 * Calculate nonce value
 * Nonce value consists of the expires time (in seconds since 1.1 1970)
 * and a secret phrase
 */
int calc_nonce(const struct nonce_context *pub, char* _nonce,
    const struct nonce_params *npp)
{
	struct nonce_context_priv *self = (typeof(self))pub;
	unsigned char ebin[RAND_SECRET_LEN + 1];
	int rc, elen;
	unsigned char dbin[RAND_SECRET_LEN], *bp;
	unsigned char *riv = dbin;

	rc = RAND_bytes(riv, RAND_SECRET_LEN / 2);
	if (rc != 1)
		return -1;

	bp = dbin + RAND_SECRET_LEN / 2;
	struct nonce_payload npl;
	memset(&npl, 0, sizeof(npl));
	npl.expires_sec = npp->expires.tv_sec;
	npl.expires_usec = npp->expires.tv_nsec / 1000;
	npl.qop = npp->qop;
	npl.alg = npp->alg;
	npl.index = npp->index;
	memcpy(bp, &npl, sizeof(npl));
	bp += sizeof(npl);
	memset(bp, 0, sizeof(dbin) - (bp - dbin));

	bp = dbin + RAND_SECRET_LEN / 2;
	xor_bufs(bp, bp, dbin, RAND_SECRET_LEN / 2);

	elen = 0;
	rc = EVP_EncryptUpdate(self->ectx, ebin, &elen, dbin, sizeof(dbin));
	if (rc != 1 || elen != sizeof(dbin))
		return -1;

	ebin[sizeof(ebin) - 1] = '\0';
	const str_const ebin_str = {.s = (const char *)ebin, .len = sizeof(ebin)};
	rc = Base64Encode(&ebin_str, _nonce);
	if (rc != 0)
		return -1;
	_nonce[NONCE_LEN] = '\0';
	return 0;
}

int decr_nonce(const struct nonce_context *pub, const str_const * _n,
    struct nonce_params *npp)
{
	struct nonce_context_priv *self = (typeof(self))pub;
	unsigned char bin[RAND_SECRET_LEN + 1];
	const unsigned char *bp;
	unsigned char *wbp;
	unsigned char dbin[RAND_SECRET_LEN];
	int rc;

	if (_n->len != NONCE_LEN)
		return -1;
	rc = Base64Decode(_n, bin);
	if (rc != 0 || bin[sizeof(bin) - 1] != '\0')
		return -1;
	int dlen = 0;
	bp = (const unsigned char *)bin;
	rc = EVP_DecryptUpdate(self->dctx, dbin, &dlen, bp, RAND_SECRET_LEN);
	if (rc != 1 || dlen != sizeof(dbin))
		return -1;

	wbp = dbin + RAND_SECRET_LEN / 2;
	xor_bufs(wbp, wbp, dbin, RAND_SECRET_LEN / 2);

	bp = (const unsigned char *)wbp;
	struct nonce_payload npl;
	memcpy(&npl, bp, sizeof(npl));
	if (npl.expires_usec >= 1000000)
		return -1;
	npp->expires.tv_sec = npl.expires_sec;
	npp->expires.tv_nsec = npl.expires_usec * 1000;
	npp->alg = npl.alg;
	npp->qop = npl.qop;
	npp->index = npl.index;
	bp += sizeof(npl);
	int tailbytes = sizeof(dbin) - (bp - dbin);
	if (tailbytes > 0) {
		if (bp[0] != 0)
			return -1;
		if (tailbytes > 1 && bcmp(bp, bp + 1, tailbytes - 1) != 0)
			return -1;
	}
	return 0;
}

#define timespeccmp(tvp, uvp, cmp)                                      \
	(((tvp)->tv_sec == (uvp)->tv_sec) ?                             \
	    ((tvp)->tv_nsec cmp (uvp)->tv_nsec) :                       \
	    ((tvp)->tv_sec cmp (uvp)->tv_sec))

/*
 * Check if a nonce is stale
 */
int is_nonce_stale(const struct nonce_params *npp, int nonce_expire)
{
	struct timespec now;

	if (clock_gettime(CLOCK_REALTIME, &now) != 0)
		return (-1);
	if (timespeccmp(&now, &npp->expires, >=))
		return (1);
	now.tv_sec += nonce_expire;
	if (timespeccmp(&now, &npp->expires, <))
		return 1;
	return 0;
}

int generate_random_secret(struct nonce_context *pub)
{
	struct nonce_context_priv *self = (typeof(self))pub;
	int rc;

	self->sec_rand = (char*)pkg_malloc(RAND_SECRET_LEN);
	if (!self->sec_rand) {
		LM_ERR("no pkg memory left\n");
		goto e0;
	}

	/* the generator is seeded from the core */
	rc = RAND_bytes((unsigned char *)self->sec_rand, RAND_SECRET_LEN);
	if(rc != 1) {
		LM_ERR("RAND_bytes() failed, error = %lu\n", ERR_get_error());
		goto e1;
	}

	pub->secret.s = self->sec_rand;
	pub->secret.len = RAND_SECRET_LEN;

	/*LM_DBG("Generated secret: '%.*s'\n", pub->secret.len, pub->secret.s); */

	return 0;
e1:
	pkg_free(self->sec_rand);
	self->sec_rand = NULL;
e0:
	return (-1);
}

int dauth_noncer_init(struct nonce_context *pub)
{
	struct nonce_context_priv *self = (typeof(self))pub;
	const unsigned char *key;

	key = (unsigned char *)pub->secret.s;
	if (EVP_EncryptInit_ex(self->ectx, EVP_aes_256_ecb(), NULL, key, NULL) != 1) {
		LM_ERR("EVP_EncryptInit_ex() failed\n");
		goto e0;
	}
	DASSERT(EVP_CIPHER_CTX_key_length(self->ectx) == pub->secret.len);
	EVP_CIPHER_CTX_set_padding(self->ectx, 0);
	if (EVP_DecryptInit_ex(self->dctx, EVP_aes_256_ecb(), NULL,  key, NULL) != 1) {
		LM_ERR("EVP_DecryptInit_ex() failed\n");
		goto e0;
	}
	DASSERT(EVP_CIPHER_CTX_key_length(self->dctx) == pub->secret.len);
	EVP_CIPHER_CTX_set_padding(self->dctx, 0);
	return 0;
e0:
	return (-1);
}

#if defined(CLOCK_REALTIME_PRECISE)
#define MYCLOCK_REALTIME CLOCK_REALTIME_PRECISE
#else
#define MYCLOCK_REALTIME CLOCK_REALTIME
#endif
#if defined(CLOCK_MONOTONIC_PRECISE)
#define MYCLOCK_MONOTONIC CLOCK_MONOTONIC_PRECISE
#else
#define MYCLOCK_MONOTONIC CLOCK_MONOTONIC
#endif


void dauth_noncer_reseed(void)
{
	struct {
		pid_t pid;
		struct timespec rtime;
		struct timespec mtime;
        } seed;

	seed.pid = getpid();
	clock_gettime(MYCLOCK_REALTIME, &seed.rtime);
	clock_gettime(MYCLOCK_MONOTONIC, &seed.mtime);

	RAND_add(&seed, sizeof(seed), (double)sizeof(seed) * 0.1);
}

struct nonce_context *dauth_noncer_new(void)
{
	struct nonce_context_priv *self;

	self = pkg_malloc(sizeof(*self));
	if (self == NULL) {
		LM_ERR("no pkg memory left\n");
		goto e0;
	}
	memset(self, 0, sizeof(*self));
	self->ectx = EVP_CIPHER_CTX_new();
	if (self->ectx == NULL) {
		LM_ERR("EVP_CIPHER_CTX_new failed\n");
		goto e1;
	}
	self->dctx = EVP_CIPHER_CTX_new();
	if (self->dctx == NULL) {
		LM_ERR("EVP_CIPHER_CTX_new failed\n");
		goto e2;
	}

	self->pub.nonce_len = NONCE_LEN;
	return &(self->pub);
e2:
	EVP_CIPHER_CTX_free(self->ectx);
e1:
	pkg_free(self);
e0:
	return NULL;
}

void dauth_noncer_dtor(struct nonce_context *pub)
{
	struct nonce_context_priv *self = (typeof(self))pub;

	if (self->sec_rand != NULL)
		pkg_free(self->sec_rand);
	if (self->dctx != NULL)
		EVP_CIPHER_CTX_free(self->dctx);
	if (self->ectx != NULL)
		EVP_CIPHER_CTX_free(self->ectx);
	pkg_free(self);
}

static int Base64Encode(const str_const *message, char* b64buffer)
{
	int rval;

	rval = EVP_EncodeBlock((unsigned char *)b64buffer, (const unsigned char *)message->s,
	    message->len);
	return (rval == NONCE_LEN) ? 0 : -1;
}

static int Base64Decode(const str_const *b64message, unsigned char* obuffer)
{
        int rval;

        rval = EVP_DecodeBlock(obuffer, (const unsigned char *)b64message->s,
            b64message->len);
        return (rval == (RAND_SECRET_LEN + 1)) ? 0 : -1;
}
