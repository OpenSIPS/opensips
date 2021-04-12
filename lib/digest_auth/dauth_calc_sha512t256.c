/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2011 VoIP Embedded Inc.
 * Copyright (C) 2013 OpenSIPS Solutions
 * Copyright (C) 2020 Maksym Sobolyev
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * Registrant OpenSIPS-module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <ctype.h>
#include <string.h>

#include <openssl/evp.h>

#include "../../str.h"
#include "../../parser/digest/digest_parser.h"
#include "../../lib/dassert.h"

#include "dauth_calc_sha512t256.h"
#include "digest_auth.h"
#include "dauth_calc.h"
#include "dauth_hexops.h"

#define SHA512t256_Init(ctxpp) { \
	*(ctxpp) = EVP_MD_CTX_new(); \
	if (*(ctxpp) == NULL) \
		return -1; \
	if (EVP_DigestInit_ex(*(ctxpp), EVP_sha512_256(), NULL) != 1) { \
		EVP_MD_CTX_free(*(ctxpp)); \
		return -1; \
	} \
}

#define SHA512t256_Update(ctxpp, m, mlen) { \
	if (EVP_DigestUpdate(*(ctxpp), (m), (mlen)) != 1) { \
		EVP_MD_CTX_free(*(ctxpp)); \
		return -1; \
	} \
}

#define SHA512t256_Final(buf, ctxpp) { \
	unsigned int olen = 0; \
	if (EVP_DigestFinal_ex(*(ctxpp), (buf), &olen) != 1) { \
		EVP_MD_CTX_free(*(ctxpp)); \
		return -1; \
	} \
	DASSERT(olen == HASHLEN_SHA512t256); \
	EVP_MD_CTX_free(*(ctxpp)); \
	*(ctxpp) = NULL; \
}

/*
 * calculate H(A1)
 */
static int digest_calc_HA1(const struct digest_auth_credential *crd,
    HASHHEX *sess_key)
{
	EVP_MD_CTX *Sha512t256Ctx;
	HASH_SHA512t256 HA1;

	SHA512t256_Init(&Sha512t256Ctx);
	SHA512t256_Update(&Sha512t256Ctx, crd->user.s, crd->user.len);
	SHA512t256_Update(&Sha512t256Ctx, ":", 1);
	SHA512t256_Update(&Sha512t256Ctx, crd->realm.s, crd->realm.len);
	SHA512t256_Update(&Sha512t256Ctx, ":", 1);
	SHA512t256_Update(&Sha512t256Ctx, crd->passwd.s, crd->passwd.len);
	SHA512t256_Final((unsigned char *)HA1, &Sha512t256Ctx);
	cvt_hex128(HA1, sess_key->SHA512t256, HASHLEN_SHA512t256, HASHHEXLEN_SHA512t256);

	return 0;

}

static int digest_calc_HA1sess(const str_const *nonce, const str_const *cnonce,
    HASHHEX *sess_key)
{
	EVP_MD_CTX *Sha512t256Ctx;
	HASH_SHA512t256 HA1;

	SHA512t256_Init(&Sha512t256Ctx);
	SHA512t256_Update(&Sha512t256Ctx, sess_key->SHA512t256, HASHHEXLEN_SHA512t256);
	SHA512t256_Update(&Sha512t256Ctx, ":", 1);
	SHA512t256_Update(&Sha512t256Ctx, nonce->s, nonce->len);
	SHA512t256_Update(&Sha512t256Ctx, ":", 1);
	SHA512t256_Update(&Sha512t256Ctx, cnonce->s, cnonce->len);
	SHA512t256_Final((unsigned char *)HA1, &Sha512t256Ctx);
	cvt_hex128(HA1, sess_key->SHA512t256, HASHLEN_SHA512t256, HASHHEXLEN_SHA512t256);

        return 0;

}

/*
 * calculate H(A2)
 */
static int digest_calc_HA2(const str_const *msg_body, const str_const *method,
    const str_const *uri, int auth_int, HASHHEX *HA2Hex)
{
	EVP_MD_CTX *Sha512t256Ctx;
	HASH_SHA512t256 HA2;
	HASH_SHA512t256 HENTITY;
	HASHHEX_SHA512t256 HENTITYHex;

	if (auth_int) {
		SHA512t256_Init(&Sha512t256Ctx);
		SHA512t256_Update(&Sha512t256Ctx, msg_body->s, msg_body->len);
		SHA512t256_Final((unsigned char *)HENTITY, &Sha512t256Ctx);
		cvt_hex128(HENTITY, HENTITYHex, HASHLEN_SHA512t256, HASHHEXLEN_SHA512t256);
	}

	SHA512t256_Init(&Sha512t256Ctx);
	SHA512t256_Update(&Sha512t256Ctx, method->s, method->len);
	SHA512t256_Update(&Sha512t256Ctx, ":", 1);
	SHA512t256_Update(&Sha512t256Ctx, uri->s, uri->len);

	if (auth_int)
	{
		SHA512t256_Update(&Sha512t256Ctx, ":", 1);
		SHA512t256_Update(&Sha512t256Ctx, HENTITYHex, HASHHEXLEN_SHA512t256);
	};

	SHA512t256_Final((unsigned char *)HA2, &Sha512t256Ctx);
	cvt_hex128(HA2, HA2Hex->SHA512t256, HASHLEN_SHA512t256, HASHHEXLEN_SHA512t256);
	return 0;
}

/*
 * calculate request-digest/response-digest as per HTTP Digest spec
 */
static int _digest_calc_response(const HASHHEX *ha1, const HASHHEX *ha2,
    const str_const *nonce, const str_const *qop_val, const str_const *nc,
    const str_const *cnonce, struct digest_auth_response *response)
{
	EVP_MD_CTX *Sha512t256Ctx;

	SHA512t256_Init(&Sha512t256Ctx);
	SHA512t256_Update(&Sha512t256Ctx, ha1->SHA512t256, HASHHEXLEN_SHA512t256);
	SHA512t256_Update(&Sha512t256Ctx, ":", 1);
	SHA512t256_Update(&Sha512t256Ctx, nonce->s, nonce->len);
	SHA512t256_Update(&Sha512t256Ctx, ":", 1);

	if (qop_val && qop_val->s && qop_val->len != 0)
	{
		SHA512t256_Update(&Sha512t256Ctx, nc->s, nc->len);
		SHA512t256_Update(&Sha512t256Ctx, ":", 1);
		SHA512t256_Update(&Sha512t256Ctx, cnonce->s, cnonce->len);
		SHA512t256_Update(&Sha512t256Ctx, ":", 1);
		SHA512t256_Update(&Sha512t256Ctx, qop_val->s, qop_val->len);
		SHA512t256_Update(&Sha512t256Ctx, ":", 1);
	};
	SHA512t256_Update(&Sha512t256Ctx, ha2->SHA512t256, HASHHEXLEN_SHA512t256);
	SHA512t256_Final((unsigned char *)response->RespHash.SHA512t256, &Sha512t256Ctx);
	return 0;
}

static int digest_calc_response(const HASHHEX *ha1, const HASHHEX *ha2,
    const str_const *nonce, const str_const *qop_val, const str_const *nc,
    const str_const *cnonce, struct digest_auth_response *response)
{
	int rval;

	rval = _digest_calc_response(ha1, ha2, nonce, qop_val, nc, cnonce, response);
	response->digest_calc = &sha512t256_digest_calc;
	return rval;
}

static int digest_calc_response_s(const HASHHEX *ha1, const HASHHEX *ha2,
    const str_const *nonce, const str_const *qop_val, const str_const *nc,
    const str_const *cnonce, struct digest_auth_response *response)
{
	int rval;

	rval = _digest_calc_response(ha1, ha2, nonce, qop_val, nc, cnonce, response);
	response->digest_calc = &sha512t256sess_digest_calc;
	return rval;
}

static char *response_hash_fill(const struct digest_auth_response *response, char *hex, int len)
{
	DASSERT(len >= HASHHEXLEN_SHA512t256);

	cvt_hex128(response->RespHash.SHA512t256, hex, HASHLEN_SHA512t256, HASHHEXLEN_SHA512t256);
	return hex;
}

static int response_hash_bcmp(const struct digest_auth_response *response, const str_const *hex)
{
	if (hex->len != HASHHEXLEN_SHA512t256)
		return 1;

	return bcmp_hex128(response->RespHash.SHA512t256, hex->s, HASHLEN_SHA512t256);
}

const struct digest_auth_calc sha512t256_digest_calc = {
	.HA1 = digest_calc_HA1,
	.HA1sess = NULL,
	.HA2 = digest_calc_HA2,
	.response = &digest_calc_response,
	.response_hash_bcmp = response_hash_bcmp,
	.response_hash_fill = response_hash_fill,
	.algorithm_val = str_const_init(ALG_SHA512_256_STR),
	.HASHLEN = HASHLEN_SHA512t256,
	.HASHHEXLEN = HASHHEXLEN_SHA512t256
};

const struct digest_auth_calc sha512t256sess_digest_calc = {
	.HA1 = digest_calc_HA1,
	.HA1sess = digest_calc_HA1sess,
	.HA2 = digest_calc_HA2,
	.response = &digest_calc_response_s,
	.response_hash_bcmp = response_hash_bcmp,
	.response_hash_fill = response_hash_fill,
	.algorithm_val = str_const_init(ALG_SHA512_256SESS_STR),
	.HASHLEN = HASHLEN_SHA512t256,
	.HASHHEXLEN = HASHHEXLEN_SHA512t256
};
