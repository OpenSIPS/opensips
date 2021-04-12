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

#include <openssl/sha.h>

#include "../../str.h"
#include "../../parser/digest/digest_parser.h"
#include "../../lib/dassert.h"

#include "dauth_calc_sha256.h"
#include "digest_auth.h"
#include "dauth_calc.h"
#include "dauth_hexops.h"

/*
 * calculate H(A1)
 */
static int digest_calc_HA1(const struct digest_auth_credential *crd,
    HASHHEX *sess_key)
{
	SHA256_CTX Sha256Ctx;
	HASH_SHA256 HA1;

	SHA256_Init(&Sha256Ctx);
	SHA256_Update(&Sha256Ctx, crd->user.s, crd->user.len);
	SHA256_Update(&Sha256Ctx, ":", 1);
	SHA256_Update(&Sha256Ctx, crd->realm.s, crd->realm.len);
	SHA256_Update(&Sha256Ctx, ":", 1);
	SHA256_Update(&Sha256Ctx, crd->passwd.s, crd->passwd.len);
	SHA256_Final((unsigned char *)HA1, &Sha256Ctx);
	cvt_hex128(HA1, sess_key->SHA256, HASHLEN_SHA256, HASHHEXLEN_SHA256);

	return 0;

}

static int digest_calc_HA1sess(const str_const *nonce, const str_const *cnonce,
    HASHHEX *sess_key)
{
	SHA256_CTX Sha256Ctx;
	HASH_SHA256 HA1;

	SHA256_Init(&Sha256Ctx);
	SHA256_Update(&Sha256Ctx, sess_key->SHA256, HASHHEXLEN_SHA256);
	SHA256_Update(&Sha256Ctx, ":", 1);
	SHA256_Update(&Sha256Ctx, nonce->s, nonce->len);
	SHA256_Update(&Sha256Ctx, ":", 1);
	SHA256_Update(&Sha256Ctx, cnonce->s, cnonce->len);
	SHA256_Final((unsigned char *)HA1, &Sha256Ctx);
	cvt_hex128(HA1, sess_key->SHA256, HASHLEN_SHA256, HASHHEXLEN_SHA256);

        return 0;
}

/*
 * calculate H(A2)
 */
static int digest_calc_HA2(const str_const *msg_body, const str_const *method,
    const str_const *uri, int auth_int, HASHHEX *HA2Hex)
{
	SHA256_CTX Sha256Ctx;
	HASH_SHA256 HA2;
	HASH_SHA256 HENTITY;
	HASHHEX_SHA256 HENTITYHex;

	if (auth_int) {
		SHA256_Init(&Sha256Ctx);
		SHA256_Update(&Sha256Ctx, msg_body->s, msg_body->len);
		SHA256_Final((unsigned char *)HENTITY, &Sha256Ctx);
		cvt_hex128(HENTITY, HENTITYHex, HASHLEN_SHA256, HASHHEXLEN_SHA256);
	}

	SHA256_Init(&Sha256Ctx);
	SHA256_Update(&Sha256Ctx, method->s, method->len);
	SHA256_Update(&Sha256Ctx, ":", 1);
	SHA256_Update(&Sha256Ctx, uri->s, uri->len);

	if (auth_int)
	{
		SHA256_Update(&Sha256Ctx, ":", 1);
		SHA256_Update(&Sha256Ctx, HENTITYHex, HASHHEXLEN_SHA256);
	};

	SHA256_Final((unsigned char *)HA2, &Sha256Ctx);
	cvt_hex128(HA2, HA2Hex->SHA256, HASHLEN_SHA256, HASHHEXLEN_SHA256);
	return 0;
}

/*
 * calculate request-digest/response-digest as per HTTP Digest spec
 */
static int _digest_calc_response(const HASHHEX *ha1, const HASHHEX *ha2,
    const str_const *nonce, const str_const *qop_val, const str_const *nc,
    const str_const *cnonce, struct digest_auth_response *response)
{
	SHA256_CTX Sha256Ctx;

	SHA256_Init(&Sha256Ctx);
	SHA256_Update(&Sha256Ctx, ha1->SHA256, HASHHEXLEN_SHA256);
	SHA256_Update(&Sha256Ctx, ":", 1);
	SHA256_Update(&Sha256Ctx, nonce->s, nonce->len);
	SHA256_Update(&Sha256Ctx, ":", 1);

	if (qop_val && qop_val->s && qop_val->len != 0)
	{
		SHA256_Update(&Sha256Ctx, nc->s, nc->len);
		SHA256_Update(&Sha256Ctx, ":", 1);
		SHA256_Update(&Sha256Ctx, cnonce->s, cnonce->len);
		SHA256_Update(&Sha256Ctx, ":", 1);
		SHA256_Update(&Sha256Ctx, qop_val->s, qop_val->len);
		SHA256_Update(&Sha256Ctx, ":", 1);
	};
	SHA256_Update(&Sha256Ctx, ha2->SHA256, HASHHEXLEN_SHA256);
	SHA256_Final((unsigned char *)response->RespHash.SHA256, &Sha256Ctx);
	return 0;
}

static int digest_calc_response(const HASHHEX *ha1, const HASHHEX *ha2,
    const str_const *nonce, const str_const *qop_val, const str_const *nc,
    const str_const *cnonce, struct digest_auth_response *response)
{
	int rval;

	rval = _digest_calc_response(ha1, ha2, nonce, qop_val, nc, cnonce, response);
	response->digest_calc = &sha256_digest_calc;
	return rval;
}

static int digest_calc_response_s(const HASHHEX *ha1, const HASHHEX *ha2,
    const str_const *nonce, const str_const *qop_val, const str_const *nc,
    const str_const *cnonce, struct digest_auth_response *response)
{
	int rval;

	rval = _digest_calc_response(ha1, ha2, nonce, qop_val, nc, cnonce, response);
	response->digest_calc = &sha256sess_digest_calc;
	return rval;
}

static char *response_hash_fill(const struct digest_auth_response *response, char *hex, int len)
{
	DASSERT(len >= HASHHEXLEN_SHA256);

	cvt_hex128(response->RespHash.SHA256, hex, HASHLEN_SHA256, HASHHEXLEN_SHA256);
	return hex;
}

static int response_hash_bcmp(const struct digest_auth_response *response, const str_const *hex)
{
	if (hex->len != HASHHEXLEN_SHA256)
		return 1;

	return bcmp_hex128(response->RespHash.SHA256, hex->s, HASHLEN_SHA256);
}

const struct digest_auth_calc sha256_digest_calc = {
	.HA1 = digest_calc_HA1,
	.HA1sess = NULL,
	.HA2 = digest_calc_HA2,
	.response = &digest_calc_response,
	.response_hash_bcmp = response_hash_bcmp,
	.response_hash_fill = response_hash_fill,
	.algorithm_val = str_const_init(ALG_SHA256_STR),
	.HASHLEN = HASHLEN_SHA256,
	.HASHHEXLEN = HASHHEXLEN_SHA256
};

const struct digest_auth_calc sha256sess_digest_calc = {
	.HA1 = digest_calc_HA1,
	.HA1sess = digest_calc_HA1sess,
	.HA2 = digest_calc_HA2,
	.response = &digest_calc_response_s,
	.response_hash_bcmp = response_hash_bcmp,
	.response_hash_fill = response_hash_fill,
	.algorithm_val = str_const_init(ALG_SHA256SESS_STR),
	.HASHLEN = HASHLEN_SHA256,
	.HASHHEXLEN = HASHHEXLEN_SHA256
};
