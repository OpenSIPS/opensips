/*
 * Copyright (C) 2019 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
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
 *
 */

#ifndef STIR_SHAKEN_PASSPORT_H
#define STIR_SHAKEN_PASSPORT_H

#include <time.h>

#ifdef STIR_SHAKEN_OPENSSL
#include <openssl/x509.h>
#else
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/x509.h>
#endif

#ifdef STIR_SHAKEN_OPENSSL
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/ecdsa.h>
#else
#include <wolfssl/openssl/x509v3.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/ecdsa.h>
#endif

#include "../../str.h"
#include "../../lib/cJSON.h"

#define FULL_ATTEST_STR    "A"
#define PARTIAL_ATTEST_STR "B"
#define GATEWAY_ATTEST_STR "C"

#define CRLF "\r\n"
#define CRLF_LEN (sizeof(CRLF) - 1)

#define PPORT_HDR_ALG 	  "alg"
#define PPORT_HDR_ALG_VAL "ES256"
#define PPORT_HDR_PPT     "ppt"
#define PPORT_HDR_PPT_VAL "shaken"
#define PPORT_HDR_TYP     "typ"
#define PPORT_HDR_TYP_VAL "passport"
#define PPORT_HDR_X5U "x5u"
#define PPORT_PAYLOAD_ATTEST "attest"
#define PPORT_PAYLOAD_DEST "dest"
#define PPORT_PAYLOAD_TN "tn"
#define PPORT_PAYLOAD_IAT "iat"
#define PPORT_PAYLOAD_ORIG "orig"
#define PPORT_PAYLOAD_ORIGID "origid"
#define PPORT_SEPARATOR '.'

#define HDR_PARAM_SEPARATOR ';'

#define BASE64_PAD_CHAR '='

#define IDENTITY_HDR_S "Identity: "
#define IDENTITY_HDR_LEN (sizeof(IDENTITY_HDR_S)-1)
#define HDR_INFO_PARAM_S "info="
#define HDR_INFO_PARAM_LEN (sizeof(HDR_INFO_PARAM_S)-1)
#define HDR_ALG_PARAM_S "alg=ES256"
#define HDR_ALG_PARAM_LEN (sizeof(HDR_ALG_PARAM_S)-1)
#define HDR_PPT_PARAM_S "ppt=shaken"
#define HDR_PPT_PARAM_LEN (sizeof(HDR_PPT_PARAM_S)-1)

#define R_S_INT_LEN 32
#define RAW_SIG_LEN 64

struct parsed_identity {
	cJSON *header;
	cJSON *x5u;

	cJSON *payload;
	cJSON *attest;
	cJSON *dest_tn;
	cJSON *iat;
	cJSON *orig_tn;
	cJSON *origid;

	str dec_header;
	str dec_payload;
	str dec_signature;
	str signing_input; /* Original encoded A.B, borrowed from the input body. */

	str ppt_hdr_param;
	str alg_hdr_param;
	str info_hdr_param;
};

/* Returns a static str container holding a caller-owned, pkg-allocated header.
 * Copy the str before the next call; free only its buffer. */
str *passport_build_identity(EVP_PKEY *pkey, time_t iat, str *attest,
	str *x5u, str *orig, str *dest, str *origid);
str *passport_build_div(EVP_PKEY *pkey, time_t iat, str *x5u,
	str *orig, str *div, str *dest);

/* Pass a zero-initialized parsed object and writable input (decoding temporarily
 * changes padding). Clean up the object even when parsing fails. */
int passport_parse_identity(str *body, struct parsed_identity *parsed);
int passport_check_claims(struct parsed_identity *parsed);
int passport_verify_signature(X509 *cert, struct parsed_identity *parsed,
	time_t iat, str *orig, str *dest);
int passport_verify_full_signature(X509 *cert, struct parsed_identity *parsed);

/* Releases members, but not the parsed_identity container itself. */
void passport_identity_cleanup(struct parsed_identity *parsed);

#endif /* STIR_SHAKEN_PASSPORT_H */
