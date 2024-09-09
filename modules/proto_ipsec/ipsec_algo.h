/*
 * Copyright (C) 2024 - OpenSIPS Solutions
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
 *
 */

#ifndef _IPSEC_ALGO_H_
#define _IPSEC_ALGO_H_

#include "../../ut.h"
#include "../../parser/parse_security.h"

struct ipsec_algorithm_desc {
	const char *name;
	const char *xfrm_name;
	const char *deprecated;
	int key_len;
};
struct ipsec_allowed_algo;

#define IPSEC_ALGO_KEY_SIZE 128
/*
 * According to 3GPP TS 33.203, Annex I
 * Integrity Keys:
 *
 * If the selected authentication algorithm is HMAC-SHA-1-96 then IKesp is obtained
 * from IKim by appending 32 zero bits to the end of IKim to create a 160-bit string.
 *
 * If selected authentication algorithm is AES-GMAC as specified in RFC 4543 with
 * 128 bit key then IKesp = IKim. The salt value specified in Section 3.2 of RFC 4543
 * shall be derived using the key derivation function KDF defined in Annex B of
 * TS 33.220. The input Key to the KDF function shall be equal to the concatenation
 * of CKim and IKim: CKim || IKim. The input S to the KDF function shall be formed
 * from the following parameters:
 *  - FC = 0x58.
 *  - P0 = "AES_GMAC_SALT" .
 *  - L0 = length of the string "AES_GMAC_SALT" (i.e. 0x00 0x0D).
 *
 * The salt value shall consist of the 32 least significant bits of the 256 bits of
 * the KDF output.
 *
 * "Hmac-sha-1-96" is not recommended.
 *
 * Encryption Keys:
 *
 * If selected encryption algorithm is AES-CBC as specified in RFC 3602 with 128
 * bit key then CKesp = CKim . If selected encryption algorithm is AES-GCM as
 * specified in RFC 4106 with 128 bit key then CKesp = CKim. The salt value
 * specified in Section 4 of RFC 4106 shall be derived using the key derivation
 * function KDF defined in Annex B of TS 33.220. The input Key to the KDF function
 * shall be equal to the concatenation of CKim and IKim: CKim || IKim. The input S
 * to the KDF function shall be formed from the following parameters:
 *  - FC = 0x59
 *  - P0 = "AES_GCM_SALT"
 *  - L0 = length of the string "AES_GCM_SALT" (i.e. 0x00 0x0C)
 * The salt value shall consist of the 32 least significant bits of the 256 bits of
 * the KDF output.
 *
 * "aes-cbc" is not recommended.
 */
#define IPSEC_ALGO_MD5_KEY_SIZE IPSEC_ALGO_KEY_SIZE
#define IPSEC_ALGO_SHA1_KEY_SIZE_PAD 32 /* '\0' padding */
#define IPSEC_ALGO_SHA1_KEY_SIZE (IPSEC_ALGO_KEY_SIZE + IPSEC_ALGO_SHA1_KEY_SIZE_PAD)
#define IPSEC_ALGO_AES_KEY_SIZE IPSEC_ALGO_KEY_SIZE
#define IPSEC_ALGO_DES3_KEY_SIZE_PAD 64 /* 192 key size, so 64 padding */
#define IPSEC_ALGO_DES3_KEY_SIZE (IPSEC_ALGO_KEY_SIZE + IPSEC_ALGO_DES3_KEY_SIZE_PAD)
#define IPSEC_ALGO_NULL_KEY_SIZE 0
#define IPSEC_ALGO_MAX_KEY_SIZE IPSEC_ALGO_DES3_KEY_SIZE

enum ipsec_algo_type {
	IPSEC_ALGO_TYPE_AUTH,
	IPSEC_ALGO_TYPE_ENC,
};

int ipsec_add_allowed_algorithms(str *algs);
struct ipsec_algorithm_desc *ipsec_parse_algorithm(str *name, enum ipsec_algo_type type);
struct ipsec_allowed_algo *ipsec_parse_allowed_algorithms(str *algs);
sec_agree_body_t *ipsec_get_security_client(struct sip_msg *msg, struct ipsec_allowed_algo *algos);
void ipsec_free_allowed_algorithms(struct ipsec_allowed_algo *algos);

extern int ipsec_disable_deprecated_algorithms;

#endif /* _IPSEC_ALGO_H_ */
