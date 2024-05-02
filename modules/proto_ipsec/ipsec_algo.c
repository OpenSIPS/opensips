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

#include "ipsec_algo.h"
#include "../../trim.h"
#include "../../dprint.h"
#include "../../lib/csv.h"

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

int ipsec_disable_deprecated_algorithms = 0;

static struct ipsec_algorithm_desc ipsec_auth_algorithms[] = {
	{
		"hmac-md5-96",
		"md5",
		"hmac-md5-96 algorithm should not be used",
		IPSEC_ALGO_MD5_KEY_SIZE,
	},
	{
		"hmac-sha-1-96",
		"sha1",
		"usage of hmac-sha-1-96 algorithm is not recommended",
		IPSEC_ALGO_SHA1_KEY_SIZE,
	},
	{
		"aes-gmac",
		"rfc4543(gcm(aes))",
		NULL,
		IPSEC_ALGO_AES_KEY_SIZE,
	},
	{
		"null",
		"digest_null",
		NULL,
		IPSEC_ALGO_NULL_KEY_SIZE,
	},
};


static struct ipsec_algorithm_desc ipsec_enc_algorithms[] = {
	{
		"des-ede3-cbc",
		"des3_ede",
		"des-ede3-cbc encryption algorithm should not be used",
		IPSEC_ALGO_DES3_KEY_SIZE,
	},
	{
		"aes-cbc",
		"aes",
		"usage of aes-cbc encryption algorithm is not recommended",
		IPSEC_ALGO_AES_KEY_SIZE,
	},
	{
		"aes-gcm",
		"rfc4106(gcm(aes))",
		NULL,
		IPSEC_ALGO_AES_KEY_SIZE,
	},
	{
		"null",
		"cipher_null",
		NULL,
		IPSEC_ALGO_NULL_KEY_SIZE,
	},
};

struct ipsec_algorithm_desc *ipsec_parse_algorithm(str *name, enum ipsec_algo_type type)
{
	struct ipsec_algorithm_desc *desc;
	int size, i;
	if (!name || !name->len)
		return NULL;
	switch (type) {
		case IPSEC_ALGO_TYPE_AUTH:
			desc = ipsec_auth_algorithms;
			size = (sizeof ipsec_auth_algorithms) / sizeof *desc;
			break;
		case IPSEC_ALGO_TYPE_ENC:
			desc = ipsec_enc_algorithms;
			size = (sizeof ipsec_enc_algorithms) / sizeof *desc;
			break;
		default:
			/* unknown */
			return NULL;
	}
	for (i = 0; i < size; i++)
		if (str_casematch(name, _str(desc[i].name)))
			return desc + i;
	return NULL;
}

struct ipsec_allowed_algo {
	struct ipsec_algorithm_desc *auth;
	struct ipsec_algorithm_desc *enc;
	struct ipsec_allowed_algo *next;
};

struct ipsec_allowed_algo *ipsec_allowed_algos;

/* Types is 1 for integrity, 2 for encryption, 0 for both */
int ipsec_add_allowed_algorithms(str *algs)
{
	int ret = -1;
	csv_record *csv;
	str_list *it;
	char *p;
	str alg;
	struct ipsec_allowed_algo *pair;
	static struct ipsec_allowed_algo *ipsec_allowed_algos_last;
	struct ipsec_algorithm_desc *auth, *enc;

	if (!algs || !algs->s)
		return 0;
	algs->len = strlen(algs->s);
	LM_DBG("parse allowed_algorithms: %.*s\n", algs->len, algs->s);

	csv = parse_csv_record(algs);
	if (!csv) {
		LM_ERR("could not parse algorithms\n");
		return -1;
	}
	for (it = csv; it; it = it->next) {
		trim(&it->s);
		if (!it->s.len) {
			LM_ERR("no algorithm specified\n");
			goto end;
		}
		/* check for the separator */
		p = q_memchr(it->s.s, '=', it->s.len);
		if (p) {
			alg.s = it->s.s;
			alg.len = p - it->s.s;
			trim(&alg);
			if (alg.len != 0) {
				auth = ipsec_parse_algorithm(&alg, IPSEC_ALGO_TYPE_AUTH);
				if (!auth) {
					LM_ERR("could not parse pair authenticatin algorithm\n");
					goto end;
				}
			} else {
				auth = NULL;
			}
			alg.s = p + 1;
			alg.len = it->s.len - (alg.s - it->s.s);
			trim(&alg);
			enc = ipsec_parse_algorithm(&alg, IPSEC_ALGO_TYPE_ENC);
			if (!enc) {
				LM_ERR("could not parse pair encryption algorithm\n");
				goto end;
			}
		} else {
			auth = ipsec_parse_algorithm(&it->s, IPSEC_ALGO_TYPE_AUTH);
			if (!auth) {
				/* check if it is an encryption algorithm */
				enc = ipsec_parse_algorithm(&it->s, IPSEC_ALGO_TYPE_ENC);
				if (!enc) {
					LM_ERR("unknown algorithm %.*s\n", it->s.len, it->s.s);
					goto end;
				}
			} else {
				enc = NULL;
			}
		}
		pair = pkg_malloc(sizeof *pair);
		if (!pair) {
			LM_ERR("oom for authentication pair\n");
			return -1;
		}
		memset(pair, 0, sizeof *pair);
		pair->auth = auth;
		pair->enc = enc;
		if (ipsec_allowed_algos_last)
			ipsec_allowed_algos_last->next = pair;
		else
			ipsec_allowed_algos = pair;
		ipsec_allowed_algos_last = pair;
	}
	ret = 0;
end:
	LM_DBG("full list of allowed supported algorithms:\n");
	for (pair = ipsec_allowed_algos; pair; pair = pair->next) {
		LM_DBG(" - auth=%s enc=%s\n",
				(pair->auth->name?pair->auth->name:"ANY"),
				(pair->enc->name?pair->enc->name:"ANY"));
	}
	free_csv_record(csv);
	return ret;
}

sec_agree_body_t *ipsec_get_security_client(struct sip_msg *msg)
{
	struct hdr_field *h;
	sec_agree_body_t *sa, *sas;
	static sec_agree_body_t ret_sa;
	struct ipsec_allowed_algo *algs;
	struct ipsec_algorithm_desc *auth, *enc;
	str null_enc = str_init("null");
	struct ipsec_algorithm_desc *alg_desc;

	/* find the proper Security-Client in the request */
	if (parse_headers(msg, HDR_SECURITY_CLIENT_F, 0) < 0 || !msg->security_client) {
		LM_ERR("cannot parse Security-Client header\n");
		return NULL;
	}
	/* TODO: order by priority */
	if (!ipsec_allowed_algos) {
		LM_DBG("no allowed algorithms specified - using the first supported one!\n");
		/* if we have no prefference, choose the first one supported */
		for (h = msg->security_client; h; h = h->sibling) {
			/* duplicate the header, to avoid writing the parsed structure into
			 * the request, which is shared */
			sas = parse_sec_agree_body(&h->body);
			if (!sas)
				continue;
			for (sa = sas; sa; sa = sa->next) {
				if (sa->invalid || sa->mechanism != SEC_AGREE_MECHANISM_IPSEC_3GPP)
					continue;
				/* TODO: should we check mode for now? */
				if (!sa->ts3gpp.alg_str.len)
					continue;
				alg_desc = ipsec_parse_algorithm(&sa->ts3gpp.alg_str, IPSEC_ALGO_TYPE_AUTH);
				if (!alg_desc) {
					LM_DBG("unknown authentication algorithm %.*s\n",
							sa->ts3gpp.alg_str.len, sa->ts3gpp.alg_str.s);
					continue;
				}
				if (alg_desc->deprecated && ipsec_disable_deprecated_algorithms) {
					LM_DBG("disabled authentication algorithm %.*s\n",
							sa->ts3gpp.alg_str.len, sa->ts3gpp.alg_str.s);
					continue;
				}
				if (!sa->ts3gpp.ealg_str.len)
					goto found; /* choosing 'null' encryption algorithm */
				alg_desc = ipsec_parse_algorithm(&sa->ts3gpp.ealg_str, IPSEC_ALGO_TYPE_ENC);
				if (!alg_desc) {
					LM_DBG("unknown encryption algorithm %.*s\n",
							sa->ts3gpp.ealg_str.len, sa->ts3gpp.ealg_str.s);
					continue;
				}
				if (alg_desc->deprecated && ipsec_disable_deprecated_algorithms) {
					LM_DBG("disabled encryption algorithm %.*s\n",
							sa->ts3gpp.ealg_str.len, sa->ts3gpp.ealg_str.s);
					continue;
				}
				/* found a proper one */
				goto found;
			}
			/* nothing found, freeing the header */
			free_sec_agree(&sas);
		}
	} else {
		/* choose according to our preference */
		LM_DBG("try to match against allowed supported algorithms:\n");
		for (algs = ipsec_allowed_algos; algs; algs = algs->next) {
			LM_DBG(" - attempt auth=%s enc=%s\n",
					(algs->auth->name?algs->auth->name:"ANY"),
					(algs->enc->name?algs->enc->name:"ANY"));
			for (h = msg->security_client; h; h = h->sibling) {
				/* iterate through all headers and check if we have a match */
				sas = parse_sec_agree_body(&h->body);
				if (!sas)
					continue;
				for (sa = sas; sa; sa = sa->next) {
					if (sa->invalid || sa->mechanism != SEC_AGREE_MECHANISM_IPSEC_3GPP)
						continue;
					/* TODO: should we check mode for now? */
					if (!sa->ts3gpp.alg_str.len)
						continue;
					auth = ipsec_parse_algorithm(&sa->ts3gpp.alg_str, IPSEC_ALGO_TYPE_AUTH);
					if (!auth) {
						LM_DBG("unknown authentication algorithm %.*s\n",
								sa->ts3gpp.alg_str.len, sa->ts3gpp.alg_str.s);
						continue;
					}
					LM_DBG("   + hdr auth=%s\n", auth->name);
					if (algs->auth && algs->auth != auth)
						continue;
					if (!sa->ts3gpp.ealg_str.len)
						enc = ipsec_parse_algorithm(&null_enc, IPSEC_ALGO_TYPE_ENC);
					else
						enc = ipsec_parse_algorithm(&sa->ts3gpp.ealg_str, IPSEC_ALGO_TYPE_ENC);
					if (!enc) {
						LM_DBG("unknown encryption algorithm %.*s\n",
								sa->ts3gpp.ealg_str.len, sa->ts3gpp.ealg_str.s);
						continue;
					}
					LM_DBG("   + hdr end=%s\n", enc->name);
					if (algs->enc && algs->enc != enc)
						continue;
					goto found;
				}
				/* nothing found, freeing the header */
				free_sec_agree(&sas);
			}
		}
	}
	return NULL;
found:
	/* we need to make a copy of the body, because we will release the
	 * structure, so it may vanish until we actually use it */
	memcpy(&ret_sa, sa, sizeof *sa);
	ret_sa.params = NULL; /* we are not interested in extra params,
						  so we shall not carry them */
	free_sec_agree(&sas);
	return &ret_sa;
}
