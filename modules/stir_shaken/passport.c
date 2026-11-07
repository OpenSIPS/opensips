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

#include <stdlib.h>

#include "passport.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../parser/parse_param.h"

void passport_identity_cleanup(struct parsed_identity *parsed)
{
	if (parsed) {
		cJSON_Delete(parsed->header);
		cJSON_Delete(parsed->payload);
		pkg_free(parsed->dec_header.s);
		pkg_free(parsed->dec_payload.s);
		pkg_free(parsed->dec_signature.s);
	}
}

static int ss_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen)
{
	int bnlen, padlen;

	bnlen = BN_num_bytes(a);

	if (tolen < bnlen)
		return -1;

	padlen = tolen - bnlen;
	memset(to, 0, padlen);

	if (BN_bn2bin(a, to + padlen) == 0)
		return -1;

	return tolen;
}

static char *build_pport_hdr_json(str *cr_url, const char *ppt)
{
	char *json_str;
	cJSON *header, *item;

	header = cJSON_CreateObject();
	if (!header) {
		LM_ERR("Failed to create json object\n");
		return NULL;
	}

	item = cJSON_CreateString(PPORT_HDR_ALG_VAL);
	if (!item) {
		LM_ERR("Failed to add json item\n");
		goto error;
	}
	cJSON_AddItemToObjectCS(header, PPORT_HDR_ALG, item);

	item = cJSON_CreateString(ppt);
	if (!item) {
		LM_ERR("Failed to add json item\n");
		goto error;
	}
	cJSON_AddItemToObjectCS(header, PPORT_HDR_PPT, item);

	item = cJSON_CreateString(PPORT_HDR_TYP_VAL);
	if (!item) {
		LM_ERR("Failed to add json item\n");
		goto error;
	}
	cJSON_AddItemToObjectCS(header, PPORT_HDR_TYP, item);

	item = cJSON_CreateStr(cr_url->s, cr_url->len);
	if (!item) {
		LM_ERR("Failed to add json item\n");
		goto error;
	}
	cJSON_AddItemToObjectCS(header, PPORT_HDR_X5U, item);

	json_str = cJSON_PrintUnformatted(header);
	if (!json_str) {
		LM_ERR("Failed to print json object\n");
		goto error;
	}
	cJSON_Delete(header);

	return json_str;

error:
	cJSON_Delete(header);
	return NULL;
}

static char *build_pport_payload_json(str *attest, str *orig_tn, str *dest_tn,
	time_t iat_ts, str *origid)
{
	char *json_str;
	cJSON *payload, *item, *tn_item;

	payload = cJSON_CreateObject();
	if (!payload) {
		LM_ERR("Failed to create json object\n");
		return NULL;
	}

	item = cJSON_CreateStr(attest->s, attest->len);
	if (!item) {
		LM_ERR("Failed to add json item\n");
		goto error;
	}
	cJSON_AddItemToObjectCS(payload, PPORT_PAYLOAD_ATTEST, item);

	item = cJSON_CreateObject();
	if (!item) {
		LM_ERR("Failed to create json object\n");
		goto error;
	}
	cJSON_AddItemToObjectCS(payload, PPORT_PAYLOAD_DEST, item);

	tn_item = cJSON_CreateArray();
	if (!tn_item) {
		LM_ERR("Failed to create json array\n");
		goto error;
	}
	cJSON_AddItemToObjectCS(item, PPORT_PAYLOAD_TN, tn_item);

	item = cJSON_CreateStr(dest_tn->s, dest_tn->len);
	if (!item) {
		LM_ERR("Failed to add json item\n");
		goto error;
	}
	cJSON_AddItemToArray(tn_item, item);

	item = cJSON_CreateNumber((double)iat_ts);
	if (!item) {
		LM_ERR("Failed to add json item\n");
		goto error;
	}
	cJSON_AddItemToObjectCS(payload, PPORT_PAYLOAD_IAT, item);

	item = cJSON_CreateObject();
	if (!item) {
		LM_ERR("Failed to create json object\n");
		goto error;
	}
	cJSON_AddItemToObjectCS(payload, PPORT_PAYLOAD_ORIG, item);

	tn_item = cJSON_CreateStr(orig_tn->s, orig_tn->len);
	if (!tn_item) {
		LM_ERR("Failed to add json item\n");
		goto error;
	}
	cJSON_AddItemToObjectCS(item, PPORT_PAYLOAD_TN, tn_item);

	item = cJSON_CreateStr(origid->s, origid->len);
	if (!item) {
		LM_ERR("Failed to add json item\n");
		goto error;
	}
	cJSON_AddItemToObjectCS(payload, PPORT_PAYLOAD_ORIGID, item);

	json_str = cJSON_PrintUnformatted(payload);
	if (!json_str) {
		LM_ERR("Failed to print json object\n");
		goto error;
	}
	cJSON_Delete(payload);

	return json_str;

error:
	cJSON_Delete(payload);
	return NULL;
}

static char *build_div_payload(time_t iat, str *orig, str *div, str *dest)
{
	cJSON *payload = cJSON_CreateObject(), *obj, *value;
	str *ids[] = {dest, div, orig};
	const char *names[] = {"dest", "div", "orig"};
	char *json = NULL;
	int i;

	if (!payload)
		return NULL;
	/* Claim order follows PASSporT canonical serialization. */
	for (i = 0; i < 3; i++) {
		obj = cJSON_CreateObject();
		if (!obj)
			goto out;
		cJSON_AddItemToObjectCS(payload, names[i], obj);
		value = cJSON_CreateStr(ids[i]->s, ids[i]->len);
		if (!value)
			goto out;
		if (i == 0) {
			cJSON *array = cJSON_CreateArray();
			if (!array) {
				cJSON_Delete(value);
				goto out;
			}
			cJSON_AddItemToArray(array, value);
			value = array;
		}
		cJSON_AddItemToObjectCS(obj,
			ids[i]->len >= 4 && !memcmp(ids[i]->s, "urn:", 4) ? "uri" : "tn",
			value);
		if (i == 1) {
			value = cJSON_CreateNumber((double)iat);
			if (!value)
				goto out;
			cJSON_AddItemToObjectCS(payload, "iat", value);
		}
	}
	json = cJSON_PrintUnformatted(payload);
out:
	cJSON_Delete(payload);
	return json;
}

static int build_unsigned_pport_type(str *buf, time_t iat_ts, str *attest,
	str *cr_url, str *orig_tn, str *dest_tn, str *origid, str *div)
{
	str hdr_json_str = {0,0}, payload_json_str = {0,0};

	hdr_json_str.s = build_pport_hdr_json(cr_url, div ? "div" : "shaken");
	if (!hdr_json_str.s) {
		LM_ERR("Failed to build PASSporT's json header\n");
		return -1;
	}
	hdr_json_str.len = strlen(hdr_json_str.s);

	LM_DBG("Built PASSporT Header: %s\n", hdr_json_str.s);

	payload_json_str.s = div ? build_div_payload(iat_ts, orig_tn, div, dest_tn) :
		build_pport_payload_json(attest, orig_tn, dest_tn, iat_ts, origid);
	if (!payload_json_str.s) {
		LM_ERR("Failed to build PASSporT's json payload\n");
		goto error;
	}
	payload_json_str.len = strlen(payload_json_str.s);

	LM_DBG("Built PASSporT Payload: %s\n", payload_json_str.s);

	buf->len = calc_base64_encode_len(hdr_json_str.len) + 1 /* '.' */ +
		calc_base64_encode_len(payload_json_str.len);
	buf->s = pkg_malloc(buf->len);
	if (!buf->s) {
		LM_ERR("oom!\n");
		goto error;
	}

	base64urlencode((unsigned char*)buf->s,
		(unsigned char*)hdr_json_str.s, hdr_json_str.len);
	buf->len = calc_base64_encode_len(hdr_json_str.len);
	/* remove base64 padding */
	if (buf->s[buf->len-1] == BASE64_PAD_CHAR)
		buf->len--;
	if (buf->s[buf->len-1] == BASE64_PAD_CHAR)
		buf->len--;

	buf->s[buf->len++] = PPORT_SEPARATOR;

	base64urlencode((unsigned char*)(buf->s + buf->len),
		(unsigned char*)payload_json_str.s, payload_json_str.len);
	buf->len += calc_base64_encode_len(payload_json_str.len);
	if (buf->s[buf->len-1] == BASE64_PAD_CHAR)
		buf->len--;
	if (buf->s[buf->len-1] == BASE64_PAD_CHAR)
		buf->len--;

	cJSON_PurgeString(hdr_json_str.s);
	cJSON_PurgeString(payload_json_str.s);

	return 0;

error:
	cJSON_PurgeString(hdr_json_str.s);
	if (payload_json_str.s)
		cJSON_PurgeString(payload_json_str.s);
	return -1;
}

static int build_unsigned_pport(str *buf, time_t iat, str *attest,
	str *x5u, str *orig, str *dest, str *origid)
{
	return build_unsigned_pport_type(buf, iat, attest, x5u, orig, dest,
		origid, NULL);
}

static void ss_ecdsa_sig_get0(const ECDSA_SIG *sig, const BIGNUM **pr,
	const BIGNUM **ps)
{
#if !defined(WOLFSSL_VERSION) && OPENSSL_VERSION_NUMBER >= 0x10100000L
	ECDSA_SIG_get0(sig, pr, ps);
#else
	*pr = sig->r;
	*ps = sig->s;
#endif
}

static str *build_identity_type(EVP_PKEY *pkey,
	time_t date_ts, str *attest, str *cr_url, str *orig_tn,
	str *dest_tn, str *origid, str *div)
{
	static str hdr_buf = {0,0};
	str unsigned_buf = STR_NULL;
	str der_sig_buf = {0,0};
	unsigned char *der_sig_p;
	unsigned char raw_sig_buf[RAW_SIG_LEN];
	EVP_MD_CTX *mdctx = NULL;
	ECDSA_SIG *sig = NULL;
	const BIGNUM *r, *s;
	int len;
	size_t sig_len;
	const char *ppt_param = div ? "ppt=div" : HDR_PPT_PARAM_S;
	int ppt_len = strlen(ppt_param);

	hdr_buf.s = NULL;

	if (build_unsigned_pport_type(&unsigned_buf, date_ts, attest, cr_url,
		orig_tn, dest_tn, origid, div) < 0) {
		LM_ERR("Failed to build PASSporT\n");
		return NULL;
	}

	mdctx = EVP_MD_CTX_create();
	if (!mdctx) {
		LM_ERR("Failed to create signing context\n");
		goto error;
	}
	if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
		LM_ERR("Failed to init signing operation\n");
		goto error;
	}
	if (EVP_DigestSignUpdate(mdctx, unsigned_buf.s, unsigned_buf.len) <= 0) {
		LM_ERR("Failed to add data to signing context\n");
		goto error;
	}

	if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) <= 0) {
		LM_ERR("Failed to get maximum signature length\n");
		goto error;
	}
	der_sig_buf.s = pkg_malloc(sig_len);
	if (!der_sig_buf.s) {
		LM_ERR("oom!\n");
		goto error;
	}
	der_sig_p = (unsigned char *)der_sig_buf.s;

	if (EVP_DigestSignFinal(mdctx, (unsigned char*)der_sig_buf.s,
		&sig_len) <= 0) {
		LM_ERR("Failed to sign data\n");
		goto error;
	}
	der_sig_buf.len = sig_len;

	EVP_MD_CTX_destroy(mdctx);
	mdctx = NULL;

	/* convert from DER format to the internal structure in order to extract
	 * the R and S values */
	sig = d2i_ECDSA_SIG(NULL, (const unsigned char **)&der_sig_p, der_sig_buf.len);
	if (!sig) {
		LM_ERR("Failed to convert from DER to internal format\n");
		goto error;
	}

	pkg_free(der_sig_buf.s);
	der_sig_buf.s = NULL;

	ss_ecdsa_sig_get0(sig, &r, &s);
	len = ss_bn2binpad(r, raw_sig_buf, R_S_INT_LEN);
	if (len < 0 || len != R_S_INT_LEN) {
		LM_ERR("Failed to convert R integer into binay represantation\n");
		goto error;
	}
	len = ss_bn2binpad(s, raw_sig_buf + R_S_INT_LEN,
		R_S_INT_LEN);
	if (len < 0 || len != R_S_INT_LEN) {
		LM_ERR("Failed to convert S integer into binay represantation\n");
		goto error;
	}

	ECDSA_SIG_free(sig);
	sig = NULL;

	hdr_buf.len = IDENTITY_HDR_LEN + unsigned_buf.len + 1/*'.'*/ +
		calc_base64_encode_len(RAW_SIG_LEN) + 1/*';'*/ + HDR_INFO_PARAM_LEN +
		2/*'<','>'*/ + cr_url->len + 1/*';'*/ + HDR_ALG_PARAM_LEN + 1/*';'*/ + ppt_len + CRLF_LEN;
	hdr_buf.s = pkg_malloc(hdr_buf.len);
	if (!hdr_buf.s) {
		LM_ERR("oom!\n");
		goto error;
	}

	memcpy(hdr_buf.s, IDENTITY_HDR_S, IDENTITY_HDR_LEN);
	memcpy(hdr_buf.s + IDENTITY_HDR_LEN, unsigned_buf.s, unsigned_buf.len);
	hdr_buf.len = IDENTITY_HDR_LEN + unsigned_buf.len;
	hdr_buf.s[hdr_buf.len++] = PPORT_SEPARATOR;

	pkg_free(unsigned_buf.s);
	unsigned_buf.s = NULL;

	base64urlencode((unsigned char*)(hdr_buf.s + hdr_buf.len),
		(unsigned char*)raw_sig_buf, RAW_SIG_LEN);
	hdr_buf.len += calc_base64_encode_len(RAW_SIG_LEN);
	if (hdr_buf.s[hdr_buf.len-1] == BASE64_PAD_CHAR)
		hdr_buf.len--;
	if (hdr_buf.s[hdr_buf.len-1] == BASE64_PAD_CHAR)
		hdr_buf.len--;

	hdr_buf.s[hdr_buf.len++] = ';';
	memcpy(hdr_buf.s + hdr_buf.len, HDR_INFO_PARAM_S, HDR_INFO_PARAM_LEN);
	hdr_buf.len += HDR_INFO_PARAM_LEN;
	hdr_buf.s[hdr_buf.len++] = '<';
	memcpy(hdr_buf.s + hdr_buf.len, cr_url->s, cr_url->len);
	hdr_buf.len += cr_url->len;
	hdr_buf.s[hdr_buf.len++] = '>';
	hdr_buf.s[hdr_buf.len++] = ';';
	memcpy(hdr_buf.s + hdr_buf.len, HDR_ALG_PARAM_S, HDR_ALG_PARAM_LEN);
        hdr_buf.len += HDR_ALG_PARAM_LEN;
        hdr_buf.s[hdr_buf.len++] = ';';
	memcpy(hdr_buf.s + hdr_buf.len, ppt_param, ppt_len);
	hdr_buf.len += ppt_len;
	memcpy(hdr_buf.s + hdr_buf.len, CRLF, CRLF_LEN);
	hdr_buf.len += CRLF_LEN;

	return &hdr_buf;

error:
	pkg_free(unsigned_buf.s);
	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);
	if (hdr_buf.s)
		pkg_free(hdr_buf.s);
	if (der_sig_buf.s)
		pkg_free(der_sig_buf.s);
	if (sig)
		ECDSA_SIG_free(sig);

	return NULL;
}

str *passport_build_identity(EVP_PKEY *pkey, time_t iat, str *attest,
	str *x5u, str *orig, str *dest, str *origid)
{
	return build_identity_type(pkey, iat, attest, x5u, orig, dest, origid, NULL);
}

str *passport_build_div(EVP_PKEY *pkey, time_t iat, str *x5u,
	str *orig, str *div, str *dest)
{
	return build_identity_type(pkey, iat, NULL, x5u, orig, dest, NULL, div);
}

/* decode base64url without padding
 * the actual buffer _in points to is assumed to
 * have a size of at least _in->len+2 */
static inline int dec_base64url_nopad(str *in, str *out)
{
	char c1, c2;

	switch (in->len % 4) {
		case 0:
			out->len = base64urldecode((unsigned char *)out->s,
				(unsigned char *)in->s, in->len);
			break;
		case 2:
			c1 = in->s[in->len];
			c2 = in->s[in->len+1];
			in->s[in->len] = BASE64_PAD_CHAR;
			in->s[in->len+1] = BASE64_PAD_CHAR;

			out->len = base64urldecode((unsigned char *)out->s,
				(unsigned char *)in->s, in->len);

			in->s[in->len] = c1;
			in->s[in->len+1] = c2;
			break;
		case 3:
			c1 = in->s[in->len];
			in->s[in->len] = BASE64_PAD_CHAR;

			out->len = base64urldecode((unsigned char *)out->s,
				(unsigned char *)in->s, in->len);

			in->s[in->len] = c1;
			break;
		default:
			return -1;
	}

	return 0;
}

static cJSON *get_pport_orig_tn(cJSON *payload)
{
	cJSON *item, *obj_item;

	if (!(obj_item = cJSON_GetObjectItem(payload, PPORT_PAYLOAD_ORIG))) {
		LM_INFO("Missing 'orig' claim\n");
		return NULL;
	}
	if (obj_item->type != cJSON_Object) {
		LM_INFO("'orig' value should be an object\n");
		return NULL;
	}
	if (!(item = cJSON_GetObjectItem(obj_item, PPORT_PAYLOAD_TN))) {
		LM_INFO("Missing 'tn' from 'orig' claim\n");
		return NULL;
	}

	return item;
}

static cJSON *get_pport_dest_tn(cJSON *payload)
{
	cJSON *item, *obj_item, *arr_item;

	if (!(obj_item = cJSON_GetObjectItem(payload, PPORT_PAYLOAD_DEST))) {
		LM_INFO("Missing 'dest' claim\n");
		return NULL;
	}
	if (obj_item->type != cJSON_Object) {
		LM_INFO("'dest' value should be an object\n");
		return NULL;
	}
	if (!(arr_item = cJSON_GetObjectItem(obj_item, PPORT_PAYLOAD_TN))) {
		LM_INFO("Missing 'tn' from 'dest' claim\n");
		return NULL;
	}
	if (arr_item->type != cJSON_Array) {
		LM_INFO("'tn' from 'dest' should be an array\n");
		return NULL;
	}
	if (!(item = cJSON_GetArrayItem(arr_item, 0))) {
		LM_INFO("Missing number in 'tn' from 'dest'\n");
		return NULL;
	}

	return item;
}

int passport_parse_identity(str *hdr_buf, struct parsed_identity *parsed)
{
	str header_str, payload_str, sig_str, params_str;
	char *p;
	param_hooks_t _;
	param_t* params = NULL, *it;
	int rc = -1;

	payload_str.s = q_memchr(hdr_buf->s, PPORT_SEPARATOR, hdr_buf->len);
	if (!payload_str.s) {
		LM_INFO("PASSporT header not found\n");
		goto invalid_hdr;
	}

	header_str.s = hdr_buf->s;
	header_str.len = payload_str.s - hdr_buf->s;
	if (header_str.len == 0) {
		LM_INFO("Empty PASSporT header\n");
		goto invalid_hdr;
	}

	payload_str.s++;  /* skip '.' */
	sig_str.s = q_memchr(payload_str.s, PPORT_SEPARATOR,
		hdr_buf->len - header_str.len - 1);
	if (!sig_str.s) {
		LM_INFO("PASSporT payload not found\n");
		goto invalid_hdr;
	}
	payload_str.len = sig_str.s - payload_str.s;
	if (payload_str.len == 0) {
		LM_INFO("Empty PASSporT payload\n");
		goto invalid_hdr;
	}

	sig_str.s++;  /* skip '.' */
	parsed->signing_input.s = hdr_buf->s;
	parsed->signing_input.len = sig_str.s - hdr_buf->s - 1;
	p = q_memchr(sig_str.s, HDR_PARAM_SEPARATOR,
		hdr_buf->len - header_str.len - payload_str.len - 2);
	if (!p) {
		LM_INFO("Signature not found\n");
		goto invalid_hdr;
	}
	sig_str.len = p - sig_str.s;
	if (sig_str.len == 0) {
		LM_INFO("Empty signature\n");
		goto invalid_hdr;
	}

	params_str.s = p + 1;
	params_str.len = hdr_buf->len - (params_str.s - hdr_buf->s);
	if (parse_params(&params_str, CLASS_ANY, &_, &params) < 0) {
		LM_INFO("Failed to parse header parameters\n");
		goto invalid_hdr;
	}
	if (!params) {
		LM_INFO("Header parameters missing\n");
		goto invalid_hdr;
	}
	for (it = params; it; it = it->next) {
		if (!str_strcasecmp(_str("alg"), &it->name)) {
			if (parsed->alg_hdr_param.s) goto invalid_hdr;
			parsed->alg_hdr_param = it->body;
		}
		if (!str_strcasecmp(_str("ppt"), &it->name)) {
			if (parsed->ppt_hdr_param.s) goto invalid_hdr;
			parsed->ppt_hdr_param = it->body;
		}
		if (!str_strcasecmp(_str("info"), &it->name)) {
			if (parsed->info_hdr_param.s) goto invalid_hdr;
			parsed->info_hdr_param = it->body;
		}
	}

	parsed->dec_header.len = calc_max_base64_decode_len(header_str.len);
	parsed->dec_header.s = pkg_malloc(parsed->dec_header.len + 1);
	if (!parsed->dec_header.s) {
		LM_ERR("oom!\n");
		goto error;
	}
	if (dec_base64url_nopad(&header_str, &parsed->dec_header) < 0) {
		LM_INFO("Invalid base64url encoding for PASSporT Header\n");
		goto invalid_hdr;
	}
	parsed->dec_header.s[parsed->dec_header.len] = 0;

	LM_DBG("PASSporT Header: %s\n", parsed->dec_header.s);

	parsed->header = cJSON_Parse(parsed->dec_header.s);
	if (!parsed->header) {
		LM_INFO("Failed to parse PASSporT Header JSON\n");
		goto invalid_hdr;
	}

	parsed->x5u = cJSON_GetObjectItem(parsed->header, PPORT_HDR_X5U);

	parsed->dec_payload.len = calc_max_base64_decode_len(payload_str.len);
	parsed->dec_payload.s = pkg_malloc(parsed->dec_payload.len + 1);
	if (!parsed->dec_payload.s) {
		LM_ERR("oom!\n");
		goto error;
	}
	if (dec_base64url_nopad(&payload_str, &parsed->dec_payload) < 0) {
		LM_INFO("Invalid base64url encoding for PASSporT Payload\n");
		goto invalid_hdr;
	}
	parsed->dec_payload.s[parsed->dec_payload.len] = 0;

	LM_DBG("PASSporT Payload: %s\n", parsed->dec_payload.s);

	parsed->payload = cJSON_Parse(parsed->dec_payload.s);
	if (!parsed->payload) {
		LM_INFO("Failed to parse PASSporT Payload JSON\n");
		goto invalid_hdr;
	}

	parsed->attest = cJSON_GetObjectItem(parsed->payload, PPORT_PAYLOAD_ATTEST);
	parsed->dest_tn = get_pport_dest_tn(parsed->payload);
	parsed->iat = cJSON_GetObjectItem(parsed->payload, PPORT_PAYLOAD_IAT);
	parsed->orig_tn = get_pport_orig_tn(parsed->payload);
	parsed->origid = cJSON_GetObjectItem(parsed->payload, PPORT_PAYLOAD_ORIGID);

	parsed->dec_signature.len = calc_max_base64_decode_len(sig_str.len);
	parsed->dec_signature.s = pkg_malloc(parsed->dec_signature.len + 1);
	if (!parsed->dec_signature.s) {
		LM_ERR("oom!\n");
		goto error;
	}
	if (dec_base64url_nopad(&sig_str, &parsed->dec_signature) < 0) {
		LM_INFO("Invalid base64url encoding for PASSporT Signature\n");
		goto invalid_hdr;
	}

	free_params(params);

	return 0;

invalid_hdr:
	rc = -4;
error:
	if (params)
		free_params(params);
	return rc;
}

int passport_check_claims(struct parsed_identity *parsed)
{
	cJSON *item;

	if (!(item = cJSON_GetObjectItem(parsed->header, PPORT_HDR_ALG))) {
		LM_INFO("Missing 'alg' claim\n");
		return -1;
	}
	if (item->type != cJSON_String) {
		LM_INFO("'alg' value should be a string\n");
		return -1;
	}
	if (strcmp(item->valuestring, PPORT_HDR_ALG_VAL)) {
		LM_INFO("'alg' value should be 'ES256'\n");
		return -1;
	}

	if (!(item = cJSON_GetObjectItem(parsed->header, PPORT_HDR_PPT))) {
		LM_INFO("Missing 'ppt' claim\n");
		return -1;
	}
	if (item->type != cJSON_String) {
		LM_INFO("'ppt' value should be a string\n");
		return -1;
	}
	if (strcmp(item->valuestring, PPORT_HDR_PPT_VAL)) {
		LM_INFO("'ppt' value should be 'shaken'\n");
		return -1;
	}

	if (!(item = cJSON_GetObjectItem(parsed->header, PPORT_HDR_TYP))) {
		LM_INFO("Missing 'typ' claim\n");
		return -1;
	}
	if (item->type != cJSON_String) {
		LM_INFO("'typ' value should be a string\n");
		return -1;
	}
	if (strcmp(item->valuestring, PPORT_HDR_TYP_VAL)) {
		LM_INFO("'typ' value should be 'passport'\n");
		return -1;
	}

	if (!parsed->x5u) {
		LM_INFO("Missing 'x5u' claim\n");
		return -1;
	}
	if (parsed->x5u->type != cJSON_String) {
		LM_INFO("'x5u' value should be a string\n");
		return -1;
	}
	if (strlen(parsed->x5u->valuestring) == 0) {
		LM_INFO("'x5u' value should not be empty\n");
		return -1;
	}

	if (!parsed->attest) {
		LM_INFO("Missing 'attest' claim\n");
		return -1;
	}
	if (parsed->attest->type != cJSON_String) {
		LM_INFO("'attest' value should be a string\n");
		return -1;
	}
	if (strlen(parsed->attest->valuestring) == 0) {
		LM_INFO("'attest' value should not be empty\n");
		return -1;
	}

	if (!parsed->dest_tn)
		return -1;
	if (parsed->dest_tn->type != cJSON_String) {
		LM_INFO("Number in 'tn' from 'dest' should be a string\n");
		return -1;
	}
	if (strlen(parsed->dest_tn->valuestring) == 0) {
		LM_INFO("'dest' value should not be empty\n");
		return -1;
	}

	if (!parsed->iat) {
		LM_INFO("Missing 'iat' claim\n");
		return -1;
	}
	if (parsed->iat->type != cJSON_Number) {
		LM_INFO("'iat' value should be a number\n");
		return -1;
	}

	if (!parsed->orig_tn)
		return -1;
	if (parsed->orig_tn->type != cJSON_String) {
		LM_INFO("'tn' from 'orig' should be a string\n");
		return -1;
	}
	if (strlen(parsed->orig_tn->valuestring) == 0) {
		LM_INFO("'orig' value should not be empty\n");
		return -1;
	}

	if (!parsed->origid) {
		LM_INFO("Missing 'origid' claim\n");
		return -1;
	}
	if (parsed->origid->type != cJSON_String) {
		LM_INFO("'origid' value should be a string\n");
		return -1;
	}
	if (strlen(parsed->origid->valuestring) == 0) {
		LM_INFO("'origid' value should not be empty\n");
		return -1;
	}

	return 0;
}

static int verify_signature_mode(X509 *cert,
	struct parsed_identity *parsed, time_t iat_ts, str *orig_tn, str *dest_tn,
	int full)
{
	str unsigned_buf = {0,0};
	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY *pubkey = NULL;
	str attest_s, x5u_s, origid_s;
	int rc = -1;
	str der_sig_buf = {0,0};
	unsigned char *der_sig_p;
	ECDSA_SIG *sig = NULL;
	BIGNUM *r_int = NULL, *s_int = NULL;
	char err_buf[256];

	if (parsed->dec_signature.len != RAW_SIG_LEN) {
		LM_ERR("Bad raw signature length [%d], should be [%d]\n",
			parsed->dec_signature.len, RAW_SIG_LEN);
		rc = 0;
		goto error;
	}

	if (!(pubkey = X509_get_pubkey(cert))) {
		LM_ERR("Failed to get public key from certificate\n");
		goto error;
	}

	mdctx = EVP_MD_CTX_create();
	if (!mdctx) {
		LM_ERR("Failed to create signature verification context\n");
		goto error;
	}
	if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey) < 1) {
		LM_ERR("Failed to init signature verification context\n");
		goto error;
	}

	if (full) {
		unsigned_buf = parsed->signing_input;
	} else {
		attest_s.s = parsed->attest->valuestring;
		attest_s.len = strlen(attest_s.s);

		x5u_s.s = parsed->x5u->valuestring;
		x5u_s.len = strlen(x5u_s.s);

		origid_s.s = parsed->origid->valuestring;
		origid_s.len = strlen(origid_s.s);

		if (build_unsigned_pport(&unsigned_buf, iat_ts, &attest_s, &x5u_s,
			orig_tn, dest_tn, &origid_s) < 0) {
			LM_ERR("Failed to build PASSporT\n");
			goto error;
		}
	}
	if (EVP_DigestVerifyUpdate(mdctx, unsigned_buf.s, unsigned_buf.len) < 1) {
		LM_ERR("Failed to add PASSporT to verification context\n");
		goto error;
	}

	/* convert the signature to DER fromat before verifying it
	 * with EVP_DigestVerifyFinal() */

	sig = ECDSA_SIG_new();
	if (!sig)
		goto error;

	#if defined(WOLFSSL_VERSION) || OPENSSL_VERSION_NUMBER < 0x10100000L
	/* R and S components are already initialised by ECDSA_SIG_new() so
	 * they should be passed to BN_bin2bn() */
	r_int = sig->r;
	s_int = sig->s;
	#endif

	r_int = BN_bin2bn((unsigned char*)parsed->dec_signature.s, R_S_INT_LEN,
		r_int);
	if (!r_int) {
		LM_ERR("Failed to convert R integer from binay represantation\n");
		goto error;
	}
	s_int = BN_bin2bn((unsigned char*)parsed->dec_signature.s + R_S_INT_LEN,
		R_S_INT_LEN, s_int);
	if (!s_int) {
		LM_ERR("Failed to convert S integer from binay represantation\n");
		goto error;
	}

	#if !defined(WOLFSSL_VERSION) && OPENSSL_VERSION_NUMBER >= 0x10100000L
	/* set the R and S components as they were not initialised by ECDSA_SIG_new() */
	if (ECDSA_SIG_set0(sig, r_int, s_int) != 1)
		goto error;
	r_int = s_int = NULL; /* sig now owns both integers */
	#endif

	der_sig_buf.len = i2d_ECDSA_SIG(sig, NULL);
	if (!der_sig_buf.len) {
		LM_ERR("Failed to get DER format signature lenght\n");
		goto error;
	}
	der_sig_buf.s = pkg_malloc(der_sig_buf.len);
	if (!der_sig_buf.s) {
		LM_ERR("oom!\n");
		goto error;
	}
	der_sig_p = (unsigned char*)der_sig_buf.s;

	der_sig_buf.len = i2d_ECDSA_SIG(sig, &der_sig_p);
	if (der_sig_buf.len < 0) {
		LM_ERR("Failed to encode raw signature into DER format\n");
		goto error;
	}

	/* so that the error logged below is this one, not a stale one */
	ERR_clear_error();
	rc = EVP_DigestVerifyFinal(mdctx, (unsigned char*)der_sig_buf.s,
		der_sig_buf.len);
	if (rc < 0) {
		ERR_error_string_n(ERR_peek_last_error(), err_buf, 256);
		LM_ERR("openssl: %s\n", err_buf);
		goto error;
	}

	ECDSA_SIG_free(sig);
	EVP_PKEY_free(pubkey);
	EVP_MD_CTX_destroy(mdctx);
	if (!full) pkg_free(unsigned_buf.s);
	pkg_free(der_sig_buf.s);

	return rc;

error:
	#if !defined(WOLFSSL_VERSION) && OPENSSL_VERSION_NUMBER >= 0x10100000L
	BN_free(r_int);
	BN_free(s_int);
	#endif
	if (sig)
		ECDSA_SIG_free(sig);
	if (pubkey)
		EVP_PKEY_free(pubkey);
	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);
	if (!full && unsigned_buf.s)
		pkg_free(unsigned_buf.s);
	if (der_sig_buf.s)
		pkg_free(der_sig_buf.s);
	return rc;
}

int passport_verify_signature(X509 *cert, struct parsed_identity *parsed,
	time_t iat, str *orig, str *dest)
{
	return verify_signature_mode(cert, parsed, iat, orig, dest, 0);
}

int passport_verify_full_signature(X509 *cert, struct parsed_identity *parsed)
{
	return verify_signature_mode(cert, parsed, 0, NULL, NULL, 1);
}

