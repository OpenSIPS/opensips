/*
 * Copyright (C) 2019 OpenSIPS Project
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

#define _XOPEN_SOURCE 600          /* glibc2 on linux, bsd */
#define _XOPEN_SOURCE_EXTENDED 1   /* solaris */

/**
 * _XOPEN_SOURCE creates conflict in swab definition in Solaris
 */
#ifdef __OS_solaris
	#undef _XOPEN_SOURCE
#endif

#include <time.h>

#undef _XOPEN_SOURCE
#undef _XOPEN_SOURCE_EXTENDED

#include <stdlib.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../../dprint.h"
#include "../../sr_module.h"
#include "../../ut.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_pai.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_uri.h"
#include "../../data_lump.h"
#include "../../modules/tls_mgm/api.h"
#include "../../lib/cJSON.h"

#include "stir.h"


static int mod_init(void);
static void mod_destroy(void);

static int w_stir_auth(struct sip_msg *msg, str *attest, str *origid,
	str *cert_buf, str *pkey_buf, str *cr_url, str *orig_tn_p, str *dest_tn_p);
static int w_stir_verify(struct sip_msg *msg, str *cert_buf,
	pv_spec_t *err_code, pv_spec_t *err_reason, str *orig_tn_p, str *dest_tn_p);
static int w_stir_check(struct sip_msg *msg);
static int fixup_attest(void **param);
static int fixup_check_wrvar(void **param);

static int auth_date_freshness = DEFAULT_AUTH_FRESHNESS;
static int verify_date_freshness = DEFAULT_VERIFY_FRESHNESS;

struct tls_mgm_binds tls_mgm_api;

static param_export_t params[] = {
	{"auth_date_freshness", INT_PARAM, &auth_date_freshness},
	{"verify_date_freshness", INT_PARAM, &verify_date_freshness},
	{0, 0, 0}
};

static pv_export_t mod_items[] = {
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

static cmd_export_t cmds[] = {
	{"stir_auth", (cmd_function)w_stir_auth, {
		{CMD_PARAM_STR, fixup_attest, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{"stir_verify", (cmd_function)w_stir_verify, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR, fixup_check_wrvar, 0},
		{CMD_PARAM_VAR, fixup_check_wrvar, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{"stir_check", (cmd_function)w_stir_check,
		{{0,0,0}}, REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

struct module_exports exports = {
	"stir",  		  /* module name*/
	MOD_TYPE_DEFAULT, /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,  /* dlopen flags */
	0,   		/* load function */
	0,          /* OpenSIPS module dependencies */
	0,          /* OpenSIPS dependencies function */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	mod_items,  /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	mod_init,   /* module initialization function */
	0,          /* response function */
	mod_destroy,/* destroy function */
	0,          /* per-child init function */
	0           /* reload confirm function */
};


static int mod_init(void)
{
	if (load_tls_mgm_api(&tls_mgm_api) != 0) {
		LM_ERR("failed to load tls_mgm API!\n");
		return -1;
	}

	return 0;
}

static void mod_destroy(void) {
	return;
}

static int fixup_check_wrvar(void** param)
{
	if (((pv_spec_t *)*param)->setf == NULL) {
		LM_ERR("Output parameter must be a writable variable\n");
		return E_CFG;
	}

	return 0;
}

static int fixup_attest(void **param)
{
	str *s = (str*)*param;

	if (!str_strcasecmp(s, _str("A")) || !str_strcasecmp(s, _str("full")))
		init_str(s, FULL_ATTEST_STR);
	else if (!str_strcasecmp(s, _str("B")) || !str_strcasecmp(s, _str("partial")))
		init_str(s, PARTIAL_ATTEST_STR);
	else if (!str_strcasecmp(s, _str("C")) || !str_strcasecmp(s, _str("gateway")))
		init_str(s, GATEWAY_ATTEST_STR);
	else {
		LM_ERR("Bad attestation level\n");
		return -1;
	}

	return 0;
}

static int get_date_ts(struct hdr_field *date_hf, time_t *date_ts)
{
	char date_s[DATE_MAX_LEN];
	char *tz;
	struct tm date_tm;

	if (date_hf->body.len >= DATE_MAX_LEN) {
		LM_ERR("Date header field to long\n");
		return -1;
	}
	memcpy(date_s, date_hf->body.s, date_hf->body.len);
	date_s[date_hf->body.len] = 0;

	memset(&date_tm, 0, sizeof date_tm);
	if (!strptime(date_s, DATE_FORMAT, &date_tm)) {
		LM_ERR("Failed to parse Date header field\n");
		return -1;
	}

	tz = getenv("TZ");
	setenv("TZ", "", 1);
	tzset();
	*date_ts = mktime(&date_tm);
	if (tz)
		setenv("TZ", tz, 1);
	else
		unsetenv("TZ");
	tzset();

	if (*date_ts == -1) {
		LM_ERR("Failed convert to UNIX time\n");
		return -1;
	}

	return 0;
}

static int add_date_hf(struct sip_msg *msg, time_t *date_ts)
{
	#define DATE_HDR_S  "Date: "
	#define DATE_HDR_L  (sizeof(DATE_HDR_S)-1)

	struct tm *date_tm;
	char *buf;
	int len;
	struct lump* anchor;

	date_tm = gmtime(date_ts);
	if (!date_tm) {
		LM_ERR("Failed to convert timestamp to broken-down time\n");
		return -1;
	}

	buf = pkg_malloc(DATE_HDR_L + DATE_MAX_LEN + CRLF_LEN);
	if (!buf) {
		LM_ERR("oom!\n");
		return -1;
	}

	memcpy(buf, DATE_HDR_S, DATE_HDR_L);
	len = strftime(buf + DATE_HDR_L, DATE_MAX_LEN, DATE_FORMAT, date_tm);
	if (len == 0) {
		LM_ERR("Failed to format date\n");
		pkg_free(buf);
		return -1;
	}
	memcpy(buf + DATE_HDR_L + len, CRLF, CRLF_LEN);

	anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0);
	if (!anchor) {
		LM_ERR("Failed to get anchor lump\n");
		return -1;
	}

	if (!insert_new_lump_before(anchor, buf, DATE_HDR_L+len+CRLF_LEN, 0)) {
		LM_ERR("Failed to insert lump\n");
		return -1;
	}

	return 0;
}

static int check_cert_validity(time_t *timestamp, struct cert_holder *cert)
{
	ASN1_STRING *notBeforeSt;
	ASN1_STRING *notAfterSt;

	notBeforeSt = X509_get_notBefore(cert->cert);
	notAfterSt = X509_get_notAfter(cert->cert);
	if (!notBeforeSt || !notAfterSt) {
		LM_ERR("failed to parse certificate validity\n");
		return 0;
	}

	if (X509_cmp_time(notBeforeSt, timestamp) == -1 &&
		X509_cmp_time(notAfterSt, timestamp) == 1)
		return 1;

	return 0;
}

static char *build_pport_hdr_json(str *cr_url)
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

	item = cJSON_CreateString(PPORT_HDR_PPT_VAL);
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

static int build_unsigned_pport(str *buf, time_t iat_ts, str *attest,
	str *cr_url, str *orig_tn, str *dest_tn, str *origid)
{
	str hdr_json_str = {0,0}, payload_json_str = {0,0};

	hdr_json_str.s = build_pport_hdr_json(cr_url);
	if (!hdr_json_str.s) {
		LM_ERR("Failed to build PASSporT's json header");
		return -1;
	}
	hdr_json_str.len = strlen(hdr_json_str.s);

	payload_json_str.s = build_pport_payload_json(attest, orig_tn, dest_tn,
		iat_ts, origid);
	if (!payload_json_str.s) {
		LM_ERR("Failed to build PASSporT's json payload");
		goto error;
	}
	payload_json_str.len = strlen(payload_json_str.s);

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

static int get_orig_tn_from_msg(struct sip_msg *msg, str *orig_tn)
{
	struct to_body *body;

	if (parse_headers(msg, HDR_PAI_F | HDR_FROM_F, 0) < 0) {
		LM_ERR("Failed to parse headers\n");
		return -1;
	}

	if (msg->pai) {
		if (parse_pai_header(msg) < 0) {
			LM_ERR("Unable to parse P-Asserted-Identity header\n");
			return -1;
		}
		body = get_pai(msg);
	} else {
		if (parse_from_header(msg) < 0) {
			LM_ERR("Unable to parse From header\n");
			return -1;
		}
		body = get_from(msg);
	}

	if (parse_uri(body->uri.s, body->uri.len, &body->parsed_uri) < 0) {
		LM_ERR("Failed to parse URI\n");
		return -1;
	}

	if ((body->parsed_uri.type != SIP_URI_T && body->parsed_uri.type != TEL_URI_T &&
		body->parsed_uri.type != SIPS_URI_T && body->parsed_uri.type != TELS_URI_T) ||
		((body->parsed_uri.type == SIP_URI_T || body->parsed_uri.type == SIPS_URI_T) &&
		str_strcmp(&body->parsed_uri.user_param, _str("user=phone")))) {
		LM_ERR("tel URI required\n");
		return -3;
	}

	if (is_e164(&body->parsed_uri.user) == -1) {
		LM_ERR("E.164 number required\n");
		return -3;
	}

	/* get rid of the '+' sign as it should not appear in the passport claim */
	orig_tn->s = body->parsed_uri.user.s + 1;
	orig_tn->len = body->parsed_uri.user.len - 1;

	return 0;
}

static int get_dest_tn_from_msg(struct sip_msg *msg, str *dest_tn)
{
	struct to_body *body;

	if (parse_to_header(msg) < 0) {
		LM_ERR("Unable to parse From header\n");
		return -1;
	}
	body = get_to(msg);

	if (parse_uri(body->uri.s, body->uri.len, &body->parsed_uri) < 0) {
		LM_ERR("Failed to parse URI\n");
		return -1;
	}
	if ((body->parsed_uri.type != SIP_URI_T && body->parsed_uri.type != TEL_URI_T) ||
		(body->parsed_uri.type == SIP_URI_T &&
		str_strcmp(&body->parsed_uri.user_param, _str("user=phone")))) {
		LM_ERR("tel URI required\n");
		return -3;
	}

	if (is_e164(&body->parsed_uri.user) == -1) {
		LM_ERR("E.164 number required\n");
		return -3;
	}

	/* get rid of the '+' sign as it should not appear in the passport claim */
	dest_tn->s = body->parsed_uri.user.s + 1;
	dest_tn->len = body->parsed_uri.user.len - 1;

	return 0;
}

static int add_identity_hf(struct sip_msg *msg, struct cert_holder *cert,
	time_t date_ts, str *attest, str *cr_url, str *orig_tn,
	str *dest_tn, str *origid)
{
	str hdr_buf = {0,0};
	str unsigned_buf;
	str sig_buf = {0,0};
	struct lump* anchor;
	EVP_MD_CTX *mdctx = NULL;

	if (build_unsigned_pport(&unsigned_buf, date_ts, attest, cr_url,
		orig_tn, dest_tn, origid) < 0) {
		LM_ERR("Failed to build PASSporT\n");
		return -1;
	}

	mdctx = EVP_MD_CTX_create();
	if (!mdctx) {
		LM_ERR("Failed to create signing context\n");
		goto error;
	}
	if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, cert->pkey) <= 0) {
		LM_ERR("Failed to init signing operation\n");
		goto error;
	}
	if (EVP_DigestSignUpdate(mdctx, unsigned_buf.s, unsigned_buf.len) <= 0) {
		LM_ERR("Failed to add data to signing context\n");
		goto error;
	}

	if (EVP_DigestSignFinal(mdctx, NULL, (size_t *)&sig_buf.len) <= 0) {
		LM_ERR("Failed to get maximum signature length\n");
		goto error;
	}
	sig_buf.s = pkg_malloc(sig_buf.len);
	if (!sig_buf.s) {
		LM_ERR("oom!\n");
		goto error;
	}
	if (EVP_DigestSignFinal(mdctx, (unsigned char*)sig_buf.s,
		(size_t *)&sig_buf.len) <= 0) {
		LM_ERR("Failed to sign data\n");
		goto error;
	}
	EVP_MD_CTX_destroy(mdctx);

	hdr_buf.len = IDENTITY_HDR_LEN + unsigned_buf.len + 1/*'.'*/ +
		calc_base64_encode_len(sig_buf.len) + 1/*';'*/ + HDR_INFO_PARAM_LEN +
		2/*'<','>'*/ + cr_url->len + 1/*';'*/ + HDR_PPT_PARAM_LEN;
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

	base64urlencode((unsigned char*)(hdr_buf.s + hdr_buf.len),
		(unsigned char*)sig_buf.s, sig_buf.len);
	hdr_buf.len += calc_base64_encode_len(sig_buf.len);
	if (hdr_buf.s[hdr_buf.len-1] == BASE64_PAD_CHAR)
		hdr_buf.len--;
	if (hdr_buf.s[hdr_buf.len-1] == BASE64_PAD_CHAR)
		hdr_buf.len--;

	pkg_free(sig_buf.s);

	hdr_buf.s[hdr_buf.len++] = ';';
	memcpy(hdr_buf.s + hdr_buf.len, HDR_INFO_PARAM_S, HDR_INFO_PARAM_LEN);
	hdr_buf.len += HDR_INFO_PARAM_LEN;
	hdr_buf.s[hdr_buf.len++] = '<';
	memcpy(hdr_buf.s + hdr_buf.len, cr_url->s, cr_url->len);
	hdr_buf.len += cr_url->len;
	hdr_buf.s[hdr_buf.len++] = '>';
	hdr_buf.s[hdr_buf.len++] = ';';
	memcpy(hdr_buf.s + hdr_buf.len, HDR_PPT_PARAM_S, HDR_PPT_PARAM_LEN);
	hdr_buf.len += HDR_PPT_PARAM_LEN;
	memcpy(hdr_buf.s + hdr_buf.len, CRLF, CRLF_LEN);
	hdr_buf.len += CRLF_LEN;

	anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0);
	if (!anchor) {
		LM_ERR("Failed to get anchor lump\n");
		goto error;
	}
	if (!insert_new_lump_before(anchor, hdr_buf.s, hdr_buf.len, 0)) {
		LM_ERR("Failed to insert lump\n");
		goto error;
	}

	return 0;

error:
	pkg_free(unsigned_buf.s);
	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);
	if (hdr_buf.s)
		pkg_free(hdr_buf.s);
	if (sig_buf.s)
		pkg_free(sig_buf.s);
	return -1;
}

static int w_stir_auth(struct sip_msg *msg, str *attest, str *origid,
	str *cert_buf, str *pkey_buf, str *cr_url, str *orig_tn_p, str *dest_tn_p)
{
	time_t now, date_ts;
	struct hdr_field *date_hf = NULL;
	struct cert_holder *cert;
	str orig_tn, dest_tn;
	int rc;

	/* looking for 'Identity' and 'Date' */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("Failed to parse headers\n");
		return -1;
	}

	if (get_header_by_static_name(msg, "Identity")) {
		LM_ERR("Identity header already exists");
		return -2;
	}

	if (!orig_tn_p) {
		if ((rc = get_orig_tn_from_msg(msg, &orig_tn)) < 0) {
			if (rc == -1)
				LM_ERR("Failed to determine Originator's identity\n");
			else
				LM_INFO("Unable to determine Originator's identity\n");
			return rc;
		}
		orig_tn_p = &orig_tn;
	}
	if (!dest_tn_p) {
		if ((rc = get_dest_tn_from_msg(msg, &dest_tn)) < 0) {
			if (rc == -1)
				LM_ERR("Failed to determine Destinations's identity\n");
			else
				LM_INFO("Unable to determine Destinations's identity\n");
			return rc;
		}
		dest_tn_p = &dest_tn;
	}

	if ((now = time(0)) == -1) {
		LM_ERR("Failed to get current time\n");
		return -1;
	}

	/* verify date header and add one if not present */
	date_hf = get_header_by_static_name(msg, "Date");
	if (!date_hf) {
		if (add_date_hf(msg, &now) < 0) {
			LM_ERR("Failed to add Date header\n");
			return -1;
		}

		date_ts = now;
	} else {
		if (get_date_ts(date_hf, &date_ts) < 0) {
			LM_ERR("Failed to get UNIX time from Date header\n");
			return -1;
		}

		if (now - date_ts > auth_date_freshness)
			return -4;
	}

	cert = tls_mgm_api.new_cert_holder(cert_buf, pkey_buf);
	if (!cert) {
		LM_ERR("Failed to load certificate\n");
		return -1;
	}

	if (!check_cert_validity(&now, cert)) {
		LM_ERR("The current time does not fall within the certificate validity\n");
		rc = -5;
		goto error;
	}
	if (date_ts != now && !check_cert_validity(&date_ts, cert)) {
		LM_ERR("The Date header does not fall within the certificate validity\n");
		rc = -5;
		goto error;
	}

	if (add_identity_hf(msg, cert, date_ts, attest, cr_url,
		orig_tn_p, dest_tn_p, origid) < 0) {
		LM_ERR("Failed to add Identity header\n");
		goto error;
	}

	tls_mgm_api.free_cert_holder(cert);

	return 1;

error:
	tls_mgm_api.free_cert_holder(cert);
	return rc;
}

static int w_stir_check(struct sip_msg *msg) {
	return 1;
}

static int w_stir_verify(struct sip_msg *msg, str *cert_buf,
	pv_spec_t *err_code_var, pv_spec_t *err_reason_var,
	str *orig_tn_p, str *dest_tn_p)
{
	return 1;
}
