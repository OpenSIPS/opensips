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
#include "../../parser/parse_param.h"
#include "../../data_lump.h"
#include "../../modules/tls_mgm/api.h"
#include "../../lib/cJSON.h"
#include "../../context.h"

#include "stir.h"

#define parsed_ctx_get() \
	(current_processing_ctx == NULL ? NULL : \
	((struct parsed_identity *)context_get_ptr(CONTEXT_GLOBAL, \
	current_processing_ctx, parsed_ctx_idx)))

#define parsed_ctx_set(_ptr) \
	context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx, parsed_ctx_idx, _ptr)

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
static char *ca_list;
static char *crl_list;

struct tls_mgm_binds tls_mgm_api;

static int tn_authlist_nid;

static int parsed_ctx_idx =-1;

static X509_STORE *store;
static X509_STORE_CTX *verify_ctx;

static param_export_t params[] = {
	{"auth_date_freshness", INT_PARAM, &auth_date_freshness},
	{"verify_date_freshness", INT_PARAM, &verify_date_freshness},
	{"ca_list", STR_PARAM, &ca_list},
	{"crl_list", STR_PARAM, &crl_list},
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


static int verify_callback(int ok, X509_STORE_CTX *ctx)
{
	int err;

	if (!ok) {
		err = X509_STORE_CTX_get_error(ctx);
		LM_INFO("certificate validation failed: %s\n",
			X509_verify_cert_error_string(err));
	}

	return ok;
}

static int init_cert_validation(void)
{
	X509_LOOKUP *lookup;

	store = X509_STORE_new();
	if (!store) {
		LM_ERR("Failed to create X509_STORE_CTX object\n");
		return -1;
	}
	X509_STORE_set_verify_cb_func(store, verify_callback);

	if (ca_list && X509_STORE_load_locations(store, ca_list, NULL) != 1) {
		LM_ERR("Failed to load trustefd CAs\n");
		return -1;
	}
	if (X509_STORE_set_default_paths(store) != 1) {
		LM_ERR("Failed to loade the system-wide CA certificates\n");
		return -1;
	}

	if (crl_list) {
		if (!(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file()))) {
			LM_ERR("Failed to create X509_LOOKUP object\n");
			return -1;
		}
		if (X509_load_crl_file(lookup, crl_list, X509_FILETYPE_PEM) < 1) {
			LM_ERR("Failed to read the CRLs file\n");
			return -1;
		}
	}

	if (!(verify_ctx = X509_STORE_CTX_new())) {
		LM_ERR("Failed to create X509_STORE_CTX object\n");
		return -1;
	}

	return 0;
}

static void parsed_ctx_free(void *param)
{
	struct parsed_identity *parsed = (struct parsed_identity *)param;

	if (parsed) {
		cJSON_Delete(parsed->header);
		cJSON_Delete(parsed->payload);
		pkg_free(parsed->dec_header.s);
		pkg_free(parsed->dec_payload.s);
		pkg_free(parsed->dec_signature.s);
	}

	pkg_free(parsed);
}

static int mod_init(void)
{
	if (load_tls_mgm_api(&tls_mgm_api) != 0) {
		LM_ERR("failed to load tls_mgm API!\n");
		return -1;
	}

	tn_authlist_nid = OBJ_create(TN_AUTH_LIST_OID,
		TN_AUTH_LIST_SN, TN_AUTH_LIST_LN);
	if (tn_authlist_nid == NID_undef) {
		LM_ERR("Failed to create new openssl object\n");
		return -1;
	}

	if (init_cert_validation() < 0)
		return -1;

	parsed_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, parsed_ctx_free);

	return 0;
}

static void mod_destroy(void) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	OBJ_cleanup();
#endif
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

	if (X509_cmp_time(notBeforeSt, timestamp) < 0 &&
		X509_cmp_time(notAfterSt, timestamp) > 0)
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
		LM_INFO("tel URI required\n");
		return -3;
	}

	if (is_e164(&body->parsed_uri.user) == -1) {
		LM_INFO("E.164 number required\n");
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
		LM_INFO("Identity header already exists");
		return -2;
	}

	if (!orig_tn_p) {
		if ((rc = get_orig_tn_from_msg(msg, &orig_tn)) < 0) {
			if (rc == -1)
				LM_ERR("Error determining Originator's identity\n");
			else
				LM_INFO("Originator's URI is not a telephone number\n");
			return rc;
		}
		orig_tn_p = &orig_tn;
	}
	if (!dest_tn_p) {
		if ((rc = get_dest_tn_from_msg(msg, &dest_tn)) < 0) {
			if (rc == -1)
				LM_ERR("Error determining Destinations's identity\n");
			else
				LM_INFO("Destinations's URI is not a telephone number\n");
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

		if (now - date_ts > auth_date_freshness) {
			LM_INFO("Date header value is older than local policy\n");
			return -4;
		}
	}

	cert = tls_mgm_api.new_cert_holder(cert_buf, pkey_buf);
	if (!cert) {
		LM_ERR("Error loading certificate\n");
		return -1;
	}

	if (!check_cert_validity(&now, cert)) {
		LM_INFO("The current time does not fall within the certificate validity\n");
		rc = -5;
		goto error;
	}
	if (date_ts != now && !check_cert_validity(&date_ts, cert)) {
		LM_INFO("The Date header does not fall within the certificate validity\n");
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

static int parse_identity_hf(str *hdr_buf, struct parsed_identity *parsed)
{
	str header_str, payload_str, sig_str, params_str;
	char *p;
	param_hooks_t _;
	param_t* params = NULL;
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
	while (params) {
		if (!str_strcmp(_str("alg"), &params->name))
			parsed->alg_hdr_param = params->body;
		if (!str_strcmp(_str("ppt"), &params->name))
			parsed->ppt_hdr_param = params->body;

		params = params->next;
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

	parsed->header = cJSON_Parse(parsed->dec_header.s);
	if (!parsed->header) {
		LM_INFO("Failed to parse PASSporT Header JSON\n");
		goto invalid_hdr;
	}

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

	parsed->payload = cJSON_Parse(parsed->dec_payload.s);
	if (!parsed->payload) {
		LM_INFO("Failed to parse PASSporT Payload JSON\n");
		goto invalid_hdr;
	}

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
	if (parsed->dec_header.s)
		pkg_free(parsed->dec_header.s);
	if (parsed->dec_payload.s)
		pkg_free(parsed->dec_payload.s);
	if (parsed->dec_signature.s)
		pkg_free(parsed->dec_signature.s);
	if (parsed->header)
		cJSON_Delete(parsed->header);
	if (parsed->payload)
		cJSON_Delete(parsed->payload);
	return rc;
}

static char *get_pport_orig_tn(cJSON *payload)
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
	if (item->type != cJSON_String) {
		LM_INFO("'tn' from 'orig' should be a string\n");
		return NULL;
	}

	return item->valuestring;
}

static char *get_pport_dest_tn(cJSON *payload)
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
	if (item->type != cJSON_String) {
		LM_INFO("Number in 'tn' from 'dest' should be a string\n");
		return NULL;
	}

	return item->valuestring;
}

static inline time_t get_pport_iat_ts(cJSON *header)
{
	cJSON *item;

	if (!(item = cJSON_GetObjectItem(header, PPORT_PAYLOAD_IAT))) {
		LM_INFO("Missing 'iat' claim\n");
		return -1;
	}
	if (item->type != cJSON_Number) {
		LM_INFO("'iat' value should be a number\n");
		return -1;
	}

	return (time_t)item->valuedouble;
}

static int check_passport_claims(cJSON *header, cJSON *payload,
	char **orig_tn, char **dest_tn, time_t *iat_ts)
{
	cJSON *item;

	if (!(item = cJSON_GetObjectItem(header, PPORT_HDR_ALG))) {
		LM_INFO("Missing 'alg' claim\n");
		return -1;
	}
	if (item->type != cJSON_String) {
		LM_INFO("'alg' value should be a string\n");
		return -1;
	}

	if (!(item = cJSON_GetObjectItem(header, PPORT_HDR_PPT))) {
		LM_INFO("Missing 'ppt' claim\n");
		return -1;
	}
	if (item->type != cJSON_String) {
		LM_INFO("'ppt' value should be a string\n");
		return -1;
	}

	if (!(item = cJSON_GetObjectItem(header, PPORT_HDR_TYP))) {
		LM_INFO("Missing 'typ' claim\n");
		return -1;
	}
	if (item->type != cJSON_String) {
		LM_INFO("'typ' value should be a string\n");
		return -1;
	}

	if (!(item = cJSON_GetObjectItem(header, PPORT_HDR_X5U))) {
		LM_INFO("Missing 'x5u' claim\n");
		return -1;
	}
	if (item->type != cJSON_String) {
		LM_INFO("'x5u' value should be a string\n");
		return -1;
	}

	if (!(item = cJSON_GetObjectItem(payload, PPORT_PAYLOAD_ATTEST))) {
		LM_INFO("Missing 'attest' claim\n");
		return -1;
	}
	if (item->type != cJSON_String) {
		LM_INFO("'attest' value should be a string\n");
		return -1;
	}

	if (!(*dest_tn = get_pport_dest_tn(payload)))
		return -1;

	if ((*iat_ts = get_pport_iat_ts(payload)) == -1)
		return -1;

	if (!(*orig_tn = get_pport_orig_tn(payload)))
		return -1;

	if (!(item = cJSON_GetObjectItem(payload, PPORT_PAYLOAD_ORIGID))) {
		LM_INFO("Missing 'origid' claim\n");
		return -1;
	}
	if (item->type != cJSON_String) {
		LM_INFO("'origid' value should be a string\n");
		return -1;
	}

	return 0;
}

static int validate_certificate(struct cert_holder *cert)
{
	int rc;

	/* check the TN Authorization list extension */
	if (X509_get_ext_by_NID(cert->cert, tn_authlist_nid, -1) == -1) {
		LM_INFO("The certificate is missing the TnAuthList extension\n");
		return -8;
	}

	if (X509_STORE_CTX_init(verify_ctx, store,
		cert->cert, cert->certchain) != 1) {
		X509_STORE_CTX_cleanup(verify_ctx);
		LM_ERR("Error initializing verification context\n");
		return -1;
	}

	rc = X509_verify_cert(verify_ctx);
	X509_STORE_CTX_cleanup(verify_ctx);

	if (rc != 1)
		return rc == 0 ? -8 : -1;
	else
		return 0;
}

static int verify_signature(struct cert_holder *cert, cJSON *header,
	cJSON *payload, str *signature, time_t iat_ts, str *orig_tn, str *dest_tn)
{
	str unsigned_buf = {0,0};
	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY *pubkey = NULL;
	cJSON *attest, *x5u, *origid;
	str attest_s, x5u_s, origid_s;
	int rc = -1;

	if (!(pubkey = X509_get_pubkey(cert->cert))) {
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
		rc = -1;
		goto error;
	}

	attest = cJSON_GetObjectItem(payload, PPORT_PAYLOAD_ATTEST);
	if (!attest) {
		LM_ERR("MIssing 'attest' claim\n");
		goto error;
	}
	attest_s.s = attest->valuestring;
	attest_s.len = strlen(attest_s.s);

	x5u = cJSON_GetObjectItem(header, PPORT_HDR_X5U);
	if (!x5u) {
		LM_ERR("MIssing 'x5u' claim\n");
		goto error;
	}
	x5u_s.s = x5u->valuestring;
	x5u_s.len = strlen(x5u_s.s);

	origid = cJSON_GetObjectItem(payload, PPORT_PAYLOAD_ORIGID);
	if (!origid) {
		LM_ERR("MIssing 'origid' claim\n");
		goto error;
	}
	origid_s.s = origid->valuestring;
	origid_s.len = strlen(origid_s.s);

	if (build_unsigned_pport(&unsigned_buf, iat_ts, &attest_s, &x5u_s,
		orig_tn, dest_tn, &origid_s) < 0) {
		LM_ERR("Failed to build PASSporT\n");
		rc = -1;
		goto error;
	}
	if (EVP_DigestVerifyUpdate(mdctx, unsigned_buf.s, unsigned_buf.len) < 1) {
		LM_ERR("Failed to add PASSporT to verification context\n");
		goto error;
	}

	rc = EVP_DigestVerifyFinal(mdctx, (unsigned char*)signature->s,
		signature->len);
	if (rc == 0)
		goto verify_fail;
	else if (rc != 1)
		goto error;

	EVP_PKEY_free(pubkey);
	EVP_MD_CTX_destroy(mdctx);
	pkg_free(unsigned_buf.s);

	return 0;

verify_fail:
	rc = -9;
error:
	if (pubkey)
		EVP_PKEY_free(pubkey);
	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);
	if (unsigned_buf.s)
		pkg_free(unsigned_buf.s);
	return rc;
}

static int get_parsed_identity(struct hdr_field *identity_hdr,
	struct parsed_identity **parsed)
{
	int rc = 0;

	*parsed = parsed_ctx_get();
	if (*parsed == NULL) {
		if (!current_processing_ctx) {
			LM_ERR("no processing ctx found!\n");
			return -1;
		}

		*parsed = pkg_malloc(sizeof **parsed);
		if (*parsed == NULL) {
			LM_ERR("oom!\n");
			return -1;
		}
		memset(*parsed, 0, sizeof **parsed);

		rc = parse_identity_hf(&identity_hdr->body, *parsed);
		if (rc == 0)
			parsed_ctx_set(*parsed);
		else
			pkg_free(*parsed);
	}

	return rc;
}

static int set_err_resp_vars(struct sip_msg *msg, pv_spec_t *err_code_var,
	pv_spec_t *err_reason_var, int code, char *reason)
{
	pv_value_t err_code_val, err_reason_val;

	err_code_val.flags = PV_TYPE_INT;
	err_code_val.ri = code;
	if (pv_set_value(msg, err_code_var, 0, &err_code_val) != 0)
		return -1;

	err_reason_val.flags = PV_VAL_STR;
	init_str(&err_reason_val.rs, reason);
	if (pv_set_value(msg, err_reason_var, 0, &err_reason_val) != 0)
		return -1;

	return 0;
}

#define SET_VERIFY_ERR_VARS(_code, _reason)  \
	do {  \
		if (set_err_resp_vars(msg, err_code_var, err_reason_var,  \
			_code, _reason) < 0) {  \
			LM_ERR("Failed to set error output variables\n");  \
			rc = -1;  \
			goto error;  \
		}  \
	} while (0)

static int w_stir_verify(struct sip_msg *msg, str *cert_buf,
	pv_spec_t *err_code_var, pv_spec_t *err_reason_var,
	str *orig_tn_p, str *dest_tn_p)
{
	struct hdr_field *identity_hdr;
	str orig_tn, dest_tn, pport_orig_tn, pport_dest_tn;
	time_t now, date_ts, iat_ts;
	struct hdr_field *date_hf = NULL;
	struct cert_holder *cert = NULL;
	struct parsed_identity *parsed;
	int rc;

	/* looking for 'Identity' and 'Date' */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("Failed to parse headers\n");
		return -1;
	}

	if (!(identity_hdr = get_header_by_static_name(msg, "Identity"))) {
		LM_INFO("No Identity header found\n");
		SET_VERIFY_ERR_VARS(USE_IDENTITY_CODE, USE_IDENTITY_REASON);
		return -2;
	}

	if (!orig_tn_p) {
		if ((rc = get_orig_tn_from_msg(msg, &orig_tn)) < 0) {
			if (rc == -1)
				LM_ERR("Error determining Originator's identity\n");
			else  /* rc == -3 */
				LM_INFO("Originator's URI is not a telephone number\n");
			return rc;
		}
		orig_tn_p = &orig_tn;
	}
	if (!dest_tn_p) {
		if ((rc = get_dest_tn_from_msg(msg, &dest_tn)) < 0) {
			if (rc == -1)
				LM_ERR("Error determining Destinations's identity\n");
			else  /* rc == -3 */
				LM_INFO("Destinations's URI is not a telephone number\n");
			return rc;
		}
		dest_tn_p = &dest_tn;
	}

	if ((rc = get_parsed_identity(identity_hdr, &parsed)) < 0) {
		if (rc == -1) {
			LM_ERR("Failed to parse identity header\n");
		} else {  /* rc == -4 */
			LM_INFO("Invalid identity header\n");
			SET_VERIFY_ERR_VARS(INVALID_IDENTITY_CODE, INVALID_IDENTITY_REASON);
		}

		return rc;
	}

	if (str_strcmp(&parsed->ppt_hdr_param, _str(PPORT_HDR_PPT_VAL))) {
		LM_INFO("Unsupported 'ppt' extension\n");
		rc = -5;
		goto error;
	}
	if (parsed->alg_hdr_param.s &&
		str_strcmp(&parsed->alg_hdr_param, _str(PPORT_HDR_ALG_VAL))) {
		LM_INFO("Unsupported 'alg'\n");
		rc = -5;
		goto error;
	}

	if (check_passport_claims(parsed->header, parsed->payload,
		&pport_orig_tn.s, &pport_dest_tn.s, &iat_ts) < 0) {
		LM_INFO("Required PASSporT claims are missing or have bad datatypes\n");
		SET_VERIFY_ERR_VARS(INVALID_IDENTITY_CODE, INVALID_IDENTITY_REASON);
		rc = -4;
		goto error;
	}

	date_hf = get_header_by_static_name(msg, "Date");
	if (!date_hf) {
		LM_INFO("No Date header found\n");
		SET_VERIFY_ERR_VARS(STALE_DATE_CODE, STALE_DATE_REASON);
		rc = -2;
		goto error;
	}

	if (get_date_ts(date_hf, &date_ts) < 0) {
		LM_ERR("Failed to get UNIX time from Date header\n");
		rc = -1;
		goto error;
	}

	if ((now = time(0)) == -1) {
		LM_ERR("Failed to get current time\n");
		rc = -1;
		goto error;
	}
	if (now - date_ts > verify_date_freshness) {
		LM_INFO("Date header value is older than local policy\n");
		SET_VERIFY_ERR_VARS(STALE_DATE_CODE, STALE_DATE_REASON);
		rc = -6;
		goto error;
	}

	/* if the identities in the PASSporT and SIP message are different
	 * the signature verification would fail anyway */
	pport_orig_tn.len = strlen(pport_orig_tn.s);
	pport_dest_tn.len = strlen(pport_dest_tn.s);
	if (str_strcmp(&pport_orig_tn, orig_tn_p) ||
		str_strcmp(&pport_dest_tn, dest_tn_p)) {
		LM_INFO("Signature would not verify successfully\n");
		SET_VERIFY_ERR_VARS(INVALID_IDENTITY_CODE, INVALID_IDENTITY_REASON);
		rc = -9;
		goto error;
	}

	cert = tls_mgm_api.new_cert_holder(cert_buf, NULL);
	if (!cert) {
		LM_ERR("Error loading certificate\n");
		rc = -1;
		goto error;
	}

	if (!check_cert_validity(&date_ts, cert)) {
		LM_INFO("The Date header does not fall within the certificate validity\n");
		SET_VERIFY_ERR_VARS(STALE_DATE_CODE, STALE_DATE_REASON);
		rc = -7;
		goto error;
	}

	if ((rc = validate_certificate(cert)) < 0) {
		if (rc == -1) {
			LM_ERR("Error validating certificate\n");
			goto error;
		} else {  /* rc == -8 */
			LM_INFO("Invalid certificate\n");
			SET_VERIFY_ERR_VARS(UNSUPPORTED_CRED_CODE, UNSUPPORTED_CRED_REASON);
			goto error;
		}
	}

	if (iat_ts != date_ts && (now - iat_ts > verify_date_freshness))
		iat_ts = date_ts;

	if ((rc = verify_signature(cert, parsed->header, parsed->payload,
		&parsed->dec_signature, iat_ts, orig_tn_p, dest_tn_p)) < 0) {
		if (rc == -1) {
			LM_ERR("Error verifying signature\n");
			goto error;
		} else {  /* rc == -9 */
			LM_INFO("Signature did not verify successfully\n");
			SET_VERIFY_ERR_VARS(INVALID_IDENTITY_CODE, INVALID_IDENTITY_REASON);
			goto error;
		}
	}

	tls_mgm_api.free_cert_holder(cert);

	return 1;
error:
	if (cert)
		tls_mgm_api.free_cert_holder(cert);
	return rc;
}

static int w_stir_check(struct sip_msg *msg)
{
	struct hdr_field *identity_hdr;
	struct parsed_identity *parsed;
	time_t iat_ts;
	str orig_tn, dest_tn;
	int rc;

	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("Failed to parse headers\n");
		return -1;
	}

	if (!(identity_hdr = get_header_by_static_name(msg, "Identity"))) {
		LM_INFO("No Identity header found\n");
		return -2;
	}

	if ((rc = get_parsed_identity(identity_hdr, &parsed)) < 0) {
		if (rc == -1) {
			LM_ERR("Failed to parse identity header\n");
			return -1;
		} else {
			LM_INFO("Invalid identity header\n");
			return -3;
		}
	}

	if (str_strcmp(&parsed->ppt_hdr_param, _str(PPORT_HDR_PPT_VAL))) {
		LM_INFO("Unsupported 'ppt' extension\n");
		return -4;
	}
	if (parsed->alg_hdr_param.s &&
		str_strcmp(&parsed->alg_hdr_param, _str(PPORT_HDR_ALG_VAL))) {
		LM_INFO("Unsupported 'alg'\n");
		return -4;
	}

	if (check_passport_claims(parsed->header, parsed->payload,
		&orig_tn.s, &dest_tn.s, &iat_ts) < 0) {
		LM_INFO("Required PASSporT claims are missing or have bad datatypes\n");
		return -3;
	}

	return 1;
}
