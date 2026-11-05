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

/* make strptime available */
#define _GNU_SOURCE
#include <time.h>

#include "passport.h"

#undef _GNU_SOURCE

#include <stdlib.h>
#include <math.h>

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
#include "../../lib/cJSON.h"
#include "../../context.h"
#include "../../mod_fix.h"
#include "../../data_lump_rpl.h"
#include "../../mi/mi.h"

#include "stir_shaken.h"
#include "div.h"
#include "verstat.h"
#include "verify.h"

#define parsed_ctx_get() \
	(current_processing_ctx == NULL ? NULL : \
	((struct parsed_identity *)context_get_ptr(CONTEXT_GLOBAL, \
	current_processing_ctx, parsed_ctx_idx)))

#define parsed_ctx_set(_ptr) \
	context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx, parsed_ctx_idx, _ptr)

#define SS_LOCK \
	do { \
		if (ss_openssl_lock) \
			lock_get(ss_openssl_lock); \
		else \
			LM_DBG("cannot lock openssl\n"); \
	} while (0)
#define SS_UNLOCK \
	do { \
		if (ss_openssl_lock) \
			lock_release(ss_openssl_lock); \
	} while (0)

/*
 * Module core functions
 */
static int mod_init(void);
static void mod_destroy(void);


/*
 * Module internal functions
 */
static int fixup_auth_out(void** param);
static int set_verify_date_div_freshness(modparam_t type, void *value);


/*
 * Script functions
 */
static int w_stir_auth(struct sip_msg *msg, str *attest, str *origid,
	str *cert_buf, str *pkey_buf, str *cr_url, str *orig_tn_p, str *dest_tn_p,
	struct auth_out_param *out);
static int w_stir_disengagement(struct sip_msg *msg, str *token);
static int w_stir_verify(struct sip_msg *msg, str *cert_buf,
	pv_spec_t *err_code, pv_spec_t *err_reason, str *orig_tn_p, str *dest_tn_p);
static int w_stir_check(struct sip_msg *msg);
static int w_stir_check_cert(struct sip_msg *msg, str *cert_buf);
static int w_stir_auth_div(struct sip_msg *msg, str *cert_buf, str *key_buf,
	str *x5u, str *orig, str *div, str *dest, struct auth_out_param *out,
	int *previously_verified);
static int fixup_attest(void **param);
static int fixup_check_wrvar(void **param);

/*
 * MI functions
 */
mi_response_t *mi_stir_shaken_ca_reload(const mi_params_t *params, struct mi_handler *async_hdl);
mi_response_t *mi_stir_shaken_crl_reload(const mi_params_t *params, struct mi_handler *async_hdl);


/*
 * Module internal parameter variables
 */
static int auth_date_freshness = DEFAULT_AUTH_FRESHNESS;
static int verify_date_freshness = DEFAULT_VERIFY_FRESHNESS;
static int verify_date_div_freshness_configured;
static char *ca_list;
static char *ca_dir;
static char *crl_list;
static char *crl_dir;

static int e164_strict_mode;
static int e164_max_length = 15;

static int require_date_hdr = 1;

static ASN1_OBJECT *tn_authlist_obj;

static int parsed_ctx_idx =-1;
static int generated_ctx_idx = -1;
static int stale_ctx_idx = -1;

struct generated_identity {
	struct sip_msg *msg;
	unsigned int msg_id;
	str body;
	struct generated_identity *next;
};

static X509_STORE *store;
static gen_lock_t *ss_openssl_lock;


static const param_export_t params[] = {
	{"auth_date_freshness", INT_PARAM, &auth_date_freshness},
	{"verify_date_freshness", INT_PARAM, &verify_date_freshness},
	{"verify_date_div_freshness", INT_PARAM|USE_FUNC_PARAM,
		(void *)set_verify_date_div_freshness},
	{"ca_list", STR_PARAM, &ca_list},
	{"ca_dir", STR_PARAM, &ca_dir},
	{"crl_list", STR_PARAM, &crl_list},
	{"crl_dir", STR_PARAM, &crl_dir},
	{"e164_strict_mode", INT_PARAM, &e164_strict_mode},
	{"e164_max_length", INT_PARAM, &e164_max_length},
	{"require_date_hdr", INT_PARAM, &require_date_hdr},
	{0, 0, 0}
};

static const pv_export_t mod_items[] = {
	{str_const_init("identity"), 1000, pv_get_identity_all,
		0, pv_parse_identity_all, pv_parse_index, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

static const cmd_export_t cmds[] = {
	{"stir_shaken_verify_passport", (cmd_function)stir_shaken_verify_passport, {
		{CMD_PARAM_INT, 0, 0}, {CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR, fixup_check_wrvar, 0},
		{CMD_PARAM_VAR, fixup_check_wrvar, 0}, {0,0,0}}, REQUEST_ROUTE},
	{"stir_shaken_verify_chain", (cmd_function)stir_shaken_verify_chain, {
		{CMD_PARAM_VAR, fixup_check_wrvar, 0},
		{CMD_PARAM_VAR, fixup_check_wrvar, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0}, {0,0,0}}, REQUEST_ROUTE},
	{"stir_shaken_set_verstat", (cmd_function)stir_shaken_set_verstat, {
		{CMD_PARAM_STR, 0, 0}, {CMD_PARAM_STR, 0, 0}, {0,0,0}}, REQUEST_ROUTE},
	{"stir_shaken_remove_verstat", (cmd_function)stir_shaken_remove_verstat, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}}, REQUEST_ROUTE},
	{"stir_shaken_auth_div", (cmd_function)w_stir_auth_div, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_NO_EXPAND,
			fixup_auth_out, fixup_free_pkg},
		{CMD_PARAM_INT|CMD_PARAM_OPT|CMD_PARAM_NULLABLE, 0, 0}, {0,0,0}}, REQUEST_ROUTE},
	{"stir_shaken_auth", (cmd_function)w_stir_auth, {
		{CMD_PARAM_STR, fixup_attest, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_NO_EXPAND,
			fixup_auth_out, fixup_free_pkg}, {0,0,0}},
		REQUEST_ROUTE},
	{"stir_shaken_disengagement", (cmd_function)w_stir_disengagement, {
		{CMD_PARAM_STR, 0, 0},
		{0,0,0}}, REQUEST_ROUTE},
	{"stir_shaken_verify", (cmd_function)w_stir_verify, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR, fixup_check_wrvar, 0},
		{CMD_PARAM_VAR, fixup_check_wrvar, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{"stir_shaken_check", (cmd_function)w_stir_check,
		{{0,0,0}}, REQUEST_ROUTE},
	{"stir_shaken_check_cert", (cmd_function)w_stir_check_cert, {
		{CMD_PARAM_STR, 0, 0},
		{0,0,0}}, REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported MI functions
 */
static const mi_export_t mi_cmds[] = {
	{ "ca_reload", "Stir shaken ca reloader", 0, 0, {
		{mi_stir_shaken_ca_reload, {0}},
		{EMPTY_MI_RECIPE}}, {"stir_shaken_ca_reload", 0}
	},
	{ "crl_reload", "Stir shaken crl reloader", 0, 0, {
		{mi_stir_shaken_crl_reload, {0}},
		{EMPTY_MI_RECIPE}}, {"stir_shaken_crl_reload", 0}
	},
	{EMPTY_MI_EXPORT}
};


/*
 * Module interface
 */
struct module_exports exports = {
	"stir_shaken",    /* module name*/
	MOD_TYPE_DEFAULT, /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,  /* dlopen flags */
	0,   		/* load function */
	0,          /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	mi_cmds,	/* exported MI functions */
	mod_items,  /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
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

static int ss_store_set_default_paths(X509_STORE *x509_store)
{
#ifdef WOLFSSL_VERSION
	return wolfSSL_X509_STORE_set_default_paths(x509_store);
#else
	return X509_STORE_set_default_paths(x509_store);
#endif
}

static void ss_store_set_verify_cb(X509_STORE *x509_store,
	int (*verify_cb)(int, X509_STORE_CTX *))
{
#ifdef WOLFSSL_VERSION
	/* Older wolfSSL builds may not provide store-level callback setter. */
	(void)x509_store;
	(void)verify_cb;
#else
	X509_STORE_set_verify_cb_func(x509_store, verify_cb);
#endif
}

// called during mod_init
static int init_cert_validation(void)
{
	store = X509_STORE_new();
	if (!store) {
		LM_ERR("Failed to create X509_STORE_CTX object\n");
		return -1;
	}
	ss_store_set_verify_cb(store, verify_callback);

	if (ca_list || ca_dir) {
		if (X509_STORE_load_locations(store, ca_list, ca_dir) != 1) {
			LM_ERR("Failed to load trusted CAs\n");
			return -1;
		}
		if (ss_store_set_default_paths(store) != 1) {
			LM_ERR("Failed to load the system-wide CA certificates\n");
			return -1;
		}
	}

	if (crl_list || crl_dir) {
		if (X509_STORE_load_locations(store, crl_list, crl_dir) != 1) {
			LM_ERR("Failed to load CRLs\n");
			return -1;
		}
		X509_STORE_set_flags(store,
			X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
	}

	ss_openssl_lock = lock_alloc();
	if (!ss_openssl_lock || !lock_init(ss_openssl_lock)) {
		LM_ERR("could not allocate openssl lock\n");
		ss_openssl_lock = NULL;
	}

	return 0;
}

// store check then reload ca_list and ca_dir
static int init_cert_ca_reload(void)
{
	store = X509_STORE_new();
	if (!store) {
		LM_ERR("Failed to create X509_STORE_CTX object\n");
		return -1;
	}
	ss_store_set_verify_cb(store, verify_callback);

	/* check if ca_list param is set */
	if (!ca_list) {
		LM_ERR("Failed, path to a file containing trusted CA certificates for the verifier is not set or the certificates must be in PEM format, one after another.\n");
		return -2;
	}

	/* check if ca_dir param is set */
	if (!ca_dir) {
		LM_ERR("Failed, path to a directory containing trusted CA certificates for the verifier is not set or the certificates in the directory must be in hashed form, as described in the openssl documentation for the Hashed Directory Method.\n");
		return -3;
	}

	/* params are set, do reload */
	if (ca_list || ca_dir) {
		if (X509_STORE_load_locations(store, ca_list, ca_dir) != 1) {
			LM_ERR("Failed to load trusted CAs\n");
			return -4;
		}
		if (ss_store_set_default_paths(store) != 1) {
			LM_ERR("Failed to load the system-wide CA certificates\n");
			return -5;
		}
	}

	return 0;
}

// store check then reload crl_list and crl_dir
static int init_cert_crl_reload(void)
{
	store = X509_STORE_new();
	if (!store) {
		LM_ERR("Failed to create X509_STORE_CTX object\n");
		return -1;
	}
	ss_store_set_verify_cb(store, verify_callback);

	/* check if crl_list param is set */
	if (!crl_list) {
		LM_ERR("Failed, path to a file containing certificate revocation lists (CRLs) for the verifier is not set.\n");
		return -2;
	}

	/* check if crl_dir param is set */
	if (!crl_dir) {
		LM_ERR("Failed, path to a directory containing certificate revocation lists (CRLs) for the verifier is not set or the CRLs in the directory must be in hashed form, as described in the openssl documentation for the Hashed Directory Method.\n");
		return -3;
	}

	/* params are set, do reload */
	if (crl_list || crl_dir) {
		if (X509_STORE_load_locations(store, crl_list, crl_dir) != 1) {
			LM_ERR("Failed to load CRLs\n");
			return -4;
		}
		X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
	}

	return 0;
}

static void parsed_ctx_free(void *param)
{
	struct parsed_identity *parsed = (struct parsed_identity *)param;

	passport_identity_cleanup(parsed);
	pkg_free(parsed);
}

static void generated_identity_free(void *ptr)
{
	struct generated_identity *p = ptr, *next;
	while (p) {
		next = p->next;
		pkg_free(p);
		p = next;
	}
}

/* Track only headers actually appended to this request. Lumps are not visible
 * to the SIP header parser until the message is serialized. */
static struct generated_identity *prepare_generated(struct sip_msg *msg,
	str *header)
{
	struct generated_identity *p;
	if (!current_processing_ctx)
		return NULL;
	p = pkg_malloc(sizeof(*p) + header->len);
	if (!p)
		return NULL;
	p->msg = msg;
	p->msg_id = msg->id;
	p->body.s = (char *)(p + 1);
	p->body.len = header->len - IDENTITY_HDR_LEN - CRLF_LEN;
	memcpy(p->body.s, header->s + IDENTITY_HDR_LEN, p->body.len);
	p->next = NULL;
	return p;
}

static void commit_generated(struct generated_identity *p)
{
	p->next = context_get_ptr(CONTEXT_GLOBAL, current_processing_ctx,
		generated_ctx_idx);
	context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx, generated_ctx_idx, p);
}

static int set_verify_date_div_freshness(modparam_t type, void *value)
{
	verify_date_div_freshness = (int)(long)value;
	verify_date_div_freshness_configured = 1;
	return 0;
}

static int mod_init(void)
{
	tn_authlist_obj = OBJ_txt2obj(TN_AUTH_LIST_OID, 1);
	if (!tn_authlist_obj) {
		LM_ERR("Failed to create TNAuthList object identifier\n");
		return -1;
	}

	if (init_cert_validation() < 0)
		return -1;

	parsed_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, parsed_ctx_free);
	generated_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, generated_identity_free);
	stale_ctx_idx = context_register_int(CONTEXT_GLOBAL, NULL);
	if (verstat_init() < 0)
		return -1;
	if (verify_init(&verify_date_freshness, verify_date_div_freshness_configured) < 0)
		return -1;

	return 0;
}

static void mod_destroy(void) {
	if (tn_authlist_obj)
		ASN1_OBJECT_free(tn_authlist_obj);

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

	struct tm ldate_tm;
	struct tm *date_tm;
	char *buf;
	int len;
	struct lump* anchor;

	date_tm = gmtime_r(date_ts, &ldate_tm);
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
		pkg_free(buf);
		return -1;
	}

	if (!insert_new_lump_before(anchor, buf, DATE_HDR_L+len+CRLF_LEN, 0)) {
		LM_ERR("Failed to insert lump\n");
		pkg_free(buf);
		return -1;
	}

	return 0;
}

/* Add P-Identity-Bypass for Incident Management Response */
static int add_disengagement_token(struct sip_msg *msg, str *token)
{

	#define DISENGAGEMENT_HDR_S		"P-Identity-Bypass: "
	#define DISENGAGEMENT_HDR_L		(sizeof(DISENGAGEMENT_HDR_S)-1)

	char *buf, *p;
	unsigned int len;
	struct lump* anchor;

	/* make sure we detect all headers */
	if (parse_headers(msg, HDR_EOH_F, 0) == -1) {
		LM_ERR("error while parsing message\n");
		return -1;
	}

	/* check if token is available */
	if (!token){
		LM_ERR("Failed to identify disengagement token\n");
		return -1;
	}

	/* add the anchor at the very end of the SIP headers */
	anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0);
	if (anchor == NULL) {
		LM_ERR("Failed to create lump anchor\n");
		return -1;
	}

	/* calculate len (header + token + crlf) */
	len = DISENGAGEMENT_HDR_L + token->len + CRLF_LEN;
	/* alloc pkg memory */
	buf= pkg_malloc(len);
	if (!buf) {
		LM_ERR("No more pkg mem\n");
		return -1;
	}

	p = buf;
	memcpy(p, DISENGAGEMENT_HDR_S, DISENGAGEMENT_HDR_L);
	p += DISENGAGEMENT_HDR_L;
	memcpy(p, token->s, token->len);
	p += token->len;
	memcpy(p, CRLF, CRLF_LEN);
	p += CRLF_LEN;

	/* insert buf at the end of previous headers */
	if (insert_new_lump_after(anchor, buf, len, 0) == 0) {
		LM_ERR("can't insert lump\n");
		pkg_free(buf);
		return -1;
	}

	return 0;
}

static int check_cert_validity(time_t *timestamp, X509 *cert)
{
	const ASN1_TIME *notBeforeSt;
	const ASN1_TIME *notAfterSt;

	notBeforeSt = X509_get_notBefore(cert);
	notAfterSt = X509_get_notAfter(cert);
	if (!notBeforeSt || !notAfterSt) {
		LM_ERR("failed to parse certificate validity\n");
		return 0;
	}

	if (X509_cmp_time(notBeforeSt, timestamp) < 0 &&
		X509_cmp_time(notAfterSt, timestamp) > 0)
		return 1;

	return 0;
}

static int get_orig_tn_from_msg(struct sip_msg *msg, str *orig_tn)
{
	struct to_body *body;
	struct sip_uri parsed_uri;

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

	if (parse_uri(body->uri.s, body->uri.len, &parsed_uri) < 0) {
		LM_ERR("Failed to parse %s URI: %.*s\n", msg->pai ? "PAI" : "From",
		       body->uri.len, body->uri.s);
		return -1;
	}

	if ((parsed_uri.type != SIP_URI_T && parsed_uri.type != TEL_URI_T &&
	    parsed_uri.type != SIPS_URI_T && parsed_uri.type != TELS_URI_T) ||
	    (e164_strict_mode &&
	      (parsed_uri.type == SIP_URI_T || parsed_uri.type == SIPS_URI_T) &&
	      str_strcmp(&parsed_uri.user_param, _str("user=phone")))) {
		LM_ERR("'tel:' URI or 'sip:' URI %srequired\n",
		        e164_strict_mode ? "with ';user=phone' parameter " : "");
		return -3;
	}

	*orig_tn = parsed_uri.user;
	trim_user_params(orig_tn);

	return 0;
}

static int get_dest_tn_from_msg(struct sip_msg *msg, str *dest_tn)
{
	struct to_body *body;
	struct sip_uri parsed_uri;

	if (parse_to_header(msg) < 0) {
		LM_ERR("Unable to parse To header\n");
		return -1;
	}
	body = get_to(msg);

	if (parse_uri(body->uri.s, body->uri.len, &parsed_uri) < 0) {
		LM_ERR("Failed to parse To URI: %.*s\n", body->uri.len, body->uri.s);
		return -1;
	}

	if ((parsed_uri.type != SIP_URI_T && parsed_uri.type != TEL_URI_T &&
	    parsed_uri.type != SIPS_URI_T && parsed_uri.type != TELS_URI_T) ||
	    (e164_strict_mode &&
	      (parsed_uri.type == SIP_URI_T || parsed_uri.type == SIPS_URI_T) &&
	      str_strcmp(&parsed_uri.user_param, _str("user=phone")))) {
		LM_ERR("'tel:' URI or 'sip:' URI %srequired\n",
		        e164_strict_mode ? "with ';user=phone' parameter " : "");
		return -3;
	}

	*dest_tn = parsed_uri.user;
	trim_user_params(dest_tn);

	return 0;
}

static X509_INFO *ss_sk_X509_INFO_shift(STACK_OF(X509_INFO) *sk)
{
#ifdef WOLFSSL_VERSION
	return sk_X509_INFO_pop(sk);
#else
	return sk_X509_INFO_shift(sk);
#endif
}

static int load_cert(X509 **cert, STACK_OF(X509) **certchain, str *cert_buf)
{
	BIO *cbio, *chainbio;
	STACK_OF(X509) *stack;
	STACK_OF(X509_INFO) *sk;
	X509_INFO *xi;

	cbio = BIO_new_mem_buf((void*)cert_buf->s,cert_buf->len);
	if (!cbio) {
		LM_ERR("Unable to create BIO buf\n");
		return -1;
	}
	SS_LOCK;

	/* parse end-entity certificate */
	*cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
	if (*cert == NULL) {
		LM_ERR("Failed to parse certificate\n");
		BIO_free(cbio);
		SS_UNLOCK;
		return -1;
	}

	if (certchain) {
		/* parse untrusted certificate chain */
		stack = sk_X509_new_null();
		if (!stack) {
			LM_ERR("Failed to allocate cert stack\n");
			X509_free(*cert);
			*cert = NULL;
			BIO_free(cbio);
			SS_UNLOCK;
			return -1;
		}
		chainbio = BIO_new_mem_buf((void*)cert_buf->s,cert_buf->len);
		if (!chainbio) {
			LM_ERR("error reading certificate stack\n");
			X509_free(*cert);
			*cert = NULL;
			BIO_free(cbio);
			sk_X509_free(stack);
			SS_UNLOCK;
			return -1;
		}

		sk = PEM_X509_INFO_read_bio(chainbio, NULL, NULL, NULL);
		if (!sk) {
			LM_ERR("error reading certificate stack\n");
			X509_free(*cert);
			*cert = NULL;
			BIO_free(chainbio);
			BIO_free(cbio);
			sk_X509_free(stack);
			SS_UNLOCK;
			return -1;
		}

		while (sk_X509_INFO_num(sk)) {
			xi = ss_sk_X509_INFO_shift(sk);
			if (xi->x509 != NULL) {
				sk_X509_push(stack, xi->x509);
				xi->x509 = NULL;
			}
			X509_INFO_free(xi);
		}

		if (!sk_X509_num(stack))
			sk_X509_free(stack);
		else
			*certchain = stack;

		BIO_free(chainbio);
		BIO_free(cbio);
		sk_X509_INFO_free(sk);
	} else {
		BIO_free(cbio);
	}
	SS_UNLOCK;

	return 0;
}

static int load_pkey(EVP_PKEY **pkey, str *pkey_buf)
{
	BIO *kbio;

	kbio = BIO_new_mem_buf((void*)pkey_buf->s, pkey_buf->len);
	if (!kbio) {
		LM_ERR("Unable to create BIO buf\n");
		return -1;
	}

	SS_LOCK;
	*pkey = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);
	if (*pkey == NULL) {
		LM_ERR("Failed to load private key from buffer\n");
		BIO_free(kbio);
		SS_UNLOCK;
		return -1;
	}

	BIO_free(kbio);
	SS_UNLOCK;

	return 0;
}

/* Note: MAY modify @num */
static int check_passport_phonenum(str *num, int log_lev)
{
	if (!num->s || num->len == 0) {
		LM_GEN(log_lev, "number cannot be NULL or empty\n");
		return -1;
	}

	/* get rid of the '+' sign as it should not appear in the passport claim */
	if (num->s[0] == '+') {
		num->s++;
		num->len--;
	}

	if (_is_e164(num, e164_strict_mode, e164_max_length) == -1) {
		LM_GEN(log_lev, "number is not in E.164 format: %.*s\n", num->len, num->s);
		return -1;
	}

	return 0;
}

static int fixup_auth_out(void** param)
{
	struct auth_out_param *out_p;
	str *s = (str*)*param;

	out_p = pkg_malloc(sizeof *out_p);
	memset(out_p, 0, sizeof *out_p);

	if (!str_strcmp(_str(AUTH_OUT_REQ_STR), s)) {
		out_p->type = AUTH_APPEND_TO_REQ;
	} else if (!str_strcmp(_str(AUTH_OUT_RPL_STR), s)) {
		out_p->type = AUTH_APPEND_TO_RPL;
	} else if (*s->s == PV_MARKER) {
		out_p->type = AUTH_OUT_VAR;

		if (pv_parse_spec(s, &out_p->var) == NULL) {
			pkg_free(out_p);
			LM_ERR("Failed to parse output variable spec\n");
			return -1;
		}
	} else {
		LM_ERR("Expected variable or the 'req'/'rpl' flags\n");
		return -1;
	}

	*param = out_p;

	return 0;
}

static int w_stir_auth(struct sip_msg *msg, str *attest, str *origid,
	str *cert_buf, str *pkey_buf, str *cr_url, str *orig_tn_p, str *dest_tn_p,
	struct auth_out_param *out_p)
{
	time_t now, date_ts;
	struct hdr_field *date_hf = NULL;
	X509 *cert;
	EVP_PKEY *pkey = NULL;
	str orig_tn, dest_tn;
	int rc, orig_log_lev = L_ERR, dest_log_lev = L_ERR;
	str *hdr_buf = NULL;
	struct lump* anchor;
	pv_value_t out_val;
	struct generated_identity *generated = NULL;

	/* looking for 'Identity' and 'Date' */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("Failed to parse headers\n");
		return -1;
	}

	if (!orig_tn_p) {
		if ((rc = get_orig_tn_from_msg(msg, &orig_tn)) < 0) {
			if (rc == -1)
				LM_ERR("Error determining Originator number\n");
			else
				LM_NOTICE("Originator URI is not a telephone number\n");
			return rc;
		}
		orig_tn_p = &orig_tn;
		orig_log_lev = L_NOTICE;
	}

	if (check_passport_phonenum(orig_tn_p, orig_log_lev) != 0) {
		LM_GEN(orig_log_lev, "failed to validate Originator number (%.*s)\n",
		        orig_tn_p->len, orig_tn_p->s);
		return -3;
	}

	if (!dest_tn_p) {
		if ((rc = get_dest_tn_from_msg(msg, &dest_tn)) < 0) {
			if (rc == -1)
				LM_ERR("Error determining Destination number\n");
			else
				LM_NOTICE("Destination URI is not a telephone number\n");
			return rc;
		}
		dest_tn_p = &dest_tn;
		dest_log_lev = L_NOTICE;
	}

	if (check_passport_phonenum(dest_tn_p, dest_log_lev) != 0) {
		LM_GEN(dest_log_lev, "failed to validate Destination number (%.*s)\n",
		        dest_tn_p->len, dest_tn_p->s);
		return -3;
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

		if (labs(now - date_ts) > auth_date_freshness) {
			LM_NOTICE("Date header timestamp diff exceeds local policy "
			    "(diff: %llds, auth-freshness: %ds)\n",
			    (long long)(now - date_ts), auth_date_freshness);
			return -4;
		}
	}

	if (load_cert(&cert, NULL, cert_buf) < 0) {
		LM_ERR("Failed to load certificate\n");
		return -1;
	}
	if (load_pkey(&pkey, pkey_buf) < 0) {
		LM_ERR("Failed to load private key\n");
		rc = -1;
		goto error;
	}

	if (!check_cert_validity(&now, cert)) {
		LM_NOTICE("The current time does not fall within the certificate validity\n");
		rc = -5;
		goto error;
	}
	if (date_ts != now && !check_cert_validity(&date_ts, cert)) {
		LM_NOTICE("The Date header does not fall within the certificate validity\n");
		rc = -5;
		goto error;
	}

	if ((hdr_buf = passport_build_identity(pkey, date_ts, attest, cr_url,
		orig_tn_p, dest_tn_p, origid)) ==  NULL) {
		LM_ERR("Failed to add Identity header\n");
		rc = -1;
		goto error;
	}

	if (!out_p || out_p->type == AUTH_APPEND_TO_REQ) {
		if (stir_shaken_record_authenticated(msg) < 0) {
			rc = -1;
			goto error;
		}
		generated = prepare_generated(msg, hdr_buf);
		if (!generated) {
			rc = -1;
			goto error;
		}
		anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0);
		if (!anchor) {
			LM_ERR("Failed to get anchor lump\n");
			rc = -1;
			goto error;
		}
		if (!insert_new_lump_before(anchor, hdr_buf->s, hdr_buf->len, 0)) {
			LM_ERR("Failed to insert lump\n");
			rc = -1;
			goto error;
		}
		commit_generated(generated);
	} else if (out_p->type == AUTH_APPEND_TO_RPL) {
		if (!add_lump_rpl(msg, hdr_buf->s, hdr_buf->len, LUMP_RPL_HDR|LUMP_RPL_NODUP)) {
			LM_ERR("unable to add reply lump\n");
			rc = -1;
			goto error;
		}
	} else {
		out_val.flags = PV_VAL_STR;
		out_val.rs = *hdr_buf;
		if (pv_set_value(msg, &out_p->var, 0, &out_val) != 0) {
			rc = -1;
			goto error;
		}

		pkg_free(hdr_buf->s);
	}

	X509_free(cert);
	EVP_PKEY_free(pkey);

	return 1;
error:
	if (generated)
		pkg_free(generated);
	if (hdr_buf)
		pkg_free(hdr_buf->s);
	X509_free(cert);
	if (pkey)
		EVP_PKEY_free(pkey);
	return rc;
}

static int cert_has_tn_authlist(X509 *cert)
{
	int i;
	char oid[128];
	X509_EXTENSION *ext;
	for (i = 0; i < X509_get_ext_count(cert); i++) {
		ext = X509_get_ext(cert, i);
		if (ext && OBJ_obj2txt(oid, sizeof(oid),
			X509_EXTENSION_get_object(ext), 1) > 0 &&
			!strcmp(oid, TN_AUTH_LIST_OID))
			return 1;
	}
	return 0;
}

static int w_stir_auth_div(struct sip_msg *msg, str *cert_buf, str *key_buf,
	str *x5u, str *orig_arg, str *div_arg, str *dest_arg,
	struct auth_out_param *out, int *previously_verified)
{
	struct div_chain chain = {0};
	struct hdr_field *hf;
	struct generated_identity *g, *generated = NULL;
	struct lump *anchor;
	struct sip_uri uri;
	str orig, from, dest, *header = NULL;
	X509 *cert = NULL;
	EVP_PKEY *key = NULL;
	EC_KEY *ec = NULL;
	pv_value_t val;
	time_t now;
	int rc = -1;

	if (!current_processing_ctx || parse_headers(msg, HDR_EOH_F, 0) < 0)
		goto done;
	if (context_get_int(CONTEXT_GLOBAL, current_processing_ctx, stale_ctx_idx)) {
		LM_NOTICE("refusing div authentication after a recorded freshness failure\n");
		rc = -4;
		goto done;
	}
	if (previously_verified)
		*previously_verified = !!*previously_verified;
	if (previously_verified && !*previously_verified) {
		stir_shaken_record_verification(msg, 0);
		LM_NOTICE("refusing div authentication: prior verification is known to have failed\n");
		rc = -8;
		goto done;
	}
	/* URI delimiters in x5u would corrupt the generated SIP header. */
	if (!x5u->len || memchr(x5u->s, '\r', x5u->len) ||
		memchr(x5u->s, '\n', x5u->len) || memchr(x5u->s, '>', x5u->len) ||
		memchr(x5u->s, '<', x5u->len) || memchr(x5u->s, ' ', x5u->len) ||
		memchr(x5u->s, '\t', x5u->len)) {
		rc = -3;
		goto done;
	}
	for (hf = get_header_by_static_name(msg, "Identity"); hf;
		hf = get_next_header_by_static_name(hf, "Identity")) {
		if (div_chain_add(&chain, &hf->body) < 0) {
			rc = -7;
			goto done;
		}
	}
	for (g = context_get_ptr(CONTEXT_GLOBAL, current_processing_ctx,
		generated_ctx_idx); g; g = g->next) {
		if (g->msg == msg && g->msg_id == msg->id &&
			div_chain_add(&chain, &g->body) < 0) {
			rc = -7;
			goto done;
		}
	}
	if (div_arg) {
		from = *div_arg;
		if (div_normalize(&from, 1)) {
			rc = -3;
			goto done;
		}
	}
	rc = div_chain_select(&chain, div_arg ? &from : NULL);
	if (rc < 0)
		goto done;
	orig = orig_arg ? *orig_arg : chain.orig;
	if (div_normalize(&orig, 0) || str_strcmp(&orig, &chain.orig)) {
		rc = -3;
		goto done;
	}
	from = chain.previous;
	if (dest_arg) {
		dest = *dest_arg;
	} else {
		str ruri = *GET_RURI(msg);
		if (ruri.len >= 4 && !memcmp(ruri.s, "urn:", 4)) {
			dest = ruri;
		} else {
			if (parse_uri(ruri.s, ruri.len, &uri) < 0 ||
				(uri.type != SIP_URI_T && uri.type != SIPS_URI_T &&
				 uri.type != TEL_URI_T && uri.type != TELS_URI_T)) {
				rc = -3;
				goto done;
			}
			dest = uri.user;
			trim_user_params(&dest);
		}
	}
	if (div_normalize(&dest, 1) || div_normalize(&from, 1) ||
		!str_strcmp(&from, &dest)) {
		rc = -3;
		goto done;
	}
	now = time(NULL);
	if (now == (time_t)-1) {
		rc = -1;
		goto done;
	}
	if (!previously_verified) {
		int previous = stir_shaken_previous_verification(msg);
		if (previous != 1) {
			LM_NOTICE("DIV signing needs a trusted prior result or completed local VS verification\n");
			rc = previous == 0 ? -8 : -10;
			goto done;
		}
	}
	/* Bind the trusted assertion to the received Identity snapshot. This does
	 * not revalidate it or claim that per-token VS calls have been performed. */
	if (stir_shaken_record_authenticated(msg) < 0) {
		rc = -1;
		goto done;
	}
	if (load_cert(&cert, NULL, cert_buf) || load_pkey(&key, key_buf)) {
		rc = -1;
		goto done;
	}
	ec = EVP_PKEY_get1_EC_KEY(key);
	if (!check_cert_validity(&now, cert) || !cert_has_tn_authlist(cert) ||
		!ec || EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)) != NID_X9_62_prime256v1 ||
		X509_check_private_key(cert, key) != 1) {
		rc = -5;
		goto done;
	}
	/* Trust and TN authorization are SP policy, as with base authentication. */
	header = passport_build_div(key, now, x5u, &orig, &from, &dest);
	if (!header) {
		rc = -1;
		goto done;
	}
	if (!out || out->type == AUTH_APPEND_TO_REQ) {
		generated = prepare_generated(msg, header);
		anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0);
		if (!generated || !anchor ||
			!insert_new_lump_before(anchor, header->s, header->len, 0)) {
			rc = -1;
			goto done;
		}
		commit_generated(generated);
		generated = NULL;
		header = NULL; /* lump owns the buffer */
	} else if (out->type == AUTH_OUT_VAR) {
		val.flags = PV_VAL_STR;
		val.rs = *header;
		if (pv_set_value(msg, &out->var, 0, &val)) {
			rc = -1;
			goto done;
		}
	} else {
		/* ATIS authenticates the retargeted request, not a 3xx response. */
		rc = -3;
		goto done;
	}
	rc = 1;
done:
	if (rc < 0)
		LM_NOTICE("DIV authentication failed (rc=%d)\n", rc);
	if (generated)
		pkg_free(generated);
	if (header)
		pkg_free(header->s);
	if (key)
		EVP_PKEY_free(key);
	if (ec)
		EC_KEY_free(ec);
	if (cert)
		X509_free(cert);
	div_chain_cleanup(&chain);
	return rc;
}

/* stir shaken disengagement token function */
static int w_stir_disengagement(struct sip_msg *msg, str *token)
{
	if (add_disengagement_token(msg, token) < 0) {
		LM_ERR("Failed to add P-Identity-Bypass header\n");
		return 0;
	}
	return 1;
}

static int validate_certificate(X509 *cert, STACK_OF(X509) *certchain,
	str *authority)
{
	X509_STORE_CTX *verify_ctx;
	X509_EXTENSION *ext;
	ASN1_OBJECT *ext_obj;
	char ext_oid[128];
	int ext_count, i, has_tn_authlist = 0;
	int tn_authlist_nid;
	int rc;

	/* check the TN Authorization list extension */
	tn_authlist_nid = tn_authlist_obj ? OBJ_obj2nid(tn_authlist_obj) : NID_undef;
	if (tn_authlist_nid != NID_undef &&
		X509_get_ext_by_NID(cert, tn_authlist_nid, -1) != -1) {
		has_tn_authlist = 1;
	} else {
		/*
		 * WolfSSL may fail object-based lookup for this custom OID.
		 * Fallback to direct OID-string matching over all extensions.
		 */
		ext_count = X509_get_ext_count(cert);
		for (i = 0; i < ext_count; i++) {
			ext = X509_get_ext(cert, i);
			if (!ext)
				continue;

			ext_obj = X509_EXTENSION_get_object(ext);
			if (!ext_obj)
				continue;

			if (OBJ_obj2txt(ext_oid, sizeof(ext_oid), ext_obj, 1) <= 0)
				continue;

			if (strcmp(ext_oid, TN_AUTH_LIST_OID) == 0) {
				has_tn_authlist = 1;
				break;
			}
		}
	}

	if (!has_tn_authlist) {
		LM_INFO("The certificate is missing the TnAuthList extension\n");
		return -8;
	}

	if (!(verify_ctx = X509_STORE_CTX_new())) {
		LM_ERR("Failed to create X509_STORE_CTX object\n");
		return -1;
	}

	if (X509_STORE_CTX_init(verify_ctx, store, cert, certchain) != 1) {
		X509_STORE_CTX_cleanup(verify_ctx);
		X509_STORE_CTX_free(verify_ctx);
		LM_ERR("Error initializing verification context\n");
		return -1;
	}
	X509_STORE_CTX_set_verify_cb(verify_ctx, verify_callback);

	rc = X509_verify_cert(verify_ctx);
	if (rc == 1 && authority) {
		STACK_OF(X509) *path = X509_STORE_CTX_get_chain(verify_ctx);
		X509 *issuer;
		int j, k;
		if (!path || !sk_X509_num(path)) rc = 0;
		for (j = 0; rc == 1 && j < sk_X509_num(path); j++) {
			issuer = sk_X509_value(path, j);
			if (cert_has_tn_authlist(issuer) &&
				!passport_certificate_authority(issuer, authority)) rc = 0;
			/* Fail closed on delegated JWT constraints until their complete
			 * validation profile is supported. Never silently ignore them. */
			for (k = 0; k < X509_get_ext_count(issuer); k++) {
				ext = X509_get_ext(issuer, k);
				if (ext && OBJ_obj2txt(ext_oid, sizeof(ext_oid),
					X509_EXTENSION_get_object(ext), 1) > 0 &&
					!strcmp(ext_oid, "1.3.6.1.5.5.7.1.27")) rc = 0;
			}
		}
	}

	X509_STORE_CTX_cleanup(verify_ctx);
	X509_STORE_CTX_free(verify_ctx);

	if (rc != 1)
		return rc == 0 ? -8 : -1;
	else
		return 0;
}

int stir_shaken_outer_freshness(void)
{
	return verify_date_freshness;
}

int stir_shaken_verify_caller(struct sip_msg *msg, str *orig)
{
	return get_orig_tn_from_msg(msg, orig);
}

int stir_shaken_verify_destination(struct sip_msg *msg, str *dest)
{
	if (parse_to_header(msg) < 0) return -1;
	*dest = get_to(msg)->uri;
	if (dest->len >= 15 && !memcmp(dest->s, "urn:service:sos", 15))
		return div_normalize(dest, 1);
	return get_dest_tn_from_msg(msg, dest);
}

int stir_shaken_verify_credential(str *buf, struct parsed_identity *parsed,
	str *authority)
{
	X509 *cert = NULL;
	STACK_OF(X509) *chain = NULL;
	EVP_PKEY *pubkey = NULL;
	EC_KEY *ec = NULL;
	time_t iat, now = time(NULL);
	int rc = -8;

	if (load_cert(&cert, &chain, buf)) goto done;
	/* Check the original signing instant as well as the current trust path. */
	if (parsed->iat->valuedouble > 2147483647.0 && sizeof(time_t) < 8) goto done;
	iat = (time_t)parsed->iat->valuedouble;
	if (now == (time_t)-1 || !check_cert_validity(&iat, cert) ||
		!check_cert_validity(&now, cert) || validate_certificate(cert, chain, authority) < 0 ||
		!passport_certificate_authority(cert, authority)) goto done;
	pubkey = X509_get_pubkey(cert);
	if (!pubkey) goto done;
	ec = EVP_PKEY_get1_EC_KEY(pubkey);
	if (!ec || EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)) != NID_X9_62_prime256v1)
		goto done;
	rc = passport_verify_full_signature(cert, parsed) == 1 ? 1 : -9;
done:
	if (ec) EC_KEY_free(ec);
	if (pubkey) EVP_PKEY_free(pubkey);
	if (cert) X509_free(cert);
	if (chain) sk_X509_pop_free(chain, X509_free);
	return rc;
}

int stir_shaken_verify_result(struct sip_msg *msg, pv_spec_t *code,
	pv_spec_t *reason, int rc, const char *operation)
{
	pv_value_t value;
	int sipcode;
	const char *text;
	switch (rc) {
	case 1: sipcode = 0; text = ""; break;
	case -1: sipcode = 500; text = "Internal verification error"; break;
	case -2: sipcode = 428; text = "Missing PASSporT or invalid index"; break;
	case -3: sipcode = 400; text = "Invalid verification argument or SIP identity"; break;
	case -5: sipcode = 438; text = "Unsupported PASSporT type"; break;
	case -6: sipcode = 403; text = "Stale outermost PASSporT"; break;
	case -7: sipcode = 438; text = "Broken or cyclic PASSporT chain"; break;
	case -8: sipcode = 437; text = "Invalid or unauthorized STI credential"; break;
	case -9: sipcode = 438; text = "Invalid signature or calling identity"; break;
	case -10: sipcode = 438; text = "PASSporT has not been verified"; break;
	case -11: sipcode = 403; text = "Stale inner PASSporT"; break;
	default: sipcode = 438; text = "Malformed PASSporT"; break;
	}
	if (rc == -6 && current_processing_ctx)
		context_put_int(CONTEXT_GLOBAL, current_processing_ctx, stale_ctx_idx, 1);
	if (rc < 0) LM_NOTICE("%s failed: %s (rc=%d)\n", operation, text, rc);
	if (code) {
		memset(&value, 0, sizeof(value));
		value.flags = PV_VAL_INT|PV_TYPE_INT; value.ri = sipcode;
		if (pv_set_value(msg, code, 0, &value)) return -1;
	}
	if (reason) {
		memset(&value, 0, sizeof(value));
		value.flags = PV_VAL_STR; init_str(&value.rs, text);
		if (pv_set_value(msg, reason, 0, &value)) return -1;
	}
	return rc;
}

static int get_parsed_identity(struct sip_msg *msg,
	struct parsed_identity **parsed)
{
	struct hdr_field *identity_hdr;
	int rc;

	*parsed = parsed_ctx_get();
	if (*parsed)
		/* we are lucky, the parsing was already done */
		return 0;

	if (!current_processing_ctx) {
		LM_ERR("no processing ctx found!\n");
		return -1;
	}

	/* look for the Identity hdr */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("Failed to parse headers\n");
		return -1;
	}

	if (!(identity_hdr = get_header_by_static_name(msg, "Identity"))) {
		LM_INFO("No Identity header found\n");
		return -2;
	}

	rc = -2;

	do {

		*parsed = pkg_malloc(sizeof **parsed);
		if (*parsed == NULL) {
			LM_ERR("oom!\n");
			return -1;
		}
		memset(*parsed, 0, sizeof **parsed);

		rc = passport_parse_identity(&identity_hdr->body, *parsed);
		if (rc >= 0) {
			if (str_strcmp(&(*parsed)->ppt_hdr_param, const_str(PPORT_HDR_PPT_VAL)) == 0)
				break;
			LM_INFO("Unsupported '%.*s' extension\n",
				(*parsed)->ppt_hdr_param.len, (*parsed)->ppt_hdr_param.s);
			rc = -2; /* consider we did not find a proper Identity header */
		}
		parsed_ctx_free(*parsed);
		*parsed = NULL;
		/* let's check other Identity hdr, if present */
		identity_hdr = get_next_header_by_static_name ( identity_hdr,
			"Identity");
		if (identity_hdr==NULL) {
			LM_INFO("No valid Identity header found\n");
			return rc;
		}

	}while(rc < 0);

	if (rc >= 0)
		parsed_ctx_set(*parsed);

	return rc;
}

static int set_err_resp_vars(struct sip_msg *msg, pv_spec_t *err_code_var,
	pv_spec_t *err_reason_var, int code, char *reason)
{
	pv_value_t err_code_val, err_reason_val;

	err_code_val.flags = PV_VAL_INT|PV_TYPE_INT;
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
		if ((_code) == STALE_DATE_CODE && current_processing_ctx) \
			context_put_int(CONTEXT_GLOBAL, current_processing_ctx, stale_ctx_idx, 1); \
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
	str orig_tn, dest_tn, pport_orig_tn, pport_dest_tn;
	time_t now, date_ts, iat_ts;
	struct hdr_field *date_hf = NULL;
	X509 *cert = NULL;
	STACK_OF(X509) *certchain = NULL;
	struct parsed_identity *parsed;
	int rc, err_code, orig_log_lev = L_ERR, dest_log_lev = L_ERR;
	char *err_reason;

	if (!orig_tn_p) {
		err_code = BADREQ_CODE;
		err_reason = BADREQ_ORIG_REASON;

		if ((rc = get_orig_tn_from_msg(msg, &orig_tn)) < 0) {
			if (rc == -1)
				LM_ERR("Failed to get Originator identity\n");
			else
				LM_NOTICE("Originator URI is not a telephone number\n");

			SET_VERIFY_ERR_VARS(err_code, err_reason);
			return rc;
		}
		orig_tn_p = &orig_tn;
		orig_log_lev = L_NOTICE;
	} else {
		err_code = IERROR_CODE;
		err_reason = IERROR_REASON;
	}

	if (check_passport_phonenum(orig_tn_p, orig_log_lev) != 0) {
		LM_GEN(orig_log_lev, "failed to validate Originator number (%.*s)\n",
		       orig_tn_p->len, orig_tn_p->s);
		SET_VERIFY_ERR_VARS(err_code, err_reason);
		return -3;
	}

	if (!dest_tn_p) {
		err_code = BADREQ_CODE;
		err_reason = BADREQ_DEST_REASON;
		if ((rc = get_dest_tn_from_msg(msg, &dest_tn)) < 0) {
			if (rc == -1)
				LM_ERR("Failed to get Destination identity\n");
			else
				LM_NOTICE("Destination URI is not a telephone number\n");

			SET_VERIFY_ERR_VARS(err_code, err_reason);
			return rc;
		}
		dest_tn_p = &dest_tn;
		dest_log_lev = L_NOTICE;
	} else {
		err_code = IERROR_CODE;
		err_reason = IERROR_REASON;
	}

	if (check_passport_phonenum(dest_tn_p, dest_log_lev) != 0) {
		LM_GEN(dest_log_lev, "failed to validate Destination number (%.*s)\n",
		       dest_tn_p->len, dest_tn_p->s);
		SET_VERIFY_ERR_VARS(err_code, err_reason);
		return -3;
	}

	if ((rc = get_parsed_identity( msg, &parsed)) < 0) {
		if (rc == -1) {
			LM_ERR("Failed to parse identity header\n");
			SET_VERIFY_ERR_VARS(IERROR_CODE, IERROR_REASON_PARSE_IDENTITY);
		} else {  /* rc == -4 */
			LM_INFO("Invalid identity header\n");
			SET_VERIFY_ERR_VARS(INVALID_IDENTITY_CODE, INVALID_IDENTITY_REASON);
		}

		return rc;
	}

	if (parsed->alg_hdr_param.s &&
		str_strcmp(&parsed->alg_hdr_param, const_str(PPORT_HDR_ALG_VAL))) {
		LM_NOTICE("Unsupported 'alg': %.*s\n",
		          parsed->alg_hdr_param.len, parsed->alg_hdr_param.s);
		SET_VERIFY_ERR_VARS(INVALID_IDENTITY_CODE, INVALID_IDENTITY_REASON);
		rc = -5;
		goto error;
	}

	if (passport_check_claims(parsed) < 0) {
		LM_NOTICE("Required PASSporT claims are missing or have bad datatypes\n");
		SET_VERIFY_ERR_VARS(INVALID_IDENTITY_CODE, INVALID_IDENTITY_REASON);
		rc = -4;
		goto error;
	}

	date_hf = get_header_by_static_name(msg, "Date");

	if ((now = time(0)) == -1) {
		LM_ERR("Failed to get current time\n");
		SET_VERIFY_ERR_VARS(IERROR_CODE, IERROR_REASON_GET_CURRENT_TIME);
		rc = -1;
		goto error;
	}

	iat_ts = (time_t)parsed->iat->valuedouble;

	if (require_date_hdr || date_hf) {
		if (!date_hf) {
			LM_NOTICE("No Date header found\n");
			SET_VERIFY_ERR_VARS(BADREQ_CODE, BADREQ_NODATE_REASON);
			rc = -2;
			goto error;
		}

		if (get_date_ts(date_hf, &date_ts) < 0) {
			LM_ERR("Failed to get UNIX time from Date header\n");
			SET_VERIFY_ERR_VARS(IERROR_CODE, IERROR_REASON_GET_TIME_FROM_DATE_HEADER);
			rc = -1;
			goto error;
		}

		if (labs(now - date_ts) > verify_date_freshness) {
			LM_NOTICE("Date header timestamp diff exceeds local policy "
			    "(diff: %llds, verify-freshness: %ds)\n",
			    (long long)(now - date_ts), verify_date_freshness);
			SET_VERIFY_ERR_VARS(STALE_DATE_CODE, STALE_DATE_REASON);
			rc = -6;
			goto error;
		}
	} else {
		if (labs(now - iat_ts) > verify_date_freshness) {
			LM_NOTICE("'iat' timestamp diff exceeds local policy "
			    "(diff: %llds, verify-freshness: %ds)\n",
			    (long long)(now - iat_ts), verify_date_freshness);
			SET_VERIFY_ERR_VARS(STALE_DATE_CODE, STALE_DATE_REASON);
			rc = -6;
			goto error;
		}
	}

	/* if the identities in the PASSporT and SIP message are different
	 * the signature verification would fail anyway */
	pport_orig_tn.s = parsed->orig_tn->valuestring;
	pport_orig_tn.len = strlen(pport_orig_tn.s);
	if (str_strcmp(&pport_orig_tn, orig_tn_p)) {
		LM_NOTICE("Differing identities in orig claim [%.*s] and PAI/From hdr [%.*s]\n",
			pport_orig_tn.len, pport_orig_tn.s, orig_tn_p->len, orig_tn_p->s);
		LM_NOTICE("Signature would not verify successfully\n");
		SET_VERIFY_ERR_VARS(INVALID_IDENTITY_CODE, INVALID_IDENTITY_REASON);
		rc = -9;
		goto error;
	}

	pport_dest_tn.s = parsed->dest_tn->valuestring;
	pport_dest_tn.len = strlen(pport_dest_tn.s);
	if (str_strcmp(&pport_dest_tn, dest_tn_p)) {
		LM_NOTICE("Differing identities in dest claim [%.*s] and To hdr [%.*s]\n",
			pport_dest_tn.len, pport_dest_tn.s, dest_tn_p->len, dest_tn_p->s);
		LM_NOTICE("Signature would not verify successfully\n");
		SET_VERIFY_ERR_VARS(INVALID_IDENTITY_CODE, INVALID_IDENTITY_REASON);
		rc = -9;
		goto error;
	}

	if (load_cert(&cert, &certchain, cert_buf) < 0) {
		LM_ERR("Failed to load certificate\n");
		SET_VERIFY_ERR_VARS(IERROR_CODE, IERROR_REASON_LOAD_CERTIFICATE);
		rc = -1;
		goto error;
	}

	if (require_date_hdr || date_hf) {
		if (!check_cert_validity(&date_ts, cert)) {
			LM_INFO("The Date header does not fall within the certificate validity\n");
			SET_VERIFY_ERR_VARS(INVALID_IDENTITY_CODE, INVALID_IDENTITY_REASON " (cert validity)");
			rc = -7;
			goto error;
		}
	} else {
		if (!check_cert_validity(&iat_ts, cert)) {
			LM_INFO("The 'iat' value does not fall within the certificate validity\n");
			SET_VERIFY_ERR_VARS(INVALID_IDENTITY_CODE, INVALID_IDENTITY_REASON " (cert validity)");
			rc = -7;
			goto error;
		}
	}

	if ((rc = validate_certificate(cert, certchain, NULL)) < 0) {
		if (rc == -1) {
			LM_ERR("Error validating certificate\n");
			SET_VERIFY_ERR_VARS(IERROR_CODE, IERROR_REASON_VALIDATE_CERTIFICATE);
			goto error;
		} else {  /* rc == -8 */
			LM_INFO("Invalid certificate\n");
			SET_VERIFY_ERR_VARS(UNSUPPORTED_CRED_CODE, UNSUPPORTED_CRED_REASON);
			goto error;
		}
	}

	if (date_hf && iat_ts != date_ts &&
		(labs(now - iat_ts) > verify_date_freshness))
		iat_ts = date_ts;

	if ((rc = passport_verify_signature(cert, parsed, iat_ts, orig_tn_p, dest_tn_p)) <= 0) {
		if (rc < 0) {
			LM_ERR("Error while verifying signature\n");
			SET_VERIFY_ERR_VARS(IERROR_CODE, IERROR_REASON_VERIFY_SIGNATURE);
			rc = -1;
			goto error;
		} else {
			LM_INFO("Signature did not verify successfully\n");
			SET_VERIFY_ERR_VARS(INVALID_IDENTITY_CODE, INVALID_IDENTITY_REASON " (bad signature)");
			rc = -9;
			goto error;
		}
	}

	X509_free(cert);
	if (certchain)
		sk_X509_pop_free(certchain, X509_free);

	return 1;
error:
	if (cert)
		X509_free(cert);
	if (certchain)
		sk_X509_pop_free(certchain, X509_free);
	return rc;
}

static int w_stir_check(struct sip_msg *msg)
{
	struct parsed_identity *parsed;
	int rc;

	if ((rc = get_parsed_identity( msg, &parsed)) < 0) {
		if (rc == -1) {
			LM_ERR("Failed to parse identity header\n");
			return -1;
		} else {
			LM_INFO("Invalid identity header\n");
			return -3;
		}
	}

	if (parsed->alg_hdr_param.s &&
		str_strcmp(&parsed->alg_hdr_param, const_str(PPORT_HDR_ALG_VAL))) {
		LM_INFO("Unsupported 'alg'\n");
		return -4;
	}

	if (passport_check_claims(parsed) < 0) {
		LM_INFO("Required PASSporT claims are missing or have bad datatypes\n");
		return -3;
	}

	return 1;
}

static int w_stir_check_cert(struct sip_msg *msg, str *cert_buf)
{
	X509 *cert = NULL;
	time_t now;

	if (load_cert(&cert, NULL, cert_buf) < 0) {
		LM_ERR("Failed to load certificate\n");
		return -1;
	}

	if ((now = time(0)) == -1) {
		LM_ERR("Failed to get current time\n");
		X509_free(cert);
		return -1;
	}

	if (!check_cert_validity(&now, cert)) {
		LM_INFO("The current time does not fall within the certificate validity\n");
		X509_free(cert);
		return -2;
	}

	X509_free(cert);

	return 1;
}

/*
 * MI functions
 */

/*! \brief Reload stir ca_list and ca_dir shaken */
mi_response_t *mi_stir_shaken_ca_reload(const mi_params_t *params, struct mi_handler *async_hdl)
{
	int rc;

	rc = init_cert_ca_reload();
	LM_ERR("Engage stir shaken ca reload, result <%i>\n", rc);

	switch(rc) {
		case 0:
			/* Reload OK */
			return init_mi_result_ok();
			break;
		case -1:
			/* X509 Store Error */
			return init_mi_error(500, MI_SSTR("Error X509 store object."));
			break;
		case -2:
			/* ca_list param */
			return init_mi_error(500, MI_SSTR("Error ca_list param."));
			break;
		case -3:
			/* ca_dir param */
			return init_mi_error(500, MI_SSTR("Error ca_dir param."));
			break;
		case -4:
			/* Cert Error */
			return init_mi_error(500, MI_SSTR("Error failed to load trusted CAs."));
			break;
		case -5:
			/* Path Error */
			return init_mi_error(500, MI_SSTR("Error failed to load the system-wide CA certificates."));
			break;
		default:
			/* Any other case */
			return init_mi_error(500, MI_SSTR("Error"));
	}

}

/*! \brief Reload stir crl_list and crl_dir shaken */
mi_response_t *mi_stir_shaken_crl_reload(const mi_params_t *params, struct mi_handler *async_hdl)
{
	int rc;

	rc = init_cert_crl_reload();
	LM_ERR("Engage stir shaken crl reload, result <%i>\n", rc);

	switch(rc) {
		case 0:
			/* Reload OK */
			return init_mi_result_ok();
			break;
		case -1:
			/* X509 Store Error */
			return init_mi_error(500, MI_SSTR("Error X509 store object."));
			break;
		case -2:
			/* crl_list param */
			return init_mi_error(500, MI_SSTR("Error crl_list param."));
			break;
		case -3:
			/* crl_dir param */
			return init_mi_error(500, MI_SSTR("Error crl_dir param."));
			break;
		case -4:
			/* Cert Error */
			return init_mi_error(500, MI_SSTR("Error failed to load trusted CRL."));
			break;
		default:
			/* Any other case */
			return init_mi_error(500, MI_SSTR("Error"));
	}

}

#ifdef UNIT_TESTS
int stir_shaken_test_trust_vs(str *pem)
{
	X509 *cert = NULL;
	int rc;
	if (load_cert(&cert, NULL, pem)) return -1;
	rc = X509_STORE_add_cert(store, cert);
	X509_free(cert);
	return rc == 1 ? 0 : -1;
}

int stir_shaken_test_auth_div(struct sip_msg *msg, str *cert, str *key,
	str *x5u, str *orig, str *from, str *dest, int verified)
{
	return w_stir_auth_div(msg, cert, key, x5u, orig, from, dest, NULL,
		verified == -1 ? NULL : &verified);
}

int stir_shaken_test_auth_base(struct sip_msg *msg, str *cert, str *key, str *x5u)
{
	str attest = str_init("A"), origid = str_init("test-origid");
	return w_stir_auth(msg, &attest, &origid, cert, key, x5u, NULL, NULL, NULL);
}

str *stir_shaken_test_last_generated(void)
{
	struct generated_identity *g = context_get_ptr(CONTEXT_GLOBAL,
		current_processing_ctx, generated_ctx_idx);
	return g ? &g->body : NULL;
}

void stir_shaken_test_mark_stale(void)
{
	context_put_int(CONTEXT_GLOBAL, current_processing_ctx, stale_ctx_idx, 1);
}

/*
 * Keep the unit tests on the production PASSporT code paths without exposing
 * implementation details in normal module builds.
 */
int stir_shaken_test_build_identity(time_t iat, str *attest, str *x5u,
	str *orig, str *dest, str *origid, str *pkey_buf, str *identity)
{
	EVP_PKEY *pkey = NULL;
	str *built;

	if (load_pkey(&pkey, pkey_buf) < 0)
		return -1;

	built = passport_build_identity(pkey, iat, attest, x5u, orig, dest, origid);
	EVP_PKEY_free(pkey);
	if (!built)
		return -1;

	*identity = *built;
	return 0;
}

int stir_shaken_test_verify_msg(str *raw_msg, str *cert_buf)
{
	struct parsed_identity parsed = {0};
	struct hdr_field *identity_hf;
	struct sip_msg msg = {0};
	str orig, dest, passport_orig, passport_dest;
	char *msg_buf = NULL;
	X509 *cert = NULL;
	time_t iat;
	int rc = -1;

	msg_buf = pkg_malloc(raw_msg->len + 1);
	if (!msg_buf)
		return -1;
	memcpy(msg_buf, raw_msg->s, raw_msg->len);
	msg_buf[raw_msg->len] = '\0';

	msg.buf = msg_buf;
	msg.len = raw_msg->len;
	msg.ruri_q = Q_UNSPECIFIED;
	if (parse_msg(msg_buf, raw_msg->len, &msg) < 0)
		goto out;

	if (parse_headers(&msg, HDR_EOH_F, 0) < 0)
		goto out_msg;

	identity_hf = get_header_by_static_name(&msg, "Identity");
	if (!identity_hf)
		goto out_msg;
	if (passport_parse_identity(&identity_hf->body, &parsed) < 0)
		goto out_parsed;

	if (str_strcmp(&parsed.ppt_hdr_param,
			const_str(PPORT_HDR_PPT_VAL)) ||
		(parsed.alg_hdr_param.s && str_strcmp(&parsed.alg_hdr_param,
			const_str(PPORT_HDR_ALG_VAL))) ||
		passport_check_claims(&parsed) < 0)
		goto out_parsed;

	if (get_orig_tn_from_msg(&msg, &orig) < 0 ||
		get_dest_tn_from_msg(&msg, &dest) < 0 ||
		check_passport_phonenum(&orig, L_ERR) < 0 ||
		check_passport_phonenum(&dest, L_ERR) < 0)
		goto out_parsed;

	passport_orig.s = parsed.orig_tn->valuestring;
	passport_orig.len = strlen(passport_orig.s);
	passport_dest.s = parsed.dest_tn->valuestring;
	passport_dest.len = strlen(passport_dest.s);
	if (str_strcmp(&passport_orig, &orig) ||
		str_strcmp(&passport_dest, &dest))
		goto out_parsed;

	if (load_cert(&cert, NULL, cert_buf) < 0)
		goto out_parsed;

	iat = (time_t)parsed.iat->valuedouble;
	rc = passport_verify_signature(cert, &parsed, iat, &orig, &dest) == 1 ? 0 : -1;

	X509_free(cert);
out_parsed:
	passport_identity_cleanup(&parsed);
out_msg:
	free_sip_msg(&msg);
out:
	pkg_free(msg_buf);
	return rc;
}
#endif
