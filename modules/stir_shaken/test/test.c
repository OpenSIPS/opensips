/*
 * Copyright (C) 2026 OpenSIPS Project
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
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <tap.h>

#include "../div.h"
#include "../../../mem/mem.h"
#include "../../../str.h"
#include "../../../context.h"
#include "../../../ut.h"
#include "../../../mod_fix.h"
#include "../../../cmds.h"

int stir_shaken_test_auth_div(struct sip_msg *, str *, str *, str *,
	str *, str *, str *, int);
int stir_shaken_test_auth_base(struct sip_msg *, str *, str *, str *);
str *stir_shaken_test_last_generated(void);
void stir_shaken_test_mark_stale(void);

int stir_shaken_test_build_identity(time_t iat, str *attest, str *x5u,
	str *orig, str *dest, str *origid, str *pkey_buf, str *identity);
int stir_shaken_test_verify_msg(str *raw_msg, str *cert_buf);

#define TEST_IAT 1700000000
#define TEST_X5U "https://cert.example.test/passport.pem"
#define TEST_ORIG "12155551212"
#define TEST_DEST "12155551213"
#define TEST_ORIGID "123e4567-e89b-12d3-a456-426614174000"

static const char test_private_key[] =
	"-----BEGIN EC PRIVATE KEY-----\n"
	"MHcCAQEEIORw1DbgcFN80Sxjgs9W51uSNNrO3/R0h1RLvOaoWAvMoAoGCCqGSM49\n"
	"AwEHoUQDQgAEjaRI7F43cbJ2U5BSadK1AscH5GFZXHfMHNOo1peKJIBVGKxg1ZZi\n"
	"fF/3qnaNPxCdK0vP8EUNtqpjFEnDJeq0Og==\n"
	"-----END EC PRIVATE KEY-----\n";

static const char test_certificate[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBkDCCATegAwIBAgIUexVfq9Ts3eG4Be0HzlU5ki7uF/wwCgYIKoZIzj0EAwIw\n"
	"HTEbMBkGA1UEAwwST3BlblNJUFMtU1RJUi1UZXN0MCAXDTI2MTAyODE1NDQzOFoY\n"
	"DzIxMjYxMDA0MTU0NDM4WjAdMRswGQYDVQQDDBJPcGVuU0lQUy1TVElSLVRlc3Qw\n"
	"WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNpEjsXjdxsnZTkFJp0rUCxwfkYVlc\n"
	"d8wc06jWl4okgFUYrGDVlmJ8X/eqdo0/EJ0rS8/wRQ22qmMUScMl6rQ6o1MwUTAd\n"
	"BgNVHQ4EFgQUjMsRbrdNV3UX2EsMC0z17YNO2UkwHwYDVR0jBBgwFoAUjMsRbrdN\n"
	"V3UX2EsMC0z17YNO2UkwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBE\n"
	"AiBEB4tJpNl3NpjnfG+hC8sxYwa+advB19vbxnFFIq0j7wIgR3AYoLmhE0k/QX2S\n"
	"eQu2Mv+Iqx6dPEd6Z+Zt+bXF9t4=\n"
	"-----END CERTIFICATE-----\n";

static const char expected_unsigned_passport[] =
	"eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9jZXJ0LmV4YW1wbGUudGVzdC9wYXNzcG9ydC5wZW0ifQ."
	"eyJhdHRlc3QiOiJBIiwiZGVzdCI6eyJ0biI6WyIxMjE1NTU1MTIxMyJdfSwiaWF0IjoxNzAwMDAwMDAwLCJvcmlnIjp7InRuIjoiMTIxNTU1NTEyMTIifSwib3JpZ2lkIjoiMTIzZTQ1NjctZTg5Yi0xMmQzLWE0NTYtNDI2NjE0MTc0MDAwIn0";

/* A fixed wire input for the verification-service test. */
static const char inbound_invite[] =
	"INVITE sip:+12155551213@example.test SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-test-vs\r\n"
	"From: <sip:+12155551212@example.test>;tag=from-tag\r\n"
	"To: <sip:+12155551213@example.test>\r\n"
	"Call-ID: stir-shaken-vs-test@example.test\r\n"
	"CSeq: 1 INVITE\r\n"
	"Max-Forwards: 70\r\n"
	"Identity: "
	"eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9jZXJ0LmV4YW1wbGUudGVzdC9wYXNzcG9ydC5wZW0ifQ."
	"eyJhdHRlc3QiOiJBIiwiZGVzdCI6eyJ0biI6WyIxMjE1NTU1MTIxMyJdfSwiaWF0IjoxNzAwMDAwMDAwLCJvcmlnIjp7InRuIjoiMTIxNTU1NTEyMTIifSwib3JpZ2lkIjoiMTIzZTQ1NjctZTg5Yi0xMmQzLWE0NTYtNDI2NjE0MTc0MDAwIn0."
	"Wm2nIy7FR7SVQ8QydoKSK4_jFpTzR568cPUvD3D9RbQ9KF9uXDOsimS4XEF_2JFKIKT-4b0BiaMbwUjRPCVu2w"
	";info=<" TEST_X5U ">;alg=ES256;ppt=shaken\r\n"
	"Content-Length: 0\r\n"
	"\r\n";

static int verify_generated_identity(str *identity, str *certificate)
{
	char msg_buf[8192];
	str msg;
	int len;

	len = snprintf(msg_buf, sizeof(msg_buf),
		"INVITE sip:+" TEST_DEST "@example.test SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-test-as\r\n"
		"From: <sip:+" TEST_ORIG "@example.test>;tag=from-tag\r\n"
		"To: <sip:+" TEST_DEST "@example.test>\r\n"
		"Call-ID: stir-shaken-as-test@example.test\r\n"
		"CSeq: 1 INVITE\r\n"
		"Max-Forwards: 70\r\n"
		"%.*s"
		"Content-Length: 0\r\n"
		"\r\n", identity->len, identity->s);
	if (len < 0 || len >= sizeof(msg_buf))
		return -1;

	msg.s = msg_buf;
	msg.len = len;
	return stir_shaken_test_verify_msg(&msg, certificate);
}

static void test_inbound_verification(void)
{
	str msg = {(char *)inbound_invite, sizeof(inbound_invite) - 1};
	str cert = {(char *)test_certificate, sizeof(test_certificate) - 1};

	ok(stir_shaken_test_verify_msg(&msg, &cert) == 0,
		"VS validates a static signed INVITE");
}

static void test_outbound_authentication(void)
{
	str attest = str_init("A");
	str x5u = str_init(TEST_X5U);
	str orig = str_init(TEST_ORIG);
	str dest = str_init(TEST_DEST);
	str origid = str_init(TEST_ORIGID);
	str key = {(char *)test_private_key, sizeof(test_private_key) - 1};
	str cert = {(char *)test_certificate, sizeof(test_certificate) - 1};
	str identity = STR_NULL;
	size_t prefix_len = sizeof("Identity: ") - 1;
	size_t unsigned_len = sizeof(expected_unsigned_passport) - 1;
	int rc;

	rc = stir_shaken_test_build_identity(TEST_IAT, &attest, &x5u,
		&orig, &dest, &origid, &key, &identity);
	ok(rc == 0, "AS creates a signed Identity header");
	if (rc < 0)
		return;

	ok(identity.len > prefix_len + unsigned_len + 1 &&
		memcmp(identity.s, "Identity: ", prefix_len) == 0 &&
		memcmp(identity.s + prefix_len, expected_unsigned_passport,
			unsigned_len) == 0 &&
		identity.s[prefix_len + unsigned_len] == '.',
		"AS produces the expected JWS header and payload segments");

	ok(verify_generated_identity(&identity, &cert) == 0,
		"AS signature segment verifies with the matching certificate");

	pkg_free(identity.s);
}

/* Static test-only SPC certificate; matching key is test_private_key. */
static const char div_certificate[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBpDCCAUqgAwIBAgIUFQEaj/q6Qi/DNrbvnH1C1xC450swCgYIKoZIzj0EAwIw\n"
	"HDEaMBgGA1UEAwwRT3BlblNJUFMtRElWLVRlc3QwIBcNMjYxMDI5MTU0OTMzWhgP\n"
	"MjEyNjEwMDUxNTQ5MzNaMBwxGjAYBgNVBAMMEU9wZW5TSVBTLURJVi1UZXN0MFkw\n"
	"EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjaRI7F43cbJ2U5BSadK1AscH5GFZXHfM\n"
	"HNOo1peKJIBVGKxg1ZZifF/3qnaNPxCdK0vP8EUNtqpjFEnDJeq0OqNoMGYwHQYD\n"
	"VR0OBBYEFIzLEW63TVd1F9hLDAtM9e2DTtlJMB8GA1UdIwQYMBaAFIzLEW63TVd1\n"
	"F9hLDAtM9e2DTtlJMA8GA1UdEwEB/wQFMAMBAf8wEwYIKwYBBQUHARoEBzAFgAMw\n"
	"MDEwCgYIKoZIzj0EAwIDSAAwRQIgF+K+pusq8y3rbcP4JzNJlgAjanzF1dEZvOqx\n"
	"6+se3vwCIQD1sWIFSrxetIIhbMipCFsCTaLd0peHpHfBs9FsoaTQFA==\n"
	"-----END CERTIFICATE-----\n";

static int verify_div_signature(str *body, str *certbuf)
{
	struct parsed_identity p = {0};
	BIO *bio = NULL;
	X509 *cert = NULL;
	EVP_PKEY *key = NULL;
	EVP_MD_CTX *ctx = NULL;
	ECDSA_SIG *sig = NULL;
	BIGNUM *r = NULL, *s = NULL;
	unsigned char der[80], *cursor = der;
	char *first, *second;
	int len, rc = 0;

	if (passport_parse_identity(body, &p) < 0 || p.dec_signature.len != 64)
		goto done;
	first = memchr(body->s, '.', body->len);
	second = first ? memchr(first+1, '.', body->len-(first+1-body->s)) : NULL;
	bio = BIO_new_mem_buf(certbuf->s, certbuf->len);
	cert = bio ? PEM_read_bio_X509(bio, NULL, 0, NULL) : NULL;
	key = cert ? X509_get_pubkey(cert) : NULL;
	ctx = EVP_MD_CTX_create();
	sig = ECDSA_SIG_new();
	if (!second || !key || !ctx || !sig)
		goto done;
#if defined(WOLFSSL_VERSION) || OPENSSL_VERSION_NUMBER < 0x10100000L
	r = BN_bin2bn((unsigned char *)p.dec_signature.s, 32, sig->r);
	s = BN_bin2bn((unsigned char *)p.dec_signature.s+32, 32, sig->s);
#else
	r = BN_bin2bn((unsigned char *)p.dec_signature.s, 32, NULL);
	s = BN_bin2bn((unsigned char *)p.dec_signature.s+32, 32, NULL);
	if (!r || !s) {
		BN_free(r);
		BN_free(s);
		goto done;
	}
	ECDSA_SIG_set0(sig, r, s);
#endif
	if (!r || !s)
		goto done;
	len = i2d_ECDSA_SIG(sig, &cursor);
	if (len > 0 && EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) == 1 &&
		EVP_DigestVerifyUpdate(ctx, body->s, second-body->s) == 1)
		rc = EVP_DigestVerifyFinal(ctx, der, len) == 1;
done:
	if (sig) ECDSA_SIG_free(sig);
	if (ctx) EVP_MD_CTX_destroy(ctx);
	if (key) EVP_PKEY_free(key);
	if (cert) X509_free(cert);
	if (bio) BIO_free(bio);
	passport_identity_cleanup(&p);
	return rc;
}

static void test_div_authentication(void)
{
	struct sip_msg msg = {0};
	struct parsed_identity parsed = {0};
	str cert = STR_NULL, key = {(char *)test_private_key, sizeof(test_private_key)-1};
	str x5u = str_init(TEST_X5U);
	str target = str_init("+12155551214"), later = str_init("12155551215");
	str sos = str_init("urn:service:sos.fire"), bad = str_init("sip:evil@example.test");
	str wrong_orig = str_init("12155559999"), body;
	char input[sizeof(inbound_invite)];
	int rc, yes = 1;
	time_t before = time(NULL);
	cJSON *value;

	cert.s = (char *)div_certificate;
	cert.len = sizeof(div_certificate)-1;
	push_new_global_context();
	memcpy(input, inbound_invite, sizeof(input));
	msg.buf = input;
	msg.len = sizeof(input)-1;
	msg.ruri_q = Q_UNSPECIFIED;
	if (parse_msg(input, msg.len, &msg) < 0) {
		ok(0, "DIV signing test message setup");
		goto done;
	}
	rc = stir_shaken_test_auth_div(&msg, &cert, &key, &x5u,
		NULL, NULL, &target, -1);
	ok(rc == -10, "unknown prior state requires completed VS verification");
	rc = stir_shaken_test_auth_div(&msg, &cert, &key, &x5u,
		NULL, NULL, &target, 0);
	ok(rc == -8, "explicit false refuses DIV signing");
	rc = stir_shaken_test_auth_div(&msg, &cert, &key, &x5u,
		&wrong_orig, NULL, &target, yes);
	ok(rc == -3, "DIV signing cannot override the original caller");
	rc = stir_shaken_test_auth_div(&msg, &cert, &key, &x5u,
		NULL, NULL, &bad, yes);
	ok(rc == -3, "DIV signing rejects arbitrary URI destinations");
	rc = stir_shaken_test_auth_div(&msg, &cert, &key, &x5u,
		NULL, &later, &target, yes);
	ok(rc == -7, "DIV rejects an explicit retarget-from outside the chain");
	{
		str unsuitable = {(char *)test_certificate, sizeof(test_certificate)-1};
		rc = stir_shaken_test_auth_div(&msg, &unsuitable, &key, &x5u,
			NULL, NULL, &target, yes);
		ok(rc == -5, "DIV signing requires TNAuthList on the signing certificate");
	}
	rc = stir_shaken_test_auth_div(&msg, &cert, &key, &x5u,
		NULL, NULL, &target, yes);
	ok(rc == 1, "trusted prior verification permits signing after a delay");
	if (rc != 1)
		goto done;
	body = *stir_shaken_test_last_generated();
	ok(verify_div_signature(&body, &cert), "DIV signature verifies over received A.B");
	rc = passport_parse_identity(&body, &parsed);
	value = rc == 0 ? cJSON_GetObjectItem(parsed.header, "ppt") : NULL;
	ok(value && !strcmp(value->valuestring, "div") &&
		!str_strcmp(&parsed.ppt_hdr_param, const_str("div")),
		"DIV sets both protected and SIP ppt parameters");
	ok(parsed.iat && parsed.iat->valuedouble >= before &&
		parsed.iat->valuedouble <= time(NULL) &&
		!cJSON_GetObjectItem(parsed.payload, "attest") &&
		!cJSON_GetObjectItem(parsed.payload, "origid") &&
		!cJSON_GetObjectItem(parsed.payload, "opt"),
		"DIV uses fresh iat and does not copy SHAKEN-only claims");
	ok(parsed.orig_tn && !strcmp(parsed.orig_tn->valuestring, TEST_ORIG) &&
		parsed.dest_tn && !strcmp(parsed.dest_tn->valuestring, "12155551214") &&
		!strcmp(cJSON_GetObjectItem(cJSON_GetObjectItem(parsed.payload, "div"),
			"tn")->valuestring, TEST_DEST),
		"DIV copies original caller and links canonical old/new targets");
	passport_identity_cleanup(&parsed);
	memset(&parsed, 0, sizeof(parsed));
	rc = stir_shaken_test_auth_div(&msg, &cert, &key, &x5u,
		NULL, NULL, &later, -1);
	ok(rc == 1, "subsequent DIV uses freshly appended outermost token");
	rc = stir_shaken_test_auth_div(&msg, &cert, &key, &x5u,
		NULL, NULL, &later, -1);
	ok(rc == -3, "DIV rejects an unchanged canonical target");
	rc = stir_shaken_test_auth_div(&msg, &cert, &key, &x5u,
		NULL, NULL, &sos, -1);
	ok(rc == 1, "DIV supports an SOS URN destination");
	stir_shaken_test_mark_stale();
	rc = stir_shaken_test_auth_div(&msg, &cert, &key, &x5u,
		NULL, NULL, &target, yes);
	ok(rc == -4, "trusted flag cannot override a recorded freshness failure");
done:
	free_sip_msg(&msg);
	pop_pushed_global_context();

	/* A freshly generated base token must be visible before serialization. */
	push_new_global_context();
	memset(&msg, 0, sizeof(msg));
	memcpy(input, inbound_invite, sizeof(input));
	/* Remove the received Identity; the base AS will supply the only token. */
	{
		char *start = strstr(input, "Identity: "), *end = strstr(start, "\r\n");
		memmove(start, end+2, strlen(end+2)+1);
	}
	msg.buf = input;
	msg.len = strlen(input);
	msg.ruri_q = Q_UNSPECIFIED;
	parse_msg(input, msg.len, &msg);
	rc = stir_shaken_test_auth_div(&msg, &cert, &key, &x5u,
		NULL, NULL, &target, yes);
	ok(rc == -2, "DIV signing requires an existing SHAKEN token");
	rc = stir_shaken_test_auth_base(&msg, &cert, &key, &x5u);
	ok(rc == 1, "base AS appends a new SHAKEN token");
	/* Exercise Request-URI derivation after a script rewrite. */
	msg.new_uri = str_init("sip:+12155551214@example.test");
	rc = stir_shaken_test_auth_div(&msg, &cert, &key, &x5u,
		NULL, NULL, NULL, -1);
	ok(rc == 1, "base authentication followed immediately by DIV succeeds");
	msg.new_uri = STR_NULL; /* literal, not a pkg-owned rewrite */
	free_sip_msg(&msg);
	pop_pushed_global_context();
}

static void test_div_chain_selection(void)
{
	struct div_chain chain = {0};
	str keybuf = {(char *)test_private_key, sizeof(test_private_key)-1};
	str x5u = str_init(TEST_X5U), orig = str_init(TEST_ORIG);
	str b = str_init(TEST_DEST), c = str_init("12155551214"), d = str_init("12155551215");
	str headers[3] = {STR_NULL, STR_NULL, STR_NULL}, body[3], base;
	char input[sizeof(inbound_invite)];
	BIO *bio = BIO_new_mem_buf(keybuf.s, keybuf.len);
	EVP_PKEY *key = bio ? PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL) : NULL;
	str *built;
	int i;

	if (!key) {
		ok(0, "DIV chain test key setup");
		if (bio) BIO_free(bio);
		return;
	}
	memcpy(input, inbound_invite, sizeof(input));
	base.s = strstr(input, "Identity: ") + IDENTITY_HDR_LEN;
	base.len = strstr(base.s, "\r\n") - base.s;
	for (i = 0; i < 3; i++) {
		built = passport_build_div(key, TEST_IAT, &x5u, &orig,
			i == 0 ? &b : i == 1 ? &c : &d,
			i == 0 ? &c : i == 1 ? &d : &b);
		if (!built) {
			ok(0, "DIV chain test token setup");
			goto done;
		}
		headers[i] = *built;
		body[i].s = built->s + IDENTITY_HDR_LEN;
		body[i].len = built->len - IDENTITY_HDR_LEN - CRLF_LEN;
	}
	ok(div_chain_add(&chain, &body[1]) == 0 &&
		div_chain_add(&chain, &base) == 0 &&
		div_chain_add(&chain, &body[0]) == 0 &&
		div_chain_select(&chain, NULL) == 0 &&
		!str_strcmp(&chain.previous, &d),
		"AS orders received DIV headers by links, even with equal iat values");
	div_chain_cleanup(&chain);
	memset(&chain, 0, sizeof(chain));
	ok(div_chain_add(&chain, &base) == 0 &&
		div_chain_add(&chain, &body[1]) == 0 &&
		div_chain_select(&chain, NULL) == -7,
		"AS refuses a chain with a missing diversion link");
	div_chain_cleanup(&chain);
	memset(&chain, 0, sizeof(chain));
	ok(div_chain_add(&chain, &base) == 0 &&
		div_chain_add(&chain, &body[0]) == 0 &&
		div_chain_add(&chain, &body[1]) == 0 &&
		div_chain_add(&chain, &body[2]) == 0 &&
		div_chain_select(&chain, NULL) == -7,
		"AS refuses a cyclic diversion chain");
done:
	div_chain_cleanup(&chain);
	for (i = 0; i < 3; i++)
		if (headers[i].s) pkg_free(headers[i].s);
	EVP_PKEY_free(key);
	BIO_free(bio);
}

void test_verstat(void);
void test_verstat_edges(void);
void test_vs(str *);

static void test_nullable_previous_state(void)
{
	struct sip_msg msg = {0};
	pv_spec_t spec = {0};
	str name = str_init("$var(test_previous_state)");
	struct cmd_param params[] = {
		{CMD_PARAM_INT|CMD_PARAM_OPT|CMD_PARAM_NULLABLE, 0, 0}, {0, 0, 0}
	};
	gparam_t gp = {0};
	action_elem_t elems[2] = {{0}};
	pv_value_t value = {0}, tmp[2] = {0};
	void *args[1];
	int state;

	if (!pv_parse_spec(&name, &spec)) {
		ok(0, "parse nullable previous-state variable");
		return;
	}
	gp.type = GPARAM_TYPE_PVS;
	gp.pval = &spec;
	elems[1].u.data = &gp;
	ok(pv_set_value(&msg, &spec, 0, NULL) == 0 &&
		get_cmd_fixups(&msg, params, elems, args, tmp) == 0 && !args[0],
		"null-valued previous-state variable reaches AS as unknown");
	params[0].flags &= ~CMD_PARAM_NULLABLE;
	ok(get_cmd_fixups(&msg, params, elems, args, tmp) < 0,
		"ordinary integer parameters continue rejecting null-valued variables");
	params[0].flags |= CMD_PARAM_NULLABLE;
	for (state = 0; state <= 1; state++) {
		value.flags = PV_VAL_INT|PV_TYPE_INT;
		value.ri = state;
		ok(pv_set_value(&msg, &spec, 0, &value) == 0 &&
			get_cmd_fixups(&msg, params, elems, args, tmp) == 0 &&
			args[0] && *(int *)args[0] == state,
			"boolean previous-state variable preserves %s", state ? "true" : "false");
	}
	value.flags = PV_VAL_STR;
	value.rs = str_init("false");
	ok(pv_set_value(&msg, &spec, 0, &value) == 0 &&
		get_cmd_fixups(&msg, params, elems, args, tmp) < 0,
		"nullable integer arguments still reject strings");
	pv_set_value(&msg, &spec, 0, NULL);
}

void mod_tests(void)
{
	test_nullable_previous_state();
	test_inbound_verification();
	test_outbound_authentication();
	test_div_authentication();
	test_div_chain_selection();
	test_verstat();
	test_verstat_edges();
	{
		str key = {(char *)test_private_key, sizeof(test_private_key)-1};
		test_vs(&key);
	}
}
