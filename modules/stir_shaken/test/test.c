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

#include "../../../mem/mem.h"
#include "../../../str.h"

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

void mod_tests(void)
{
	test_inbound_verification();
	test_outbound_authentication();
}
