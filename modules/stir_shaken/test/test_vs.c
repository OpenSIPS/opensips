/* Copyright (C) 2026 OpenSIPS Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "../verify.h"
#include "../div.h"
#include <tap.h>
#include "../../../context.h"
#include "../../../ut.h"

int stir_shaken_test_trust_vs(str *);
int stir_shaken_test_auth_div(struct sip_msg *, str *, str *, str *, str *, str *, str *, int);

/* Public test fixture: self-signed trust anchor with explicit SPC TNAuthList. */
static const char vs_certificate[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBlDCCATugAwIBAgIUFQEaj/q6Qi/DNrbvnH1C1xC450swCgYIKoZIzj0EAwIw\n"
	"HDEaMBgGA1UEAwwRT3BlblNJUFMtRElWLVRlc3QwIBcNMjYxMDI5MTU0OTMzWhgP\n"
	"MjEyNjEwMDUxNTQ5MzNaMBwxGjAYBgNVBAMMEU9wZW5TSVBTLURJVi1UZXN0MFkw\n"
	"EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjaRI7F43cbJ2U5BSadK1AscH5GFZXHfM\n"
	"HNOo1peKJIBVGKxg1ZZifF/3qnaNPxCdK0vP8EUNtqpjFEnDJeq0OqNZMFcwDwYD\n"
	"VR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAoQwFQYIKwYBBQUHARoECTAHoAUW\n"
	"AzAwMTAdBgNVHQ4EFgQUjMsRbrdNV3UX2EsMC0z17YNO2UkwCgYIKoZIzj0EAwID\n"
	"RwAwRAIgLZC/jDLdpARk8CoEFi53Jv1rhQLxIasd5sYurkOQ+dECIH0ko+Kpm+eg\n"
	"ZHlOjOREl2P1NZtuuLxsxoOvxayQZFG0\n"
	"-----END CERTIFICATE-----\n";

static int make_message(struct sip_msg *msg, char *buf, size_t size,
	str *tokens, int *order, int n, const char *recipient)
{
	int i, len;
	len = snprintf(buf, size,
		"INVITE sip:%s@example.test SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK-vs\r\n"
		"From: <sip:+12155551212@example.test>;tag=abc\r\n"
		"To: <sip:+12155551213@example.test>\r\n"
		"Call-ID: chain-test\r\nCSeq: 1 INVITE\r\n", recipient);
	for (i = 0; i < n; i++) {
		if (tokens[order[i]].len >= size-len) return -1;
		memcpy(buf+len, tokens[order[i]].s, tokens[order[i]].len);
		len += tokens[order[i]].len;
	}
	if (len+23 >= size) return -1;
	len += snprintf(buf+len, size-len, "Content-Length: 0\r\n\r\n");
	memset(msg, 0, sizeof(*msg));
	msg->buf = buf; msg->len = len; msg->ruri_q = Q_UNSPECIFIED;
	return parse_msg(buf, len, msg);
}

static int verify_all(struct sip_msg *msg, str *cert, int n)
{
	int i, rc = 1, result;
	for (i = 0; i < n; i++) {
		result = stir_shaken_verify_passport(msg, &i, cert, NULL, NULL);
		if (result != 1) rc = result;
	}
	return rc;
}

static int pv_is(struct sip_msg *msg, const char *field, int index, const char *expected)
{
	pv_spec_t sp = {0};
	pv_value_t value = {0};
	str name;
	init_str(&name, field);
	if (pv_parse_identity_all(&sp, &name)) return 0;
	if (index >= 0) { sp.pvp.pvi.type = PV_IDX_INT; sp.pvp.pvi.u.ival = index; }
	if (pv_get_identity_all(msg, &sp.pvp, &value)) return 0;
	if (!strcmp(field, "count")) return (value.flags & PV_VAL_INT) && value.ri == atoi(expected);
	return (value.flags & PV_VAL_STR) && value.rs.len == strlen(expected) &&
		!memcmp(value.rs.s, expected, value.rs.len);
}

static void test_authority(str *pem)
{
	BIO *bio = BIO_new_mem_buf(pem->s, pem->len);
	X509 *cert = bio ? PEM_read_bio_X509(bio, NULL, 0, NULL) : NULL;
	ASN1_OCTET_STRING *data;
	int index = -1, i;
	char oid[128];
	str inside = str_init("12155551213"), outside = str_init("12155559999");
	str encoded;
	const unsigned char one[] = "\x30\x0f\xa2\x0d\x16\x0b" "12155551213";
	const unsigned char range[] = "\x30\x14\xa1\x12\x30\x10\x16\x0b" "12155551200" "\x02\x01\x64";
	const unsigned char malformed[] = {0x30, 0x7f, 0xa0};
	for (i = 0; cert && i < X509_get_ext_count(cert); i++)
		if (OBJ_obj2txt(oid, sizeof(oid), X509_EXTENSION_get_object(X509_get_ext(cert, i)), 1) > 0 &&
			!strcmp(oid, "1.3.6.1.5.5.7.1.26")) { index = i; break; }
	if (index < 0) { ok(0, "TNAuthList test fixture setup"); goto done; }
	data = X509_EXTENSION_get_data(X509_get_ext(cert, index));
	ok(passport_certificate_authority(cert, &inside),
		"trusted SPC TNAuthList is recognized under the SHAKEN SP authority model");
	encoded.s = (char *)one; encoded.len = sizeof(one)-1;
	ok(passport_authority_der(&encoded, &inside) &&
		!passport_authority_der(&encoded, &outside),
		"individual TN authorization does not authorize an unrelated number");
	encoded.s = (char *)range; encoded.len = sizeof(range)-1;
	ok(passport_authority_der(&encoded, &inside) &&
		!passport_authority_der(&encoded, &outside),
		"TN range authorization enforces the signed numeric scope");
	encoded.s = (char *)malformed; encoded.len = sizeof(malformed);
	ok(!passport_authority_der(&encoded, &inside),
		"malformed TNAuthList DER fails closed");
	(void)data;
done:
	if (cert) X509_free(cert);
	if (bio) BIO_free(bio);
}

static int chain_result(str *tokens, int *order, int n, str *cert,
	const char *recipient, int *inner)
{
	char buf[8192];
	struct sip_msg msg = {0};
	int rc;
	push_new_global_context();
	if (make_message(&msg, buf, sizeof(buf), tokens, order, n, recipient)) rc = -100;
	else {
		verify_all(&msg, cert, n);
		rc = stir_shaken_verify_chain(&msg, NULL, NULL, NULL, NULL, inner, NULL);
	}
	free_sip_msg(&msg);
	pop_pushed_global_context();
	return rc;
}

void test_vs(str *keybuf)
{
	BIO *bio = BIO_new_mem_buf(keybuf->s, keybuf->len);
	EVP_PKEY *key = bio ? PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL) : NULL;
	str cert = {(char *)vs_certificate, sizeof(vs_certificate)-1};
	str tokens[5] = {STR_NULL, STR_NULL, STR_NULL, STR_NULL, STR_NULL}, *built;
	str x5u = str_init("https://cert.example.test/passport.pem"), orig = str_init("12155551212");
	str b = str_init("12155551213"), c = str_init("12155551214"), d = str_init("12155551215");
	str next_target = str_init("12155551216"), final_target = str_init("12155551217");
	str a = str_init("A"), origid = str_init("vs-test");
	int normal[] = {0, 1, 2}, shuffled[] = {2, 0, 1}, missing[] = {0, 2};
	int shared[] = {2, 0, 1, 0}, bad_extra[] = {0, 1, 2, 4};
	int cycle[] = {0, 1, 3}, bypass = -1, extended = 120, invalid = 30, i, rc;
	time_t now = time(NULL);
	char buf[8192];
	struct sip_msg msg = {0};

	if (!key || stir_shaken_test_trust_vs(&cert)) {
		ok(0, "VS trust fixture setup");
		goto done;
	}
	test_authority(&cert);
	built = passport_build_identity(key, now-600, &a, &x5u, &orig, &b, &origid);
	if (!built) goto setup_error;
	tokens[0] = *built;
	built = passport_build_div(key, now-300, &x5u, &orig, &b, &c);
	if (!built) goto setup_error;
	tokens[1] = *built;
	built = passport_build_div(key, now, &x5u, &orig, &c, &d);
	if (!built) goto setup_error;
	tokens[2] = *built;
	built = passport_build_div(key, now, &x5u, &orig, &c, &b);
	if (!built) goto setup_error;
	tokens[3] = *built;
	tokens[4] = str_init("Identity: definitely-not-a-passport\r\n");

	ok(chain_result(tokens, normal, 3, &cert, d.s, NULL) == 1,
		"VS verifies trusted signatures and the complete SHAKEN-DIV chain");
	ok(chain_result(tokens, shuffled, 3, &cert, d.s, NULL) == 1,
		"VS reconstructs dependencies independent of Identity header order");
	ok(chain_result(tokens, normal, 3, &cert, d.s, &extended) == -11,
		"per-call inner freshness rejects an older original token");
	ok(chain_result(tokens, normal, 3, &cert, d.s, &bypass) == 1,
		"per-call -1 bypasses inner freshness while signatures remain checked");
	ok(chain_result(tokens, normal, 3, &cert, d.s, &invalid) == -3,
		"inner freshness must extend the outermost window");
	ok(chain_result(tokens, normal, 3, &cert, b.s, NULL) == -7,
		"VS rejects a final destination mismatch");
	ok(chain_result(tokens, missing, 2, &cert, d.s, NULL) == -7,
		"VS rejects a missing signed diversion link");
	ok(chain_result(tokens, cycle, 3, &cert, b.s, NULL) == -7,
		"VS rejects signed cyclic dependencies");
	ok(chain_result(tokens, shared, 4, &cert, d.s, NULL) == 1,
		"multiple SHAKEN roots can share the same authenticated diversion links");
	ok(chain_result(tokens, bad_extra, 4, &cert, d.s, NULL) == -4,
		"malformed extra Identity is counted and cannot silently disappear");

	push_new_global_context();
	make_message(&msg, buf, sizeof(buf), tokens, shuffled, 3, d.s);
	ok(stir_shaken_test_auth_div(&msg, &cert, keybuf, &x5u,
		NULL, NULL, &next_target, -1) == -10,
		"freshness alone cannot authorize an unknown previous state");
	ok(pv_is(&msg, "count", -1, "3") && pv_is(&msg, "ppt", 0, "div") &&
		pv_is(&msg, "ppt", 1, "shaken") && pv_is(&msg, "orig", -1, orig.s),
		"indexed Identity PVs use wire order and unindexed access selects SHAKEN");
	i = 0;
	stir_shaken_verify_passport(&msg, &i, &cert, NULL, NULL);
	ok(stir_shaken_verify_chain(&msg, NULL, NULL, NULL, NULL, NULL, NULL) == -10,
		"VS refuses to use unverified intermediate and root PASSporTs");
	verify_all(&msg, &cert, 3);
	ok(stir_shaken_verify_chain(&msg, NULL, NULL, NULL, NULL, NULL, NULL) == 1,
		"completing per-token verification enables full chain validation");
	ok(stir_shaken_test_auth_div(&msg, &cert, keybuf, &x5u,
		NULL, NULL, &next_target, -1) == 1,
		"omitted previous state reuses completed local VS success");
	ok(pv_is(&msg, "chain_status", -1, "passed") &&
		pv_is(&msg, "chain_attest", -1, "A") && pv_is(&msg, "status", 0, "verified"),
		"chain result and per-token status are available to routing policy");
	{
		str absent = str_init("not a certificate");
		stir_shaken_verify_passport(&msg, &i, &absent, NULL, NULL);
		ok(stir_shaken_verify_chain(&msg, NULL, NULL, NULL, NULL, NULL, NULL) == -8,
			"failed re-verification clears a previously successful token result");
		ok(stir_shaken_test_auth_div(&msg, &cert, keybuf, &x5u,
			NULL, NULL, &final_target, -1) == -8,
			"omitted previous state refuses a locally recorded VS failure");
	}
	free_sip_msg(&msg);
	pop_pushed_global_context();
	memset(&msg, 0, sizeof(msg));

	/* Flip one encoded signature character, retaining a syntactically valid JWS. */
	{
		char *first = memchr(tokens[2].s, '.', tokens[2].len);
		char *sig = memchr(first+1, '.', tokens[2].len-(first+1-tokens[2].s))+1;
		char saved = *sig;
		*sig = saved == 'A' ? 'B' : 'A';
		ok(chain_result(tokens, normal, 3, &cert, d.s, &bypass) == -9,
			"inner bypass cannot bypass a bad outermost signature");
		*sig = saved;
	}
	pkg_free(tokens[2].s);
	built = passport_build_div(key, now-600, &x5u, &orig, &c, &d);
	if (!built) { tokens[2] = STR_NULL; goto setup_error; }
	tokens[2] = *built;
	ok(chain_result(tokens, normal, 3, &cert, d.s, &bypass) == -6,
		"inner bypass never bypasses outermost freshness");
	ok(chain_result(tokens, normal, 3, &cert, d.s, &extended) == -6,
		"outermost staleness takes priority when inner tokens are stale too");
	push_new_global_context();
	make_message(&msg, buf, sizeof(buf), tokens, normal, 3, d.s);
	verify_all(&msg, &cert, 3);
	{
		int pre_retarget_window = 10800, invalid_outer = -1;
		ok(stir_shaken_verify_chain(&msg, NULL, NULL, NULL, NULL,
			NULL, &pre_retarget_window) == 1,
			"explicit pre-retarget outer window permits delayed verification");
		ok(stir_shaken_verify_chain(&msg, NULL, NULL, NULL, NULL,
			NULL, &invalid_outer) == -3,
			"outer freshness override cannot disable the outer age check");
		stir_shaken_verify_chain(&msg, NULL, NULL, NULL, NULL, NULL, &pre_retarget_window);
		ok(stir_shaken_test_auth_div(&msg, &cert, keybuf, &x5u,
			NULL, NULL, &next_target, -1) == 1,
			"AS reuses a delayed VS success without rechecking historical freshness");
		ok(stir_shaken_test_auth_div(&msg, &cert, keybuf, &x5u,
			NULL, NULL, &final_target, 0) == -8,
			"explicit false refuses signing even when a previous success is cached");
		ok(stir_shaken_test_auth_div(&msg, &cert, keybuf, &x5u,
			NULL, NULL, &final_target, -1) == -8,
			"a recorded explicit false is not mistaken for unknown");
	}
	free_sip_msg(&msg);
	pop_pushed_global_context();
	goto done;
setup_error:
	ok(0, "VS signed fixture setup");
done:
	for (rc = 0; rc < 4; rc++) if (tokens[rc].s) pkg_free(tokens[rc].s);
	if (key) EVP_PKEY_free(key);
	if (bio) BIO_free(bio);
}
