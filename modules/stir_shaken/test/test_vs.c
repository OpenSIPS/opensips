/* Copyright (C) 2026 OpenSIPS Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "../verify.h"
#include "../div.h"
#include <tap.h>
#include <limits.h>
#include "../../../context.h"
#include "../../../ut.h"
#include "../../../action.h"
#include "../../../msg_translator.h"
#include "credentials.h"

int stir_shaken_test_trust_vs(str *);
int stir_shaken_test_auth_div(struct sip_msg *, str *, str *, str *, str *, str *, str *, int);
int stir_shaken_test_freshness(int *, int, int *);

static void test_freshness_defaults(void)
{
	static const struct {
		int outer, inner, configured, expected_rc, expected_outer, expected_inner;
		const char *name;
	} cases[] = {
		{60,10800,0,0,60,10800,"ordinary outer window retains three-hour default"},
		{10740,10800,0,0,10740,10800,"default already has a full minute of margin"},
		{10741,10800,0,0,10741,10801,"default grows when margin falls below one minute"},
		{10799,10800,0,0,10799,10859,"default grows even when it already exceeds outer window"},
		{10799,10800,1,0,10799,10800,"explicit inner window need not adopt the default margin"},
		{10800,10800,0,0,10800,10860,"default grows when outer reaches three hours"},
		{28400,10800,0,0,28400,28460,"untouched default follows enlarged outer window"},
		{28400,10800,1,-1,28400,10800,"explicit three-hour limit is not silently increased"},
		{28400,40000,1,0,28400,40000,"explicit larger inner limit is preserved"},
		{28400,-1,1,0,28400,-1,"explicit inner bypass is preserved"},
		{-1,10800,0,-1,-1,10800,"negative outer window remains invalid"},
		{60,0,1,-1,60,0,"explicit zero inner window remains invalid"},
		{28400,28400,1,-1,28400,28400,"explicit equal inner window remains invalid"},
		{INT_MAX-60,10800,0,0,INT_MAX-60,INT_MAX,"largest outer window with a full minute of margin"},
		{INT_MAX-59,10800,0,0,INT_MAX-60,INT_MAX,"clamping starts when a full minute would overflow"},
		{INT_MAX,10800,0,0,INT_MAX-60,INT_MAX,"maximal outer window leaves room for inner default"},
		{INT_MAX,-1,1,0,INT_MAX-60,-1,"clamping the outer window preserves explicit inner bypass"},
		{INT_MAX,INT_MAX,1,0,INT_MAX-60,INT_MAX,"clamping permits an explicit maximal inner window"}
	};
	int i, outer, inner, rc;
	for (i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
		outer = cases[i].outer;
		inner = cases[i].inner;
		rc = stir_shaken_test_freshness(&outer, cases[i].configured, &inner);
		ok(rc == cases[i].expected_rc && outer == cases[i].expected_outer &&
			inner == cases[i].expected_inner,
			"freshness initialization: %s", cases[i].name);
	}
}

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
	str *tokens, const int *order, int n, const char *recipient)
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

/* Sign arbitrary JSON independently of the production payload builder, so
 * negative profile tests carry a valid signature rather than testing tampering. */
static int encode_segment(char *out, const void *data, int len)
{
	int n = calc_base64_encode_len(len);
	base64urlencode((unsigned char *)out, (unsigned char *)data, len);
	while (n && out[n-1] == '=') n--;
	return n;
}

static str signed_json(EVP_PKEY *key, cJSON *header, cJSON *payload)
{
	char *h = cJSON_PrintUnformatted(header), *p = cJSON_PrintUnformatted(payload);
	char input[4096];
	unsigned char der[256], raw[64] = {0};
	const unsigned char *cursor = der;
	const BIGNUM *r, *s;
	ECDSA_SIG *sig = NULL;
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	size_t size = sizeof(der);
	str result = STR_NULL;
	int n, bytes;
	cJSON *ppt = cJSON_GetObjectItem(header, "ppt");
	if (!h || !p || !ctx || !ppt || strlen(h)+strlen(p) > 2500) goto done;
	n = encode_segment(input, h, strlen(h));
	input[n++] = '.';
	n += encode_segment(input+n, p, strlen(p));
	if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) <= 0 ||
		EVP_DigestSignUpdate(ctx, input, n) <= 0 ||
		EVP_DigestSignFinal(ctx, der, &size) <= 0) goto done;
	sig = d2i_ECDSA_SIG(NULL, &cursor, size);
	if (!sig) goto done;
#if !defined(WOLFSSL_VERSION) && OPENSSL_VERSION_NUMBER >= 0x10100000L
	ECDSA_SIG_get0(sig, &r, &s);
#else
	r = sig->r; s = sig->s;
#endif
	bytes = BN_num_bytes(r);
	if (bytes > 32 || BN_bn2bin(r, raw+32-bytes) != bytes) goto done;
	bytes = BN_num_bytes(s);
	if (bytes > 32 || BN_bn2bin(s, raw+64-bytes) != bytes) goto done;
	input[n++] = '.';
	n += encode_segment(input+n, raw, sizeof(raw));
	result.s = pkg_malloc(n+512);
	if (result.s)
		result.len = snprintf(result.s, n+512,
			"Identity: %.*s;info=<https://cert.example.test/passport.pem>;alg=ES256;ppt=%s\r\n",
			n, input, ppt->valuestring);
done:
	if (ctx) EVP_MD_CTX_destroy(ctx);
	if (sig) ECDSA_SIG_free(sig);
	cJSON_PurgeString(h); cJSON_PurgeString(p);
	return result;
}

static str rewrite_claim(EVP_PKEY *key, str *token, int in_header,
	const char *name, const char *json)
{
	struct parsed_identity parsed = {0};
	str body = {token->s + IDENTITY_HDR_LEN, token->len - IDENTITY_HDR_LEN - CRLF_LEN};
	str result = STR_NULL;
	cJSON *object, *replacement = cJSON_Parse(json);
	if (!replacement || passport_parse_identity(&body, &parsed)) goto done;
	object = in_header ? parsed.header : parsed.payload;
	cJSON_DeleteItemFromObject(object, name);
	cJSON_AddItemToObject(object, name, replacement);
	replacement = NULL;
	result = signed_json(key, parsed.header, parsed.payload);
done:
	cJSON_Delete(replacement);
	passport_identity_cleanup(&parsed);
	return result;
}

static int chain_result(str *tokens, const int *order, int n, str *cert,
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

static void test_credentials(str *tokens)
{
	static const struct {
		const char *pem, *description;
	} cases[] = {
		{credential_expired, "expired certificate with the correct key"},
		{credential_untrusted, "untrusted certificate with the correct key"},
		{credential_missing_tn, "trusted certificate missing TNAuthList"},
		{credential_wrong_tn, "trusted certificate authorizing another TN"},
		{credential_jwt_constraints, "unsupported JWTClaimConstraints"},
		{credential_p384, "trusted P-384 key for ES256"}
	};
	char buf[8192];
	struct sip_msg msg = {0};
	str cert;
	int order[] = {0,1,2}, i, index = 1, rc;
	for (i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
		init_str(&cert, cases[i].pem);
		push_new_global_context();
		rc = 0;
		if (make_message(&msg, buf, sizeof(buf), tokens, order, 3,
			"12155551215") == 0)
			rc = stir_shaken_verify_passport(&msg, &index, &cert, NULL, NULL);
		if (rc != -8) diag("credential %s: result %d", cases[i].description, rc);
		ok(rc == -8,
			"VS rejects %s", cases[i].description);
		free_sip_msg(&msg);
		memset(&msg, 0, sizeof(msg));
		pop_pushed_global_context();
	}
	init_str(&cert, credential_div_tn);
	push_new_global_context();
	rc = make_message(&msg, buf, sizeof(buf), tokens, order, 3, "12155551215") == 0;
	if (rc) rc = stir_shaken_verify_passport(&msg, &index, &cert, NULL, NULL);
	if (rc != 1) diag("DIV-scoped credential: result %d", rc);
	ok(rc == 1,
		"DIV certificate scoped to div TN succeeds without authorizing orig");
	index = 0;
	ok(rc && stir_shaken_verify_passport(&msg, &index, &cert, NULL, NULL) == -8,
		"the same DIV-scoped credential cannot authenticate the SHAKEN origin");
	free_sip_msg(&msg);
	pop_pushed_global_context();
}

static int policy_wire(struct sip_msg *msg, const char *expected)
{
	struct socket_info sock = {0};
	unsigned int len;
	char *wire, parameter[80];
	int i, result, old_route;
	for (i = 0; i < RT_NO; i++)
		if (sroutes->request[i].name &&
			!strcmp(sroutes->request[i].name, "TEST_VERSTAT_POLICY")) break;
	if (i == RT_NO) return 0;
	swap_route_type(old_route, REQUEST_ROUTE);
	run_top_route(sroutes->request[i], msg);
	set_route_type(old_route);
	wire = build_req_buf_from_sip_req(msg, &len, &sock, PROTO_UDP,
		NULL, MSG_TRANS_NOVIA_FLAG);
	if (!wire) return 0;
	snprintf(parameter, sizeof(parameter), ";verstat=%s", expected);
	result = strstr(wire, parameter) != NULL;
	pkg_free(wire);
	return result;
}

static void test_verstat_policy(EVP_PKEY *key, str *cert, str *tokens, time_t now)
{
	static const struct {
		const char *name, *attest, *expected;
		int result;
	} cases[] = {
		{"A attestation", "\"A\"", "TN-Validation-Passed", 1},
		{"B attestation", "\"B\"", "No-TN-Validation", 1},
		{"C attestation", "\"C\"", "No-TN-Validation", 1},
		{"bad signature", NULL, "TN-Validation-Failed", -9},
		{"stale outermost", NULL, "TN-Validation-Failed", -6},
		{"broken chain", NULL, "TN-Validation-Failed", -7},
		{"absent Identity", NULL, "No-TN-Validation", -2}
	};
	str set[3], replacement;
	struct sip_msg msg = {0};
	char buf[8192], timestamp[32];
	int order[] = {0,1,2}, missing[] = {0,2}, i, n, rc;
	for (i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
		memcpy(set, tokens, sizeof(set));
		replacement = STR_NULL;
		n = 3;
		if (cases[i].attest) {
			replacement = rewrite_claim(key, &tokens[0], 0, "attest", cases[i].attest);
			set[0] = replacement;
		} else if (i == 3 || i == 4) {
			snprintf(timestamp, sizeof(timestamp), "%ld", (long)(i == 4 ? now-600 : now));
			replacement = rewrite_claim(key, &tokens[2], 0, "iat", timestamp);
			set[2] = replacement;
			if (i == 3 && replacement.s) {
				char *dot = memchr(replacement.s, '.', replacement.len);
				char *sig = memchr(dot+1, '.', replacement.len-(dot+1-replacement.s))+1;
				*sig = *sig == 'A' ? 'B' : 'A';
			}
		} else n = i == 5 ? 2 : 0;
		push_new_global_context();
		rc = (i >= 5 || replacement.s) &&
			make_message(&msg, buf, sizeof(buf), set, i == 5 ? missing : order, n,
				"12155551215") == 0;
		if (rc) {
			verify_all(&msg, cert, n);
			rc = stir_shaken_verify_chain(&msg, NULL, NULL, NULL, NULL, NULL, NULL);
		}
		ok(rc == cases[i].result && policy_wire(&msg, cases[i].expected),
			"opensips.cfg maps %s to %s on the serialized request", cases[i].name, cases[i].expected);
		free_sip_msg(&msg);
		memset(&msg, 0, sizeof(msg));
		pop_pushed_global_context();
		if (replacement.s) pkg_free(replacement.s);
	}
}

static void test_chain_edges(EVP_PKEY *key, str *cert, str *keybuf,
	str *tokens, time_t now)
{
	static const int orders[][3] = {
		{0,1,2}, {0,2,1}, {1,0,2}, {1,2,0}, {2,0,1}, {2,1,0}
	};
	static const struct {
		int token, header;
		const char *claim, *json, *description;
		int expected;
	} invalid[] = {
		{0,0,"orig","{\"uri\":\"sip:caller@example.test\"}","non-TN original caller",-4},
		{0,0,"orig","{\"tn\":\"12155559999\"}","SHAKEN caller differs from SIP From",-9},
		{1,0,"orig","{\"tn\":\"12155559999\"}","DIV changes original caller",-9},
		{1,0,"div","{\"uri\":\"sip:target@example.test\"}","non-SOS diversion URI",-4},
		{2,0,"dest","{\"uri\":[\"sip:target@example.test\"]}","non-SOS destination URI",-4},
		{2,0,"dest","{\"uri\":[\"urn:service:sos..fire\"]}","malformed SOS URN",-4},
		{2,0,"dest","{\"tn\":[]}","empty destination list",-4},
		{1,0,"orig","{\"tn\":\"12155551212\",\"uri\":\"urn:service:sos\"}","mixed TN/URI caller",-4},
		{1,0,"iat","-1","negative iat",-4},
		{1,0,"iat","1.5","fractional iat",-4},
		{1,0,"iat","\"now\"","non-numeric iat",-4},
		{1,0,"attest","\"A\"","SHAKEN-only attestation on DIV",-4},
		{1,0,"opt","\"nested-token\"","nested opt on DIV",-4},
		{0,0,"attest","\"D\"","invalid SHAKEN attestation",-4},
		{0,0,"origid","7","non-string origid",-4},
		{1,1,"alg","\"HS256\"","wrong signing algorithm",-4},
		{1,1,"typ","\"JWT\"","wrong protected typ",-4},
		{1,1,"x5u","\"https://other.example.test/cert.pem\"","x5u/info mismatch",-4},
		{1,1,"ppt","\"rph\"","unsupported rph alongside SHAKEN",-5},
		{1,1,"ppt","\"rcd\"","unsupported rcd alongside SHAKEN",-5},
		{1,1,"ppt","\"div-o\"","unsupported div-o",-5}
	};
	str set[4], changed, equal[3] = {STR_NULL, STR_NULL, STR_NULL}, *built;
	str orig = str_init("12155551212");
	str c = str_init("12155551214"), d = str_init("12155551215");
	str other = str_init("12155559999"), next = str_init("12155551216");
	str x5u = str_init("https://cert.example.test/passport.pem");
	str sos = str_init("urn:service:sos.fire"), emergency = str_init("911");
	int order[] = {0,1,2,3}, pair[] = {0,1}, i, n;
	char timestamp[32], buf[8192];
	struct sip_msg msg = {0};

	for (i = 0; i < 6; i++)
		ok(chain_result(tokens, orders[i], 3, cert, d.s, NULL) == 1,
			"VS accepts header permutation %d%d%d", orders[i][0], orders[i][1], orders[i][2]);
	snprintf(timestamp, sizeof(timestamp), "%ld", (long)now);
	for (i = 0; i < 3; i++) equal[i] = rewrite_claim(key, &tokens[i], 0, "iat", timestamp);
	ok(equal[0].s && equal[1].s && equal[2].s &&
		chain_result(equal, order, 3, cert, d.s, NULL) == 1,
		"VS links equal-iat tokens by signed identities");
	for (i = 0; i < 3; i++) if (equal[i].s) pkg_free(equal[i].s);

	for (i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++) {
		memcpy(set, tokens, 3*sizeof(str));
		changed = rewrite_claim(key, &set[invalid[i].token], invalid[i].header,
			invalid[i].claim, invalid[i].json);
		set[invalid[i].token] = changed;
		ok(changed.s && chain_result(set, order, 3, cert, d.s, NULL) == invalid[i].expected,
			"VS rejects correctly signed %s", invalid[i].description);
		if (changed.s) pkg_free(changed.s);
	}

	/* A separate valid SHAKEN root, not a duplicate token. */
	memcpy(set, tokens, 3*sizeof(str));
	set[3] = rewrite_claim(key, &tokens[0], 0, "origid", "\"independent-root\"");
	ok(set[3].s && chain_result(set, order, 4, cert, d.s, NULL) == 1,
		"distinct signed SHAKEN roots share a complete diversion path");
	if (set[3].s) pkg_free(set[3].s);

	/* All signatures pass; a disconnected or unfinished branch still fails. */
	for (i = 0; i < 2; i++) {
		built = passport_build_div(key, now, &x5u, &orig, i ? &other : &c, &next);
		set[3] = built ? *built : STR_NULL;
		ok(set[3].s && chain_result(set, order, 4, cert, d.s, NULL) == -7,
			"VS rejects %s DIV", i ? "unrelated" : "a branch ending at another target");
		if (set[3].s) pkg_free(set[3].s);
	}
	set[3] = rewrite_claim(key, &tokens[2], 0, "iat", timestamp);
	push_new_global_context();
	n = set[3].s && make_message(&msg, buf, sizeof(buf), set, order, 4, d.s) == 0;
	ok(n && stir_shaken_test_auth_div(&msg, cert, keybuf, &x5u,
		NULL, NULL, &next, 1) == -7,
		"AS rejects ambiguous parallel diversion links rather than selecting one");
	free_sip_msg(&msg);
	memset(&msg, 0, sizeof(msg));
	pop_pushed_global_context();
	if (set[3].s) pkg_free(set[3].s);

	set[3] = rewrite_claim(key, &tokens[2], 0, "iat", timestamp);
	if (set[3].s) {
		char *dot = memchr(set[3].s, '.', set[3].len);
		char *signature = memchr(dot+1, '.', set[3].len-(dot+1-set[3].s))+1;
		*signature = *signature == 'A' ? 'B' : 'A';
	}
	ok(set[3].s && chain_result(set, order, 4, cert, d.s, NULL) == -9,
		"a bad-signature extra Identity invalidates an otherwise valid chain");
	if (set[3].s) pkg_free(set[3].s);

	for (i = 0; i < 2; i++) {
		set[0] = rewrite_claim(key, &tokens[0], 0, "dest",
			i ? "{\"uri\":[\"urn:service:sos.police\"]}" : "{\"tn\":[\"911\"]}");
		built = passport_build_div(key, now, &x5u, &orig, i ? &emergency : &sos, &d);
		set[1] = built ? *built : STR_NULL;
		ok(set[0].s && set[1].s && chain_result(set, pair, 2, cert, d.s, NULL) == 1,
			"VS links emergency identities from %s to %s", i ? "SOS" : "911", i ? "911" : "SOS");
		if (set[0].s) pkg_free(set[0].s);
		if (set[1].s) pkg_free(set[1].s);
	}

	/* The receiving verifier must itself set the guard used by the signer. */
	memcpy(set, tokens, 3*sizeof(str));
	snprintf(timestamp, sizeof(timestamp), "%ld", (long)(now-600));
	set[2] = rewrite_claim(key, &tokens[2], 0, "iat", timestamp);
	push_new_global_context();
	n = set[2].s && make_message(&msg, buf, sizeof(buf), set, order, 3, d.s) == 0 &&
		verify_all(&msg, cert, 3) == 1 &&
		stir_shaken_verify_chain(&msg, NULL, NULL, NULL, NULL, NULL, NULL) == -6;
	ok(n && stir_shaken_test_auth_div(&msg, cert, keybuf, &x5u,
		NULL, NULL, &next, 1) == -4,
		"real VS outermost freshness failure blocks subsequent trusted AS signing");
	free_sip_msg(&msg);
	pop_pushed_global_context();
	if (set[2].s) pkg_free(set[2].s);

	/* Each call starts from the received chain, avoiding unchanged-target or
	 * generated-header side effects when testing integer boolean semantics. */
	for (i = 0; i < 3; i++) {
		int state = i == 0 ? -2 : i == 1 ? 2 : 42;
		memset(&msg, 0, sizeof(msg));
		push_new_global_context();
		n = make_message(&msg, buf, sizeof(buf), tokens, order, 3, d.s) == 0;
		ok(n && stir_shaken_test_auth_div(&msg, cert, keybuf, &x5u,
			NULL, NULL, &next, state) == 1,
			"previously_verified=%d is normalized to true", state);
		free_sip_msg(&msg);
		pop_pushed_global_context();
	}
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

	test_freshness_defaults();
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
	test_chain_edges(key, &cert, keybuf, tokens, now);
	test_credentials(tokens);
	test_verstat_policy(key, &cert, tokens, now);

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
