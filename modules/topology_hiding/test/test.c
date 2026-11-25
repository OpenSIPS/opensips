/*
 * Unit tests for topology_hiding Call-ID masking.
 *
 * Copyright (C) 2026 OpenSIPS Project
 */

#include <string.h>
#include <tap.h>

#include "../../../mem/mem.h"
#include "../../../parser/msg_parser.h"
#include "../topo_hiding_codec.h"
#include "../topo_hiding_logic.h"

static int only_alnum(const str *value)
{
	int i;

	for (i = 0; i < value->len; i++)
		if (!((value->s[i] >= 'A' && value->s[i] <= 'Z') ||
				(value->s[i] >= 'a' && value->s[i] <= 'z') ||
				(value->s[i] >= '0' && value->s[i] <= '9')))
			return 0;
	return 1;
}

static int contains_text(const str *value, const char *text)
{
	int text_len = strlen(text);
	int i;

	for (i = 0; i <= value->len - text_len; i++)
		if (!memcmp(value->s + i, text, text_len))
			return 1;
	return 0;
}

static void test_nist_ff1_vector(void)
{
	static const unsigned char key[] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};
	static const unsigned char plain[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
	static const unsigned char cipher[] = {2, 4, 3, 3, 4, 7, 7, 4, 8, 4};
	unsigned char result[sizeof(plain)];

	ok(th_callid_codec_test_ff1(key, 128, plain, sizeof(plain), 10,
			result, 0) == 0 && !memcmp(result, cipher, sizeof(cipher)),
		"FF1 matches NIST sample #1 encryption");
	ok(th_callid_codec_test_ff1(key, 128, cipher, sizeof(cipher), 10,
			result, 1) == 0 && !memcmp(result, plain, sizeof(plain)),
		"FF1 matches NIST sample #1 decryption");
}

static void test_codec_round_trips(void)
{
	static const char ff1_wire_fixture[] = "THAoUf1xHrYxj4QPqHP";
	str prefix = str_init("TH");
	str password = str_init("0123456789abcdef0123456789abcdef");
	str cases[] = {
		str_init("0123456789abcdef"),
		str_init("f81d4fae-7dec-11d0-a765-00a0c91e6bf6@biloxi.com"),
		str_init("A!%*_+`'~()<>:\\\"/[]?{}@z"),
		str_init("abc"),
		str_init("a"),
		str_init("non-compliant#call-id"),
	};
	str encoded = STR_NULL, decoded = STR_NULL;
	int i;

	ok(th_callid_codec_init(TH_CALLID_ENC_FF1_ALNUM62,
			&password, &prefix) == 0, "initialize ff1-alnum62 codec");
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		ok(th_callid_codec_encode(&cases[i], &encoded) == 0,
			"encode Call-ID case %d", i);
		if (i == 0)
			ok(encoded.s[prefix.len] == 'A', "select native radix-62 mode");
		else if (i == 1 || i == 2 || i == 3)
			ok(encoded.s[prefix.len] == 'B', "select structured word mode %d", i);
		else
			ok(encoded.s[prefix.len] == 'C', "select legacy fallback mode %d", i);
		ok(th_callid_codec_is_encoded(&encoded),
			"recognize encoded Call-ID case %d", i);
		if (i == 0)
			ok(encoded.len == sizeof(ff1_wire_fixture) - 1 &&
				!memcmp(encoded.s, ff1_wire_fixture,
					sizeof(ff1_wire_fixture) - 1),
				"FF1 KDF and wire representation remain stable");
		ok(th_callid_codec_decode(&encoded, &decoded) == 0 &&
				decoded.len == cases[i].len &&
				!memcmp(decoded.s, cases[i].s, cases[i].len),
			"round-trip Call-ID case %d", i);
		pkg_free(encoded.s);
		pkg_free(decoded.s);
		encoded = decoded = STR_NULL;
	}

	encoded = str_init("THZnot-a-codec-payload");
	ok(!th_callid_codec_is_encoded(&encoded), "reject an unknown wire marker");
	encoded = str_init("THCA");
	ok(th_callid_codec_decode(&encoded, &decoded) < 0,
		"reject a truncated legacy fallback payload");
}

static void test_word_domain_lengths(void)
{
	static const char symbols[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.!%*_+`'~()<>:\\\"/[]?{}";
	str prefix = str_init("TH");
	str password = str_init("0123456789abcdef0123456789abcdef");
	char input_buf[256];
	str input, encoded = STR_NULL, decoded = STR_NULL;
	int len, i, ok_all = 1;

	if (th_callid_codec_init(TH_CALLID_ENC_FF1_ALNUM62,
			&password, &prefix) < 0) {
		ok(0, "initialize exhaustive word-domain codec");
		return;
	}
	for (len = 1; len <= sizeof(input_buf); len++) {
		for (i = 0; i < len; i++)
			input_buf[i] = symbols[(i * 37 + len) % 85];
		if (len >= 3)
			input_buf[len / 2] = '@';
		input.s = input_buf;
		input.len = len;
		if (th_callid_codec_encode(&input, &encoded) < 0 ||
				th_callid_codec_decode(&encoded, &decoded) < 0 ||
				decoded.len != input.len ||
				memcmp(decoded.s, input.s, input.len)) {
			ok_all = 0;
			if (encoded.s) pkg_free(encoded.s);
			if (decoded.s) pkg_free(decoded.s);
			break;
		}
		pkg_free(encoded.s);
		pkg_free(decoded.s);
		encoded = decoded = STR_NULL;
	}
	ok(ok_all, "round-trip structured Call-IDs at every length from 1 to 256");
}

static void test_chain_growth(void)
{
	str prefix = str_init("TH");
	str password = str_init("0123456789abcdef0123456789abcdef");
	str original = str_init("f81d4fae-7dec-11d0-a765@biloxi.com");
	str current = original, next = STR_NULL;
	int first_len = 0, i;

	ok(th_callid_codec_init(TH_CALLID_ENC_FF1_ALNUM62,
			&password, &prefix) == 0, "initialize chain codec");
	for (i = 0; i < 10; i++) {
		ok(th_callid_codec_encode(&current, &next) == 0,
			"encode chain layer %d", i + 1);
		if (i == 0)
			first_len = next.len;
		else
			ok(next.len == first_len + i * (prefix.len + 1),
				"chain layer %d grows additively", i + 1);
		ok(only_alnum(&next), "chain layer %d is alphanumeric", i + 1);
		if (current.s != original.s)
			pkg_free(current.s);
		current = next;
		next = STR_NULL;
	}

	for (i = 0; i < 10; i++) {
		ok(th_callid_codec_decode(&current, &next) == 0,
			"decode chain layer %d", 10 - i);
		pkg_free(current.s);
		current = next;
		next = STR_NULL;
	}
	ok(current.len == original.len &&
		!memcmp(current.s, original.s, original.len),
		"ten-layer chain restores the original Call-ID");
	pkg_free(current.s);
}

static void test_malformed_payloads(void)
{
	str prefix = str_init("TH");
	str password = str_init("0123456789abcdef0123456789abcdef");
	char buffer[260];
	str encoded, decoded = STR_NULL;
	int len, i, rc, ok_all = 1;

	if (th_callid_codec_init(TH_CALLID_ENC_FF1_ALNUM62,
			&password, &prefix) < 0) {
		ok(0, "initialize malformed-payload codec");
		return;
	}
	memcpy(buffer, "TH", 2);
	for (len = 1; len <= 256; len++) {
		buffer[2] = "ABC"[len % 3];
		for (i = 0; i < len; i++)
			buffer[3 + i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
				[(i * 29 + len * 11) % 62];
		encoded.s = buffer;
		encoded.len = len + 3;
		rc = th_callid_codec_decode(&encoded, &decoded);
		if (rc == 0) {
			if (!decoded.s || decoded.len <= 0)
				ok_all = 0;
			pkg_free(decoded.s);
			decoded = STR_NULL;
		}
	}
	ok(ok_all, "handle malformed and wrong-key-like payloads through length 256");
}

static void test_raw_message_integration(void)
{
	static const char *requests[] = {
		"BYE sip:bob@example.com SIP/2.0",
		"INVITE sip:bob@example.com SIP/2.0",
	};
	static const char *methods[] = {"BYE", "INVITE"};
	str prefix = str_init("TH");
	str password = str_init("0123456789abcdef0123456789abcdef");
	char message[2048];
	char *encoded_buffer;
	str data;
	int len, i;

	ok(th_callid_codec_init(TH_CALLID_ENC_FF1_ALNUM62,
			&password, &prefix) == 0, "initialize raw-message codec");
	for (i = 0; i < 2; i++) {
		len = snprintf(message, sizeof(message),
			"%s\r\n"
			"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1\r\n"
			"From: <sip:alice@example.com>;tag=caller\r\n"
			"To: <sip:bob@example.com>;tag=callee\r\n"
			"Call-ID: raw-integration-1@example.com\r\n"
			"CSeq: 2 %s\r\n"
			"Content-Length: 0\r\n\r\n", requests[i], methods[i]);
		data.s = message;
		data.len = len;
		ok(th_test_encode_callid_raw(&data) == 0 &&
			contains_text(&data, "Call-ID: THB"),
			"encode raw in-dialog %s", methods[i]);
		encoded_buffer = data.s;
		ok(topo_callid_pre_raw(&data, NULL) == 0 &&
			contains_text(&data, "Call-ID: raw-integration-1@example.com"),
			"decode raw in-dialog %s", methods[i]);
		pkg_free(encoded_buffer);
		pkg_free(data.s);
	}

	len = snprintf(message, sizeof(message),
		"SIP/2.0 200 OK\r\n"
		"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1\r\n"
		"From: <sip:alice@example.com>;tag=caller\r\n"
		"To: <sip:bob@example.com>;tag=callee\r\n"
		"Call-ID: raw-integration-1@example.com\r\n"
		"CSeq: 2 BYE\r\n"
		"Content-Length: 0\r\n\r\n");
	data.s = message;
	data.len = len;
	ok(th_test_encode_callid_raw(&data) == 0 &&
		contains_text(&data, "Call-ID: THB"), "encode raw SIP reply");
	encoded_buffer = data.s;
	ok(topo_callid_pre_raw(&data, NULL) == 0 &&
		contains_text(&data, "Call-ID: raw-integration-1@example.com"),
		"decode raw SIP reply");
	pkg_free(encoded_buffer);
	pkg_free(data.s);

	/* Initial requests, including CANCEL, deliberately retain a peer's layer. */
	len = snprintf(message, sizeof(message),
		"CANCEL sip:bob@example.com SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1\r\n"
		"From: <sip:alice@example.com>;tag=caller\r\n"
		"To: <sip:bob@example.com>\r\n"
		"Call-ID: raw-integration-1@example.com\r\n"
		"CSeq: 1 CANCEL\r\n"
		"Content-Length: 0\r\n\r\n");
	data.s = message;
	data.len = len;
	ok(th_test_encode_callid_raw(&data) == 0, "encode raw CANCEL");
	encoded_buffer = data.s;
	ok(topo_callid_pre_raw(&data, NULL) == 0 && data.s == encoded_buffer &&
		contains_text(&data, "Call-ID: THB"),
		"preserve the encoded layer on initial-request CANCEL");
	pkg_free(encoded_buffer);
}

static void test_legacy_compatibility(void)
{
	static const char expected[] =
		"DLGCH_KUhUCmcvMTZiRwELMGRhYitASA9kf2V+f0AEXjBwYTZ5EgNYEys5PyAIDEAwJj0-";
	str prefix = str_init("DLGCH_");
	str password = str_init("OpenSIPS");
	str original = str_init("f81d4fae-7dec-11d0-a765-00a0c91e6bf6@biloxi.com");
	str encoded = STR_NULL, decoded = STR_NULL;

	ok(th_callid_codec_init(TH_CALLID_ENC_XOR_WORD64,
			&password, &prefix) == 0, "initialize legacy codec");
	ok(th_callid_codec_encode(&original, &encoded) == 0,
		"encode with legacy codec");
	ok(encoded.len == sizeof(expected) - 1 &&
		!memcmp(encoded.s, expected, sizeof(expected) - 1),
		"legacy output remains byte-identical");
	ok(th_callid_codec_decode(&encoded, &decoded) == 0 &&
		decoded.len == original.len &&
		!memcmp(decoded.s, original.s, original.len),
		"legacy codec remains reversible");
	pkg_free(encoded.s);
	pkg_free(decoded.s);
}

static int build_contact_message(struct sip_msg *msg, char *buffer, int size,
		const str *contact, struct socket_info *socket)
{
	int len;

	len = snprintf(buffer, size,
		"INVITE sip:bob@example.com SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1\r\n"
		"From: <sip:alice@example.com>;tag=1\r\n"
		"To: <sip:bob@example.com>\r\n"
		"Call-ID: contact-growth@example.com\r\n"
		"CSeq: 1 INVITE\r\n"
		"Contact: <%.*s>\r\n"
		"Content-Length: 0\r\n\r\n", contact->len, contact->s);
	if (len < 0 || len >= size)
		return -1;
	memset(msg, 0, sizeof(*msg));
	msg->buf = buffer;
	msg->len = len;
	if (parse_msg(buffer, len, msg) < 0 || parse_headers(msg, HDR_EOH_F, 0) < 0)
		return -1;
	msg->rcv.bind_address = socket;
	return 0;
}

static void test_contact_growth_reproduction(void)
{
	char message[8192], uri_buf[8192];
	char *suffix = NULL;
	str contact = str_init("sip:alice@192.0.2.10:5060");
	struct socket_info socket;
	struct sip_msg msg;
	int lengths[6] = {0};
	int suffix_len, previous_len, hop, over_255 = 0, ok_all = 1;

	memset(&socket, 0, sizeof(socket));
	socket.sock_str = str_init("127.0.0.1:5060");
	previous_len = contact.len;
	lengths[0] = contact.len;
	for (hop = 1; hop <= 5; hop++) {
		if (build_contact_message(&msg, message, sizeof(message), &contact,
				&socket) < 0 ||
				th_test_build_encoded_contact_suffix(&msg, &suffix_len, &suffix) < 0 ||
				suffix_len <= previous_len ||
				4 + socket.sock_str.len + suffix_len - 1 >= sizeof(uri_buf)) {
			ok_all = 0;
			free_sip_msg(&msg);
			break;
		}
		memcpy(uri_buf, "sip:", 4);
		memcpy(uri_buf + 4, socket.sock_str.s, socket.sock_str.len);
		memcpy(uri_buf + 4 + socket.sock_str.len, suffix, suffix_len - 1);
		contact.s = uri_buf;
		contact.len = 4 + socket.sock_str.len + suffix_len - 1;
		if (contact.len > 255 && !over_255)
			over_255 = hop;
		previous_len = contact.len;
		lengths[hop] = contact.len;
		pkg_free(suffix);
		suffix = NULL;
		free_sip_msg(&msg);
	}
	ok(ok_all && over_255 == 3,
		"no-dialog Contact nesting exceeds 255 characters within five hops");
	diag("Contact growth reproduction crossed 255 characters at hop %d", over_255);
	diag("Contact URI lengths by layer: %d, %d, %d, %d, %d, %d",
		lengths[0], lengths[1], lengths[2], lengths[3], lengths[4], lengths[5]);
	if (suffix)
		pkg_free(suffix);
}

void mod_tests(void)
{
	test_nist_ff1_vector();
	test_codec_round_trips();
	test_word_domain_lengths();
	test_chain_growth();
	test_malformed_payloads();
	test_raw_message_integration();
	test_legacy_compatibility();
	test_contact_growth_reproduction();
}
