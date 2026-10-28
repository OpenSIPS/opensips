/*
 * Copyright (C) 2025 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <tap.h>
#include <string.h>

#include "../../../dprint.h"
#include "../../../parser/msg_parser.h"
#include "../../../mem/mem.h"
#include "../rtpengine_bracket.h"
#include "../rtpengine.h"

/* Helper: collapse a bencode item to a string for comparison */
static int check_bencode(const char *input, int len, const char *expected,
		bencode_buffer_t *buf, int depth)
{
	bencode_item_t *result;
	char *enc;
	int enc_len;

	result = parse_bracket_value(input, len, buf, depth);
	if (!result)
		return expected == NULL; /* NULL expected means we expect failure */
	if (!expected)
		return 0; /* got result but expected failure */

	enc = bencode_collapse(result, &enc_len);
	if (!enc)
		return 0;

	return (enc_len == (int)strlen(expected) &&
			memcmp(enc, expected, enc_len) == 0);
}

static void test_bracket_lists(void)
{
	bencode_buffer_t buf;
	int t = 1;

	/* 1. Basic list: video message image */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-list-%d", t++);
	ok(check_bencode("video message image", 19,
			"l5:video7:message5:imagee", &buf, 0),
			"test-bracket-list-%d", t++);
	bencode_buffer_free(&buf);

	/* 2. Single-item list */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-list-%d", t++);
	ok(check_bencode("accept", 6,
			"l6:accepte", &buf, 0),
			"test-bracket-list-%d", t++);
	bencode_buffer_free(&buf);

	/* 3. Empty brackets -> empty list */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-list-%d", t++);
	ok(check_bencode("", 0,
			"le", &buf, 0),
			"test-bracket-list-%d", t++);
	bencode_buffer_free(&buf);

	/* 4. Multiple spaces between items */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-list-%d", t++);
	ok(check_bencode("a  b   c", 8,
			"l1:a1:b1:ce", &buf, 0),
			"test-bracket-list-%d", t++);
	bencode_buffer_free(&buf);

	/* 5. Leading/trailing spaces */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-list-%d", t++);
	ok(check_bencode("  a b  ", 7,
			"l1:a1:be", &buf, 0),
			"test-bracket-list-%d", t++);
	bencode_buffer_free(&buf);
}

static void test_bracket_dicts(void)
{
	bencode_buffer_t buf;
	int t = 1;

	/* 1. Basic dict: key1=val1 key2=val2 */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-dict-%d", t++);
	ok(check_bencode("key1=val1 key2=val2", 19,
			"d4:key14:val14:key24:val2e", &buf, 0),
			"test-bracket-dict-%d", t++);
	bencode_buffer_free(&buf);

	/* 2. Dict with nested list values: transcode=[PCMA PCMU] strip=[EVS] */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-dict-%d", t++);
	ok(check_bencode("transcode=[PCMA PCMU] strip=[EVS]", 33,
			"d9:transcodel4:PCMA4:PCMUe5:stripl3:EVSee", &buf, 0),
			"test-bracket-dict-%d", t++);
	bencode_buffer_free(&buf);

	/* 3. Nested dict: codec with nested lists */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-dict-%d", t++);
	ok(check_bencode("transcode=[PCMA PCMU] accept=[AMR-WB AMR] strip=[EVS]",
			53,
			"d9:transcodel4:PCMA4:PCMUe6:acceptl6:AMR-WB3:AMRe5:stripl3:EVSee",
			&buf, 0),
			"test-bracket-dict-%d", t++);
	bencode_buffer_free(&buf);
}

static void test_bracket_nested(void)
{
	bencode_buffer_t buf;
	int t = 1;

	/* 1. List containing nested list: [a [b c] d] */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-nested-%d", t++);
	ok(check_bencode("a [b c] d", 9,
			"l1:al1:b1:ce1:de", &buf, 0),
			"test-bracket-nested-%d", t++);
	bencode_buffer_free(&buf);

	/* 2. Nested empty brackets */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-nested-%d", t++);
	ok(check_bencode("[] []", 5,
			"lleleee", &buf, 0) ||
		check_bencode("[] []", 5,
			"llelee", &buf, 0),
			"test-bracket-nested-%d", t++);
	bencode_buffer_free(&buf);
}

static void test_bracket_security(void)
{
	bencode_buffer_t buf;
	int t = 1;

	/* 1. Exceeding max depth (9 levels of nesting) */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-security-%d", t++);
	ok(check_bencode("[[[[[[[[[x]]]]]]]]]", 19, NULL, &buf, 0),
			"test-bracket-security-%d", t++);
	bencode_buffer_free(&buf);

	/* 2. Exceeding max length */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-security-%d", t++);
	{
		char big[BRACKET_MAX_LEN + 100];
		memset(big, 'a', sizeof(big));
		big[sizeof(big) - 1] = '\0';
		ok(check_bencode(big, sizeof(big) - 1, NULL, &buf, 0),
				"test-bracket-security-%d", t++);
	}
	bencode_buffer_free(&buf);

	/* 3. Unmatched ] at start */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-security-%d", t++);
	ok(check_bencode("]", 1, NULL, &buf, 0),
			"test-bracket-security-%d", t++);
	bencode_buffer_free(&buf);

	/* 4. Unmatched [ only */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-security-%d", t++);
	ok(check_bencode("[", 1, NULL, &buf, 0),
			"test-bracket-security-%d", t++);
	bencode_buffer_free(&buf);

	/* 5. Empty key in dict context */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-security-%d", t++);
	ok(check_bencode("=val", 4, NULL, &buf, 0) ||
		/* empty key is skipped, result is empty dict */
		check_bencode("=val", 4, "de", &buf, 0),
			"test-bracket-security-%d", t++);
	bencode_buffer_free(&buf);

	/* 6. Empty value after = in dict */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-security-%d", t++);
	{
		/* key= with nothing after it - empty value is skipped */
		bencode_item_t *r = parse_bracket_value("key=", 4, &buf, 0);
		/* Either NULL or a dict with skipped empty value */
		ok(r == NULL || r->type == BENCODE_DICTIONARY,
				"test-bracket-security-%d", t++);
	}
	bencode_buffer_free(&buf);

	/* 7. NULL buf pointer */
	ok(parse_bracket_value("test", 4, NULL, 0) == NULL,
			"test-bracket-security-%d", t++);

	/* 8. Unmatched bracket inside dict value: key=[val */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-security-%d", t++);
	ok(check_bencode("key=[val", 8, NULL, &buf, 0),
			"test-bracket-security-%d", t++);
	bencode_buffer_free(&buf);

	/* 9. Nested empty brackets [[][]] */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-security-%d", t++);
	{
		bencode_item_t *r = parse_bracket_value("[] []", 5, &buf, 0);
		ok(r != NULL && r->type == BENCODE_LIST,
				"test-bracket-security-%d", t++);
	}
	bencode_buffer_free(&buf);
}

static void test_bracket_escapes(void)
{
	bencode_buffer_t buf;
	int t = 1;

	/* 1. Double-dash escapes to equals: fmtp:96..useinbandfec--1
	 *    '..' -> ' ', '--' -> '=' => "fmtp:96 useinbandfec=1" */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-escape-%d", t++);
	ok(check_bencode("fmtp:96..useinbandfec--1", 24,
			"l22:fmtp:96 useinbandfec=1e", &buf, 0),
			"test-bracket-escape-%d", t++);
	bencode_buffer_free(&buf);

	/* 2. Double-dot escapes to space: rtpmap:96..opus/48000/2
	 *    => "rtpmap:96 opus/48000/2" */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-escape-%d", t++);
	ok(check_bencode("rtpmap:96..opus/48000/2", 23,
			"l22:rtpmap:96 opus/48000/2e", &buf, 0),
			"test-bracket-escape-%d", t++);
	bencode_buffer_free(&buf);

	/* 3. No escapes - single dash/dot pass through unchanged */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-escape-%d", t++);
	ok(check_bencode("a-b c.d", 7,
			"l3:a-b3:c.de", &buf, 0),
			"test-bracket-escape-%d", t++);
	bencode_buffer_free(&buf);

	/* 4. Consecutive escapes: ---- becomes == */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-escape-%d", t++);
	ok(check_bencode("a----b", 6,
			"l4:a==be", &buf, 0),
			"test-bracket-escape-%d", t++);
	bencode_buffer_free(&buf);

	/* 5. Escape at end of token: foo-- becomes foo= */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-escape-%d", t++);
	ok(check_bencode("foo--", 5,
			"l4:foo=e", &buf, 0),
			"test-bracket-escape-%d", t++);
	bencode_buffer_free(&buf);

	/* 6. Escape in dict value: key=val--ue => key: "val=ue" */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-escape-%d", t++);
	ok(check_bencode("key=val--ue", 11,
			"d3:key6:val=uee", &buf, 0),
			"test-bracket-escape-%d", t++);
	bencode_buffer_free(&buf);

	/* 7. sdp-attr real-world case: add=[fmtp:96..useinbandfec--1] */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-escape-%d", t++);
	ok(check_bencode("add=[fmtp:96..useinbandfec--1]", 30,
			"d3:addl22:fmtp:96 useinbandfec=1ee", &buf, 0),
			"test-bracket-escape-%d", t++);
	bencode_buffer_free(&buf);

	/* 8. Mixed escape and no-escape tokens in a list */
	ok(bencode_buffer_init(&buf) == 0, "test-bracket-escape-%d", t++);
	ok(check_bencode("plain foo..bar baz--qux", 23,
			"l5:plain7:foo bar7:baz=quxe", &buf, 0),
			"test-bracket-escape-%d", t++);
	bencode_buffer_free(&buf);
}


/*
 * subscribe / publish: which tags the ng request carries.  A call leg's own
 * tag must never be sent as the subscriber or publisher tag, or rtpengine
 * rewires (or unsubscribes) that leg's media.
 */
#define PS_CALLER_TAG "caller-ft"
#define PS_CALLEE_TAG "callee-tt"
#define PS_SDP "v=0\r\no=- 1 1 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\n" \
	"t=0 0\r\nm=audio 20000 RTP/AVP 0\r\na=recvonly\r\n"

enum ps_msg_kind { PS_INITIAL_INVITE, PS_REINVITE, PS_200_OK };

static int ps_mk_msg(struct sip_msg *msg, enum ps_msg_kind kind)
{
	static char msgbuf[3][1024];
	char *b = msgbuf[kind];
	int len;

	if (kind == PS_200_OK)
		len = snprintf(b, sizeof msgbuf[0],
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP 192.0.2.4:5060;branch=z9hG4bKps1\r\n"
			"From: <sip:alice@example.org>;tag=" PS_CALLER_TAG "\r\n"
			"To: <sip:bob@example.org>;tag=" PS_CALLEE_TAG "\r\n"
			"Call-ID: ps-call-1\r\n"
			"CSeq: 1 INVITE\r\n"
			"Content-Length: 0\r\n\r\n");
	else
		len = snprintf(b, sizeof msgbuf[0],
			"INVITE sip:bob@example.org SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.0.2.4:5060;branch=z9hG4bKps1\r\n"
			"From: <sip:alice@example.org>;tag=" PS_CALLER_TAG "\r\n"
			"To: <sip:bob@example.org>%s\r\n"
			"Call-ID: ps-call-1\r\n"
			"CSeq: %d INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n",
			kind == PS_REINVITE ? ";tag=" PS_CALLEE_TAG : "",
			kind == PS_REINVITE ? 2 : 1);

	memset(msg, 0, sizeof *msg);
	msg->buf = b;
	msg->len = len;
	if (parse_msg(b, len, msg) != 0) {
		LM_ERR("failed to parse the test message\n");
		return -1;
	}
	return 0;
}

/* encoded "<len>:<s>" */
static const char *ps_bstr(const char *s, char *out, int outlen)
{
	snprintf(out, outlen, "%d:%s", (int)strlen(s), s);
	return out;
}

static int ps_has(const char *enc, int enc_len, const char *needle, int nlen)
{
	int i;

	for (i = 0; i + nlen <= enc_len; i++)
		if (!memcmp(enc + i, needle, nlen))
			return 1;
	return 0;
}

/* builds @cmd for @kind/@flags/@body; returns the encoded request, or NULL
 * if the module refused to build it; @buf must be freed by the caller when
 * the result is not NULL */
static char *ps_build(bencode_buffer_t *buf, enum ps_msg_kind kind,
		const char *cmd, const char *flags, int flags_len, const char *body,
		int *enc_len)
{
	struct sip_msg msg;
	bencode_item_t *dict;
	str f, b, *fp = NULL, *bp = NULL;
	char *enc;

	if (ps_mk_msg(&msg, kind) < 0)
		return NULL;
	if (flags) {
		f.s = (char *)flags;
		f.len = flags_len >= 0 ? flags_len : strlen(flags);
		fp = &f;
	}
	if (body) {
		b.s = (char *)body;
		b.len = strlen(body);
		bp = &b;
	}
	/* rtpe_test_build_request() initializes @buf */
	if (rtpe_test_build_request(buf, &msg, cmd, fp, bp, &dict) < 0) {
		free_sip_msg(&msg);
		return NULL;
	}
	enc = bencode_collapse(dict, enc_len);
	free_sip_msg(&msg);
	if (!enc)
		bencode_buffer_free(buf);
	return enc;
}

/* key present with exactly @val (NULL: key absent) */
static int ps_key(const char *enc, int enc_len, const char *key, const char *val)
{
	char k[512], v[512], kv[1024];

	ps_bstr(key, k, sizeof k);
	if (!val)
		return !ps_has(enc, enc_len, k, strlen(k));
	snprintf(kv, sizeof kv, "%s%s", k, ps_bstr(val, v, sizeof v));
	return ps_has(enc, enc_len, kv, strlen(kv));
}

#define PS_CASE(_kind, _cmd, _flags, _body, _desc, _checks) \
	do { \
		bencode_buffer_t _buf; \
		int enc_len; \
		char *enc = ps_build(&_buf, _kind, _cmd, _flags, -1, _body, &enc_len); \
		ok(enc != NULL, "pubsub: %s: request built", _desc); \
		if (enc) { \
			_checks; \
			bencode_buffer_free(&_buf); \
		} \
	} while (0)

#define PS_REFUSED(_kind, _cmd, _flags, _flags_len, _desc) \
	do { \
		bencode_buffer_t _buf; \
		int enc_len; \
		char *enc = ps_build(&_buf, _kind, _cmd, _flags, _flags_len, PS_SDP, &enc_len); \
		ok(enc == NULL, "pubsub: %s: refused", _desc); \
		if (enc) \
			bencode_buffer_free(&_buf); \
	} while (0)

static void test_pubsub_tags(void)
{
	char long_tag[301], long_flags[320];

	/* subscribe request: to-tag only when given (rtpengine generates it) */
	PS_CASE(PS_200_OK, "subscribe request", "from-tag=" PS_CALLEE_TAG, NULL,
		"subscribe request from a reply, from-tag given", {
		ok(ps_key(enc, enc_len, "command", "subscribe request"), "pubsub: command is subscribe request");
		ok(ps_key(enc, enc_len, "from-tag", PS_CALLEE_TAG), "pubsub: from-tag is the given source");
		ok(ps_key(enc, enc_len, "to-tag", NULL), "pubsub: no leg tag sent as the subscriber tag");
	});
	PS_CASE(PS_200_OK, "subscribe request", "all", NULL,
		"subscribe request from a reply, all", {
		ok(ps_key(enc, enc_len, "to-tag", NULL), "pubsub: all: no to-tag");
		ok(ps_key(enc, enc_len, "from-tag", NULL), "pubsub: all: no from-tag (all selects the sources)");
	});
	PS_CASE(PS_REINVITE, "subscribe request", NULL, NULL,
		"subscribe request from a re-INVITE, no flags", {
		ok(ps_key(enc, enc_len, "from-tag", PS_CALLER_TAG), "pubsub: default source is the From tag");
		ok(ps_key(enc, enc_len, "to-tag", NULL), "pubsub: callee tag not sent as the subscriber tag");
		ok(ps_key(enc, enc_len, "call-id", "ps-call-1"), "pubsub: call-id from the message");
		ok(ps_key(enc, enc_len, "sdp", NULL), "pubsub: subscribe request carries no sdp");
	});
	PS_CASE(PS_INITIAL_INVITE, "subscribe request", "from-tags=[a b]", NULL,
		"subscribe request, from-tags list", {
		ok(ps_key(enc, enc_len, "from-tag", NULL), "pubsub: from-tags: no single from-tag");
		ok(ps_has(enc, enc_len, "9:from-tagsl1:a1:be", 19), "pubsub: from-tags sent as a list");
	});
	PS_CASE(PS_INITIAL_INVITE, "subscribe request", "label=caller", NULL,
		"subscribe request, label", {
		ok(ps_key(enc, enc_len, "from-tag", NULL), "pubsub: label: no from-tag");
		ok(ps_key(enc, enc_len, "label", "caller"), "pubsub: label passed through");
	});
	PS_CASE(PS_200_OK, "subscribe request", "to-tag=sub-1 from-tag=src-1", NULL,
		"subscribe request, both tags given", {
		ok(ps_key(enc, enc_len, "to-tag", "sub-1"), "pubsub: given subscriber tag kept");
		ok(ps_key(enc, enc_len, "from-tag", "src-1"), "pubsub: given source tag kept");
	});
	PS_CASE(PS_INITIAL_INVITE, "subscribe request", "no-from-tag call-id=other-call", NULL,
		"subscribe request, no-from-tag + call-id", {
		ok(ps_key(enc, enc_len, "from-tag", NULL), "pubsub: no-from-tag honoured");
		ok(ps_key(enc, enc_len, "call-id", "other-call"), "pubsub: call-id flag overrides the message");
	});

	/* subscribe answer: needs the subscription's to-tag, never swapped */
	PS_CASE(PS_200_OK, "subscribe answer", "to-tag=sub-1", PS_SDP,
		"subscribe answer from a reply", {
		ok(ps_key(enc, enc_len, "to-tag", "sub-1"), "pubsub: subscribe answer keeps the given to-tag");
		ok(ps_key(enc, enc_len, "from-tag", NULL), "pubsub: subscribe answer sends no leg tag");
		ok(ps_key(enc, enc_len, "sdp", PS_SDP), "pubsub: subscribe answer carries the sdp");
	});
	PS_CASE(PS_REINVITE, "subscribe answer", "to-tag=sub-1", PS_SDP,
		"subscribe answer from a request", {
		ok(ps_key(enc, enc_len, "to-tag", "sub-1"), "pubsub: request: given to-tag kept");
		ok(ps_key(enc, enc_len, "from-tag", NULL), "pubsub: request: no leg tag");
	});
	PS_REFUSED(PS_REINVITE, "subscribe answer", NULL, -1, "subscribe answer without to-tag");
	PS_REFUSED(PS_200_OK, "subscribe answer", "to-tag=", -1, "subscribe answer with an empty to-tag");
	PS_REFUSED(PS_200_OK, "subscribe answer", "   ", -1, "subscribe answer with blank flags");

	/* unsubscribe: same rule */
	PS_CASE(PS_200_OK, "unsubscribe", "to-tag=sub-1", NULL, "unsubscribe from a reply", {
		ok(ps_key(enc, enc_len, "to-tag", "sub-1"), "pubsub: unsubscribe keeps the given to-tag");
		ok(ps_key(enc, enc_len, "from-tag", NULL), "pubsub: unsubscribe sends no leg tag");
	});
	PS_REFUSED(PS_REINVITE, "unsubscribe", NULL, -1, "unsubscribe without to-tag");
	PS_REFUSED(PS_REINVITE, "unsubscribe", "from-tag=x", -1, "unsubscribe with from-tag only");

	/* publish: the publisher is from-tag (default: the From tag), no to-tag */
	PS_CASE(PS_INITIAL_INVITE, "publish", NULL, PS_SDP, "publish from an initial INVITE", {
		ok(ps_key(enc, enc_len, "command", "publish"), "pubsub: command is publish");
		ok(ps_key(enc, enc_len, "from-tag", PS_CALLER_TAG), "pubsub: publisher defaults to the From tag");
		ok(ps_key(enc, enc_len, "to-tag", NULL), "pubsub: publish sends no to-tag");
		ok(ps_key(enc, enc_len, "sdp", PS_SDP), "pubsub: publish carries the sdp");
	});
	PS_CASE(PS_REINVITE, "publish", NULL, PS_SDP, "publish from a re-INVITE", {
		ok(ps_key(enc, enc_len, "to-tag", NULL), "pubsub: re-INVITE: callee tag not sent");
	});
	PS_CASE(PS_200_OK, "publish", "from-tag=pub-1", PS_SDP, "publish from a reply", {
		ok(ps_key(enc, enc_len, "from-tag", "pub-1"), "pubsub: reply: given publisher tag kept");
		ok(ps_key(enc, enc_len, "to-tag", NULL), "pubsub: reply: no to-tag");
	});

	/* offer/answer/delete are unchanged */
	PS_CASE(PS_INITIAL_INVITE, "offer", NULL, PS_SDP, "offer from an INVITE (regression)", {
		ok(ps_key(enc, enc_len, "from-tag", PS_CALLER_TAG), "pubsub: offer from-tag");
		ok(ps_key(enc, enc_len, "to-tag", NULL), "pubsub: offer no to-tag");
	});
	PS_CASE(PS_200_OK, "answer", NULL, PS_SDP, "answer from a 200 OK (regression)", {
		ok(ps_key(enc, enc_len, "from-tag", PS_CALLER_TAG), "pubsub: answer from-tag");
		ok(ps_key(enc, enc_len, "to-tag", PS_CALLEE_TAG), "pubsub: answer to-tag");
	});
	PS_CASE(PS_200_OK, "delete", NULL, NULL, "delete from a reply (regression)", {
		ok(ps_key(enc, enc_len, "from-tag", PS_CALLER_TAG), "pubsub: delete from-tag");
		ok(ps_key(enc, enc_len, "to-tag", NULL), "pubsub: delete no to-tag");
	});

	/* adversarial tag values are passed through byte-exact */
	PS_CASE(PS_200_OK, "subscribe answer", "to-tag=a\\b", PS_SDP, "backslash in a tag", {
		ok(ps_key(enc, enc_len, "to-tag", "a\\b"), "pubsub: backslash kept");
	});
	PS_CASE(PS_200_OK, "unsubscribe", "to-tag=x;y\"z", NULL, "quote and semicolon in a tag", {
		ok(ps_key(enc, enc_len, "to-tag", "x;y\"z"), "pubsub: quote and semicolon kept");
	});
	memset(long_tag, 'T', 300);
	long_tag[300] = 0;
	snprintf(long_flags, sizeof long_flags, "to-tag=%s", long_tag);
	PS_CASE(PS_200_OK, "unsubscribe", long_flags, NULL, "300-byte tag", {
		ok(ps_key(enc, enc_len, "to-tag", long_tag), "pubsub: long tag kept");
	});
	{
		/* flags end at an embedded NUL */
		static const char nul_flags[] = "to-tag=sub-1\0 from-tag=hidden";
		bencode_buffer_t buf;
		int enc_len;
		char *enc = ps_build(&buf, PS_200_OK, "subscribe answer", nul_flags,
			sizeof nul_flags - 1, PS_SDP, &enc_len);
		ok(enc != NULL, "pubsub: embedded NUL: request built");
		if (enc) {
			ok(ps_key(enc, enc_len, "to-tag", "sub-1"), "pubsub: embedded NUL: to-tag before it kept");
			ok(!ps_has(enc, enc_len, "hidden", 6), "pubsub: embedded NUL: flags after it ignored");
			bencode_buffer_free(&buf);
		}
	}
	PS_REFUSED(PS_INITIAL_INVITE, "subscribe request", "from-tags=[a", -1, "unbalanced bracket");
	PS_REFUSED(PS_REINVITE, "unsubscribe", "", 0, "empty flags");
}

/* building a request, and freeing it or having it refused, must return all
 * of its pkg memory */
static void test_pubsub_no_leak(void)
{
#ifdef PKG_MALLOC
	unsigned long before;
	int i;

	/* first round outside the measurement */
	PS_CASE(PS_200_OK, "subscribe answer", "to-tag=sub-1", PS_SDP,
		"leak check warm-up", {});

	before = PKG_GET_USED();
	for (i = 0; i < 10; i++) {
		PS_CASE(PS_200_OK, "subscribe answer", "to-tag=sub-1", PS_SDP,
			"leak check", {});
		/* refused after the flags were copied and parsed */
		PS_REFUSED(PS_REINVITE, "unsubscribe", "from-tag=x", -1, "leak check");
	}
	ok(PKG_GET_USED() == before,
		"pubsub: 10 built and 10 refused requests leave pkg usage unchanged "
		"(%lu -> %lu)", before, (unsigned long)PKG_GET_USED());
#endif
}

void mod_tests(void)
{
	test_pubsub_tags();
	test_pubsub_no_leak();
	test_bracket_lists();
	test_bracket_dicts();
	test_bracket_nested();
	test_bracket_security();
	test_bracket_escapes();
}
