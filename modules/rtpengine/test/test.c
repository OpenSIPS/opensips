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
#include "../rtpengine_bracket.h"

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

void mod_tests(void)
{
	test_bracket_lists();
	test_bracket_dicts();
	test_bracket_nested();
	test_bracket_security();
	test_bracket_escapes();
}
