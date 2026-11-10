/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * The usrloc row-key encoder must be
 * injective, round-trippable, produce only NATS-KV-safe *and token-valid*
 * subjects, and the PK path must REJECT (not silently drop) AoRs that would
 * encode to an invalid subject.
 *
 * Guards beyond the existing test_kv_key_encode.c (=HH round-trip):
 *   1. backslash '\\' must be ESCAPED (was in the safe set -> violated
 *      the project's mandatory backslash-adversarial rule).
 *   2. '.' and '/' stay literal (valid multi-token subjects; keeps
 *      `nats kv` greppability) BUT a key with an EMPTY subject token
 *      (leading '.', trailing '.', or '..') is REJECTED by cdbn_kv_key_validate()
 *      before any kvStore_* call -- else JetStream rejects it and the REGISTER
 *      is silently lost (remote DoS / per-user poisoning).
 *   3. injectivity over an adversarial corpus; decode(encode(x)) == x for all
 *      byte strings incl. embedded NUL, '@', '=', empty.
 *
 * On the real cdbn_kv_encode_key / cdbn_kv_key_validate; the =HH decoder
 * below is the test's oracle (production never decodes).  Added: the PK
 * fast path's inlined encoder (cdbn_pk_target_key) must agree with
 * cdbn_kv_encode_key byte for byte, or a PK read misses the row a save wrote.
 */

#include <tap.h>
#include <string.h>

#include "../../../mem/mem.h"
#include "../cachedb_nats_json_internal.h"

#include "cn_ut.h"

/* round-trip decoder for the =HH scheme */
static int _hexv(int c)
{
	if (c>='0'&&c<='9') return c-'0';
	if (c>='A'&&c<='F') return c-'A'+10;
	if (c>='a'&&c<='f') return c-'a'+10;
	return -1;
}
static char *_kv_decode_key(const char *in, int in_len, int *out_len)
{
	char *out = pkg_malloc(in_len + 1);
	int i = 0, w = 0;
	if (!out) return NULL;
	while (i < in_len) {
		if (in[i] == '=' && i + 2 < in_len) {
			int hi = _hexv((unsigned char)in[i+1]), lo = _hexv((unsigned char)in[i+2]);
			if (hi < 0 || lo < 0) { out[w++] = in[i++]; continue; }
			out[w++] = (char)((hi << 4) | lo); i += 3;
		} else out[w++] = in[i++];
	}
	out[w] = '\0';
	if (out_len) *out_len = w;
	return out;
}

#define CHECK(cond, msg) ok((cond), "kv_key_validate: %s", (msg))

static int enc_has(const char *in, const char *needle)
{
	int el; char *e = cdbn_kv_encode_key(in, (int)strlen(in), &el);
	int r = e && strstr(e, needle) != NULL; if (e) pkg_free(e); return r;
}
static int roundtrips(const char *in, int len)
{
	int el, dl; char *e = cdbn_kv_encode_key(in, len, &el);
	char *d = e ? _kv_decode_key(e, el, &dl) : NULL;
	int good = e && d && dl == len && memcmp(d, in, len) == 0;
	if (e) pkg_free(e);
	if (d) pkg_free(d);
	return good;
}
static int validate_aor(const char *aor)
{
	int el; char *e = cdbn_kv_encode_key(aor, (int)strlen(aor), &el);
	int r = e ? cdbn_kv_key_validate(e, el) : -2; if (e) pkg_free(e); return r;
}

/* the PK path's inlined encoder against the row-key encoder */
static int pk_matches_encoder(const char *in, int len)
{
	extern char *fts_json_prefix;
	char stackbuf[64], *pk;
	int heap = 0, el, plen, good;
	char *e = cdbn_kv_encode_key(in, len, &el);

	pk = cdbn_pk_target_key(in, len, stackbuf, sizeof stackbuf, &heap);
	plen = (fts_json_prefix && *fts_json_prefix) ? (int)strlen(fts_json_prefix) : 0;
	good = e && pk && (int)strlen(pk) == plen + el &&
		memcmp(pk, fts_json_prefix, plen) == 0 && memcmp(pk + plen, e, el) == 0;
	if (e) pkg_free(e);
	if (pk && heap) pkg_free(pk);
	return good;
}

void cn_ut_kv_key_validate(void)
{
	diag("backslash is escaped:");
	CHECK(enc_has("a\\b", "=5C"), "'\\\\' -> =5C (escaped, not literal)");

	diag("reserved/separator handling:");
	CHECK(enc_has("a@b", "=40"), "'@' -> =40");
	CHECK(enc_has("a=b", "=3D"), "'=' -> =3D (self-escape, injective)");
	CHECK(enc_has("a*b", "=2A") && enc_has("a>b", "=3E") && enc_has("a b", "=20"),
	      "'*','>',' ' escaped (no wildcard/space injection)");
	CHECK(!enc_has("alice.example.com", "=2E"), "'.' stays literal (greppable multi-token)");

	diag("PK-path token validation (reject empty tokens):");
	CHECK(validate_aor("sip:a..b@d") == -1,  "double-dot 'a..b' rejected");
	CHECK(validate_aor(".alice@d")   == -1,  "leading-dot rejected");
	CHECK(validate_aor("alice.")     == -1,  "trailing-dot rejected");
	CHECK(validate_aor("")           == -1,  "empty AoR rejected");
	CHECK(validate_aor("alice@example.com") == 0, "normal AoR accepted");
	CHECK(validate_aor("alice.smith@example.com") == 0, "dotted user/host accepted");

	diag("injectivity + round-trip (incl. NUL/empty):");
	const char *corpus[] = { "alice@example.com", "a..b", ".x", "x.", "a=b",
	                         "a/b\\c", "weird user", " unicode@domain", "" };
	int n = sizeof(corpus)/sizeof(corpus[0]), k, j, collisions = 0;
	for (k = 0; k < n; k++)
		CHECK(roundtrips(corpus[k], (int)strlen(corpus[k])), corpus[k][0]?corpus[k]:"<empty>");
	{ const char nulstr[] = {'a','\0','b'}; CHECK(roundtrips(nulstr, 3), "embedded NUL round-trips"); }
	for (k = 0; k < n; k++) for (j = k+1; j < n; j++) {
		int al,bl; char *a=cdbn_kv_encode_key(corpus[k],(int)strlen(corpus[k]),&al);
		char *b=cdbn_kv_encode_key(corpus[j],(int)strlen(corpus[j]),&bl);
		if (a && b && al==bl && memcmp(a,b,al)==0) collisions++;
		if (a) pkg_free(a);
		if (b) pkg_free(b);
	}
	ok(collisions == 0, "kv_key_validate: no collisions across corpus (%d)", collisions);

	diag("the PK target key encodes like the row key:");
	for (k = 0; k < n; k++)
		CHECK(pk_matches_encoder(corpus[k], (int)strlen(corpus[k])),
			corpus[k][0] ? corpus[k] : "<empty>");
	{ const char nulstr[] = {'a','\0','b'}; CHECK(pk_matches_encoder(nulstr, 3), "embedded NUL (PK)"); }
	{
		/* past the 64-byte stack buffer: the heap branch */
		char lng[80]; memset(lng, '@', sizeof lng);
		CHECK(pk_matches_encoder(lng, sizeof lng), "80 x '@' (heap branch)");
	}

}
