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
 * A map field lives at "_map.enc(map_key).enc(field)" and a map is listed
 * with the server-side filter "_map.enc(map_key).>": composing then
 * extracting (strip the filter prefix, decode the tail, as map_get does)
 * recovers the field byte-exact, and the format is disjoint from the
 * legacy "key:field" layout (no raw ':' in a composed key; neither
 * prefix matches the other).  On the real map_subject / nats_map_decode
 * through UNIT_TESTS wrappers (native.c); replaces tests/test_map_compose.c
 * (its carried codec + compose model and source greps).
 */

#include <tap.h>
#include <string.h>

#include "../../../str.h"

#include "cn_ut.h"

int cn_ut_map_decode(const char *in, int in_len, char *out, int out_size);
int cn_ut_map_subject(char *out, int out_size, const char *ns,
		const str *a, const char *b, int b_len, int wildcard);

/* the stored key of map @key field @field */
static int compose(const char *key, const char *field, char *out, int size)
{
	str k;

	k.s = (char *)key;
	k.len = (int)strlen(key);
	return cn_ut_map_subject(out, size, "_map", &k, field, (int)strlen(field), 0);
}

/* the map's list filter "_map.enc(key).>" without the ">" */
static int prefix(const char *key, char *out, int size)
{
	str k;
	int n;

	k.s = (char *)key;
	k.len = (int)strlen(key);
	n = cn_ut_map_subject(out, size, "_map", &k, NULL, 0, 1);
	if (n < 1 || out[n - 1] != '>')
		return -1;
	out[--n] = '\0';
	return n;
}

static void roundtrip(const char *key, const char *field, const char *label)
{
	char comp[512], pre[512], got[256];
	int cl = compose(key, field, comp, sizeof comp);
	int pl = prefix(key, pre, sizeof pre);
	int fl = -1;

	if (cl > 0 && pl > 0 && cl > pl && !strncmp(comp, pre, pl))
		fl = cn_ut_map_decode(comp + pl, cl - pl, got, sizeof got);
	ok(fl == (int)strlen(field) && !memcmp(got, field, fl),
		"map_compose: %s: field recovered byte-exact (%s)", label, comp);
	ok(cl > 0 && strchr(comp, ':') == NULL, "map_compose: %s: composed key has no raw ':'", label);
}

void cn_ut_map_compose(void)
{
	char comp[512], pre[512];
	int pl;

	roundtrip("usrloc", "alice", "plain");
	roundtrip("user.1@host", "x:y", "key with dot/@ + field with colon");
	roundtrip("m", "sub:field", "legacy-style subkey:pair field");
	roundtrip("a%b", "c=d", "percent + equals");
	roundtrip("k", "a\\b", "backslash in a field");

	compose("a.b", "c", comp, sizeof comp);
	pl = prefix("a.b", pre, sizeof pre);
	ok(pl > 0 && !strncmp(comp, pre, pl), "map_compose: new key starts with the map's filter prefix (%s)", pre);
	ok(strncmp("a.b:c", pre, pl) != 0, "map_compose: a legacy ':' key is not matched by the new prefix");
	ok(strncmp(comp, "a.b:", 4) != 0, "map_compose: the new key is not matched by the legacy 'key:' scan");
	ok(compose("", "c", comp, sizeof comp) < 0, "map_compose: an empty map key is refused");
	ok(compose("k", "", comp, sizeof comp) < 0, "map_compose: an empty field is refused");
}
