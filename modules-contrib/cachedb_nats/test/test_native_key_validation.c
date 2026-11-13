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
 * Both components of a map subject are escaped (map_subject applies
 * nats_map_encode to the map key AND the field): whatever the bytes --
 * subject separators, wildcards, spaces, an embedded NUL -- the stored
 * key has exactly two raw '.' (the separators), no '*', '>' or space,
 * and stays a valid NATS KV key.  On the real map_subject through a
 * UNIT_TESTS wrapper (native.c); replaces
 * tests/test_native_key_validation.c (a source grep).
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

static int count(const char *s, int n, char c)
{
	int i, k = 0;

	for (i = 0; i < n; i++)
		if (s[i] == c)
			k++;
	return k;
}

void cn_ut_native_key_validation(void)
{
	char comp[512];
	int n;
	str k;

	n = compose("a.b*c>d e", "f.g*h>i j", comp, sizeof comp);
	ok(n > 0 && count(comp, n, '.') == 2, "native_key_validation: only the two separators are raw '.' (%s)", comp);
	ok(n > 0 && !strpbrk(comp, "*> "), "native_key_validation: no raw wildcard or space in either component");
	k.s = "x\0y";
	k.len = 3;
	n = cn_ut_map_subject(comp, sizeof comp, "_map", &k, "f\0g", 3, 0);
	ok(n > 0 && (int)strlen(comp) == n, "native_key_validation: an embedded NUL in either component is escaped (%s)", comp);
	n = compose("..", "..", comp, sizeof comp);
	ok(n > 0 && count(comp, n, '.') == 2, "native_key_validation: dot-only components cannot make an empty token");
	(void)prefix;
}
