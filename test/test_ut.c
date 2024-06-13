/*
 * Copyright (C) 2021 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include <tap.h>

#include "../ut.h"

void test_ut(void)
{
	ok(is_e164(_str("")) == -1, "test-e164-0");
	ok(is_e164(_str("+")) == -1, "test-e164-1");
	ok(is_e164(_str("+1")) == -1, "test-e164-2");
	ok(is_e164(_str("12")) == -1, "test-e164-3");
	ok(is_e164(_str("+12")) == 1, "test-e164-4");
	ok(is_e164(_str("123")) == -1, "test-e164-5");
	ok(is_e164(_str("+123456789012345")) == 1, "test-e164-6");
	ok(is_e164(_str("+1234567890123456")) == -1, "test-e164-7");
	ok(is_e164(_str("+123456789x12345")) == -1, "test-e164-8");

	ok(_is_e164(_str(""), 0, 15) == -1, "test-e164-9");
	ok(_is_e164(_str("+"), 0, 15) == -1, "test-e164-10");
	ok(_is_e164(_str("+1"), 0, 15) == -1, "test-e164-11");
	ok(_is_e164(_str("12"), 0, 15) == 1, "test-e164-12");
	ok(_is_e164(_str("+12"), 0, 15) == 1, "test-e164-13");
	ok(_is_e164(_str("123"), 0, 15) == 1, "test-e164-14");
	ok(_is_e164(_str("123456789012345"), 0, 15) == 1, "test-e164-15");
	ok(_is_e164(_str("1234567890123456"), 0, 15) == -1, "test-e164-16");
	ok(_is_e164(_str("+123456789012345"), 0, 15) == 1, "test-e164-17");
	ok(_is_e164(_str("+1234567890123456"), 0, 15) == -1, "test-e164-18");
	ok(_is_e164(_str("123456789x12345"), 0, 15) == -1, "test-e164-19");

	/* str_strcasestr() tests */
	{
		struct {
			str a;
			str b;
			int ok_offset;
		} tests[] = {
			{str_init(""), str_init(""), -1},
			{str_init(""), str_init("x"), -1},
			{str_init("x"), str_init(""), -1},
			{str_init("x"), str_init("x"), 0},
			{str_init("xy"), str_init("x"), 0},
			{str_init("yx"), str_init("x"), 1},
			{str_init("yxy"), str_init("x"), 1},
			{str_init("foo"), str_init("bar"), -1},
			{str_init("foobar"), str_init("BAR"), 3},
			{str_init("fooBaRx"), str_init("bAr"), 3},
			{str_init("fbaRx"), str_init("bar"), 1},
			{str_init("barx"), str_init("Bar"), 0},
			{str_init("Bar"), str_init("baR"), 0},
			{str_init("foo"), str_init("foobar"), -1},
		};
		int i;

		for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
			char *p = str_strcasestr(&tests[i].a, &tests[i].b);
			if (tests[i].ok_offset < 0)
				ok(!p, "test-str_strcasestr-%d", i);
			else
				ok(p == (tests[i].a.s + tests[i].ok_offset), "test-str_strcasestr-%d", i);
		}
	}
}
