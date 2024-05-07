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
#include "../str.h"
#include "../mod_fix.h"

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

	/* named flags -> output bitmask */
	{
		str f_names[] = {
			str_init("A"),
			str_init("B"),
			str_init("C"),
			str_init("D"),
			str_init("E"),
			STR_NULL
			};
		void *out = &str_init("B,D,E");

		ok(!fixup_named_flags(&out, f_names, NULL, NULL), "test-fixup-flags-0");
		ok((unsigned int)(unsigned long)out == (2|8|16), "test-fixup-flags-1");
	}

	/* named K/V flags -> output a list of values */
	{
		str kvf_names[] = {
			str_init("A"),
			str_init("B"),
			str_init("C"),
			str_init("D"),
			str_init("E"),
			STR_NULL
			};
		str kvf_values[sizeof(kvf_names)/sizeof(kvf_names[0])] = {};

		void *out = &str_init("A=X,C=YYY,E=ZZZZZZZZZ");
		ok(!fixup_named_flags(&out, NULL, kvf_names, kvf_values), "test-fixup-flags-2");

		/* Note: the @out no longer gets changed now */

		ok(str_match(&kvf_values[0], &str_init("X")), "test-fixup-flags-3.1");
		ok(str_match(&kvf_values[1], &STR_NULL), "test-fixup-flags-3.2");
		ok(str_match(&kvf_values[2], &str_init("YYY")), "test-fixup-flags-3.3");
		ok(str_match(&kvf_values[3], &STR_NULL), "test-fixup-flags-3.4");
		ok(str_match(&kvf_values[4], &str_init("ZZZZZZZZZ")), "test-fixup-flags-3.5");
		ok(str_match(&kvf_values[5], &STR_NULL), "test-fixup-flags-3.6");
	}

	/* combined flags test:
	 *  - named flags -> output bitmask
	 *  - named K/V flags -> output a list of values */
	{
		str f_names[] = {
			str_init("A"),
			str_init("B"),
			str_init("C"),
			str_init("D"),
			str_init("E"),
			STR_NULL
			};
		str kvf_names[] = {
			str_init("KA"),
			str_init("KB"),
			str_init("KC"),
			str_init("KD"),
			str_init("KE"),
			STR_NULL
			};
		str kvf_values[sizeof(kvf_names)/sizeof(kvf_names[0])] = {};

		void *out = &str_init("E,KB=X,D,A,KC=YYY,B,KE=ZZZZZZZZZ");
		ok(!fixup_named_flags(&out, f_names, kvf_names, kvf_values), "test-fixup-flags-4");
		ok((unsigned int)(unsigned long)out == (1|2|8|16), "test-fixup-flags-5");

		ok(str_match(&kvf_values[0], &STR_NULL), "test-fixup-flags-3.1");
		ok(str_match(&kvf_values[1], &str_init("X")), "test-fixup-flags-3.2");
		ok(str_match(&kvf_values[2], &str_init("YYY")), "test-fixup-flags-3.3");
		ok(str_match(&kvf_values[3], &STR_NULL), "test-fixup-flags-3.4");
		ok(str_match(&kvf_values[4], &str_init("ZZZZZZZZZ")), "test-fixup-flags-3.5");
		ok(str_match(&kvf_values[5], &STR_NULL), "test-fixup-flags-3.6");
	}

	/* str_strstr() tests */
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
			{str_init("foobar"), str_init("bar"), 3},
			{str_init("foobarx"), str_init("bar"), 3},
			{str_init("fbarx"), str_init("bar"), 1},
			{str_init("barx"), str_init("bar"), 0},
			{str_init("bar"), str_init("bar"), 0},
			{str_init("foo"), str_init("foobar"), -1},
		};
		int i;

		for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
			char *p = str_strstr(&tests[i].a, &tests[i].b);
			if (tests[i].ok_offset < 0)
				ok(!p, "test-str_strstr-%d", i);
			else
				ok(p == (tests[i].a.s + tests[i].ok_offset), "test-str_strstr-%d", i);
		}
	}
}
