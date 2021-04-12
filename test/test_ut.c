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

	ok(_is_e164(_str(""), 0) == -1, "test-e164-9");
	ok(_is_e164(_str("+"), 0) == -1, "test-e164-10");
	ok(_is_e164(_str("+1"), 0) == -1, "test-e164-11");
	ok(_is_e164(_str("12"), 0) == 1, "test-e164-12");
	ok(_is_e164(_str("+12"), 0) == 1, "test-e164-13");
	ok(_is_e164(_str("123"), 0) == 1, "test-e164-14");
	ok(_is_e164(_str("123456789012345"), 0) == 1, "test-e164-15");
	ok(_is_e164(_str("1234567890123456"), 0) == -1, "test-e164-16");
	ok(_is_e164(_str("+123456789012345"), 0) == 1, "test-e164-17");
	ok(_is_e164(_str("+1234567890123456"), 0) == -1, "test-e164-18");
	ok(_is_e164(_str("123456789x12345"), 0) == -1, "test-e164-19");
}
