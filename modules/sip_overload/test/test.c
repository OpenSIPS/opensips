/*
 * Unit tests for RFC 7339 / RFC 7415 parsing helpers.
 *
 * Copyright (C) 2026 OpenSIPS Project
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
#include <limits.h>

int sip_overload_test_parse_uint(const char *text, unsigned int *out);
int sip_overload_test_parse_seq(const char *text,
	unsigned long long *major, unsigned int *minor);
int sip_overload_test_seq_cmp(const char *left, const char *right);
int sip_overload_test_algo_list_has(const char *list, const char *algo);
int sip_overload_test_advertised_algo_list_valid(const char *list);

static void test_uint_parser(void)
{
	unsigned int value = 0;

	ok(sip_overload_test_parse_uint("0", &value) == 0 && value == 0,
		"sip-overload-uint-zero");
	ok(sip_overload_test_parse_uint("100", &value) == 0 && value == 100,
		"sip-overload-uint-valid");
	ok(sip_overload_test_parse_uint("4294967295", &value) == 0 &&
		value == UINT_MAX, "sip-overload-uint-max");
	ok(sip_overload_test_parse_uint("4294967296", &value) < 0,
		"sip-overload-uint-overflow");
	ok(sip_overload_test_parse_uint("-1", &value) < 0,
		"sip-overload-uint-negative");
	ok(sip_overload_test_parse_uint("1x", &value) < 0,
		"sip-overload-uint-garbage");
	ok(sip_overload_test_parse_uint("", &value) < 0,
		"sip-overload-uint-empty");
}

static void test_sequence_parser(void)
{
	unsigned long long major = 0;
	unsigned int minor = 0;

	ok(sip_overload_test_parse_seq("1.00001", &major, &minor) == 0 &&
		major == 1 && minor == 1, "sip-overload-seq-valid");
	ok(sip_overload_test_parse_seq("123456789012.99999", &major, &minor) == 0 &&
		major == 123456789012ULL && minor == 99999,
		"sip-overload-seq-max-shape");
	ok(sip_overload_test_parse_seq("1.000001", &major, &minor) < 0,
		"sip-overload-seq-minor-too-long");
	ok(sip_overload_test_parse_seq("1234567890123.1", &major, &minor) < 0,
		"sip-overload-seq-major-too-long");
	ok(sip_overload_test_parse_seq("1", &major, &minor) < 0,
		"sip-overload-seq-missing-dot");
	ok(sip_overload_test_parse_seq(".1", &major, &minor) < 0,
		"sip-overload-seq-missing-major");
	ok(sip_overload_test_parse_seq("1.", &major, &minor) < 0,
		"sip-overload-seq-missing-minor");
	ok(sip_overload_test_parse_seq("1.2.3", &major, &minor) < 0,
		"sip-overload-seq-multiple-dots");

	ok(sip_overload_test_seq_cmp("10.00001", "10.00001") == 0,
		"sip-overload-seq-equal");
	ok(sip_overload_test_seq_cmp("10.00002", "10.00001") > 0,
		"sip-overload-seq-newer-minor");
	ok(sip_overload_test_seq_cmp("11.00000", "10.99999") > 0,
		"sip-overload-seq-newer-major");
	ok(sip_overload_test_seq_cmp("9.99999", "10.00000") < 0,
		"sip-overload-seq-older-major");
}

static void test_advertised_algorithm_grammar(void)
{
	ok(sip_overload_test_advertised_algo_list_valid("loss"),
		"sip-overload-advertised-algo-single");
	ok(sip_overload_test_advertised_algo_list_valid("loss,rate"),
		"sip-overload-advertised-algo-list");
	ok(sip_overload_test_advertised_algo_list_valid("loss,abc123"),
		"sip-overload-advertised-algo-extension-token");
	ok(!sip_overload_test_advertised_algo_list_valid("loss,"),
		"sip-overload-advertised-algo-no-trailing-comma");
	ok(!sip_overload_test_advertised_algo_list_valid("loss,,rate"),
		"sip-overload-advertised-algo-no-empty-token");
	ok(!sip_overload_test_advertised_algo_list_valid("loss, rate"),
		"sip-overload-advertised-algo-no-whitespace");
	ok(!sip_overload_test_advertised_algo_list_valid("\"loss,rate\""),
		"sip-overload-advertised-algo-no-config-quotes");
	ok(!sip_overload_test_advertised_algo_list_valid("loss;oc=100"),
		"sip-overload-advertised-algo-no-via-injection");
	ok(!sip_overload_test_advertised_algo_list_valid("loss\r\nVia"),
		"sip-overload-advertised-algo-no-header-injection");
}

static void test_algorithm_list(void)
{
	ok(sip_overload_test_algo_list_has("loss,rate", "loss"),
		"sip-overload-algo-loss");
	ok(sip_overload_test_algo_list_has("loss,rate", "rate"),
		"sip-overload-algo-rate");
	ok(sip_overload_test_algo_list_has("\"loss, rate\"", "rate"),
		"sip-overload-algo-quoted-whitespace");
	ok(sip_overload_test_algo_list_has("LOSS,RATE", "loss"),
		"sip-overload-algo-case-insensitive");
	ok(!sip_overload_test_algo_list_has("rate", "loss"),
		"sip-overload-algo-missing-loss");
	ok(!sip_overload_test_algo_list_has("lossy,rate", "loss"),
		"sip-overload-algo-token-boundary");
}

void mod_tests(void)
{
	test_uint_parser();
	test_sequence_parser();
	test_advertised_algorithm_grammar();
	test_algorithm_list();
}
