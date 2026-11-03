/*
 * Unit tests for media_qoe pure parsing and threshold logic.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <tap.h>

int media_qoe_test_sample_valid(long mos, long jitter, long packetloss,
	long roundtrip);
int media_qoe_test_parse_metric(const char *text, long *out);
int media_qoe_test_reason(long mos, long jitter, long packetloss,
	long roundtrip, int min_mos, int max_jitter,
	int max_packetloss, int max_roundtrip);

static void test_metric_parser(void)
{
	long value = -99;

	ok(media_qoe_test_parse_metric("35", &value) == 1 && value == 35,
		"media-qoe-parse-valid");
	ok(media_qoe_test_parse_metric("0", &value) == 1 && value == 0,
		"media-qoe-parse-zero");
	ok(media_qoe_test_parse_metric("null", &value) == 0 && value == -1,
		"media-qoe-parse-null");
	ok(media_qoe_test_parse_metric("N/A", &value) == 0 && value == -1,
		"media-qoe-parse-na-case-insensitive");
	ok(media_qoe_test_parse_metric("<null>", &value) == 0 && value == -1,
		"media-qoe-parse-printed-null-pvar");
	ok(media_qoe_test_parse_metric("", &value) == 0 && value == -1,
		"media-qoe-parse-empty-unavailable");
	ok(media_qoe_test_parse_metric(NULL, &value) == 0 && value == -1,
		"media-qoe-parse-missing-unavailable");
	ok(media_qoe_test_parse_metric("-1", &value) < 0,
		"media-qoe-reject-negative");
	ok(media_qoe_test_parse_metric("3.5", &value) < 0,
		"media-qoe-reject-non-integer");
	ok(media_qoe_test_parse_metric("35x", &value) < 0,
		"media-qoe-reject-trailing-garbage");
	ok(media_qoe_test_parse_metric(" 35", &value) < 0,
		"media-qoe-reject-leading-blank");
	ok(media_qoe_test_parse_metric("+35", &value) < 0,
		"media-qoe-reject-plus-sign");
	ok(media_qoe_test_parse_metric("99999999999999999999999", &value) < 0,
		"media-qoe-reject-overflow");
}

static void test_metric_ranges(void)
{
	ok(media_qoe_test_sample_valid(35, 20, 3, 50000),
		"media-qoe-valid-rtpengine-units");
	ok(media_qoe_test_sample_valid(-1, -1, -1, -1),
		"media-qoe-unavailable-values-allowed");
	ok(!media_qoe_test_sample_valid(51, 20, 3, 50000),
		"media-qoe-reject-mos-over-50");
	ok(!media_qoe_test_sample_valid(35, 20, 101, 50000),
		"media-qoe-reject-loss-over-100-percent");
}

static void test_thresholds(void)
{
	ok(media_qoe_test_reason(40, 10, 0, 20, 35, 50, 5, 100) == 0,
		"media-qoe-healthy-sample");
	ok(media_qoe_test_reason(34, 10, 0, 20, 35, 50, 5, 100) == 1,
		"media-qoe-mos-threshold");
	ok(media_qoe_test_reason(40, 51, 0, 20, 35, 50, 5, 100) == 2,
		"media-qoe-jitter-threshold");
	ok(media_qoe_test_reason(40, 10, 6, 20, 35, 50, 5, 100) == 3,
		"media-qoe-loss-threshold");
	ok(media_qoe_test_reason(40, 10, 0, 101, 35, 50, 5, 100) == 4,
		"media-qoe-rtt-threshold");
	ok(media_qoe_test_reason(-1, -1, -1, -1, 35, 50, 5, 100) == 0,
		"media-qoe-unavailable-values-do-not-degrade");
	ok(media_qoe_test_reason(1, 9999, 9999, 9999, -1, -1, -1, -1) == 0,
		"media-qoe-disabled-thresholds");
}

void mod_tests(void)
{
	test_metric_parser();
	test_metric_ranges();
	test_thresholds();
}
