/*
 * Unit tests for deterministic SIP OpenTelemetry correlation IDs.
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
#include <string.h>

int opentelemetry_test_transaction_id(const char *callid,
	const char *cseq, const char *branch, char out[33]);
int opentelemetry_test_dialog_id(const char *callid,
	const char *tag_a, const char *tag_b, char out[33]);

static void test_transaction_id(void)
{
	char a[33], b[33], c[33];

	ok(opentelemetry_test_transaction_id(
		"call-1", "1 INVITE", "z9hG4bK-a", a),
		"otel-transaction-id-built");
	ok(opentelemetry_test_transaction_id(
		"call-1", "1 INVITE", "z9hG4bK-a", b) &&
		!strcmp(a, b),
		"otel-transaction-id-stable");
	ok(opentelemetry_test_transaction_id(
		"call-1", "1 INVITE", "z9hG4bK-b", c) &&
		strcmp(a, c),
		"otel-transaction-id-branch-sensitive");
	ok(opentelemetry_test_transaction_id(
		"call-1", "2 INVITE", "z9hG4bK-a", c) &&
		strcmp(a, c),
		"otel-transaction-id-cseq-sensitive");
}

static void test_dialog_id(void)
{
	char ab[33], ba[33], other[33];

	ok(opentelemetry_test_dialog_id("call-1", "from-a", "to-b", ab),
		"otel-dialog-id-built");
	ok(opentelemetry_test_dialog_id("call-1", "to-b", "from-a", ba) &&
		!strcmp(ab, ba),
		"otel-dialog-id-direction-independent");
	ok(opentelemetry_test_dialog_id("call-1", "from-a", "to-c", other) &&
		strcmp(ab, other),
		"otel-dialog-id-tag-sensitive");
	ok(opentelemetry_test_dialog_id("call-2", "from-a", "to-b", other) &&
		strcmp(ab, other),
		"otel-dialog-id-callid-sensitive");
	ok(opentelemetry_test_dialog_id("call-1", "ab", "c", ab) &&
		opentelemetry_test_dialog_id("call-1", "a", "bc", other) &&
		strcmp(ab, other),
		"otel-dialog-id-unambiguous-split");
}

void mod_tests(void)
{
	test_transaction_id();
	test_dialog_id();
}
