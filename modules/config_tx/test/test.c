/*
 * Unit tests for config_tx immutable snapshot and diff primitives.
 *
 * Copyright (C) 2026 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int config_tx_test_replaceable_path(const char *path);
unsigned long long config_tx_test_hash(const char *text);
int config_tx_test_count_lines(const char *text);
int config_tx_test_first_changed_line(const char *left, const char *right);

static void test_replaceable_paths(void)
{
	char file[] = "/tmp/opensips-config-tx-file-XXXXXX";
	char link_path[256];
	int fd;

	fd = mkstemp(file);
	ok(fd >= 0, "config-tx-create-regular-fixture");
	if (fd < 0)
		return;
	close(fd);

	ok(config_tx_test_replaceable_path(file),
		"config-tx-regular-file-is-replaceable");

	snprintf(link_path, sizeof(link_path), "%s.link", file);
	unlink(link_path);
	ok(symlink(file, link_path) == 0,
		"config-tx-create-symlink-fixture");
	if (access(link_path, F_OK) == 0) {
		ok(!config_tx_test_replaceable_path(link_path),
			"config-tx-symlink-is-not-replaceable");
		unlink(link_path);
	}
	unlink(file);
}

static void test_hash(void)
{
	unsigned long long a = config_tx_test_hash("route { exit; }\n");
	unsigned long long b = config_tx_test_hash("route { exit; }\n");
	unsigned long long c = config_tx_test_hash("route { xlog(\"changed\"); }\n");

	ok(a != 0, "config-tx-hash-nonzero");
	ok(a == b, "config-tx-hash-stable");
	ok(a != c, "config-tx-hash-detects-change");
}

static void test_line_count(void)
{
	ok(config_tx_test_count_lines("") == 0,
		"config-tx-lines-empty");
	ok(config_tx_test_count_lines("one") == 1,
		"config-tx-lines-single");
	ok(config_tx_test_count_lines("one\ntwo") == 2,
		"config-tx-lines-two");
	ok(config_tx_test_count_lines("one\ntwo\n") == 2,
		"config-tx-lines-trailing-newline");
	ok(config_tx_test_count_lines("\n") == 1,
		"config-tx-lines-single-empty-line");
}

static void test_first_changed_line(void)
{
	ok(config_tx_test_first_changed_line(
		"a\nb\nc\n", "a\nb\nc\n") == 0,
		"config-tx-diff-identical");
	ok(config_tx_test_first_changed_line(
		"a\nb\nc\n", "a\nB\nc\n") == 2,
		"config-tx-diff-middle-line");
	ok(config_tx_test_first_changed_line(
		"a\nb\n", "a\nb\nc\n") == 3,
		"config-tx-diff-append-line");
	ok(config_tx_test_first_changed_line(
		"x\nb\n", "a\nb\n") == 1,
		"config-tx-diff-first-line");
}

void mod_tests(void)
{
	test_replaceable_paths();
	test_hash();
	test_line_count();
	test_first_changed_line();
}
