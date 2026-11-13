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
 */

/*
 * test_nats_ca_dir.c -- unit test for nats_load_ca_directory().
 *
 * Verifies:
 *   - Empty directory: returns NULL with a clear error
 *   - Missing directory: returns NULL with a clear error
 *   - NULL/empty input: returns NULL with a clear error
 *   - Single .pem: returns its content + trailing '\n'
 *   - Multiple .pem files: concatenated in lexicographic order
 *   - Non-.pem files in dir are skipped
 *   - Subdirectories named *.pem are skipped (not regular files)
 *
 * Build:
 *   make -C modules-contrib/nats/tests test_nats_ca_dir
 */

#define _GNU_SOURCE
#include <tap.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../nats_ca_dir.h"

#include "nats_ut.h"


#define ASSERT_TRUE(cond, label) ok((cond), "%s", (label))

#define ASSERT_NULL(ptr, label) ok((ptr) == NULL, "%s", (label))

#define ASSERT_NOT_NULL(ptr, label) ok((ptr) != NULL, "%s", (label))

#define ASSERT_STREQ(got, want, label) is((got), (want), "%s", (label))

/* Write a file under @dir with @name and @content.  Used to set up
 * the temporary CA dir for the multi-file tests. */
static int write_file(const char *dir, const char *name, const char *content)
{
	char path[512];
	FILE *f;
	snprintf(path, sizeof(path), "%s/%s", dir, name);
	f = fopen(path, "w");
	if (!f) return -1;
	fputs(content, f);
	fclose(f);
	return 0;
}

/* Make a fresh temp directory (mkdtemp) and return its path (caller
 * frees with free()). */
static char *make_tmpdir(void)
{
	char tmpl[] = "/tmp/test_nats_ca_dir.XXXXXX";
	char *d = mkdtemp(tmpl);
	return d ? strdup(d) : NULL;
}

/* Recursively rm -rf a directory.  Used for cleanup. */
static void rmrf(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	char path[512];
	if (!d) return;
	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
		struct stat st;
		if (stat(path, &st) == 0) {
			if (S_ISDIR(st.st_mode))
				rmrf(path);
			else
				unlink(path);
		}
	}
	closedir(d);
	rmdir(dir);
}

void nats_ut_nats_ca_dir(void)
{
	char *out;
	char *err;
	char *dir;


	/* NULL input rejected */
	err = NULL;
	out = nats_load_ca_directory(NULL, &err);
	ASSERT_NULL(out, "NULL dir returns NULL");
	ASSERT_NOT_NULL(err, "NULL dir sets error string");
	free(err);

	/* Empty string input rejected */
	err = NULL;
	out = nats_load_ca_directory("", &err);
	ASSERT_NULL(out, "empty dir string returns NULL");
	ASSERT_NOT_NULL(err, "empty dir string sets error");
	free(err);

	/* Missing directory rejected */
	err = NULL;
	out = nats_load_ca_directory("/nonexistent/path/that/cannot/exist", &err);
	ASSERT_NULL(out, "missing directory returns NULL");
	ASSERT_NOT_NULL(err, "missing directory sets error");
	free(err);

	/* Empty directory (no .pem files) rejected */
	dir = make_tmpdir();
	ASSERT_NOT_NULL(dir, "make_tmpdir succeeded for empty-dir test");
	if (dir) {
		err = NULL;
		out = nats_load_ca_directory(dir, &err);
		ASSERT_NULL(out, "empty dir returns NULL");
		ASSERT_NOT_NULL(err, "empty dir sets error");
		free(err);
		rmrf(dir);
		free(dir);
	}

	/* Directory with non-.pem files only — also rejected */
	dir = make_tmpdir();
	ASSERT_NOT_NULL(dir, "make_tmpdir for non-pem-only test");
	if (dir) {
		write_file(dir, "ca.crt", "not pem suffix");
		write_file(dir, "readme.txt", "ignore me");
		err = NULL;
		out = nats_load_ca_directory(dir, &err);
		ASSERT_NULL(out, "dir with no .pem files returns NULL");
		ASSERT_NOT_NULL(err, "dir with no .pem files sets error");
		free(err);
		rmrf(dir);
		free(dir);
	}

	/* Single .pem returns its content + trailing newline */
	dir = make_tmpdir();
	ASSERT_NOT_NULL(dir, "make_tmpdir for single-pem test");
	if (dir) {
		write_file(dir, "ca.pem", "PEM CONTENT 1");
		err = NULL;
		out = nats_load_ca_directory(dir, &err);
		ASSERT_NOT_NULL(out, "single .pem load succeeds");
		if (out) {
			ASSERT_STREQ(out, "PEM CONTENT 1\n",
			             "single .pem content + trailing newline");
			free(out);
		}
		free(err);
		rmrf(dir);
		free(dir);
	}

	/* Multiple .pem files concatenated in LEX order */
	dir = make_tmpdir();
	ASSERT_NOT_NULL(dir, "make_tmpdir for multi-pem test");
	if (dir) {
		/* Insert in non-lex order to catch sort bugs */
		write_file(dir, "zeta.pem", "ZZZ");
		write_file(dir, "alpha.pem", "AAA");
		write_file(dir, "middle.pem", "MMM");
		err = NULL;
		out = nats_load_ca_directory(dir, &err);
		ASSERT_NOT_NULL(out, "multi-pem load succeeds");
		if (out) {
			ASSERT_STREQ(out, "AAA\nMMM\nZZZ\n",
			             "multi-pem concatenated in lex order");
			free(out);
		}
		free(err);
		rmrf(dir);
		free(dir);
	}

	/* Non-.pem files mixed with .pem are skipped */
	dir = make_tmpdir();
	ASSERT_NOT_NULL(dir, "make_tmpdir for mixed-files test");
	if (dir) {
		write_file(dir, "a.pem", "ALPHA");
		write_file(dir, "ignore.txt", "should be skipped");
		write_file(dir, "b.pem", "BETA");
		write_file(dir, "README", "no extension, skip");
		err = NULL;
		out = nats_load_ca_directory(dir, &err);
		ASSERT_NOT_NULL(out, "mixed-files load succeeds");
		if (out) {
			ASSERT_STREQ(out, "ALPHA\nBETA\n",
			             "non-.pem files skipped, only .pem concatenated");
			free(out);
		}
		free(err);
		rmrf(dir);
		free(dir);
	}

	/* Subdirectory with .pem suffix is skipped (not a regular file) */
	dir = make_tmpdir();
	ASSERT_NOT_NULL(dir, "make_tmpdir for subdir-suffix test");
	if (dir) {
		char subdir[512];
		write_file(dir, "real.pem", "ACTUAL");
		snprintf(subdir, sizeof(subdir), "%s/decoy.pem", dir);
		mkdir(subdir, 0755);
		err = NULL;
		out = nats_load_ca_directory(dir, &err);
		ASSERT_NOT_NULL(out, "subdir-suffix load succeeds");
		if (out) {
			ASSERT_STREQ(out, "ACTUAL\n",
			             "subdir with .pem suffix is skipped");
			free(out);
		}
		free(err);
		rmrf(dir);
		free(dir);
	}
}
