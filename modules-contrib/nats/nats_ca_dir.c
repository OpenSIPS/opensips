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
 * nats_ca_dir.c -- libc-only PEM-directory concatenation.
 * See nats_ca_dir.h for the contract and rationale.
 */

#define _DEFAULT_SOURCE   /* readdir, struct dirent */
#define _GNU_SOURCE       /* asprintf */

#include <dirent.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "nats_ca_dir.h"

/* Helper: set *err if non-NULL.  Always uses vasprintf so caller
 * frees with libc free().  Silent if err is NULL or vasprintf fails
 * (best-effort diagnostic). */
static void set_err(char **err, const char *fmt, ...)
{
	va_list ap;
	if (!err)
		return;
	*err = NULL;
	va_start(ap, fmt);
	if (vasprintf(err, fmt, ap) < 0)
		*err = NULL;
	va_end(ap);
}

char *nats_load_ca_directory(const char *dir, char **err)
{
	DIR *d = NULL;
	struct dirent *e;
	char path[1024];
	char **pem_files = NULL;
	int    pem_cnt = 0, pem_cap = 0;
	int    i;
	char  *out = NULL;
	char  *p;
	size_t total = 0;

	if (err) *err = NULL;

	if (!dir || !*dir) {
		set_err(err, "NULL or empty directory path");
		return NULL;
	}

	d = opendir(dir);
	if (!d) {
		set_err(err, "opendir('%s') failed", dir);
		return NULL;
	}

	/* Pass 1: collect .pem filenames so we can sort them. */
	while ((e = readdir(d))) {
		size_t nlen = strlen(e->d_name);
		if (nlen < 5 || strcmp(e->d_name + nlen - 4, ".pem") != 0)
			continue;
		if (pem_cnt == pem_cap) {
			int    newcap = pem_cap ? pem_cap * 2 : 8;
			char **next = realloc(pem_files,
			                      newcap * sizeof(*pem_files));
			if (!next) {
				set_err(err, "realloc(pem_files, %zu) failed",
				        newcap * sizeof(*pem_files));
				goto fail;
			}
			pem_files = next;
			pem_cap   = newcap;
		}
		pem_files[pem_cnt] = strdup(e->d_name);
		if (!pem_files[pem_cnt]) {
			set_err(err, "strdup('%s') failed", e->d_name);
			goto fail;
		}
		pem_cnt++;
	}
	closedir(d);
	d = NULL;

	if (pem_cnt == 0) {
		set_err(err, "no .pem files in directory '%s'", dir);
		goto fail;
	}

	/* Sort lexicographically (insertion sort -- N is tiny in
	 * practice, typically 1-10 CA files). */
	for (i = 1; i < pem_cnt; i++) {
		int j;
		char *cur = pem_files[i];
		for (j = i; j > 0 && strcmp(pem_files[j-1], cur) > 0; j--)
			pem_files[j] = pem_files[j-1];
		pem_files[j] = cur;
	}

	/* Pass 2: sum file sizes for the output allocation. */
	for (i = 0; i < pem_cnt; i++) {
		struct stat st;
		int pn = snprintf(path, sizeof(path), "%s/%s", dir, pem_files[i]);
		/* A truncated path would stat a different (or nonexistent) file;
		 * skip it in both passes so the size sum and the concat agree. */
		if (pn < 0 || pn >= (int)sizeof(path))
			continue;
		if (stat(path, &st) != 0) {
			set_err(err, "stat('%s') failed", path);
			goto fail;
		}
		if (!S_ISREG(st.st_mode))
			continue;
		total += (size_t)st.st_size + 1; /* +1 for newline separator */
	}
	if (total == 0) {
		set_err(err, "directory '%s' has no regular .pem files", dir);
		goto fail;
	}

	out = malloc(total + 1);
	if (!out) {
		set_err(err, "malloc(%zu) for concat buffer failed", total + 1);
		goto fail;
	}
	p = out;

	/* Pass 3: read + concatenate.  Every write is bounded by the
	 * budget computed in pass 2 (`out` holds `total` payload bytes + a
	 * trailing NUL): a .pem that GREW between the two stat() passes
	 * (TOCTOU) must never overflow `out`.  A file that SHRANK is
	 * tolerated -- we copy whatever fread returns and move on rather
	 * than failing on a "short read", since the file legitimately
	 * changed under us. */
	for (i = 0; i < pem_cnt; i++) {
		FILE  *f;
		struct stat st;
		size_t got;
		size_t avail;     /* bytes left in `out`, excluding final NUL */
		size_t budget;    /* max payload bytes we may read this file */
		int pn = snprintf(path, sizeof(path), "%s/%s", dir, pem_files[i]);
		if (pn < 0 || pn >= (int)sizeof(path))
			continue;     /* truncated path skipped in pass 2 too */
		if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
			continue;
		avail = (size_t)(total - (size_t)(p - out));
		if (avail <= 1)
			break;            /* no room left for data + separator */
		budget = avail - 1;   /* reserve 1 byte for the '\n' separator */
		if ((size_t)st.st_size < budget)
			budget = (size_t)st.st_size;
		f = fopen(path, "rb");
		if (!f) {
			set_err(err, "fopen('%s') failed", path);
			free(out);
			out = NULL;
			goto fail;
		}
		got = fread(p, 1, budget, f);
		fclose(f);
		p += got;
		*p++ = '\n';   /* separator between files */
	}
	*p = '\0';

	for (i = 0; i < pem_cnt; i++)
		free(pem_files[i]);
	free(pem_files);
	return out;

fail:
	if (d) closedir(d);
	if (pem_files) {
		for (i = 0; i < pem_cnt; i++)
			free(pem_files[i]);
		free(pem_files);
	}
	return NULL;
}
