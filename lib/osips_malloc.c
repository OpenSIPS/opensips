/*
 * OpenSIPS equivalent of the stdlib allocation functions
 *
 * Copyright (C) 2017 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#include <string.h>

#include "../mem/mem.h"
#include "../mem/shm_mem.h"

#include "osips_malloc.h"

/* PKG (fastest) */

void *osips_pkg_malloc(size_t size)
{
	return pkg_malloc(size);
}

void osips_pkg_free(void *ptr)
{
	pkg_free(ptr);
}

void *osips_pkg_calloc(size_t nmemb, size_t size)
{
	void *p;

	p = pkg_malloc(nmemb * size);
	if (p) {
		memset(p, '\0', nmemb * size);
	}

	return p;
}

void *osips_pkg_realloc(void *ptr, size_t size)
{
	return pkg_realloc(ptr, size);
}

char *osips_pkg_strdup(const char *s)
{
	char *rval;
	int len;

	len = strlen(s) + 1;
	rval = pkg_malloc(len);
	if (!rval) {
		return NULL;
	}

	memcpy(rval, s, len);
	return rval;
}

/* SHM */

void *osips_shm_malloc(size_t size)
{
	return shm_malloc(size);
}

void osips_shm_free(void *ptr)
{
	shm_free(ptr);
}

void *osips_shm_calloc(size_t nmemb, size_t size)
{
	void *p;

	p = shm_malloc(nmemb * size);
	if (p) {
		memset(p, '\0', nmemb * size);
	}

	return p;
}

void *osips_shm_realloc(void *ptr, size_t size)
{
	return shm_realloc(ptr, size);
}

char *osips_shm_strdup(const char *s)
{
	char *rval;
	int len;

	len = strlen(s) + 1;
	rval = shm_malloc(len);
	if (!rval) {
		return NULL;
	}

	memcpy(rval, s, len);
	return rval;
}
