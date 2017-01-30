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

#ifndef __OSIPS_MALLOC_H__
#define __OSIPS_MALLOC_H__

void *osips_pkg_malloc(size_t size);
void osips_pkg_free(void *ptr);
void *osips_pkg_calloc(size_t nmemb, size_t size);
void *osips_pkg_realloc(void *ptr, size_t size);
char *osips_pkg_strdup(const char *s);

void *osips_shm_malloc(size_t size);
void osips_shm_free(void *ptr);
void *osips_shm_calloc(size_t nmemb, size_t size);
void *osips_shm_realloc(void *ptr, size_t size);
char *osips_shm_strdup(const char *s);

#endif /* __OSIPS_MALLOC_H__ */
