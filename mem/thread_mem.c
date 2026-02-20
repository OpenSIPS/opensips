/*
 * Copyright (C) 2026 OpenSIPS Solutions
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

/*
 * Thread memory wrappers mapped to libc allocators.
 */

#include <stdlib.h>

#include "mem.h"

#ifdef DBG_MALLOC
void *thread_malloc_dbg(size_t size, const char *file,
		const char *function, unsigned int line)
{
	(void)file;
	(void)function;
	(void)line;
	return malloc(size);
}

void *thread_realloc_dbg(void *ptr, size_t size, const char *file,
		const char *function, unsigned int line)
{
	(void)file;
	(void)function;
	(void)line;
	return realloc(ptr, size);
}

void thread_free_dbg(void *ptr, const char *file,
		const char *function, unsigned int line)
{
	(void)file;
	(void)function;
	(void)line;
	free(ptr);
}
#else
void *thread_malloc(size_t size)
{
	return malloc(size);
}

void *thread_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

void thread_free(void *ptr)
{
	free(ptr);
}
#endif
