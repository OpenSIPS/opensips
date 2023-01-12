/*
 * Copyright (C) 2019 OpenSIPS Solutions
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

#ifndef func_mem_h
#define func_mem_h

#ifdef DBG_MALLOC
typedef void *(*osips_malloc_f) (unsigned long size,
                      const char *file, const char *func, unsigned int line);
typedef void *(*osips_realloc_f) (void *ptr, unsigned long size,
                      const char *file, const char *func, unsigned int line);
typedef void (*osips_free_f) (void *ptr,
                      const char *file, const char *func, unsigned int line);
#define func_malloc(_func, _size) (_func)(_size, \
		__FILE__, __FUNCTION__, __LINE__ )
#define func_realloc(_func, _ptr, _size) (_func)(_ptr, _size, \
		__FILE__, __FUNCTION__, __LINE__ )
#define func_free(_func, _ptr) (_func)(_ptr, \
		__FILE__, __FUNCTION__, __LINE__ )
#else
typedef void *(*osips_malloc_f) (unsigned long size);
typedef void *(*osips_realloc_f) (void *ptr, unsigned long size);
typedef void (*osips_free_f) (void *ptr);
#define func_malloc(_func, _size) (_func)(_size)
#define func_realloc(_func, _ptr, _size) (_func)(_ptr, _size)
#define func_free(_func, _ptr) (_func)(_ptr)
#endif

#endif
