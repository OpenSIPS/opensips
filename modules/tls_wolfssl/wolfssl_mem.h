/*
 * Copyright (C) 2023 OpenSIPS Foundation
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
 *
 *
 */

#ifndef WOLFSSL_MEM_H
#define WOLFSSL_MEM_H

/* XXX: include this file as soon as possible in your config file, to make
 * sure that all the functions that are acutally using the memory allocators
 * are properly used
 */

/* if we do not have DBG_MALLOC, we do not have the memory information
 * available, thus it makes no sense to use WOLFSSL_DEBUG_MEMORY */
#ifndef DBG_MALLOC
#undef WOLFSSL_DEBUG_MEMORY
#endif
#ifdef WOLFSSL_DEBUG_MEMORY
#define oss_wolfSSL_Free(_p) wolfSSL_Free(_p, NULL, DYNAMIC_TYPE_TMP_BUFFER)
#else
#define oss_wolfSSL_Free wolfSSL_Free
#endif

#endif	/* WOLFSSL_MEM_H */
