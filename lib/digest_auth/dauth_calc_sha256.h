/*
 * Copyright (C) 2020 Maksym Sobolyev
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

#ifndef _digest_auth_sha256_h
#define _digest_auth_sha256_h

#define HASHLEN_SHA256 32
#define HASHHEXLEN_SHA256 (HASHLEN_SHA256 * 2)

typedef char HASH_SHA256[HASHLEN_SHA256];
typedef char HASHHEX_SHA256[HASHHEXLEN_SHA256 + 1];

extern const struct digest_auth_calc sha256_digest_calc;
extern const struct digest_auth_calc sha256sess_digest_calc;

#endif /* _digest_auth_sha256_h */
