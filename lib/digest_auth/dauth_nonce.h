/*
 * Nonce related functions
 *
 * Copyright (C) 2001-2003 FhG Fokus
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


#ifndef NONCE_H
#define NONCE_H

#include "../../str.h"
#include <time.h>

struct nonce_context {
        str_const secret; /* secret phrase used to generate nonce */
        int nonce_len;
};

struct nonce_params {
	struct timespec expires;
	int index;
	qop_type_t qop;
	alg_t alg;
};

/*
 * Calculate nonce value
 */
int calc_nonce(const struct nonce_context *ncp, char* _nonce,
    const struct nonce_params *npp);

/*
 * Decrypt nonce value
 */
int decr_nonce(const struct nonce_context *pub, const str_const * _n,
    struct nonce_params *npp);

/*
 * Check if the nonce is stale
 */
int is_nonce_stale(const struct nonce_params *npp, int nonce_expire);

struct nonce_context *dauth_noncer_new(void);
void dauth_noncer_dtor(struct nonce_context *);
int generate_random_secret(struct nonce_context *ncp);
int dauth_noncer_init(struct nonce_context *ncp);
void dauth_noncer_reseed(void);

#endif /* NONCE_H */
