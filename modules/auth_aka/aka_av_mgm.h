/*
 * AKA Authentication - generic Authentication Manager support
 *
 * Copyright (C) 2024 Razvan Crainea
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
 */

#ifndef AKA_AV_MGM_H
#define AKA_AV_MGM_H

#include "../../str.h"
#include "../../lib/list.h"

#define AKA_AV_MGM_PREFIX "load_aka_av_"

/*
 * realm - the Realm of the authentication vector
 * impu - Public identity of the user
 * impi - Private identity of the user
 * resync - Resync/auts token, or NULL if not a resync request
 * algmask - Masks of algorithms to request
 * no - number of AVs for each algorithm
 * async - indicates whether the request is asynchronous or not
 */
typedef int (*aka_av_fetch_f)(str *realm, str *impu, str *impi, str *resync, int algmask, int no, int async);

struct aka_av_binds {
	aka_av_fetch_f fetch;
};

/*
 * Adds a new AV for a user
 *  - pub_id - Public Identity of the user
 *  - priv_id - Private identity of the user
 *  - algmask - Algorithm Mask this AV should be used for
 *  - authenticate - The authenticate string used in the digest
 *  - authorize - The authenticate string used in digest
 *  - ck - The Confidentiality key used in AKA
 *  - ik - The Integrity key used in AKA
 */
typedef int (*aka_av_add_f)(str *pub_id, str *priv_id, int algmask, str *authenticate,
		str *authorize, str *ck, str *ik);

/*
 * Drops one of the identities of the user, identified by the
 * nonce/authenticate string
 *  - pub_id - Public Identity of the user
 *  - priv_id - Private identity of the user
 *  - nonce - The authenticate string used in the digest
 */
typedef int (*aka_av_drop_f)(str *pub_id, str *priv_id, str *nonce);

/*
 * Drops all the identities of a user
 *  - pub_id - Public Identity of the user
 *  - priv_id - Private identity of the user
 */
typedef int (*aka_av_drop_all_f)(str *pub_id, str *priv_id);


typedef struct aka_av_api {
	aka_av_add_f add;
	aka_av_drop_f drop;
	aka_av_drop_all_f drop_all;
} aka_av_api;

typedef int (*aka_av_api_bind_f)(aka_av_api *api);

static inline int aka_av_bind_api(aka_av_api *api)
{
	aka_av_api_bind_f bind_f = (aka_av_api_bind_f)find_export("aka_av_api_bind", 0);
	if (!bind_f) {
		LM_INFO("could not find AKA AV API\n");
		return -1;
	}
	return bind_f(api);
}

#endif /* AKA_AV_MGM_H */
