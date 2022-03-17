/*
 * Challenge related functions
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


#ifndef CHALLENGE_H
#define CHALLENGE_H

#include "../../parser/msg_parser.h"
#include "../../parser/digest/digest_parser.h"

#include "../../lib/digest_auth/dauth_nonce.h"

int fixup_qop(void** param);

/*
 * Challenge a user agent using WWW-Authenticate header field
 */
int www_challenge(struct sip_msg* _msg, str* _realm, void* _qop,
    intptr_t alg_flgs);


/*
 * Challenge a user agent using Proxy-Authenticate header field
 */
int proxy_challenge(struct sip_msg* _msg, str* _realm, void* _qop,
    intptr_t alg_flgs);


/*
 * Remove used credentials from a SIP message header
 */
int consume_credentials(struct sip_msg* _m, char* _s1, char* _s2);

/*
 * Build {WWW,Proxy}-Authenticate header field
 */
char *build_auth_hf(struct nonce_context *ncp, struct nonce_params *calc_np,
	int _stale, const str_const *_realm, int* _len,
    const str_const *alg_val, const str_const* _hf_name, const str_const *opaque);

#endif /* AUTH_H */
