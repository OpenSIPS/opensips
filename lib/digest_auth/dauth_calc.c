/*
 * Copyright (C) 2020 Maksym Sobolyev
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * Registrant OpenSIPS-module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "../../parser/digest/digest_parser.h"

#include "digest_auth.h"
#include "dauth_calc.h"

const struct digest_auth_calc* get_digest_calc(alg_t algorithm)
{
	const struct digest_auth_calc *digest_calc;

	switch (algorithm) {
	case ALG_UNSPEC:
	case ALG_MD5:
		digest_calc = &md5_digest_calc;
		break;

	case ALG_MD5SESS:
		digest_calc = &md5sess_digest_calc;
		break;

#if defined(SHA_256_ENABLE)
	case ALG_SHA256:
		digest_calc = &sha256_digest_calc;
		break;

	case ALG_SHA256SESS:
		digest_calc = &sha256sess_digest_calc;
		break;
#endif
#if defined(SHA_512_256_ENABLE)
	case ALG_SHA512_256:
		digest_calc = &sha512t256_digest_calc;
		break;

	case ALG_SHA512_256SESS:
		digest_calc = &sha512t256sess_digest_calc;
		break;
#endif

	default:
		digest_calc = NULL;
		break;
        }
	return (digest_calc);
}
