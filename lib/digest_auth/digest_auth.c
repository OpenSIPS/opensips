/*
 * digest_auth library
 *
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

#include "../../parser/parse_authenticate.h"
#include "../../lib/csv.h"

#include "digest_auth.h"

int digest_algorithm_available(alg_t algorithm)
{
        switch (algorithm) {
        case ALG_UNSPEC:
        case ALG_MD5:
        case ALG_MD5SESS:
#if defined(SHA_256_ENABLE)
        case ALG_SHA256:
        case ALG_SHA256SESS:
#endif
#if defined(SHA_512_256_ENABLE)
        case ALG_SHA512_256:
        case ALG_SHA512_256SESS:
#endif
		return (1);

	default:
		break;
        }
        return (0);
}

int dauth_algorithm_check(const struct authenticate_body *auth,
    const struct match_auth_hf_desc *mdp)
{
	const struct dauth_algorithm_match *damp;

	if (!digest_algorithm_available(auth->algorithm))
		return (0);
	damp = (const struct dauth_algorithm_match *)mdp->argp;
	return (ALG2ALGFLG(auth->algorithm) & damp->algmask);
}

int dauth_fixup_algorithms(void** param)
{
	str *s = (str*)*param;
	alg_t af;
	int algflags = 0;
	csv_record *q_csv, *q;

	q_csv = parse_csv_record(s);
	if (!q_csv) {
		LM_ERR("Failed to parse list of algorithms\n");
		return -1;
	}
	for (q = q_csv; q; q = q->next) {
		af = parse_digest_algorithm(&q->s);
		if (!digest_algorithm_available(af)) {
			LM_ERR("Unsupported algorithm type: \"%.*s\"\n",
			    q->s.len, q->s.s);
			free_csv_record(q_csv);
			return (-1);
		}
		algflags |= ALG2ALGFLG(af);
	}
	free_csv_record(q_csv);

	*(intptr_t *)param = algflags;
	return (0);
}
