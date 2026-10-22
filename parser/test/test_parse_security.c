/*
 * Copyright (C) 2026 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include <tap.h>

#include "../../str.h"
#include "../../ut.h"

#include "../../parser/parse_security.h"

#include "test_parse_security.h"

void test_parse_security(void)
{
	sec_agree_body_t *sa;

	sa = parse_sec_agree_body(_str("ipsec-3gpp;alg=hmac-sha-1-96;"
		"spi-c=1;spi-s=2;port-c=5062;port-s=5064"));
	ok(sa != NULL, "sec-agree-1");
	ok(sa && !sa->invalid && sa->mechanism == SEC_AGREE_MECHANISM_IPSEC_3GPP &&
		sa->ts3gpp.spi_c == 1 && sa->ts3gpp.spi_s == 2 &&
		sa->ts3gpp.port_c == 5062 && sa->ts3gpp.port_s == 5064, "sec-agree-2");
	free_sec_agree(&sa);

	/* a ',' right after an empty parameter list ends the body: the
	 * already linked mechanism must be returned, not freed */
	sa = parse_sec_agree_body(_str("tls;,"));
	ok(sa != NULL && sa->mechanism == SEC_AGREE_MECHANISM_TLS &&
		!sa->next, "sec-agree-3");
	free_sec_agree(&sa);

	/* same for a ',' right after a parameter name */
	sa = parse_sec_agree_body(_str("ipsec-3gpp;q=,"));
	ok(sa != NULL && sa->mechanism == SEC_AGREE_MECHANISM_IPSEC_3GPP &&
		!sa->next, "sec-agree-4");
	free_sec_agree(&sa);

	/* and after a parameter value */
	sa = parse_sec_agree_body(_str("ipsec-3gpp;spi-c=1,"));
	ok(sa != NULL && sa->mechanism == SEC_AGREE_MECHANISM_IPSEC_3GPP &&
		sa->ts3gpp.spi_c == 1 && !sa->next, "sec-agree-5");
	free_sec_agree(&sa);

	sa = parse_sec_agree_body(_str("tls;,digest"));
	ok(sa != NULL && sa->mechanism == SEC_AGREE_MECHANISM_TLS && sa->next &&
		sa->next->mechanism == SEC_AGREE_MECHANISM_DIGEST, "sec-agree-6");
	free_sec_agree(&sa);
}
