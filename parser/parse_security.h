/*
 * Security-{Client,Server,Verify} header field body parser
 *
 * Copyright (c) 2024 OpenSIPS Solutions
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

#ifndef PARSE_SECURITY_H
#define PARSE_SECURITY_H

#include <stdio.h>

#include "hf.h"

typedef struct sec_agree_param {
	str name;
	str value;
	struct sec_agree_param *next;
} sec_agree_param_t;

typedef enum sec_agree_mechanism {
	SEC_AGREE_MECHANISM_OTHER,
	SEC_AGREE_MECHANISM_DIGEST,
	SEC_AGREE_MECHANISM_TLS,
	SEC_AGREE_MECHANISM_IPSEC_IKE,
	SEC_AGREE_MECHANISM_IPSEC_MAN,
	SEC_AGREE_MECHANISM_IPSEC_3GPP,
} sec_agree_mechanism_t;

typedef struct sec_agree_3gpp_body {
	/* 3GPP TS 33.203 */
	int pref;       /* preference (multiplied by 1000) */
	str pref_str;   /* preference str */
	str alg_str;    /* algorithm str */
	str prot_str;   /* protocol str */
	str mod_str;    /* mode str */
	str ealg_str;   /* encryption-algorithm str */
	str spi_c_str;  /* spi-c str */
	unsigned int spi_c;
	str spi_s_str;  /* spi-s str */
	unsigned int spi_s;
	str port_c_str; /* port-s str */
	unsigned short port_c;
	str port_s_str; /* port-c str */
	unsigned short port_s;
} sec_agree_3gpp_body_t;

typedef struct sec_agree_rfc3329_body {
	/* RFC 3329 */
	float preference;
	str preference_str;
	str algorithm_str;
	str qop_str;
	str verify_str;
} sec_agree_rfc3329_body_t, sec_agree_default_body_t;

typedef struct sec_agree_body {
	sec_agree_mechanism_t mechanism;
	str mechanism_str;
	union {
		sec_agree_3gpp_body_t ts3gpp;
		sec_agree_rfc3329_body_t rfc3329;
		sec_agree_default_body_t def;
	};
	sec_agree_param_t *params;
	struct sec_agree_body *next;
	int invalid;
} sec_agree_body_t;


/*
 * Parse Security-{Client,Server,Verify} header
 *
 * Return
 *      0: success, @_h->parsed was allocated and parsed
 *    < 0: otherwise
 */
int parse_sec_agree(struct hdr_field* _h);

/*
 * Parse Security-{Client,Server,Verify} header field body
 */
sec_agree_body_t *parse_sec_agree_body(str *body);

/*
 * Free all memory
 */
void free_sec_agree(sec_agree_body_t **_s);


#endif /* PARSE_SECURITY_H */
