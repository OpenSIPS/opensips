/*
 * Digest credentials parser
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
 *
 * History:
 * -------
 * 2003-03-15: Duplicate algorithm in dig_cred_t removed (janakj)
 */



#ifndef DIGEST_PARSER_H
#define DIGEST_PARSER_H

#include "../../str.h"


/* Type of algorithm used */
typedef enum alg {
	ALG_UNSPEC = 0,   /* Algorithm parameter not specified */
	ALG_MD5 = 1,      /* MD5 - default value*/
	ALG_MD5SESS = 2,  /* MD5-Session */
	ALG_OTHER = 4     /* Unknown */
} alg_t;


/* Quality Of Protection used */
typedef enum qop_type {
	QOP_UNSPEC_D = 0,   /* QOP parameter not present in response */
	QOP_AUTH_D = 1,     /* Authentication only */
	QOP_AUTHINT_D = 2,  /* Authentication with integrity checks */
	QOP_OTHER_D = 4     /* Unknown */
} qop_type_t;


/* Algorithm structure */
struct algorithm {
	str alg_str;       /* The original string representation */
	alg_t alg_parsed;  /* Parsed value */
};


/* QOP structure */
struct qp {
	str qop_str;           /* The original string representation */
	qop_type_t qop_parsed; /* Parsed value */
};


/* Username structure */
struct username {
	str whole;        /* The whole username parameter value */
	str user;         /* username part only */
	str domain;       /* Domain part only */
};


/*
 * Parsed digest credentials
 */
typedef struct dig_cred {
	struct username username;   /* Username */
	str realm;                  /* Realm */
	str nonce;                  /* Nonce value */
	str uri;                    /* URI */
	str response;               /* Response string */
	struct algorithm alg;       /* Type of algorithm used */
	str cnonce;                 /* Cnonce value */
	str opaque;                 /* Opaque data string */
	struct qp qop;              /* Quality Of Protection */
	str nc;                     /* Nonce count parameter */
} dig_cred_t;


 /*
 * Macro to obtain the value of realm. The macro would first
 * check if there is any @domain part in the username and if
 * so, it will be returned as the value of realm. This hack is
 * ofter used to protect realm using the digest (username parameter
 * is protected by the response hash) and also to allow subscribers
 * to specify a different domain part than the one in realm parameter
 */
#define GET_REALM(cred)                                           \
    (((cred)->username.domain.len && (cred)->username.domain.s) ? \
     &(cred)->username.domain :                                   \
     &(cred)->realm)


/*
 * Initialize a digest credentials structure
 */
void init_dig_cred(dig_cred_t* _c);


/*
 * We support Digest authentication only
 *
 * Returns:
 *  0 - if everything is OK
 * -1 - Error while parsing
 *  1 - Unknown scheme
 */
int parse_digest_cred(str* _s, dig_cred_t* _c);


#endif /* DIGEST_PARSER_H */
