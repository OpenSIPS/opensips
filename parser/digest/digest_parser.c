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
 * --------
 * 2003-03-02: Added parse_domain function (janakj)
 */



#include "digest_parser.h"
#include "../../lib/dassert.h"
#include "../../trim.h"    /* trim_leading */
#include "../../lib/turbocompare.h" /* turbo_casematch */
#include "param_parser.h"  /* Digest parameter name parser */
#include "../../ut.h"      /* q_memchr */


#define DIGEST_SCHEME "digest"
#define DIG_LEN 6

#define QOP_AUTH_STR_LEN (sizeof(QOP_AUTH_STR) - 1)
#define QOP_AUTHINT_STR_LEN (sizeof(QOP_AUTHINT_STR) - 1)

#define ALG_MD5_STR_LEN (sizeof(ALG_MD5_STR) - 1)
#define ALG_MD5SESS_STR_LEN (sizeof(ALG_MD5SESS_STR) - 1)
#define ALG_SHA256_STR_LEN (sizeof(ALG_SHA256_STR) - 1)
#define ALG_SHA256SESS_STR_LEN (sizeof(ALG_SHA256SESS_STR) - 1)
#define ALG_SHA512_256_STR_LEN (sizeof(ALG_SHA512_256_STR) - 1)
#define ALG_SHA512_256SESS_STR_LEN (sizeof(ALG_SHA512_256SESS_STR) - 1)
#define ALG_AKAv1_MD5_STR_LEN (sizeof(ALG_AKAv1_MD5_STR) - 1)
#define ALG_AKAv1_MD5SESS_STR_LEN (sizeof(ALG_AKAv1_MD5SESS_STR) - 1)
#define ALG_AKAv1_SHA256_STR_LEN (sizeof(ALG_AKAv1_SHA256_STR) - 1)
#define ALG_AKAv1_SHA256SESS_STR_LEN (sizeof(ALG_AKAv1_SHA256SESS_STR) - 1)
#define ALG_AKAv1_SHA512_256_STR_LEN (sizeof(ALG_AKAv1_SHA512_256_STR) - 1)
#define ALG_AKAv1_SHA512_256SESS_STR_LEN (sizeof(ALG_AKAv1_SHA512_256SESS_STR) - 1)
#define ALG_AKAv2_MD5_STR_LEN (sizeof(ALG_AKAv2_MD5_STR) - 1)
#define ALG_AKAv2_MD5SESS_STR_LEN (sizeof(ALG_AKAv2_MD5SESS_STR) - 1)
#define ALG_AKAv2_SHA256_STR_LEN (sizeof(ALG_AKAv2_SHA256_STR) - 1)
#define ALG_AKAv2_SHA256SESS_STR_LEN (sizeof(ALG_AKAv2_SHA256SESS_STR) - 1)
#define ALG_AKAv2_SHA512_256_STR_LEN (sizeof(ALG_AKAv2_SHA512_256_STR) - 1)
#define ALG_AKAv2_SHA512_256SESS_STR_LEN (sizeof(ALG_AKAv2_SHA512_256SESS_STR) - 1)

/*
 * Parse quoted string in a parameter body
 * return the string without quotes in _r
 * parameter and update _s to point behind the
 * closing quote
 */
static inline int parse_quoted(str* _s, str* _r)
{
	char* end_quote;

	     /* The string must have at least
	      * surrounding quotes
	      */
	if (_s->len < 2) {
		return -1;
	}

	     /* Skip opening quote */
	_s->s++;
	_s->len--;


	     /* Find closing quote */
	end_quote = q_memchr(_s->s, '\"', _s->len);

	     /* Not found, return error */
	if (!end_quote) {
		return -2;
	}

	     /* Let _r point to the string without
	      * surrounding quotes
	      */
	_r->s = _s->s;
	_r->len = end_quote - _s->s;

	     /* Update _s parameter to point
	      * behind the closing quote
	      */
	_s->len -= (end_quote - _s->s + 1);
	_s->s = end_quote + 1;

	     /* Everything went OK */
	return 0;
}


/*
 * Parse unquoted token in a parameter body
 * let _r point to the token and update _s
 * to point right behind the token
 */
static inline int parse_token(str* _s, str* _r)
{
	int i;

	     /* Save the beginning of the
	      * token in _r->s
	      */
	_r->s = _s->s;

	     /* Iterate through the
	      * token body
	      */
	for(i = 0; i < _s->len; i++) {

		     /* All LWS characters + ','
		      * mark end of the token
		      */
		if (is_ws(_s->s[i]) || _s->s[i] == ',') {
			     /* So if you find
			      * any of them
			      * stop iterating
			      */
			goto out;
		}
	}
 out:
	     /* Empty token is error */
	if (i == 0) {
	        return -2;
	}

	     /* Save length of the token */
        _r->len = i;

	     /* Update _s parameter so it points
	      * right behind the end of the token
	      */
	_s->s = _s->s + i;
	_s->len -= i;

	     /* Everything went OK */
	return 0;
}


/*
 * Parse a digest parameter
 */
static inline int parse_digest_param(str* _s, dig_cred_t* _c)
{
	dig_par_t t;
	str* ptr;
	str dummy;

	     /* Get type of the parameter */
	if (parse_param_name(_s, &t) < 0) {
		return -1;
	}

	_s->s++;  /* skip = */
	_s->len--;

	     /* Find the beginning of body */
	trim_leading(_s);

	if (_s->len == 0) {
		return -2;
	}

	     /* Decide in which attribute the
	      * body content will be stored
	      */
	switch(t) {
	case PAR_USERNAME:  ptr = &_c->username.whole;  break;
	case PAR_REALM:     ptr = &_c->realm;           break;
	case PAR_NONCE:     ptr = &_c->nonce;           break;
	case PAR_URI:       ptr = &_c->uri;             break;
	case PAR_RESPONSE:  ptr = &_c->response;        break;
	case PAR_CNONCE:    ptr = &_c->cnonce;          break;
	case PAR_OPAQUE:    ptr = &_c->opaque;          break;
	case PAR_QOP:       ptr = &_c->qop.qop_str;     break;
	case PAR_NC:        ptr = &_c->nc;              break;
	case PAR_ALGORITHM: ptr = &_c->alg.alg_str;     break;
	case PAR_AUTS:      ptr = &_c->auts;            break;
	case PAR_OTHER:     ptr = &dummy;               break;
	default:            ptr = &dummy;               break;
	}

	     /* If the first character is quote, it is
	      * a quoted string, otherwise it is a token
	      */
	if (_s->s[0] == '\"') {
		if (parse_quoted(_s, ptr) < 0) {
			return -3;
		}
	} else {
		if (parse_token(_s, ptr) < 0) {
			return -4;
		}
	}

	return 0;
}


/*
 * Parse qop parameter body
 */
static inline void parse_qop(struct qp* _q)
{
	str s;

	s.s = _q->qop_str.s;
	s.len = _q->qop_str.len;

	trim(&s);

	if (turbo_strcasematch(&s, QOP_AUTH_STR, QOP_AUTH_STR_LEN)) {
		_q->qop_parsed = QOP_AUTH_D;
	} else if (turbo_strcasematch(&s, QOP_AUTHINT_STR, QOP_AUTHINT_STR_LEN)) {
		_q->qop_parsed = QOP_AUTHINT_D;
	} else {
		_q->qop_parsed = QOP_OTHER_D;
	}
}

#define CASE_ALG(alg, sptr) \
	case ALG_##alg##_STR_LEN: \
		if (turbo_casematch((sptr)->s, ALG_##alg##_STR, (sptr)->len)) \
			return ALG_##alg; \
		break;

#define CASE_ALG2(alg1, alg2, sptr) \
	case ALG_##alg1##_STR_LEN: \
		if (turbo_casematch((sptr)->s, ALG_##alg1##_STR, (sptr)->len)) \
			return ALG_##alg1; \
		if (turbo_casematch((sptr)->s, ALG_##alg2##_STR, (sptr)->len)) \
			return ALG_##alg2; \
		break;

/*
 * Parse algorithm parameter body
 */
alg_t parse_digest_algorithm(const str *sp)
{

	switch (sp->len) {
	CASE_ALG(MD5, sp);
	CASE_ALG(MD5SESS, sp);
	CASE_ALG(SHA256, sp);
	CASE_ALG(SHA256SESS, sp);
	CASE_ALG(SHA512_256, sp);
	CASE_ALG(SHA512_256SESS, sp);
	CASE_ALG2(AKAv1_MD5, AKAv2_MD5, sp);
	CASE_ALG2(AKAv1_MD5SESS, AKAv2_MD5SESS, sp);
	CASE_ALG2(AKAv1_SHA256, AKAv2_SHA256, sp);
	CASE_ALG2(AKAv1_SHA256SESS, AKAv2_SHA256SESS, sp);
	CASE_ALG2(AKAv1_SHA512_256, AKAv2_SHA512_256, sp);
	CASE_ALG2(AKAv1_SHA512_256SESS, AKAv2_SHA512_256SESS, sp);
	default:
		break;
	}
	return ALG_OTHER;
}

const str *print_digest_algorithm(alg_t alg)
{
	switch (alg) {
	case ALG_MD5:
		return _str(ALG_MD5_STR);
	case ALG_MD5SESS:
		return _str(ALG_MD5SESS_STR);
	case ALG_SHA256:
		return _str(ALG_SHA256_STR);
	case ALG_SHA256SESS:
		return _str(ALG_SHA256SESS_STR);
	case ALG_SHA512_256:
		return _str(ALG_SHA512_256_STR);
	case ALG_SHA512_256SESS:
		return _str(ALG_SHA512_256SESS_STR);
	case ALG_AKAv1_MD5:
		return _str(ALG_AKAv1_MD5_STR);
	case ALG_AKAv1_MD5SESS:
		return _str(ALG_AKAv1_MD5SESS_STR);
	case ALG_AKAv1_SHA256:
		return _str(ALG_AKAv1_SHA256_STR);
	case ALG_AKAv1_SHA256SESS:
		return _str(ALG_AKAv1_SHA256SESS_STR);
	case ALG_AKAv1_SHA512_256:
		return _str(ALG_AKAv1_SHA512_256_STR);
	case ALG_AKAv1_SHA512_256SESS:
		return _str(ALG_AKAv1_SHA512_256SESS_STR);
	case ALG_AKAv2_MD5:
		return _str(ALG_AKAv2_MD5_STR);
	case ALG_AKAv2_MD5SESS:
		return _str(ALG_AKAv2_MD5SESS_STR);
	case ALG_AKAv2_SHA256:
		return _str(ALG_AKAv2_SHA256_STR);
	case ALG_AKAv2_SHA256SESS:
		return _str(ALG_AKAv2_SHA256SESS_STR);
	case ALG_AKAv2_SHA512_256:
		return _str(ALG_AKAv2_SHA512_256_STR);
	case ALG_AKAv2_SHA512_256SESS:
		return _str(ALG_AKAv2_SHA512_256SESS_STR);
	default:
	case ALG_OTHER:
	case ALG_UNSPEC:
		return _str("Unknown");
	}
}

/*
 * Parse username for user and domain parts
 */
static inline void parse_username(struct username* _u)
{
	char* d;

	_u->user = _u->whole;
	if (_u->whole.len <= 2) return;

	d = q_memchr(_u->whole.s, '@', _u->whole.len);

	if (d) {
		_u->domain.s = d + 1;
		_u->domain.len = _u->whole.len - (d - _u->whole.s) - 1;
		_u->user.len = d - _u->user.s;
	}
}


/*
 * Parse Digest credentials parameter, one by one
 */
static inline int parse_digest_params(str* _s, dig_cred_t* _c)
{
	char* comma;

	do {
		     /* Parse the first parameter */
		if (parse_digest_param(_s, _c) < 0) {
			return -1;
		}

		     /* Try to find the next parameter */
		comma = q_memchr(_s->s, ',', _s->len);
		if (comma) {
			     /* Yes, there is another,
			      * remove any leading white-spaces
			      * and let _s point to the next
			      * parameter name
			      */
			_s->len -= comma - _s->s + 1;
			_s->s = comma + 1;
			trim_leading(_s);
		}
	} while(comma); /* Repeat while there are next parameters */

	     /* Parse QOP body if the parameter was present */
	if (_c->qop.qop_str.len > 0) {
		parse_qop(&_c->qop);
	}

	     /* Parse algorithm body if the parameter was present */
	if (_c->alg.alg_str.len > 0) {
		trim(&(_c->alg.alg_str));
		_c->alg.alg_parsed = parse_digest_algorithm(&(_c->alg.alg_str));
	} else {
		/* No algorithm specified */
		DASSERT(_c->alg.alg_parsed == ALG_UNSPEC);
	}

	if (_c->username.whole.len > 0) {
		parse_username(&_c->username);
	}

	return 0;
}


/*
 * We support Digest authentication only
 *
 * Returns:
 *  0 - if everything is OK
 * -1 - Error while parsing
 *  1 - Unknown scheme
 */
int parse_digest_cred(str* _s, dig_cred_t* _c)
{
	str tmp;

	     /* Make a temporary copy, we are
	      * going to modify it
	      */
	tmp.s = _s->s;
	tmp.len = _s->len;

	     /* Remove any leading spaces, tabs, \r and \n */
	trim_leading(&tmp);

	     /* Check the string length */
	if (tmp.len < (DIG_LEN + 1)) return 1; /* Too short, unknown scheme */

	     /* Now test, if it is digest scheme, since it is the only
	      * scheme we are able to parse here
	      */
	if (turbo_casematch(tmp.s, DIGEST_SCHEME, DIG_LEN) &&
	    /* Test for one of LWS chars + ',' */
	    (is_ws(tmp.s[DIG_LEN]) || (tmp.s[DIG_LEN] == ','))) {
		     /* Scheme is Digest */
		tmp.s += DIG_LEN + 1;
		tmp.len -= DIG_LEN + 1;

		     /* Again, skip all white-spaces */
		trim_leading(&tmp);

		     /* And parse digest parameters */
		if (parse_digest_params(&tmp, _c) < 0) {
			return -2; /* We must not return -1 in this function ! */
		} else {
			return 0;
		}
	} else {
		return 1; /* Unknown scheme */
	}
}


/*
 * Initialize a digest credentials structure
 */
void init_dig_cred(dig_cred_t* _c)
{
	memset(_c, 0, sizeof(dig_cred_t));
}
