/*
 * Copyright (C) 2011 VoIP Embedded Inc. <http://www.voipembedded.com/>
 *
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
 *  2005-01-31  first version (ramona)
 *  2011-03-07  Initial revision (Ovidiu Sas)
 */

#include <stdlib.h>
#include <string.h>
#include "../dprint.h"
#include "../ut.h"
#include "../lib/turbocompare.h"
#include "../mem/mem.h"
#include "msg_parser.h"
#include "parse_authenticate.h"


#define AUTHENTICATE_DIGEST_S    "Digest"
#define AUTHENTICATE_DIGEST_LEN  (sizeof(AUTHENTICATE_DIGEST_S)-1)

#define LOWER1B(_n) \
	((_n < 'A' ||_n > 'Z') ? _n : _n |0x20)
#define LOWER4B(_n) \
	((_n)|TURBO_LCMASK((unsigned int)_n))
#define GET4B(_p) \
	((*(_p)<<24) + (*(_p+1)<<16) + (*(_p+2)<<8) + *(_p+3))

#define CASE_5B(_hex4,_c5, _new_state, _quoted) \
	case _hex4: \
		if (body.len > 5 && LOWER1B(*(body.s+4))==_c5 ) \
		{ \
			STR_ADVANCE_BY(&body, 5); \
			state = _new_state; \
			quoted_val = _quoted; \
		} else { \
			STR_ADVANCE_BY(&body, 4); \
		} \
		break;

#define CASE_6B(_hex4,_c5,_c6, _new_state, _quoted) \
	case _hex4: \
		if (body.len > 6 && LOWER1B(*(body.s+4))==_c5 && LOWER1B(*(body.s+5))==_c6) \
		{ \
			STR_ADVANCE_BY(&body, 6); \
			state = _new_state; \
			quoted_val = _quoted; \
		} else { \
			STR_ADVANCE_BY(&body, 4); \
		} \
		break;

#define OTHER_STATE      0
#define QOP_STATE        1
#define REALM_STATE      2
#define NONCE_STATE      3
#define STALE_STATE      4
#define DOMAIN_STATE     5
#define OPAQUE_STATE     6
#define ALGORITHM_STATE  7

#define TRB_SCASEMATCH(cp, S) (turbo_casematch(cp, (S), (sizeof(S) - 1)))
#define TRB_STRCASEMATCH(sarg, S) (turbo_strcasematch(sarg, (S), (sizeof(S) - 1)))
#define TRB_STRCASESTARTS(sarg, S) ((sarg)->len >= (sizeof(S) - 1) && \
  turbo_casematch((sarg)->s, (S), (sizeof(S) - 1)))

#define STR_ADVANCE_BY(sptr, incr) {int _t = (incr); (sptr)->s += _t; (sptr)->len -= _t;}
#define STR_ADVANCE(sptr) STR_ADVANCE_BY(sptr, 1)
#define STR_ADVANCE_IF_STARTS(sarg, S) (str_advance_if_starts((sarg), (S), (sizeof(S) - 1)))

static int str_advance_if_starts(str *val, const char *sval, size_t slen)
{
	if (val->len < slen || !turbo_casematch(val->s, sval, slen))
		return 0;
	STR_ADVANCE_BY(val, slen);
	return 1;
}

int parse_qop_value(str val, struct authenticate_body *auth)
{

	/* parse first token */
	if (!STR_ADVANCE_IF_STARTS(&val, "auth"))
		return -1;
	if (val.len == 0) {
		auth->flags |= QOP_AUTH;
		return 0;
	}
	switch (*val.s) {
		case ' ':
		case '\t':
			STR_ADVANCE(&val);
			auth->flags |= QOP_AUTH;
			break;
		case '-':
			STR_ADVANCE(&val);
			if (STR_ADVANCE_IF_STARTS(&val, "int")) {
				auth->flags |= QOP_AUTH_INT;
			} else
				return -1;
			break;
		case ',':
			auth->flags |= QOP_AUTH;
			goto postcomma;
		default:
			return -1;
	}

	if (val.len == 0)
		return 0;

	trim_leading(&val);

	if (val.len == 0)
		return 0;
	if (*val.s != ',')
		return -1;
postcomma:
	STR_ADVANCE(&val);
	trim_leading(&val);

	/* parse second token */
	if (!STR_ADVANCE_IF_STARTS(&val, "auth"))
		return -1;
	if (val.len == 0) {
		auth->flags |= QOP_AUTH;
		return 0;
	}
	if (TRB_STRCASEMATCH(&val, "-int")) {
		auth->flags |= QOP_AUTH_INT;
		return 0;
	} else
		return -1;
}

int parse_authenticate_body( str body, struct authenticate_body *auth)
{
	int  n, ret = 0;
	int state;
	str name;
	str val;
	int quoted_val;

	if (body.len == 0)
	{
		LM_ERR("empty body\n");
		goto error;
	}

	memset( auth, 0, sizeof(struct authenticate_body));

	/* parse the "digest" */
	trim_leading(&body);
	if (body.len <= AUTHENTICATE_DIGEST_LEN)
		goto parse_error;
	if (!TRB_SCASEMATCH(body.s, "digest"))
		goto parse_error;
	STR_ADVANCE_BY(&body, AUTHENTICATE_DIGEST_LEN);
	if (!is_ws(*body.s))
		goto parse_error;
	STR_ADVANCE(&body);
	trim_leading(&body);
	if (body.len == 0)
		goto parse_error;

	while (body.len > 0)
	{
		state = OTHER_STATE;
		quoted_val = 0;
		/* get name */
		name.s = body.s;
		if (body.len > 4)
		{
			n = LOWER4B( GET4B(body.s) );
			switch(n)
			{
				CASE_5B( 0x7265616c, 'm', REALM_STATE, 1); /*realm*/
				CASE_5B( 0x6e6f6e63, 'e', NONCE_STATE, 1); /*nonce*/
				CASE_5B( 0x7374616c, 'e', STALE_STATE, 0); /*stale*/
				CASE_6B( 0x646f6d62, 'i', 'n', DOMAIN_STATE, 1); /*domain*/
				CASE_6B( 0x6f706171, 'u', 'e', OPAQUE_STATE, 1); /*opaque*/
				case 0x616c676f: /*algo*/
					if (body.len > 9 && TRB_SCASEMATCH(body.s+4, "rithm"))
					{
						STR_ADVANCE_BY(&body, 9);
						state = ALGORITHM_STATE;
					} else {
						STR_ADVANCE_BY(&body, 4);
					}
					break;
				default:
					if ((n|0xff)==0x716f70ff) /*qop*/
					{
						state = QOP_STATE;
						STR_ADVANCE_BY(&body, 3);
					}
			}
		} else if (body.len > 3) {
			if (TRB_SCASEMATCH(body.s, "qop"))
			{
				STR_ADVANCE_BY(&body, 3);
				state = QOP_STATE;
			}
		}

		/* parse to the "=" */
		for(n=0 ; body.len > 0 && !is_ws(*body.s) && *body.s != '=' ; n++)
			STR_ADVANCE(&body);
		if (body.len == 0)
			goto parse_error;
		if (n!=0)
			state = OTHER_STATE;
		name.len = body.s - name.s;
		/* get the '=' */
		trim_leading(&body);
		if (body.len == 0 || *body.s != '=')
			goto parse_error;
		STR_ADVANCE(&body);
		/* get the value (quoted or not) */
		trim_leading(&body);
		if (body.len <= 1 || (quoted_val && *body.s != '\"'))
			goto parse_error;
		if (!quoted_val && *body.s == '\"')
			quoted_val = 1;
		if (quoted_val)
		{
			STR_ADVANCE(&body);
			char *cp = memchr(body.s, '\"', body.len);
			if (cp == NULL)
				goto error;
			val.s = body.s;
			STR_ADVANCE_BY(&body, cp - body.s);
		} else {
			val.s = body.s;
			while (body.len > 0 && !is_ws(*body.s) && *body.s != ',')
				STR_ADVANCE(&body);
		}
		val.len = body.s - val.s;
		if (val.len==0)
			val.s = 0;
		/* consume the closing '"' if quoted */
		STR_ADVANCE_BY(&body, quoted_val);
		trim_leading(&body);
		if (body.len > 0 && *body.s == ',')
		{
			STR_ADVANCE(&body);
			trim_leading(&body);
		}

		LM_DBG("<%.*s>=\"%.*s\" state=%d\n",
			name.len,name.s,val.len,val.s,state);

		/* process the AVP */
		switch (state)
		{
			case QOP_STATE:
				auth->qop = val;
				if (parse_qop_value(val, auth) < 0)
					LM_DBG("Unknown token in qop value '%.*s'\n",
						val.len, val.s);
				break;
			case REALM_STATE:
				auth->realm = val;
				break;
			case NONCE_STATE:
				auth->nonce = val;
				break;
			case DOMAIN_STATE:
				auth->domain = val;
				break;
			case OPAQUE_STATE:
				auth->opaque = val;
				break;
			case ALGORITHM_STATE:
				auth->algorithm = parse_digest_algorithm(&val);
				if (auth->algorithm == ALG_OTHER) {
					LM_INFO("bad algorithm \"%.*s\"\n", val.len, val.s);
					goto error;
				}
				break;
			case STALE_STATE:
				if (TRB_STRCASEMATCH(&val, "true"))
				{
					auth->flags |= AUTHENTICATE_STALE;
				} else if (!(TRB_STRCASEMATCH(&val, "false")))
				{
					LM_ERR("unsupported stale value \"%.*s\"\n",val.len,val.s);
					goto error;
				}
				break;
			default:
				break;
		}
	}

	/* some checkings */
	if (auth->nonce.s==0 || auth->realm.s==0)
	{
		LM_ERR("realm or nonce missing\n");
		goto error;
	}

	return ret;
parse_error:
	LM_ERR("parse error in <%.*s> around %ld\n", body.len, body.s, (long)(body.len));
error:
	return -1;
}


int parse_authenticate_header(struct hdr_field *authenticate,
    const struct match_auth_hf_desc *md, struct authenticate_body **picked_auth)
{
	void **parsed;
	struct authenticate_body *auth_body, *ret_auth;
	int rc;

	parsed = &(authenticate->parsed);
	ret_auth = NULL;

	while(*parsed == NULL)
	{
		auth_body = pkg_malloc(sizeof(struct authenticate_body));
		if (auth_body == NULL)
		{
			LM_ERR("oom\n");
			*picked_auth = ret_auth;
			return -1;
		}

		rc = parse_authenticate_body(authenticate->body, auth_body);
		if (rc < 0) {
			pkg_free(auth_body);
			*picked_auth = ret_auth;
			return -1;
		}

		if (rc == 0 && !ret_auth &&
		    (md == NULL || md->matchf(auth_body, md)))
			ret_auth = auth_body;

		*parsed = auth_body;

		authenticate = authenticate->sibling;
		if (authenticate)
			parsed = &(authenticate->parsed);
		else
			break;
	}
	*picked_auth = ret_auth;

	return ret_auth ? 0 : -1;
}

/*
 * This method is used to parse WWW-Authenticate header.
 *
 * params: msg : sip msg
 * returns 0 on success,
 *        -1 on failure.
 */
int parse_www_authenticate_header(struct sip_msg *msg,
    const struct match_auth_hf_desc *md, struct authenticate_body **picked_auth)
{
    if ( !msg->www_authenticate &&
	(parse_headers(msg, HDR_WWW_AUTHENTICATE_F,0)==-1 || !msg->www_authenticate)) {
	return -1;
    }

    return parse_authenticate_header(msg->www_authenticate, md,
	picked_auth);
}


/*
 * This method is used to parse Proxy-Authenticate header.
 *
 * params: msg : sip msg
 * returns 0 on success,
 *        -1 on failure.
 */
int parse_proxy_authenticate_header(struct sip_msg *msg,
    const struct match_auth_hf_desc *md, struct authenticate_body **picked_auth)
{
    if ( !msg->proxy_authenticate &&
	(parse_headers(msg, HDR_PROXY_AUTHENTICATE_F,0)==-1 || !msg->proxy_authenticate)) {
	return -1;
    }

    return parse_authenticate_header(msg->proxy_authenticate, md,
	picked_auth);
}


void free_authenticate(struct authenticate_body *authenticate_b)
{
    if (authenticate_b) {
	pkg_free(authenticate_b);
    }

    return;
}
