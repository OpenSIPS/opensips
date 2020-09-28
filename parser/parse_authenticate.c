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
#include "../mem/mem.h"
#include "msg_parser.h"
#include "parse_authenticate.h"


#define AUTHENTICATE_MD5         (1<<0)
#define AUTHENTICATE_MD5SESS     (1<<1)
#define AUTHENTICATE_STALE       (1<<2)

#define AUTHENTICATE_DIGEST_S    "Digest"
#define AUTHENTICATE_DIGEST_LEN  (sizeof(AUTHENTICATE_DIGEST_S)-1)

#define LOWER1B(_n) \
	((_n)|0x20)
#define LOWER4B(_n) \
	((_n)|0x20202020)
#define GET4B(_p) \
	((*(_p)<<24) + (*(_p+1)<<16) + (*(_p+2)<<8) + *(_p+3))
#define GET3B(_p) \
	((*(_p)<<24) + (*(_p+1)<<16) + (*(_p+2)<<8) + 0xff)

#define CASE_5B(_hex4,_c5, _new_state, _quoted) \
	case _hex4: \
		if (p+5<end && LOWER1B(*(p+4))==_c5 ) \
		{ \
			p+=5; \
			state = _new_state; \
			quoted_val = _quoted; \
		} else { \
			p+=4; \
		} \
		break;

#define CASE_6B(_hex4,_c5,_c6, _new_state, _quoted) \
	case _hex4: \
		if (p+6<end && LOWER1B(*(p+4))==_c5 && LOWER1B(*(p+5))==_c6) \
		{ \
			p+=6; \
			state = _new_state; \
			quoted_val = _quoted; \
		} else { \
			p+=4; \
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


int parse_qop_value(str *val, struct authenticate_body *auth)
{
	char *q = val->s, *end = val->s + val->len;

	/* parse first token */
	if (val->len<4 || LOWER4B(GET4B(q))!=0x61757468) /* "auth" */
		return -1;
	q += 4;
	if (q==end) {
		auth->flags |= QOP_AUTH;
		return 0;
	}
	switch (*q) {
		case ' ':
		case '\t':
			auth->flags |= QOP_AUTH;
			break;
		case '-':
			q++;
			if (q+3 <= end && LOWER4B(GET3B(q))==0x696e74ff) {
				auth->flags |= QOP_AUTH_INT;
				q+=3;
			} else
				return -1;
			break;
		case ',':
			auth->flags |= QOP_AUTH;
			break;
		default:
			return -1;
	}

	if (q==end) return 0;
	while (q<end && is_ws((int)*q)) q++;
	if (q==end) return 0;
	if (*q!=',')
		return -1;
	q++;
	while (q<end && is_ws((int)*q)) q++;

	/* parse second token */
	if (q+4 > end || LOWER4B(GET4B(q))!=0x61757468)  /* "auth" */
		return -1;
	q += 4;
	if (q==end) {
		auth->flags |= QOP_AUTH;
		return 0;
	}
	if (q+4 <= end && *q == '-' && LOWER4B(GET3B(q+1))==0x696e74ff) {
		auth->flags |= QOP_AUTH_INT;
		return 0;
	} else
		return -1;
}

int parse_authenticate_body( str *body, struct authenticate_body *auth)
{
	char *p;
	char *end;
	int  n, ret = 0;
	int state;
	str name;
	str val;
	int quoted_val;

	if (body->len == 0)
	{
		LM_ERR("empty body\n");
		goto error;
	}

	memset( auth, 0, sizeof(struct authenticate_body));
	p = body->s;
	end = body->s + body->len;

	/* parse the "digest" */
	while (p<end && isspace((int)*p)) p++;
	if (p+AUTHENTICATE_DIGEST_LEN>=end )
		goto parse_error;
	if ( LOWER4B( GET4B(p) ) != 0x64696765 /*dige*/ ||
	LOWER1B(*(p+4))!=0x73 /*s*/ || LOWER1B(*(p+5))!=0x74 /*t*/)
		goto parse_error;
	p += AUTHENTICATE_DIGEST_LEN;
	if (!isspace((int)*p))
		goto parse_error;
	p++;
	while (p<end && isspace((int)*p)) p++;
	if (p==end)
		goto parse_error;

	while (p<end)
	{
		state = OTHER_STATE;
		quoted_val = 0;
		/* get name */
		name.s = p;
		if (p+4<end)
		{
			n = LOWER4B( GET4B(p) );
			switch(n)
			{
				CASE_5B( 0x7265616c, 'm', REALM_STATE, 1); /*realm*/
				CASE_5B( 0x6e6f6e63, 'e', NONCE_STATE, 1); /*nonce*/
				CASE_5B( 0x7374616c, 'e', STALE_STATE, 0); /*stale*/
				CASE_6B( 0x646f6d62, 'i', 'n', DOMAIN_STATE, 1); /*domain*/
				CASE_6B( 0x6f706171, 'u', 'e', OPAQUE_STATE, 1); /*opaque*/
				case 0x616c676f: /*algo*/
					if (p+9<end && LOWER4B(GET4B(p+4))==0x72697468
						&& LOWER1B(*(p+8))=='m' )
					{
						p+=9;
						state = ALGORITHM_STATE;
					} else {
						p+=4;
					}
					break;
				default:
					if ((n|0xff)==0x716f70ff) /*qop*/
					{
						state = QOP_STATE;
						p+=3;
					}
			}
		} else if (p+3<end) {
			n = LOWER4B( GET3B(p) );
			if (n==0x716f70ff) /*qop*/
			{
				p+=3;
				state = QOP_STATE;
			}
		}

		/* parse to the "=" */
		for( n=0 ; p<end&&!isspace((int)*p)&&*p!='=' ; n++,p++  );
		if (p==end)
			goto parse_error;
		if (n!=0)
			state = OTHER_STATE;
		name.len = p-name.s;
		/* get the '=' */
		while (p<end && isspace((int)*p)) p++;
		if (p==end || *p!='=')
			goto parse_error;
		p++;
		/* get the value (quoted or not) */
		while (p<end && isspace((int)*p)) p++;
		if (p+1>=end || (quoted_val && *p!='\"'))
			goto parse_error;
		if (!quoted_val && *p=='\"')
			quoted_val = 1;
		if (quoted_val)
		{
			val.s = ++p;
			while (p<end && *p!='\"')
				p++;
			if (p==end)
				goto error;
		} else {
			val.s = p;
			while (p<end && !isspace((int)*p) && *p!=',')
				p++;
		}
		val.len = p - val.s;
		if (val.len==0)
			val.s = 0;
		/* consume the closing '"' if quoted */
		p += quoted_val;
		while (p<end && isspace((int)*p)) p++;
		if (p<end && *p==',')
		{
			p++;
			while (p<end && isspace((int)*p)) p++;
		}

		LM_DBG("<%.*s>=\"%.*s\" state=%d\n",
			name.len,name.s,val.len,val.s,state);

		/* process the AVP */
		switch (state)
		{
			case QOP_STATE:
				auth->qop = val;
				if (parse_qop_value(&val, auth) < 0)
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
				if (val.len==3)
				{
					if ( LOWER4B(GET3B(val.s))==0x6d6435ff) /* MD5 */
						auth->flags |= AUTHENTICATE_MD5;
				} else if ((val.len == 11 && (              /* SHA-512-256 */
					           LOWER4B(GET4B(val.s + 0)) == 0x7368612d &&
					           LOWER4B(GET4B(val.s + 4)) == 0x3531322d &&
					           LOWER4B(GET3B(val.s + 8)) == 0x323536ff)) ||
					       (val.len == 7 && (               /* SHA-256 */
					           LOWER4B(GET4B(val.s + 0)) == 0x7368612d &&
					           LOWER4B(GET3B(val.s + 4)) == 0x323536ff))) {
					LM_INFO("RFC 8760 (%.*s) is only available "
					        "in OpenSIPS 3.2+\n", val.len, val.s);
					ret = 1;
				} else {
					LM_INFO("bad algorithm \"%.*s\"\n", val.len, val.s);
					goto error;
				}
				break;
			case STALE_STATE:
				if (val.len==4 && LOWER4B(GET4B(val.s))==0x74727565) /*true*/
				{
						auth->flags |= AUTHENTICATE_STALE;
				} else if ( !(val.len==5 && LOWER1B(val.s[4])=='e' &&
					LOWER4B(GET4B(val.s))==0x66616c73) )
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
	LM_ERR("parse error in <%.*s> around %ld\n", body->len, body->s, (long)(p-body->s));
error:
	return -1;
}


int parse_authenticate_header(struct hdr_field *authenticate,
                              struct authenticate_body **picked_auth)
{
	void **parsed;
	struct authenticate_body *auth_body;
	int rc;

	parsed = &(authenticate->parsed);
	*picked_auth = NULL;

	while(*parsed == NULL)
	{
		auth_body = pkg_malloc(sizeof(struct authenticate_body));
		if (auth_body == NULL)
		{
			LM_ERR("oom\n");
			*picked_auth = NULL;
			return -1;
		}

		rc = parse_authenticate_body(&authenticate->body, auth_body);
		if (rc < 0) {
			*picked_auth = NULL;
			return -1;
		}

		if (rc == 0 && !*picked_auth)
			*picked_auth = auth_body;

		*parsed = auth_body;

		authenticate = authenticate->sibling;
		if (authenticate)
			parsed = &(authenticate->parsed);
		else
			break;
	}

	return picked_auth ? 0 : -1;
}

/*
 * This method is used to parse WWW-Authenticate header.
 *
 * params: msg : sip msg
 * returns 0 on success,
 *        -1 on failure.
 */
int parse_www_authenticate_header(struct sip_msg *msg,
                                  struct authenticate_body **picked_auth)
{
    if ( !msg->www_authenticate &&
	(parse_headers(msg, HDR_WWW_AUTHENTICATE_F,0)==-1 || !msg->www_authenticate)) {
	return -1;
    }

    return parse_authenticate_header(msg->www_authenticate, picked_auth);
}


/*
 * This method is used to parse Proxy-Authenticate header.
 *
 * params: msg : sip msg
 * returns 0 on success,
 *        -1 on failure.
 */
int parse_proxy_authenticate_header(struct sip_msg *msg,
                                    struct authenticate_body **picked_auth)
{
    if ( !msg->proxy_authenticate &&
	(parse_headers(msg, HDR_PROXY_AUTHENTICATE_F,0)==-1 || !msg->proxy_authenticate)) {
	return -1;
    }

    return parse_authenticate_header(msg->proxy_authenticate, picked_auth);
}


void free_authenticate(struct authenticate_body *authenticate_b)
{
    if (authenticate_b) {
	pkg_free(authenticate_b);
    }

    return;
}
