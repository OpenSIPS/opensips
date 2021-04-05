/*
 * Copyright (c) 2011 VoIP Embedded Inc. <http://www.voipembedded.com/>
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

#ifndef PARSE_AUTHENTICATE_H
#define PARSE_AUTHENTICATE_H


#include "msg_parser.h"
#include "digest/digest_parser.h"

#define AUTHENTICATE_STALE	(1<<0)
#define QOP_AUTH		(1<<1)
#define QOP_AUTH_INT		(1<<2)

struct authenticate_body {
	alg_t algorithm;
	int flags;
	str realm;
	str domain;
	str nonce;
	str opaque;
	str qop;
};

/* casting macro for accessing the topmost www/proxy authenticate body */
#define get_www_authenticate(p_msg)   ((struct authenticate_body*)(p_msg)->www_authenticate->parsed)
#define get_proxy_authenticate(p_msg) ((struct authenticate_body*)(p_msg)->proxy_authenticate->parsed)

/*
 * WWW/Proxy-Authenticate header field parser
 */
struct match_auth_hf_desc;
typedef int (*match_auth_hf_function)(const struct authenticate_body *,
    const struct match_auth_hf_desc *);

struct match_auth_hf_desc {
	match_auth_hf_function matchf;
	const void *argp;
};

#define MATCH_AUTH_HF(_fn, _argp) (const struct match_auth_hf_desc){ \
    .matchf = (_fn), .argp = (_argp)}

int parse_proxy_authenticate_header(struct sip_msg *msg,
    const struct match_auth_hf_desc *md, struct authenticate_body **picked_auth);
int parse_www_authenticate_header(struct sip_msg *msg,
    const struct match_auth_hf_desc *md, struct authenticate_body **picked_auth);
int parse_authenticate_header(struct hdr_field *authenticate,
    const struct match_auth_hf_desc *md, struct authenticate_body **picked_auth);
static inline int _parse_authenticate_header(struct hdr_field *authenticate)
{
	struct authenticate_body *_;
	return parse_authenticate_header(authenticate, NULL, &_);
}


int parse_qop_value(str val, struct authenticate_body *auth);
int parse_authenticate_body(str body, struct authenticate_body *auth);

void free_authenticate(struct authenticate_body *authenticate_b);

#endif /* ! PARSE_AUTHENTICATE_H */
