/*
 * AKA Authentication - helper functions
 *
 * Copyright (C) 2024 Razvan Crainea
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
 *
 */

#ifndef _LIB_AKA_H_
#define _LIB_AKA_H_

#include "../parser/parse_from.h"
#include "../parser/parse_to.h"
#include "../parser/parse_uri.h"

static inline struct to_body *aka_get_identity_body(struct sip_msg *msg, hdr_types_t hftype)
{
	switch (hftype) {
	case HDR_AUTHORIZATION_T:
		if (!msg->to && ((parse_headers(msg, HDR_TO_F, 0)==-1) || (!msg->to))) {
			LM_ERR("failed to parse TO headers\n");
			return NULL;
		}
		/* force parsing */
		if (!parse_to_uri(msg)) {
			LM_ERR("failed to parse TO URI\n");
			return NULL;
		}
		return get_to(msg);

	case HDR_PROXYAUTH_T:
		if (parse_from_header(msg) < 0) {
			LM_ERR("failed to parse From headers\n");
			return NULL;
		}
		/* force parsing */
		if (!parse_from_uri(msg)) {
			LM_ERR("failed to parse From URI\n");
			return NULL;
		}
		return get_from(msg);

	default:
		LM_ERR("Unhandld header type %d\n", hftype);
		return NULL;
	}
}

static inline void aka_strip_uri_params(struct to_body *body, str *res)
{
	char *p;
	*res = body->uri;
	/* limit the result to the end of the host/port, to skip parameters */
	if (body->parsed_uri.port.len)
		p = body->parsed_uri.port.s + body->parsed_uri.port.len;
	else
		p = body->parsed_uri.host.s + body->parsed_uri.host.len;
	res->len = p - res->s;
}

static inline str *aka_get_public_identity(struct sip_msg *msg, hdr_types_t hftype)
{
	static str res;
	struct to_body *body = aka_get_identity_body(msg, hftype);
	if (!body)
		return NULL;
	aka_strip_uri_params(body, &res);
	return &res;
}

static inline str *aka_get_private_identity(struct sip_msg *msg, auth_body_t *auth, hdr_types_t hftype)
{
	int len;
	static str res;
	struct to_body *body;

	if (auth)
		return &auth->digest.username.whole;

	body = aka_get_identity_body(msg, hftype);
	if (!body)
		return NULL;

	aka_strip_uri_params(body, &res);

	if (body->parsed_uri.type != ERROR_URI_T) {
		len = uri_typestrlen(body->parsed_uri.type);
		res.s += len + 1;
		res.len -= len + 1;
	}

	return &res;
}

#endif /* _LIB_AKA_H_ */
