/*
 * Helper functions for Path support.
 *
 * Copyright (C) 2006 Andreas Granig <agranig@linguin.org>
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
 */

#include "../../data_lump.h"
#include "../../parser/parse_rr.h"
#include "../../parser/parse_uri.h"
#include "../../ut.h"
#include "../../strcommon.h"

#include "path.h"
#include "config.h"

/*! \brief
 * Combines all Path HF bodies into one string.
 */
int build_path_vector(struct sip_msg *_m, str *path, str *received,
														unsigned int flags)
{
	static char buf[MAX_PATH_SIZE];
	static str unescape_buf;

	char *p;
	str uri_params;
	struct hdr_field *hdr;
	struct sip_uri puri;

	rr_t *route = 0;
	param_hooks_t hooks;
	param_t *params;

	path->len = 0;
	path->s = 0;
	received->s = 0;
	received->len = 0;

	if(parse_headers(_m, HDR_EOH_F, 0) < 0) {
		LM_ERR("failed to parse the message\n");
		goto error;
	}

	for( hdr=_m->path,p=buf ; hdr ; hdr=hdr->sibling) {
		/* check for max. Path length */
		if( p-buf+hdr->body.len+1 >= MAX_PATH_SIZE) {
			LM_ERR("Overall Path body exceeds max. length of %d\n",
					MAX_PATH_SIZE);
			goto error;
		}
		if(p!=buf)
			*(p++) = ',';
		memcpy( p, hdr->body.s, hdr->body.len);
		p +=  hdr->body.len;
	}

	if (p!=buf) {
		/* check if next hop is a loose router */
		if (parse_rr_body( buf, p-buf, &route) < 0) {
			LM_ERR("failed to parse Path body, no head found\n");
			goto error;
		}
		if (parse_uri(route->nameaddr.uri.s,route->nameaddr.uri.len,&puri)<0){
			LM_ERR("failed to parse the first Path URI\n");
			goto error;
		}
		if (!puri.lr.s) {
			LM_ERR("first Path URI is not a loose-router, not supported\n");
			goto error;
		}
		if ( flags&REG_SAVE_PATH_RECEIVED_FLAG ) {
			uri_params = puri.params;
			if (parse_params(&uri_params,CLASS_URI,&hooks,&params)!=0){
				LM_ERR("failed to parse parameters of first hop\n");
				goto error;
			}

			/* we have a double-Path OpenSIPS in front of us - skip 1st Path */
			if (hooks.uri.r2 && route->next) {
				if (parse_uri(route->next->nameaddr.uri.s,
				              route->next->nameaddr.uri.len, &puri) < 0) {
					LM_ERR("failed to parse the 2nd Path URI\n");
					free_params(params);
					goto error;
				}
			}

			free_params(params);

			if (parse_params(&(puri.params),CLASS_CONTACT,&hooks,&params)!=0){
				LM_ERR("failed to parse parameters of first hop\n");
				goto error;
			}

			if (hooks.contact.received) {
				if (pkg_str_extend(&unescape_buf,
				                  hooks.contact.received->body.len + 1) != 0) {
					LM_ERR("oom\n");
					goto error;
				}

				LM_DBG("extended to %d %p\n", unescape_buf.len, unescape_buf.s);

				if (unescape_param(&hooks.contact.received->body,
				                           &unescape_buf) != 0)
					LM_ERR("failed to unescape received=%.*s\n",
					       hooks.contact.received->body.len,
					       hooks.contact.received->body.s);
				else
					*received = unescape_buf;
			}

			free_params(params);
		}
		free_rr(&route);
	}

	path->s = buf;
	path->len = p-buf;
	return 0;
error:
	if(route) free_rr(&route);
	return -1;
}


