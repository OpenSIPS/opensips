/*
 * Digest Authentication - generic AAA support
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2009 Irina Stanescu
 * Copyright (C) 2009 Voice Systems
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


#include <string.h>
#include <stdlib.h>
#include "../../mem/mem.h"
#include "../../str.h"
#include "../../parser/hf.h"
#include "../../parser/digest/digest.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_to.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../pvar.h"
#include "../auth/api.h"
#include "authorize.h"
#include "sterman.h"
#include "authaaa_mod.h"


/*
 * Extract URI depending on the request from To or From header
 */
static inline int get_uri_user(struct sip_msg* _m, str** _uri_user)
{
    struct sip_uri *puri;

    if ((REQ_LINE(_m).method.len == 8) &&
	(memcmp(REQ_LINE(_m).method.s, "REGISTER", 8) == 0)) {
	if ((puri=parse_to_uri(_m))==NULL) {
	    LM_ERR("failed to parse To header\n");
	    return -1;
	}
    } else {
	if ((puri=parse_from_uri(_m))==NULL) {
	    LM_ERR("parsing From header\n");
	    return -1;
	}
    }

    *_uri_user = &(puri->user);

    return 0;
}


/*
 * Authorize digest credentials
 */
static inline int authorize(struct sip_msg* _msg, str* _realm,
			    str * _uri_user, int _hftype)
{
    int res;
    auth_result_t ret;
    struct hdr_field* h;
    auth_body_t* cred;
    str *uri_user;
    str user, domain;

    /* get pre_auth domain from _realm pvar (if exists) */
    if (_realm) {
		domain = *_realm;
    } else {
	/* get pre_auth domain from To/From header */
	domain.len = 0;
	domain.s = 0;
    }

    ret = auth_api.pre_auth(_msg, &domain, _hftype, &h);

    if (ret != DO_AUTHORIZATION)
	return ret;

    cred = (auth_body_t*)h->parsed;

    /* get uri_user from _uri_user pvap (if exists) or
       from To/From URI */
    if (_uri_user) {
		res = aaa_authorize_sterman(_msg, &cred->digest,
					       &_msg->first_line.u.request.method,
					       _uri_user);
    } else {
		if (get_uri_user(_msg, &uri_user) < 0) {
		    LM_ERR("To/From URI not found\n");
		    return AUTH_ERROR;
		}
		user.s = (char *)pkg_malloc(uri_user->len);
		if (user.s == NULL) {
		    LM_ERR("no pkg memory left for user\n");
		    return AUTH_ERROR;
		}
		un_escape(uri_user, &user);
		res = aaa_authorize_sterman(_msg, &cred->digest,
					       &_msg->first_line.u.request.method,
					       &user);
		pkg_free(user.s);
    }

    if (res == 1) {
	ret = auth_api.post_auth(_msg, h);
	return ret;
    }

    return AUTH_ERROR;
}


/*
 * Authorize using Proxy-Authorize header field (URI user parameter given)
 */
int aaa_proxy_authorize(struct sip_msg* _msg, str* _realm,
														str* _uri_user)
{
	return authorize(_msg, _realm, _uri_user, HDR_PROXYAUTH_T);
}


/*
 * Authorize using WWW-Authorize header field
 */
int aaa_www_authorize(struct sip_msg* _msg, str* _realm, str* _uri_user)
{
	return authorize(_msg, _realm, _uri_user, HDR_AUTHORIZATION_T);
}
