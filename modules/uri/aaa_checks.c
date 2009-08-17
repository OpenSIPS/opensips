/*
 * $Id: $
 *
 * Various URI checks and Request URI manipulation
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 * 2009-08-07 - Created by Irina Stanescu based on checks.c from the formerly
 *		uri_radius module
 */

#include <string.h>
#include "../../mem/mem.h"
#include "../../parser/parse_uri.h"
#include "../../dprint.h"
#include "../../aaa/aaa.h"
#include "aaa_checks.h"
#include "uri_mod.h"
#include "../../pvar.h"



/*
 * Check from AAA if URI, whose user an host parts are given as
 * arguments, exists.
 * If so, loads AVPs based on reply items returned from AAA.
 */
int aaa_does_uri_user_host_exist(str user, str host, str callid)
{
 	aaa_message *send = NULL, *received = NULL;
    uint32_t service;
    char* at, *uri = 0;

	if ((send = proto.create_aaa_message(conn, AAA_AUTH)) == NULL) {
		LM_ERR("failed to create new aaa message for auth\n");
		return -1;
	}

	if (!use_sip_uri_host) {

		/* Send userpart@hostpart of Request-URI in A_USER_NAME attr */
		uri = (char*)pkg_malloc(user.len + host.len + 2);
		if (!uri) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}

		at = uri;
		memcpy(at, user.s, user.len);
		at += user.len;
		*at = '@';
		at++;
		memcpy(at , host.s, host.len);
		at += host.len;
		*at = '\0';

		if (proto.avp_add(conn, send, &attrs[A_USER_NAME], uri, -1, 0)) {
			LM_ERR("adding User-Name failed\n");
			goto error;
		}

	} else {

		/* Send userpart of Request-URI in A_USER_NAME attribute and
		   hostpart in A_SIP_URI_HOST attribute */
		if (proto.avp_add(conn, send, &attrs[A_USER_NAME],
						   user.s, user.len, 0)) {
			LM_ERR("adding User-Name failed\n");
			goto error;
		}
		if (proto.avp_add(conn, send, &attrs[A_SIP_URI_HOST], 
							host.s,	host.len, 0)) {
			LM_ERR("adding SIP-URI-Host failed\n");
			goto error;
		}
	}

	service = vals[V_CALL_CHECK].value;
	if (proto.avp_add(conn, send, &attrs[A_SERVICE_TYPE], &service, -1, 0)) {
		LM_ERR("adding service type failed\n");
		goto error;
	}

	/* Add CALL-ID in Acct-Session-Id Attribute */
	if (proto.avp_add(conn, send, &attrs[A_ACCT_SESSION_ID], callid.s,
						callid.len, 0)) {
		LM_ERR("unable to add CALL-ID attribute\n");
		goto error;
	}

	if (!proto.send_aaa_request(conn, send, &received)) {
		LM_DBG("success\n");
		proto.destroy_aaa_message(conn, send);
		proto.destroy_aaa_message(conn, received);
		if (uri) pkg_free(uri);
		return 1;
	} else {
		proto.destroy_aaa_message(conn, send);
		proto.destroy_aaa_message(conn, received);
		if (uri) pkg_free(uri);
#ifdef REJECT_RC
		/*if (res == REJECT_RC) {
			LM_DBG("rejected\n");
			return -1;
		} else {
			LM_ERR("failure\n");
			return -2;
		}*/
#else
		LM_DBG("failure\n");
		return -1;
#endif
	}

error:
	proto.destroy_aaa_message(conn, send);
	if (uri) pkg_free(uri);
	return -1;
}


/*
 * Check from AAA if Request URI belongs to a local user.
 * If so, loads AVPs based on reply items returned from AAA.
 */
int aaa_does_uri_exist_0(struct sip_msg* _m, char* _s1, char* _s2)
{

    if (parse_sip_msg_uri(_m) < 0) {
	LM_ERR("parsing URI failed\n");
	return -1;
    }

	if ( _m->callid==NULL &&
	(parse_headers(_m, HDR_CALLID_F, 0)==-1 || _m->callid==NULL)  ) {
		LM_ERR("msg parsing failed or callid not present");
		return -1;
	}

	return aaa_does_uri_user_host_exist(_m->parsed_uri.user,
			_m->parsed_uri.host, _m->callid->body);
}


/*
 * Check from AAA if URI giving in pvar argument belongs to a local user.
 * If so, loads AVPs based on reply items returned from AAA.
 */
int aaa_does_uri_exist_1(struct sip_msg* _m, char* _sp, char* _s2)
{
    pv_spec_t *sp;
    pv_value_t pv_val;
    struct sip_uri parsed_uri;

    sp = (pv_spec_t *)_sp;

    if (sp && (pv_get_spec_value(_m, sp, &pv_val) == 0)) {
		if (pv_val.flags & PV_VAL_STR) {
	    	if (pv_val.rs.len == 0 || pv_val.rs.s == NULL) {
				LM_ERR("pvar argument is empty\n");
				return -1;
	    	}
		} else {
		    LM_ERR("pvar value is not string\n");
	    	return -1;
		}
    } else {
		LM_ERR("cannot get pvar value\n");
		return -1;
    }

	if (parse_uri(pv_val.rs.s, pv_val.rs.len, &parsed_uri) < 0) {
		LM_ERR("parsing of URI in pvar failed\n");
		return -1;
	}

	if ( _m->callid == NULL &&
	(parse_headers(_m, HDR_CALLID_F, 0) == -1 || _m->callid == NULL)) {
		LM_ERR("msg parsing failed or callid not present");
		return -1;
	}

	return aaa_does_uri_user_host_exist(parsed_uri.user, parsed_uri.host,
		_m->callid->body);
}


/*
 * Check from AAA if URI user given as argument belongs to a local user.
 * If so, loads AVPs based on reply items returned from AAA.
 */
int aaa_does_uri_user_exist(str user, str callid)
{
	aaa_message *send = NULL, *received = NULL;
    uint32_t service;

	if ((send = proto.create_aaa_message(conn, AAA_AUTH)) == NULL) {
		LM_ERR("failed to create new aaa message for auth\n");
		return -1;
	}

	if (proto.avp_add(conn, send, &attrs[A_USER_NAME], user.s, user.len, 0)) {
		LM_ERR("error adding User-Name\n");
		goto error;
	}

	service = vals[V_CALL_CHECK].value;
	if (proto.avp_add(conn, send, &attrs[A_SERVICE_TYPE], &service, -1, 0)) {
		LM_ERR("error adding service type\n");
		goto error;
	}

	/* Add CALL-ID in Acct-Session-Id Attribute */
	if (proto.avp_add(conn, send, &attrs[A_ACCT_SESSION_ID], callid.s,
						callid.len, 0) == 0) {
		LM_ERR("unable to add CALL-ID attribute\n");
		goto error;
	}

	if (!proto.send_aaa_request(conn, send, &received)) {
		LM_DBG("success\n");
		proto.destroy_aaa_message(conn, send);
		proto.destroy_aaa_message(conn, received);
		return 1;
	} else {
		proto.destroy_aaa_message(conn, send);
		proto.destroy_aaa_message(conn, received);
#ifdef REJECT_RC
/*		if (res == REJECT_RC) {
			LM_DBG("rejected\n");
			return -1;
		} else {
			LM_ERR("failure\n");
			return -2;
		}*/
#else
		LM_DBG("failure\n");
		return -1;
#endif
	}
error:
	proto.destroy_aaa_message(conn, send);
	return -1;
}


/*
 * Check from AAA if Request URI user belongs to a local user.
 * If so, loads AVPs based on reply items returned from AAA.
 */
int aaa_does_uri_user_exist_0(struct sip_msg* _m, char* _s1, char* _s2)
{

    if (parse_sip_msg_uri(_m) < 0) {
		LM_ERR("parsing URI failed\n");
		return -1;
    }

	if ( !_m->callid &&
			(parse_headers(_m, HDR_CALLID_F, 0) == -1 || !_m->callid)) {
		LM_ERR("msg parsing failed or callid not present");
		return -1;
	}

    return aaa_does_uri_user_exist(_m->parsed_uri.user, _m->callid->body);
}


/*
 * Check from AAA if URI user giving in pvar argument belongs
 * to a local user. If so, loads AVPs based on reply items returned
 * from AAA.
 */
int aaa_does_uri_user_exist_1(struct sip_msg* _m, char* _sp, char* _s2)
{
    pv_spec_t *sp;
    pv_value_t pv_val;

    sp = (pv_spec_t *)_sp;

    if (sp && (pv_get_spec_value(_m, sp, &pv_val) == 0)) {
		if (pv_val.flags & PV_VAL_STR) {
	    	if (pv_val.rs.len == 0 || pv_val.rs.s == NULL) {
				LM_ERR("pvar argument is empty\n");
				return -1;
		    }
		} else {
	    	LM_ERR("pvar value is not string\n");
		    return -1;
		}
    } else {
		LM_ERR("cannot get pvar value\n");
		return -1;
    }

	if ( !_m->callid &&
			(parse_headers(_m, HDR_CALLID_F, 0) == -1 || !_m->callid)) {
		LM_ERR("msg parsing failed or callid not present");
		return -1;
	}

    return aaa_does_uri_user_exist(pv_val.rs, _m->callid->body);
}
