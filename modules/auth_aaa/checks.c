/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include <string.h>
#include "../../pvar.h"
#include "../../mem/mem.h"
#include "../../parser/parse_uri.h"
#include "../../dprint.h"
#include "../../aaa/aaa.h"
#include "authaaa_mod.h"
#include "checks.h"



/*
 * Check from AAA if URI, whose user an host parts are given as
 * arguments, exists.
 * If so, loads AVPs based on reply items returned from AAA.
 */
int aaa_does_uri_user_host_exist(str user, str host, str callid)
{
	aaa_message *send = NULL, *received = NULL;
	uint32_t service;

	if ((send = proto.create_aaa_message(conn, AAA_AUTH)) == NULL) {
		LM_ERR("failed to create new aaa message for auth\n");
		return -1;
	}

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
		return 1;
	} else {
		proto.destroy_aaa_message(conn, send);
		proto.destroy_aaa_message(conn, received);
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
	return -1;
}


/*
 * Check from AAA if URI giving in pvar argument belongs to a local user.
 * If so, loads AVPs based on reply items returned from AAA.
 */
int aaa_does_uri_exist(struct sip_msg* _m, str *val)
{
	struct sip_uri parsed_uri;

	if (val) {
		if (parse_uri(val->s, val->len, &parsed_uri) < 0) {
			LM_ERR("parsing of URI in pvar failed\n");
			return -1;
		}

		if ( _m->callid == NULL &&
		(parse_headers(_m, HDR_CALLID_F, 0) == -1 || _m->callid == NULL)) {
			LM_ERR("msg parsing failed or callid not present\n");
			return -1;
		}

		return aaa_does_uri_user_host_exist(parsed_uri.user, parsed_uri.host,
			_m->callid->body);
	} else {
		if (parse_sip_msg_uri(_m) < 0) {
			LM_ERR("parsing URI failed\n");
			return -1;
		}

		if ( _m->callid==NULL &&
		(parse_headers(_m, HDR_CALLID_F, 0)==-1 || _m->callid==NULL)  ) {
			LM_ERR("msg parsing failed or callid not present\n");
			return -1;
		}

		return aaa_does_uri_user_host_exist(_m->parsed_uri.user,
				_m->parsed_uri.host, _m->callid->body);
	}
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
 * Check from AAA if URI user giving in pvar argument belongs
 * to a local user. If so, loads AVPs based on reply items returned
 * from AAA.
 */
int w_aaa_does_uri_user_exist(struct sip_msg* _m, str *val)
{
	if (val) {
		if ( !_m->callid &&
				(parse_headers(_m, HDR_CALLID_F, 0) == -1 || !_m->callid)) {
			LM_ERR("msg parsing failed or callid not present\n");
			return -1;
		}

		return aaa_does_uri_user_exist(*val, _m->callid->body);
	} else {
		if (parse_sip_msg_uri(_m) < 0) {
			LM_ERR("parsing URI failed\n");
			return -1;
		}

		if ( !_m->callid &&
				(parse_headers(_m, HDR_CALLID_F, 0) == -1 || !_m->callid)) {
			LM_ERR("msg parsing failed or callid not present\n");
			return -1;
		}

		return aaa_does_uri_user_exist(_m->parsed_uri.user, _m->callid->body);
	}
}
