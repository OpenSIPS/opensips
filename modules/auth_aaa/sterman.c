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
 *
 */


#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../aaa/aaa.h"
#include "../auth/api.h"
#include "sterman.h"
#include "authaaa_mod.h"

#include <stdlib.h>
#include <string.h>




static int add_cisco_vsa(aaa_message** send, struct sip_msg* msg)
{
	str callid;

	if (!msg->callid && parse_headers(msg, HDR_CALLID_F, 0) == -1) {
		LM_ERR("cannot parse Call-ID header field\n");
		return -1;
	}

	if (!msg->callid) {
		LM_ERR("call-ID header field not found\n");
		return -1;
	}

	callid.len = msg->callid->body.len + 8;
	callid.s = pkg_malloc(callid.len);
	if (callid.s == NULL) {
		LM_ERR("no pkg memory left\n");
		return -1;
	}

	memcpy(callid.s, "call-id=", 8);
	memcpy(callid.s + 8, msg->callid->body.s, msg->callid->body.len);

	if (proto.avp_add(conn, *send, &attrs[A_CISCO_AVPAIR], callid.s,
			callid.len, attrs[A_CISCO_AVPAIR].value)) {

		LM_ERR("unable to add Cisco-AVPair attribute\n");
		pkg_free(callid.s);
		return -1;
	}

	pkg_free(callid.s);
	return 0;
}


/*
 * This function creates and submits aaa authentication request as per
 * draft-sterman-aaa-sip-00.txt.  In addition, _user parameter is included
 * in the request as value of a SER specific attribute type SIP-URI-User,
 * which can be be used as a check item in the request.  Service type of
 * the request is Authenticate-Only.
 */
int aaa_authorize_sterman(struct sip_msg* _msg, dig_cred_t* _cred, str* _method, str* _user)
{
	aaa_message *send, *received;
	uint32_t service;
	str method, user, user_name;
	str *ruri;

	send = received = NULL;

	if (!(_cred && _method && _user)) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	method = *_method;
	user = *_user;

	if ((send = proto.create_aaa_message(conn, AAA_AUTH)) == NULL) {
		LM_ERR("failed to create new aaa message for auth\n");
		return -1;
	}

	/*
	 * Add all the user digest parameters according to the qop defined.
	 * Most devices tested only offer support for the simplest digest.
	 */
	if (_cred->username.domain.len) {
		if (proto.avp_add(conn, send, &attrs[A_USER_NAME], _cred->username.whole.s, _cred->username.whole.len, 0)) {
			LM_ERR("unable to add User-Name attribute\n");
			goto err;
		}
	} else {
		user_name.len = _cred->username.user.len + _cred->realm.len + 1;
		user_name.s = pkg_malloc(user_name.len);
		if (!user_name.s) {
			LM_ERR("no pkg memory left\n");
			return -3;
		}
		memcpy(user_name.s, _cred->username.whole.s, _cred->username.whole.len);
		user_name.s[_cred->username.whole.len] = '@';
		memcpy(user_name.s + _cred->username.whole.len + 1, _cred->realm.s,
			_cred->realm.len);
		if (proto.avp_add(conn, send, &attrs[A_USER_NAME], user_name.s,
					user_name.len, 0)) {
			LM_ERR("unable to add User-Name attribute\n");
			pkg_free(user_name.s);
			goto err;
		}
		pkg_free(user_name.s);
	}

	if (proto.avp_add(conn, send, &attrs[A_DIGEST_USER_NAME],
				_cred->username.whole.s, _cred->username.whole.len, 0)) {
		LM_ERR("unable to add Digest-User-Name attribute\n");
		goto err;
	}

	if (proto.avp_add(conn, send, &attrs[A_DIGEST_REALM], _cred->realm.s,
				_cred->realm.len, 0)) {
		LM_ERR("unable to add Digest-Realm attribute\n");
		goto err;
	}
	if (proto.avp_add(conn, send, &attrs[A_DIGEST_NONCE], _cred->nonce.s,
				_cred->nonce.len, 0)) {
		LM_ERR("unable to add Digest-Nonce attribute\n");
		goto err;
	}

	if (use_ruri_flag < 0 || isflagset(_msg, use_ruri_flag) != 1) {
		ruri = &_cred->uri;
	} else {
		ruri = GET_RURI(_msg);
	}
	if (proto.avp_add(conn, send, &attrs[A_DIGEST_URI], ruri->s,
				ruri->len, 0)) {
		LM_ERR("unable to add Digest-URI attribute\n");
		goto err;
	}

	if (proto.avp_add(conn, send, &attrs[A_DIGEST_METHOD], method.s,
				method.len, 0)) {
		LM_ERR("unable to add Digest-Method attribute\n");
		goto err;
	}

	/*
	 * Add the additional authentication fields according to the QOP.
	 */
	if (_cred->qop.qop_parsed == QOP_AUTH_D) {
		if (proto.avp_add(conn, send, &attrs[A_DIGEST_QOP], "auth", 4, 0)) {
			LM_ERR("unable to add Digest-QOP attribute\n");
			goto err;
		}
		if (proto.avp_add(conn, send, &attrs[A_DIGEST_NONCE_COUNT],
				_cred->nc.s, _cred->nc.len, 0)) {
			LM_ERR("unable to add Digest-CNonce-Count attribute\n");
			goto err;
		}
		if (proto.avp_add(conn, send, &attrs[A_DIGEST_CNONCE],
				_cred->cnonce.s, _cred->cnonce.len, 0)) {
			LM_ERR("unable to add Digest-CNonce attribute\n");
			goto err;
		}
	} else if (_cred->qop.qop_parsed == QOP_AUTHINT_D) {
		if (proto.avp_add(conn, send, &attrs[A_DIGEST_QOP],
				"auth-int", 8, 0)) {
			LM_ERR("unable to add Digest-QOP attribute\n");
			goto err;
		}
		if (proto.avp_add(conn, send, &attrs[A_DIGEST_NONCE_COUNT],
				_cred->nc.s, _cred->nc.len, 0)) {
			LM_ERR("unable to add Digest-Nonce-Count attribute\n");
			goto err;
		}
		if (proto.avp_add(conn, send, &attrs[A_DIGEST_CNONCE],
				_cred->cnonce.s, _cred->cnonce.len, 0)) {
			LM_ERR("unable to add Digest-CNonce attribute\n");
			goto err;
		}
		if (proto.avp_add(conn, send, &attrs[A_DIGEST_BODY_DIGEST],
				_cred->opaque.s, _cred->opaque.len, 0)) {
			LM_ERR("unable to add Digest-Body-Digest attribute\n");
			goto err;
		}
	} else  {
		/* send nothing for qop == "" */
	}

	/* Add the response... What to calculate against... */
	if (proto.avp_add(conn, send, &attrs[A_DIGEST_RESPONSE],
			_cred->response.s, _cred->response.len, 0)) {
		LM_ERR("unable to add Digest-Response attribute\n");
		goto err;
	}

	/* Indicate the service type, Authenticate only in our case */
	service = vals[V_SIP_SESSION].value;
	if (proto.avp_add(conn, send, &attrs[A_SERVICE_TYPE], &service, -1, 0)) {
		LM_ERR("unable to add Service-Type attribute\n");
		goto err;
	}

	/* Add SIP URI as a check item */
	if (proto.avp_add(conn, send, &attrs[A_SIP_URI_USER], user.s,user.len,0)) {
		LM_ERR("unable to add Sip-URI-User attribute\n");
		goto err;
	}

	/* Add CALL-ID in Acct-Session-Id Attribute */
	if ( _msg->callid==NULL &&
		(parse_headers(_msg, HDR_CALLID_F, 0)==-1 || _msg->callid==NULL)  ) {
		LM_ERR("msg parsing failed or callid not present\n");
		goto err;
	}
	if (proto.avp_add(conn, send, &attrs[A_ACCT_SESSION_ID],
				_msg->callid->body.s, _msg->callid->body.len, 0)) {
		LM_ERR("unable to add CALL-ID attribute\n");
		goto err;
	}

	if (attrs[A_CISCO_AVPAIR].name != NULL) {
		if (add_cisco_vsa(&send, _msg)) {
			goto err;
		}
	}

	/* Send request */
	if (!proto.send_aaa_request(conn, send, &received)) {
		LM_DBG("Success\n");
		proto.destroy_aaa_message(conn, send);
		proto.destroy_aaa_message(conn, received);
		return 1;
	} else {
#ifdef REJECT_RC
/*		if (i == REJECT_RC) {
			LM_DBG("Failure\n");
			goto err;
		}*/
#endif
		LM_ERR("authorization failed\n");
	}

err:
	if (send)
		proto.destroy_aaa_message(conn, send);
	if (received)
		proto.destroy_aaa_message(conn, received);
	return -1;
}
