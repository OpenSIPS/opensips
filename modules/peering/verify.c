/*
 * Verification functions
 *
 * Copyright (C) 2008 Juha Heinanen
 * Copyright (C) 2009 Irina-Maria Stanescu
 * Copyright (C) 2009 Voice System
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 * USA.
 *
 */


#include "../../str.h"
#include "../../dprint.h"
#include "../../aaa/aaa.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_from.h"
#include "peering.h"


/*
 * Send Radius request to verify destination and generate AVPs from
 * reply items of positive response.
 */
int verify_destination(struct sip_msg* _msg, char* s1, char* s2)
{
	aaa_message *send = NULL, *received = NULL;
    uint32_t service;

    /* Add Request-URI host A_USER_NAME and user as A_SIP_URI_USER */
    if (parse_sip_msg_uri(_msg) < 0) {
        LM_ERR("error while parsing Request-URI\n");
		return -1;
    }

	if ((send = proto.create_aaa_message(conn, AAA_AUTH)) == NULL) {
		LM_ERR("failed to create new aaa message for auth\n");
		return -1;
	}

    if (proto.avp_add(conn, send, &attrs[A_USER_NAME],
		       _msg->parsed_uri.host.s,
		       _msg->parsed_uri.host.len, 0)) {
		LM_ERR("error adding PW_USER_NAME\n");
		goto err;
    }

    if (proto.avp_add(conn, send, &attrs[A_SIP_URI_USER],
		       _msg->parsed_uri.user.s,
		       _msg->parsed_uri.user.len, 0)) {
		LM_ERR("error adding PW_SIP_URI_USER\n");
		goto err;
    }

    /* Add From Tag */
    if (parse_from_header(_msg) < 0) {
		LM_ERR("error while parsing From header field\n");
		goto err;
    }

    if ((_msg->from==NULL) || (get_from(_msg) == NULL) ||
				(get_from(_msg)->tag_value.s == NULL) ||
				(get_from(_msg)->tag_value.len <= 0)) {
		LM_ERR("error while accessing From header tag\n");
		goto err;
    }

    if (proto.avp_add(conn, send, &attrs[A_SIP_FROM_TAG],
		       get_from(_msg)->tag_value.s,
		       get_from(_msg)->tag_value.len, 0)) {
		LM_ERR("error adding PW_SIP_FROM_TAG\n");
		goto err;
    }

    /* Add Call-Id */
    if ((parse_headers(_msg, HDR_CALLID_F, 0) == -1) ||
	(_msg->callid == NULL) || (_msg->callid->body.s == NULL) ||
	(_msg->callid->body.len <= 0)) {
		LM_ERR("error while accessing Call-Id\n");
		goto err;
    }

    if (proto.avp_add(conn, send, &attrs[A_SIP_CALL_ID],
		       _msg->callid->body.s,
		       _msg->callid->body.len, 0)) {
		LM_ERR("error adding PW_SIP_CALL_ID\n");
		goto err;
    }

    /* Add Service-Type */
    service = vals[V_SIP_VERIFY_DESTINATION].value;
    if (proto.avp_add(conn, send, &attrs[A_SERVICE_TYPE],
		       &service, -1, 0)) {
		LM_ERR("error adding PW_SERVICE_TYPE\n");
		goto err;
    }

    /* Send Request and generate AVPs of positive reply */
    if (!proto.send_aaa_request(conn, send, &received)) {
		LM_DBG("success\n");
		proto.destroy_aaa_message(conn, send);
		proto.destroy_aaa_message(conn, received);
		return 1;
    }

	LM_DBG("failure\n");

err:
    if (send)
		proto.destroy_aaa_message(conn, send);
    if (received)
		proto.destroy_aaa_message(conn, received);
    return -1;
}


/*
 * Send Radius request to verify source.
 */
int verify_source(struct sip_msg* _msg, char* s1, char* s2)
{
    aaa_message *send = NULL, *received = NULL;
	struct hdr_field *hf;
    uint32_t service;

    /* Add Request-URI host A_USER_NAME and user as A_SIP_URI_USER */
    if (parse_sip_msg_uri(_msg) < 0) {
        LM_ERR("error while parsing Request-URI\n");
		return -1;
    }

	if ((send = proto.create_aaa_message(conn, AAA_AUTH)) == NULL) {
		LM_ERR("failed to create new aaa message for auth\n");
		return -1;
	}

    if (proto.avp_add(conn, send, &attrs[A_USER_NAME],
		       _msg->parsed_uri.host.s,
		       _msg->parsed_uri.host.len, 0)) {
		LM_ERR("error adding PW_USER_NAME\n");
		goto err;
    }

    if (proto.avp_add(conn, send, &attrs[A_SIP_URI_USER],
		       _msg->parsed_uri.user.s,
		       _msg->parsed_uri.user.len, 0)) {
		LM_ERR("error adding PW_SIP_URI_USER\n");
		goto err;
    }

    /* Add From Tag */
    if (parse_from_header(_msg) < 0) {
		LM_ERR("error while parsing From header field\n");
		goto err;
    }

    if (_msg->from == NULL || get_from(_msg) == NULL ||
				get_from(_msg)->tag_value.s == NULL ||
				get_from(_msg)->tag_value.len <= 0) {
		LM_ERR("error while accessing From header tag\n");
		goto err;
    }

    if (proto.avp_add(conn, send, &attrs[A_SIP_FROM_TAG],
		       get_from(_msg)->tag_value.s,
		       get_from(_msg)->tag_value.len, 0)) {
		LM_ERR("error adding PW_SIP_FROM_TAG\n");
		goto err;
    }

    /* Add Call-Id */
    if (parse_headers(_msg, HDR_CALLID_F, 0) == -1 ||
			_msg->callid == NULL || _msg->callid->body.s == NULL ||
			_msg->callid->body.len <= 0) {
		LM_ERR("error while accessing Call-Id\n");
		goto err;
    }

    if (proto.avp_add(conn, send, &attrs[A_SIP_CALL_ID],
		       _msg->callid->body.s,
		       _msg->callid->body.len, 0)) {
		LM_ERR("error adding PW_SIP_CALL_ID\n");
		goto err;
    }

	/* Add P-Request-Hash header body */
	if (parse_headers(_msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("cannot pase message!\n");
		goto err;
	}
	hf = get_header_by_static_name( _msg, "P-Request-Hash");
	if (!hf) {
		LM_ERR("no P-Request-Hash header field\n");
		goto err;
	}
    if (hf->body.s == NULL || hf->body.len <= 0) {
		LM_ERR("error while accessing P-Request-Hash body\n");
		goto err;
    }
    if (proto.avp_add(conn, send, &attrs[A_SIP_REQUEST_HASH],
		       hf->body.s, hf->body.len, 0)) {
		LM_ERR("error adding PW_SIP_REQUEST_HASH\n");
		goto err;
    }

    /* Add Service-Type */
    service = vals[V_SIP_VERIFY_SOURCE].value;
    if (proto.avp_add(conn, send, &attrs[A_SERVICE_TYPE], &service, -1, 0)) {
		LM_ERR("error adding PW_SERVICE_TYPE\n");
		goto err;
    }

    /* Send Request and generate AVPs of positive reply */
    if (!proto.send_aaa_request(conn, send, &received)) {
		LM_DBG("success\n");
		proto.destroy_aaa_message(conn, send);
		proto.destroy_aaa_message(conn, received);
		return 1;
	}

	LM_DBG("failure\n");

err:
    if (send)
		proto.destroy_aaa_message(conn, send);
    if (received)
		proto.destroy_aaa_message(conn, received);
    return -1;
}
