/*
 * pua_mi module - MI pua module
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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

#include <stdio.h>
#include <stdlib.h>
#include <libxml/parser.h>

#include "../../parser/parse_expires.h"
#include "../../parser/parse_uri.h"
#include  "../../mem/mem.h"
#include "../../mi/mi.h"
#include "../../ut.h"

#include "../pua/pua_bind.h"
#include "../pua/pua.h"
#include "pua_mi.h"

/*
 * mi cmd: pua_publish
 *		<presentity_uri>
 *		<expires>
 *		<event package>
 *		<content_type>     - body type if body of a type different from default
 *                            event content-type or .
 *		<ETag>             - ETag that publish should match or . if no ETag
 *		<extra_headers>    - extra headers to be added to the request or .
 *		<publish_body>     - may not be present in case of update for expire
 */

mi_response_t *mi_pua_publish(const mi_params_t *params,
					struct mi_handler *async_hdl, str *etag, str *extra_headers,
					str *content_type, str *body)
{
	int exp;
	str pres_uri;
	struct sip_uri uri;
	publ_info_t publ;
	str event;
	int result;

	LM_DBG("start\n");

	if (get_mi_string_param(params, "presentity_uri",
		&pres_uri.s, &pres_uri.len) < 0)
		return init_mi_param_error();

	if(pres_uri.s == NULL || pres_uri.s== 0)
	{
		LM_ERR("empty uri\n");
		return init_mi_error(404, MI_SSTR("Empty presentity URI"));
	}
	if(parse_uri(pres_uri.s, pres_uri.len, &uri)<0 )
	{
		LM_ERR("bad uri\n");
		return init_mi_error(404, MI_SSTR("Bad presentity URI"));
	}
	LM_DBG("pres_uri '%.*s'\n", pres_uri.len, pres_uri.s);

	if (get_mi_int_param(params, "expires", &exp) < 0)
		return init_mi_param_error();

	LM_DBG("expires '%d'\n", exp);

	if (get_mi_string_param(params, "event_package", &event.s, &event.len) < 0)
		return init_mi_param_error();

	if(event.s== NULL || event.len== 0)
	{
		LM_ERR("empty event parameter\n");
		return init_mi_error(400, MI_SSTR("Empty event parameter"));
	}
	LM_DBG("event '%.*s'\n",
	    event.len, event.s);

	/* Create the publ_info_t structure */
	memset(&publ, 0, sizeof(publ_info_t));

	publ.pres_uri= &pres_uri;
	if(body)
	{
		publ.body= body;
	}

	publ.event= get_event_flag(&event);
	if(publ.event< 0)
	{
		LM_ERR("unknown event\n");
		return init_mi_error(400, MI_SSTR("Unknown event"));
	}
	if(content_type)
	{
		publ.content_type= *content_type;
	}

	if(etag)
	{
		publ.etag= etag;
	}
	publ.expires= exp;

	if (extra_headers) {
	    publ.extra_headers = extra_headers;
	}

	if (async_hdl)
	{
		publ.source_flag= MI_ASYN_PUBLISH;
		publ.cb_param= (void*)async_hdl;
	}
	else
		publ.source_flag|= MI_PUBLISH;

	publ.outbound_proxy = presence_server;

	result= pua_send_publish(&publ);

	if(result< 0)
	{
		LM_ERR("sending publish failed\n");
		return init_mi_error(500, MI_SSTR("MI/PUBLISH failed"));
	}
	if(result== 418)
		return init_mi_error(418, MI_SSTR("Wrong ETag"));

	if (async_hdl==NULL)
			return init_mi_result_string(MI_SSTR("Accepted"));
	else
			return MI_ASYNC_RPL;
}

mi_response_t *get_ctype_body_params(const mi_params_t *params,
										str *content_type, str *body)
{
	if (get_mi_string_param(params, "content_type",
		&content_type->s, &content_type->len) < 0)
		return init_mi_param_error();

	if(content_type->s== NULL || content_type->len== 0)
	{
		LM_ERR("empty content type\n");
		return init_mi_error(400, MI_SSTR("Empty content type parameter"));
	}
	LM_DBG("content type '%.*s'\n",
	    content_type->len, content_type->s);

	if (get_mi_string_param(params, "body", &body->s, &body->len) < 0)
		return init_mi_param_error();

	if(body->s == NULL || body->s== 0)
	{
		LM_ERR("empty body parameter\n");
		return init_mi_error(400, MI_SSTR("Empty body parameter"));
	}
	LM_DBG("body '%.*s'\n", body->len, body->s);

	return NULL;
}

mi_response_t *get_etag_param(const mi_params_t *params, str *etag)
{
	if (get_mi_string_param(params, "etag", &etag->s, &etag->len) < 0)
		return init_mi_param_error();

	if(etag->s== NULL || etag->len== 0)
	{
		LM_ERR("empty etag parameter\n");
		return init_mi_error(400, MI_SSTR("Empty etag parameter"));
	}
	LM_DBG("etag '%.*s'\n", etag->len, etag->s);

	return NULL;
}

mi_response_t *get_extra_hdrs_param(const mi_params_t *params, str *extra_hdrs)
{
	if (get_mi_string_param(params, "extra_headers",
		&extra_hdrs->s, &extra_hdrs->len) < 0)
		return init_mi_param_error();

	if(extra_hdrs->s== NULL || extra_hdrs->len== 0)
	{
		LM_ERR("empty extra_headers parameter\n");
		return init_mi_error(400, MI_SSTR("Empty extra_headers"));
	}
	LM_DBG("extra_headers '%.*s'\n",
	    extra_hdrs->len, extra_hdrs->s);

	return NULL;
}

mi_response_t *mi_pua_publish_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	return mi_pua_publish(params, async_hdl, NULL,NULL,NULL,NULL);
}

mi_response_t *mi_pua_publish_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str etag;
	mi_response_t *err;

	if ((err = get_etag_param(params, &etag)) != NULL)
		return err;

	return mi_pua_publish(params, async_hdl, &etag, NULL,NULL,NULL);
}

mi_response_t *mi_pua_publish_3(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str extra_hdrs;
	mi_response_t *err;

	if ((err = get_extra_hdrs_param(params, &extra_hdrs)) != NULL)
		return err;

	return mi_pua_publish(params, async_hdl, NULL, &extra_hdrs,NULL,NULL);
}

mi_response_t *mi_pua_publish_4(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str content_type, body;
	mi_response_t *err;

	if ((err = get_ctype_body_params(params, &content_type, &body)) != NULL)
		return err;

	return mi_pua_publish(params, async_hdl, NULL,NULL, &content_type, &body);
}

mi_response_t *mi_pua_publish_5(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str etag, extra_hdrs;
	mi_response_t *err;

	if ((err = get_etag_param(params, &etag)) != NULL)
		return err;
	if ((err = get_extra_hdrs_param(params, &extra_hdrs)) != NULL)
		return err;

	return mi_pua_publish(params, async_hdl, &etag, &extra_hdrs,NULL,NULL);
}

mi_response_t *mi_pua_publish_6(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str etag, content_type, body;
	mi_response_t *err;

	if ((err = get_etag_param(params, &etag)) != NULL)
		return err;
	if ((err = get_ctype_body_params(params, &content_type, &body)) != NULL)
		return err;	

	return mi_pua_publish(params, async_hdl, &etag, NULL, &content_type, &body);
}

mi_response_t *mi_pua_publish_7(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str extra_hdrs, content_type, body;
	mi_response_t *err;

	if ((err = get_extra_hdrs_param(params, &extra_hdrs)) != NULL)
		return err;
	if ((err = get_ctype_body_params(params, &content_type, &body)) != NULL)
		return err;	

	return mi_pua_publish(params, async_hdl, NULL, &extra_hdrs, &content_type, &body);
}

mi_response_t *mi_pua_publish_8(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str etag, extra_hdrs, content_type, body;
	mi_response_t *err;

	if ((err = get_etag_param(params, &etag)) != NULL)
		return err;
	if ((err = get_extra_hdrs_param(params, &extra_hdrs)) != NULL)
		return err;
	if ((err = get_ctype_body_params(params, &content_type, &body)) != NULL)
		return err;	

	return mi_pua_publish(params, async_hdl, &etag, &extra_hdrs, &content_type, &body);
}

int mi_publ_rpl_cback( ua_pres_t* hentity, struct sip_msg* reply)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	struct mi_handler* mi_hdl= NULL;
	struct hdr_field* hdr= NULL;
	int statuscode;
	int lexpire;
	str etag;
	str reason= {0, 0};

	if(reply== NULL || hentity== NULL)
	{
		LM_ERR("NULL parameter\n");
		return -1;
	}
	if(hentity->cb_param== NULL)
	{
		LM_DBG("NULL callback parameter, probably a refresh\n");
		return -1;
	}
	if(reply== FAKED_REPLY)
	{
		statuscode= 408;
		reason.s= "Request Timeout";
		reason.len= strlen(reason.s);
	}
	else
	{
		statuscode= reply->first_line.u.reply.statuscode;
		reason= reply->first_line.u.reply.reason;
	}

	mi_hdl = (struct mi_handler *)(hentity->cb_param);

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		goto done;

	if (add_mi_string_fmt(resp_obj, MI_SSTR("reply"), "%d %.*s",
		statuscode, reason.len, reason.s) < 0)
		goto error;

	if(statuscode== 200)
	{
		/* extract ETag and expires */
		lexpire = ((exp_body_t*)reply->expires->parsed)->val;
		LM_DBG("lexpire= %d\n", lexpire);

		hdr = get_header_by_static_name( reply, "SIP-ETag");
		if( hdr==NULL ) /* must find SIP-Etag header field in 200 OK msg*/
		{
			LM_ERR("SIP-ETag header field not found\n");
			goto error;
		}
		etag= hdr->body;

		if (add_mi_string(resp_obj, MI_SSTR("ETag"), etag.s, etag.len) < 0)
			goto error;

		if (add_mi_number(resp_obj, MI_SSTR("Expires"), lexpire) < 0)
			goto error;
	}

done:
	if ( statuscode >= 200)
	{
		mi_hdl->handler_f( resp, mi_hdl, 1);
	}
	else
	{
		mi_hdl->handler_f( resp, mi_hdl, 0 );
	}
	hentity->cb_param = 0;
	return 0;

error:
	return  -1;
}


/*Command parameters:
 * pua_subscribe
 *		<presentity_uri>
 *		<watcher_uri>
 *		<event_package>
 *		<expires>
 * */


mi_response_t *mi_pua_subscribe(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int exp= 0;
	str pres_uri, watcher_uri;
	struct sip_uri uri;
	subs_info_t subs;
	str event;

	if (get_mi_string_param(params, "presentity_uri",
		&pres_uri.s, &pres_uri.len) < 0)
		return init_mi_param_error();

	if(pres_uri.s == NULL || pres_uri.s== 0)
	{
		return init_mi_error(400, MI_SSTR("Bad uri"));
	}
	if(parse_uri(pres_uri.s, pres_uri.len, &uri)<0 )
	{
		LM_ERR("bad uri\n");
		return init_mi_error(400, MI_SSTR("Bad uri"));
	}

	if (get_mi_string_param(params, "watcher_uri",
		&watcher_uri.s, &watcher_uri.len) < 0)
		return init_mi_param_error();

	if(watcher_uri.s == NULL || watcher_uri.s== 0)
	{
		return init_mi_error(400, MI_SSTR("Bad uri"));
	}
	if(parse_uri(watcher_uri.s, watcher_uri.len, &uri)<0 )
	{
		LM_ERR("bad uri\n");
		return init_mi_error(400, MI_SSTR("Bad uri"));
	}

	if (get_mi_string_param(params, "event_package",
		&event.s, &event.len) < 0)
		return init_mi_param_error();

	if(event.s== NULL || event.len== 0)
	{
		LM_ERR("empty event parameter\n");
		return init_mi_error(400, MI_SSTR("Empty event parameter"));
	}
	LM_DBG("event '%.*s'\n", event.len, event.s);

	if (get_mi_int_param(params, "expires", &exp) < 0)
		goto error;

	LM_DBG("expires '%d'\n", exp);

	memset(&subs, 0, sizeof(subs_info_t));

	subs.pres_uri= &pres_uri;

	subs.watcher_uri= &watcher_uri;

	subs.contact= &watcher_uri;

	subs.expires= exp;
	subs.source_flag |= MI_SUBSCRIBE;
	subs.event= get_event_flag(&event);
	if(subs.event< 0)
	{
		LM_ERR("unknown event\n");
		return init_mi_error(400, MI_SSTR("Unknown event"));
	}

	if(pua_send_subscribe(&subs)< 0)
	{
		LM_ERR("while sending subscribe\n");
		goto error;
	}

	return init_mi_result_string(MI_SSTR("accepted"));

error:

	return 0;

}

