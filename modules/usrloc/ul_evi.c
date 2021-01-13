/*
 * Copyright (C) 2020 OpenSIPS Solutions
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
 */

#include "../../evi/evi_modules.h"
#include "../../ipc.h"

#include "ul_evi.h"

#define UL_ASYNC_CT_REFRESH 1


/* AOR events and parameters */
event_id_t ei_ins_id = EVI_ERROR;
event_id_t ei_del_id = EVI_ERROR;
static evi_params_p ul_aor_event_params;
static struct {
	evi_param_p domain;
	evi_param_p aor;
} ul_aor_event;

/* Contact events and parameters */
event_id_t ei_c_ins_id = EVI_ERROR;
event_id_t ei_c_update_id = EVI_ERROR;
event_id_t ei_c_del_id = EVI_ERROR;
event_id_t ei_c_latency_update_id = EVI_ERROR;
static evi_params_p ul_contact_event_params;
static struct {
	evi_param_p domain;
	evi_param_p aor;
	evi_param_p uri;
	evi_param_p received;
	evi_param_p path;
	evi_param_p qval;
	evi_param_p user_agent;
	evi_param_p socket;
	evi_param_p bflags;
	evi_param_p expires;
	evi_param_p callid;
	evi_param_p cseq;
	evi_param_p attr;
	evi_param_p latency;
	evi_param_p shtag;
} ul_ct_event;

/* Contact PN events and parameters */
event_id_t ei_c_refresh_id = EVI_ERROR;
static evi_params_p ul_contact_pn_event_params;
static struct {
	evi_param_p domain;
	evi_param_p aor;
	evi_param_p uri;
	evi_param_p received;
	evi_param_p user_agent;
	evi_param_p socket;
	evi_param_p bflags;
	evi_param_p expires;
	evi_param_p callid;
	evi_param_p attr;
	evi_param_p shtag;
	evi_param_p reason;
	evi_param_p req_callid;
} ul_ct_pn_event;

/*! \brief
 * Initialize event structures
 */
int ul_event_init(void)
{
	/* Event IDs */

	ei_ins_id = evi_publish_event(str_init(UL_EV_AOR_INSERT));
	if (ei_ins_id == EVI_ERROR) {
		LM_ERR("cannot register aor insert event\n");
		return -1;
	}

	ei_del_id = evi_publish_event(str_init(UL_EV_AOR_DELETE));
	if (ei_del_id == EVI_ERROR) {
		LM_ERR("cannot register aor delete event\n");
		return -1;
	}

	ei_c_ins_id = evi_publish_event(str_init(UL_EV_CT_INSERT));
	if (ei_c_ins_id == EVI_ERROR) {
		LM_ERR("cannot register contact insert event\n");
		return -1;
	}

	ei_c_update_id = evi_publish_event(str_init(UL_EV_CT_UPDATE));
	if (ei_c_update_id == EVI_ERROR) {
		LM_ERR("cannot register contact update event\n");
		return -1;
	}

	ei_c_del_id = evi_publish_event(str_init(UL_EV_CT_DELETE));
	if (ei_c_del_id == EVI_ERROR) {
		LM_ERR("cannot register contact delete event\n");
		return -1;
	}

	ei_c_refresh_id = evi_publish_event(str_init(UL_EV_CT_REFRESH));
	if (ei_c_refresh_id == EVI_ERROR) {
		LM_ERR("cannot register contact refresh event\n");
		return -1;
	}

	ei_c_latency_update_id = evi_publish_event(str_init(UL_EV_LATENCY_UPDATE));
	if (ei_c_latency_update_id == EVI_ERROR) {
		LM_ERR("cannot register contact latency update event\n");
		return -1;
	}

	/* AoR event params */

	ul_aor_event_params = pkg_malloc(sizeof(evi_params_t));
	if (!ul_aor_event_params) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(ul_aor_event_params, 0, sizeof(evi_params_t));

	ul_aor_event.domain = evi_param_create(ul_aor_event_params,
	                                _str(UL_EV_PARAM_DOMAIN));
	if (!ul_aor_event.domain) {
		LM_ERR("cannot create AoR domain parameter\n");
		return -1;
	}

	ul_aor_event.aor = evi_param_create(ul_aor_event_params,
	                                _str(UL_EV_PARAM_AOR));
	if (!ul_aor_event.domain) {
		LM_ERR("cannot create AOR parameter\n");
		return -1;
	}

	/* Contact event params */

	ul_contact_event_params = pkg_malloc(sizeof(evi_params_t));
	if (!ul_contact_event_params) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(ul_contact_event_params, 0, sizeof(evi_params_t));

	ul_ct_event.domain = evi_param_create(ul_contact_event_params,
	                          _str(UL_EV_PARAM_DOMAIN));
	if (!ul_ct_event.domain) {
		LM_ERR("cannot create contact domain parameter\n");
		return -1;
	}

	ul_ct_event.aor = evi_param_create(ul_contact_event_params,
	                          _str(UL_EV_PARAM_AOR));
	if (!ul_ct_event.aor) {
		LM_ERR("cannot create contact aor parameter\n");
		return -1;
	}

	ul_ct_event.uri = evi_param_create(ul_contact_event_params,
	                          _str(UL_EV_PARAM_CT_URI));
	if (!ul_ct_event.uri) {
		LM_ERR("cannot create contact address parameter\n");
		return -1;
	}

	ul_ct_event.received = evi_param_create(ul_contact_event_params,
	                          _str(UL_EV_PARAM_CT_RCV));
	if (!ul_ct_event.received) {
		LM_ERR("cannot create received parameter\n");
		return -1;
	}

	ul_ct_event.path = evi_param_create(ul_contact_event_params,
	                          _str(UL_EV_PARAM_CT_PATH));
	if (!ul_ct_event.path) {
		LM_ERR("cannot create path parameter\n");
		return -1;
	}

	ul_ct_event.qval = evi_param_create(ul_contact_event_params,
	                          _str(UL_EV_PARAM_CT_QVAL));
	if (!ul_ct_event.qval) {
		LM_ERR("cannot create Qval parameter\n");
		return -1;
	}

	ul_ct_event.user_agent = evi_param_create(ul_contact_event_params,
	                          _str(UL_EV_PARAM_CT_UA));
	if (!ul_ct_event.user_agent) {
		LM_ERR("cannot create user_agent parameter\n");
		return -1;
	}

	ul_ct_event.socket = evi_param_create(ul_contact_event_params,
	                          _str(UL_EV_PARAM_CT_SOCK));
	if (!ul_ct_event.socket) {
		LM_ERR("cannot create socket parameter\n");
		return -1;
	}

	ul_ct_event.bflags = evi_param_create(ul_contact_event_params,
	                          _str(UL_EV_PARAM_CT_BFL));
	if (!ul_ct_event.bflags) {
		LM_ERR("cannot create bflags parameter\n");
		return -1;
	}

	ul_ct_event.expires = evi_param_create(ul_contact_event_params,
	                          _str(UL_EV_PARAM_CT_EXP));
	if (!ul_ct_event.expires) {
		LM_ERR("cannot create expires parameter\n");
		return -1;
	}

	ul_ct_event.callid = evi_param_create(ul_contact_event_params,
	                          _str(UL_EV_PARAM_CT_CLID));
	if (!ul_ct_event.callid) {
		LM_ERR("cannot create callid parameter\n");
		return -1;
	}

	ul_ct_event.cseq = evi_param_create(ul_contact_event_params,
	                          _str(UL_EV_PARAM_CT_CSEQ));
	if (!ul_ct_event.cseq) {
		LM_ERR("cannot create cseq parameter\n");
		return -1;
	}

	ul_ct_event.attr = evi_param_create(ul_contact_event_params,
	                          _str(UL_EV_PARAM_CT_ATTR));
	if (!ul_ct_event.attr) {
		LM_ERR("cannot create attr parameter\n");
		return -1;
	}

	ul_ct_event.latency = evi_param_create(ul_contact_event_params,
	                          _str(UL_EV_PARAM_CT_LTCY));
	if (!ul_ct_event.latency) {
		LM_ERR("cannot create latency parameter\n");
		return -1;
	}

	ul_ct_event.shtag = evi_param_create(ul_contact_event_params,
	                          _str(UL_EV_PARAM_CT_SHTAG));
	if (!ul_ct_event.shtag) {
		LM_ERR("cannot create shtag parameter\n");
		return -1;
	}

	/* Contact PN event params */

	ul_contact_pn_event_params = pkg_malloc(sizeof(evi_params_t));
	if (!ul_contact_pn_event_params) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(ul_contact_pn_event_params, 0, sizeof(evi_params_t));

	ul_ct_pn_event.domain = evi_param_create(ul_contact_pn_event_params,
	                          _str(UL_EV_PARAM_DOMAIN));
	if (!ul_ct_pn_event.domain) {
		LM_ERR("cannot create contact domain parameter\n");
		return -1;
	}

	ul_ct_pn_event.aor = evi_param_create(ul_contact_pn_event_params,
	                          _str(UL_EV_PARAM_AOR));
	if (!ul_ct_pn_event.aor) {
		LM_ERR("cannot create contact aor parameter\n");
		return -1;
	}

	ul_ct_pn_event.uri = evi_param_create(ul_contact_pn_event_params,
	                          _str(UL_EV_PARAM_CT_URI));
	if (!ul_ct_pn_event.uri) {
		LM_ERR("cannot create contact address parameter\n");
		return -1;
	}

	ul_ct_pn_event.received = evi_param_create(ul_contact_pn_event_params,
	                          _str(UL_EV_PARAM_CT_RCV));
	if (!ul_ct_pn_event.received) {
		LM_ERR("cannot create received parameter\n");
		return -1;
	}

	ul_ct_pn_event.user_agent = evi_param_create(ul_contact_pn_event_params,
	                          _str(UL_EV_PARAM_CT_UA));
	if (!ul_ct_pn_event.user_agent) {
		LM_ERR("cannot create user_agent parameter\n");
		return -1;
	}

	ul_ct_pn_event.socket = evi_param_create(ul_contact_pn_event_params,
	                          _str(UL_EV_PARAM_CT_SOCK));
	if (!ul_ct_pn_event.socket) {
		LM_ERR("cannot create socket parameter\n");
		return -1;
	}

	ul_ct_pn_event.bflags = evi_param_create(ul_contact_pn_event_params,
	                          _str(UL_EV_PARAM_CT_BFL));
	if (!ul_ct_pn_event.bflags) {
		LM_ERR("cannot create bflags parameter\n");
		return -1;
	}

	ul_ct_pn_event.expires = evi_param_create(ul_contact_pn_event_params,
	                          _str(UL_EV_PARAM_CT_EXP));
	if (!ul_ct_pn_event.expires) {
		LM_ERR("cannot create expires parameter\n");
		return -1;
	}

	ul_ct_pn_event.callid = evi_param_create(ul_contact_pn_event_params,
	                          _str(UL_EV_PARAM_CT_CLID));
	if (!ul_ct_pn_event.callid) {
		LM_ERR("cannot create callid parameter\n");
		return -1;
	}

	ul_ct_pn_event.attr = evi_param_create(ul_contact_pn_event_params,
	                          _str(UL_EV_PARAM_CT_ATTR));
	if (!ul_ct_pn_event.attr) {
		LM_ERR("cannot create attr parameter\n");
		return -1;
	}

	ul_ct_pn_event.shtag = evi_param_create(ul_contact_pn_event_params,
	                          _str(UL_EV_PARAM_CT_SHTAG));
	if (!ul_ct_pn_event.shtag) {
		LM_ERR("cannot create shtag parameter\n");
		return -1;
	}

	ul_ct_pn_event.reason = evi_param_create(ul_contact_pn_event_params,
	                          _str(UL_EV_PARAM_CT_REASON));
	if (!ul_ct_pn_event.reason) {
		LM_ERR("cannot create reason parameter\n");
		return -1;
	}

	ul_ct_pn_event.req_callid = evi_param_create(ul_contact_pn_event_params,
	                          _str(UL_EV_PARAM_CT_RCLID));
	if (!ul_ct_pn_event.req_callid) {
		LM_ERR("cannot create req_callid parameter\n");
		return -1;
	}

	return 0;
}


/*! \brief
 * Raise an event when an AOR is inserted/deleted
 */
void ul_raise_aor_event(event_id_t _e, struct urecord* _r)
{
	if (_e == EVI_ERROR) {
		LM_ERR("event not yet registered %d\n", _e);
		return;
	}

	if (evi_param_set_str(ul_aor_event.domain, _r->domain) < 0) {
		LM_ERR("cannot set domain parameter\n");
		return;
	}

	if (evi_param_set_str(ul_aor_event.aor, &_r->aor) < 0) {
		LM_ERR("cannot set AOR parameter\n");
		return;
	}

	if (evi_raise_event(_e, ul_aor_event_params) < 0)
		LM_ERR("cannot raise event\n");
}


void ul_raise_contact_event(event_id_t _e, const ucontact_t *_c)
{
	if (_e == EVI_ERROR) {
		LM_ERR("event not yet registered %d\n", _e);
		return;
	}

	/* the domain */
	if (evi_param_set_str(ul_ct_event.domain, _c->domain) < 0) {
		LM_ERR("cannot set contact domain parameter\n");
		return;
	}

	/* the AOR */
	if (evi_param_set_str(ul_ct_event.aor, _c->aor) < 0) {
		LM_ERR("cannot set contact aor parameter\n");
		return;
	}

	/* the contact URI */
	if (evi_param_set_str(ul_ct_event.uri, &_c->c) < 0) {
		LM_ERR("cannot set contact URI parameter\n");
		return;
	}

	/* the received URI */
	if (evi_param_set_str(ul_ct_event.received, &_c->received) < 0) {
		LM_ERR("cannot set received parameter\n");
		return;
	}

	/* the PATH URI */
	if (evi_param_set_str(ul_ct_event.path, &_c->path) < 0) {
		LM_ERR("cannot set path parameter\n");
		return;
	}

	/* the Q value */
	if (evi_param_set_int(ul_ct_event.qval, &_c->q) < 0) {
		LM_ERR("cannot set Qval parameter\n");
		return;
	}

	/* the User Agent */
	if (evi_param_set_str(ul_ct_event.user_agent, &_c->user_agent) < 0) {
		LM_ERR("cannot set user_agent parameter\n");
		return;
	}

	/* the socket */
	if (evi_param_set_str(ul_ct_event.socket,
			(_c->sock ? &_c->sock->sock_str : _str(""))) < 0) {
		LM_ERR("cannot set socket parameter\n");
		return;
	}

	/* the Branch flags */
	if (evi_param_set_int(ul_ct_event.bflags, &_c->cflags) < 0) {
		LM_ERR("cannot set bflags parameter\n");
		return;
	}

	/* the Expires value */
	if (evi_param_set_int(ul_ct_event.expires, &_c->expires) < 0) {
		LM_ERR("cannot set expires parameter\n");
		return;
	}

	/* the Call-ID value */
	if (evi_param_set_str(ul_ct_event.callid, &_c->callid) < 0) {
		LM_ERR("cannot set callid parameter\n");
		return;
	}

	/* the CSeq value */
	if (evi_param_set_int(ul_ct_event.cseq, &_c->cseq) < 0) {
		LM_ERR("cannot set cseq parameter\n");
		return;
	}

	/* the ATTR value */
	if (evi_param_set_str(ul_ct_event.attr,
	                       _c->attr.len ? &_c->attr : _str("")) < 0) {
		LM_ERR("cannot set attr parameter\n");
		return;
	}

	/* the last known ping latency */
	if (evi_param_set_int(ul_ct_event.latency, &_c->sipping_latency) < 0) {
		LM_ERR("cannot set latency parameter\n");
		return;
	}

	/* the shared tag */
	if (evi_param_set_str(ul_ct_event.shtag,
		                   _c->shtag.s ? &_c->shtag : _str("")) < 0) {
		LM_ERR("cannot set shtag parameter\n");
		return;
	}

	if (evi_raise_event(_e, ul_contact_event_params) < 0)
		LM_ERR("cannot raise event\n");
}


static inline void _ul_raise_ct_refresh_event(
                const ucontact_t *_c, const str *reason, const str *req_callid)
{
	if (ei_c_refresh_id == EVI_ERROR) {
		LM_ERR("event not yet registered ("UL_EV_CT_REFRESH")\n");
		return;
	}

	/* the domain */
	if (evi_param_set_str(ul_ct_pn_event.domain, _c->domain) < 0) {
		LM_ERR("cannot set contact domain parameter\n");
		return;
	}

	/* the AOR */
	if (evi_param_set_str(ul_ct_pn_event.aor, _c->aor) < 0) {
		LM_ERR("cannot set contact aor parameter\n");
		return;
	}

	/* the contact URI */
	if (evi_param_set_str(ul_ct_pn_event.uri, &_c->c) < 0) {
		LM_ERR("cannot set contact URI parameter\n");
		return;
	}

	/* the received URI */
	if (evi_param_set_str(ul_ct_pn_event.received, &_c->received) < 0) {
		LM_ERR("cannot set received parameter\n");
		return;
	}

	/* the User Agent */
	if (evi_param_set_str(ul_ct_pn_event.user_agent, &_c->user_agent) < 0) {
		LM_ERR("cannot set user_agent parameter\n");
		return;
	}

	/* the socket */
	if (evi_param_set_str(ul_ct_pn_event.socket,
			(_c->sock ? &_c->sock->sock_str : _str(""))) < 0) {
		LM_ERR("cannot set socket parameter\n");
		return;
	}

	/* the Branch flags */
	if (evi_param_set_int(ul_ct_pn_event.bflags, &_c->cflags) < 0) {
		LM_ERR("cannot set bflags parameter\n");
		return;
	}

	/* the Expires value */
	if (evi_param_set_int(ul_ct_pn_event.expires, &_c->expires) < 0) {
		LM_ERR("cannot set expires parameter\n");
		return;
	}

	/* the Call-ID value */
	if (evi_param_set_str(ul_ct_pn_event.callid, &_c->callid) < 0) {
		LM_ERR("cannot set callid parameter\n");
		return;
	}

	/* the ATTR value */
	if (evi_param_set_str(ul_ct_pn_event.attr,
	                       _c->attr.len ? &_c->attr : _str("")) < 0) {
		LM_ERR("cannot set attr parameter\n");
		return;
	}

	/* the shared tag */
	if (evi_param_set_str(ul_ct_pn_event.shtag,
		                   _c->shtag.s ? &_c->shtag : _str("")) < 0) {
		LM_ERR("cannot set shtag parameter\n");
		return;
	}

	/* the contact refresh reason */
	if (evi_param_set_str(ul_ct_pn_event.reason, reason) < 0) {
		LM_ERR("cannot set the reason parameter\n");
		return;
	}

	/* the Call-ID of the pending request */
	if (req_callid &&
	        evi_param_set_str(ul_ct_pn_event.req_callid, req_callid) < 0) {
		LM_ERR("cannot set the req_callid parameter\n");
		return;
	}

	if (evi_raise_event(ei_c_refresh_id, ul_contact_pn_event_params) < 0)
		LM_ERR("cannot raise event\n");
}


static void ul_rpc_raise_ct_refresh(int _, void *_ev)
{
	struct ct_refresh_event_data *ev = (struct ct_refresh_event_data *)_ev;

	_ul_raise_ct_refresh_event(ev->ct, &ev->reason, &ev->req_callid);
	shm_free(ev);
}


void ul_raise_ct_refresh_event(const ucontact_t *c, const str *reason,
                               const str *req_callid)
{
#if !UL_ASYNC_CT_REFRESH
	_ul_raise_ct_refresh_event(c, reason, req_callid);
#else
	struct ct_refresh_event_data *ev;
	ucontact_t *ct;
	char *p;

	/* since we cannot send a (ucontact_t *), we must dup the data */
	ev = shm_malloc(sizeof *ev + sizeof *ct + sizeof *c->domain +
	            c->domain->len + sizeof *c->aor + c->aor->len + c->c.len +
	            c->received.len + c->path.len + c->user_agent.len +
	            (c->sock ? (sizeof *c->sock + c->sock->sock_str.len) : 0) +
	            c->callid.len + c->attr.len + c->shtag.len + reason->len +
	            (req_callid ? req_callid->len : 0));
	if (!ev) {
		LM_ERR("oom\n");
		return;
	}

	p = (char *)(ev + 1);

	ev->reason.s = p;
	ev->reason.len = reason->len;
	memcpy(p, reason->s, reason->len);
	p += reason->len;

	if (!req_callid) {
		memset(&ev->req_callid, 0, sizeof ev->req_callid);
	} else {
		ev->req_callid.s = p;
		ev->req_callid.len = req_callid->len;
		memcpy(p, req_callid->s, req_callid->len);
		p += req_callid->len;
	}

	ct = ev->ct = (ucontact_t *)p;
	p = (char *)(ct + 1);

	ct->domain = (str *)p;
	p += sizeof *ct->domain;

	ct->domain->s = p;
	str_cpy(ct->domain, c->domain);
	p += ct->domain->len;

	ct->aor = (str *)p;
	p += sizeof *ct->aor;

	ct->aor->s = p;
	str_cpy(ct->aor, c->aor);
	p += ct->aor->len;

	ct->c.s = p;
	str_cpy(&ct->c, &c->c);
	p += ct->c.len;

	ct->received.s = p;
	str_cpy(&ct->received, &c->received);
	p += ct->received.len;

	ct->path.s = p;
	str_cpy(&ct->path, &c->path);
	p += ct->path.len;

	ct->user_agent.s = p;
	str_cpy(&ct->user_agent, &c->user_agent);
	p += ct->user_agent.len;

	if (!c->sock) {
		ct->sock = NULL;
	} else {
		ct->sock = (struct socket_info *)p;
		p += sizeof *ct->sock;

		ct->sock->sock_str.s = p;
		str_cpy(&ct->sock->sock_str, &c->sock->sock_str);
		p += ct->sock->sock_str.len;
	}

	ct->callid.s = p;
	str_cpy(&ct->callid, &c->callid);
	p += ct->callid.len;

	ct->attr.s = p;
	str_cpy(&ct->attr, &c->attr);
	p += ct->attr.len;

	if (!c->shtag.s) {
		memset(&ct->shtag, 0, sizeof ct->shtag);
	} else {
		ct->shtag.s = p;
		str_cpy(&ct->shtag, &c->shtag);
	}

	ct->q = c->q;
	ct->cflags = c->cflags;
	ct->expires = c->expires;
	ct->cseq = c->cseq;
	ct->sipping_latency = c->sipping_latency;

	if (ipc_dispatch_rpc(ul_rpc_raise_ct_refresh, (void *)ev) != 0) {
		LM_ERR("failed to send RPC for "UL_EV_CT_REFRESH"\n");
		return;
	}
#endif
}
