/*
 * mid-registrar User location callbacks
 *
 * This module is intended to be used as a middle layer SIP component in
 * environments where a large proportion of SIP UAs (e.g. mobile devices)
 * register at high enough frequencies that they actually degrade the
 * performance of their registrars.
 *
 * Copyright (C) 2016 OpenSIPS Solutions
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
 *  2016-10-31 initial version (liviu)
 */

#include "../usrloc/ul_callback.h"

#include "../../parser/contact/contact.h"
#include "../tm/tm_load.h"
#include "../tm/dlg.h"
#include "../../lib/reg/rerrno.h"
#include "../../lib/reg/regtime.h"

#include "mid_registrar.h"
#include "ul_storage.h"

char extra_hdrs_buf[512];
static str extra_hdrs={extra_hdrs_buf, 512};

static int build_unregister_hdrs(const str *ct_uri)
{
	char *p;

	p = extra_hdrs.s;
	memcpy(p, contact_hdr.s, contact_hdr.len);
	p += contact_hdr.len;

	LM_DBG("building contact from uri '%.*s'\n", ct_uri->len, ct_uri->s);

	*p++ = '<';
	memcpy(p, ct_uri->s, ct_uri->len);
	p += ct_uri->len;
	*p++ = '>';

	*p++ = ';';
	memcpy(p, expires_param.s, expires_param.len);
	p += expires_param.len;
	*p++ = '=';

	*p++ = '0';
	memcpy(p, CRLF, CRLF_LEN); p += CRLF_LEN;

	extra_hdrs.len = (int)(p - extra_hdrs.s);
	LM_DBG("extra hdrs: '%.*s'\n", extra_hdrs.len, extra_hdrs.s);

	return 0;
}

static void reg_tm_cback(struct cell *t, int type, struct tmcb_params *ps)
{
	LM_DBG(">> [REPLY] UNREGISTER !\n");
}

static int send_unregister(str *from, str *to, str *ruri, str *callid,
                           unsigned int last_cseq, str *obp, str *ct_uri)
{
	dlg_t *dlg;
	int ret;

	/* create a tm dialog in preparation for our De-REGISTER */
	if (tm_api.new_auto_dlg_uac(from, to, ruri, callid, NULL, &dlg)) {
		LM_ERR("failed to create new TM dlg\n");
		return -1;
	}
	dlg->state = DLG_CONFIRMED;

	/* t_request_within() will increment it for us */
	dlg->loc_seq.value = last_cseq;

	if (!ZSTRP(obp)) {
		LM_DBG("adding next hop: %.*s\n", obp->len, obp->s);
		dlg->obp = *obp;
	}

	if (build_unregister_hdrs(ct_uri) != 0) {
		LM_ERR("failed to build unregister headers\n");
		return -1;
	}

	ret = tm_api.t_request_within(
		&register_method,	/* method */
		&extra_hdrs,		/* extra headers*/
		NULL,			/* body */
		dlg,		/* dialog structure*/
		reg_tm_cback,		/* callback function */
		NULL,	/* callback param */
		NULL);	/* function to release the parameter */

	tm_api.free_dlg(dlg);

	return (ret == 1 ? 0 : ret);
}

static int unregister_contact(ucontact_t *c)
{
	int_str_t *value;
	str *from, *to, *ruri, *callid, *obp = NULL, *ct;
	unsigned int last_cseq;

	value = ul_api.get_ucontact_key(c, &ul_key_from);
	if (!value) {
		LM_ERR("'from' key not found, skipping De-REGISTER\n");
		return -1;
	}
	from = &value->s;

	value = ul_api.get_ucontact_key(c, &ul_key_to);
	if (!value) {
		LM_ERR("'to' key not found, skipping De-REGISTER\n");
		return -1;
	}
	to = &value->s;

	value = ul_api.get_ucontact_key(c, &ul_key_main_reg_uri);
	if (!value) {
		LM_ERR("'main_reg_uri' key not found, skipping De-REGISTER\n");
		return -1;
	}
	ruri = &value->s;

	value = ul_api.get_ucontact_key(c, &ul_key_callid);
	if (!value) {
		LM_ERR("'callid' key not found, skipping De-REGISTER\n");
		return -1;
	}
	callid = &value->s;

	value = ul_api.get_ucontact_key(c, &ul_key_main_reg_next_hop);
	if (value)
		obp = &value->s;

	value = ul_api.get_ucontact_key(c, &ul_key_ct_uri);
	if (!value) {
		LM_ERR("'ct_uri' key not found, skipping De-REGISTER\n");
		return -1;
	}
	ct = &value->s;

	value = ul_api.get_ucontact_key(c, &ul_key_last_cseq);
	if (!value) {
		LM_ERR("'last_cseq' key not found, skipping De-REGISTER\n");
		return -1;
	}
	last_cseq = value->i;

	return send_unregister(from, to, ruri, callid, last_cseq, obp, ct);
}

static int unregister_record(urecord_t *r)
{
	int_str_t *value;
	str *from, *to, *ruri, *callid, *obp = NULL, *ct;
	unsigned int last_cseq;

	value = ul_api.get_urecord_key(r, &ul_key_from);
	if (!value) {
		LM_ERR("'from' key not found, skipping De-REGISTER\n");
		return -1;
	}
	from = &value->s;

	value = ul_api.get_urecord_key(r, &ul_key_to);
	if (!value) {
		LM_ERR("'to' key not found, skipping De-REGISTER\n");
		return -1;
	}
	to = &value->s;

	value = ul_api.get_urecord_key(r, &ul_key_main_reg_uri);
	if (!value) {
		LM_ERR("'main_reg_uri' key not found, skipping De-REGISTER\n");
		return -1;
	}
	ruri = &value->s;

	value = ul_api.get_urecord_key(r, &ul_key_callid);
	if (!value) {
		LM_ERR("'callid' key not found, skipping De-REGISTER\n");
		return -1;
	}
	callid = &value->s;

	value = ul_api.get_urecord_key(r, &ul_key_main_reg_next_hop);
	if (value)
		obp = &value->s;

	value = ul_api.get_urecord_key(r, &ul_key_ct_uri);
	if (!value) {
		LM_ERR("'ct_uri' key not found, skipping De-REGISTER\n");
		return -1;
	}
	ct = &value->s;

	value = ul_api.get_urecord_key(r, &ul_key_last_cseq);
	if (!value) {
		LM_ERR("'last_cseq' key not found, skipping De-REGISTER\n");
		return -1;
	}
	last_cseq = value->i;

	return send_unregister(from, to, ruri, callid, last_cseq, obp, ct);
}

void mid_reg_ct_event(void *binding, ul_cb_type type)
{
	ucontact_t *c = (ucontact_t *)binding;
	int_str_t *skip_dereg;

	LM_DBG("Contact callback (%d): contact='%.*s'\n", type, c->c.len, c->c.s);

	if (type & (UL_CONTACT_DELETE|UL_CONTACT_EXPIRE)) {
		if (reg_mode == MID_REG_THROTTLE_CT) {
			skip_dereg = ul_api.get_ucontact_key(c, &ul_key_skip_dereg);
			if (skip_dereg && skip_dereg->i == 1)
				return;

			if (unregister_contact(c) != 0)
				LM_ERR("failed to unregister contact\n");
		}
	}
}

void mid_reg_aor_event(void *binding, ul_cb_type type)
{
	urecord_t *r = (urecord_t *)binding;
	int_str_t *skip_dereg;

	LM_DBG("AOR callback (%d): contact='%.*s'\n", type,
	       r->aor.len, r->aor.s);

	if (type & (UL_AOR_DELETE|UL_AOR_EXPIRE)) {
		skip_dereg = ul_api.get_urecord_key(r, &ul_key_skip_dereg);
		if (skip_dereg && skip_dereg->i == 1)
			return;

		if (unregister_record(r) != 0)
			LM_ERR("failed to unregister contact\n");
	}
}
