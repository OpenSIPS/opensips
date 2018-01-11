/*
 * functions that attach data to usrloc contacts/aors
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "../../ut.h"
#include "../../lib/reg/regtime.h"

#include "../usrloc/urecord.h"

#include "mid_registrar.h"
#include "ul_storage.h"

str ul_key_from              = str_init("F");
str ul_key_to                = str_init("T");
str ul_key_main_reg_uri      = str_init("ru");
str ul_key_main_reg_next_hop = str_init("hop");
str ul_key_callid            = str_init("CID");
str ul_key_last_cseq         = str_init("Seq");
str ul_key_ct_uri            = str_init("Con");
str ul_key_expires           = str_init("exp");
str ul_key_expires_out       = str_init("expO");
str ul_key_last_reg_ts       = str_init("LRTs");
str ul_key_skip_dereg        = str_init("noDR");

int store_urecord_data(urecord_t *r, struct mid_reg_info *mri,
            const str *ct_uri, int expires_out, int last_reg_ts, int last_cseq)
{
	int_str_t value;

	/* integers */
	value.is_str = 0;

	value.i = expires_out;
	if (!ul_api.put_urecord_key(r, &ul_key_expires_out, &value))
		return -1;

	value.i = last_reg_ts;
	if (!ul_api.put_urecord_key(r, &ul_key_last_reg_ts, &value))
		return -1;

	value.i = last_cseq;
	if (!ul_api.put_urecord_key(r, &ul_key_last_cseq, &value))
		return -1;

	/* strings */
	value.is_str = 1;

	value.s = mri->from;
	if (!ul_api.put_urecord_key(r, &ul_key_from, &value))
		return -1;

	value.s = mri->to;
	if (!ul_api.put_urecord_key(r, &ul_key_to, &value))
		return -1;

	value.s = mri->callid;
	if (!ul_api.put_urecord_key(r, &ul_key_callid, &value))
		return -1;

	value.s = mri->main_reg_uri;
	if (!ul_api.put_urecord_key(r, &ul_key_main_reg_uri, &value))
		return -1;

	if (!ZSTR(mri->main_reg_next_hop)) {
		value.s = mri->main_reg_next_hop;
		if (!ul_api.put_urecord_key(r, &ul_key_main_reg_next_hop, &value))
			return -1;
	}

	value.s = *ct_uri;
	if (!ul_api.put_urecord_key(r, &ul_key_ct_uri, &value))
		return -1;

	return 0;
}

int update_urecord_data(urecord_t *r, int no_rpl_contacts, const str *callid,
                        int last_cseq)
{
	int_str_t value, *cur_callid, *cseq;
	unsigned int last_reg_ts;

	cur_callid = ul_api.get_urecord_key(r, &ul_key_callid);
	if (!cur_callid) {
		LM_ERR("callid not found!, $ci=%.*s\n", callid->len, callid->s);
		return -1;
	}

	/*
	 * the AoR registration update may sometimes get forwarded
	 * under a different Call-ID, when aggregating contacts
	 */
	if (str_strcmp(&cur_callid->s, callid) != 0) {
		value.is_str = 1;
		value.s = *callid;
		if (!ul_api.put_urecord_key(r, &ul_key_callid, &value))
			return -1;

		value.is_str = 0;
		value.i = last_cseq;
		if (!ul_api.put_urecord_key(r, &ul_key_last_cseq, &value))
			return -1;
	} else {
		/* same Call-ID - choose the larger CSeq */
		cseq = ul_api.get_urecord_key(r, &ul_key_last_cseq);
		if (!cseq) {
			LM_ERR("cseq not found!, $ci=%.*s\n", callid->len, callid->s);
			return -1;
		}

		if (cseq->i < last_cseq) {
			value.is_str = 0;
			value.i = last_cseq;
			if (!ul_api.put_urecord_key(r, &ul_key_last_cseq, &value))
				return -1;
		}
	}

	value.is_str = 0;

	if (no_rpl_contacts) {
		last_reg_ts = 0;
		value.i = 1;
		if (!ul_api.put_urecord_key(r, &ul_key_skip_dereg, &value))
			return -1;
	} else {
		last_reg_ts = get_act_time();
	}

	value.i = last_reg_ts;
	if (!ul_api.put_urecord_key(r, &ul_key_last_reg_ts, &value))
		return -1;

	return 0;
}

int store_ucontact_data(ucontact_t *c, struct mid_reg_info *mri,
                        const str *ct_uri, int expires, int expires_out,
                        int last_reg_ts, int last_cseq)
{
	int_str_t value;

	/* integers */
	value.is_str = 0;

	value.i = expires;
	if (!ul_api.put_ucontact_key(c, &ul_key_expires, &value))
		return -1;

	value.i = expires_out;
	if (!ul_api.put_ucontact_key(c, &ul_key_expires_out, &value))
		return -1;

	value.i = last_reg_ts;
	if (!ul_api.put_ucontact_key(c, &ul_key_last_reg_ts, &value))
		return -1;

	value.i = last_cseq;
	if (!ul_api.put_ucontact_key(c, &ul_key_last_cseq, &value))
		return -1;

	/* strings */
	value.is_str = 1;

	value.s = mri->from;
	if (!ul_api.put_ucontact_key(c, &ul_key_from, &value))
		return -1;

	value.s = mri->to;
	if (!ul_api.put_ucontact_key(c, &ul_key_to, &value))
		return -1;

	value.s = mri->callid;
	if (!ul_api.put_ucontact_key(c, &ul_key_callid, &value))
		return -1;

	value.s = mri->main_reg_uri;
	if (!ul_api.put_ucontact_key(c, &ul_key_main_reg_uri, &value))
		return -1;

	if (!ZSTR(mri->main_reg_next_hop)) {
		value.s = mri->main_reg_next_hop;
		if (!ul_api.put_ucontact_key(c, &ul_key_main_reg_next_hop, &value))
			return -1;
	}

	value.s = *ct_uri;
	if (!ul_api.put_ucontact_key(c, &ul_key_ct_uri, &value))
		return -1;

	return 0;
}

int update_ucontact_data(ucontact_t *c, int expires, int expires_out,
                         int last_cseq)
{
	int_str_t value;

	value.is_str = 0;

	value.i = expires;
	if (!ul_api.put_ucontact_key(c, &ul_key_expires, &value))
		return -1;

	value.i = expires_out;
	if (!ul_api.put_ucontact_key(c, &ul_key_expires_out, &value))
		return -1;

	value.i = last_cseq;
	if (!ul_api.put_ucontact_key(c, &ul_key_last_cseq, &value))
		return -1;

	value.i = get_act_time();
	if (!ul_api.put_ucontact_key(c, &ul_key_last_reg_ts, &value))
		return -1;

	return 0;
}
