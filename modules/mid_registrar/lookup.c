/*
 * contact lookup
 *
 * This module is intended to be used as a middle layer SIP component in
 * environments where a large proportion of SIP UAs (e.g. mobile devices)
 * register at high enough frequencies that they actually degrade the
 * performance of their registrars.
 *
 * Copyright (C) 2016-2020 OpenSIPS Solutions
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

#include "mid_registrar.h"
#include "lookup.h"
#include "encode.h"

#include "../../parser/parse_rr.h"
#include "../../parser/parse_uri.h"
#include "../../dset.h"
#include "../../mod_fix.h"
#include "../../lib/reg/common.h"

#include "../usrloc/usrloc.h"
#include "../usrloc/urecord.h"


#define ua_re_check(return) \
	if (flags & REG_LOOKUP_UAFILTER_FLAG) { \
		if (regexec(&ua_re, ptr->user_agent.s, 1, &ua_match, 0)) { \
			return; \
		} \
	}


int mid_reg_lookup(struct sip_msg *req, udomain_t *d, str *sflags, str *uri)
{
	struct sip_uri puri;
	unsigned int flags;
	int ret = LOOKUP_ERROR, pos, ruri_is_pushed = 0;
	int regexp_flags = 0, max_latency = 0;
	uint64_t contact_id;
	str aor;
	ucontact_t *ct;
	urecord_t *r;
	regex_t ua_re;

	if (reg_mode == MID_REG_THROTTLE_AOR)
		return lookup(req, d, sflags, uri, 0, mid_reg_update_aor);

	if (parse_lookup_flags(sflags, &flags, &ua_re, &regexp_flags,
	                       &max_latency) != 0) {
		LM_ERR("failed to parse flags: %.*s\n", sflags->len, sflags->s);
		return LOOKUP_ERROR;
	}

	ruri_is_pushed = flags & REG_LOOKUP_NO_RURI_FLAG;

	if (!uri)
		uri = GET_RURI(req);

	/* we're not in "throttle AoR" mode, so we expect a R-URI contact ID! */

	if (!req->callid && (parse_headers(req, HDR_CALLID_F, 0) < 0 ||
	                     !req->callid)) {
		LM_ERR("bad request or missing Call-ID hdr\n");
		return -1;
	}

	if (parse_uri(uri->s, uri->len, &puri) < 0) {
		LM_ERR("failed to parse R-URI <%.*s>, ci: %.*s\n", uri->len,
		       uri->s, req->callid->body.len, req->callid->body.s);
		return -1;
	}

	if (ctid_insertion == MR_APPEND_PARAM) {
		pos = get_uri_param_idx(&ctid_param, &puri);
		if (pos < 0) {
			LM_ERR("failed to locate our ';%.*s=' param in %sURI '%.*s', "
			       "ci = %.*s!\n", ctid_param.len, ctid_param.s,
			       uri ? "" : "R-", uri->len, uri->s, req->callid->body.len,
			       req->callid->body.s);
			return -1;
		}
		if (str2int64(&puri.u_val[pos], &contact_id) != 0) {
			LM_ERR("invalid contact_id in %sURI '%.*s', ci: %.*s\n",
			       uri ? "" : "R-", uri->len, uri->s, req->callid->body.len,
			       req->callid->body.s);
			return -1;
		}
	} else {
		if (str2int64(&puri.user, &contact_id) != 0) {
			LM_ERR("invalid contact_id in %sURI '%.*s', ci: %.*s\n",
			       uri ? "" : "R-", uri->len, uri->s, req->callid->body.len,
			       req->callid->body.s);
			return -1;
		}
	}

	LM_DBG("getting ucontact from contact_id %llu\n",
	       (unsigned long long)contact_id);

	update_act_time();

	ct = ul.get_ucontact_from_id(d, contact_id, &r);
	if (!ct) {
		LM_DBG("no record found for %.*s, ci: %.*s\n", uri->len, uri->s,
		       req->callid->body.len, req->callid->body.s);
		return -1;
	}

	aor = r->aor;

	switch (push_branch(req, ct, &ruri_is_pushed)) {
	case 0:
		ret = LOOKUP_OK;
		break;

	case 2:
		switch (pn_awake_pn_contacts(req, &ct, 1)) {
		case 1:
			ret = LOOKUP_PN_SENT;
			break;
		case 0:
			ret = LOOKUP_STOP_SCRIPT;
			break;
		default:
			ret = LOOKUP_ERROR;
			break;
		}
		break;

	default:
		ret = LOOKUP_ERROR;
	}

	ul.release_urecord(r, 0);
	ul.unlock_udomain(d, &aor);
	return ret;
}
