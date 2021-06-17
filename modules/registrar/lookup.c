/*
 * Lookup contacts in usrloc
 *
 * Copyright (C) 2001-2003 FhG Fokus
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

/*!
 * \file
 * \brief SIP registrar module - lookup contacts in usrloc
 * \ingroup registrar
 */

#include <string.h>

#include "../../ut.h"
#include "../../str.h"
#include "../../config.h"
#include "../../action.h"
#include "../../mod_fix.h"
#include "../../parser/parse_rr.h"
#include "../../parser/parse_from.h"
#include "../../lib/reg/common.h"
#include "../usrloc/usrloc.h"

#include "reg_mod.h"
#include "lookup.h"
#include "sip_msg.h"

#define GR_E_PART_SIZE	22
#define GR_A_PART_SIZE	14


int reg_lookup(struct sip_msg* _m, void* _t, str* flags_s, str* uri)
{
	return lookup(_m, _t, flags_s, uri, reg_use_domain, NULL);
}


struct to_body* select_uri(struct sip_msg* _m)
{
	if (_m->REQ_METHOD != METHOD_REGISTER) {
		if (parse_from_header(_m) < 0) {
			LM_ERR("failed to parse from!\n");
			return NULL;
		}

		return get_from(_m);

	} else {
		/* WARNING in msg_aor_parse the to header is checked in
		 * parse_reg_headers so no need to check it; take care when
		 * you use this function */
		return get_to(_m);
	}
}


/*
 * shall be done for all three functions
 * so why not use a macro
 *
 * USABLE VARS:
 * ud  - udomain_t
 * aor - extracted aor
 */

#define IS_FOUND  1
#define NOT_FOUND  -1
#define CHECK_DOMAIN(__d) \
	if (!__d) { \
		LM_ERR("no domain specified!\n"); \
		return -2; \
	}

int msg_aor_parse(struct sip_msg* _m, str *_aor, str *_saor)
{
	str uri, aor;
	struct to_body *hdr;

	if (parse_reg_headers(_m) < 0) {
		LM_ERR("unable to parse message\n");
		return -2;
	}

	/* we don't process replies */
	if (_m->first_line.type != SIP_REQUEST) {
		LM_ERR("message should be a request!\n");
		return -2;
	}

	if (!_aor) {
		hdr=select_uri(_m);
		if (!hdr) {
			LM_ERR("failed to get uri header!\n");
			return -2;
		}

		uri = hdr->uri;
	} else {
		uri = *_aor;
	}

	if (extract_aor(&uri, &aor, 0, 0, reg_use_domain) < 0) {
		LM_ERR("failed to extract address of record!\n");
		return -2;
	}

	*_saor = aor;

	return 0;
}



/*! \brief the is_registered() function
 * Return 1 if the AOR is registered, -1 otherwise
 * AOR comes from:
 *	- "from" header on REGISTER
 *	- "to" header on any other SIP REQUEST
 *	- aor parameter of the function
 */
int is_registered(struct sip_msg* _m, void *_d, str* _a)
{
	int ret=NOT_FOUND;
	urecord_t* r;
	ucontact_t *c;
	udomain_t* ud = (udomain_t*)_d;
	int_str istr;
	str aor;

	if (msg_aor_parse(_m, _a, &aor)) {
		LM_ERR("failed to parse!\n");
		return -1;
	}

	CHECK_DOMAIN(ud);
	update_act_time();

	LM_DBG("checking aor <%.*s>\n",aor.len,aor.s);
	ul.lock_udomain(ud, &aor);
	if (ul.get_urecord(ud, &aor, &r) == 0) {
		for ( c=r->contacts; c && (ret==NOT_FOUND); c=c->next ) {
			if (VALID_CONTACT(c,get_act_time())) {
				/* populate the 'attributes' avp */
				if (attr_avp_name != -1) {
					istr.s = c->attr;
					if (add_avp_last(AVP_VAL_STR, attr_avp_name, istr) != 0) {
						LM_ERR("Failed to populate attr avp!\n");
					}
				}
				ret = IS_FOUND;
			}
		}
	}
	ul.unlock_udomain(ud, &aor);

	return ret;
}

/*! \brief the is_contact_registered() function
 * Return 1 if the contact and/or callid is registered
 * for a given AOR, -1 when not found
 * AOR comes from:
 *	- "from" header on REGISTER
 *	- "to" header on any other SIP REQUEST
 *	- aor parameter of the function
 *
 * Contact comes from:
 *  - first valid "Contact" header when neither contact nor
 *  callid params are provided
 *  - the contact parameter (third parameter)
 */
int is_contact_registered(struct sip_msg* _m, void *_d, str* _a,
							str* _c, str* _cid)
{
	int exp;

	str callid = {NULL, 0};
	str curi = {NULL, 0};
	str aor;

	udomain_t* ud = (udomain_t*)_d;
	urecord_t* r;

	contact_t* ct;
	ucontact_t *c;


	if (msg_aor_parse(_m, _a, &aor)) {
		LM_ERR("failed to parse!\n");
		return -1;
	}

	CHECK_DOMAIN(ud);

	if (!_c && !_cid) {
		LM_DBG("Neither contact nor callid supplied!"
				"First valid contact from the message body shall be used!\n");
		if (!_m->contact ||
				!(ct=(((contact_body_t*)_m->contact->parsed)->contacts)))
			goto out_no_contact;

		/* getting first non expired contact */
		while (ct) {
			calc_contact_expires(_m, ct->expires, &exp, NULL);
			if (exp)
				break;
			ct = ct->next;
		}

		if (!ct)
			goto out_no_contact;

		curi = ct->uri;
	} else {
		if (_c)
			curi = *_c;

		if (_cid)
			callid = *_cid;
	}

	ul.lock_udomain(ud, &aor);
	if (ul.get_urecord(ud, &aor, &r) == 1) {
		LM_DBG("AoR '%.*s' not found in usrloc!\n", aor.len, aor.s);
		ul.unlock_udomain(ud, &aor);
		return NOT_FOUND;
	}

	/* callid not defined; contact might be defined or not */
	if (!_cid) {
		LM_DBG("found AoR, searching for ct: '%.*s'\n", curi.len, curi.s);

		for (c=r->contacts; c; c=c->next) {
			if (str_match(&curi, &c->c))
				goto out_found_unlock;
		}
	/* contact not defined; callid defined */
	} else if (!_c && _cid) {
		LM_DBG("found AoR, searching for Call-ID: '%.*s'\n",
		       callid.len, callid.s);

		for (c=r->contacts; c; c=c->next) {
			if (str_match(&callid, &c->callid))
				goto out_found_unlock;
		}
	/* both callid and contact defined */
	} else {
		LM_DBG("found AoR, searching for ct: '%.*s' and Call-ID: '%.*s'\n",
		       curi.len, curi.s, callid.len, callid.s);

		for (c=r->contacts; c; c=c->next) {
			if (str_match(&curi, &c->c) && str_match(&callid, &c->callid))
				goto out_found_unlock;
		}
	}

	ul.unlock_udomain(ud, &aor);
	return NOT_FOUND;

out_no_contact:
	LM_WARN("Contact and callid not provided!"
			"Message does not have any valid contacts!\n");
	return -1;

out_found_unlock:
	ul.unlock_udomain(ud, &aor);
	return IS_FOUND;
}

/*! \brief the is_ip_registered() function
 * Return 1 if the IPs are registered for the received parameter
 * for a contact inside the given AOR
 * -1 when not found
 *
 * IPs comes from:
 * - the IPs avp given as a third parameter
 */
int is_ip_registered(struct sip_msg* _m, void* _d, str* _a, pv_spec_t *spec)
{
	str aor;
	str pv_host={NULL, 0};
	struct sip_uri tmp_uri;
	str uri;
	char is_avp=1;
	udomain_t* ud = (udomain_t*)_d;
	urecord_t* r;
	ucontact_t *c;
	struct usr_avp *avp;
	pv_value_t val;
	struct ip_addr *ipp, ip;

	if (msg_aor_parse(_m, _a, &aor)) {
		LM_ERR("failed to parse!\n");
		return -2;
	}

	CHECK_DOMAIN(ud);

	if (spec == NULL) {
		LM_NOTICE("nothing to compare! exiting...\n");
		return -1;
	} else if (spec->type != PVT_AVP) {
		is_avp=0;
		if (pv_get_spec_value( _m, spec, &val)!=0) {
			LM_ERR("failed to get IP PV value!\n");
			return -1;
		}

		if ((val.flags&PV_VAL_STR)==0) {
			LM_ERR("IP should be a string!\n");
			return -1;
		}
		pv_host = val.rs;
	}

	ul.lock_udomain(ud, &aor);
	if (ul.get_urecord(ud, &aor, &r) == 1) {
		LM_DBG("no contact found for aor=<%.*s>\n", aor.len, aor.s);
		goto out_unlock_notfound;
	}

	for (c=r->contacts; c; c=c->next) {
		if (c->received.len && c->received.s)
			uri = c->received;
		else
			uri = c->c;

		/* extract the IP from contact */
		if (parse_uri(uri.s, uri.len, &tmp_uri) < 0) {
			LM_ERR("contact [%.*s] is not valid! Will not store it!\n",
				  uri.len, uri.s);
		}
		if ( (ipp=str2ip(&tmp_uri.host))==NULL &&
		(ipp=str2ip6(&tmp_uri.host))==NULL ) {
			LM_ERR("failed to get IP from contact/received <%.*s>, skipping\n",
				tmp_uri.host.len, tmp_uri.host.s);
			continue;
		}
		ip = *ipp;

		if (!is_avp) {

			/* convert the param IP to ip_addr too*/
			if ( (ipp=str2ip(&pv_host))==NULL &&
			(ipp=str2ip6(&pv_host))==NULL ) {
				LM_ERR("param IP  <%.*s> is not valid, skipping\n",
					pv_host.len, pv_host.s);
				continue;
			}

			if (ip_addr_cmp(&ip, ipp))
				goto out_unlock_found;

		} else {

			avp = NULL;
			while ((avp=search_first_avp(spec->pvp.pvn.u.isname.type,
					spec->pvp.pvn.u.isname.name.n, (int_str*)&pv_host,avp))) {
				if (!(avp->flags&AVP_VAL_STR)) {
					LM_NOTICE("avp value should be string\n");
					continue;
				}

				/* convert the param IP to ip_addr too*/
				if ( (ipp=str2ip(&pv_host))==NULL &&
				(ipp=str2ip6(&pv_host))==NULL ) {
					LM_ERR("param IP  <%.*s> is not valid, skipping\n",
						pv_host.len, pv_host.s);
					continue;
				}

				if (ip_addr_cmp(&ip, ipp))
					goto out_unlock_found;
			}
		}
	}

out_unlock_notfound:
	ul.unlock_udomain(ud, &aor);
	return NOT_FOUND;
out_unlock_found:
	ul.unlock_udomain(ud, &aor);
	return IS_FOUND;
}

#undef CHECK_DOMAIN
#undef IS_FOUND
#undef NOT_FOUND

