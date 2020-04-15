/*
 * Lookup contacts in usrloc
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * ---------
 * 2003-03-12 added support for zombie state (nils)
 */
/*!
 * \file
 * \brief SIP registrar module - lookup contacts in usrloc
 * \ingroup registrar
 */


#include <string.h>
#include "../../ut.h"
#include "../../dset.h"
#include "../../str.h"
#include "../../config.h"
#include "../../action.h"
#include "../../mod_fix.h"
#include "../../parser/parse_rr.h"
#include "../usrloc/usrloc.h"
#include "../../parser/parse_from.h"

#include "../../lib/reg/sip_msg.h"
#include "../../lib/reg/regtime.h"
#include "../../lib/reg/config.h"
#include "../../lib/reg/ci.h"
#include "../../lib/reg/pn.h"

#include "reg_mod.h"
#include "lookup.h"
#include "sip_msg.h"

#define GR_E_PART_SIZE	22
#define GR_A_PART_SIZE	14

#define allowed_method(_msg, _c, _f) \
	( !((_f)&REG_LOOKUP_METHODFILTER_FLAG) || \
		((_msg)->REQ_METHOD)&((_c)->methods) )

ucontact_t **selected_cts; /* always has an extra terminating NULL ptr */
int selected_cts_sz = 20;

static int cmp_ucontact(const void *_ct1, const void *_ct2)
{
	ucontact_t *ct1 = *(ucontact_t **)_ct1, *ct2 = *(ucontact_t **)_ct2;

	if (ct1->sipping_latency == 0) {
		if (ct2->sipping_latency == 0)
			return 0;

		return 1;
	}

	if (ct2->sipping_latency == 0)
		return -1;

	return ct1->sipping_latency - ct2->sipping_latency;
}

/**
 * Return:
 *     0 - success: contact pushed
 *     1 - success: nothing to push
 *     2 - success: contact not pushed, as it must be awoken by a PN first
 *    -1 - failure to push to R-URI
 *    -2 - failure to push to new branch
 */
int push_branch(struct sip_msg *msg, ucontact_t *ct, int *ruri_is_pushed)
{
	str path_dst;
	int_str istr;
	str *ct_uri, _ct_uri;
	struct sip_uri puri;

	if (!ct)
		return 1;

	if (pn_enable && pn_has_uri_params(&ct->c, &puri)) {
		if (pn_required(ct))
			return 2;

		if (pn_remove_uri_params(&puri, ct->c.len, &_ct_uri) != 0) {
			LM_ERR("failed to remove PN URI params\n");
			return *ruri_is_pushed ? -1 : -2;
		}

		ct_uri = &_ct_uri;
	} else {
		ct_uri = &ct->c;
	}

	if (*ruri_is_pushed)
		goto append_branch;

	LM_DBG("setting msg R-URI <%.*s>\n", ct_uri->len, ct_uri->s);

	if (set_ruri(msg, ct_uri) < 0) {
		LM_ERR("unable to rewrite Request-URI\n");
		return -2;
	}

	/* If a Path is present, use first path-uri in favour of
	 * received-uri because in that case the last hop towards the uac
	 * has to handle NAT. - agranig */
	if (ct->path.s && ct->path.len) {
		if (get_path_dst_uri(&ct->path, &path_dst) < 0) {
			LM_ERR("failed to get dst_uri for Path\n");
			return -2;
		}
		if (set_path_vector(msg, &ct->path) < 0) {
			LM_ERR("failed to set path vector\n");
			return -2;
		}
		if (set_dst_uri(msg, &path_dst) < 0) {
			LM_ERR("failed to set dst_uri of Path\n");
			return -2;
		}
	} else if (ct->received.s && ct->received.len) {
		if (set_dst_uri(msg, &ct->received) < 0)
			return -2;
	}

	if (!(ct->flags & FL_EXTRA_HOP)) {
		set_ruri_q(msg, ct->q);

		setbflag(msg, 0, ct->cflags);

		if (ct->sock)
			msg->force_send_socket = ct->sock;
	}

	*ruri_is_pushed = 1;
	goto add_attr_avp;

append_branch:
	LM_DBG("setting branch R-URI <%.*s>\n", ct_uri->len, ct_uri->s);

	if (ct->flags & FL_EXTRA_HOP) {
		if (append_branch(msg, ct_uri, &ct->received, &msg->path_vec,
		                  get_ruri_q(msg), getb0flags(msg),
		                  msg->force_send_socket) == -1) {
			LM_ERR("failed to append a branch\n");
			return -1;
		}

	} else {
		path_dst.len = 0;
		if (!ZSTR(ct->path) && get_path_dst_uri(&ct->path, &path_dst) < 0) {
			LM_ERR("failed to get dst_uri for Path\n");
			return -1;
		}

		/* The same as for the first contact applies for branches
		 * regarding path vs. received. */
		if (append_branch(msg, ct_uri,
		           path_dst.len ? &path_dst : &ct->received,
		           &ct->path, ct->q, ct->cflags, ct->sock) == -1) {
			LM_ERR("failed to append a branch\n");
			return -1;
		}
	}

add_attr_avp:
	if (attr_avp_name != -1) {
		istr.s = ct->attr;
		if (add_avp_last(AVP_VAL_STR, attr_avp_name, istr) != 0)
			LM_ERR("Failed to populate attr avp!\n");
	}

	return 0;
}

ucontact_t **select_contacts(struct sip_msg *msg, ucontact_t *contacts,
                        int flags, const str *sip_instance, const str *call_id,
                        const regex_t *ua_re, int max_latency, int *ret)
{
	int count = 0, have_gruu = 0;
	ucontact_t *it, *ct, **doubled;
	regmatch_t ua_match;

	for (ct = contacts; ct; ct = ct->next) {
		LM_DBG("ct: %.*s\n", ct->c.len, ct->c.s);
		if (!VALID_CONTACT(ct, get_act_time())) {
			LM_DBG("skipping expired contact %.*s\n", ct->c.len, ct->c.s);
			continue;
		}

		if (*ret < 0)
			*ret = -2;

		if (!allowed_method(msg, ct, flags))
			continue;

		if (*ret < 0)
			*ret = -1;

		if ((flags & REG_LOOKUP_UAFILTER_FLAG) &&
			regexec(ua_re, ct->user_agent.s, 1, &ua_match, 0))
			continue;

		if (max_latency && ct->sipping_latency > max_latency)
			continue;

		/* have temp gruu */
		if (!ZSTR(*sip_instance)) {
			have_gruu = 1;
			LM_DBG("ruri has gruu\n");

			if (ZSTR(ct->instance) || ct->instance.len-2 != sip_instance->len ||
			        memcmp(ct->instance.s+1, sip_instance->s, sip_instance->len)) {

				LM_DBG("no match to sip instance - [%.*s] - [%.*s]\n",
				       ZSTR(ct->instance) ? 0 : ct->instance.len-2,
				       ZSTR(ct->instance) ? NULL : ct->instance.s+1,
				       sip_instance->len, sip_instance->s);
				/* not the targeted instance, search some more */
				continue;
			}

			LM_DBG("matched sip instance\n");
		}

		/* have pub gruu */
		if (!ZSTR(*call_id)) {
			/* decide whether GRUU is expired or not
			 *
			 * first - match call-id */
			if (ct->callid.len != call_id->len ||
			        memcmp(ct->callid.s, call_id->s, call_id->len)) {
				LM_DBG("no match to call id - [%.*s] - [%.*s]\n",
				       ct->callid.len, ct->callid.s, call_id->len, call_id->s);
				continue;
			}

			/* matched call-id, check if there are newer contacts with
			 * same sip instace but newer last_modified */

			it = ct->next;
			while (it) {
				if (VALID_CONTACT(it, get_act_time())) {
					if (it->instance.len-2 == sip_instance->len &&
					    sip_instance->s && memcmp(it->instance.s+1,
							sip_instance->s,sip_instance->len) == 0)
						if (it->last_modified > ct->last_modified) {
							/* same instance id, but newer modified ->
							 * expired GRUU, no match at all */
							return NULL;
						}
				}

				it = it->next;
			}
		}

		*ret = 1;

		if (count == selected_cts_sz - 1) {
			doubled = pkg_realloc(selected_cts,
					2 * selected_cts_sz * sizeof *selected_cts);
			if (!doubled) {
				LM_ERR("oom\n");
				return NULL;
			}

			selected_cts = doubled;
			selected_cts_sz *= 2;
		}

		selected_cts[count++] = ct;

		/* If we got to this point and the URI had a ;gr parameter and it was
		 * matched to a contact -> no point in selecting additional contacts */
		if (have_gruu)
			goto skip_remaining;
	}

skip_remaining:
	selected_cts[count] = NULL;

	if (flags & REG_LOOKUP_LATENCY_SORT_FLAG)
		qsort(selected_cts, count, sizeof *selected_cts, cmp_ucontact);

	return selected_cts;
}

int parse_lookup_flags(const str *input, unsigned int *flags, regex_t *ua_re,
                        int *regexp_flags, int *max_latency)
{
	char *ua = NULL;
	char* re_end = NULL;
	int i, re_len = 0;

	for (i = 0; i < input->len; i++) {
		switch (input->s[i]) {
		case 'm': *flags |= REG_LOOKUP_METHODFILTER_FLAG; break;
		case 'b': *flags |= REG_LOOKUP_NOBRANCH_FLAG; break;
		case 'g': *flags |= REG_LOOKUP_GLOBAL_FLAG; break;
		case 'r': *flags |= REG_BRANCH_AOR_LOOKUP_FLAG; break;
		case 'B': *flags |= REG_LOOKUP_NO_RURI_FLAG; break;
		case 'u':
			if (input->s[i+1] != '/') {
				LM_ERR("no regexp start after 'u' flag\n");
				break;
			}
			i++;
			re_end = q_memchr(input->s + i + 1, '/', input->len - i - 1);
			if (!re_end) {
				LM_ERR("no regexp end after 'u' flag\n");
				break;
			}
			i++;
			re_len = re_end - input->s - i;
			if (re_len == 0) {
				LM_ERR("empty regexp\n");
				break;
			}
			ua = input->s + i;
			*flags |= REG_LOOKUP_UAFILTER_FLAG;
			LM_DBG("found regexp /%.*s/", re_len, ua);

			i += re_len;
			break;
		case 'i': *regexp_flags |= REG_ICASE; break;
		case 'e': *regexp_flags |= REG_EXTENDED; break;
		case 'y':
			*max_latency = 0;
			while (i<input->len-1 && isdigit(input->s[i+1])) {
				*max_latency = *max_latency*10 + input->s[i+1] - '0';
				i++;
			}

			if (*max_latency)
				*flags |= REG_LOOKUP_MAX_LATENCY_FLAG;
			else
				*flags &= ~REG_LOOKUP_MAX_LATENCY_FLAG;
			break;
		case 'Y': *flags |= REG_LOOKUP_LATENCY_SORT_FLAG; break;
		default: LM_WARN("unsupported flag %c \n", input->s[i]);
		}
	}

	LM_DBG("final flags: %d\n", *flags);

	if (*flags & REG_LOOKUP_UAFILTER_FLAG) {
		ua[re_len] = '\0';
		if (regcomp(ua_re, ua, *regexp_flags) != 0) {
			LM_ERR("bad regexp '%s'\n", ua);
			ua[re_len] = '/';
			return -1;
		}
		ua[re_len] = '/';
	}

	return 0;
}

/*! \brief
 * Lookup contact in the database and rewrite Request-URI
 * \return: -1 : not found
 *          -2 : found but method not allowed
 *          -3 : error
 */
int lookup(struct sip_msg* _m, void* _t, str* flags_s, str* uri)
{
	static char urimem[MAX_BRANCHES-1][MAX_URI_SIZE];
	static str branch_uris[MAX_BRANCHES-1];
	int idx = 0, nbranches = 0, tlen;
	char *turi;
	qvalue_t tq;

	urecord_t* r;
	str aor;
	ucontact_t *ct, **ptr, **pn_cts, **cts;
	int max_latency = 0, ruri_is_pushed = 0, regexp_flags = 0;
	unsigned int flags;
	int rc, ret = -1, have_pn_cts = 0;
	str sip_instance = STR_NULL, call_id = STR_NULL;
	regex_t ua_re;

	flags = 0;
	if (flags_s && flags_s->s[0] != '\0') {
		if (parse_lookup_flags(flags_s, &flags, &ua_re, &regexp_flags,
		                       &max_latency) != 0) {
			LM_ERR("failed to parse flags: %.*s\n", flags_s->len, flags_s->s);
			return -1;
		}
	}

	if (flags & REG_BRANCH_AOR_LOOKUP_FLAG) {
		/* extract all the branches for further usage */
		while (
			(turi=get_branch(nbranches, &tlen, &tq, NULL, NULL, NULL, NULL))
				) {
			/* copy uri */
			branch_uris[nbranches].s = urimem[nbranches];
			if (tlen) {
				memcpy(branch_uris[nbranches].s, turi, tlen);
				branch_uris[nbranches].len = tlen;
			} else {
				*branch_uris[nbranches].s  = '\0';
				branch_uris[nbranches].len = 0;
			}

			nbranches++;
		}
		clear_branches();
	}

	if (!uri)
		uri = GET_RURI(_m);

	if (extract_aor(uri, &aor, &sip_instance, &call_id) < 0) {
		LM_ERR("failed to extract address of record\n");
		return -3;
	}

	update_act_time();

fetch_urecord:
	ul.lock_udomain((udomain_t*)_t, &aor);
	if (ul.cluster_mode == CM_FEDERATION_CACHEDB
	        && (flags & REG_LOOKUP_GLOBAL_FLAG))
		rc = ul.get_global_urecord((udomain_t*)_t, &aor, &r);
	else
		rc = ul.get_urecord((udomain_t*)_t, &aor, &r);

	if (rc > 0) {
		LM_DBG("'%.*s' Not found in usrloc\n", aor.len, ZSW(aor.s));
		ul.unlock_udomain((udomain_t*)_t, &aor);
		return -1;
	}

	print_urecord(r);

	cts = select_contacts(_m, r->contacts, flags, &sip_instance, &call_id,
	                      &ua_re, max_latency, &ret);

	/* do not attempt to push anything to RURI if the flags say so */
	if (flags & REG_LOOKUP_NO_RURI_FLAG)
		ruri_is_pushed = 1;

	for (ptr = pn_cts = cts; *ptr; ptr++) {
		rc = push_branch(_m, *ptr, &ruri_is_pushed);
		if (rc == -2) {
			ret = -3;
			goto done;
		} else if (rc == 2) {
			*pn_cts++ = *ptr;
		}

		if (rc == 0 && (flags & REG_LOOKUP_NOBRANCH_FLAG))
			goto done;
	}

	if (ul.cluster_mode == CM_FEDERATION_CACHEDB
	        && (flags & REG_LOOKUP_GLOBAL_FLAG)) {
		for (ct = r->remote_aors; ct; ct = ct->next) {
			rc = push_branch(_m, ct, &ruri_is_pushed);
			if (rc == 0 && (flags & REG_LOOKUP_NOBRANCH_FLAG))
				goto done;
		}
	}

	if ((flags & REG_BRANCH_AOR_LOOKUP_FLAG) && idx < nbranches) {
		/* relsease old aor lock */
		ul.release_urecord(r, 0);
		ul.unlock_udomain((udomain_t *)_t, &aor);

		uri = &branch_uris[idx];
		LM_DBG("getting contacts from aor [%.*s] "
		       "in branch %d\n", aor.len, aor.s, idx);

		if (extract_aor(uri, &aor, NULL, &call_id) < 0) {
			LM_ERR("failed to extract address of record for branch uri\n");
			ret = -3;
			goto out_cleanup;
		}

		idx++;
		goto fetch_urecord;
	}

done:
	if (ruri_is_pushed)
		ret = 1;

	ul.release_urecord(r, 0);
	ul.unlock_udomain((udomain_t*)_t, &aor);
out_cleanup:
	if (flags & REG_LOOKUP_UAFILTER_FLAG)
		regfree(&ua_re);
	return ret;
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

	if (extract_aor(&uri, &aor, 0, 0) < 0) {
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
		LM_DBG("%.*s not found in usrloc!\n", aor.len, aor.s);
		ul.unlock_udomain(ud, &aor);
		return NOT_FOUND;
	}

	/* callid not defined; contact might be defined or not */
	if (!_cid) {
		for (c=r->contacts; c; c=c->next) {
			if (!str_strcmp(&curi, &c->c))
				goto out_found_unlock;
		}
	/* contact not defined; callid defined */
	} else if (!_c && _cid) {
		for (c=r->contacts; c; c=c->next) {
			if (!str_strcmp(&callid, &c->callid))
				goto out_found_unlock;
		}
	/* both callid and contact defined */
	} else {
		for (c=r->contacts; c; c=c->next) {
			if (!str_strcmp(&curi, &c->c) &&
					!str_strcmp(&callid, &c->callid))
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

