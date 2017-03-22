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
#include "common.h"
#include "regtime.h"
#include "reg_mod.h"
#include "lookup.h"
#include "sip_msg.h"

#define GR_E_PART_SIZE	22
#define GR_A_PART_SIZE	14

#define allowed_method(_msg, _c, _f) \
	( !((_f)&REG_LOOKUP_METHODFILTER_FLAG) || \
		((_msg)->REQ_METHOD)&((_c)->methods) )

#define ua_re_check(return) \
	if (flags & REG_LOOKUP_UAFILTER_FLAG) { \
		if (regexec(&ua_re, ptr->user_agent.s, 1, &ua_match, 0)) { \
			return; \
		} \
	}

unsigned int nbranches;

static char urimem[MAX_BRANCHES-1][MAX_URI_SIZE];
static str branch_uris[MAX_BRANCHES-1];


/*! \brief
 * Lookup contact in the database and rewrite Request-URI
 * \return: -1 : not found
 *          -2 : found but method not allowed
 *          -3 : error
 */
int lookup(struct sip_msg* _m, char* _t, char* _f, char* _s)
{
	unsigned int flags;
	urecord_t* r;
	str aor, uri;
	ucontact_t* ptr,*it;
	int res;
	int ret;
	str path_dst;
	str flags_s;
	char* ua = NULL;
	char* re_end = NULL;
	int re_len = 0;
	char tmp;
	regex_t ua_re;
	int regexp_flags = 0;
	regmatch_t ua_match;
	pv_value_t val;
	int_str istr;
	str sip_instance = {0,0},call_id = {0,0};

	/* branch index */
	int idx;

	/* temporary branch values*/
	int tlen;
	char *turi;

	qvalue_t tq;

	flags = 0;
	if (_f && _f[0]!=0) {
		if (fixup_get_svalue( _m, (gparam_p)_f, &flags_s)!=0) {
			LM_ERR("invalid owner uri parameter");
			return -1;
		}
		for( res=0 ; res< flags_s.len ; res++ ) {
			switch (flags_s.s[res]) {
				case 'm': flags |= REG_LOOKUP_METHODFILTER_FLAG; break;
				case 'b': flags |= REG_LOOKUP_NOBRANCH_FLAG; break;
				case 'r': flags |= REG_BRANCH_AOR_LOOKUP_FLAG; break;
				case 'u':
					if (flags_s.s[res+1] != '/') {
						LM_ERR("no regexp after 'u' flag");
						break;
					}
					res++;
					if ((re_end = strrchr(flags_s.s+res+1, '/')) == NULL) {
						LM_ERR("no regexp after 'u' flag");
						break;
					}
					res++;
					re_len = re_end-flags_s.s-res;
					if (re_len == 0) {
						LM_ERR("empty regexp");
						break;
					}
					ua = flags_s.s+res;
					flags |= REG_LOOKUP_UAFILTER_FLAG;
					LM_DBG("found regexp /%.*s/", re_len, ua);
					res += re_len;
					break;
				case 'i': regexp_flags |= REG_ICASE; break;
				case 'e': regexp_flags |= REG_EXTENDED; break;
				default: LM_WARN("unsupported flag %c \n",flags_s.s[res]);
			}
		}
	}
	if (flags&REG_BRANCH_AOR_LOOKUP_FLAG) {
		/* extract all the branches for further usage */
		nbranches = 0;
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
		idx=0;
	}


	if (_s) {
		if (pv_get_spec_value( _m, (pv_spec_p)_s, &val)!=0) {
			LM_ERR("failed to get PV value\n");
			return -1;
		}
		if ( (val.flags&PV_VAL_STR)==0 ) {
			LM_ERR("PV vals is not string\n");
			return -1;
		}
		uri = val.rs;
	} else {
		if (_m->new_uri.s) uri = _m->new_uri;
		else uri = _m->first_line.u.request.uri;
	}

	if (extract_aor(&uri, &aor,&sip_instance,&call_id) < 0) {
		LM_ERR("failed to extract address of record\n");
		return -3;
	}

	get_act_time();

	ul.lock_udomain((udomain_t*)_t, &aor);
	res = ul.get_urecord((udomain_t*)_t, &aor, &r);
	if (res > 0) {
		LM_DBG("'%.*s' Not found in usrloc\n", aor.len, ZSW(aor.s));
		ul.unlock_udomain((udomain_t*)_t, &aor);
		return -1;
	}

	if (flags & REG_LOOKUP_UAFILTER_FLAG) {
		tmp = *(ua+re_len);
		*(ua+re_len) = '\0';
		if (regcomp(&ua_re, ua, regexp_flags) != 0) {
			LM_ERR("bad regexp '%s'\n", ua);
			*(ua+re_len) = tmp;
			return -1;
		}
		*(ua+re_len) = tmp;
	}


	ptr = r->contacts;
	ret = -1;
	/* look first for an un-expired and suported contact */
search_valid_contact:
	while ( (ptr) &&
	!(VALID_CONTACT(ptr,act_time) && (ret=-2) && allowed_method(_m,ptr,flags)))
		ptr = ptr->next;
	if (ptr==0) {
		/* nothing found */
		LM_DBG("nothing found !\n");
		goto done;
	}

	ua_re_check(
		ret = -1;
		ptr = ptr->next;
		goto search_valid_contact
	);

	if (sip_instance.len && sip_instance.s) {
		LM_DBG("ruri has gruu in lookup\n");
		/* uri has GRUU */
		if (ptr->instance.len-2 != sip_instance.len ||
				memcmp(ptr->instance.s+1,sip_instance.s,sip_instance.len)) {
			LM_DBG("no match to sip instace - [%.*s] - [%.*s]\n",ptr->instance.len-2,ptr->instance.s+1,
					sip_instance.len,sip_instance.s);
			/* not the targeted instance, search some more */
			ptr = ptr->next;
			goto search_valid_contact;
		}

		LM_DBG("matched sip instace\n");
	}

	if (call_id.len && call_id.s) {
		/* decide whether GRUU is expired or not
		 *
		 * first - match call-id */
		if (ptr->callid.len != call_id.len ||
				memcmp(ptr->callid.s,call_id.s,call_id.len)) {
			LM_DBG("no match to call id - [%.*s] - [%.*s]\n",ptr->callid.len,ptr->callid.s,
					call_id.len,call_id.s);
			ptr = ptr->next;
			goto search_valid_contact;
		}

		/* matched call-id, check if there are newer contacts with
		 * same sip instace bup newer last_modified */

		it = ptr->next;
		while ( it ) {
			if (VALID_CONTACT(it,act_time)) {
				if (it->instance.len-2 == sip_instance.len && sip_instance.s &&
						memcmp(it->instance.s+1,sip_instance.s,sip_instance.len) == 0)
					if (it->last_modified > ptr->last_modified) {
						/* same instance id, but newer modified -> expired GRUU, no match at all */
						break;
					}
			}
			it=it->next;
		}

		if (it != NULL) {
			ret = -1;
			goto done;
		}
	}

	LM_DBG("found a complete match\n");

	ret = 1;
	if (ptr) {
		LM_DBG("setting as ruri <%.*s>\n",ptr->c.len,ptr->c.s);
		if (set_ruri(_m, &ptr->c) < 0) {
			LM_ERR("unable to rewrite Request-URI\n");
			ret = -3;
			goto done;
		}

		/* If a Path is present, use first path-uri in favour of
		 * received-uri because in that case the last hop towards the uac
		 * has to handle NAT. - agranig */
		if (ptr->path.s && ptr->path.len) {
			if (get_path_dst_uri(&ptr->path, &path_dst) < 0) {
				LM_ERR("failed to get dst_uri for Path\n");
				ret = -3;
				goto done;
			}
			if (set_path_vector(_m, &ptr->path) < 0) {
				LM_ERR("failed to set path vector\n");
				ret = -3;
				goto done;
			}
			if (set_dst_uri(_m, &path_dst) < 0) {
				LM_ERR("failed to set dst_uri of Path\n");
				ret = -3;
				goto done;
			}
		} else if (ptr->received.s && ptr->received.len) {
			if (set_dst_uri(_m, &ptr->received) < 0) {
				ret = -3;
				goto done;
			}
		}

		set_ruri_q( _m, ptr->q);

		setbflag( _m, 0, ptr->cflags);

		if (ptr->sock)
			_m->force_send_socket = ptr->sock;

		/* populate the 'attributes' avp */
		if (attr_avp_name != -1) {
			istr.s = ptr->attr;
			if (add_avp_last(AVP_VAL_STR, attr_avp_name, istr) != 0) {
				LM_ERR("Failed to populate attr avp!\n");
			}
		}

		ptr = ptr->next;
	}

	/* Append branches if enabled */
	/* If we got to this point and the URI had a ;gr parameter and it was matched
	 * to a contact. No point in branching */
	if ( flags&REG_LOOKUP_NOBRANCH_FLAG || (sip_instance.len && sip_instance.s) ) goto done;
	LM_DBG("looking for branches\n");

	do {
		for( ; ptr ; ptr = ptr->next ) {
			if (VALID_CONTACT(ptr, act_time) && allowed_method(_m,ptr,flags)) {
				path_dst.len = 0;
				if(ptr->path.s && ptr->path.len
				&& get_path_dst_uri(&ptr->path, &path_dst) < 0) {
					LM_ERR("failed to get dst_uri for Path\n");
					continue;
				}

				ua_re_check(continue);

				/* The same as for the first contact applies for branches
				 * regarding path vs. received. */
				LM_DBG("setting branch <%.*s>\n",ptr->c.len,ptr->c.s);
				if (append_branch(_m,&ptr->c,path_dst.len?&path_dst:&ptr->received,
				&ptr->path, ptr->q, ptr->cflags, ptr->sock) == -1) {
					LM_ERR("failed to append a branch\n");
					/* Also give a chance to the next branches*/
					continue;
				}

				/* populate the 'attributes' avp */
				if (attr_avp_name != -1) {
					istr.s = ptr->attr;
					if (add_avp_last(AVP_VAL_STR, attr_avp_name, istr) != 0) {
						LM_ERR("Failed to populate attr avp!\n");
					}
				}
			}
		}
		/* 0 branches condition also filled; idx initially -1*/
		if (!(flags&REG_BRANCH_AOR_LOOKUP_FLAG) || idx == nbranches)
			goto done;


		/* relsease old aor lock */
		ul.unlock_udomain((udomain_t*)_t, &aor);
		ul.release_urecord(r, 0);

		/* idx starts from -1 */
		uri = branch_uris[idx];
		if (extract_aor(&uri, &aor, NULL, &call_id) < 0) {
			LM_ERR("failed to extract address of record for branch uri\n");
			return -3;
		}

		/* release old urecord */

		/* get lock on new aor */
		LM_DBG("getting contacts from aor [%.*s]"
					"in branch %d\n", aor.len, aor.s, idx);
		ul.lock_udomain((udomain_t*)_t, &aor);
		res = ul.get_urecord((udomain_t*)_t, &aor, &r);

		if (res > 0) {
			LM_DBG("'%.*s' Not found in usrloc\n", aor.len, ZSW(aor.s));
			goto done;
		}
		idx++;
		ptr = r->contacts;
	} while (1);

done:
	ul.release_urecord(r, 0);
	ul.unlock_udomain((udomain_t*)_t, &aor);
	if (flags & REG_LOOKUP_UAFILTER_FLAG) {
		regfree(&ua_re);
	}
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

int msg_aor_parse(struct sip_msg* _m, char *_aor, str *_saor)
{
	str uri, aor;
	pv_value_t val;
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
		if (pv_get_spec_value(_m, (pv_spec_p)_aor, &val)) {
			LM_ERR("failed to get aor PV value!\n");
			return -1;
		}

		if ((val.flags&PV_VAL_STR) == 0) {
			LM_ERR("aor PV vals is not string\n");
			return -1;
		}
		uri = val.rs;
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
int is_registered(struct sip_msg* _m, char *_d, char* _a)
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
	get_act_time();

	LM_DBG("checking aor <%.*s>\n",aor.len,aor.s);
	ul.lock_udomain(ud, &aor);
	if (ul.get_urecord(ud, &aor, &r) == 0) {
		for ( c=r->contacts; c && (ret==NOT_FOUND); c=c->next ) {
			if (VALID_CONTACT(c,act_time)) {
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
int is_contact_registered(struct sip_msg* _m, char *_d, char* _a,
							char* _c, char* _cid)
{
	int exp;

	str aor;
	str callid = {NULL, 0};
	str curi = {NULL, 0};
	pv_value_t val;

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
		if (_c) {
			if (pv_get_spec_value(_m, (pv_spec_p)_c, &val)!=0 ||
			(val.flags&PV_VAL_STR)==0 ) {
				LM_ERR("failed to retrieve string value from CONTACT "
					"parameter!\n");
				return -1;
			}
			curi = val.rs;
		}

		if (_cid) {
			if (pv_get_spec_value(_m, (pv_spec_p)_cid, &val)!=0 ||
			(val.flags&PV_VAL_STR)==0 ) {
				LM_ERR("failed to retrieve string value from CALLID "
					"parameter!\n");
				return -1;
			}
			callid = val.rs;
		}
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
int is_ip_registered(struct sip_msg* _m, char* _d, char* _a, char *_out_pv)
{
	str aor;
	str host, pv_host={NULL, 0};

	int start;
	char is_avp=1;

	udomain_t* ud = (udomain_t*)_d;

	urecord_t* r;

	ucontact_t *c;

	struct usr_avp *avp;
	pv_spec_p spec = (pv_spec_p)_out_pv;
	pv_value_t val;


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
		if (!c->received.len || !c->received.s || c->received.len < 4)
			continue;

		/* 'sip:' or 'sips:' ?; is this sane? FIXME if problems */
		start    = c->received.s[3]==':'?4:5;
		host.s   = c->received.s   + start;
		host.len = c->received.len - start;

		if (!is_avp) {
			if (pv_host.len <= host.len
				&& !memcmp(host.s, pv_host.s, pv_host.len))
				goto out_unlock_found;

			/* skip the part with avp */
			continue;
		}

		avp = NULL;
		while ((avp=search_first_avp(spec->pvp.pvn.u.isname.type,
					spec->pvp.pvn.u.isname.name.n, (int_str*)&pv_host,avp))) {
			if (!(avp->flags&AVP_VAL_STR)) {
				LM_NOTICE("avp value should be string\n");
				continue;
			}

			if (pv_host.len <= host.len
					&& !memcmp(host.s, pv_host.s, pv_host.len))
				goto out_unlock_found;
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

