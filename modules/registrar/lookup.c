/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
#include "common.h"
#include "regtime.h"
#include "reg_mod.h"
#include "lookup.h"


#define GR_E_PART_SIZE	22
#define GR_A_PART_SIZE	14

#define allowed_method(_msg, _c, _f) \
	( !((_f)&REG_LOOKUP_METHODFILTER_FLAG) || \
		((_msg)->REQ_METHOD)&((_c)->methods) )

static int ua_check(str ua, regex_t *re)
{
	char tmp;
	regmatch_t ua_match;
	int result;

	tmp = *(ua.s+ua.len);
	strncpy(ua_buf, ua.s, ua.len);
	result = regexec(re, ua_buf, 1, &ua_match, 0);
	pkg_free(ua_buf);
	return result;
}

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
	regex_t ua_re;
	int regexp_flags = 0;
	pv_value_t val;
	int_str istr;
	str sip_instance = {0,0},call_id = {0,0};

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
				case 'u':
					if (flags_s.s[++res] != '/') {
						LM_ERR("no regexp after 'u' flag");
						break;
					}
					res++;
					ua = flags_s.s+res;
					res = flags_s.len - 1;
					while (res > ua-flags_s.s && flags_s.s[res] != '/') res--;
					if (flags_s.s[res] == '/') {
						flags_s.s[res] = '\0';
					} else {
						LM_ERR("no regexp after 'u' flag");
						break;
					}
					flags |= REG_LOOKUP_UAFILTER_FLAG;
					LM_DBG("found regexp /%s/", ua);
					break;
				case 'i': regexp_flags |= REG_ICASE; break;
				case 'e': regexp_flags |= REG_EXTENDED; break;
				default: LM_WARN("unsuported flag %c \n",flags_s.s[res]);
			}
		}
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
		if (regcomp(&ua_re, ua, regexp_flags) != 0) {
			LM_ERR("bad regexp '%s'\n", ua);
			return -1;
		}
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

	if (flags & REG_LOOKUP_UAFILTER_FLAG) {
		if (ua_check(ptr->user_agent, &ua_re)) {
			ret = -1;
			ptr = ptr->next;
			goto search_valid_contact;
		}
	}

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
				if (it->instance.len-2 == sip_instance.len &&
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

		set_ruri_q(ptr->q);

		setbflag( 0, ptr->cflags);

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

	for( ; ptr ; ptr = ptr->next ) {
		if (VALID_CONTACT(ptr, act_time) && allowed_method(_m,ptr,flags)) {
			path_dst.len = 0;
			if(ptr->path.s && ptr->path.len
			&& get_path_dst_uri(&ptr->path, &path_dst) < 0) {
				LM_ERR("failed to get dst_uri for Path\n");
				continue;
			}

			if (flags & REG_LOOKUP_UAFILTER_FLAG) {
				if (ua_check(ptr->user_agent, &ua_re)) {
					continue;
				}
			}

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

done:
	ul.release_urecord(r, 0);
	ul.unlock_udomain((udomain_t*)_t, &aor);
	regfree(&ua_re);
	return ret;
}


/*! \brief the is_registered() function
 * Return true if the AOR in the Request-URI is registered,
 * it is similar to lookup but registered neither rewrites
 * the Request-URI nor appends branches
 */
int registered(struct sip_msg* _m, char* _t, char* _s, char *_c)
{
	str uri, aor;
	urecord_t* r;
	ucontact_t* ptr;
	pv_value_t val;
	str callid;
	int res;
	int_str istr;

	/* get the AOR */
	if (_s) {
		if (pv_get_spec_value( _m, (pv_spec_p)_s, &val)!=0) {
			LM_ERR("failed to getAOR PV value\n");
			return -1;
		}
		if ( (val.flags&PV_VAL_STR)==0 ) {
			LM_ERR("AOR PV vals is not string\n");
			return -1;
		}
		uri = val.rs;
	} else {
		if (_m->first_line.type!=SIP_REQUEST) {
			LM_ERR("no AOR and called for a reply!");
			return -1;
		}
		if (_m->new_uri.s) uri = _m->new_uri;
		else uri = _m->first_line.u.request.uri;
	}

	if (extract_aor(&uri, &aor,0,0) < 0) {
		LM_ERR("failed to extract address of record\n");
		return -1;
	}

	/* get the callid */
	if (_c) {
		if (pv_get_spec_value( _m, (pv_spec_p)_c, &val)!=0) {
			LM_ERR("failed to get callid PV value\n");
			return -1;
		}
		if ( (val.flags&PV_VAL_STR)==0 ) {
			LM_ERR("callid PV vals is not string\n");
			return -1;
		}
		callid = val.rs;
	} else {
		callid.s = NULL;
		callid.len = 0;
	}

	ul.lock_udomain((udomain_t*)_t, &aor);
	res = ul.get_urecord((udomain_t*)_t, &aor, &r);

	if (res < 0) {
		ul.unlock_udomain((udomain_t*)_t, &aor);
		LM_ERR("failed to query usrloc\n");
		return -1;
	}

	if (res == 0) {
		ptr = r->contacts;
		while (ptr && !VALID_CONTACT(ptr, act_time)) {
			ptr = ptr->next;
		}

		for( ; ptr ; ptr=ptr->next ) {
			if (callid.len==0 || (callid.len==ptr->callid.len &&
			memcmp(callid.s,ptr->callid.s,callid.len)==0 ) ) {

				/* also populate the 'attributes' avp */
				if (attr_avp_name != -1) {
				    istr.s = ptr->attr;

				    if (add_avp_last(AVP_VAL_STR, attr_avp_name, istr) != 0)
				        LM_ERR("Failed to populate attr avp!\n");
				}

				ul.unlock_udomain((udomain_t*)_t, &aor);
				LM_DBG("'%.*s' found in usrloc\n", aor.len, ZSW(aor.s));
				return 1;
			}
		}
	}

	ul.unlock_udomain((udomain_t*)_t, &aor);
	LM_DBG("'%.*s' not found in usrloc\n", aor.len, ZSW(aor.s));
	return -1;
}
