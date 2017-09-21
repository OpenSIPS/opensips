/*
 * contact lookup
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
 *  2016-10-23 initial version (liviu)
 */

#include "mid_registrar.h"
#include "lookup.h"
#include "encode.h"

#include "../../lib/reg/regtime.h"
#include "../../lib/reg/ci.h"
#include "../../parser/parse_rr.h"
#include "../../parser/parse_uri.h"
#include "../../dset.h"

#include "../../mod_fix.h"

#include "../usrloc/usrloc.h"
#include "../usrloc/urecord.h"


#define allowed_method(_msg, _c, _f) \
	( !((_f)&REG_LOOKUP_METHODFILTER_FLAG) || \
		((_msg)->REQ_METHOD)&((_c)->methods) )

#define ua_re_check(return) \
	if (flags & REG_LOOKUP_UAFILTER_FLAG) { \
		if (regexec(&ua_re, ptr->user_agent.s, 1, &ua_match, 0)) { \
			return; \
		} \
	}

#define REG_LOOKUP_METHODFILTER_FLAG   (1<<0)
#define REG_LOOKUP_NOBRANCH_FLAG       (1<<1)
#define REG_LOOKUP_UAFILTER_FLAG       (1<<2)
#define REG_BRANCH_AOR_LOOKUP_FLAG     (1<<3)

char uri_buf[MAX_URI_SIZE];
unsigned int nbranches;
static char urimem[MAX_BRANCHES-1][MAX_URI_SIZE];
static str branch_uris[MAX_BRANCHES-1];

int get_match_token(str *uri, str *out_tok, struct sip_uri *out_puri, int *out_idx)
{
	struct sip_uri puri;
	int i;

	if (parse_uri(uri->s, uri->len, &puri) < 0) {
		LM_ERR("failed to parse contact <%.*s>\n", uri->len, uri->s);
		return -1;
	}

	if (matching_mode == MATCH_BY_PARAM) {
		for (i = 0; i < puri.u_params_no; i++) {
			if (!str_strcmp(&puri.u_name[i], &matching_param)) {
				*out_tok = puri.u_val[i];
				if (out_idx)
					*out_idx = i;
				break;
			}
		}

		if (!out_tok->s || out_tok->len <= 0) {
			LM_ERR("a Contact from main registrar (%.*s) is missing the '%.*s'"
			       " hf parameter\n", uri->len, uri->s,
			       matching_param.len, matching_param.s);
			return -1;
		}
	} else {
		*out_tok = puri.user;

		if (!out_tok->s || out_tok->len <= 0) {
			LM_ERR("missing SIP user in Contact from main registrar (%.*s)\n",
			       uri->len, uri->s);
			return -1;
		}
	}

	if (out_puri)
		*out_puri = puri;

	return 0;
}

int mid_reg_lookup(struct sip_msg* _m, char* _t, char* _f, char* _s)
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
	str pst, dec_tok, match_tok, hostport;
	struct sip_uri dec_uri;
	int i;

	/* branch index */
	int idx;

	/* temporary branch values*/
	int tlen;
	char *turi;

	qvalue_t tq;

	LM_DBG("mid_reg_lookup ... \n");

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
		uri = *GET_RURI(_m);
	}

	if (reg_mode != MID_REG_THROTTLE_AOR && insertion_mode == INSERT_BY_CONTACT) {
		if (get_match_token(&uri, &match_tok, NULL, NULL) != 0) {
			LM_ERR("failed to get match token\n");
			return -1;
		}

		if (decrypt_str(&match_tok, &dec_tok)) {
			LM_ERR("failed to decrypt matching Contact param (%.*s=%.*s)\n",
			       matching_param.len, matching_param.s,
			       match_tok.len, match_tok.s);
			return -1;
		}

		LM_DBG("dec URI: %.*s\n", dec_tok.len, dec_tok.s);

		if (parse_uri(dec_tok.s, dec_tok.len, &dec_uri) < 0) {
			LM_ERR("failed to parse dec URI <%.*s>\n", dec_tok.len, dec_tok.s);
			return -1;
		}

		hostport = dec_uri.host;
		if (dec_uri.port.len > 0)
			hostport.len = dec_uri.port.s + dec_uri.port.len - dec_uri.host.s;

		/* replace the host:port part */
		dec_uri.port.s = NULL;
		dec_uri.host = hostport;

		/* remove the match parameter */
		for (i = 0; i < dec_uri.u_params_no; i++) {
			if (str_strcmp(&dec_uri.u_name[i], &matching_param) == 0) {
				dec_uri.u_name[i].s = NULL;
				break;
			}
		}

		pst.s = uri_buf;
		pst.len = MAX_URI_SIZE;
		if (print_uri(&dec_uri, &pst) != 0) {
			LM_ERR("failed to print URI\n");
			return -1;
		}

		LM_DBG("printed URI: %.*s\n", pst.len, pst.s);

		pkg_free(dec_tok.s);

		if (!_s) {
			if (set_ruri(_m, &pst) != 0) {
				LM_ERR("failed to set R-URI\n");
				return -1;
			}
		}
	}

	if (reg_mode != MID_REG_THROTTLE_AOR) {
		return 1;
	}

	if (extract_aor(&uri, &aor,&sip_instance,&call_id) < 0) {
		LM_ERR("failed to extract address of record\n");
		return -3;
	}

	update_act_time();

	ul_api.lock_udomain((udomain_t*)_t, &aor);
	res = ul_api.get_urecord((udomain_t*)_t, &aor, &r);
	if (res > 0) {
		LM_DBG("'%.*s' Not found in usrloc\n", aor.len, ZSW(aor.s));
		ul_api.unlock_udomain((udomain_t*)_t, &aor);
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
	!(VALID_CONTACT(ptr,get_act_time()) && (ret=-2) && allowed_method(_m,ptr,flags)))
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
			if (VALID_CONTACT(it,get_act_time())) {
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
			if (VALID_CONTACT(ptr, get_act_time()) && allowed_method(_m,ptr,flags)) {
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
		ul_api.unlock_udomain((udomain_t*)_t, &aor);
		ul_api.release_urecord(r, 0);

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
		ul_api.lock_udomain((udomain_t*)_t, &aor);
		res = ul_api.get_urecord((udomain_t*)_t, &aor, &r);

		if (res > 0) {
			LM_DBG("'%.*s' Not found in usrloc\n", aor.len, ZSW(aor.s));
			goto done;
		}
		idx++;
		ptr = r->contacts;
	} while (1);

done:
	ul_api.release_urecord(r, 0);
	ul_api.unlock_udomain((udomain_t*)_t, &aor);
	if (flags & REG_LOOKUP_UAFILTER_FLAG) {
		regfree(&ua_re);
	}
	return ret;
}
