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
#include "../../strcommon.h"

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
#define REG_LOOKUP_GLOBAL_FLAG         (1<<4)

char uri_buf[MAX_URI_SIZE];
unsigned int nbranches;
static char urimem[MAX_BRANCHES-1][MAX_URI_SIZE];
static str branch_uris[MAX_BRANCHES-1];

int mid_reg_lookup(struct sip_msg* req, char* _t, char* _f, char* _s)
{
	static str unescape_buf;
	unsigned int flags;
	urecord_t* r;
	str aor, uri, unesc_aor;
	ucontact_t* ptr,*it;
	int res, pos, remote_cts_done = 0;
	int ret, bak;
	str path_dst;
	str flags_s;
	char* ua = NULL;
	char* re_end = NULL;
	int re_len = 0;
	char tmp;
	regex_t ua_re;
	int regexp_flags = 0;
	regmatch_t ua_match;
	int_str istr;
	str sip_instance = {0,0},call_id = {0,0};
	struct sip_uri puri;
	uint64_t contact_id;

	/* branch index */
	int idx;

	/* temporary branch values*/
	int tlen;
	char *turi;

	qvalue_t tq;

	LM_DBG("mid_reg_lookup ... \n");

	flags = 0;
	if (_f && _f[0]!=0) {
		if (fixup_get_svalue(req, (gparam_p)_f, &flags_s)!=0) {
			LM_ERR("failed to get a string value for the 'flags' parameter\n");
			return -1;
		}
		for( res=0 ; res< flags_s.len ; res++ ) {
			switch (flags_s.s[res]) {
				case 'm': flags |= REG_LOOKUP_METHODFILTER_FLAG; break;
				case 'b': flags |= REG_LOOKUP_NOBRANCH_FLAG; break;
				case 'g': flags |= REG_LOOKUP_GLOBAL_FLAG; break;
				case 'r': flags |= REG_BRANCH_AOR_LOOKUP_FLAG; break;
				case 'u':
					if (flags_s.s[res+1] != '/') {
						LM_ERR("no regexp after 'u' flag\n");
						break;
					}
					res++;
					if ((re_end = strrchr(flags_s.s+res+1, '/')) == NULL) {
						LM_ERR("no regexp after 'u' flag\n");
						break;
					}
					res++;
					re_len = re_end-flags_s.s-res;
					if (re_len == 0) {
						LM_ERR("empty regexp\n");
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
		if (fixup_get_svalue(req, (gparam_p)_s, &uri) != 0) {
			LM_ERR("failed to get a string value for the 'AoR' parameter\n");
			return -1;
		}
	} else {
		uri = *GET_RURI(req);
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

	if (reg_mode != MID_REG_THROTTLE_AOR) {

		if ( (!req->callid && parse_headers(req, HDR_CALLID_F,0)<0) || !req->callid ) {
			LM_ERR("bad request or missing Call-ID hdr\n");
			return -1;
		}

		if (parse_uri(uri.s, uri.len, &puri) < 0) {
			LM_ERR("failed to parse R-URI <%.*s>, ci: %.*s\n", uri.len,
			       uri.s, req->callid->body.len, req->callid->body.s);
			return -1;
		}

		if (ctid_insertion == MR_APPEND_PARAM) {
			pos = get_uri_param_idx(&ctid_param, &puri);
			if (pos < 0) {
				LM_ERR("failed to locate our ';%.*s=' param in %sURI '%.*s', "
				       "ci = %.*s!\n", ctid_param.len, ctid_param.s,
				       _s ? "" : "R-", uri.len, uri.s, req->callid->body.len,
				       req->callid->body.s);
				return -1;
			}
			if (str2int64(&puri.u_val[pos], &contact_id) != 0) {
				LM_ERR("invalid contact_id in %sURI '%.*s', ci: %.*s\n",
				       _s ? "" : "R-", uri.len, uri.s, req->callid->body.len,
				       req->callid->body.s);
				return -1;
			}
		} else {
			if (str2int64(&puri.user, &contact_id) != 0) {
				LM_ERR("invalid contact_id in %sURI '%.*s', ci: %.*s\n",
				       _s ? "" : "R-", uri.len, uri.s, req->callid->body.len,
				       req->callid->body.s);
				return -1;
			}
		}

		LM_DBG("getting ucontact from contact_id %llu\n", (unsigned long long)contact_id);

		ptr = ul_api.get_ucontact_from_id((udomain_t *)_t, contact_id, &r);
		if (!ptr) {
			LM_DBG("no record found for %.*s, ci: %.*s\n", uri.len, uri.s,
			       req->callid->body.len, req->callid->body.s);
			return -1;
		}
		aor = r->aor;
		flags |= REG_LOOKUP_NOBRANCH_FLAG;
		goto have_contact;
	}

	bak = reg_use_domain;
	reg_use_domain = 0;
	if (extract_aor(&uri, &aor, &sip_instance, &call_id) < 0) {
		LM_ERR("failed to extract address of record\n");
		reg_use_domain = bak;
		return -3;
	}
	reg_use_domain = bak;

	if (reg_use_domain) {
		if (pkg_str_extend(&unescape_buf, aor.len + 1) != 0) {
			LM_ERR("oom\n");
			return -3;
		}

		unesc_aor = unescape_buf;
		if (unescape_param(&aor, &unesc_aor) != 0) {
			LM_ERR("failed to unescape aor: %.*s\n", aor.len, aor.s);
			return -3;
		}

		aor = unesc_aor;
	}

	update_act_time();

	ul_api.lock_udomain((udomain_t*)_t, &aor);
	if (ul_api.cluster_mode == CM_FEDERATION_CACHEDB
	        && (flags & REG_LOOKUP_GLOBAL_FLAG))
		res = ul_api.get_global_urecord((udomain_t*)_t, &aor, &r);
	else
		res = ul_api.get_urecord((udomain_t*)_t, &aor, &r);

	if (res > 0) {
		LM_DBG("'%.*s' Not found in usrloc\n", aor.len, ZSW(aor.s));
		ul_api.unlock_udomain((udomain_t*)_t, &aor);
		return -1;
	}

	ptr = r->contacts;
	ret = -1;
	/* look first for an un-expired and suported contact */
search_valid_contact:
	while ( (ptr) &&
	!(VALID_CONTACT(ptr,get_act_time()) && (ret=-2) && allowed_method(req,ptr,flags)))
		ptr = ptr->next;
	if (ptr==0) {
		if (ul_api.cluster_mode == CM_FEDERATION_CACHEDB &&
		    (flags & REG_LOOKUP_GLOBAL_FLAG) && !remote_cts_done) {
			ptr = r->remote_aors;
			remote_cts_done = 1;
			goto search_valid_contact;
		}
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

have_contact:
	ret = 1;

	LM_DBG("setting as ruri <%.*s>\n",ptr->c.len,ptr->c.s);
	if (set_ruri(req, &ptr->c) < 0) {
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
		if (set_path_vector(req, &ptr->path) < 0) {
			LM_ERR("failed to set path vector\n");
			ret = -3;
			goto done;
		}
		if (set_dst_uri(req, &path_dst) < 0) {
			LM_ERR("failed to set dst_uri of Path\n");
			ret = -3;
			goto done;
		}
	} else if (ptr->received.s && ptr->received.len) {
		if (set_dst_uri(req, &ptr->received) < 0) {
			ret = -3;
			goto done;
		}
	}

	set_ruri_q(req, ptr->q);

	setbflag(req, 0, ptr->cflags);

	if (ptr->sock)
		req->force_send_socket = ptr->sock;

	/* populate the 'attributes' avp */
	if (attr_avp_name != -1) {
		istr.s = ptr->attr;
		if (add_avp_last(AVP_VAL_STR, attr_avp_name, istr) != 0) {
			LM_ERR("Failed to populate attr avp!\n");
		}
	}

	ptr = ptr->next;

	/* Append branches if enabled */
	/* If we got to this point and the URI had a ;gr parameter and it was matched
	 * to a contact. No point in branching */
	if ( flags&REG_LOOKUP_NOBRANCH_FLAG || (sip_instance.len && sip_instance.s) ) goto done;
	LM_DBG("looking for branches\n");

	do {
cts_to_branches:
		for( ; ptr ; ptr = ptr->next ) {
			if (VALID_CONTACT(ptr, get_act_time()) && allowed_method(req,ptr,flags)) {
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
				if (append_branch(req,&ptr->c,path_dst.len?&path_dst:&ptr->received,
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

		if (ul_api.cluster_mode == CM_FEDERATION_CACHEDB &&
		    (flags & REG_LOOKUP_GLOBAL_FLAG) && !remote_cts_done) {
			ptr = r->remote_aors;
			remote_cts_done = 1;
			goto cts_to_branches;
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
		if (ul_api.cluster_mode == CM_FEDERATION_CACHEDB
		        && (flags & REG_LOOKUP_GLOBAL_FLAG))
			res = ul_api.get_global_urecord((udomain_t*)_t, &aor, &r);
		else
			res = ul_api.get_urecord((udomain_t*)_t, &aor, &r);

		if (res > 0) {
			LM_DBG("'%.*s' Not found in usrloc\n", aor.len, ZSW(aor.s));
			goto done;
		}
		idx++;
		remote_cts_done = 0;
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
