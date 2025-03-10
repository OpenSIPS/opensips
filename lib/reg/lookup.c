/*
 * common contact lookup code
 *
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

#include "../../dset.h"
#include "../../strcommon.h"
#include "../../mod_fix.h"

#include "common.h"

ucontact_t **selected_cts; /* always has an extra terminating NULL ptr */
int selected_cts_sz = 20;

static ucontact_t **select_contacts(struct sip_msg *msg, ucontact_t *contacts,
                        int flags, const str *sip_instance, const str *call_id,
                        const regex_t *ua_re, int max_latency, int *ret);


int reg_init_lookup(void)
{
	/* init contact sorting array */
	selected_cts = pkg_malloc(selected_cts_sz * sizeof *selected_cts);
	if (!selected_cts) {
		LM_ERR("oom\n");
		return -1;
	}

	return 0;
}


lookup_rc lookup(struct sip_msg *req, udomain_t *d,
	struct lookup_flags *lookup_flags,
	str *aor_uri, int use_domain, int (*aor_update) (str *aor))
{
	static char urimem[MAX_BRANCHES-1][MAX_URI_SIZE];
	static str branch_uris[MAX_BRANCHES-1];
	int idx = 0, nbranches = 0, tlen;
	char *turi;
	qvalue_t tq;
	urecord_t* r;
	str aor;
	ucontact_t *ct, **ptr, **pn_cts, **cts;
	int max_latency = 0, ruri_is_pushed = 0;
	unsigned int flags = 0;
	int rc, ret = LOOKUP_NO_RESULTS, have_pn_cts = 0, single_branch = 0;
	str sip_instance = STR_NULL, call_id = STR_NULL;
	regex_t *ua_re = NULL;

	if (!req->callid) {
		LM_ERR("bad %.*s request (missing Call-ID header)\n",
		       req->REQ_METHOD_S.len, req->REQ_METHOD_S.s);
		return LOOKUP_ERROR;
	}

	if (lookup_flags) {
		flags = lookup_flags->flags;
		if (flags & REG_LOOKUP_UAFILTER_FLAG)
			ua_re = &lookup_flags->ua_re;
		max_latency = lookup_flags->max_latency;
	}

	single_branch = flags & REG_LOOKUP_NOBRANCH_FLAG;

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

	if (!aor_uri)
		aor_uri = GET_RURI(req);

	if (extract_aor(aor_uri, &aor, &sip_instance, &call_id, use_domain) < 0) {
		LM_ERR("failed to extract address of record\n");
		return LOOKUP_ERROR;
	}

	/* any on-the-spot edits to the AoR? */
	if (aor_update && aor_update(&aor) != 0) {
		LM_ERR("failed to apply changes to AoR: %.*s\n", aor.len, aor.s);
		return LOOKUP_ERROR;
	}

	update_act_time();

fetch_urecord:
	ul.lock_udomain(d, &aor);
	if (ul.cluster_mode == CM_FEDERATION_CACHEDB
	        && (flags & REG_LOOKUP_GLOBAL_FLAG))
		rc = ul.get_global_urecord(d, &aor, &r);
	else
		rc = ul.get_urecord(d, &aor, &r);

	if (rc > 0) {
		LM_DBG("'%.*s' Not found in usrloc\n", aor.len, ZSW(aor.s));
		ul.unlock_udomain(d, &aor);

		if ((flags & REG_BRANCH_AOR_LOOKUP_FLAG) && idx < nbranches)
			goto next_aor;

		goto done;
	}

	print_urecord(r);

	cts = select_contacts(req, r->contacts, flags, &sip_instance, &call_id,
	                      ua_re, max_latency, &ret);

	/* do not attempt to push anything to RURI if the flags say so */
	if (flags & REG_LOOKUP_NO_RURI_FLAG)
		ruri_is_pushed = 1;

	for (ptr = pn_cts = cts; *ptr; ptr++) {
		rc = push_branch(req, *ptr, &ruri_is_pushed);
		if (rc == -2) {
			ret = LOOKUP_ERROR;
			goto done;
		} else if (rc == 2) {
			*pn_cts++ = *ptr;
		}

		if (rc == 0 && single_branch)
			goto done;
	}

	if (ul.cluster_mode == CM_FEDERATION_CACHEDB
	        && (flags & REG_LOOKUP_GLOBAL_FLAG)) {
		for (ct = r->remote_aors; ct; ct = ct->next) {
			rc = push_branch(req, ct, &ruri_is_pushed);
			if (rc == 0 && single_branch)
				goto done;
		}
	}

	if (pn_cts > cts) {
		rc = pn_awake_pn_contacts(req, cts, single_branch ? 1 : pn_cts - cts);
		if (rc <= 0) {
			ret = (rc == 0 ? LOOKUP_STOP_SCRIPT : LOOKUP_ERROR);
			goto done;
		} else if (rc == 1) {
			have_pn_cts = 1;
			if (single_branch)
				goto done;
		}
	}

	if ((flags & REG_BRANCH_AOR_LOOKUP_FLAG) && idx < nbranches) {
		/* relsease old aor lock */
		ul.release_urecord(r, 0);
		ul.unlock_udomain(d, &aor);

	next_aor:
		aor_uri = &branch_uris[idx];
		LM_DBG("getting contacts from aor [%.*s] "
		       "in branch %d\n", aor_uri->len, aor_uri->s, idx);

		if (extract_aor(aor_uri, &aor, NULL, &call_id, reg_use_domain) < 0) {
			LM_ERR("failed to extract address of record for branch uri\n");
			ret = LOOKUP_ERROR;
			goto out_cleanup;
		}

		idx++;
		goto fetch_urecord;
	}

done:
	if (ruri_is_pushed)
		ret = LOOKUP_OK;
	else if (have_pn_cts)
		ret = LOOKUP_PN_SENT;

	if (r) {
		ul.release_urecord(r, 0);
		ul.unlock_udomain(d, &aor);
	}
out_cleanup:
	return ret;
}


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


static ucontact_t **select_contacts(struct sip_msg *msg, ucontact_t *contacts,
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
			*ret = LOOKUP_METHOD_UNSUP;

		if (!allowed_method(msg, ct, flags))
			continue;

		if (*ret < 0)
			*ret = LOOKUP_NO_RESULTS;

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
			if (!str_match(&ct->callid, call_id)) {
				LM_DBG("no match to call id - [%.*s] - [%.*s]\n",
				       ct->callid.len, ct->callid.s, call_id->len, call_id->s);
				continue;
			}

			/* matched call-id, check if there are newer contacts with
			 * same sip instace but newer last_modified */

			for (it = ct->next; it; it = it->next) {
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
			}
		}

		*ret = LOOKUP_OK;

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


#define REG_LOOKUP_TMP_REG_ICASE    (1<<6)
#define REG_LOOKUP_TMP_REG_EXTENDED (1<<7)

static str lookup_flag_names[] = {
	str_init("method-filtering"), /* REG_LOOKUP_METHODFILTER_FLAG */
	str_init("no-branches"),      /* REG_LOOKUP_NOBRANCH_FLAG */
	str_init("global"),           /* REG_LOOKUP_GLOBAL_FLAG */
	str_init("sort-by-latency"),  /* REG_LOOKUP_LATENCY_SORT_FLAG */
	str_init("branch"),           /* REG_BRANCH_AOR_LOOKUP_FLAG */
	str_init("to-branches-only"), /* REG_LOOKUP_NO_RURI_FLAG */

	/* used just for parsing, the returned bitmasks will be ingored after fixup */
	str_init("case-insensitive"), /* REG_LOOKUP_TMP_REG_ICASE */
	str_init("extended-regexp"),  /* REG_LOOKUP_TMP_REG_EXTENDED */
	STR_NULL
};

#define LOOKUP_KV_FLAGS_NO 2

static str lookup_kv_flag_names[] = {
	str_init("ua-filtering"),
	str_init("max-ping-latency"),
	STR_NULL
};

int reg_fixup_lookup_flags(void** param)
{
	struct lookup_flags *lookup_flags;
	str flag_vals[LOOKUP_KV_FLAGS_NO];
	int regexp_flags = 0;
	char *p, *re_end = NULL;
	int re_len = 0;

	lookup_flags = pkg_malloc(sizeof *lookup_flags);
	if (!lookup_flags) {
		LM_ERR("out of pkg memory\n");
		return -1;
	}
	memset(lookup_flags, 0, sizeof *lookup_flags);

	if (fixup_named_flags(param, lookup_flag_names, lookup_kv_flag_names,
		flag_vals) < 0) {
		LM_ERR("Failed to parse flags\n");
		return -1;
	}

	lookup_flags->flags = (unsigned int)(unsigned long)*param;
	*param = (void*)lookup_flags;

	/* "temporary" flags */
	if (lookup_flags->flags&REG_LOOKUP_TMP_REG_ICASE) {
		lookup_flags->flags &= ~REG_LOOKUP_TMP_REG_ICASE;
		regexp_flags |= REG_ICASE;
	}
	if (lookup_flags->flags&REG_LOOKUP_TMP_REG_EXTENDED) {
		lookup_flags->flags &= ~REG_LOOKUP_TMP_REG_EXTENDED;
		regexp_flags |= REG_EXTENDED;
	}

	/* ua-filtering */
	if (flag_vals[0].s) {
		p = flag_vals[0].s;
		if (*p != '/') {
			LM_ERR("no regexp start in 'ua-filtering' flag\n");
			return -1;
		}
		p++;
		re_end = q_memchr(p, '/', flag_vals[0].len -1);
		if (!re_end) {
			LM_ERR("no regexp end after 'ua-filtering' flag\n");
			return -1;
		}
		re_len = re_end - p;
		if (re_len == 0) {
			LM_ERR("empty regexp\n");
			return -1;
		}

		lookup_flags->flags |= REG_LOOKUP_UAFILTER_FLAG;
		LM_DBG("found regexp /%.*s/", re_len, p);

		*(p + re_len) = '\0';
		if (regcomp(&lookup_flags->ua_re, p, regexp_flags) != 0) {
			LM_ERR("bad regexp '%s'\n", p);
			*(p + re_len) = '/';
			return -1;
		}
		*(p + re_len) = '/';
	}

	/* max-ping-latency */
	if (flag_vals[1].s) {
		if (str2int(&flag_vals[1],
			(unsigned int*)&lookup_flags->max_latency) < 0) {
			LM_ERR("max-ping-latency [%.*s] value is not an integer\n",
				flag_vals[1].len, flag_vals[1].s);
			return -1;
		}

		lookup_flags->flags |= REG_LOOKUP_MAX_LATENCY_FLAG;
	}

	return 0;
}

int reg_fixup_free_lookup_flags(void** param)
{
	struct lookup_flags *lookup_flags = (struct lookup_flags *)*param;

	if (lookup_flags) {
		if (lookup_flags->flags & REG_LOOKUP_UAFILTER_FLAG)
			regfree(&lookup_flags->ua_re);
		pkg_free(lookup_flags);
	}
	return 0;
}

int push_branch(struct sip_msg *msg, ucontact_t *ct, int *ruri_is_pushed)
{
	str path_dst;
	int_str istr;
	str *ct_uri, _ct_uri;
	struct sip_uri puri;

	if (!ct)
		return 1;

	if (pn_enable && pn_on(ct) && pn_has_uri_params(&ct->c, &puri)) {
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
