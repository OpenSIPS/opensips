/**
 * SIP Push Notification support - RFC 8599
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#include "../../lib/csv.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_fcaps.h"
#include "../../usr_avp.h"
#include "../../data_lump.h"
#include "../../data_lump_rpl.h"

#include "../../modules/usrloc/ul_evi.h"
#include "../../modules/event_routing/api.h"

#include "common.h"

/* PN modparams */
int pn_enable;
int pn_pnsreg_interval = 130;  /* sec */
int pn_trigger_interval = 120; /* sec */
int pn_skip_pn_interval = 0; /* sec */
int pn_refresh_timeout = 6; /* sec */
int pn_enable_purr;
char *_pn_ct_params = "pn-provider, pn-prid, pn-param";
char *_pn_providers;

/* list of parsed match params */
str_list *pn_ct_params;

static struct pn_provider *pn_providers;
static ebr_filter *pn_ebr_filters;

/* Contact URI parameters */
static str pn_provider_str = str_init("pn-provider");
static str pn_prid_str = str_init("pn-prid");
static str pn_param_str = str_init("pn-param");
//static str pn_purr_str = str_init("pn-purr");

#define MAX_PROVIDER_LEN 40
#define MAX_PNSPURR_LEN 40
#define MAX_FEATURE_CAPS_SIZE \
	(sizeof("Feature-Caps: +sip.pns=\"\";" \
			"+sip.pnsreg=\"\";+sip.pnspurr=\"\"") + \
			MAX_PROVIDER_LEN + INT2STR_MAX_LEN + MAX_PNSPURR_LEN + CRLF_LEN)
#define PN_REASON_BUFSZ 32

static ebr_api_t ebr;
static ebr_event *ev_ct_update;


int pn_init(void)
{
	str_list *param;
	csv_record *items, *pnp;
	struct pn_provider *provider;
	ebr_filter *filter;
	int nprov = 0;

	if (!pn_enable)
		return 0;

	if (!pn_cfg_validate()) {
		LM_ERR("failed to validate opensips.cfg PN configuration\n");
		return -1;
	}

	pn_provider_str.len = strlen(pn_provider_str.s);

	if (!_pn_providers) {
		LM_ERR("the 'pn_providers' modparam is missing\n");
		return -1;
	}

	if (load_ebr_api(&ebr) != 0) {
		LM_ERR("failed to load EBR API\n");
		return -1;
	}

	ev_ct_update = ebr.get_ebr_event(_str(UL_EV_CT_UPDATE));
	if (!ev_ct_update) {
		LM_ERR("failed to obtain EBR event for Contact UPDATE\n");
		return -1;
	}

	/* parse the list of PN params */
	items = parse_csv_record(_str(_pn_ct_params));
	for (pnp = items; pnp; pnp = pnp->next) {
		if (ZSTR(pnp->s))
			continue;

		if (pnp->s.len > MAX_PROVIDER_LEN) {
			LM_ERR("PN provider name too long (%d/%d)\n",
			       pnp->s.len, MAX_PROVIDER_LEN);
			return -1;
		}

		param = shm_malloc(sizeof *param + pnp->s.len + 1);
		if (!param) {
			LM_ERR("oom\n");
			return -1;
		}
		memset(param, 0, sizeof *param);

		param->s.s = (char *)(param + 1);
		str_cpy(&param->s, &pnp->s);
		param->s.s[pnp->s.len] = '\0';

		add_last(param, pn_ct_params);

		LM_DBG("parsed PN contact param: '%.*s'\n",
		       param->s.len, param->s.s);

		/* build the filter templates, values are to be filled in at runtime */
		filter = shm_malloc(sizeof *filter);
		if (!filter) {
			LM_ERR("oom\n");
			return -1;
		}
		memset(filter, 0, sizeof *filter);

		filter->key = *_str(UL_EV_PARAM_CT_URI);
		filter->uri_param_key = param->s;
		add_last(filter, pn_ebr_filters);
	}
	free_csv_record(items);

	if (!pn_ct_params) {
		LM_ERR("'pn_ct_match_params' must contain at least 1 param!\n");
		return -1;
	}

	/* parse the list of providers */
	items = parse_csv_record(_str(_pn_providers));
	for (pnp = items; pnp; pnp = pnp->next) {
		if (ZSTR(pnp->s))
			continue;

		if (++nprov > PN_MAX_PROVIDERS) {
			LM_ERR("max number of PN providers exceeded (%lu)\n",
			       PN_MAX_PROVIDERS);
			return -1;
		}

		provider = shm_malloc(sizeof *provider + pnp->s.len + 1 +
		                      MAX_FEATURE_CAPS_SIZE);
		if (!provider) {
			LM_ERR("oom\n");
			return -1;
		}
		memset(provider, 0, sizeof *provider);

		provider->name.s = (char *)(provider + 1);
		str_cpy(&provider->name, &pnp->s);
		provider->name.s[provider->name.len] = '\0';

		provider->feature_caps_query.s = provider->name.s + pnp->s.len + 1;
		provider->feature_caps_query.len =
			sprintf(provider->feature_caps_query.s,
				"Feature-Caps: +sip.pns=\"%.*s\""CRLF, pnp->s.len, pnp->s.s);

		provider->feature_caps.s = provider->feature_caps_query.s +
			                       provider->feature_caps_query.len + 1;
		provider->feature_caps.len = sprintf(provider->feature_caps.s,
				"Feature-Caps: +sip.pns=\"%.*s\";+sip.pnsreg=\"%u\"%s",
				pnp->s.len, pnp->s.s, pn_pnsreg_interval,
				pn_enable_purr ? ";+sip.pnspurr=\"" : CRLF);

		add_last(provider, pn_providers);
		LM_DBG("parsed PN provider: '%.*s', hdr: '%.*s'\n", provider->name.len,
		       provider->name.s, provider->feature_caps.len,
		       provider->feature_caps.s);
	}
	free_csv_record(items);

	return 0;
}


int pn_cfg_validate(void)
{
	if (pn_enable_purr &&
	        !is_script_func_used("record_route", -1) &&
	        !is_script_func_used("record_route_preset", -1) &&
	        !is_script_func_used("topology_hiding", -1)) {
		LM_ERR("you have enabled modparam 'pn_enable_purr' without "
		       "inserting yourself in the mid-dialog SIP flow "
		       "(e.g. using record_route()), config not valid\n");
		return 0;
	}

	if (pn_enable_purr && !is_script_async_func_used("pn_process_purr", 1)) {
		LM_ERR("you have enabled modparam 'pn_enable_purr', but there is no "
		       "async call to 'pn_process_purr()', config not valid\n");
		return 0;
	}

	if (!pn_enable_purr && is_script_async_func_used("pn_process_purr", 1)) {
		LM_ERR("you are calling 'pn_process_purr()' without also enabling "
		       "modparam 'pn_enable_purr', config not valid\n");
		return 0;
	}

	return 1;
}


struct module_dependency *pn_get_deps(param_export_t *param)
{
	int pn_is_on = *(int *)param->param_pointer;

	if (!pn_is_on)
		return NULL;

	return _alloc_module_dep(
		MOD_TYPE_DEFAULT, "tm", DEP_ABORT,
		MOD_TYPE_DEFAULT, "event_routing", DEP_ABORT,
		MOD_TYPE_NULL);
}


/**
 * attempt to match @prov in any Feature-Caps hf value of @req
 *
 * Return: 1 on match, 0 on non-match, -1 on error
 */
static int pn_fcaps_match_provider(struct sip_msg *req, const str *prov)
{
	struct hdr_field *fcaps;
	fcaps_body_t *fcaps_body;

	if (parse_headers(req, HDR_EOH_F, 0) < 0) {
		LM_ERR("failed to parse headers\n");
		return -1;
	}

	for (fcaps = req->feature_caps; fcaps; fcaps = fcaps->sibling) {
		if (parse_fcaps(fcaps) != 0) {
			LM_ERR("failed to parse Feature-Caps hf\n");
			continue;
		}

		fcaps_body = (fcaps_body_t *)fcaps->parsed;

		if (str_match(&fcaps_body->pns, prov)) {
			LM_DBG("PNs for '%.*s' are being handled by an upstream proxy\n",
			       fcaps_body->pns.len, fcaps_body->pns.s);
			return 1;
		}
	}

	return 0;
}


enum pn_action pn_inspect_ct_params(struct sip_msg *req, const str *ct_uri)
{
	struct sip_uri puri;
	struct pn_provider *pvd = NULL;
	str_list *param;
	int i, is_cap_query = 1, is_handled_upstream = 0;

	if (parse_uri(ct_uri->s, ct_uri->len, &puri) != 0) {
		LM_ERR("failed to parse Contact URI '%.*s'\n", ct_uri->len, ct_uri->s);
		return -1;
	}

	if (!puri.pn_provider.s)
		return PN_NONE;

	/* ";pn-provider" -> this is a query for a full PNS listing */
	if (!puri.pn_provider_val.s) {
		/* if any of our providers are being handled upstream, ignore them */
		for (pvd = pn_providers; pvd; pvd = pvd->next) {
			switch (pn_fcaps_match_provider(req, &pvd->name)) {
			case -1:
				return -1;
			case 0:
				pvd->append_fcaps_query = 1;
			}
		}

		return PN_LIST_ALL_PNS;
	}

	/* are PNs for this provider being handled by an upstream proxy? */
	switch (pn_fcaps_match_provider(req, &puri.pn_provider_val)) {
	case -1:
		return -1;
	case 1:
		is_handled_upstream = 1;
		goto match_params;
	}

	for (pvd = pn_providers; pvd; pvd = pvd->next)
		if (str_match(&puri.pn_provider_val, &pvd->name))
			goto match_params;

	LM_DBG("unsupported PN provider: '%.*s'\n", puri.pn_provider_val.len,
	       puri.pn_provider_val.s);
	return PN_UNSUPPORTED_PNS;

match_params:
	for (param = pn_ct_params; param; param = param->next) {
		if (str_match(&param->s, &pn_provider_str)) {
			continue;
		} else if ((str_match(&param->s, &pn_prid_str) && puri.pn_prid.s) ||
		          (str_match(&param->s, &pn_param_str) && puri.pn_param.s)) {
			is_cap_query = 0;
			continue;
		} else {
			for (i = 0; i < puri.u_params_no; i++)
				if (str_match(&param->s, &puri.u_name[i]))
					goto next_param;
		}

		if (is_handled_upstream)
			/* at least one required PN param is missing and PNs are already
			 * handled upstream anyway -- just match by URI string */
			return PN_NONE;
		else if (!is_cap_query)
			return PN_UNSUPPORTED_PNS;

next_param:;
	}

	if (is_handled_upstream)
		return PN_MATCH_PN_PARAMS;

	if (is_cap_query) {
		pvd->append_fcaps_query = 1;
		return PN_LIST_ONE_PNS;
	}

	pvd->append_fcaps = 1;
	return PN_ON;
}


int pn_inspect_request(struct sip_msg *req, const str *ct_uri,
                       struct save_ctx *sctx)
{
	int rc;

	if (sctx->cmatch.mode != CT_MATCH_NONE) {
		LM_DBG("skip PN processing, matching mode already enforced\n");
		return 0;
	}

	rc = pn_inspect_ct_params(req, ct_uri);
	if (rc < 0) {
		rerrno = R_PARSE_CONT;
		LM_DBG("failed to parse Contact URI\n");
		return -1;
	}

	switch (rc) {
	case PN_NONE:
		LM_DBG("Contact URI has no PN params\n");
		break;

	case PN_ON:
		LM_DBG("match this contact using PN params and send PN\n");
		sctx->cmatch.mode = CT_MATCH_PARAMS;
		sctx->cmatch.match_params = pn_ct_params;
		sctx->flags |= REG_SAVE__PN_ON_FLAG;
		break;

	case PN_LIST_ALL_PNS:
		LM_DBG("Contact URI includes PN capability query (all PNS)\n");
		break;

	case PN_LIST_ONE_PNS:
		LM_DBG("Contact URI includes PN capability query (one PNS)\n");
		break;

	case PN_MATCH_PN_PARAMS:
		LM_DBG("match this contact using PN params but don't send PN\n");
		sctx->cmatch.mode = CT_MATCH_PARAMS;
		sctx->cmatch.match_params = pn_ct_params;
		break;

	case PN_UNSUPPORTED_PNS:
		LM_DBG("at least one required PN param is missing, reply with 555\n");
		rerrno = R_PNS_UNSUP;
		return -1;
	}

	return 0;
}


int pn_append_req_fcaps(struct sip_msg *msg, void **pn_provider_state)
{
	struct pn_provider *prov;
	struct lump *anchor;
	str fcaps;
	unsigned long prov_bitmask = 0;
	int i, rc = 0;

	for (i = 0, prov = pn_providers; prov; i++, prov = prov->next) {
		if (!prov->append_fcaps && !prov->append_fcaps_query)
			continue;

		if (prov->append_fcaps_query) {
			prov->append_fcaps_query = 0;
			prov_bitmask |= PN_PROVIDER_RPL_QFCAPS << (i * PN_PROVIDER_FLAGS);
		} else {
			prov->append_fcaps = 0;
			prov_bitmask |= PN_PROVIDER_RPL_FCAPS << (i * PN_PROVIDER_FLAGS);
		}

		if (pkg_str_dup(&fcaps, &prov->feature_caps_query) != 0) {
			LM_ERR("oom3\n");
			rc = -1;
			continue;
		}

		anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0);
		if (!anchor) {
			pkg_free(fcaps.s);
			LM_ERR("oom2\n");
			rc = -1;
			continue;
		}

		if (!insert_new_lump_before(anchor, fcaps.s, fcaps.len, 0)) {
			pkg_free(fcaps.s);
			LM_ERR("oom5\n");
			rc = -1;
		}
	}

	*pn_provider_state = (void *)prov_bitmask;
	return rc;
}


void pn_restore_provider_state(void *pn_provider_state)
{
	struct pn_provider *prov;
	unsigned long prov_bitmask = (unsigned long)pn_provider_state;
	int i;

	for (i = 0, prov = pn_providers; prov; i++, prov = prov->next) {
		prov->append_fcaps_query = !!(prov_bitmask &
					(PN_PROVIDER_RPL_QFCAPS << (i * PN_PROVIDER_FLAGS)));

		prov->append_fcaps = !!(prov_bitmask &
					(PN_PROVIDER_RPL_FCAPS << (i * PN_PROVIDER_FLAGS)));
	}
}


int pn_append_rpl_fcaps(struct sip_msg *msg)
{
	struct pn_provider *prov;
	struct lump *anchor;
	str fcaps, *hdr, _hdr;
	int rc = 0;

	for (prov = pn_providers; prov; prov = prov->next) {
		if (!prov->append_fcaps && !prov->append_fcaps_query)
			continue;

		if (prov->append_fcaps_query) {
			hdr = &prov->feature_caps_query;
			prov->append_fcaps_query = 0;
		} else {
			_hdr = prov->feature_caps;
			_hdr.len = strlen(_hdr.s); /* count the post-print length */
			hdr = &_hdr;
			prov->append_fcaps = 0;
		}

		if (msg->first_line.type == SIP_REQUEST) {
			if (!add_lump_rpl(msg, hdr->s, hdr->len,
			                  LUMP_RPL_HDR|LUMP_RPL_NODUP|LUMP_RPL_NOFREE)) {
				LM_ERR("oom1\n");
				rc = -1;
			}
		} else {
			anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0);
			if (!anchor) {
				LM_ERR("oom2\n");
				rc = -1;
				continue;
			}

			if (pkg_str_dup(&fcaps, hdr) != 0) {
				LM_ERR("oom3\n");
				rc = -1;
				continue;
			}

			if (!insert_new_lump_before(anchor, fcaps.s, fcaps.len, 0)) {
				pkg_free(fcaps.s);
				LM_ERR("oom5\n");
				rc = -1;
			}
		}
	}

	return rc;
}


/**
 * On an incoming REGISTER triggered by a PN, this callback trims away the RFC
 * 8599 Contact URI parameters from the E_UL_CONTACT_UPDATE event data before
 * packing the data as AVPs, to be included in the outgoing SIP branch R-URI
 */
static struct usr_avp *pn_trim_pn_params(evi_params_t *params)
{
	struct usr_avp *avp, *head = NULL;
	struct sip_uri puri;
	evi_param_t *p;
	int_str val;
	int avp_id;
	str *sval, _sval;

	for (p = params->first; p; p = p->next) {
		/* get an AVP name matching the param name */
		if (parse_avp_spec(&p->name, &avp_id) < 0) {
			LM_ERR("cannot get AVP ID for name <%.*s>, skipping..\n",
			       p->name.len, p->name.s);
			continue;
		}

		/* the Contact URI is the only EVI param we're interested in */
		if (str_match(&p->name, _str(UL_EV_PARAM_CT_URI)) &&
              pn_has_uri_params(&p->val.s, &puri)) {
			if (pn_remove_uri_params(&puri, p->val.s.len, &_sval) != 0) {
				LM_ERR("failed to remove PN params from Contact '%.*s'\n",
				       p->val.s.len, p->val.s.s);
				sval = &p->val.s;
			} else {
				sval = &_sval;
			}
		} else {
			sval = &p->val.s;
		}

		/* create a new AVP */
		if (p->flags & EVI_STR_VAL) {
			val.s = *sval;
			avp = new_avp(AVP_VAL_STR, avp_id, val);
		} else if (p->flags & EVI_INT_VAL) {
			val.n = p->val.n;
			avp = new_avp(0, avp_id, val);
		} else {
			LM_DBG("EVI param '%.*s' not STR, nor INT (%d), ignoring...\n",
			       p->name.len, p->name.s, p->flags);
			continue;
		}

		if (!avp) {
			LM_ERR("cannot get create new AVP name <%.*s>, skipping..\n",
			       p->name.len, p->name.s);
			continue;
		}

		/* link the AVP */
		avp->next = head;
		head = avp;
	}

	return head;
}


static void pn_inject_branch(void)
{
	if (tmb.t_inject_ul_event_branch() != 1)
		LM_ERR("failed to inject a branch for the "UL_EV_CT_UPDATE" event!\n");
}


int pn_awake_pn_contacts(struct sip_msg *req, ucontact_t **cts, int sz)
{
	ucontact_t **end;
	struct sip_uri puri;
	int rc, pn_sent = 0;

	if (sz <= 0)
		return 2;

	rc = tmb.t_newtran(req);
	switch (rc) {
	case 1:
		break;

	case E_SCRIPT:
		LM_DBG("%.*s transaction already exists, continuing...\n",
		       req->REQ_METHOD_S.len, req->REQ_METHOD_S.s);
		break;

	case 0:
		LM_INFO("absorbing %.*s retransmission, use t_check_trans() "
		        "earlier\n", req->REQ_METHOD_S.len, req->REQ_METHOD_S.s);
		return 0;

	default:
		LM_ERR("internal error %d while creating %.*s transaction\n",
		       rc, req->REQ_METHOD_S.len, req->REQ_METHOD_S.s);
		return -1;
	}

	if (tmb.t_wait_for_new_branches(req) != 1)
		LM_ERR("failed to enable waiting for new branches\n");

	for (end = cts + sz; cts < end; cts++) {
		if (parse_uri((*cts)->c.s, (*cts)->c.len, &puri) != 0) {
			LM_ERR("failed to parse Contact '%.*s'\n",
			       (*cts)->c.len, (*cts)->c.s);
			continue;
		}

		if (pn_trigger_pn(req, *cts, &puri) != 0) {
			LM_ERR("failed to trigger PN for Contact: '%.*s'\n",
			       (*cts)->c.len, (*cts)->c.s);
			continue;
		}

		pn_sent = 1;
	}

	return pn_sent ? 1 : 2;
}


int pn_trigger_pn(struct sip_msg *req, const ucontact_t *ct,
                  const struct sip_uri *ct_uri)
{
	ebr_filter *f;
	char _reason[PN_REASON_BUFSZ + 1];
	str reason = {_reason, 0}, met;

	/* fill in the EBR filters, so we can match the future reg event */
	for (f = pn_ebr_filters; f; f = f->next) {
		if (get_uri_param_val(ct_uri, &f->uri_param_key, &f->val) != 0) {
			LM_ERR("failed to locate '%.*s' URI param in Contact '%.*s'\n",
			       f->uri_param_key.len, f->uri_param_key.s,
			       ct->c.len, ct->c.s);
			return -1;
		}
	}

	if (ebr.notify_on_event(req, ev_ct_update, pn_ebr_filters,
	        pn_trim_pn_params, pn_inject_branch, pn_refresh_timeout) != 0) {
		LM_ERR("failed to EBR-subscribe to "UL_EV_CT_UPDATE", Contact: %.*s\n",
		       ct->c.len, ct->c.s);
		return -1;
	}

	met = req->REQ_METHOD_S;
	if (met.len > PN_REASON_BUFSZ - 4)
		met.len = PN_REASON_BUFSZ - 4;
	sprintf(reason.s, "ini-%.*s", met.len, met.s);
	reason.len = 4 + met.len;

	ul.raise_ev_ct_refresh(ct, &reason, &req->callid->body);
	return 0;
}


int pn_has_uri_params(const str *ct, struct sip_uri *puri)
{
	str_list *param;
	struct sip_uri _puri;
	int i;

	if (!puri)
		puri = &_puri;

	if (parse_uri(ct->s, ct->len, puri) != 0) {
		LM_ERR("failed to parse contact: '%.*s'\n", ct->len, ct->s);
		return 0;
	}

	for (param = pn_ct_params; param; param = param->next) {
		if ((str_match(&param->s, &pn_provider_str) && puri->pn_provider.s) ||
		        (str_match(&param->s, &pn_prid_str) && puri->pn_prid.s) ||
		        (str_match(&param->s, &pn_param_str) && puri->pn_param.s)) {
			continue;
		} else {
			for (i = 0; i < puri->u_params_no; i++)
				if (str_match(&param->s, &puri->u_name[i]))
					goto next_param;
		}

		return 0;

next_param:;
	}

	return 1;
}


int pn_remove_uri_params(struct sip_uri *puri, int uri_len, str *out_uri)
{
	static str buf;
	static int buf_len;
	str_list *param;
	str u_name_bak[URI_MAX_U_PARAMS];
	char *pn_prov, *pn_prid, *pn_param;
	int i;

	if (pkg_str_extend(&buf, uri_len) != 0) {
		LM_ERR("oom\n");
		return -1;
	}
	buf_len = buf.len;

	memcpy(u_name_bak, puri->u_name, URI_MAX_U_PARAMS * sizeof *u_name_bak);
	pn_prov = puri->pn_provider.s;
	pn_prid = puri->pn_prid.s;
	pn_param = puri->pn_param.s;

	puri->pn_provider.s = NULL;
	puri->pn_prid.s = NULL;
	puri->pn_param.s = NULL;

	for (param = pn_ct_params; param; param = param->next)
		for (i = 0; i < puri->u_params_no; i++)
			if (str_match(&param->s, &puri->u_name[i])) {
				puri->u_name[i].s = NULL;
				break;
			}

	if (print_uri(puri, &buf) != 0) {
		LM_ERR("failed to print contact URI\n");
		return -1;
	}

	/* fix the struct sip_uri back */
	memcpy(puri->u_name, u_name_bak, URI_MAX_U_PARAMS * sizeof *u_name_bak);
	puri->pn_provider.s = pn_prov;
	puri->pn_prid.s = pn_prid;
	puri->pn_param.s = pn_param;

	LM_DBG("trimmed URI: '%.*s'\n", buf.len, buf.s);

	*out_uri = buf;
	buf.len = buf_len;
	return 0;
}


int pn_async_process_purr(struct sip_msg *req, async_ctx *ctx, udomain_t *d)
{
	char _reason[PN_REASON_BUFSZ + 1];
	ebr_filter *f;
	struct sip_uri puri;
	str *purr, *rt_uri, reason = {_reason, 0}, met;
	ucontact_id id;
	urecord_t *r;
	ucontact_t *c;

	if (req->first_line.type != SIP_REQUEST) {
		LM_ERR("pn_process_purr() cannot be called on SIP replies\n");
		return -1;
	}

	if (!req->callid) {
		LM_ERR("bad %.*s request (missing Call-ID header)\n",
		       req->REQ_METHOD_S.len, req->REQ_METHOD_S.s);
		return -1;
	}

	/* locate "pn-purr" in the R-URI */
	if (parse_sip_msg_uri(req) < 0) {
		LM_ERR("failed to parse R-URI: '%.*s'\n",
		       GET_RURI(req)->len, GET_RURI(req)->s);
		return -1;
	}

	if (req->parsed_uri.pn_purr.s) {
		purr = &req->parsed_uri.pn_purr_val;
		goto have_purr;
	}

	/* locate "pn-purr" in the topmost Route hfs */
	if (!req->route && (parse_headers(req, HDR_ROUTE_F, 0) != 0 ||
	                    !req->route)) {
		LM_DBG("request has no 'pn-purr' (no Route headers found)\n");
		return -1;
	}

	if (!req->route->parsed && parse_rr(req->route) != 0) {
		LM_ERR("failed to parse Route header\n");
		return -1;
	}

	rt_uri = &((rr_t *)req->route->parsed)->nameaddr.uri;
	if (parse_uri(rt_uri->s, rt_uri->len, &puri) != 0) {
		LM_ERR("failed to parse Route URI: '%.*s'\n", rt_uri->len, rt_uri->s);
		return -1;
	}

	if (!puri.pn_purr.s) {
		LM_DBG("did not find 'pn-purr' in either R-URI or topmost Route\n");
		return 2;
	}

	purr = &puri.pn_purr_val;

have_purr:
	if (pn_purr_unpack(purr, &id) != 0) {
		LM_DBG("this 'pn-purr' is not ours, ignoring\n");
		return 2;
	}

	/* look up the PURR */
	c = ul.get_ucontact_from_id(d, id, &r);
	if (!c) {
		LM_DBG("recognized pn-purr: '%.*s', ctid: %lu, but ct not found!\n",
		       purr->len, purr->s, id);
		return 2;
	}

	LM_DBG("retrieved ct: '%.*s' from pn-purr: '%.*s'\n", c->c.len, c->c.s,
	       purr->len, purr->s);

	if (parse_uri(c->c.s, c->c.len, &puri) != 0) {
		LM_ERR("failed to parse Contact: '%.*s'\n", c->c.len, c->c.s);
		goto err_unlock;
	}

	/* fill in the EBR filters, so we can match the future reg event */
	for (f = pn_ebr_filters; f; f = f->next) {
		if (get_uri_param_val(&puri, &f->uri_param_key, &f->val) != 0) {
			LM_ERR("failed to locate '%.*s' URI param in Contact '%.*s'\n",
			       f->uri_param_key.len, f->uri_param_key.s,
			       c->c.len, c->c.s);
			goto err_unlock;
		}
	}

	/* subscribe for re-register events from this contact */
	if (ebr.async_wait_for_event(req, ctx, ev_ct_update, pn_ebr_filters,
	          pn_trim_pn_params, pn_refresh_timeout) != 0) {
		LM_ERR("failed to EBR-subscribe to "UL_EV_CT_UPDATE", ct: '%.*s'\n",
		       c->c.len, c->c.s);
		goto err_unlock;
	}

	met = req->REQ_METHOD_S;
	if (met.len > PN_REASON_BUFSZ - 4)
		met.len = PN_REASON_BUFSZ - 4;
	sprintf(reason.s, "mid-%.*s", met.len, met.s);
	reason.len = 4 + met.len;

	/* trigger the Push Notification */
	ul.raise_ev_ct_refresh(c, &reason, &req->callid->body);

	ul.unlock_udomain(d, &r->aor);
	return 1;

err_unlock:
	ul.unlock_udomain(d, &r->aor);
	return -1;
}


int pn_add_reply_purr(const ucontact_t *ct)
{
	struct sip_uri puri;
	struct pn_provider *prov;

	if (!pn_enable_purr || !ct)
		return 0;

	if (parse_uri(ct->c.s, ct->c.len, &puri) != 0) {
		LM_ERR("failed to parse Contact URI: '%.*s'\n", ct->c.len, ct->c.s);
		return -1;
	}

	/* non-PN contact, uninteresting */
	if (!puri.pn_provider.s)
		return 0;

	for (prov = pn_providers; prov; prov = prov->next)
		if (str_match(&prov->name, &puri.pn_provider_val))
			goto have_provider;

	LM_DBG("skipping unknown provider '%.*s'\n",
	       puri.pn_provider_val.len, puri.pn_provider_val.s);
	return 0;

have_provider:
	if (!prov->append_fcaps) {
		LM_DBG("no need to add +sip.pnspurr for '%.*s'\n",
		       prov->name.len, prov->name.s);
		return 0;
	}

	sprintf(prov->feature_caps.s + prov->feature_caps.len, "%s\"" CRLF,
	        pn_purr_pack(ct->contact_id));

	return 0;
}


char *pn_purr_pack(ucontact_id ct_id)
{
	static char purr_buf[OPENSIPS_PURR_LEN + 1];

	sprintf(purr_buf, "%016lx", ct_id);

	memmove(purr_buf + 4, purr_buf + 3, 13);
	purr_buf[3] = '.';

	memmove(purr_buf + 10, purr_buf + 9, 8);
	purr_buf[9] = '.';

	/* the last byte is set to '\0' by default */
	return purr_buf;
}


int pn_purr_unpack(const str *purr, ucontact_id *ct_id)
{
	char purr_buf[OPENSIPS_PURR_LEN + 1], *p, c, *end;
	int i = 0;

	if (purr->len != OPENSIPS_PURR_LEN ||
	        purr->s[3] != '.' || purr->s[9] != '.')
		goto unknown_fmt;

	for (p = purr->s, end = p + OPENSIPS_PURR_LEN; p < end; p++) {
		c = *p;
		if (c == '.' && (i == 3 || i == 8))
			continue;

		if (!isxdigit(c))
			goto unknown_fmt;

		purr_buf[i++] = c;
	}

	purr_buf[16] = '\0';
	*ct_id = strtoul(purr_buf, NULL, 16);
	return 0;

unknown_fmt:
	LM_DBG("unrecognized pn-purr value format: '%.*s', skipping\n",
	       purr->len, purr->s);
	return -1;
}
