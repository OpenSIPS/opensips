/**
 * SIP Push Notification support - RFC 8599
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
#include "../../ipc.h"
#include "../../usr_avp.h"
#include "../../parser/parse_uri.h"
#include "../../modules/tm/tm_load.h"
#include "../../modules/usrloc/usrloc.h"
#include "../../modules/usrloc/ul_evi.h"
#include "../../modules/event_routing/api.h"

#include "pn.h"

/* registrar modparams */
int pn_enable;
int pn_pnsreg_interval = 130;  /* sec */
int pn_trigger_interval = 120; /* sec */
int pn_skip_pn_interval = 0; /* sec */
int pn_inv_timeout = 6; /* sec */
str pn_provider_param = str_init("pn-provider");
char *_pn_ct_params = "pn-provider, pn-prid, pn-param";
char *_pn_providers;

str_list *pn_ct_params;

struct pn_provider *pn_providers;
static ebr_filter *pn_ebr_filters;

#define MAX_PROVIDER_LEN 20
#define MAX_PNSPURR_LEN 40
#define MAX_FEATURE_CAPS_SIZE \
	(sizeof("Feature-Caps: +sip.pns=\"\";" \
			"+sip.pnsreg=\"\";+sip.pnspurr=\"\"") + \
			MAX_PROVIDER_LEN + INT2STR_MAX_LEN + MAX_PNSPURR_LEN + CRLF_LEN)

static ebr_api_t ebr;
extern usrloc_api_t ul;
extern struct tm_binds tmb;
static ebr_event *ev_ct_update;


int pn_init(void)
{
	str_list *param;
	csv_record *items, *pnp;
	struct pn_provider *provider;
	ebr_filter *filter;

	if (!pn_enable)
		return 0;

	pn_provider_param.len = strlen(pn_provider_param.s);

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

		provider->feature_caps.s = (char *)(provider->name.s + pnp->s.len + 1);
		provider->feature_caps.len = sprintf(provider->feature_caps.s,
				"Feature-Caps: +sip.pns=\"%.*s\";+sip.pnsreg=\"%u\"\r\n",
							  // TODO: ";+sip.pnspurr=\"",
				pnp->s.len, pnp->s.s, pn_pnsreg_interval);

		add_last(provider, pn_providers);
		LM_DBG("parsed PN provider: '%.*s', hdr: '%.*s'\n", provider->name.len,
		       provider->name.s, provider->feature_caps.len,
		       provider->feature_caps.s);
	}
	free_csv_record(items);

	return 0;
}


enum pn_action pn_inspect_ct_params(const str *ct_uri)
{
	struct sip_uri puri;
	struct pn_provider *pvd;
	str_list *param;
	int i;

	if (parse_uri(ct_uri->s, ct_uri->len, &puri) != 0) {
		LM_ERR("failed to parse URI: '%.*s'\n", ct_uri->len, ct_uri->s);
		return -1;
	}

	for (i = 0; i < puri.u_params_no; i++)
		if (str_match(&puri.u_name[i], &pn_provider_param))
			goto match_provider;

	return PN_NONE;

match_provider:
	if (ZSTR(puri.u_val[i])) {
		for (pvd = pn_providers; pvd; pvd = pvd->next)
			pvd->append_fcaps = 1;
		return PN_LIST_ALL_PNS;
	}

	for (pvd = pn_providers; pvd; pvd = pvd->next)
		if (str_match(&puri.u_val[i], &pvd->name)) {
			pvd->append_fcaps = 1;
			goto match_params;
		}

	LM_DBG("unsupported PN provider: '%.*s'\n", puri.u_val[i].len,
	       puri.u_val[i].s);
	return PN_UNSUPPORTED_PNS;

match_params:
	for (param = pn_ct_params; param; param = param->next) {
		for (int i = 0; i < puri.u_params_no; i++)
			if (str_match(&param->s, &puri.u_name[i]))
				goto next_param;

		return PN_LIST_ONE_PNS;

next_param:;
	}

	return PN_ON;
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
			LM_BUG("EVI param no STR, nor INT, ignoring...\n");
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
	// TODO
	//tmb.t_inject_branch()
}


static void pn_rpc_raise_ct_refresh(int _, void *param)
{
	ul.raise_ev_ct_refresh((ucontact_t *)param);
}


int pn_trigger_pn(struct sip_msg *req, const ucontact_t *ct,
                  const struct sip_uri *ct_uri)
{
	ebr_filter *f;

	/* fill in the filter templates */
	for (f = pn_ebr_filters; f; f = f->next) {
		for (int i = 0; i < ct_uri->u_params_no; i++) {
			if (str_match(&f->uri_param_key, ct_uri->u_name + i)) {
				f->val = ct_uri->u_val[i];
				goto next_param;
			}
		}

		LM_ERR("failed to locate '%.*s' URI param in Contact '%.*s'\n",
		       f->uri_param_key.len, f->uri_param_key.s, ct->c.len, ct->c.s);
		return -1;

next_param:;
	}

	if (ebr.notify_on_event(req, ev_ct_update, pn_ebr_filters,
	        pn_trim_pn_params, pn_inject_branch, pn_inv_timeout) != 0) {
		LM_ERR("failed to subscribe to "UL_EV_CT_UPDATE", Contact: %.*s\n",
		       ct->c.len, ct->c.s);
		return -1;
	}

	if (ipc_dispatch_rpc(pn_rpc_raise_ct_refresh, (void *)ct) != 0) {
		LM_ERR("failed to send RPC for "UL_EV_CT_REFRESH"\n");
		return -1;
	}

	return 0;
}


int pn_has_uri_params(const str *ct, struct sip_uri *puri)
{
	str_list *param;
	struct sip_uri _puri;

	if (!puri)
		puri = &_puri;

	memset(puri, 0, sizeof *puri);

	if (parse_uri(ct->s, ct->len, puri) != 0) {
		LM_ERR("failed to parse contact: '%.*s'\n", ct->len, ct->s);
		return 0;
	}

	for (param = pn_ct_params; param; param = param->next) {
		for (int i = 0; i < puri->u_params_no; i++)
			if (str_match(&param->s, &puri->u_name[i]))
				goto next_param;

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

	if (pkg_str_extend(&buf, uri_len) != 0) {
		LM_ERR("oom\n");
		return -1;
	}
	buf_len = buf.len;

	memcpy(u_name_bak, puri->u_name, URI_MAX_U_PARAMS * sizeof *u_name_bak);

	for (param = pn_ct_params; param; param = param->next)
		for (int i = 0; i < puri->u_params_no; i++)
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

	LM_DBG("trimmed URI: '%.*s'\n", buf.len, buf.s);

	*out_uri = buf;
	buf.len = buf_len;
	return 0;
}
