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
#include "../../parser/parse_uri.h"

#include "pn.h"

/* modparams */
int pn_enable;
int pn_pnsreg_interval = 130;  /* sec */
int pn_trigger_interval = 120; /* sec */
char *pn_provider_param = "pn-provider";
char *_pn_ct_params = "pn-provider, pn-prid, pn-param";
char *_pn_providers;

str_list *pn_ct_params;

struct pn_provider *pn_providers;

#define MAX_PROVIDER_LEN 20
#define MAX_PNSPURR_LEN 40
#define MAX_FEATURE_CAPS_SIZE \
	(sizeof("Feature-Caps: +sip.pns=\"\";" \
			"+sip.pnsreg=\"\";+sip.pnspurr=\"\"") + \
			MAX_PROVIDER_LEN + INT2STR_MAX_LEN + MAX_PNSPURR_LEN + CRLF_LEN)


int pn_init(void)
{
	str_list *param;
	csv_record *items, *pnp;
	struct pn_provider *provider;

	if (!pn_enable)
		return 0;

	if (!_pn_providers) {
		LM_ERR("the 'pn_providers' modparam is missing\n");
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
		if (str_match(&puri.u_name[i], _str(pn_provider_param)))
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
