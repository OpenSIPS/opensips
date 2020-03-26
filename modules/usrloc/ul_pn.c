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

#include "ul_pn.h"

int pn_enable;
int pn_pnsreg_interval = 130;  /* sec */
int pn_trigger_interval = 120; /* sec */
char *_pn_ct_params = "pn-provider; pn-prid; pn-param";

str *pn_ct_params;
int pn_ct_params_n;
str *pn_ct_param_vals;

int ul_init_pn(void)
{
	csv_record *pn_params, *pnp;
	int i;

	if (!pn_enable)
		return 0;

	/* parse the list of PN params */
	pn_params = __parse_csv_record(_str(_pn_ct_params), 0, ';');
	for (pnp = pn_params; pnp; pnp = pnp->next) {
		if (ZSTR(pnp->s))
			continue;

		pn_ct_params = pkg_realloc(pn_ct_params,
		                      (pn_ct_params_n + 1) * sizeof *pn_ct_params);
		if (!pn_ct_params) {
			LM_ERR("oom\n");
			return -1;
		}

		if (pkg_nt_str_dup(&pn_ct_params[pn_ct_params_n], &pnp->s)) {
			LM_ERR("oom\n");
			return -1;
		}

		pn_ct_params_n++;
	}
	free_csv_record(pn_params);

	if (!pn_ct_params) {
		LM_ERR("'pn_ct_match_params' must contain at least 1 param!\n");
		return -1;
	}

	/* helper array */
	pn_ct_param_vals = pkg_malloc(pn_ct_params_n * sizeof *pn_ct_param_vals);
	if (!pn_ct_param_vals) {
		LM_ERR("oom\n");
		return -1;
	}

	for (i = 0; i < pn_ct_params_n; i++)
		LM_DBG("pn_ct_match_param #%d: '%.*s'\n", i + 1,
		       pn_ct_params[i].len, pn_ct_params[i].s);

	return 0;
}

int extract_pn_params(const str *uri, str *val_arr, int *val_len)
{
	struct sip_uri puri;

	if (parse_uri(uri->s, uri->len, &puri) != 0) {
		LM_ERR("failed to parse URI: '%.*s'\n", uri->len, uri->s);
		return -1;
	}

	*val_len = 0;
	return _extract_pn_params(&puri, val_arr, val_len);
}
