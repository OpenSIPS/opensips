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

#ifndef __REG_PN_H__
#define __REG_PN_H__

#include "../../parser/msg_parser.h"
#include "../../parser/parse_uri.h"
#include "../../str_list.h"
#include "../../ut.h"

struct pn_provider {
	str name;
	str feature_caps;

	struct pn_provider *next;
};

/* modparams */
extern int pn_enable;
extern int pn_pnsreg_interval;
extern int pn_trigger_interval;
extern char *_pn_ct_params;
extern char *_pn_providers;

/* useful fixups */
extern str_list *pn_ct_params;  /* list of parsed match params */
extern int pn_ct_params_n;      /* list size */
extern struct pn_provider *pn_providers;


/**
 * initialize RFC 8599 support
 */
int pn_init(void);


//TODO
#if 0
/**
 * parse and extract all PN parameters from @uri into the
 *     @val_arr array.  Also sum their lengths into @val_len
 * @return: 0 if all parameters found, otherwise -1
 */
int pn_extract_params(const str *uri, str *val_arr, int *val_len);


/**
 * similar to the above, except it receives a parsed URI
 * @return: 0 if all parameters found, otherwise -1
 */
static inline int _pn_extract_params(const struct sip_uri *uri,
                                     str *val_arr, int *val_len);
#endif


/**
 * check whether the given SIP @uri string contains all PN params
 * @return: 1 on success, otherwise 0
 */
static inline int pn_uri_has_params(const str *uri);


/**
 * build a Feature-Caps header with all server capabilities, store it in @out
 * @return: 0 on success, -1 otherwise
 */
int pn_build_feature_caps(const str *provider, str *out);


/* ------------------------------------------------------------------------- */


static inline int pn_uri_has_params(const str *uri)
{
	struct sip_uri puri;
	str_list *pnp;

	if (parse_uri(uri->s, uri->len, &puri) != 0) {
		LM_ERR("failed to parse URI: '%.*s'\n", uri->len, uri->s);
		return -1;
	}

	for (pnp = pn_ct_params; pnp; pnp = pnp->next) {
		for (int i = 0; i < puri.u_params_no; i++)
			if (str_match(&pnp->s, &puri.u_name[i]))
				goto found_param;

		return 0;

found_param:;
	}

	return 1;
}

//TODO
#if 0
static inline int _pn_extract_params(const struct sip_uri *uri,
                                     str *val_arr, int *val_len)
{
	for (int i = 0; i < pn_ct_params_n; i++) {
		for (int j = 0; j < uri->u_params_no; j++) {
			if (str_match(&pn_ct_params[i], &uri->u_name[j])) {
				val_arr[i] = uri->u_val[j];
				*val_len += uri->u_val[j].len;
				goto found_param;
			}
		}

		return -1;

found_param:;
	}

	return 0;
}
#endif

#endif /* __REG_PN_H__ */
