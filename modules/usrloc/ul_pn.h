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

#ifndef __UL_PN_H__
#define __UL_PN_H__

#include "../../parser/msg_parser.h"

#include "ul_mod.h"

int ul_init_pn(void);
int extract_pn_params(const str *uri, str *val_arr, int *val_len);

/* modparams */
extern int pn_enable;
extern int pn_pnsreg_interval;
extern int pn_trigger_interval;
extern char *_pn_ct_params;

/* useful fixups */
extern str *pn_ct_params;     /* array of parsed match params */
extern int pn_ct_params_n;    /* array size */
extern str *pn_ct_param_vals; /* helper array for building a unique key */

static inline int uri_has_pn_params(struct sip_uri *uri)
{
	for (int i = 0; i < pn_ct_params_n; i++) {
		for (int j = 0; j < uri->u_params_no; j++) {
			if (str_match(&pn_ct_params[i], &uri->u_name[j]))
				goto found_param;
		}

		return 0;

found_param:;
	}

	return 1;
}

static inline int _extract_pn_params(const struct sip_uri *uri,
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

#endif /* __UL_PN_H__ */
