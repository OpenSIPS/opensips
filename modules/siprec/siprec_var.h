/*
 * Copyright (C) 2021 OpenSIPS Project
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _SIPREC_VAR_H_
#define _SIPREC_VAR_H_

#include "../../str.h"
#include "../../pvar.h"
#include "../../socket_info.h"

struct srec_var {
	str group, caller, callee, media, headers, group_custom_extension, session_custom_extension;
	struct socket_info *si;
};

int init_srec_var(void);
int pv_parse_siprec(pv_spec_p sp, const str *in);
int pv_get_siprec(struct sip_msg *msg,  pv_param_t *param,
		pv_value_t *val);
int pv_set_siprec(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val);

struct srec_var *get_srec_var(void);

#endif /* _SIPREC_VAR_H_ */
