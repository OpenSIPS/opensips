/**
 *
 * Copyright (C) 2016 OpenSIPS Foundation
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
 * History
 * -------
 *  2016-06-23  initial version (Ionut Ionita)
*/

#ifndef _ACC_VARS_H
#define _ACC_VARS_H

/* $acc_extra */
int pv_parse_acc_extra_name(pv_spec_p sp, str *in);
int pv_get_acc_extra(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val);
int pv_set_acc_extra(struct sip_msg *msg, pv_param_t *param, int flag,
		pv_value_t *val);
int set_value_shm(pv_value_t* pvt, extra_value_t* values);
/* $acc_current_leg */
int pv_get_acc_current_leg(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val);
/* $acc_leg */
int pv_parse_acc_leg_index(pv_spec_p sp, str* in);
int pv_parse_acc_leg_name(pv_spec_p sp, str *in);
int pv_get_acc_leg(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val);

int pv_set_acc_leg(struct sip_msg *msg, pv_param_t *param, int flag,
		pv_value_t *val);

void push_ctx_to_ctx(acc_ctx_t *src, acc_ctx_t *dst);

#endif
