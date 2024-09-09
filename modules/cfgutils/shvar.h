/*
 * Copyright (C) 2007 Elena-Ramona Modroiu
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
 */

#ifndef _SHVAR_H_
#define _SHVAR_H_

#include "../../sr_module.h"
#include "../../mi/mi.h"
#include "../../script_var.h"

extern int shv_hash_size;

typedef struct sh_var {
	int n;                  /* Index of the variable */
	str name;               /* Name of the variable */
	script_val_t v;         /* Value of the variable */

	int hash_entry;         /* pre-computed hash(name) */
	struct sh_var *next;
} sh_var_t, *sh_var_p;

int init_shvars(void);
void destroy_shvars();

int pv_parse_shvar_name(pv_spec_p sp, const str *in);
int pv_get_shvar(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res);
int pv_set_shvar(struct sip_msg* msg, pv_param_t *param, int op,
		pv_value_t *val);

mi_response_t *mi_shvar_get(const mi_params_t *_, struct mi_handler *__);
mi_response_t *mi_shvar_get_1(const mi_params_t *params, struct mi_handler *_);
mi_response_t *mi_shvar_set(const mi_params_t *params, struct mi_handler *_);

int param_set_var( modparam_t type, void* val);
int param_set_shvar( modparam_t type, void* val);

/*** $time(name) PV class */
int pv_parse_time_name(pv_spec_p sp, const str *in);
int pv_get_time(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

#endif

