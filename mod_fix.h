/*
 * Copyright (C) 2001-2003 FhG Fokus
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


#ifndef _mod_fix_h_
#define _mod_fix_h_

#include <regex.h>
#include "mem/mem.h"
#include "pvar.h"
#include "route_struct.h"

#define GPARAM_TYPE_VAL		0
#define GPARAM_TYPE_PVS		1
#define GPARAM_TYPE_PVE		2
#define GPARAM_TYPE_FIXUP	3

typedef struct _gparam
{
	int type;
	void *pval;
	union {
		int ival;
		str sval;
	} v;
} gparam_t, *gparam_p;


struct cmd_param;

int check_cmd(const struct cmd_param *params, action_elem_t *elems);
int fix_cmd(const struct cmd_param *params, action_elem_t *elems);
int get_cmd_fixups(struct sip_msg* msg, const struct cmd_param *params,
				action_elem_t *elems, void **cmdp, pv_value_t *tmp_val);
int free_cmd_fixups(const struct cmd_param *params, action_elem_t *elems, void **cmdp);

/* Helper function that parses CSV named flags and sets the bitmasks / returns
 * the string values for key-value type of flags ("flag_name=flag_value")
 * @param - function parameter as received by the fixup function; *param will
 * be set with the OR'ed bitmasks
 * @flag_names - array of flag names which will be translated to bitmasks
 * according to the indexes of the flag names in the array, i.e. (1<<array_idx)
 * @kv_flag_names - array of key-value flag names
 * @kv_flag_vals - array of flag values to be returned; each str the in the
 * array will be set if the corresponding flag from @kv_flag_names is present
 */
int fixup_named_flags(void** param, str *flag_names, str *kv_flag_names,
	str *kv_flag_vals);

static inline int fixup_free_pkg(void **param)
{
	pkg_free(*param);
	return 0;
}

#endif
