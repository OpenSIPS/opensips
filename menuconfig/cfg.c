/*
 * Copyright (C) 2012 OpenSIPS Solutions
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
 * History:
 * -------
 *  2012-01-19  created (vlad)
 */

#include "string.h"

#include "cfg.h"
#include "main.h"

/* Configs that will be used to generate the Menus
 * Add more CFG entries here
*/
cfg_gen_t configs[] = {
	{CONF_RESIDENTIAL_SCRIPT,"residential","opensips_residential_def.m4","opensips_residential.m4"},
	{CONF_TRUNKING_SCRIPT,"trunking","opensips_trunking_def.m4","opensips_trunking.m4"},
	{CONF_LB_SCRIPT,"loadbalancer","opensips_loadbalancer_def.m4","opensips_loadbalancer.m4"},
	{0,0,0,0}
};

/* Finds a cfg entry with the specified name
 * Returns NULL on failure
*/
cfg_gen_t* find_cfg_entry(char *name)
{
	cfg_gen_t *it;

	for (it=configs;it->name;it++) {
		if (strcmp(name,it->name) == 0)
			return it;
	}

	return NULL;
}

