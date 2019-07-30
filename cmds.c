/*
 * Copyright (C) 2019 OpenSIPS Solutions
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

#include "cmds.h"

cmd_export_t* find_cmd_export_t(char* name, int flags)
{
	cmd_export_t* cmd;

	cmd = find_core_cmd_export_t(name, flags);
	if (!cmd)
		cmd = find_mod_cmd_export_t(name, flags);

	return cmd;
}

/* Checks if the module function is called with the right number of parameters
 * and all mandatory parameters are given
 * Return:
 *  0 - correct call
 * -1 - too few parameters
 * -2 - too many parameters
 * -3 - mandatory parameter omitted
 */
int check_cmd_call_params(cmd_export_t *cmd, action_elem_t *elems, int no_params)
{
	struct cmd_param *param;
	int n=0, m=0, i;

	for (param=cmd->params; param->flags; param++, n++)
		if (!(param->flags & CMD_PARAM_OPT))
			m = n+1;

	if (no_params < m)  /* check the minimum number of arguments for the call,
						 * including optional params that must be explicitly omitted */
		return -1;
	else if (no_params > n)
		return -2;

	for (i=1, param=cmd->params; i<=no_params; i++, param++)
		if (!(param->flags & CMD_PARAM_OPT) && elems[i].type == NULLV_ST)
			return -3;

	return 0;
}

/* simillar function to check_cmd_call_params but for async cmds */
int check_acmd_call_params(acmd_export_t *acmd, action_elem_t *elems, int no_params)
{
	struct cmd_param *param;
	int n=0, m=0, i;

	for (param=acmd->params; param->flags; param++, n++)
		if (!(param->flags & CMD_PARAM_OPT))
			m = n+1;

	if (no_params < m)  /* check the minimum number of arguments for the call,
						 * including optional params that must be explicitly omitted */
		return -1;
	else if (no_params > n)
		return -2;

	for (i=1, param=acmd->params; i<=no_params; i++, param++)
		if (!(param->flags & CMD_PARAM_OPT) && elems[i].type == NULLV_ST)
			return -3;

	return 0;
}
