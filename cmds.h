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

#ifndef _CORE_CMDS_H_
#define _CORE_CMDS_H_

#include "parser/msg_parser.h"
#include "route_struct.h"
#include "async.h"

#define MAX_CMD_PARAMS (MAX_ACTION_ELEMS-1)

/* parameter type flags */
#define CMD_PARAM_INT        (1<<0)  /* integer parameter */
#define CMD_PARAM_STR        (1<<1)  /* string parameter */
#define CMD_PARAM_VAR        (1<<2)  /* PV spec parameter */
#define CMD_PARAM_REGEX      (1<<3)  /* regexp string parameter */

#define CMD_PARAM_OPT        (1<<4)  /* optional parameter */
#define CMD_PARAM_FIX_NULL   (1<<5)  /* run fixup even if optional parameter is omitted */
#define CMD_PARAM_NO_EXPAND  (1<<6)  /* do not pv-expand strings */
#define CMD_PARAM_STATIC	 (1<<7)  /* don't accept variables or formatted string */

typedef  int (*cmd_function)(struct sip_msg*, void*, void*, void*, void*,
			void*, void*, void *, void *);
typedef  int (*acmd_function)(struct sip_msg*, async_ctx *ctx,
			void*, void*, void*, void*, void*, void*, void *, void *);
typedef  int (*fixup_function)(void** param);
typedef  int (*free_fixup_function)(void** param);

struct cmd_param {
	int flags;              /* parameter flags */
	fixup_function fixup;   /* pointer to the function called to "fix" the
							   parameter */
	free_fixup_function
				free_fixup; /* pointer to the function called to free the
							   "fixed" parameter */
};

struct cmd_export_ {
	char* name;                 /* null terminated command name */
	cmd_function function;      /* pointer to the corresponding function */
	struct cmd_param
		params[MAX_CMD_PARAMS+1]; /* array of parameters */
	int flags;                  /* Function flags */
};


struct acmd_export_ {
	char* name;                 /* null terminated command name */
	acmd_function function;     /* pointer to the corresponding function */
	struct cmd_param
		params[MAX_CMD_PARAMS+1]; /* array of parameters */
};

typedef struct cmd_export_  cmd_export_t;
typedef struct acmd_export_ acmd_export_t;

cmd_export_t* find_cmd_export_t(char* name, int flags);
int check_cmd_call_params(cmd_export_t *cmd, action_elem_t *elems, int no_params);
int check_acmd_call_params(acmd_export_t *acmd, action_elem_t *elems, int no_params);

cmd_export_t* find_core_cmd_export_t(char* name, int flags);
cmd_export_t* find_mod_cmd_export_t(char* name, int flags);
acmd_export_t* find_mod_acmd_export_t(char* name);

#endif /* _CORE_CMDS_H_ */
