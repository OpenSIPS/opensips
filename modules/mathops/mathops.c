/*
 * Copyright (C) 2013 OpenSIPS Solutions
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
 * 2013-02-13: Created (Liviu)
 */


#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#define _ADDED_XOPEN
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>

#ifdef _ADDED_XOPEN
#undef _ADDED_XOPEN
#undef _XOPEN_SOURCE
#undef _GNU_SOURCE
#endif

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mod_fix.h"

#include "math_funcs.h"

/**
 * Module initialization function prototype
 */
static int mod_init(void);

/**
 * Module parameter variables
 */
int decimal_digits = 6; /* default number of decimal digits written into pvs */


/**
 * Function headers
 */
static int w_evaluate_exp(struct sip_msg *msg, str *exp, pv_spec_t *result);
static int w_evaluate_rpn(struct sip_msg *msg, str *exp, pv_spec_t *result);
static int w_basic_round_op(struct sip_msg *msg, str *exp, pv_spec_t *result,
                            double (*round_func)(double));
static int w_floor_op(struct sip_msg *msg, str *exp, pv_spec_t *result);
static int w_ceil_op(struct sip_msg *msg, str *exp, pv_spec_t *result);
static int w_trunc_op(struct sip_msg *msg, str *exp, pv_spec_t *result);
static int w_round_dp_op(struct sip_msg *msg, str *exp, pv_spec_t *result,
                         int *digits);
static int w_round_sf_op(struct sip_msg *msg, str *exp, pv_spec_t *result,
                         int *digits);


/**
 * Exported functions
 */

static cmd_export_t cmds[] = {
	{"math_eval", (cmd_function)w_evaluate_exp, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR,0,0}, {0,0,0}},
		ALL_ROUTES},
	{"math_rpn", (cmd_function)w_evaluate_rpn, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR,0,0}, {0,0,0}},
		ALL_ROUTES},
	{"math_floor",(cmd_function)w_floor_op, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR,0,0}, {0,0,0}},
		ALL_ROUTES},
	{"math_ceil",(cmd_function)w_ceil_op, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR,0,0}, {0,0,0}},
		ALL_ROUTES},
	{"math_trunc",(cmd_function)w_trunc_op, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR,0,0}, {0,0,0}},
		ALL_ROUTES},
	{"math_round",(cmd_function)w_round_dp_op, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR,0,0},
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, {0,0,0}},
		ALL_ROUTES},
	{"math_round_sf",(cmd_function)w_round_sf_op, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR,0,0},
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, {0,0,0}},
		ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

/**
 * Exported parameters
 */
static param_export_t params[] = {
	{"decimal_digits", INT_PARAM, &decimal_digits},
	{0, 0, 0}
};


/**
 * Module parameter variables
 */
struct module_exports exports = {
	"mathops",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,  /* module version */
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,     /* Exported functions */
	0,        /* Exported async functions */
	params,   /* Exported parameters */
	0,        /* exported statistics */
	0,        /* exported MI functions */
	0,        /* exported pseudo-variables */
	0,		  /* exported transformations */
	0,        /* extra processes */
	0,        /* module pre-initialization function */
	mod_init, /* module initialization function */
	0,        /* response function*/
	0,        /* destroy function */
	0,        /* per-child init function */
	0         /* reload confirm function */
};


static int mod_init(void)
{
	LM_DBG("Initializing...\n");

	LM_INFO("Module initialized!\n");

	return 0;
}


/**************************** Module functions *******************************/


static int w_evaluate_exp(struct sip_msg *msg, str *exp, pv_spec_t *result)
{
	LM_DBG("Evaluating expression: %.*s\n", exp->len, exp->s);

	return evaluate_exp(msg, exp, result);
}

static int w_evaluate_rpn(struct sip_msg *msg, str *exp, pv_spec_t *result)
{
	LM_DBG("Evaluating expression: %.*s\n", exp->len, exp->s);

	return evaluate_rpn(msg, exp, result);
}


static int w_floor_op(struct sip_msg *msg, str *number, pv_spec_t *result)
{
	return w_basic_round_op(msg, number, result, floor);
}


static int w_ceil_op(struct sip_msg *msg, str *number, pv_spec_t *result)
{
	return w_basic_round_op(msg, number, result, ceil);
}


static int w_trunc_op(struct sip_msg *msg, str *number, pv_spec_t *result)
{
	return w_basic_round_op(msg, number, result, trunc);
}


static int w_basic_round_op(struct sip_msg *msg, str *exp, pv_spec_t *result,
                            double (*round_func)(double))
{
	return basic_round_op(msg, exp, result, round_func);
}


static int w_round_dp_op(struct sip_msg *msg, str *exp, pv_spec_t *result,
                         int *digits)
{
	if (!digits)
		return round_dp_op(msg, exp, result, 0);

	return round_dp_op(msg, exp, result, *digits);
}


static int w_round_sf_op(struct sip_msg *msg, str *exp, pv_spec_t *result,
                         int *digits)
{
	if (!digits)
		return round_dp_op(msg, exp, result, 0);

	return round_sf_op(msg, exp, result, *digits);
}

