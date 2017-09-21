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
 * Fixup functions
 */
static int fixup_evaluate_exp(void **param, int param_no);
static int fixup_binary_op(void **param, int param_no);
static int fixup_round_op(void **param, int param_no);

/**
 * Function headers
 */
static int w_evaluate_exp(struct sip_msg *msg, char *exp, char *result);
static int w_evaluate_rpn(struct sip_msg *msg, char *exp, char *result);
static int w_basic_round_op(struct sip_msg *msg, char *number, char *result,
                            double (*math_op)(double));
static int w_floor_op(struct sip_msg *msg, char *number, char *result);
static int w_ceil_op(struct sip_msg *msg, char *number, char *result);
static int w_trunc_op(struct sip_msg *msg, char *number, char *result);
static int w_round_dp_op(struct sip_msg *msg, char *number, char *result,
                         char *digits);
static int w_round_sf_op(struct sip_msg *msg, char *number, char *result,
                         char *digits);


/**
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"math_eval",(cmd_function)w_evaluate_exp, 2, fixup_evaluate_exp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE},
	{"math_rpn",(cmd_function)w_evaluate_rpn, 2, fixup_evaluate_exp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE},
	{"math_floor",(cmd_function)w_floor_op, 2, fixup_binary_op, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE},
	{"math_ceil",(cmd_function)w_ceil_op, 2, fixup_binary_op, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE},
	{"math_trunc",(cmd_function)w_trunc_op, 2, fixup_binary_op, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE},
	{"math_round",(cmd_function)w_round_dp_op, 2, fixup_binary_op, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE},
	{"math_round",(cmd_function)w_round_dp_op, 3, fixup_round_op, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE},
	{"math_round_sf",(cmd_function)w_round_sf_op, 3, fixup_round_op, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE},
	{0, 0, 0, 0, 0, 0}
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
	NULL,            /* OpenSIPS module dependencies */
	cmds,     /* Exported functions */
	0,        /* Exported async functions */
	params,   /* Exported parameters */
	0,        /* exported statistics */
	0,        /* exported MI functions */
	0,        /* exported pseudo-variables */
	0,		  /* exported transformations */
	0,        /* extra processes */
	mod_init, /* module initialization function */
	0,        /* response function*/
	0,        /* destroy function */
	0         /* per-child init function */
};


static int mod_init(void)
{
	LM_DBG("Initializing...\n");

	LM_INFO("Module initialized!\n");

	return 0;
}

/**************************** Fixup functions ********************************/


static int fixup_binary_op(void **param, int param_no)
{
	pv_spec_p sp;
	str s;

	switch (param_no) {
	case 1:
		return fixup_sgp(param);

	case 2:
		if (!(sp = pkg_malloc(sizeof(*sp)))) {
			LM_ERR("No more pkg memory!\n");
			return -1;
		}

		memset(sp, 0, sizeof(*sp));

		s.s = (char *)*param; s.len = strlen(s.s);
		if (!pv_parse_spec(&s, sp)) {
			LM_ERR("Parameter 2 only accepts pvars! Given: <%.*s>\n", s.len, s.s);
			return -1;
		}

		*param = (void *)sp;
		return 0;

	default:
		LM_ERR("Invalid parameter number: %d\n", param_no);
		return E_UNSPEC;
	}
}


static int fixup_round_op(void **param, int param_no)
{
	switch (param_no) {
	case 1:
	case 2:
		return fixup_binary_op(param, param_no);
	case 3:
		return fixup_igp(param);

	default:
		LM_ERR("Invalid parameter number: %d\n", param_no);
		return E_UNSPEC;
	}
}


static int fixup_evaluate_exp(void **param, int param_no)
{
	pv_elem_p ep;
	pv_spec_p sp;
	str s;

	if (param_no != 1 && param_no != 2) {
		LM_ERR("Invalid parameter number: %d\n", param_no);
		return E_UNSPEC;
	}

	if (param_no == 1) {

    	s.s = (char*)(*param); s.len = strlen(s.s);

		if (pv_parse_format(&s, &ep) < 0) {
		    LM_ERR("wrong format[%.*s]\n", s.len, s.s);
		    return E_UNSPEC;
		}

		*param = (void *)ep;
		return 0;

	} else {
		if (!(sp = pkg_malloc(sizeof(*sp)))) {
			LM_ERR("No more pkg memory!\n");
			return -1;
		}

		memset(sp, 0, sizeof(*sp));

		s.s = (char *)*param; s.len = strlen(s.s);
		if (!pv_parse_spec(&s, sp)) {
			LM_ERR("Parameter 2 only accepts pvars! Given: <%.*s>\n", s.len, s.s);
			return -1;
		}

		*param = (void *)sp;
		return 0;
	}
}


/**************************** Module functions *******************************/


static int w_evaluate_exp(struct sip_msg *msg, char *exp, char *result)
{
	pv_elem_p exp_fmt = (pv_elem_p)exp;
	str s;

	if (pv_printf_s(msg, exp_fmt, &s) != 0) {
		LM_ERR("Failed to print the pv format string!\n");
		return -1;
	}

	LM_DBG("Evaluating expression: %.*s\n", s.len, s.s);

	return evaluate_exp(msg, &s, (pv_spec_p)result);
}

static int w_evaluate_rpn(struct sip_msg *msg, char *exp, char *result)
{
	pv_elem_p exp_fmt = (pv_elem_p)exp;
	str s;

	if (pv_printf_s(msg, exp_fmt, &s) != 0) {
		LM_ERR("Failed to print the pv format string!\n");
		return -1;
	}

	LM_DBG("Evaluating expression: %.*s\n", s.len, s.s);

	return evaluate_rpn(msg, &s, (pv_spec_p)result);
}


static int w_floor_op(struct sip_msg *msg, char *number, char *result)
{
	return w_basic_round_op(msg, number, result, floor);
}


static int w_ceil_op(struct sip_msg *msg, char *number, char *result)
{
	return w_basic_round_op(msg, number, result, ceil);
}


static int w_trunc_op(struct sip_msg *msg, char *number, char *result)
{
	return w_basic_round_op(msg, number, result, trunc);
}


static int w_basic_round_op(struct sip_msg *msg, char *number, char *result,
                            double (*round_func)(double))
{
	str n;

	if (fixup_get_svalue(msg, (gparam_p)number, &n) != 0) {
		LM_ERR("Invalid number pseudo variable!\n");
		return -1;
	}

	return basic_round_op(msg, &n, (pv_spec_p)result, round_func);
}


static int w_round_dp_op(struct sip_msg *msg, char *number, char *result,
                         char *digits)
{
	int d;
	str n;

	if (fixup_get_svalue(msg, (gparam_p)number, &n) != 0) {
		LM_ERR("Invalid number pseudo variable!\n");
		return -1;
	}

	if (!digits)
		return round_dp_op(msg, &n, (pv_spec_p)result, 0);

	if (fixup_get_ivalue(msg, (gparam_p)digits, &d) != 0) {
		LM_ERR("Invalid digits pseudo variable!\n");
		return -1;
	}

	return round_dp_op(msg, &n, (pv_spec_p)result, d);
}


static int w_round_sf_op(struct sip_msg *msg, char *number, char *result,
                         char *digits)
{
	int d;
	str n;

	if (fixup_get_svalue(msg, (gparam_p)number, &n) != 0) {
		LM_ERR("Invalid number pseudo variable!\n");
		return -1;
	}

	if (!digits)
		return round_dp_op(msg, &n, (pv_spec_p)result, 0);

	if (fixup_get_ivalue(msg, (gparam_p)digits, &d) != 0) {
		LM_ERR("Invalid digits pseudo variable!\n");
		return -1;
	}

	return round_sf_op(msg, &n, (pv_spec_p)result, d);
}

