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

#ifndef __MATHOPS_H__
#define __MATHOPS_H__

#include <math.h>
#include "tinyexpr.h"

#define MAX_STACK_SIZE   100

#define MATHOP_PLUS    '+'
#define MATHOP_MINUS   '-'
#define MATHOP_MULT    '*'
#define MATHOP_SLASH   '/'
#define MATHOP_L_PAREN '('
#define MATHOP_R_PAREN ')'

#define MATHOP_REAL_DIGITS    128
#define MATHOP_DECIMAL_DIGITS 128

extern int decimal_digits;

enum { MATHOP_NUMBER = 0, MATHOP_LPAREN, MATHOP_ADD, MATHOP_SUB, MATHOP_MUL,
       MATHOP_DIV, MATHOP_DROP, MATHOP_DUP, MATHOP_SWAP, MATHOP_MOD, MATHOP_NEG,
       MATHOP_POW, MATHOP_EXP, MATHOP_LN, MATHOP_LOG10, MATHOP_ABS, MATHOP_SQRT,
       MATHOP_CBRT, MATHOP_FLOOR, MATHOP_CEIL, MATHOP_ROUND, MATHOP_NEARBYINT,
       MATHOP_TRUNC, MATHOP_E, MATHOP_PI };

typedef struct _token {
	int type;
	double value;
} token;

/**
 * Exported function headers
 */
int basic_round_op(struct sip_msg *msg, str *n, pv_spec_p result_var,
                   double (*math_op)(double));
int round_dp_op(struct sip_msg *msg, str *n, pv_spec_p result_var, int digits);
int round_sf_op(struct sip_msg *msg, str *n, pv_spec_p result_var, int digits);

int evaluate_rpn(struct sip_msg *msg, str *exp, pv_spec_p result_var);
int evaluate_exp(struct sip_msg *msg, str *exp, pv_spec_p result_var);

#endif /* __MATHOPS_H__ */
