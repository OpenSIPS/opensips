/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * -------
 * 2013-02-13: Created (Liviu)
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>

#include "math_funcs.h"

static char print_buffer[MATHOP_REAL_DIGITS + MATHOP_DECIMAL_DIGITS];

static token stack[MAX_STACK_SIZE];
static token output[MAX_STACK_SIZE];

int top = 0;
int pos = 0;

static int precedence(int op)
{
	switch (op) {

	case MATHOP_ADD:
	case MATHOP_SUB:
		return 1;
	
	case MATHOP_MUL:
	case MATHOP_DIV:
		return 2;
	
	default:
		return 3;
	}
}

static int get_op(char symbol)
{
	switch (symbol) {
		case MATHOP_PLUS:
			return  MATHOP_ADD;

		case MATHOP_MINUS:
			return  MATHOP_SUB;

		case MATHOP_MULT:
			return  MATHOP_MUL;

		case MATHOP_SLASH:
			return  MATHOP_DIV;

		default:
			return -1;
	}
}

static void push_op(int type)
{
	stack[top].type = type;
	top++;
}

static void push_number(int type, double value)
{
	stack[top].type = type;
	stack[top].value = value;
	top++;
}

static double pop_number(void)
{
	top--;

	return stack[top].value;
}

static void pop_to_output(void)
{
	output[pos++] = stack[--top];
}

static void pop_while_higher(int op_type)
{
	while (top > 0 && stack[top-1].type != MATHOP_LPAREN &&
	       precedence(stack[top-1].type) >= precedence(op_type))
	{
		pop_to_output();
	}
}

static double pop_and_eval(int op_type)
{
	double o1, o2;

	o2 = pop_number();
	o1 = pop_number();

	switch (op_type) {
	case MATHOP_ADD:
		return o1 + o2;
	
	case MATHOP_SUB:
		return o1 - o2;
	
	case MATHOP_MUL:
		return o1 * o2;
	
	case MATHOP_DIV:
		return o1 / o2;
	
	default:
		return 0;
	}
}

#define inc_and_trim(s)   \
	do {                  \
		s.s++;            \
		s.len--;          \
		trim_leading(&s); \
	} while (0)

/**
 * Shunting-yard algorithm
 *
 * Converts an expression to Reverse Polish Notation
 * Result is written to the 'output' buffer
 */
static int convert_to_rpn(str *exp)
{
	double d;
	char *p;
	int op;
	str s;

	p = exp->s;
	s.s = exp->s;
	s.len = exp->len;

	while (s.len) {

		if (*s.s > '0' && *s.s < '9') {
			errno = 0;
			d = strtod(s.s, &p);

			s.len -= p - s.s;
			s.s = p;

			if (errno == ERANGE) {
				LM_WARN("Overflow in parsing a numeric value!\n");
			}

			output[pos].type = MATHOP_NUMBER;
			output[pos].value = d;
			pos++;

			trim_leading(&s);
			continue;
		}

		switch (*s.s) {

		case MATHOP_L_PAREN:

			push_op(MATHOP_LPAREN);
			inc_and_trim(s);
			break;

		case MATHOP_R_PAREN:
			
			while (top > 0 && stack[top-1].type != MATHOP_LPAREN) {
				pop_to_output();
			}

			if (top == 0) {
				LM_ERR("Parse expr error: mismatched parantheses!\n");
				return -1;
			}

			/* just pop the left paranthesis off the stack */
			top--;

			inc_and_trim(s);

			break;

		default:

			op = get_op(*s.s);
			if (op < 0) {
				LM_WARN("Parse expr error: Invalid operator! <%c>\n", *s.s);
				return -1;
			}

			pop_while_higher(op);
			push_op(op);

			inc_and_trim(s);
		}
	}

	/* since ADD has lowest precedence, this will pop all remaining operators */
	pop_while_higher(MATHOP_ADD);

	return 0;
}

/**
 * The function assumes that the 'output' buffer is properly written and
 * the 'pos' variable holds the size of the buffer
 */
static int evaluate_rpn_output(double *result)
{
	int i;
	double val;

	/* since all supported operators are binary, just hardcode the 2 */
	for (i = 0; i < pos; i++) {
		
		if (output[i].type == MATHOP_NUMBER) {
			push_number(MATHOP_NUMBER, output[i].value);
		} else if (top >= 2) {
			val = pop_and_eval(output[i].type);
			push_number(MATHOP_NUMBER, val);

		} else {
			LM_ERR("Parse expr error: insufficient operands!\n");
			return -1;
		}
	}

	if (top > 1) {
		LM_ERR("Parse expr error: insufficient operators/closing parantheses!\n");
		return -1;
	}

	*result = stack[top-1].value;
	return 0;
}


/**
 * Computes the result of a given expression
 */
int evaluate_exp(struct sip_msg *msg, str *exp, pv_spec_p result_var)
{
	double result;
	pv_value_t pv_val;

	trim(exp);

	/* reset stack and output markers */
	top = 0;
	pos = 0;

	if (convert_to_rpn(exp) != 0) {
		LM_ERR("Failed to convert expression to RPN form!\n");
		return -1;
	}

	if (evaluate_rpn_output(&result) != 0) {
		LM_ERR("Mismatched tokens in expression: <%.*s>\n", exp->len, exp->s);
		return -1;
	}

	sprintf(print_buffer, "%.*lf", decimal_digits, result);
	
	pv_val.flags = PV_VAL_STR;
	pv_val.rs.s = print_buffer;
	pv_val.rs.len = strlen(print_buffer);
	
	if (pv_set_value(msg, result_var, 0, &pv_val) != 0)
	{
		LM_ERR("SET output value failed.\n");
		return -1;
	}

	return 1;
}


/**
 * Basic rounding to nearest integer functions: floor, ceil, trunc
 */
int basic_round_op(struct sip_msg *msg, str *n, pv_spec_p result_var,
                   double (*math_op)(double))
{
	double d;
	pv_value_t pv_val;

	errno = 0;
	d = strtod(n->s, NULL);

	if (errno == ERANGE) {
		LM_WARN("Overflow in parsing a numeric value!\n");
	}

	pv_val.flags = PV_VAL_INT|PV_TYPE_INT;
	pv_val.ri = (int)math_op(d);

	if (pv_set_value(msg, result_var, 0, &pv_val) != 0)
	{
		LM_ERR("SET output value failed.\n");
		return -1;
	}

	return 1;
}


/**
 * Rounds a number away from zero [ to the specified number of decimal digits ]
 */
int round_dp_op(struct sip_msg *msg, str *n, pv_spec_p result_var, int digits)
{
	double d;
	pv_value_t pv_val;

	errno = 0;
	d = strtod(n->s, NULL);

	if (errno == ERANGE) {
		LM_WARN("Overflow in parsing a numeric value!\n");
	}

	if (digits == 0) {
		pv_val.flags = PV_TYPE_INT|PV_VAL_INT;
		pv_val.ri = (int)round(d);
	} else {
		sprintf(print_buffer, "%.*lf", digits, d);
	
		pv_val.flags = PV_VAL_STR;
		pv_val.rs.s = print_buffer;
		pv_val.rs.len = strlen(print_buffer);
	}

	if (pv_set_value(msg, result_var, 0, &pv_val) != 0)
	{
		LM_ERR("SET output value failed.\n");
		return -1;
	}

	return 1;
}


/**
 * Rounds a number to the given number of significant digits
 */
int round_sf_op(struct sip_msg *msg, str *n, pv_spec_p result_var, int digits)
{
	double d, factor;
	pv_value_t pv_val;

	d = strtod(n->s, NULL);
	factor = pow(10.0, digits - ceil(log10(fabs(d))));
	d = round(d * factor) / factor;

	sprintf(print_buffer, "%.*f", decimal_digits, d);
	
	pv_val.flags = PV_VAL_STR;
	pv_val.rs.s = print_buffer;
	pv_val.rs.len = strlen(print_buffer);

	if (pv_set_value(msg, result_var, 0, &pv_val) != 0)
	{
		LM_ERR("SET output value failed.\n");
		return -1;
	}

	return 1;
}

