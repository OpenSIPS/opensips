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

#include <errno.h>

#include "../../pvar.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../mem/mem.h"
#include "../../trim.h"

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

static int push_op(int type)
{
  if(top >= MAX_STACK_SIZE) {
		LM_ERR("RPN Stack Full\n");
    return -1;
  }

	stack[top].type = type;
	top++;
  return 0;
}

static int push_number(double value)
{
  if(top >= MAX_STACK_SIZE) {
		LM_ERR("RPN Stack Full\n");
    return -1;
  }

	LM_DBG("push %f\n",value);
	stack[top].type = MATHOP_NUMBER;
	stack[top].value = value;
	top++;
  return 0;
}

static int pop_number(double *value)
{
  if(top <= 0) {
		LM_ERR("RPN Stack Empty\n");
    return -1;
  }

	top--;

  if(stack[top].type != MATHOP_NUMBER) {
    LM_ERR("RPN Stack Top is not a number\n");
    return -1;
  }

	*value = stack[top].value;
	LM_DBG("pop = %f\n",*value);
  return 0;
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

static int rpn_eval(const token* t)
{
  double o1, o2;

  switch (t->type) {
  case MATHOP_NUMBER:
    return push_number(t->value);

  case MATHOP_ADD:
    return pop_number(&o2) || pop_number(&o1) || push_number(o1 + o2);

  case MATHOP_SUB:
    return pop_number(&o2) || pop_number(&o1) || push_number(o1 - o2);

  case MATHOP_MUL:
    return pop_number(&o2) || pop_number(&o1) || push_number(o1 * o2);

  case MATHOP_DIV:
    return pop_number(&o2) || pop_number(&o1) || push_number(o1 / o2);

  case MATHOP_NEG:
    return pop_number(&o1) || push_number(-o1);

  case MATHOP_DROP:
    return pop_number(&o1);

  case MATHOP_DUP:
    if(pop_number(&o1)) return -1;
    return push_number(o1) || push_number(o1);

  case MATHOP_SWAP:
    return pop_number(&o2) || pop_number(&o1) || push_number(o2) || push_number(o1);

  case MATHOP_MOD:
    return pop_number(&o2) || pop_number(&o1) || push_number(fmod(o1,o2));

  case MATHOP_POW:
    return pop_number(&o2) || pop_number(&o1) || push_number(pow(o1,o2));

  case MATHOP_EXP:
    return pop_number(&o1) || push_number(exp(o1));

  case MATHOP_LOG10:
    return pop_number(&o1) || push_number(log10(o1));

  case MATHOP_LN:
    return pop_number(&o1) || push_number(log(o1));

  case MATHOP_ABS:
    return pop_number(&o1) || push_number(fabs(o1));

  case MATHOP_SQRT:
    return pop_number(&o1) || push_number(sqrt(o1));

  case MATHOP_CBRT:
    return pop_number(&o1) || push_number(cbrt(o1));

  case MATHOP_FLOOR:
    return pop_number(&o1) || push_number(floor(o1));

  case MATHOP_CEIL:
    return pop_number(&o1) || push_number(ceil(o1));

  case MATHOP_ROUND:
    return pop_number(&o1) || push_number(round(o1));

  case MATHOP_NEARBYINT:
    return pop_number(&o1) || push_number(nearbyint(o1));

  case MATHOP_TRUNC:
    return pop_number(&o1) || push_number(trunc(o1));

  case MATHOP_E:
    return push_number(M_E);

  case MATHOP_PI:
    return push_number(M_PI);

  default:
    LM_WARN("Invalid RPN token type\n");
    return -1;
  }
}

#define inc_and_trim(s)   \
	do {                  \
		s.s++;            \
		s.len--;          \
		trim_leading(&s); \
	} while (0)

static inline void parse_word(str* _s, str* word)
{
  trim_leading(_s);
  word->len = 0;
  word->s = _s->s;
  for(; _s->len > 0; _s->len--, _s->s++) {
    switch(*(_s->s)) {
      case ' ':
      case '\t':
      case '\r':
      case '\n':
        return;

      default:
        word->len++;
        break;
    }
  }
}

struct mathop_entry {
  str s;
  int op;
};

const struct mathop_entry word_to_mathop[] = {
  {s:{ len:1, s:"+" }, op:MATHOP_ADD},
  {s:{ len:1, s:"-" }, op:MATHOP_SUB},
  {s:{ len:1, s:"*" }, op:MATHOP_MUL},
  {s:{ len:1, s:"/" }, op:MATHOP_DIV},
  {s:{ len:4, s:"drop" }, op:MATHOP_DROP},
  {s:{ len:3, s:"dup" }, op:MATHOP_DUP},
  {s:{ len:4, s:"swap" }, op:MATHOP_SWAP},
  {s:{ len:3, s:"mod" }, op:MATHOP_MOD},
  {s:{ len:3, s:"pow" }, op:MATHOP_POW},
  {s:{ len:3, s:"exp" }, op:MATHOP_EXP},
  {s:{ len:2, s:"ln" }, op:MATHOP_LN},
  {s:{ len:3, s:"log10" }, op:MATHOP_LOG10},
  {s:{ len:3, s:"abs" }, op:MATHOP_ABS},
  {s:{ len:3, s:"neg" }, op:MATHOP_NEG},
  {s:{ len:4, s:"sqrt" }, op:MATHOP_SQRT},
  {s:{ len:4, s:"cbrt" }, op:MATHOP_CBRT},
  {s:{ len:5, s:"floor" }, op:MATHOP_FLOOR},
  {s:{ len:4, s:"ceil" }, op:MATHOP_CEIL},
  {s:{ len:5, s:"round" }, op:MATHOP_ROUND},
  {s:{ len:9, s:"nearbyint" }, op:MATHOP_NEARBYINT},
  {s:{ len:5, s:"trunc" }, op:MATHOP_TRUNC},
  {s:{ len:1, s:"e" }, op:MATHOP_E},
  {s:{ len:2, s:"pi" }, op:MATHOP_PI},
  {s:{ len:0, s:NULL}, op:-1}
};

static int get_rpn_op(str *_s)
{
  str word;
  const struct mathop_entry* j;

  trim_leading(_s);
  parse_word(_s,&word);
  if(word.len == 0) {
    return -1;
  }

  for( j = word_to_mathop; j->s.len > 0; j++ ) {
    if(j->s.len == word.len && !strncmp(j->s.s,word.s,j->s.len)) {
      return j->op;
    }
  }

  LM_WARN("Parse expr error: Invalid operator! <%.*s>\n", word.len, word.s);
  return -1;
}

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

		if (*s.s >= '0' && *s.s <= '9') {
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

static int parse_rpn(str *exp)
{
  double d;
  char *p;
  int op;
  str s;

  p = exp->s;
  s.s = exp->s;
  s.len = exp->len;

  while (s.len) {

    if (*s.s >= '0' && *s.s <= '9') {
      errno = 0;
      d = strtod(s.s, &p);

      s.len -= p - s.s;
      s.s = p;

      if (errno == ERANGE) {
        LM_WARN("Overflow in parsing a numeric value!\n");
        return -1;
      }

      output[pos].type = MATHOP_NUMBER;
      output[pos].value = d;
      pos++;
    } else {
      op = get_rpn_op(&s);
      if (op < 0) {
        return -1;
      }

      output[pos].type = op;
      pos++;
    }
    trim_leading(&s);
  }

  return 0;
}

/**
 * The function assumes that the 'output' buffer is properly written and
 * the 'pos' variable holds the size of the buffer
 */
static int evaluate_rpn_output(double *result)
{
	int i;

	for (i = 0; i < pos; i++) {
		if(rpn_eval(output+i) < 0) {
        return -1;
		}
	}

	if (top != 1) {
		LM_ERR("Parse expr error: stack has %d elements\n",top);
		return -1;
	}

	return pop_number(result);
}


/**
 * Computes the result of a given expression
 */
int evaluate_exp(struct sip_msg *msg, str *exp, pv_spec_p result_var, short is_rpn)
{
	double result;
	pv_value_t pv_val;

	trim(exp);

	/* reset stack and output markers */
	top = 0;
	pos = 0;

	if(is_rpn) {
		if (parse_rpn(exp) != 0) {
			LM_ERR("Failed to parse RPN!\n");
			return -1;
		}
	} else {
		if (convert_to_rpn(exp) != 0) {
			LM_ERR("Failed to convert expression to RPN form!\n");
			return -1;
		}
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

