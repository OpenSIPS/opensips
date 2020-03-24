/**
 * Fraud Detection Module
 *
 * Copyright (C) 2016 OpenSIPS Foundation
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
 * History
 * -------
 *  2016-06-23  initial version (Ionut Ionita)
*/
#include <stdio.h>
#include <string.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "acc_extra.h"
#include "acc_logic.h"

#define GET_EXTRA_VALUE_SAFE(val_ptr, extra) \
	do { \
		*val_ptr = extra->value; \
	} while(0);

#define ACC_CTX_VAL_DELETED  (-1)

extern int    extra_tgs_len;
extern tag_t* extra_tags;

extern int    leg_tgs_len;
extern tag_t* leg_tags;

extern int acc_flags_ctx_idx;

/*
 * acc_extra
 * VARIABLE
 * ***********************/

/*
 * parse $acc_extra variable name
 */
int pv_parse_acc_extra_name(pv_spec_p sp, str *in)
{
	int idx;

	if (sp == NULL || in == NULL || in->s == NULL || in->len == 0) {
		LM_ERR("bad name!\n");
		return -1;
	}

	str_trim_spaces_lr(*in);

	for (idx = 0; idx < extra_tgs_len; idx++) {
		if (!str_strcmp(in, &extra_tags[idx])) {
			sp->pvp.pvn.u.isname.name.n = idx;
			return 0;
		}
	}

	LM_ERR("tag <%.*s> not declared in modparam section!\n", in->len, in->s);

	return -1;
}


/*
 * getter function for $acc_extra
 */
int pv_get_acc_extra(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val)
{
	int tag_idx;

	acc_ctx_t* ctx=try_fetch_ctx();

	if (param == NULL || val == NULL) {
		LM_ERR("bad input params!\n");
		return -1;
	}

	if (ctx == NULL) {
		/* if we don't have a context then create it */
		if (init_acc_ctx(&ctx) < 0) {
			LM_ERR("failed to create accounting context!\n");
			return -1;
		}
	}

	tag_idx = param->pvn.u.isname.name.n;
	/* sanity checks for the tag; it should be valid since
	 * we found it in the parse name function */
	if (tag_idx < 0 || tag_idx >= extra_tgs_len) {
		LM_BUG("invalid tag value! probably a memory corruption issue!\n");
		return -1;
	}


	accX_lock(&ctx->lock);
	if (ctx->extra_values[tag_idx].value.s == NULL) {
		val->flags = PV_VAL_NULL;
	} else {
		val->rs = ctx->extra_values[tag_idx].value;
		val->flags = PV_VAL_STR;
	}
	accX_unlock(&ctx->lock);

	return 0;
}


/*
 * set pv_value_t in pkg to pv_value_t from extra in shm
 *
 * * if it's an integer then convert it to string and set the string value
 * to the shm pv_value_t
 * * if it's a string then try converting it to it
 */
int set_value_shm(pv_value_t* pvt, extra_value_t* extra)
{
	str s;

	if (pvt == NULL || pvt->flags&PV_VAL_NULL
	    || (pvt->flags & PV_VAL_STR && pvt->rs.len == 0)) {
		/* also treat empty strings as NULL */
		if (extra->value.s) {
			shm_free(extra->value.s);
		}
		extra->shm_buf_len = ACC_CTX_VAL_DELETED;
		extra->value.s = NULL;
		extra->value.len = 0;
	} else {
		if (pvt->flags&PV_VAL_STR) {
			s = pvt->rs;
		} else if (pvt->flags&PV_VAL_INT) {
			s.s = int2str( pvt->ri, &s.len);
		} else {
			LM_ERR("invalid pvt value!\n");
			return -1;
		}

		if (extra->value.s == 0) {
			extra->value.s = shm_malloc(s.len);
			extra->shm_buf_len = extra->value.len = s.len;
		} else if (extra->shm_buf_len < s.len) {
			extra->value.s = shm_realloc(extra->value.s, s.len);
			extra->shm_buf_len = extra->value.len = s.len;
		} else {
			extra->value.len = s.len;
		}

		if (extra->value.s == NULL) {
			extra->shm_buf_len = extra->value.len = 0;
			goto memerr;
		}

		memcpy(extra->value.s, s.s, s.len);
	}

	return 0;

memerr:
	LM_ERR("No more shm!\n");
	return -1;
}

/*
 * setter function for $acc_extra
 */
int pv_set_acc_extra(struct sip_msg *msg, pv_param_t *param, int op,
		pv_value_t *val)
{
	int tag_idx;

	acc_ctx_t* ctx=try_fetch_ctx();

	if (param == NULL) {
		LM_ERR("bad params!\n");
		return -1;
	}

	if (ctx == NULL) {
		/* if we don't have a context then create it */
		if (init_acc_ctx(&ctx) < 0) {
			LM_ERR("failed to create accounting context!\n");
			return -1;
		}
	}

	tag_idx = param->pvn.u.isname.name.n;
	/* sanity checks for the tag; it should be valid since
	 * we found it in the parse name function */
	if (tag_idx < 0 || tag_idx >= extra_tgs_len) {
		LM_BUG("invalid tag value! probably a memory corruption issue!\n");
		return -1;
	}


	/* go through all extras and fetch first value you find
	 * all the extras with the same tag will have the same
	 * value */
	accX_lock(&ctx->lock);
	if (set_value_shm(val, &ctx->extra_values[tag_idx]) < 0) {
		LM_ERR("failed to set extra <%.*s> value!\n",
				extra_tags[tag_idx].len, extra_tags[tag_idx].s);
		accX_unlock(&ctx->lock);
		return -1;
	}
	accX_unlock(&ctx->lock);

	return 0;
}


static inline void push_val_to_val( extra_value_t *src, extra_value_t *dst )
{
	pv_value_t val;

	if (src->value.s) {
		/* the extra has a value set */
		val.flags = PV_VAL_STR;
		val.rs = src->value;
		if (set_value_shm( &val, dst ) < 0)
			LM_ERR("failed to move extra acc value\n");
	} else if (src->shm_buf_len==ACC_CTX_VAL_DELETED) {
		/* the extra had the value deleted */
		val.flags = PV_VAL_NULL;
		val.rs.s = 0 ; val.rs.len = 0;
		if (set_value_shm( &val, dst ) < 0)
			LM_ERR("failed to move extra acc value\n");
	} /* this extra was not used.
	   * nothing to push */
}

void push_ctx_to_ctx(acc_ctx_t *src, acc_ctx_t *dst)
{
	int i,j;

	/* extra values */
	for( i=0 ; i<extra_tgs_len ; i++ )
		push_val_to_val( &src->extra_values[i], &dst->extra_values[i] );

	for( j=0 ; j<src->legs_no ; j++ )
		for( i=0 ; i<leg_tgs_len ; i++ )
			push_val_to_val( &src->leg_values[j][i], &dst->leg_values[j][i] );
}


/*
 * acc_current_leg
 * VARIABLE
 * ***********************/

int pv_get_acc_current_leg(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val)
{
	acc_ctx_t* ctx=try_fetch_ctx();

	if (ctx == NULL) {
		/* if we don't have a context then create it */
		if (init_acc_ctx(&ctx) < 0) {
			LM_ERR("failed to create accounting context!\n");
			return -1;
		}
	}

	if (ctx->leg_values == NULL) {
		LM_ERR("no legs defined!\n");
		return -1;
	}

	accX_lock(&ctx->lock);
	val->ri = ctx->legs_no - 1;
	val->rs.s = int2str(ctx->legs_no - 1, &val->rs.len);
	accX_unlock(&ctx->lock);

	val->flags = PV_VAL_INT | PV_VAL_STR | PV_TYPE_INT;

	return 0;
}

/*
 * acc_leg
 * VARIABLE
 * ***********************/

int pv_parse_acc_leg_index(pv_spec_p sp, str* in)
{
	int idx;
	pv_spec_p e;

	if (in == NULL || in->s == NULL || in->len == 0) {
		LM_ERR("bad index!\n");
		return -1;
	}

	if (sp == NULL) {
		LM_ERR("bad pv spec!\n");
		return -1;
	}

	str_trim_spaces_lr(*in);

	if (in->s[0] == PV_MARKER) {
		e=pkg_malloc(sizeof(pv_spec_t));
		if (e==NULL) {
			LM_ERR("no more pkg mem!\n");
			return -1;
		}
		memset(e, 0, sizeof(pv_spec_t));

		if (pv_parse_spec(in, e) == NULL) {
			LM_ERR("failed to parse index variable!\n");
			pv_spec_free(e);
			return -1;
		}

		sp->pvp.pvi.type = PV_IDX_PVAR;
		sp->pvp.pvi.u.dval = (void *)e;
	} else {
		if (str2sint(in, &idx) < 0) {
			LM_ERR("bad index! not a number! <%.*s>!\n", in->len, in->s);
			return -1;
		}

		sp->pvp.pvi.type = PV_IDX_INT;
		sp->pvp.pvi.u.ival = idx;
	}

	return 0;
}

/*
* parse $acc_leg variable name
*/
int pv_parse_acc_leg_name(pv_spec_p sp, str *in)
{
   int idx;

   if (sp == NULL || in == NULL || in->s == NULL || in->len == 0) {
	   LM_ERR("bad name!\n");
	   return -1;
   }

   str_trim_spaces_lr(*in);

   for (idx=0; idx<leg_tgs_len; idx++) {
		if (!str_strcmp(in, &leg_tags[idx])) {
		   sp->pvp.pvn.u.isname.name.n = idx;
		   return 0;
	   }
   }

   LM_ERR("tag <%.*s> not declared in modparam section!\n", in->len, in->s);

   return -1;
}


int pv_get_acc_leg(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val)
{
	int tag_idx, leg_idx;
	acc_ctx_t* ctx = try_fetch_ctx();

	pv_value_t idx_value;

	if (ctx == NULL) {
		/* if we don't have a context then create it */
		if (init_acc_ctx(&ctx) < 0) {
			LM_ERR("failed to create accounting context!\n");
			return -1;
		}
	}

	if (ctx->leg_values == NULL) {
		LM_ERR("no legs defined!\n");
		return -1;
	}

	tag_idx = param->pvn.u.isname.name.n;

	if (param->pvi.type == PV_IDX_PVAR) {
		if (pv_get_spec_value(msg, param->pvi.u.dval, &idx_value) < 0) {
			LM_ERR("failed to fetch index value!\n");
			return -1;
		}

		if (idx_value.flags&PV_VAL_INT) {
			leg_idx = idx_value.ri;
		} else if (idx_value.flags&PV_VAL_STR) {
			if (str2sint(&idx_value.rs, &leg_idx) < 0) {
				goto invalid_leg;
			}
		} else {
			goto invalid_leg;
		}

	} else if (param->pvi.type == PV_IDX_INT) {
		leg_idx = param->pvi.u.ival;
	} else {
		/* if not provided consider the value of the last leg */
		leg_idx = ctx->legs_no - 1;
	}

	if (leg_idx >= ctx->legs_no) {
		LM_ERR("bad $acc_leg index: %d\n", leg_idx);
		return -1;
	}

	if (leg_idx < 0) {
		if ((int)ctx->legs_no + leg_idx < 0) {
			LM_ERR("invalid leg index %d!\n", leg_idx);
			return -1;
		}

		/* -1 will be the last element and so on */
		leg_idx += ctx->legs_no;
	}

	val->flags = PV_VAL_STR;

	accX_lock(&ctx->lock);
	if (ctx->leg_values[leg_idx][tag_idx].value.s == NULL) {
		val->flags = PV_VAL_NULL;
	} else {
		val->rs = ctx->leg_values[leg_idx][tag_idx].value;
	}
	accX_unlock(&ctx->lock);

	return 0;

invalid_leg:
	LM_ERR("cannot fetch leg index value!\n");
	return -1;
}

/*
 *
 *
 */
int pv_set_acc_leg(struct sip_msg *msg, pv_param_t *param, int flag,
		pv_value_t *val)
{
	int tag_idx, leg_idx;
	acc_ctx_t* ctx = try_fetch_ctx();

	pv_value_t idx_value;

	if (ctx == NULL) {
		/* if we don't have a context then create it */
		if (init_acc_ctx(&ctx) < 0) {
			LM_ERR("failed to create accounting context!\n");
			return -1;
		}
	}

	if (ctx->leg_values == NULL) {
		LM_ERR("no legs defined!\n");
		return -1;
	}

	tag_idx = param->pvn.u.isname.name.n;

	if (param->pvi.type == PV_IDX_PVAR) {
		if (pv_get_spec_value(msg, param->pvi.u.dval, &idx_value) < 0) {
			LM_ERR("failed to fetch index value!\n");
			return -1;
		}

		if (idx_value.flags&PV_VAL_INT) {
			leg_idx = idx_value.ri;
		} else if (idx_value.flags&PV_VAL_STR) {
			if (str2sint(&idx_value.rs, &leg_idx) < 0) {
				goto invalid_leg;
			}
		} else {
			goto invalid_leg;
		}

	} else if(param->pvi.type == PV_IDX_INT) {
		leg_idx = param->pvi.u.ival;
	} else {
		/* if not provided consider the value of the last leg */
		leg_idx = ctx->legs_no - 1;
	}

	if (leg_idx >= (int)ctx->legs_no) {
		LM_ERR("there aren't that many legs!\n");
		return -1;
	}

	if (leg_idx < 0) {
		if ((int)ctx->legs_no + leg_idx < 0) {
			LM_ERR("invalid leg index %d!\n", leg_idx);
			return -1;
		}

		/* -1 will be the last element and so on */
		leg_idx += ctx->legs_no;
	}

	accX_lock(&ctx->lock);
	if (set_value_shm(val, &ctx->leg_values[leg_idx][tag_idx]) < 0) {
		LM_ERR("failed to set leg <%.*s> value for leg number %d!\n",
				extra_tags[tag_idx].len, leg_tags[tag_idx].s, leg_idx);
		accX_unlock(&ctx->lock);
		return -1;
	}
	accX_unlock(&ctx->lock);

	return 0;

invalid_leg:
	LM_ERR("cannot fetch leg index value!\n");
	return -1;
}



