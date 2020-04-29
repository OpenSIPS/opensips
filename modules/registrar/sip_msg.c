/*
 * Module specific Contact header operations
 *
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

/*!
 * \file
 * \brief SIP registrar module - SIP message related functions
 * \ingroup registrar
 */



#include "../../parser/hf.h"
#include "../../dprint.h"
#include "../../parser/parse_expires.h"
#include "../../ut.h"
#include "../../qvalue.h"

#include "../../lib/reg/common.h"

#include "reg_mod.h"                     /* Module parameters */
#include "sip_msg.h"


/*! \brief
 * Return value of Expires header field
 * if the HF exists converted to absolute
 * time, if the HF doesn't exist, returns
 * default value;
 */
static inline int get_expires_hf(struct sip_msg* _m)
{
	exp_body_t* p;

	if (_m->expires) {
		p = (exp_body_t*)_m->expires->parsed;
		if (p->valid) {
			if (p->val != 0) {
				return p->val + get_act_time();
			} else return 0;
		} else return get_act_time() + default_expires;
	} else {
		return get_act_time() + default_expires;
	}
}

/*! \brief
 * Calculate absolute expires value per contact as follows:
 * 1) If the contact has expires value, use the value. If it
 *    is not zero, add actual time to it
 * 2) If the contact has no expires parameter, use expires
 *    header field in the same way
 * 3) If the message contained no expires header field, use
 *    the default value
 */
void calc_contact_expires(struct sip_msg* _m, param_t* _ep, int* _e, struct save_ctx *_sctx)
{
	int min_exp;
	int max_exp;

	/* global or local expire limits ? */
	if (_sctx) {
		min_exp = _sctx->min_expires;
		max_exp = _sctx->max_expires;
	} else {
		min_exp = min_expires;
		max_exp = max_expires;
	}

	if (!_ep || !_ep->body.len) {
		*_e = get_expires_hf(_m);
	} else {
		if (str2int(&_ep->body, (unsigned int*)_e) < 0) {
			*_e = default_expires;
		}
		/* Convert to absolute value */
		if (*_e != 0) *_e += get_act_time();
	}

	if ((*_e != 0) && ((*_e - get_act_time()) < min_exp)) {
		*_e = min_exp + get_act_time();
	}

	if ((*_e != 0) && max_exp && ((*_e - get_act_time()) > max_exp)) {
		*_e = max_exp + get_act_time();
	}
}

