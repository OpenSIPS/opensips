/*
 * User location callbacks
 *
 * This module is intended to be used as a middle layer SIP component in
 * environments where a large proportion of SIP UAs (e.g. mobile devices)
 * register at high enough frequencies that they actually degrade the
 * performance of their registrars.
 *
 * Copyright (C) 2016 OpenSIPS Solutions
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
 * --------
 *  2016-10-31 initial version (liviu)
 */

#include "../usrloc/ul_callback.h"

#include "mid_registrar.h"

void mid_reg_ct_event(void *binding, int type, void **data)
{
	ucontact_t *c = (ucontact_t *)binding;
	struct mid_reg_ct *mct;

	LM_DBG("insert contact callback: contact='%.*s' | "
	       "param=(%p -> %p) | data[idx]=(%p)\n", c->c.len, c->c.s, data,
	       data ? *data : NULL, c->attached_data[ucontact_data_idx]);

	if (type & UL_CONTACT_INSERT)
		*data = get_ct();

	if (type & UL_CONTACT_UPDATE) {
		mct = *(struct mid_reg_ct **)data;
		mct->expires_out = get_ct()->expires_out;
	}

	if (type & (UL_CONTACT_DELETE|UL_CONTACT_EXPIRE))
		shm_free(*data);
}
