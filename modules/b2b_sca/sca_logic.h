/*
 * sca logic module
 *
 * Copyright (C) 2010 VoIP Embedded, Inc.
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
 *  2010-11-21  initial version (Ovidiu Sas)
 */

#ifndef B2B_SLA_LOGIC
#define B2B_SLA_LOGIC

#include <stdio.h>
#include <stdlib.h>

#include "../../str.h"


typedef struct b2bl_cb_ctx {
	unsigned int hash_index;
	str shared_line;
	unsigned int appearance;
} b2bl_cb_ctx_t;


void destroy_b2b_sca_handlers(void);

b2bl_cb_ctx_t* build_cb_params(unsigned int hash_index,
		str *shared_line, unsigned int appearance_index);

int sca_logic_notify(b2bl_cb_params_t *params, unsigned int b2b_event);

#endif
