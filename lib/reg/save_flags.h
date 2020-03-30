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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __LIB_REG_SAVE_FLAGS__
#define __LIB_REG_SAVE_FLAGS__

#include "../../str.h"
#include "../../modules/usrloc/urecord.h"

struct save_ctx {
	unsigned int flags;
	str aor;
	str ownership_tag;

	unsigned int max_contacts;

	unsigned int min_expires;
	unsigned int max_expires;

	/* info on how the contact matching should be performed.
	 * Note that the "param" (if used) is just a reference, the
	 * string itself is not part of the structure (points into
	 * the input save flags) */
	struct ct_match cmatch;

	/* fields specific to mid-registrar */
	unsigned int expires;
	int expires_out;
	int star;
};


void reg_parse_save_flags(str *flags_s, struct save_ctx *sctx);

#endif
