/*
 * contact param handling
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
 *  2016-10-23 initial version (liviu)
 */

#include "encode.h"

#include "../../ut.h"

int encrypt_str(str *in, str *out)
{
	if (in->len == 0 || !in->s) {
		out->len = 0;
		out->s = NULL;
		return 0;
	}

	out->len = calc_base64_encode_len(in->len);
	out->s = pkg_malloc(out->len);
	if (!out->s) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	memset(out->s, 0, out->len);

	base64encode((unsigned char *)out->s, (unsigned char *)in->s, in->len);
	return 0;
}

int decrypt_str(str *in, str *out)
{
	out->len = calc_max_base64_decode_len(in->len);
	out->s = pkg_malloc(out->len);
	if (!out->s) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	out->len = base64decode((unsigned char *)out->s,
	             (unsigned char *)in->s, in->len);
	return 0;
}

