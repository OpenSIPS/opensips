/*
 * Copyright (C) 2017 OpenSIPS Project
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * History:
 * ---------
 *  2017-06-20  created (razvanc)
 */

#ifndef _SIPREC_UUID_H_
#define _SIPREC_UUID_H_

#include <uuid/uuid.h>

#define SIPREC_UUID_LEN calc_base64_encode_len(sizeof(uuid_t))
typedef unsigned char siprec_uuid[SIPREC_UUID_LEN];

static inline void siprec_build_uuid(siprec_uuid uuid)
{
	uuid_t tmp_uuid;
	uuid_generate(tmp_uuid);
	base64encode(uuid, tmp_uuid, sizeof(tmp_uuid));
}


#endif /* _SIPREC_UUID_H_ */
