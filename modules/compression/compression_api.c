/*
 * Copyright (C) 2015 OpenSIPS Solutions
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
 */
#include "compression_api.h"
#include "gz_helpers.h"
#include "compression_helpers.h"

extern int mc_level;

int bind_compression(compression_api_t *api)
{
	if (!api) {
		LM_ERR("invalid parameter value!\n");
		return -1;
	}

	api->level = mc_level;

	api->compress   = gzip_compress;
	api->decompress = gzip_uncompress;
	api->check_rc   = check_zlib_rc;

	return 0;
}



