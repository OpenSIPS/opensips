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


#ifndef _MC_API_H
#define _MC_API_H

#include "../../sr_module.h"


typedef int (*compress_t)(unsigned char* in, unsigned long ilen, str* out,
		unsigned long* olen, int level);
typedef int (*decompress_t)(unsigned char* in, unsigned long ilen, str* out,
		unsigned long* olen);
typedef int (*check_rc_t)(int rc);

typedef struct compression_api {
	int level;

	check_rc_t	 check_rc;
	compress_t   compress;
	decompress_t decompress;
} compression_api_t;

typedef int (*bind_compression_t)(compression_api_t* api);
int bind_compression(compression_api_t *api);
typedef int (*load_compression_f)(compression_api_t *api);


static inline int load_compression_api(compression_api_t* api )
{
	load_compression_f load_compression;

	/* import the TM auto-loading function */
	if ( !(load_compression=(load_compression_f)find_export("load_compression", 0))) {
		LM_ERR("failed to import load_compression\n");
		return -1;
	}
	/* let the auto-loading function load all TM stuff */
	if (load_compression( api )==-1)
		return -1;

	return 0;
}

#endif







