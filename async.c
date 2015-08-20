/*
 * Copyright (C) 2014 OpenSIPS Solutions
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
 * history:
 * ---------
 *  2014-10-15  created (bogdan)
 */

#include "dprint.h"
#include "async.h"

int async_status = ASYNC_NO_IO;

async_start_function  *async_start_f  = NULL;
async_resume_function *async_resume_f = NULL;


int register_async_handlers(async_start_function *f1, async_resume_function *f2)
{
	if (async_start_f) {
		LM_ERR("aync handler already registered, it cannot be override\n");
		return -1;
	}

	async_start_f = f1;
	async_resume_f = f2;

	return 0;
}
