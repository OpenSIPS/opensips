/*
 * Copyright (C) 2006 Voice Sistem SRL
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
 *  2006-09-08  first version (bogdan)
 */

/*!
 * \file
 * \brief MI :: Format handling
 * \ingroup mi
 */


#include <string.h>
#include "../dprint.h"
#include "../mem/mem.h"

char *mi_fmt_buf = 0;
int  mi_fmt_buf_len = 0;


int mi_fmt_init( unsigned int size )
{
	mi_fmt_buf = (char*)pkg_malloc(size);
	if (mi_fmt_buf==NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	mi_fmt_buf_len = size;
	return 0;
}


