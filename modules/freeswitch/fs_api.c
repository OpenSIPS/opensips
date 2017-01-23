/*
 * FreeSWITCH API
 *
 * Copyright (C) 2017 OpenSIPS Solutions
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
 *  2017-01-23 initial version (liviu)
 */

#include "../../parser/parse_uri.h"
#include "../../proxy.h"

#include "fs_api.h"

add_fs_evs_f add_fs_event_sock(str *evs_str, char *tag, enum fs_evs_types typ,
                               ev_hrbeat_cb_f scb, void *info)
{
	return NULL;
}

del_fs_evs_f del_fs_event_sock(fs_evs *evs, char *tag)
{
	return 0;
}
