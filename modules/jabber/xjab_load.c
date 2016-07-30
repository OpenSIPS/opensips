/*
 * Copyright (C) 2001-2003 FhG Fokus
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
 */


#include "xjab_load.h"

int load_xjab(struct xjab_binds *xjb)
{
	if(!( xjb->register_watcher=(pa_register_watcher_f)
			find_export("jab_register_watcher", XJ_NO_SCRIPT_F, 0)) )
	{
		LM_ERR("'jab_register_watcher' not found!\n");
		return -1;
	}
	if(!( xjb->unregister_watcher=(pa_unregister_watcher_f)
			find_export("jab_unregister_watcher", XJ_NO_SCRIPT_F, 0)) )
	{
		LM_ERR("'jab_unregister_watcher' not found!\n");
		return -1;
	}
	return 1;
}
