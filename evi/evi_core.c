/*
 * Copyright (C) 2011 OpenSIPS Solutions
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2011-05-xx  created (razvancrainea)
 */

#include "evi_modules.h"
#include "evi_core.h"
#include "../ut.h"

/* static events exported by the core */
static str evi_core_table[] = {
	CORE_EVENT_STR(THRESHOLD)
};

int evi_register_core(void)
{
	int i, size = sizeof(evi_core_table) / sizeof(str);

	for (i = 0; i < size; i++) {
		if (EVI_ERROR == evi_publish_event(evi_core_table[i]))
			return -1;
	}
	return 0;
}


