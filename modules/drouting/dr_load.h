/*
 * Copyright (C) 2005-2008 Voice Sistem SRL
 * Copyright (C) 2020 OpenSIPS Solutions
 *
 * This file is part of Open SIP Server (OpenSIPS).
 *
 * DROUTING OpenSIPS-module is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * DROUTING OpenSIPS-module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */


#ifndef _DR_LOAD_
#define _DR_LOAD_

#include "../../str.h"
#include "../../db/db.h"
#include "dr_partitions.h"
#include "routing.h"

void dr_update_head_cache(struct head_db *head);
rt_data_t* dr_load_routing_info(struct head_db *current_partition,
                                int persistent_state);

#endif
