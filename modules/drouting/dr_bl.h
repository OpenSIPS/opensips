/*
 * Copyright (C) 2009 Voice Sistem SRL
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


#ifndef _DR_DR_BL_H
#define _DR_DR_BL_H

#include "../../sr_module.h"
#include "../../blacklists.h"
#include "prefix_tree.h"
#include "dr_partitions.h"

#define MAX_TYPES_PER_BL 32

struct dr_bl {
	unsigned int no_types;
	unsigned int types[MAX_TYPES_PER_BL];
    struct head_db * part;
	struct bl_head *bl;
	struct dr_bl *next;
};

int set_dr_bl( modparam_t type, void* val);

int init_dr_bls( struct head_db *);

void destroy_dr_bls(void);

int populate_dr_bls(map_t pgw_tree);

#endif
