/*
 * Copyright (C) 2013-2020 OpenSIPS Solutions
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
 *
 */

#ifndef _DR_DB_DEFS
#define _DR_DB_DEFS

#include "../../str.h"

/* DR group table related defs */
extern str drg_table;
extern str drg_user_col;
extern str drg_domain_col;
extern str drg_grpid_col;

/* DR gateway table related defs */
extern str drd_table;
extern str id_drd_col;
extern str gwid_drd_col;
extern str address_drd_col;
extern str strip_drd_col;
extern str prefix_drd_col;
extern str type_drd_col;
extern str attrs_drd_col;
extern str probe_drd_col;
extern str sock_drd_col;
extern str state_drd_col;

/* DR rule table related defs */
extern str drr_table;
extern str rule_id_drr_col;
extern str group_drr_col;
extern str prefix_drr_col;
extern str time_drr_col;
extern str priority_drr_col;
extern str routeid_drr_col;
extern str dstlist_drr_col;
extern str sort_alg_drr_col;
extern str sort_profile_drr_col;
extern str attrs_drr_col;

/* DR carrier table related defs */
extern str drc_table;
extern str id_drc_col;
extern str cid_drc_col;
extern str flags_drc_col;
extern str sort_alg_drc_col;
extern str gwlist_drc_col;
extern str attrs_drc_col;
extern str state_drc_col;

#endif

