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
 */


#include "../../ut.h"
#include "dr_db_def.h"

/* DR group table related defs */
str drg_table = str_init("dr_groups");
str drg_user_col = str_init("username");
str drg_domain_col = str_init("domain");
str drg_grpid_col = str_init("groupid");

/* DR gateway table related defs */
#define ID_DRD_COL       "id"
#define GWID_DRD_COL     "gwid"
#define ADDRESS_DRD_COL  "address"
#define STRIP_DRD_COL    "strip"
#define PREFIX_DRD_COL   "pri_prefix"
#define TYPE_DRD_COL     "type"
#define ATTRS_DRD_COL    "attrs"
#define PROBE_DRD_COL    "probe_mode"
#define SOCKET_DRD_COL   "socket"
#define STATE_DRD_COL    "state"
str drd_table = str_init("dr_gateways");
str id_drd_col = str_init(ID_DRD_COL);
str gwid_drd_col = str_init(GWID_DRD_COL);
str address_drd_col = str_init(ADDRESS_DRD_COL);
str strip_drd_col = str_init(STRIP_DRD_COL);
str prefix_drd_col = str_init(PREFIX_DRD_COL);
str type_drd_col = str_init(TYPE_DRD_COL);
str attrs_drd_col = str_init(ATTRS_DRD_COL);
str probe_drd_col = str_init(PROBE_DRD_COL);
str sock_drd_col = str_init(SOCKET_DRD_COL);
str state_drd_col = str_init(STATE_DRD_COL);

/* DR rule table related defs */
#define RULE_ID_DRR_COL   "ruleid"
#define GROUP_DRR_COL     "groupid"
#define PREFIX_DRR_COL    "prefix"
#define TIME_DRR_COL      "timerec"
#define PRIORITY_DRR_COL  "priority"
#define ROUTEID_DRR_COL   "routeid"
#define DSTLIST_DRR_COL   "gwlist"
#define SORT_ALG_DRR_COL "sort_alg"
#define SORT_PROFILE_DRR_COL "sort_profile"
#define ATTRS_DRR_COL     "attrs"

str drr_table = str_init("dr_rules");
str rule_id_drr_col = str_init(RULE_ID_DRR_COL);
str group_drr_col = str_init(GROUP_DRR_COL);
str prefix_drr_col = str_init(PREFIX_DRR_COL);
str time_drr_col = str_init(TIME_DRR_COL);
str priority_drr_col = str_init(PRIORITY_DRR_COL);
str routeid_drr_col = str_init(ROUTEID_DRR_COL);
str dstlist_drr_col = str_init(DSTLIST_DRR_COL);
str sort_alg_drr_col = str_init(SORT_ALG_DRR_COL);
str sort_profile_drr_col = str_init(SORT_PROFILE_DRR_COL);
str attrs_drr_col = str_init(ATTRS_DRR_COL);

/* DR carrier table related defs */
#define ID_DRC_COL     "id"
#define CID_DRC_COL    "carrierid"
#define FLAGS_DRC_COL  "flags"
#define SORT_ALG_DRC_COL "sort_alg"
#define GWLIST_DRC_COL "gwlist"
#define ATTRS_DRC_COL  "attrs"
#define STATE_DRC_COL  "state"
str drc_table = str_init("dr_carriers");
str id_drc_col = str_init(ID_DRC_COL);
str cid_drc_col = str_init(CID_DRC_COL);
str flags_drc_col = str_init(FLAGS_DRC_COL);
str sort_alg_drc_col = str_init(SORT_ALG_DRC_COL);
str gwlist_drc_col = str_init(GWLIST_DRC_COL);
str attrs_drc_col = str_init(ATTRS_DRC_COL);
str state_drc_col = str_init(STATE_DRC_COL);


