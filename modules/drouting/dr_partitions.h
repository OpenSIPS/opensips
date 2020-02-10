/**
 * dispatcher module fixup functions
 *
 * Copyright (C) 2004-2005 FhG Fokus
 * Copyright (C) 2006-2010 Voice Sistem SRL
 * Copyright (C) 2014 OpenSIPS Foundation
 * Copyright (C) 2015-2020 OpenSIPS Solutions
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

#ifndef DR_DR_PARTITIONS_H
#define DR_DR_PARTITIONS_H

#include "routing.h"
#include "../../db/db.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../rw_locking.h"
#include "../../action.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../resolve.h"
#include "../../mod_fix.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_uri.h"
#include "../../mi/mi.h"
#include "../tm/tm_load.h"

extern int use_partitions;
extern rw_lock_t *reload_lock;

struct head_db {
	str db_url;
	str partition;
	db_func_t db_funcs;
	db_con_t **db_con;
	str drd_table; /* drd_table name extracted from database */
	str drr_table; /* drr_table name extracted from database */
	str drc_table; /* drc_table name extracted from database */
	str drg_table; /* drg_table name extracted from database */
	time_t time_last_update;
	int acc_call_params_avp;
	int avpID_store_ruri;       /* from parse_avp_spec */
	int avpID_store_prefix;    /* from parse_avp_spec */
	int avpID_store_index;     /* from parse_avp_spec */
	int avpID_store_whitelist; /* from parse_avp_spec */
	int avpID_store_group;     /* from parse_avp_spec */
	int avpID_store_flags;      /* from parse_avp_spec */
	int gw_priprefix_avp;      /* from parse_avp_spec */
	int rule_id_avp;           /* from parse_avp_spec */
	int rule_prefix_avp;       /* from parse_avp_spec */
	int carrier_id_avp;        /* from parse_avp_spec */
	int ruri_avp;
	int gw_id_avp;
	int gw_sock_avp;
	int gw_attrs_avp;
	int rule_attrs_avp;
	int carrier_attrs_avp;
	int restart_persistent;
	rt_data_t *rdata;
	rw_lock_t *ref_lock;
	int ongoing_reload;
	struct head_db *next;
	osips_malloc_f malloc;
	osips_free_f free;
	struct head_cache *cache;
};

struct head_db * get_partition(const str *);



#endif
