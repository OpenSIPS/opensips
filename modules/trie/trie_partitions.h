 /*
￼ * Trie Module
￼ *
￼ * Copyright (C) 2024 OpenSIPS Project
￼ *
￼ * opensips is free software; you can redistribute it and/or modify
￼ * it under the terms of the GNU General Public License as published by
￼ * the Free Software Foundation; either version 2 of the License, or
￼ * (at your option) any later version.
￼ *
￼ * opensips is distributed in the hope that it will be useful,
￼ * but WITHOUT ANY WARRANTY; without even the implied warranty of
￼ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
￼ * GNU General Public License for more details.
￼ *
￼ * You should have received a copy of the GNU General Public License
￼ * along with this program; if not, write to the Free Software
￼ * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
￼ *
￼ * History:
￼ * --------
￼ * 2024-12-03 initial release (vlad)
￼ */

#ifndef TRIE_PARTITIONS_H
#define TRIE_PARTITIONS_H

#include "prefix_tree.h"
#include "../../db/db.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../rw_locking.h"
#include "../../action.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../mod_fix.h"
#include "../../md5global.h"
#include "../../md5.h"

extern int use_partitions;
extern rw_lock_t *reload_lock;

#define HASHLEN 16
typedef char HASH[HASHLEN];

#define HASHHEXLEN 32
typedef char HASHHEX[HASHHEXLEN+1];

struct head_db {
	str db_url;
	str partition;
	db_func_t db_funcs;
	db_con_t **db_con;
	str trie_table; /* trie_table name extracted from database */
	time_t time_last_update;
	trie_data_t *rdata;
	HASHHEX md5;
	rw_lock_t *ref_lock;
	int ongoing_reload;
	struct head_db *next;
	osips_malloc_f malloc;
	osips_free_f free;
};

struct head_db * get_partition(const str *);

#endif
