/*
 * Usrloc domain structure
 *
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
/*
 * History:
 * --------
 *  2003-03-11  changed to new locking scheme: locking.h (andrei)
 */


/*! \file
 *  \brief USRLOC - Usrloc domain structure
 *  \ingroup usrloc
 */

#ifndef UDOMAIN_H
#define UDOMAIN_H


#include <stdio.h>
#include "../../statistics.h"
#include "../../locking.h"
#include "../../str.h"
#include "../../db/db.h"
#include "../../db/db_insertq.h"
#include "urecord.h"
#include "hslot.h"

struct hslot;   /*!< Hash table slot */
struct urecord; /*!< Usrloc record */
struct ucontact;


/*! \brief
 * The structure represents a usrloc domain
 */
typedef struct udomain {
	str* name;                 /*!< Domain name (NULL terminated) */
	query_list_t *ins_list;    /*!< insert buffering list for this domain */
	int size;                  /*!< Hash table size */
	struct hslot* table;       /*!< Hash table - array of collision slots */
	/* statistics */
	stat_var *users;           /*!< no of registered users */
	stat_var *contacts;        /*!< no of registered contacts */
	stat_var *expires;         /*!< no of expires */
} udomain_t;


/*! \brief
 * Create a new domain structure
 * _n is pointer to str representing
 * name of the domain, the string is
 * not copied, it should point to str
 * structure stored in domain list
 * _s is hash table size
 */
int new_udomain(str* _n, int _s, udomain_t** _d);


/*! \brief
 * Free all memory allocated for
 * the domain
 */
void free_udomain(udomain_t* _d);


/*! \brief
 * Load data from a database
 */
int preload_udomain(db_con_t* _c, udomain_t* _d);


/*! \brief
 * Check the DB validity of a domain
 */
int testdb_udomain(db_con_t* con, udomain_t* d);


/*! \brief
 * Timer handler for given domain (db_only)
 */
int db_timer_udomain(udomain_t* _d);


/*! \brief
 * Timer handler for given domain
 */
int mem_timer_udomain(udomain_t* _d);

/*! \brief
 * Insert record into domain
 */
int mem_insert_urecord(udomain_t* _d, str* _aor, struct urecord** _r);


/*! \brief
 * Delete a record
 */
void mem_delete_urecord(udomain_t* _d, struct urecord* _r);


/*! \brief
 * Locks the domain hash entrie corresponding to AOR
 */
void lock_udomain(udomain_t* _d, str *_aor);


/*! \brief
 *  Unlocks the domain hash entrie corresponding to AOR
 */
void unlock_udomain(udomain_t* _d, str *_aor);

struct ucontact* get_ucontact_from_id(udomain_t *d, uint64_t contact_id, struct urecord **_r);

/*! \brief
 * Locks the specific domain hash entrie
 */
void lock_ulslot(udomain_t* _d, int slot);


/*! \brief
 * Unlocks the specific domain hash entrie
 */
void unlock_ulslot(udomain_t* _d, int slot);
#define _unlock_ulslot(domain, contact_id) \
	do { \
		unsigned int _rlab; \
		unsigned short _aorh, _clab; \
		unpack_indexes(contact_id, &_aorh, &_rlab, &_clab); \
		unlock_ulslot(domain, _aorh & ((domain)->size - 1)); \
	} while (0)

/* ===== module interface ======= */


/*! \brief
 * Create and insert a new record
 */
int insert_urecord(udomain_t* _d, str* _aor, struct urecord** _r,
                   char skip_replication);

/*! \brief
 * Obtain a urecord pointer if the urecord exists in domain
 */
int get_urecord(udomain_t* _d, str* _aor, struct urecord** _r);

/*! \brief
 * Only relevant in a federation @cluster_mode.
 * Obtain urecord pointer if AoR exists in at least one location.
 */
int get_global_urecord(udomain_t* _d, str* _aor, struct urecord** _r);

int cdb_update_urecord_metadata(const str *_aor, int unpublish);


/*! \brief
 * Delete a urecord from domain
 */
int delete_urecord(udomain_t* _d, str* _aor, struct urecord* _r,
                   char skip_replication);

#endif /* UDOMAIN_H */
