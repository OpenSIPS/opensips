/* 
 * $Id$ 
 *
 * Usrloc domain structure
 *
 * Copyright (C) 2001-2003 Fhg Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
 * History:
 * --------
 *  2003-03-11  changed to new locking scheme: locking.h (andrei)
 */


#ifndef UDOMAIN_H
#define UDOMAIN_H


#include <stdio.h>
#include "../../locking.h"
#include "../../str.h"
#include "urecord.h"
#include "hslot.h"


struct hslot;   /* Hash table slot */
struct urecord; /* Usrloc record */


/*
 * The structure represents a usrloc domain
 */
typedef struct udomain {
	str* name;                     /* Domain name */
	int size;                      /* Hash table size */
	int users;                     /* Number of registered users */
	int expired;                   /* Number of expired contacts */
	struct hslot* table;           /* Hash table - array of collision slots */
	struct {                       /* Linked list of all elements in the domain */
		int n;                 /* Number of element in the linked list */
		struct urecord* first; /* First element in the list */
		struct urecord* last;  /* Last element in the list */
	} d_ll;
	gen_lock_t lock;                /* lock variable */
} udomain_t;


/*
 * Create a new domain structure
 * _n is pointer to str representing
 * name of the domain, the string is
 * not copied, it should point to str
 * structure stored in domain list
 * _s is hash table size
 */
int new_udomain(str* _n, int _s, udomain_t** _d);


/*
 * Free all memory allocated for
 * the domain
 */
void free_udomain(udomain_t* _d);


/*
 * Just for debugging
 */
void print_udomain(FILE* _f, udomain_t* _d);


/*
 * Load data from a database
 */
int preload_udomain(udomain_t* _d);


/*
 * Timer handler for given domain
 */
int timer_udomain(udomain_t* _d);


/*
 * Insert record into domain
 */
int mem_insert_urecord(udomain_t* _d, str* _aor, struct urecord** _r);


/*
 * Delete a record
 */
void mem_delete_urecord(udomain_t* _d, struct urecord* _r);


/*
 * Get lock
 */
typedef void (*lock_udomain_t)(udomain_t* _d);
void lock_udomain(udomain_t* _d);


/*
 * Release lock
 */
typedef void (*unlock_udomain_t)(udomain_t* _d);
void unlock_udomain(udomain_t* _d);


/* ===== module interface ======= */


/*
 * Create and insert a new record
 */
typedef int (*insert_urecord_t)(udomain_t* _d, str* _aor, struct urecord** _r);
int insert_urecord(udomain_t* _d, str* _aor, struct urecord** _r);


/*
 * Obtain a urecord pointer if the urecord exists in domain
 */
typedef int  (*get_urecord_t)(udomain_t* _d, str* _a, struct urecord** _r);
int get_urecord(udomain_t* _d, str* _aor, struct urecord** _r);


/*
 * Delete a urecord from domain
 */
typedef int  (*delete_urecord_t)(udomain_t* _d, str* _a);
int delete_urecord(udomain_t* _d, str* _aor);


#endif /* UDOMAIN_H */
