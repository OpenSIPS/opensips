/*
 * List of registered domains
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
 *
 * History:
 * ========
 * 2006-11-28 Added get_number_of_users() (Jeffrey Magder - SOMA Networks)
 * 2007-09-12 added partitioning support for fetching all ul contacts
 *            (bogdan)
 */

/*! \file
 *  \brief USRLOC - List of registered domains
 *  \ingroup usrloc
 */



#ifndef DLIST_H
#define DLIST_H

#include <stdio.h>
#include "udomain.h"
#include "../../str.h"


/*
 * List of all domains registered with usrloc
 */
typedef struct dlist {
	str name;            /* Name of the domain (null terminated) */
	udomain_t* d;        /* Payload */
	struct dlist* next;  /* Next element in the list */
} dlist_t;


extern dlist_t* root;

/*
 * Function registers a new domain with usrloc
 * if the domain exists, pointer to existing structure
 * will be returned, otherwise a new domain will be
 * created
 */
typedef int (*register_udomain_t)(const char* _n, udomain_t** _d);
int register_udomain(const char* _n, udomain_t** _d);


/*
 * Free all registered domains
 */
void free_all_udomains(void);


/*
 * Just for debugging
 */
void print_all_udomains(FILE* _f);


/*! \brief
 * Called from timer
 */
int synchronize_all_udomains(void);


/*! \brief
 * Get contacts to all registered users
 */
typedef int  (*get_all_ucontacts_t) (void* buf, int len, unsigned int flags,
		unsigned int part_idx, unsigned int part_max, int pack_cid);
int get_all_ucontacts(void *, int, unsigned int,
		unsigned int part_idx, unsigned int part_max, int pack_cid);

/*! \brief
 * Get contacts structures to all registered users
 */
typedef int  (*get_domain_ucontacts_t) (udomain_t *d, void* buf, int len,
		unsigned int flags, unsigned int part_idx, unsigned int part_max,
		int pack_cid);
int get_domain_ucontacts(udomain_t *d,void *buf, int len, unsigned int flags,
					unsigned int part_idx, unsigned int part_max, int pack_cid);



/* Sums up the total number of users in memory, over all domains. */
unsigned long get_number_of_users(void *);


/*! \brief
 * Find a particular domain
 */
int find_domain(str* _d, udomain_t** _p);


/*! \brief
 * Returnes the next udomain, following the given one (as param)
 */
typedef udomain_t* (*get_next_udomain_t) (udomain_t* _d);
udomain_t* get_next_udomain(udomain_t *_d);

/*contact label may not be higher than 14 bits*/
#define CLABEL_MASK ((1<<14)-1)
#define CLABEL_INC_AND_TEST(_clabel_) ((_clabel_+1)&CLABEL_MASK)
#define CID_GET_CLABEL(_cid) (_cid&CLABEL_MASK)
#define CID_NEXT_RLABEL(_dom, _sl) (_dom->table[_sl].next_label++)

static inline uint64_t
pack_indexes(unsigned short aorhash, unsigned int rlabel, unsigned short clabel)
{
	return clabel + ((uint64_t)rlabel << 14) + ((uint64_t)aorhash << 46);
}


static inline int
unpack_indexes(uint64_t v,
		unsigned short *aorhash, unsigned int *rlabel, unsigned short *clabel)
{
	if (aorhash == NULL || rlabel == NULL || clabel == NULL) {
		LM_ERR("invalid arguments\n");
		return -1;
	}

	/* first 14 bits 0-13 */
	*clabel  = v & CLABEL_MASK;
	/* middle 32 bits 14-45 */
	*rlabel  = (v >> 14) & 0xFFFFFFFF;
	/* last 16 bits 46-61 */
	*aorhash = (v >> 46);

	return 0;
}

typedef int (*delete_ucontact_from_id_t)(udomain_t *d,
					uint64_t contact_id, char is_replicated);
int delete_ucontact_from_id(udomain_t *d,
		uint64_t contact_id, char is_replicated);

#endif /* UDLIST_H */
