/*
 * Convenience usrloc header file
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

/*! \file
 *  \brief USRLOC - Convenience usrloc header file
 *  \ingroup usrloc
 */

#ifndef USRLOC_H
#define USRLOC_H


#include "dlist.h"
#include "udomain.h"
#include "urecord.h"
#include "ucontact.h"
#include "ul_callback.h"
#include "ul_dbg.h"

enum ul_cluster_mode {
	CM_NONE,
	CM_FEDERATION,
	CM_FEDERATION_CACHEDB,
	CM_FULL_SHARING,
	CM_FULL_SHARING_CACHEDB,
	CM_SQL_ONLY,
} ul_cluster_mode_t;

/* XXX: deprecated! */
enum usrloc_modes {
	NOT_SET       = -1,

	NO_DB         = 0,
	WRITE_THROUGH = 1,
	WRITE_BACK    = 2,
	DB_ONLY       = 3,
};

typedef struct usrloc_api {
	int use_domain;
	enum ul_cluster_mode cluster_mode;
	/* whether the user location caches contacts in memory */
	int (*have_mem_storage) (void);
	/* whether the user location makes use of contact ownership tags */
	int (*tags_in_use) (void);
	unsigned int nat_flag;

	register_udomain_t     register_udomain;
	get_all_ucontacts_t    get_all_ucontacts;
	get_domain_ucontacts_t get_domain_ucontacts;

	insert_urecord_t          insert_urecord;
	delete_urecord_t          delete_urecord;
	get_urecord_t             get_urecord;
	get_global_urecord_t      get_global_urecord;
	release_urecord_t         release_urecord;
	lock_udomain_t            lock_udomain;
	unlock_udomain_t          unlock_udomain;

	insert_ucontact_t         insert_ucontact;
	delete_ucontact_t         delete_ucontact;
	delete_ucontact_from_coords_t delete_ucontact_from_coords;
	/* Return: 0 if equal, -1 otherwise */
	int (*ucontact_coords_cmp) (ucontact_coords a, ucontact_coords b);
	void (*free_ucontact_coords) (ucontact_coords coords);
	get_ucontact_from_id_t    get_ucontact_from_id;
	get_ucontact_t            get_ucontact;
	update_ucontact_t         update_ucontact;

	get_next_udomain_t        get_next_udomain;
	next_contact_id_t         next_contact_id;
	lock_ulslot_t             lock_ulslot;
	unlock_ulslot_t           unlock_ulslot;

	get_urecord_key_t         get_urecord_key;
	put_urecord_key_t         put_urecord_key;
	get_ucontact_key_t        get_ucontact_key;
	put_ucontact_key_t        put_ucontact_key;

	register_ulcb_t           register_ulcb;
	update_sipping_latency_t  update_sipping_latency;
} usrloc_api_t;


typedef int (*bind_usrloc_t)(usrloc_api_t* api);

static inline int load_ul_api(usrloc_api_t *ul)
{
	bind_usrloc_t bind_usrloc;

	bind_usrloc = (bind_usrloc_t)find_export("ul_bind_usrloc", 0);
	if (!bind_usrloc) {
		LM_ERR("can't bind usrloc\n");
		return -1;
	}

	if (bind_usrloc(ul) < 0)
		return -1;

	return 0;
}

#endif /* USRLOC_H */
