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

typedef struct usrloc_api {
	int           use_domain;
	int           db_mode;
	unsigned int  nat_flag;

	register_udomain_t     register_udomain;
	get_all_ucontacts_t    get_all_ucontacts;
	get_domain_ucontacts_t get_domain_ucontacts;

	insert_urecord_t          insert_urecord;
	delete_urecord_t          delete_urecord;
	get_urecord_t             get_urecord;
	lock_udomain_t            lock_udomain;
	unlock_udomain_t          unlock_udomain;

	release_urecord_t         release_urecord;
	insert_ucontact_t         insert_ucontact;
	delete_ucontact_t         delete_ucontact;
	delete_ucontact_from_id_t delete_ucontact_from_id;
	get_ucontact_t            get_ucontact;

	update_ucontact_t         update_ucontact;

	get_next_udomain_t        get_next_udomain;
	lock_ulslot_t             lock_ulslot;
	unlock_ulslot_t           unlock_ulslot;

	register_ulcb_t           register_ulcb;
} usrloc_api_t;


typedef int (*bind_usrloc_t)(usrloc_api_t* api);


#endif /* USRLOC_H */
