/*
 * Usrloc interface
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
 *
 * 2006-11-28 Added a new function to the usrloc_api, to retrieve the number
 *            of registered users.  (Jeffrey Magder - SOMA Networks)
 */

/*! \file
 *  \brief USRLOC - Usrloc interface
 *  \ingroup usrloc
 */

#include "usrloc.h"
#include "../../sr_module.h"
#include "ul_mod.h"

extern unsigned int nat_bflag;
extern unsigned int init_flag;


int bind_usrloc(usrloc_api_t* api)
{
	if (!api) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}
	if (init_flag==0) {
		LM_ERR("configuration error - trying to bind to usrloc module"
				" before being initialized\n");
		return -1;
	}

	api->register_udomain        = register_udomain;
	api->get_next_udomain        = get_next_udomain;
	api->next_contact_id         = next_contact_id;
	api->get_all_ucontacts       = get_all_ucontacts;
	api->get_domain_ucontacts    = get_domain_ucontacts;
	api->insert_urecord          = insert_urecord;
	api->delete_urecord          = delete_urecord;
	api->get_urecord             = get_urecord;
	api->lock_udomain            = lock_udomain;
	api->unlock_udomain          = unlock_udomain;
	api->lock_ulslot             = lock_ulslot;
	api->unlock_ulslot           = unlock_ulslot;
	api->release_urecord         = release_urecord;
	api->insert_ucontact         = insert_ucontact;
	api->delete_ucontact         = delete_ucontact;
	api->delete_ucontact_from_id = delete_ucontact_from_id;
	api->get_ucontact            = get_ucontact;
	api->get_ucontact_from_id    = get_ucontact_from_id;
	api->update_ucontact         = update_ucontact;
	api->get_ucontact_key        = get_ucontact_key;
	api->put_ucontact_key        = put_ucontact_key;
	api->register_ulcb           = register_ulcb;

	api->use_domain = use_domain;
	api->db_mode    = db_mode;
	api->nat_flag   = nat_bflag;

	return 0;
}
