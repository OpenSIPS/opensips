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
#include "ul_evi.h"

extern unsigned int nat_bflag;


int bind_usrloc(usrloc_api_t* api)
{
	if (!api) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	/* runtime configuration */
	api->use_domain       = use_domain;
	api->cluster_mode     = cluster_mode;
	api->have_mem_storage = have_mem_storage;
	api->tags_in_use      = tags_in_use;
	api->nat_flag         = nat_bflag;

	/* domain manipulation */
	api->register_udomain = register_udomain;
	api->lock_udomain     = lock_udomain;
	api->unlock_udomain   = unlock_udomain;

	/* record manipulation */
	api->get_urecord         = get_urecord;
	api->get_global_urecord  = get_global_urecord;
	api->release_urecord     = release_urecord;
	api->insert_urecord      = insert_urecord;
	api->get_urecord_key     = get_urecord_key;
	api->put_urecord_key     = put_urecord_key;
	api->delete_urecord      = delete_urecord;

	/* contact manipulation */
	api->get_ucontact                = get_ucontact;
	api->get_ucontact_from_id        = get_ucontact_from_id;
	api->insert_ucontact             = insert_ucontact;
	api->update_ucontact             = update_ucontact;
	api->get_ucontact_key            = get_ucontact_key;
	api->put_ucontact_key            = put_ucontact_key;
	api->delete_ucontact             = delete_ucontact;
	api->delete_ucontact_from_coords = delete_ucontact_from_coords;
	api->ucontact_coords_cmp         = ucontact_coords_cmp;
	api->free_ucontact_coords        = free_ucontact_coords;
	api->is_my_ucontact              = is_my_ucontact;
	api->next_contact_id             = next_contact_id;
	api->update_sipping_latency      = update_sipping_latency;
	api->raise_ev_ct_refresh         = ul_raise_ct_refresh_event;

	/* domain iteration and retrieval */
	api->get_next_udomain      = get_next_udomain;
	api->lock_ulslot           = lock_ulslot;
	api->unlock_ulslot         = unlock_ulslot;
	api->get_domain_ucontacts  = get_domain_ucontacts;
	api->get_all_ucontacts     = get_all_ucontacts;

	/* usrloc callbacks */
	api->register_ulcb  = register_ulcb;

	return 0;
}
