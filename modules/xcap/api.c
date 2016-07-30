/*
 * xcap module - XCAP operations module
 *
 * Copyright (C) 2012 AG Projects
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
 */

#include "api.h"
#include "xcap_mod.h"


int bind_xcap(xcap_api_t* api)
{
	if (!api)
	{
		LM_ERR("Invalid parameter value\n");
		return -1;
	}
	api->integrated_server = integrated_xcap_server;
	api->db_url = xcap_db_url;
	api->xcap_table = xcap_table;
	api->normalize_sip_uri = normalize_sip_uri;
	api->parse_xcap_uri = parse_xcap_uri;
	api->get_xcap_doc = get_xcap_doc;
	return 0;
}

