/*
 * rls module - resource list server
 *
 * Copyright (C) 2007 Voice Sistem S.R.L.
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
 * --------
 *  2007-09-11  initial version (Anca Vamanu)
 */

#ifndef RLS_SUBSCRIBE_H
#define RLS_SUBSCRIBE_H

#include <libxml/parser.h>
#include "../../parser/msg_parser.h"
#include "../pua/uri_list.h"

int rls_handle_subscribe(struct sip_msg* msg, char* s1, char* s2);
int get_resource_list(str* service_uri, str owner_user, str owner_domain,
		      xmlNodePtr* service_node, xmlDocPtr* rl_doc);
int resource_subscriptions(subs_t* subs, xmlNodePtr rl_node);

#endif
