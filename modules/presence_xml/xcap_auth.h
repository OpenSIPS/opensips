/*
 * presence_xml module -
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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
 *  2007-04-12  initial version (anca)
 */
#ifndef _AUTH_XML_H_
#define _AUTH_XML_H_

#include <libxml/parser.h>
#include "../../str.h"
#include "../presence/subscribe.h"

/* sub-handling priorities */
enum
{
    SH_ACTION_BLOCK = 0,
    SH_ACTION_CONFIRM = 10,
    SH_ACTION_POLITE_BLOCK = 20,
    SH_ACTION_ALLOW = 30
};

/* OMA rule types*/
enum {
    IDENTITY_RULE = 0,
    EXTERNAL_LIST_RULE,
    ANONYMOUS_REQUEST_RULE,
    OTHER_IDENTITY_RULE,
};

typedef struct xcap_rule_s
{
        xmlNodePtr node;
        struct xcap_rule_s *next;

} xcap_rule_t;


int pres_watcher_allowed(subs_t* subs);
xmlNodePtr get_rule_node(subs_t* subs, xmlDocPtr xcap_tree );
int pres_get_rules_doc(str* user, str* domain, str** rules_doc);
int p_get_xcap_doc(str* user, str* domain, int type, str** doc);

#endif
