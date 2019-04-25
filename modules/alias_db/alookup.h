/*
 * ALIAS_DB Module
 *
 * Copyright (C) 2004 Voice Sistem SRL
 *
 * This file is part of a module for opensips, a free SIP server.
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
 * 2004-09-01: first version (ramona)
 * 2009-04-30: alias_db_find() added; NO_DOMAIN and REVERT flags added;
 *             use_domain param removed (bogdan)
 */


#ifndef _ALOOKUP_H_
#define _ALOOKUP_H_

#include "../../parser/msg_parser.h"

#define ALIAS_REVERT_FLAG      (1<<0)
#define ALIAS_NO_DOMAIN_FLAG   (1<<1)

int alias_db_lookup(struct sip_msg* _msg, str* _table, void *flags);

int alias_db_find(struct sip_msg* _msg, str* _table, str* _in_s, pv_spec_t* _out,
															void* flags);

#endif /* _ALOOKUP_H_ */
