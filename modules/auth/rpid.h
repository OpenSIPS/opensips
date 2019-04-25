/*
 * Remote-Party-ID related functions
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
 * --------
 * 2003-04-28 rpid contributed by Juha Heinanen added (janakj)
 * 2005-05-31 general avp specification added for rpid (bogdan)
 */

#ifndef RPID_H
#define RPID_H

#include "../../parser/msg_parser.h"
#include "../../str.h"
#include "../../usr_avp.h"


/*
 * Parse and init the rpid avp specification
 */
int init_rpid_avp(char *rpid_avp_param);


/*
 * Get the RPID avp specs
 */
void get_rpid_avp( int *rpid_avp_p, int *rpid_avp_type_p );


/*
 * Append RPID header field to the message with parameters
 */
int append_rpid_hf(struct sip_msg* _m, str* _prefix, str* _suffix);


/*
 * Check if SIP URI in rpid contains an e164 user part
 */
int is_rpid_user_e164(struct sip_msg* _m);


#endif /* RPID_H */
