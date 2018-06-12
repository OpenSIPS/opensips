/*
 * $Id$
 *
 * Remote-Party-ID related functions
 *
 * Copyright (C) 2001-2003 Fhg Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 * 2003-04-28 rpid contributed by Juha Heinanen added (janakj)
 */

#ifndef RPID_H
#define RPID_H

#include "../../parser/msg_parser.h"
#include "../../str.h"


/*
 * Append RPID header field to the message
 */
int append_rpid_hf(struct sip_msg* _m, char* _s1, char* _s2);


/*
 * Append RPID header field to the message with parameters
 */
int append_rpid_hf_p(struct sip_msg* _m, char* _prefix, char* _suffix);


/*
 * Check if SIP URI in rpid contains an e164 user part
 */
int is_rpid_user_e164(struct sip_msg* _m, char* _s1, char* _s2);


/*
 * Store rpid
 */
void save_rpid(str* _rpid);


#endif /* RPID_H */
