/*
 * $Id$ 
 * Digest Authentication - Diameter support
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
 * -------
 *  
 *  
 */

#ifndef AUTHDIAM_MOD_H
#define AUTHDIAM_MOD_H

#include "../../parser/msg_parser.h"
#include "defs.h"
#define M_NAME "auth_diameter"

extern char *diameter_client_host;
extern char* diameter_client_port;

/* Stateless reply function pointer */
extern int (*sl_reply)(struct sip_msg* _m, char* _str1, char* _str2);

int sockfd;
int use_domain;
extern rd_buf_t *rb;


#endif /* AUTHDIAM_MOD_H */
 
