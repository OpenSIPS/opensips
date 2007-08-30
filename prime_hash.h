/*
 * $Id$
 *
 * Copyright (C) 2007 1&1 Internet AG
 *
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * Functions for determinung a pseudo random number over a message's
 * header field, based on a prime number algorithm.
 */
#ifndef PRIME_HASH_H
#define PRIME_HASH_H 1

#include "parser/msg_parser.h"


/* 
Determines from which part of a message the hash shall be calculated.
Possible values are:

shs_call_id     the content of the Call-ID header field
shs_from_uri    the entire URI in the From header field
shs_from_user   the username part of the URI in the From header field
shs_to_uri      the entire URI in the To header field
shs_to_user     the username part of the URI in the To header field
*/
enum hash_source {
	shs_call_id = 1,
	shs_from_uri,
	shs_from_user,
	shs_to_uri,
	shs_to_user,
	shs_error
};

typedef int (*hash_func_t)(struct sip_msg * msg,
	enum hash_source source, int denominator);


/****************** Declaration of extern interface functions **************/

/*
static int real_hash_func (struct sip_msg*, int);
static int calculate_hash (struct sip_msg*, char*, char*);
*/

/* 
 * Returns an integer number between 0 and denominator - 1 based on
 * the hash source from the msg. The hash algorith is CRC32.
*/
int hash_func (struct sip_msg * msg,
                         enum hash_source source, int denominator);

/* 
 * Returns an integer number between 0 and denominator - 1 based on
 * the hash source from the msg. Use the prime number algorithm.
*/
int prime_hash_func (struct sip_msg * msg,
                               enum hash_source source, int denominator);

#endif
