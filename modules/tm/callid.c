/*
 * Fast Call-ID Generator
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
 * ----------
 *  2003-04-09  Created by janakj
 *  2003-10-24  updated to the new socket_info lists (andrei)
 */

#include <stdio.h>
#include <stdlib.h>
#include "../../dprint.h"
#include "../../pt.h"
#include "../../socket_info.h"
#include "callid.h"

#define CALLID_NR_LEN 20

/* Call-ID has the following form: <callid_nr>-<pid>@<ip>
 * callid_nr is initialized as a random number and continually
 * increases; -<pid>@<ip> is kept in callid_suffix
 */
#define CALLID_SUFFIX_LEN ( 1 /* - */                                            + \
			    5 /* pid */                                          + \
                           42 /* embedded v4inv6 address can be looong '128.' */ + \
	                    2 /* parenthesis [] */                              + \
                            1 /* ZT 0 */                                         + \
	                   16 /* one never knows ;-) */                            \
                          )

#define CID_SEP '-' /* the character which separates random from constant part */

static unsigned long callid_nr;
static char callid_buf[CALLID_NR_LEN + CALLID_SUFFIX_LEN];

str callid_prefix;
str callid_suffix;


/*
 * Initialize the Call-ID generator -- generates random prefix
 */
int init_callid(void)
{
	int rand_bits, i;

	     /* calculate the initial call-id */
	     /* how many bits and chars do we need to display the
	      * whole ULONG number */
	callid_prefix.len = sizeof(unsigned long) * 2;
	callid_prefix.s = callid_buf;

	if (callid_prefix.len > CALLID_NR_LEN) {
		LM_ERR("too small callid buffer\n");
		return -1;
	}

	for(rand_bits = 1, i = RAND_MAX; i; i >>= 1, rand_bits++);  /* how long are the rand()s ? */
	i = callid_prefix.len * 4 / rand_bits; /* how many rands() fit in the ULONG ? */

	     /* now fill in the callid with as many random
	      * numbers as you can + 1 */
       	callid_nr = rand(); /* this is the + 1 */

	while(i--) {
		callid_nr <<= rand_bits;
		callid_nr |= rand();
	}

	i = snprintf(callid_prefix.s, callid_prefix.len + 1, "%0*lx", callid_prefix.len, callid_nr);
	if ((i == -1) || (i > callid_prefix.len)) {
		LM_CRIT("callid calculation failed\n");
		return -2;
	}

	LM_DBG("Call-ID initialization: '%.*s'\n", callid_prefix.len, callid_prefix.s);
	return 0;
}


/*
 * Child initialization -- generates suffix
 */
int child_init_callid(int rank)
{
	struct socket_info *si;

	/* on tcp/tls bind_address is 0 so try to get the first address we listen
	 * on no matter the protocol */
	si=bind_address?bind_address:get_first_socket();
	if (si==0){
		LM_CRIT("null socket list\n");
		return -1;
	}
	callid_suffix.s = callid_buf + callid_prefix.len;

	callid_suffix.len = snprintf(callid_suffix.s, CALLID_SUFFIX_LEN,
				     "%c%d@%.*s", CID_SEP, my_pid(),
				     si->address_str.len,
				     si->address_str.s);
	if ((callid_suffix.len == -1) || (callid_suffix.len > CALLID_SUFFIX_LEN)) {
		LM_ERR("buffer too small\n");
		return -1;
	}

	LM_DBG("callid: '%.*s'\n", callid_prefix.len + callid_suffix.len, callid_prefix.s);
	return 0;
}


/*
 * Increment a character in hex, return
 * carry flag
 */
static inline int inc_hexchar(char* _c)
{
	if (*_c == '9') {
		*_c = 'a';
		return 0;
	}

	if (*_c == 'f') {
		*_c = '0';
		return 1;
	}

	(*_c)++;
	return 0;
}


/*
 * Get a unique Call-ID
 */
void generate_callid(str* callid)
{
	int i;

	for(i = callid_prefix.len; i; i--) {
		if (!inc_hexchar(callid_prefix.s + i - 1)) break;
	}
	callid->s = callid_prefix.s;
	callid->len = callid_prefix.len + callid_suffix.len;
}
