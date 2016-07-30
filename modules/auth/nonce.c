/*
 * Nonce related functions
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
 */


#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "../../md5global.h"
#include "../../md5.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../timer.h"
#include "nonce.h"
#include "index.h"
#include "auth_mod.h"


/*
 * Convert an integer to its hex representation,
 * destination array must be at least 8 bytes long,
 * this string is NOT zero terminated
 */
static inline void integer2hex(char* _d, int _s)
{
	int i;
	unsigned char j;
	char* s;

	_s = htonl(_s);
	s = (char*)&_s;

	for (i = 0; i < 4; i++) {

		j = (s[i] >> 4) & 0xf;
		if (j <= 9) {
			_d[i * 2] = (j + '0');
		} else {
			_d[i * 2] = (j + 'a' - 10);
		}

		j = s[i] & 0xf;
		if (j <= 9) {
			_d[i * 2 + 1] = (j + '0');
		} else {
		       _d[i * 2 + 1] = (j + 'a' - 10);
		}
	}
}


/*
 * Convert hex string to integer
 */
static inline int hex2integer(char* _s)
{
	unsigned int i, res = 0;

	for(i = 0; i < 8; i++) {
		res *= 16;
		if ((_s[i] >= '0') && (_s[i] <= '9')) {
			res += _s[i] - '0';
		} else if ((_s[i] >= 'a') && (_s[i] <= 'f')) {
			res += _s[i] - 'a' + 10;
		} else if ((_s[i] >= 'A') && (_s[i] <= 'F')) {
			res += _s[i] - 'A' + 10;
		} else return 0;
	}

	return res;
}


/*
 * Calculate nonce value
 * Nonce value consists of the expires time (in seconds since 1.1 1970)
 * and a secret phrase
 */
void calc_nonce(char* _nonce, int _expires, int _index, str* _secret)
{
	MD5_CTX ctx;
	unsigned char bin[16];
	unsigned int offset = 8;

	MD5Init(&ctx);


	integer2hex(_nonce, _expires);

	if(!disable_nonce_check) {
		integer2hex(_nonce + 8, _index);
		offset = 16;
	}

    MD5Update(&ctx, _nonce, offset);

	MD5Update(&ctx, _secret->s, _secret->len);
	MD5Final(bin, &ctx);
	string2hex(bin, 16, _nonce + offset);
	_nonce[offset + 32] = '\0';
}

/*
 * Get nonce index
 */
int get_nonce_index(str* _n)
{
    return hex2integer(_n->s + 8);
}


/*
 * Get expiry time from nonce string
 */
time_t get_nonce_expires(str* _n)
{
	return (time_t)hex2integer(_n->s);
}


/*
 * Check, if the nonce received from client is
 * correct
 */
int check_nonce(str* _nonce, str* _secret)
{
	int expires;
	char non[NONCE_LEN + 1];
    int index = 0;

	if (_nonce->s == 0) {
		return -1;  /* Invalid nonce */
	}

	if (NONCE_LEN != ((!disable_nonce_check)?_nonce->len:_nonce->len +8)) {
		return 1; /* Lengths must be equal */
	}

	expires = get_nonce_expires(_nonce);
    if(!disable_nonce_check)
		index = get_nonce_index(_nonce);

    calc_nonce(non, expires, index, _secret);


	LM_DBG("comparing [%.*s] and [%.*s]\n",
			_nonce->len, ZSW(_nonce->s), ((!disable_nonce_check)?NONCE_LEN:NONCE_LEN-8), non);
    if (!memcmp(non, _nonce->s, _nonce->len)) {
		return 0;
	}
	return 2;
}


/*
 * Check if a nonce is stale
 */
int is_nonce_stale(str* _n)
{
	if (!_n->s) return 0;

	if (get_nonce_expires(_n) < time(0)) {
		return 1;
	} else {
		return 0;
	}
}
