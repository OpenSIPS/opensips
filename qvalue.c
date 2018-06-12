/*
 * $Id$
 *
 * Handling of the q value
 *
 * Copyright (C) 2004 FhG FOKUS
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
 * History
 * ------
 * 2004-04-25 created (janakj)
 */

#include "error.h"
#include "qvalue.h"


/*
 * Convert string representation of q parameter in qvalue_t
 */
int str2q(qvalue_t* q, char* s, int len)
{
	int i, digits;

	     /* States and equivalent regular expressions of input */
	enum {
		ST_START,   /* (SPC|TAB)* */
		ST_0,       /* 0+ */
		ST_1,       /* 1 */
		ST_0_PT,    /* 0*\. */
		ST_1_PT,    /* 1\. */
		ST_1_PT_0,  /* 1\.0+ */
		ST_0_PT_N   /* 0*\.[0-9]+ */
	} state = ST_START;

	if (!q || !s) {
		return E_INVALID_PARAMS;
	}

	digits = 1;
	for(i = 0; i < len; i++) {
		switch(state) {
		case ST_START:
			switch(s[i]) {
			case ' ':
			case '\t':
				break;

			case '0':
				*q = 0;
				state = ST_0;
				break;

			case '1':
				*q = 1000;
				state = ST_1;
				break;

			case '.':
				state = ST_0_PT;
				break;

			default:
				return E_Q_INV_CHAR;
			}
			break;

		case ST_0:
			switch(s[i]) {
			case '0':
				break;

			case '.':
				state = ST_0_PT;
				break;

			case '1':
				*q = 1000;
				state = ST_1;
				break;

			default:
				if (s[i] >= '2' && s[i] <= '9') {
					return E_Q_TOO_BIG;
				} else {
					return E_Q_INV_CHAR;
				}
			}
			break;

		case ST_1:
			if (s[i] == '.') {
				state = ST_1_PT;
				break;
			} else {
				if (s[i] >= '0' && s[i] <= '9') {
					return E_Q_TOO_BIG;
				} else {
					return E_Q_INV_CHAR;
				}
			}
			break;

		case ST_0_PT:
			if (s[i] >= '0' && s[i] <= '9') {
				*q =  s[i] - '0';
				state = ST_0_PT_N;
			} else {
				return E_Q_INV_CHAR;
			}
			break;

		case ST_1_PT:
			if (s[i] == '0') {
				state = ST_1_PT_0;
			} else {
				if (s[i] >= '1' && s[i] <= '9') {
					return E_Q_TOO_BIG;
				} else {
					return E_Q_INV_CHAR;
				}
			}
			break;

		case ST_1_PT_0:
			if (s[i] == '0') {
				break;
			} else {
				if (s[i] >= '1' && s[i] <= '9') {
					return E_Q_TOO_BIG;
				} else {
					return E_Q_INV_CHAR;
				}
			}
			break;

		case ST_0_PT_N:
			if (s[i] >= '0' && s[i] <= '9') {
				if (digits < 3) {
					*q = *q * 10 + s[i] - '0';
					digits++;
				}
			} else {
				return E_Q_INV_CHAR;
			}
			break;
		}
	}

	switch(state) {
	case ST_START:
		return E_Q_EMPTY;
		
	case ST_0_PT:
	case ST_1_PT:
		return E_Q_DEC_MISSING;
		
	default:
		return 0;
	}
}
