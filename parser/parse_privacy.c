/*
 * Copyright (c) 2006 Juha Heinanen
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
 * -------
 * 2006-12-18 Introduced parsing of Privacy header (RFC 3323)

 */

#include <stdlib.h>
#include <string.h>
#include "../dprint.h"
#include "../trim.h"
#include "../errinfo.h"
#include "parse_privacy.h"
#include "msg_parser.h"


/*
 * Parse a privacy value pointed by start that can be at most max_len long.
 * Returns length of matched privacy value or NULL otherwise.
 */
unsigned int parse_priv_value(char* start, unsigned int max_len,
			      unsigned int* value)
{
    unsigned int len;

    if (!start || !value) {
	LM_ERR("invalid parameter value\n");
	return 0;
    }

    switch (start[0]) {

    case 'c':
    case 'C':
	if(max_len < 8)
	    return 0;
	if (strncasecmp(start, "critical", 8) == 0) {
	    *value = PRIVACY_CRITICAL;
	    len = 8;
	    break;
	} else {
	    return 0;
	}

    case 'h':
    case 'H':
	if (max_len < 6)
	    return 0;
	if (strncasecmp(start, "header", 6) == 0) {
	    *value = PRIVACY_HEADER;
	    len = 6;
	    break;
	}
	if (max_len < 7)
	    return 0;
	if (strncasecmp(start, "history", 7) == 0) {
	    *value = PRIVACY_HISTORY;
	    len = 7;
	    break;
	} else {
	    return 0;
	}

    case 'i':
    case 'I':
	if(max_len < 2)
	    return 0;
	if (start[1] == 'd' || start[1] == 'D') {
	    *value = PRIVACY_ID;
	    len = 2;
	    break;
	} else {
	    return 0;
	}

    case 'n':
    case 'N':
	if(max_len < 4)
	    return 0;
	if (strncasecmp(start, "none", 4) == 0) {
	    *value = PRIVACY_NONE;
	    len = 4;
	    break;
	} else {
	    return 0;
	}

    case 's':
    case 'S':
	if(max_len < 7)
	    return 0;
	if (strncasecmp(start, "session", 7) == 0) {
	    *value = PRIVACY_SESSION;
	    len = 7;
	    break;
	} else {
	    return 0;
	}

    case 'u':
    case 'U':
	if(max_len < 4)
	    return 0;
	if (strncasecmp(start, "user", 4) == 0) {
	    *value = PRIVACY_USER;
	    len = 4;
	    break;
	} else {
	    return 0;
	}

    default:
	return 0;
    }

    if(len < max_len) {
	if(start[len] != '\0' && start[len] != ';' && start[len] != ' '
	   && start[len] != '\t' && start[len] != '\r' && start[len] != '\n')
	    return 0;
    }

    return len;
}


/*
 * This method is used to parse Privacy HF body, which consist of
 * comma separated list of priv-values.  After parsing, msg->privacy->parsed
 * contains enum bits of privacy values defined in parse_privacy.h.
 * Returns 0 on success and -1 on failure.
 */
int parse_privacy(struct sip_msg *msg)
{
    unsigned int val_len, value, values, len;
    str next;
    char *p, *beyond;

    /* maybe the header is already parsed! */
    if (msg->privacy && msg->privacy->parsed)
	return 0;

    /* parse Privacy HF (there should be only one) */
	if (!msg->privacy &&
		(parse_headers(msg, HDR_PRIVACY_F, 0) == -1 || !msg->privacy)) {
		goto error;
	}

	next.len = msg->privacy->body.len;
	next.s = msg->privacy->body.s;

	trim_leading(&next);

	if (next.len == 0) {
		LM_ERR("no values\n");
		goto parse_error;
	}

	values = 0;
	p = next.s;
	len = next.len;
	beyond = p + len;

	while (p < beyond) {
		if((val_len = parse_priv_value(p, len, &value)) != 0) {
			values |= value;
			p = p + val_len;
			len = len - val_len;
		} else {
			LM_ERR("invalid privacy value\n");
			goto parse_error;
		}

		while(p < beyond && (*p == ' ' || *p == '\t'
		|| *p == '\r' || *p == '\n'))
			p++;

		if(p >= beyond) break;

		if (*p == ';') {
			p++;
			while(p < beyond && (*p == ' ' || *p == '\t'
					 || *p == '\r' || *p == '\n'))
				p++;
			if(p >= beyond) {
				LM_ERR("no privacy value after comma\n");
				goto parse_error;
			}
		} else {
			LM_ERR("semicolon expected\n");
			goto parse_error;
		}
	}

	if ((values & PRIVACY_NONE) && (values ^ PRIVACY_NONE)) {
		LM_ERR("no other privacy values allowed with 'none'\n");
		goto parse_error;
	}

	msg->privacy->parsed = (void *)(long)values;

	return 0;

parse_error:
	set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
		"error parsing privacy header");
	set_err_reply(400, "bad headers");

error:
	return -1;
}
