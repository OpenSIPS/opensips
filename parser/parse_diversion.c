/*
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

#include <stdlib.h>
#include <string.h>
#include "../dprint.h"
#include "../ut.h"
#include "../mem/mem.h"
#include "parse_from.h"
#include "parse_to.h"
#include "msg_parser.h"

/*
 * This method is used to parse DIVERSION header as per RFC5806
 *  (Diversion Indication in SIP)
 *
 * params: msg : sip msg
 * returns 0 on success,
 *        -1 on failure.
 */
int parse_diversion_header(struct sip_msg *msg)
{
	struct to_body* diversion_b;

	if (!msg->diversion && (parse_headers(msg, HDR_DIVERSION_F, 0) == -1 ||
				!msg->diversion)) {
		goto error;
	}

	/* maybe the header is already parsed! */
	if (msg->diversion->parsed)
		return 0;

	/* bad luck! :-( - we have to parse it */
	/* first, get some memory */
	diversion_b = pkg_malloc(sizeof(struct to_body));
	if (diversion_b == 0) {
		LM_ERR("out of pkg_memory\n");
		goto error;
	}

	/* now parse it!! */
	parse_multi_to(msg->diversion->body.s,
		msg->diversion->body.s + msg->diversion->body.len + 1, diversion_b);
	if (diversion_b->error == PARSE_ERROR) {
		LM_ERR("bad diversion header\n");
		pkg_free(diversion_b);
		goto error;
	}
	msg->diversion->parsed = diversion_b;

	return 0;
error:
	return -1;
}


/*
 * Get value of given diversion parameter
 */
str *diversion_param(struct sip_msg *msg, str name)
{
	struct to_param *params;

	if (parse_diversion_header(msg) == -1) {
		LM_ERR("could not get diversion parameter\n");
		return 0;
	}

	params =  ((struct to_body*)(msg->diversion->parsed))->param_lst;

	while (params) {
		if ((params->name.len == name.len) &&
		(strncmp(params->name.s, name.s, name.len) == 0)) {
			return &(params->value);
		}
		params = params->next;
	}

	return 0;
}
