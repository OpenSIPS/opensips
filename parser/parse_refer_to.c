/*
 * Copyright (C) 2005 Juha Heinanen
 *
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
#include "../errinfo.h"
#include "../mem/mem.h"
#include "msg_parser.h"
#include "parse_from.h"
#include "parse_to.h"


/*
 * This method is used to parse Refer-To header.
 *
 * params: msg : sip msg
 * returns 0 on success,
 *        -1 on failure.
 */
int parse_refer_to_header( struct sip_msg *msg )
{
	struct to_body* refer_to_b;

	if ( !msg->refer_to &&
	(parse_headers(msg, HDR_REFER_TO_F,0)==-1 || !msg->refer_to)) {
		goto error;
	}

	/* maybe the header is already parsed! */
	if (msg->refer_to->parsed)
		return 0;

	/* bad luck! :-( - we have to parse it */
	/* first, get some memory */
	refer_to_b = pkg_malloc(sizeof(struct to_body));
	if (refer_to_b == 0) {
		LM_ERR("out of pkg_memory\n");
		goto error;
	}

	/* now parse it!! */
	parse_to(msg->refer_to->body.s,
		msg->refer_to->body.s + msg->refer_to->body.len+1,
		refer_to_b);
	if (refer_to_b->error == PARSE_ERROR) {
		LM_ERR("bad Refer-To header\n");
		pkg_free(refer_to_b);
		set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
			"error parsing REFER-TO header");
		set_err_reply(400, "bad headers");
		goto error;
	}
	msg->refer_to->parsed = refer_to_b;

	return 0;
error:
	return -1;
}
