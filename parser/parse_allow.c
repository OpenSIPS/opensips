/*
 * Copyright (c) 2004 Juha Heinanen
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
 * 2006-03-02  parse_allow() parses and cumulates all ALLOW headers (bogdan)

 */

#include <stdlib.h>
#include <string.h>
#include "../dprint.h"
#include "../errinfo.h"
#include "../mem/mem.h"
#include "parse_allow.h"
#include "parse_methods.h"
#include "msg_parser.h"


/*
 * This method is used to parse all Allow HF body.
 *
 * params: msg : sip msg
 * returns 0 on success,
 *        -1 on failure.
 */
int parse_allow(struct sip_msg *msg)
{
	unsigned int allow;
	struct hdr_field  *hdr;
	struct allow_body *ab = 0;

	/* maybe the header is already parsed! */
	if (msg->allow && msg->allow->parsed)
		return 0;

	/* parse to the end in order to get all ALLOW headers */
	if (parse_headers(msg,HDR_EOH_F,0)==-1 || !msg->allow)
		return -1;

	/* bad luck! :-( - we have to parse them */
	allow = 0;
	for( hdr=msg->allow ; hdr ; hdr=hdr->sibling) {
		if (hdr->parsed) {
			allow |= ((struct allow_body*)hdr->parsed)->allow;
			continue;
		}

		ab = (struct allow_body*)pkg_malloc(sizeof(struct allow_body));
		if (ab == 0) {
			LM_ERR("out of pkg_memory\n");
			return -1;
		}

		if (parse_methods(&(hdr->body), &(ab->allow))!=0) {
			LM_ERR("bad allow body header\n");
			set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
				"error parsing ALLOW header");
			set_err_reply(400, "bad headers");
			goto error;
		}
		ab->allow_all = 0;
		hdr->parsed = (void*)ab;
		allow |= ab->allow;
	}

	((struct allow_body*)msg->allow->parsed)->allow_all = allow;
	return 0;

error:
	if(ab!=0)
		pkg_free(ab);
	return -1;
}

