/*
 * Copyright (c) 2011 VoIP Embedded, Inc. <http://www.voipembedded.com/>
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
 * --------
 * 2011-12-07 Initial revision (osas@voipembedded.com)
 */

#include "../error.h"
#include "../dprint.h"
#include "../errinfo.h"
#include "parse_sst.h"


int parse_min_expires(struct sip_msg *msg)
{
	if (msg->min_expires==NULL && parse_headers(msg,HDR_MIN_EXPIRES_F,0)!=0 ) {
		LM_ERR("failed to parse Min=Expires\n");
		return -1;
	}
	if (msg->min_expires) {
		/* We will re-uise the min-se parser here */
		if (msg->min_expires->parsed == 0 &&
			parse_sst_success != parse_min_se_body(msg->min_expires)) {
			set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
				"error parsing Min-Expires header");
				set_err_reply(400, "bad headers");
				return -1;
		}
	}
	return 0;
}

