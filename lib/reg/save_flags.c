/*
 * Copyright (C) 2019 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <ctype.h>

#include "../../dprint.h"
#include "common.h"


void reg_parse_save_flags(str *flags_s, struct save_ctx *sctx)
{
	static str_list mp;
	int st, max_ct;

	sctx->cmatch.mode = CT_MATCH_NONE;
	sctx->max_contacts = max_contacts;

	for( st=0 ; st< flags_s->len ; st++ ) {
		switch (flags_s->s[st]) {
			case 'm': sctx->flags |= REG_SAVE_MEMORY_FLAG; break;
			case 'o': sctx->flags |= REG_SAVE_REQ_CT_ONLY_FLAG; break;
			case 'r': sctx->flags |= REG_SAVE_NOREPLY_FLAG; break;
			case 's': sctx->flags |= REG_SAVE_SOCKET_FLAG; break;
			case 'v': sctx->flags |= REG_SAVE_PATH_RECEIVED_FLAG; break;
			case 'f': sctx->flags |= REG_SAVE_FORCE_REG_FLAG; break;
			case 'c':
				max_ct = 0;
				while (st<flags_s->len-1 && isdigit(flags_s->s[st+1])) {
					max_ct = max_ct * 10 + flags_s->s[st+1] - '0';
					st++;
				}

				if (max_ct)
					sctx->max_contacts = max_ct;
				break;
			case 'e':
				sctx->min_expires = 0;
				while (st<flags_s->len-1 && isdigit(flags_s->s[st+1])) {
					sctx->min_expires = sctx->min_expires*10 +
						flags_s->s[st+1] - '0';
					st++;
				}
				break;
			case 'E':
				sctx->max_expires = 0;
				while (st<flags_s->len-1 && isdigit(flags_s->s[st+1])) {
					sctx->max_expires = sctx->max_expires*10 +
						flags_s->s[st+1] - '0';
					st++;
				}
				break;
			case 'p':
				if (st<flags_s->len-1) {
					st++;
					if (flags_s->s[st]=='2')
						sctx->flags |= REG_SAVE_PATH_STRICT_FLAG;
					else if (flags_s->s[st]=='1')
						sctx->flags |= REG_SAVE_PATH_LAZY_FLAG;
					else if (flags_s->s[st]=='0')
						sctx->flags |= REG_SAVE_PATH_OFF_FLAG;
					else
						LM_ERR("invalid value for PATH 'p' param, "
							"discarding trailing <%c>\n", flags_s->s[st]);
				}
				break;
			case 'M':
				if (st<flags_s->len-1) {
					st++;
					if (flags_s->s[st]=='0')
						sctx->cmatch.mode = CT_MATCH_CONTACT_ONLY;
					else if (flags_s->s[st]=='1')
						sctx->cmatch.mode = CT_MATCH_CONTACT_CALLID;
					else if (flags_s->s[st]=='<' && st<flags_s->len-3) {
						st++;
						mp.s.s = flags_s->s + st;
						while (st<flags_s->len-1 && flags_s->s[st+1]!='>')
							st++;
						if (st<flags_s->len-1 && flags_s->s[st+1]=='>') {
							mp.s.len = flags_s->s + st + 1
								 - mp.s.s;

							sctx->cmatch.match_params = &mp;
							sctx->cmatch.mode = CT_MATCH_PARAMS;
							st++;
						} else {
							LM_ERR("invalid format for MATCH 'M' param, "
								"discarding trailing '%.*s'\n",
								(int)(flags_s->s + st - mp.s.s), mp.s.s);
							mp.s.s = NULL;
						}
					} else {
						LM_ERR("invalid value for MATCH 'M' param, "
							"discarding trailing <%c>\n", flags_s->s[st]);
					}
				}
				break;
			default:
				LM_WARN("unsupported flag %c \n",flags_s->s[st]);
		}
	}
}
