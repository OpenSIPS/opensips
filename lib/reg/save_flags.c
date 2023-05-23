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
#include "../../mod_fix.h"
#include "common.h"

static str save_flag_names[] = {
	str_init("memory-only"),           /* REG_SAVE_MEMORY_FLAG */
	str_init("no-reply"),              /* REG_SAVE_NOREPLY_FLAG */
	str_init("socket-header"),         /* REG_SAVE_SOCKET_FLAG */
	str_init("path-strict"),           /* REG_SAVE_PATH_STRICT_FLAG */
	str_init("path-lazy"),             /* REG_SAVE_PATH_LAZY_FLAG */
	str_init("path-off"),              /* REG_SAVE_PATH_OFF_FLAG */
	str_init("path-received"),         /* REG_SAVE_PATH_RECEIVED_FLAG */
	str_init("force-registration"),    /* REG_SAVE_FORCE_REG_FLAG */
	str_init("only-request-contacts"), /* REG_SAVE_REQ_CT_ONLY_FLAG */
	STR_NULL
};

#define SAVE_KV_FLAGS_NO 4

static str save_kv_flag_names[] = {
	str_init("max-contacts"),
	str_init("min-expires"),
	str_init("max-expires"),
	str_init("matching-mode"),
	STR_NULL
};

int reg_fixup_save_flags(void** param, struct save_flags *default_flags)
{
	struct save_flags *save_flags;
	str flag_vals[SAVE_KV_FLAGS_NO];
	str_list *mp;
	char *p;

	save_flags = pkg_malloc(sizeof *save_flags);
	if (!save_flags) {
		LM_ERR("out of pkg memory\n");
		return -1;
	}

	*save_flags = *default_flags;

	if (fixup_named_flags(param, save_flag_names, save_kv_flag_names,
		flag_vals) < 0) {
		LM_ERR("Failed to parse flags\n");
		return -1;
	}

	save_flags->flags = (unsigned int)(unsigned long)(void*)*param;
	*param = (void*)save_flags;

	/* max-contacts */
	if (flag_vals[0].s) {
		if (str2int(&flag_vals[0], &save_flags->max_contacts) < 0) {
			LM_ERR("max-contacts [%.*s] value is not an integer\n",
				flag_vals[0].len, flag_vals[0].s);
			return -1;
		}
	}
	/* min-expires */
	if (flag_vals[1].s) {
		if (str2int(&flag_vals[1], &save_flags->min_expires) < 0) {
			LM_ERR("min-expires [%.*s] value is not an integer\n",
				flag_vals[1].len, flag_vals[1].s);
			return -1;
		}
	}
	/* max-expires */
	if (flag_vals[2].s) {
		if (str2int(&flag_vals[2], &save_flags->max_expires) < 0) {
			LM_ERR("min-expires [%.*s] value is not an integer\n",
				flag_vals[2].len, flag_vals[2].s);
			return -1;
		}
	}
	/* matching-mode */
	if (flag_vals[3].s) {
		p = flag_vals[3].s;
		if (*p=='0')
			save_flags->cmatch.mode = CT_MATCH_CONTACT_ONLY;
		else if (*p=='1')
			save_flags->cmatch.mode = CT_MATCH_CONTACT_CALLID;
		else if (*p=='<' && flag_vals[3].len >= 3) {
			p++;
			mp = &save_flags->match_params;
			save_flags->cmatch.match_params = mp;
			mp->s.s = p;
			while (p<flag_vals[3].s+flag_vals[3].len && *(p+1)!='>')
				p++;
			if (p<flag_vals[3].s+flag_vals[3].len && *(p+1)=='>') {
				mp->s.len = p + 1 - mp->s.s;

				save_flags->cmatch.mode = CT_MATCH_PARAMS;
			} else {
				LM_ERR("invalid format for 'matching-mode' param"
					"discarding trailing '%.*s'\n", (int)(p - mp->s.s), mp->s.s);
				mp->s.s = NULL;
			}
		} else {
			LM_ERR("invalid value for 'matching-mode' param, "
				"discarding trailing <%c>\n", *p);
		}
	}

	return 0;
}

int reg_fixup_free_save_flags(void** param)
{
	if (*param)
		pkg_free(*param);
	return 0;
}
