/*
 * statistics module - script interface to internal statistics manager
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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
 *  2006-03-14  initial version (bogdan)
 */


#include <string.h>

#include "../../dprint.h"
#include "../../statistics.h"
#include "../../mem/mem.h"
#include "stats_funcs.h"


#define NORESET_FLAG_STR "no_reset"
#define MODULE_STATS     "script"


typedef struct stat_mod_elem_
{
	char *name;
	int flags;
	struct stat_mod_elem_ *next;
} stat_elem;

static stat_elem *stat_list = 0;


int reg_statistic( char* name)
{
	stat_elem *se;
	char *flag_str;
	int flags;

	if (name==0 || *name==0) {
		LM_ERR("empty parameter\n");
		goto error;
	}

	flags = 0;
	flag_str = strchr( name, '/');
	if (flag_str) {
		*flag_str = 0;
		flag_str++;
		if (strcasecmp( flag_str, NORESET_FLAG_STR)==0) {
			flags |= STAT_NO_RESET;
		} else {
			LM_ERR("unsupported flag <%s>\n",flag_str);
			goto error;
		}
	}

	se = (stat_elem*)pkg_malloc( sizeof(stat_elem) );
	if (se==0) {
		LM_ERR("no more pkg mem\n");
		goto error;
	}

	se->name = name;
	se->flags = flags;
	se->next = stat_list;
	stat_list = se;

	return 0;
error:
	return -1;
}



int register_all_mod_stats(void)
{
	stat_elem *se;
	stat_elem *se_tmp;
#ifdef STATISTICS
	stat_var  *stat = NULL;
#endif

	se = stat_list;
	while( se ) {
		se_tmp = se;
		se = se->next;

		/* register the new variable */
		if (register_stat(MODULE_STATS, se_tmp->name, &stat, se_tmp->flags)!=0){
			LM_ERR("failed to register var. <%s> flags %d\n",
					se_tmp->name,se_tmp->flags);
			return -1;
		}
		pkg_free(se_tmp);
	}

	return 0;
}

void parse_groupname(const str *in, str *out_grp, str *out_name)
{
	char *p, *lim = in->s + in->len;

	for (p = in->s; *p != STAT_GROUP_DELIM && p < lim; p++) {}

	if (p >= lim) {
		out_grp->s = NULL;
		out_grp->len = 0;
		*out_name = *in;
	} else {
		out_grp->s = in->s;
		out_grp->len = p - in->s;
		out_name->s = p + 1;
		out_name->len = in->len - (out_name->s - in->s);
	}

	LM_DBG("group: '%.*s', name: '%.*s'\n", out_grp->len, out_grp->s,
	       out_name->len, out_name->s);
}








