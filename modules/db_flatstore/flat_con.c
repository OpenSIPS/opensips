/*
 * Flastore module connection structure
 *
 * Copyright (C) 2004 FhG Fokus
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

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "flatstore_mod.h"
#include "flat_con.h"


/* returns a pkg_malloc'ed file name */
static char* get_name(struct flat_id* id)
{
	char* buf;
	int buf_len;
	char* num, *ptr;
	int num_len;
	int total_len;
	str prefix, suffix;

	static struct sip_msg flat_dummy_msg;

	buf_len=pathmax();
	if (!id) {
		LM_ERR("invalid parameter value\n");
		return 0;
	}
	if (flat_suffix) {
		if (pv_printf_s(&flat_dummy_msg, flat_suffix, &suffix) != 0) {
			LM_ERR("bad suffix - using default \"%s\"\n", FILE_SUFFIX);
			suffix.s = FILE_SUFFIX;
			suffix.len = FILE_SUFFIX_LEN;
		}
	} else {
		suffix.s = 0;
		suffix.len = 0;
	}
	if (flat_prefix) {
		if (pv_printf_s(&flat_dummy_msg, flat_prefix, &prefix) != 0) {
			LM_ERR("bad prefix - discarding\n");
			prefix.s = 0;
			prefix.len = 0;
		}
	} else {
		prefix.s = 0;
		prefix.len = 0;
	}


	total_len = id->dir.len + 1 /* / */ +
		prefix.len /* table prefix */ +
		id->table.len /* table name */ +
		suffix.len /* table suffix */ +
		flat_single_file ? 2 : 1 /* _ needed? + '\0' */;
				/* without pid */
	if (buf_len<total_len){
		LM_ERR("the path is too long (%d and PATHMAX is %d)\n",
					total_len, buf_len);
		return 0;
	}

	buf=pkg_malloc(buf_len);
	if (buf==0){
		LM_ERR("pkg memory allocation failure\n");
		return 0;
	}

	ptr = buf;

	memcpy(ptr, id->dir.s, id->dir.len);
	ptr += id->dir.len;
	*ptr++ = '/';

	memcpy(ptr, prefix.s, prefix.len);
	ptr += prefix.len;

	memcpy(ptr, id->table.s, id->table.len);
	ptr += id->table.len;

	if (!flat_single_file) {
		*ptr++ = '_';

		num = int2str(flat_pid, &num_len);
		if (buf_len<(total_len+num_len)){
			LM_ERR("the path is too long (%d and PATHMAX is"
					" %d)\n", total_len+num_len, buf_len);
			pkg_free(buf);
			return 0;
		}
		memcpy(ptr, num, num_len);
		ptr += num_len;
	}

	memcpy(ptr, suffix.s, suffix.len);
	ptr += suffix.len;

	*ptr = '\0';
	return buf;
}


struct flat_con* flat_new_connection(struct flat_id* id)
{
	char* fn;

	struct flat_con* res;

	if (!id) {
		LM_ERR("invalid parameter value\n");
		return 0;
	}

	res = (struct flat_con*)pkg_malloc(sizeof(struct flat_con));
	if (!res) {
		LM_ERR("no pkg memory left\n");
		return 0;
	}

	memset(res, 0, sizeof(struct flat_con));
	res->ref = 1;

	res->id = id;

	fn = get_name(id);
	if (fn==0){
		LM_ERR("get_name() failed\n");
		return 0;
	}

	res->file = fopen(fn, "a");
	pkg_free(fn); /* we don't need fn anymore */
	if (!res->file) {
		LM_ERR(" %s\n", strerror(errno));
		pkg_free(res);
		return 0;
	}

	return res;
}


/*
 * Close the connection and release memory
 */
void flat_free_connection(struct flat_con* con)
{
	if (!con) return;
	if (con->id) free_flat_id(con->id);
	if (con->file) {
		fclose(con->file);
	}
	pkg_free(con);
}


/*
 * Reopen a connection
 */
int flat_reopen_connection(struct flat_con* con)
{
	char* fn;

	if (!con) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	if (con->file) {
		fclose(con->file);
		con->file = 0;

		fn = get_name(con->id);
		if (fn == 0) {
			LM_ERR("failed to get_name\n");
			return -1;
		}

		con->file = fopen(fn, "a");
		pkg_free(fn);

		if (!con->file) {
			LM_ERR("invalid parameter value\n");
			return -1;
		}
	}

	return 0;
}
