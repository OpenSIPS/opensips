/*
 * Copyright (C) 2017 OpenSIPS Solutions
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
#include <stdio.h>

#include "../mem/mem.h"
#include "../trim.h"

#include "csv.h"

static struct csv_record *push_csv_field(const str *field,
                                         struct csv_record **record)
{
	struct csv_record *rec;

	rec = pkg_malloc(sizeof *rec);
	if (!rec) {
		LM_ERR("oom\n");
		return NULL;
	}

	memset(rec, 0, sizeof *rec);
	rec->field = *field;

	if (!*record)
		*record = rec;
	else
		(*record)->next_field = rec;

	return rec;
}

struct csv_record *__parse_csv_record(const str *_in, int parse_flags,
                                      unsigned char sep)
{
	struct csv_record *record = NULL, **last = &record;
	str in = *_in, field;
	char *ch;

	/* TODO: implement this and re-use in transformations.c.
	 *        (possibly merge & fix code from there)
	 * Issue #1220 should get fixed during this process as well */
	if ((parse_flags & CSV_SIMPLE) != CSV_SIMPLE) {
		LM_BUG("RFC 4180 not fully implemented yet");
		abort();
	}

	trim(&in);

	for (;;) {
		ch = memchr(in.s, sep, in.len);
		if (!ch)
			ch = in.s + in.len;

		field.s = in.s;
		field.len = ch - in.s;
		in.s += field.len + 1;
		in.len -= field.len + 1;
		trim(&field);

		if (!push_csv_field(&field, last)) {
			LM_ERR("oom\n");
			free_csv_record(record);
			return NULL;
		}

		if (in.len <= 0)
			break;

		last = &(*last)->next_field;
	}

	return record;
}

void free_csv_record(struct csv_record *record)
{
	struct csv_record *prev;

	while (record) {
		prev = record;
		record = record->next_field;
		pkg_free(prev);
	}
}
