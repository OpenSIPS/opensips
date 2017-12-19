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

static struct str_list *push_csv_field(const str *field,
                      struct str_list **record, enum csv_flags parse_flags)
{
	struct str_list *rec;
	osips_malloc_t malloc_f;
	osips_free_t free_f;
	enum csv_flags *flags_holder;
	int len;

	if (parse_flags & CSV_SHM) {
		malloc_f = osips_shm_malloc;
		free_f = osips_shm_free;
	} else {
		malloc_f = osips_pkg_malloc;
		free_f = osips_pkg_free;
	}

	len = sizeof *rec;
	if (!*record)
		len += sizeof *flags_holder;

	rec = malloc_f(len);
	if (!rec) {
		LM_ERR("oom\n");
		return NULL;
	}

	memset(rec, 0, len);

	if (parse_flags & CSV_DUP_FIELDS) {
		rec->s.s = malloc_f(field->len + 1);
		if (!rec->s.s) {
			free_f(rec);
			LM_ERR("oom\n");
			return NULL;
		}
		memcpy(rec->s.s, field->s, field->len);
		rec->s.len = field->len;
		rec->s.s[field->len] = '\0';
	} else {
		rec->s = *field;
	}

	if (!*record) {
		flags_holder = (enum csv_flags *)(rec + 1);
		*flags_holder = parse_flags;
		*record = rec;
	} else {
		(*record)->next = rec;
	}

	return rec;
}

csv_record *__parse_csv_record(const str *_in, enum csv_flags parse_flags,
                               unsigned char sep)
{
	struct str_list *record = NULL, **last = &record;
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

		if (!push_csv_field(&field, last, parse_flags)) {
			LM_ERR("oom\n");
			free_csv_record(record);
			return NULL;
		}

		if (in.len <= 0)
			break;

		last = &(*last)->next;
	}

	return record;
}

void free_csv_record(csv_record *record)
{
	osips_free_t free_f;
	enum csv_flags flags_holder;
	struct str_list *prev;

	if (!record)
		return;

	flags_holder = *(enum csv_flags *)(record + 1);
	if (flags_holder & CSV_SHM)
		free_f = osips_shm_free;
	else
		free_f = osips_pkg_free;

	while (record) {
		prev = record;
		record = record->next;

		if (flags_holder & CSV_DUP_FIELDS)
			free_f(prev->s.s);

		free_f(prev);
	}
}
