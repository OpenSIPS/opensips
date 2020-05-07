/*
 * Copyright (C) 2017-2019 OpenSIPS Solutions
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

#include <string.h>
#include <stdio.h>

#include "../mem/mem.h"
#include "../trim.h"

#include "csv.h"

static osips_malloc_t malloc_f;
static osips_free_t free_f;

static str_list *push_csv_field(const str *field,
                                str_list **record, enum csv_flags parse_flags)
{
	str_list *rec;
	enum csv_flags *flags_holder;
	int len;

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
	str_list *record = NULL, **last = &record;
	str in = *_in, field;
	char *ch, *p, *c, finished, *lim, *field_start;

	if (parse_flags & CSV_SHM) {
		malloc_f = osips_shm_malloc;
		free_f = osips_shm_free;
	} else {
		malloc_f = osips_pkg_malloc;
		free_f = osips_pkg_free;
	}

	if (parse_flags & CSV_RFC_4180)
		goto rfc_4180_parsing;

	trim(&in);

	for (finished = 0; !finished; ) {
		ch = memchr(in.s, sep, in.len);
		if (!ch) {
			ch = in.s + in.len;
			finished = 1;
		}

		field.s = in.s;
		field.len = ch - in.s;
		in.s += field.len + 1;
		in.len -= field.len + 1;
		trim(&field);

		if (!push_csv_field(&field, last, parse_flags))
			goto oom;

		last = &(*last)->next;
	}

	return record;

rfc_4180_parsing:
	if (in.len >= 2 && in.s[in.len - 2] == '\r' && in.s[in.len - 1] == '\n')
		in.len -= 2;

	field_start = NULL;
	for (ch = in.s, lim = in.s + in.len; ch < lim; ch++) {
		if (*ch < 0x20 || *ch > 0x7E)
			goto bad_csv_str;

		switch (*ch) {
		case ',':
			if (field_start)
				field.s = field_start;
			else
				field.s = in.s;

			field.len = ch - field.s;
			field_start = ch + 1;

			if (!push_csv_field(&field, last, parse_flags))
				goto oom;

			last = &(*last)->next;
			break;

		case '"':
			if ((field_start && ch != field_start) ||
				(!field_start && ch != in.s))
				continue;

			for (p = ch + 1; p < lim; p++) {
				if (*p == '"') {
					if (p == lim - 1 || *(p + 1) != '"')
						goto matched_quote;

					p++;
					continue;
				}
			}

			goto bad_csv_str;

matched_quote:
			field.s = malloc_f(p - ch);
			if (!field.s)
				goto oom;

			for (c = field.s; ++ch < p; c++) {
				if (*ch == '"')
					ch++;
				*c = *ch;
			}

			if (ch < lim - 1) {
				if (*(ch + 1) != ',') {
					free_f(field.s);
					goto bad_csv_str;
				}
				ch++;
				field_start = ch + 1;
			}

			*c = '\0';
			field.len = c - field.s;

			if (!push_csv_field(&field, last, parse_flags & (~CSV_DUP_FIELDS)))
				goto oom;

			last = &(*last)->next;

			if (ch == lim - 1)
				return record;

			break;
		}
	}

	if (field_start) {
		field.s = field_start;
		field.len = lim - field.s;
	} else {
		field = in;
	}

	if (!push_csv_field(&field, last, parse_flags))
		goto oom;

	return record;

bad_csv_str:
	LM_DBG("invalid CSV string: '%.*s'\n", in.len, in.s);
	free_csv_record(record);
	return NULL;

oom:
	LM_ERR("oom while parsing '%.*s'\n", in.len, in.s);
	free_csv_record(record);
	return NULL;
}

void free_csv_record(csv_record *record)
{
	enum csv_flags flags_holder;
	str_list *prev;

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
