/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 * nats_msg_id.c -- the Nats-Msg-Id of a JetStream publish (see
 * nats_msg_id.h).  libc only.
 */

#include <stdio.h>
#include <string.h>

#include "nats_msg_id.h"

static int is_space(char c)
{
	return c == ' ' || c == '\t';
}

/* a name: non-empty, no space or control byte, no ':' or ',' */
static int name_ok(const char *s, int len)
{
	int i;

	if (len <= 0)
		return 0;
	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c <= 0x20 || c >= 0x7f || c == ':' || c == ',')
			return 0;
	}
	return 1;
}

/* trim spaces around [*s, *s + *len) */
static void trim(const char **s, int *len)
{
	while (*len > 0 && is_space(**s)) {
		(*s)++;
		(*len)--;
	}
	while (*len > 0 && is_space((*s)[*len - 1]))
		(*len)--;
}

int nats_msg_id_rule_parse(const char *spec, int len, nats_msg_id_rule *r)
{
	const char *colon, *p, *end, *tok;
	int tlen, i;

	if (!spec || len <= 0 || !r)
		return -1;
	memset(r, 0, sizeof *r);
	end = spec + len;
	colon = memchr(spec, ':', len);
	if (!colon)
		return -1;

	tok = spec;
	tlen = (int)(colon - spec);
	trim(&tok, &tlen);
	if (!name_ok(tok, tlen))
		return -1;
	r->event.s = (char *)tok;
	r->event.len = tlen;

	p = colon + 1;
	for (;;) {
		const char *comma = memchr(p, ',', end - p);
		const char *stop = comma ? comma : end;

		tok = p;
		tlen = (int)(stop - p);
		trim(&tok, &tlen);
		if (!name_ok(tok, tlen))
			return -1;
		if (r->nparams == NATS_MSG_ID_MAX_PARAMS)
			return -1;
		for (i = 0; i < r->nparams; i++)
			if (r->params[i].len == tlen &&
			    memcmp(r->params[i].s, tok, tlen) == 0)
				return -1;
		r->params[r->nparams].s = (char *)tok;
		r->params[r->nparams].len = tlen;
		r->nparams++;
		if (!comma)
			break;
		p = comma + 1;
	}
	return 0;
}

static const evi_param_t *find_param(const evi_params_t *params, const str *name)
{
	const evi_param_t *p;

	for (p = params ? params->first : NULL; p; p = p->next)
		if (p->name.len == name->len &&
		    memcmp(p->name.s, name->s, name->len) == 0)
			return p;
	return NULL;
}

/* append one byte, encoded when needed; -1 when out of room */
static int put_byte(char *out, int *pos, unsigned char c)
{
	static const char hex[] = "0123456789ABCDEF";

	if (c > 0x20 && c < 0x7f && c != ':' && c != '%') {
		if (*pos + 1 > NATS_MSG_ID_MAX)
			return -1;
		out[(*pos)++] = (char)c;
		return 0;
	}
	if (*pos + 3 > NATS_MSG_ID_MAX)
		return -1;
	out[(*pos)++] = '%';
	out[(*pos)++] = hex[c >> 4];
	out[(*pos)++] = hex[c & 0x0f];
	return 0;
}

int nats_msg_id_build(const nats_msg_id_rule *r, const evi_params_t *params,
		char *out, int size)
{
	char num[16];
	int pos = 0, i, j, n;

	if (!r || !out || size < NATS_MSG_ID_BUF)
		return NATS_MSG_ID_ETOOLONG;

	/* the event name passed name_ok(): nothing to encode */
	if (r->event.len > NATS_MSG_ID_MAX)
		return NATS_MSG_ID_ETOOLONG;
	memcpy(out, r->event.s, r->event.len);
	pos = r->event.len;

	for (i = 0; i < r->nparams; i++) {
		const evi_param_t *p = find_param(params, &r->params[i]);

		if (!p)
			return NATS_MSG_ID_EMISSING;
		if (pos + 1 > NATS_MSG_ID_MAX)
			return NATS_MSG_ID_ETOOLONG;
		out[pos++] = ':';
		if (p->flags & EVI_INT_VAL) {
			n = snprintf(num, sizeof num, "%d", p->val.n);
			if (pos + n > NATS_MSG_ID_MAX)
				return NATS_MSG_ID_ETOOLONG;
			memcpy(out + pos, num, n);
			pos += n;
		} else if (p->flags & EVI_STR_VAL) {
			for (j = 0; j < p->val.s.len; j++)
				if (put_byte(out, &pos, (unsigned char)p->val.s.s[j]) < 0)
					return NATS_MSG_ID_ETOOLONG;
		}
		/* a parameter with no value (neither flag) adds an empty field */
	}
	out[pos] = '\0';
	return pos;
}

int nats_msg_id_check(const char *id, int len)
{
	int i;

	if (!id || len <= 0 || len > NATS_MSG_ID_MAX)
		return -1;
	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)id[i];
		if (c <= 0x20 || c >= 0x7f)
			return -1;
	}
	return 0;
}

int nats_msg_id_generated(uint64_t prefix, uint64_t seq, char *out, int size)
{
	int n;

	if (!out || size <= 0)
		return -1;
	n = snprintf(out, size, "%016llx-%llu",
		(unsigned long long)prefix, (unsigned long long)seq);
	if (n < 0 || n >= size)
		return -1;
	return n;
}
