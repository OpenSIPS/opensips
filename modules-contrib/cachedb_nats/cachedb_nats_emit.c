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
 * cachedb_nats_emit.c — row emitter: one result-set walk per MI
 * handler, json-vs-table decided by the backend (cachedb_nats_emit.h).
 * The table backend is unit-locked in test/test_emit_rows.c, which
 * compiles this file directly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cachedb_nats_emit.h"

/* ==================================================================== */
/* table backend — names ignored, cells appended in call order          */
/* ==================================================================== */

static int emt_rec(struct nats_emit *e)
{
	(void)e;
	return 0;
}

static int emt_str(struct nats_emit *e, const char *name, int nlen,
	const char *v, int vlen)
{
	(void)name; (void)nlen;
	fmt_str(&e->t, v, vlen);
	return e->t.oom ? -1 : 0;
}

static int emt_i64(struct nats_emit *e, const char *name, int nlen,
	long long v)
{
	(void)name; (void)nlen;
	fmt_int(&e->t, v);
	return e->t.oom ? -1 : 0;
}

static int emt_absent(struct nats_emit *e, const char *name, int nlen)
{
	(void)name; (void)nlen;
	fmt_empty(&e->t);
	return e->t.oom ? -1 : 0;
}

static int emt_lit(struct nats_emit *e, const char *v, int vlen)
{
	fmt_str(&e->t, v, vlen);
	return e->t.oom ? -1 : 0;
}

static int emt_end(struct nats_emit *e)
{
	fmt_end_record(&e->t);
	return e->t.oom ? -1 : 0;
}

static const struct nats_emit_ops _emit_table_ops = {
	.rec    = emt_rec,
	.str    = emt_str,
	.i64    = emt_i64,
	.absent = emt_absent,
	.lit    = emt_lit,
	.end    = emt_end,
};

int nats_emit_open_fmt(struct nats_emit *e, int kind, int eol_lf, int header,
	const char **cols, int ncols)
{
	memset(e, 0, sizeof(*e));
	e->ops = &_emit_table_ops;
	e->table = 1;
	return fmt_init(&e->t, kind, eol_lf, header, cols, ncols);
}

char *nats_emit_take(struct nats_emit *e, int *out_len)
{
	if (!e->table)
		return NULL;
	return fmt_take(&e->t, out_len);
}

void nats_emit_abort(struct nats_emit *e)
{
	if (e->table)
		fmt_free(&e->t);
}

#ifndef NATS_EMIT_STANDALONE

/* ==================================================================== */
/* MI backend — rows become objects in a json array; absent/lit no-ops  */
/* ==================================================================== */

static int emi_rec(struct nats_emit *e)
{
	e->cur = add_mi_object(e->arr, NULL, 0);
	return e->cur ? 0 : -1;
}

static int emi_str(struct nats_emit *e, const char *name, int nlen,
	const char *v, int vlen)
{
	if (!e->cur)                    /* rec() failed or never called */
		return -1;
	return add_mi_string(e->cur, (char *)name, nlen, (char *)v, vlen);
}

static int emi_i64(struct nats_emit *e, const char *name, int nlen,
	long long v)
{
	if (!e->cur)
		return -1;
	return add_mi_number(e->cur, (char *)name, nlen, (double)v);
}

static int emi_absent(struct nats_emit *e, const char *name, int nlen)
{
	(void)e; (void)name; (void)nlen;
	return 0;
}

static int emi_lit(struct nats_emit *e, const char *v, int vlen)
{
	(void)e; (void)v; (void)vlen;
	return 0;
}

static int emi_end(struct nats_emit *e)
{
	(void)e;
	return 0;
}

static const struct nats_emit_ops _emit_mi_ops = {
	.rec    = emi_rec,
	.str    = emi_str,
	.i64    = emi_i64,
	.absent = emi_absent,
	.lit    = emi_lit,
	.end    = emi_end,
};

int nats_emit_open_mi(struct nats_emit *e, mi_item_t *obj,
	char *arr_name, int arr_len)
{
	memset(e, 0, sizeof(*e));
	e->ops = &_emit_mi_ops;
	e->arr = add_mi_array(obj, arr_name, arr_len);
	return e->arr ? 0 : -1;
}

int nats_emit_open(struct nats_emit *e, mi_item_t *obj,
	char *arr_name, int arr_len,
	int kind, int eol_lf, int header, const char **cols, int ncols)
{
	if (kind == FMT_JSON)
		return nats_emit_open_mi(e, obj, arr_name, arr_len);
	return nats_emit_open_fmt(e, kind, eol_lf, header, cols, ncols);
}

static const char *emit_fmt_name(int kind)
{
	return kind == FMT_CSV ? "csv" : kind == FMT_TXT ? "txt" : "json";
}

int nats_emit_attach_blob(mi_item_t *obj, int kind, char *blob, int blen)
{
	const char *fn = emit_fmt_name(kind);
	int rc = -1;

	if (blob &&
	    add_mi_string(obj, MI_SSTR("format"),
			(char *)fn, (int)strlen(fn)) == 0 &&
	    add_mi_string(obj, MI_SSTR("data"), blob, blen) == 0)
		rc = 0;
	free(blob);
	return rc;
}

int nats_emit_close(struct nats_emit *e, mi_item_t *obj)
{
	char *blob;
	int blen, kind;

	if (!e->table)
		return 0;
	kind = e->t.kind;
	blob = nats_emit_take(e, &blen);
	return nats_emit_attach_blob(obj, kind, blob, blen);
}

int nats_mi_fmt_param(const mi_params_t *params,
	int *kind, int *eol_lf, int *header)
{
	str fmtp = {NULL, 0};

	*kind = FMT_JSON; *eol_lf = 0; *header = 1;
	if (try_get_mi_string_param(params, "format", &fmtp.s, &fmtp.len) == 0 &&
	    fmtp.s &&
	    cdbn_fmt_opts_parse(fmtp.s, fmtp.len, kind, eol_lf, header) < 0)
		return -1;
	return 0;
}

#endif /* !NATS_EMIT_STANDALONE */
