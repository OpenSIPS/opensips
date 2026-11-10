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
 * cachedb_nats_emit.h — the row emitter behind the MI handlers.
 * A handler walks its result set ONCE;
 * the backend picked at open time decides what a row becomes:
 *
 *   MI backend     rec() opens an object in a json array, str/i64 add named
 *                  fields, absent() omits the field, lit() is ignored.
 *   table backend  str/i64/absent/lit append csv/txt cells (names ignored --
 *                  the column header comes from open), end() ends the record.
 *
 * `absent` is the one contract that differs on purpose: a field with no
 * value is OMITTED from json but renders an EMPTY CELL in a fixed-width
 * table.  `lit` is the dual: a table-structural cell (e.g. the "scope"
 * column) that json has no use for.
 *
 * Unit-locked in test/test_emit_rows.c, which compiles this TU directly
 * (NATS_EMIT_STANDALONE drops the MI backend, whose add_mi_* calls need the
 * cJSON core; the json shapes are asserted by the sip_e2e suite instead).
 *
 * Memory/locking/context (whole TU): the table backend buffers in LIBC
 * heap (struct fmt_table, cachedb_nats_fmt.c) — NOT pkg/shm — so the
 * blob can cross into nats_emit_attach_blob()'s free() and the
 * standalone unit build; the MI backend allocates through the MI tree
 * (owned and freed by the MI framework with the response).  No locking
 * anywhere; an emitter is a single-threaded, caller-owned object.  All
 * production callers are MI handlers, so the calling context is the MI
 * process handling the command.
 */

#ifndef CACHEDB_NATS_EMIT_H
#define CACHEDB_NATS_EMIT_H

#include "cachedb_nats_fmt.h"

#ifdef NATS_EMIT_STANDALONE
typedef void mi_item_t;                  /* opaque: MI backend compiled out */
#else
#include "../../mi/mi.h"
#endif

struct nats_emit;

struct nats_emit_ops {
	int (*rec)(struct nats_emit *e);                     /* begin a row   */
	int (*str)(struct nats_emit *e, const char *name, int nlen,
		const char *v, int vlen);
	int (*i64)(struct nats_emit *e, const char *name, int nlen,
		long long v);
	int (*absent)(struct nats_emit *e, const char *name, int nlen);
	int (*lit)(struct nats_emit *e, const char *v, int vlen);
	int (*end)(struct nats_emit *e);                     /* end the row   */
};

struct nats_emit {
	const struct nats_emit_ops *ops;
	int table;                           /* 1 = table backend             */
	struct fmt_table t;                  /* table backend state           */
	mi_item_t *arr, *cur;                /* MI backend state              */
};

/**
 * Open the emitter on the TABLE backend (csv/txt): zeroes @e, installs
 * the table ops and writes the header record per the options.
 *
 * @param e       emitter to initialize (caller-owned, stack is fine).
 * @param kind    FMT_CSV or FMT_TXT.
 * @param eol_lf  0 = CRLF, 1 = LF.
 * @param header  0 drops the header record.
 * @param cols    column names for the header (borrowed for the call).
 * @param ncols   column count.
 * @return 0 ok, -1 on libc OOM (emitter safe to nats_emit_abort()).
 *
 * Ownership: the growing blob is libc heap owned by the emitter until
 * nats_emit_take()/nats_emit_close() hands it over or nats_emit_abort()
 * frees it.  Locking: none.  Context: MI process (also the standalone
 * unit-test build).
 */
int nats_emit_open_fmt(struct nats_emit *e, int kind, int eol_lf, int header,
	const char **cols, int ncols);

/**
 * Hand over the finished table blob (see fmt_take()).
 *
 * @param e        emitter (table backend).
 * @param out_len  [out, NULL-able] blob length.
 * @return the libc-malloc'd, NUL-terminated blob — the CALLER frees it
 *         with free(); NULL for the MI backend or after a table OOM
 *         (internal buffer already released).  The emitter is emptied.
 *
 * Locking: none.  Context: MI process / standalone tests.
 */
char *nats_emit_take(struct nats_emit *e, int *out_len);

/**
 * Error-path teardown: releases the table backend's libc buffer; a
 * no-op on the MI backend (the MI tree is freed with the response).
 * Safe on either backend, and after a failed open.
 *
 * @param e  emitter.
 *
 * Locking: none.  Context: MI process / standalone tests.
 */
void nats_emit_abort(struct nats_emit *e);

/* Backend dispatchers: each forwards to the op installed at open time
 * and inherits that backend's semantics (header comment above).  All
 * return 0 ok / -1 error (table: sticky libc OOM; MI: add_mi_* failure
 * — stop emitting and nats_emit_abort()).  No allocation beyond the
 * backend's own buffers, no locking; called wherever the emitter was
 * opened (MI process in production). */

/**
 * Begin a row: a new json object (MI) or a no-op (table).
 * @param e  open emitter.   @return 0 ok, -1 error.
 */
static inline int nats_emit_rec(struct nats_emit *e)
	{ return e->ops->rec(e); }

/**
 * Add a named string field (MI) / append a cell (table; name ignored).
 * @param e  open emitter.  @param name/nlen  field name (borrowed).
 * @param v/vlen  value bytes (borrowed, copied by the backend).
 * @return 0 ok, -1 error.
 */
static inline int nats_emit_str(struct nats_emit *e, const char *name,
	int nlen, const char *v, int vlen)
	{ return e->ops->str(e, name, nlen, v, vlen); }

/**
 * Add a named integer field (MI) / append a numeric cell (table).
 * @param e  open emitter.  @param name/nlen  field name (borrowed).
 * @param v  value.   @return 0 ok, -1 error.
 */
static inline int nats_emit_i64(struct nats_emit *e, const char *name,
	int nlen, long long v)
	{ return e->ops->i64(e, name, nlen, v); }

/**
 * Value-less field: OMITTED from json, an EMPTY CELL in a table.
 * @param e  open emitter.  @param name/nlen  field name (borrowed).
 * @return 0 ok, -1 error.
 */
static inline int nats_emit_absent(struct nats_emit *e, const char *name,
	int nlen)
	{ return e->ops->absent(e, name, nlen); }

/**
 * Table-structural literal cell (e.g. the "scope" column); ignored by
 * the json/MI backend.
 * @param e  open emitter.  @param v/vlen  cell bytes (borrowed).
 * @return 0 ok, -1 error.
 */
static inline int nats_emit_lit(struct nats_emit *e, const char *v, int vlen)
	{ return e->ops->lit(e, v, vlen); }

/**
 * End the row: terminates the table record with the configured EOL;
 * a no-op on the MI backend.
 * @param e  open emitter.   @return 0 ok, -1 error.
 */
static inline int nats_emit_end(struct nats_emit *e)
	{ return e->ops->end(e); }

#ifndef NATS_EMIT_STANDALONE
/**
 * Open the emitter on the MI (json) backend: rows land as objects in a
 * new @arr_name array created under @obj.
 *
 * @param e         emitter to initialize (caller-owned).
 * @param obj       parent MI item (owned by the MI response tree).
 * @param arr_name  array name (borrowed by add_mi_array).
 * @param arr_len   name length.
 * @return 0 ok, -1 when the array cannot be added (MI OOM).
 *
 * Ownership: everything emitted becomes part of the mi_response_t and
 * is freed by the MI framework with the response — the emitter itself
 * holds nothing to free.  Locking: none.  Context: MI process.
 */
int nats_emit_open_mi(struct nats_emit *e, mi_item_t *obj,
	char *arr_name, int arr_len);

/**
 * One-stop open: picks the backend from @kind (FMT_JSON -> MI backend
 * via nats_emit_open_mi; FMT_CSV/FMT_TXT -> table backend via
 * nats_emit_open_fmt).  Parameters and contract are those of the
 * selected open function.
 *
 * @return 0 ok, -1 error.
 *
 * Locking: none.  Context: MI process.
 */
int nats_emit_open(struct nats_emit *e, mi_item_t *obj,
	char *arr_name, int arr_len,
	int kind, int eol_lf, int header, const char **cols, int ncols);

/**
 * Finish the walk: the table backend attaches the blob to @obj as the
 * format+data fields (the blob is consumed and freed here, via
 * nats_emit_attach_blob); the MI backend is a no-op.
 *
 * @param e    open emitter (released either way).
 * @param obj  the MI response object to attach to.
 * @return 0 ok, -1 on OOM (table blob missing or add_mi_string failed).
 *
 * Locking: none.  Context: MI process.
 */
int nats_emit_close(struct nats_emit *e, mi_item_t *obj);

/**
 * The response shape for a pre-built table blob — for handlers
 * whose table layout is not row-shaped (nats_stream_info).  Adds
 * `format` (kind name) and `data` (@blob) strings to @obj.
 *
 * @param obj   the MI response object.
 * @param kind  enum fmt_kind (names the `format` field).
 * @param blob  libc-malloc'd table text; CONSUMED: freed with free()
 *              here on every path, success or failure.  NULL (a prior
 *              fmt_take OOM) simply yields -1.
 * @param blen  blob length.
 * @return 0 ok, -1 on NULL blob or MI OOM.
 *
 * Locking: none.  Context: MI process.
 */
int nats_emit_attach_blob(mi_item_t *obj, int kind, char *blob, int blen);

/**
 * Parse the optional trailing `format` MI parameter, one parse for all
 * handlers: "<fmt>[;eol=lf|crlf][;header=0|1]".
 *
 * @param params  the handler's MI params.
 * @param kind    [out] enum fmt_kind (default FMT_JSON when absent).
 * @param eol_lf  [out] 0 = CRLF (default), 1 = LF.
 * @param header  [out] header record on/off (default 1).
 * @return 0 ok (defaults applied when the parameter is absent), -1
 *         refused (caller answers 400).
 *
 * No allocation handed out (the param string is borrowed from the MI
 * framework).  Locking: none.  Context: MI process.
 */
int nats_mi_fmt_param(const mi_params_t *params,
	int *kind, int *eol_lf, int *header);
#endif

#endif /* CACHEDB_NATS_EMIT_H */
