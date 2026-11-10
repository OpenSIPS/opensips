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
 * cachedb_nats_fmt.h — the table formatter behind format=csv/txt on
 * the MI commands.  Pure: no
 * MI/NATS coupling; unit-locked in test/test_fmt_table.c.
 *
 *   csv  RFC 4180 (CRLF, header record, quote-and-double escaping)
 *   txt  TAB-separated, "# "-prefixed header, TAB/CR/LF in values -> space
 *   eol=lf switches both to bare LF; header=0 drops the header record.
 *
 * The formatted table rides as ONE string in the response's `data` field
 *; the json path never touches this TU.
 *
 * Memory/locking/context (whole TU): the buffer is LIBC heap
 * (malloc/realloc/free) — NOT pkg/shm — so the finished blob can be
 * consumed by nats_emit_attach_blob()'s free() and the TU links into
 * the standalone unit build.  OOM is sticky in t->oom: every later call
 * degrades to a no-op and fmt_take() returns NULL.  No locking; a
 * fmt_table is a single-threaded, caller-owned object.  All production
 * callers are MI handlers (MI process); any process context is safe.
 */

#ifndef CACHEDB_NATS_FMT_H
#define CACHEDB_NATS_FMT_H

enum fmt_kind { FMT_JSON = 0, FMT_CSV = 1, FMT_TXT = 2 };

struct fmt_table {
	char *buf;
	int len, cap;
	int kind;                   /* FMT_CSV / FMT_TXT only */
	int eol_lf;                 /* 0 = CRLF, 1 = LF */
	int col;                    /* current column within the record */
	int oom;
};

/**
 * Begin a table: zeroes @t and writes the header record (unless
 * @header is 0; txt headers get the "# " prefix).
 *
 * @param t       table state (caller-owned, typically stack).
 * @param kind    FMT_CSV or FMT_TXT.
 * @param eol_lf  0 = CRLF, 1 = LF.
 * @param header  0 skips the header record.
 * @param cols    NUL-terminated column names (borrowed for the call).
 * @param ncols   column count.
 * @return 0 ok, -1 on libc OOM (t->oom latched; fmt_free() is safe).
 *
 * Ownership: t->buf is libc heap owned by the table until fmt_take()
 * hands it over or fmt_free() releases it.
 */
int  fmt_init(struct fmt_table *t, int kind, int eol_lf, int header,
	const char **cols, int ncols);

/**
 * Append one string field (the column separator is handled
 * internally).  csv: RFC 4180 quote-and-double escaping when needed;
 * txt: TAB/CR/LF bytes in the value are replaced by a space.
 *
 * @param t  initialized table.
 * @param s  value bytes (borrowed; copied into the buffer).
 * @param n  value length.
 *
 * No return value: a libc OOM latches t->oom (checked by fmt_take()).
 */
void fmt_str(struct fmt_table *t, const char *s, int n);

/**
 * Append one decimal integer field (separator handled internally).
 *
 * @param t  initialized table.
 * @param v  value.
 *
 * OOM latches t->oom.
 */
void fmt_int(struct fmt_table *t, long long v);

/**
 * Append one EMPTY field (just the separator) — the table rendering of
 * an absent value.
 *
 * @param t  initialized table.
 *
 * OOM latches t->oom.
 */
void fmt_empty(struct fmt_table *t);

/**
 * Terminate the record with the configured EOL and reset the column
 * counter.
 *
 * @param t  initialized table.
 *
 * OOM latches t->oom.
 */
void fmt_end_record(struct fmt_table *t);

/**
 * Hand over the finished blob; the table resets (t->buf NULL).
 *
 * @param t        initialized table.
 * @param out_len  [out, NULL-able] blob length.
 * @return the libc-malloc'd, NUL-terminated blob — the CALLER frees it
 *         with free() (nats_emit_attach_blob() does exactly that); an
 *         empty table yields strdup("").  NULL on a latched OOM (the
 *         internal buffer is already released here).
 */
char *fmt_take(struct fmt_table *t, int *out_len);

/**
 * Error-path teardown: free the internal libc buffer (NULL-safe) and
 * reset len/cap.  Needed only when fmt_take() was never reached.
 *
 * @param t  initialized table.
 */
void  fmt_free(struct fmt_table *t);

/**
 * Map "json"/"csv"/"txt" to enum fmt_kind.
 *
 * @param v  token bytes.   @param n  token length.
 * @return the enum value, or -1 for an unknown kind.
 *
 * Pure: no allocation, no locking; any process context.
 */
int cdbn_fmt_kind_parse(const char *v, int n);

/**
 * Parse the positional format parameter:
 * "<fmt>[;eol=lf|crlf][;header=0|1]" — a bare leading kind is
 * shorthand; the "format=<fmt>" long form is accepted; unknown options
 * are refused.
 *
 * @param s       parameter bytes (empty input yields pure defaults).
 * @param len     parameter length.
 * @param kind    [out] enum fmt_kind (default FMT_JSON).
 * @param eol_lf  [out] 0 = CRLF (default), 1 = LF.
 * @param header  [out] header on/off (default 1).
 * @return 0 ok, -1 refused (outputs may hold partial results then).
 *
 * Pure: no allocation, no locking; any process context (MI process in
 * production, via nats_mi_fmt_param()).
 */
int cdbn_fmt_opts_parse(const char *s, int len,
	int *kind, int *eol_lf, int *header);

#endif /* CACHEDB_NATS_FMT_H */
