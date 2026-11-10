/*
 * Copyright (C) 2025 OpenSIPS Solutions
 * Copyright (C) 2025 Norm Brandinger <n.brandinger@gmail.com>
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
 * cachedb_nats_json_internal.h — private cross-TU declarations for the
 * JSON index / serializer / query+update translation units (the
 * proc-TU split of cachedb_nats_json.c).  Nothing here is module
 * API: modules outside cachedb_nats must use cachedb_nats_json.h.
 */

#ifndef CACHEDB_NATS_JSON_INTERNAL_H
#define CACHEDB_NATS_JSON_INTERNAL_H

#include <stdint.h>
#include <time.h>

#include "../../cachedb/cachedb.h"
#include "cachedb_nats_json.h"
#include "../../locking.h"

/* Iterative JSON scanners used to pre-validate broker-supplied bytes
 * before the recursive cJSON parser (and to walk documents in the
 * single-pass update). */

/**
 * Advance past JSON whitespace (space, TAB, LF, CR) in [p, end).
 *
 * @param p    scan position.
 * @param end  one past the last readable byte.
 * @return pointer to the first non-whitespace byte, or @end when the
 *         buffer is exhausted (never NULL).
 *
 * Pure function on caller-provided memory: no allocation, no locking;
 * callable from any process context (SIP worker, reaper proc, MI
 * handler, unit tests).
 */
const char *cdbn_skip_ws(const char *p, const char *end);

/**
 * Skip over one complete JSON value (string / object / array /
 * number / bool / null) without extracting it.  Strings are scanned
 * escape-aware; objects/arrays by brace depth (strings inside them are
 * skipped so their bytes cannot be miscounted as structure).
 *
 * @param p    position of the value's first byte (leading whitespace
 *             is skipped internally).
 * @param end  one past the last readable byte.
 * @return pointer past the value, or NULL on malformed/truncated input.
 *
 * Pure: no allocation, no locking; any process context.
 */
const char *cdbn_skip_json_value(const char *p, const char *end);

/* Per-field callback for cdbn_json_foreach_top_field: @fname/@flen
 * is the raw (still-escaped) name span, @vstart..@vend the raw value
 * span (nested structures arrive as one span).  Return 0 to continue,
 * <0 to abort the walk. */
typedef int (*json_field_cb)(const char *fname, int flen,
	const char *vstart, const char *vend, void *ud);

/**
 * Walk the top-level fields of a JSON object — the ONE field
 * iterator behind the row-mutation paths.
 *
 * Invokes @cb once per field with the raw (still-escaped) name span
 * and the raw value span; all spans point INTO @json (borrowed, valid
 * only while @json lives — nothing is allocated, nothing to free).
 *
 * @param json  document bytes (need not be NUL-terminated).
 * @param len   byte length of @json.
 * @param cb    per-field visitor (0 = continue, <0 = abort).
 * @param ud    opaque cookie handed to @cb.
 * @return 0 after a complete walk; -1 on malformed JSON, a cb abort,
 *         or bad arguments.
 *
 * Pure: no allocation, no logging, no locking; any process context.
 */
int cdbn_json_foreach_top_field(const char *json, int len,
	json_field_cb cb, void *ud);

/**
 * Parse a JSON quoted string (escape-aware).
 *
 * @p must point at the opening '"'.  Backslash escapes are honoured so
 * embedded quotes do not terminate the scan early; the escape sequences
 * are NOT decoded — the returned slice is the raw bytes between the
 * quotes, pointing into the caller's buffer.
 *
 * @param p        position of the opening quote.
 * @param end      one past the last readable byte.
 * @param out      [out] start of the raw slice (borrowed, into the
 *                 input buffer; caller frees nothing).
 * @param out_len  [out] raw byte length of the slice.
 * @return pointer past the closing quote, or NULL on malformed input
 *         (*out / *out_len unmodified in that case).
 *
 * Pure: no allocation, no locking; any process context.
 */
const char *cdbn_parse_json_string(const char *p, const char *end,
	const char **out, int *out_len);

/**
 * Depth/size-guarded JSON -> cdb_dict_t conversion.
 *
 * Pre-validates broker-supplied bytes with an iterative guard (rejects
 * nesting > 64, size > 1 MiB, and raw embedded NUL) before handing a
 * guaranteed NUL-terminated copy to the recursive cdb_json_to_dict()
 * (small documents use a stack buffer, larger ones a transient pkg
 * buffer freed internally).
 *
 * @param data      document bytes (need not be NUL-terminated).
 * @param data_len  byte length of @data.
 * @param out       [out] caller-initialized dict head; on success it
 *                  holds pkg-allocated pairs which the CALLER releases
 *                  via cdb_free_entries(out, osips_pkg_free) (or as
 *                  part of cdb_free_rows).  Untouched on rejection.
 * @return 0 on success, -1 on guard rejection or parse failure (logs
 *         a WARN/ERR).
 *
 * Locking: none.  Context: any process with a pkg pool — the SIP
 * worker read path (query) and the nats_reg_show MI handler.
 */
int cdbn_safe_json_to_dict(const char *data, int data_len, cdb_dict_t *out);

/* --- JSON sink / serializer (cachedb_nats_json_ser.c) -------------- */

typedef struct {
	char *buf;
	int   len;
	int   cap;
	int   oom;     /* sticky: once set, all subsequent ops are no-ops */
} json_sink_t;

/**
 * Initialize a JSON sink with a fresh pkg buffer.
 *
 * @param s        sink to initialize (caller-owned struct, typically
 *                 stack-allocated).
 * @param initial  initial capacity hint in bytes (floored to 16).
 * @return 0 on success; -1 on pkg OOM (s->oom set, s->buf NULL).
 *
 * Ownership: s->buf is pkg memory owned by the sink until
 * cdbn_sink_take() transfers it out; on error/abort paths the caller
 * must pkg_free(s->buf) (NULL-safe).  Locking: none; the sink is
 * strictly single-threaded.  Context: any process with a pkg pool
 * (SIP worker update path, reaper projection, rowmeta finalize).
 */
int   cdbn_sink_init(json_sink_t *s, int initial);

/**
 * Append @n raw bytes to the sink, growing the pkg buffer as needed.
 * The buffer stays NUL-terminated.  A prior OOM is sticky: the call
 * becomes a no-op returning -1.
 *
 * @param s  sink (initialized).
 * @param p  bytes to append.
 * @param n  byte count (n <= 0 appends nothing, returns 0 unless oom).
 * @return 0 on success; -1 on (sticky) pkg OOM.
 *
 * Locking: none.  Context: any process with a pkg pool.
 */
int   cdbn_sink_write(json_sink_t *s, const char *p, int n);

/**
 * Append one byte to the sink (cdbn_sink_write of length 1).
 *
 * @param s  sink (initialized).
 * @param c  byte to append.
 * @return 0 on success; -1 on (sticky) pkg OOM.
 *
 * Locking: none.  Context: any process with a pkg pool.
 */
int   cdbn_sink_putc(json_sink_t *s, char c);

/**
 * Emit a JSON string: surrounding quotes plus the RFC 8259-escaped
 * form of the raw bytes [p, p+n) (two-pass: exact escape size is
 * counted first, then written).
 *
 * @param s  sink (initialized).
 * @param p  raw (unescaped) bytes.
 * @param n  byte count.
 * @return 0 on success; -1 on pkg OOM or length overflow (oom latched).
 *
 * Locking: none.  Context: any process with a pkg pool.
 */
int   cdbn_sink_emit_string(json_sink_t *s, const char *p, int n);

/**
 * Emit a JSON string whose bytes are ALREADY escaped — a name/value
 * slice straight out of cdbn_parse_json_string() that still carries its
 * original RFC 8259 escaping.  The bytes are copied through verbatim
 * with surrounding quotes; re-escaping them via cdbn_sink_emit_string()
 * would double-escape backslashes and corrupt the output.
 *
 * @param s  sink (initialized).
 * @param p  already-escaped string bytes (no quotes).
 * @param n  byte count.
 * @return 0 on success; -1 on (sticky) pkg OOM.
 *
 * Locking: none.  Context: any process with a pkg pool.
 */
int   cdbn_sink_emit_raw_string(json_sink_t *s, const char *p, int n);

/**
 * Emit a decimal integer (INT64_MIN-safe divide loop, no printf).
 *
 * @param s  sink (initialized).
 * @param v  value to emit.
 * @return 0 on success; -1 on (sticky) pkg OOM.
 *
 * Locking: none.  Context: any process with a pkg pool.
 */
int   cdbn_sink_emit_int(json_sink_t *s, int64_t v);

/**
 * Transfer ownership of the accumulated buffer to the caller; the sink
 * resets to empty (buf NULL, len/cap 0).  On a sticky OOM the internal
 * buffer is released here and NULL is returned.
 *
 * @param s        sink (initialized).
 * @param out_len  [out, NULL-able] byte length (excluding the NUL).
 * @return the pkg-allocated, NUL-terminated buffer — the CALLER frees
 *         it with pkg_free(); NULL after OOM (nothing left to free).
 *
 * Locking: none.  Context: any process with a pkg pool.
 */
char *cdbn_sink_take(json_sink_t *s, int *out_len);

/**
 * Serialize a cdb_dict_t into JSON object text (single growable
 * buffer, no per-pair malloc churn).  Pairs are emitted in list order;
 * pair->unset entries are omitted; subkey-bearing sets emit
 * "field":{"subkey":value}.
 *
 * @param dict     dict to serialize (read-only; caller retains it).
 * @param out_len  [out, NULL-able] byte length of the result.
 * @return fresh pkg-allocated, NUL-terminated JSON text — the CALLER
 *         frees it with pkg_free(); NULL on pkg OOM or an unknown pair
 *         type (logged).
 *
 * Locking: none.  Context: SIP worker update path (nested-dict op
 * serialization); any process with a pkg pool.
 */
char *cdbn_serialize_cdb_dict(const cdb_dict_t *dict, int *out_len);

/**
 * Percent-encode arbitrary bytes into a NATS-KV-safe key ('=HH'
 * escapes).  NATS KV subject tokens reject characters outside
 * [-./_=a-zA-Z0-9]; usrloc AoRs commonly contain '@'.  Round-trippable:
 * a literal '=' becomes "=3D"; '\\' is always escaped.
 *
 * @param in       raw key bytes.
 * @param in_len   byte length of @in.
 * @param out_len  [out, NULL-able] encoded length.
 * @return fresh pkg-allocated, NUL-terminated encoded key — the CALLER
 *         frees it with pkg_free(); NULL on pkg OOM.
 *
 * Locking: none.  Context: SIP worker query/update key paths; any
 * process with a pkg pool.
 */
char *cdbn_kv_encode_key(const char *in, int in_len, int *out_len);

/**
 * Validate an encoded row key (AoR portion): reject the empty
 * key or any empty subject token (leading/trailing/double '.') that
 * would make JetStream reject the publish and silently lose the
 * REGISTER.
 *
 * @param enc      encoded key bytes (output of cdbn_kv_encode_key()).
 * @param enc_len  byte length of @enc.
 * @return 0 when the key is a valid subject, -1 to reject.
 *
 * Pure: no allocation, no locking; any process context.
 */
int cdbn_kv_key_validate(const char *enc, int enc_len);

/**
 * Build the PK target key "<fts_json_prefix>" + '=HH'-encoded @val.
 *
 * Writes into @stackbuf when the worst-case encoding fits, otherwise
 * allocates a pkg buffer — avoiding the two mallocs the PK fast path
 * would otherwise pay per usrloc read/write.
 *
 * @param val       PK value bytes (typically the AoR).
 * @param val_len   byte length of @val.
 * @param stackbuf  caller-provided buffer for the fast path.
 * @param stackcap  capacity of @stackbuf in bytes.
 * @param heap      [out] set to 1 when the result is pkg-allocated,
 *                  0 when it is @stackbuf.
 * @return the NUL-terminated key (@stackbuf or a pkg buffer), or NULL
 *         on pkg OOM.  Free with: if (*heap) pkg_free(ptr) — never
 *         free the stack-path result.
 *
 * Reads the fts_json_prefix/fts_json_prefix_len module globals (set at
 * mod_init, read-only afterwards).  Locking: none.  Context: SIP
 * worker PK read/write fast path and the nats_reg_show MI handler.
 */
char *cdbn_pk_target_key(const char *val, int val_len,
	char *stackbuf, int stackcap, int *heap);

/**
 * Build a minimal {"<field>":"<val>"} seed document for the
 * update-creates-doc (first-insert) path.  Field name and value are
 * RFC 8259 escaped; a NULL/empty @field yields "{}" so the document is
 * still a valid JSON object.
 *
 * @param field    field name bytes (NULL/empty allowed).
 * @param flen     name length.
 * @param val      value bytes (vlen 0 emits an empty string value).
 * @param vlen     value length.
 * @param out_len  [out] byte length of the result.
 * @return fresh pkg-allocated, NUL-terminated document — the CALLER
 *         frees it with pkg_free(); NULL on pkg OOM or oversize input.
 *
 * Locking: none.  Context: SIP worker update path (rev==0 create);
 * any process with a pkg pool.
 */
char *cdbn_build_seed_doc(const char *field, int flen,
	const char *val, int vlen, int *out_len);

/* --- usrloc row metadata (cachedb_nats_json_rowmeta.c) ------------- */

/**
 * 1 if any incoming contact field value
 * carries an embedded NUL (a raw 0x00 or the escaped "\u0000" cJSON would
 * decode to 0x00) at any nesting depth.  Checked before any merge /
 * kvStore op so the save is refused cleanly (no partial row); the value
 * cannot round-trip (the reader's strlen truncates it).
 *
 * @param dict  incoming update dict (read-only; recursed through nested
 *              CDB_DICT values; unset pairs skipped).  NULL yields 0.
 * @return 1 if a NUL-bearing CDB_STR value exists anywhere, else 0.
 *
 * Pure read of caller memory: no allocation, no locking; called on the
 * SIP worker update path (nats_cache_update, pre-merge).
 */
int cdbn_dict_has_nul_field(const cdb_dict_t *dict);

/**
 * The shared cdb_json_to_dict
 * clamps every JSON number to CDB_INT32, silently narrowing a `last_mod`
 * > INT32_MAX (a usrloc CDB_INT64).  Re-parse `last_mod` as int64 from
 * the raw row @json and overwrite each contact's last_mod pair in
 * @row_dict to CDB_INT64.  Only last_mod is widened (expires stays
 * int32-bounded).  No-op for a document without a top-level
 * "contacts" object, for malformed input, and for any contact whose
 * last_mod is absent / non-integer.
 *
 * @param json      the raw stored row (source of truth for the re-parse).
 * @param len       byte length of @json.
 * @param row_dict  the parsed row dict, mutated IN PLACE (pair types /
 *                  values retyped; nothing allocated or freed).
 *
 * Locking: none.  Context: read paths — SIP worker query and the
 * nats_reg_show MI handler, after cdbn_safe_json_to_dict().
 */
void cdbn_row_patch_last_mod_int64(const char *json, int len, cdb_dict_t *row_dict);

/* Classify a stored KV value on read.  An EMPTY
 * value (zero-length / all-whitespace) is a legitimate server-side delete
 * marker (absent); an OBJECT is parsed; a non-empty value that is not a JSON
 * object is POISON — a hard integrity error that must NOT be masked as an
 * empty AoR (silent deregistration). */
enum nats_val_class { NATS_VAL_EMPTY = 0, NATS_VAL_OBJECT = 1, NATS_VAL_POISON = 2 };

/**
 * Classify a stored KV value on read (see enum nats_val_class above).
 *
 * @param data  stored value bytes (NULL treated as empty).
 * @param len   byte length (<= 0 treated as empty).
 * @return NATS_VAL_EMPTY (delete marker / absent), NATS_VAL_OBJECT
 *         (first non-whitespace byte is '{'), or NATS_VAL_POISON
 *         (non-empty, not an object — hard integrity error).
 *
 * Pure: no allocation, no locking; SIP worker read path (and anywhere
 * a stored value must be vetted before parsing).
 */
int cdbn_value_classify(const char *data, int len);

/**
 * Strip the cachedb_nats-private
 * top-level peers (row_exp, schema_version) from a freshly parsed read
 * row so usrloc sees exactly {contacts, aorhash}.
 *
 * @param row_dict  parsed row dict, mutated IN PLACE (NULL is a no-op).
 *                  Each removed pair is unlinked and freed completely
 *                  (pkg memory, via osips_pkg_free — it is no longer
 *                  reachable from cdb_free_rows).
 *
 * Locking: none.  Context: SIP worker read path, at row assembly.
 */
void cdbn_row_strip_private_keys(cdb_dict_t *row_dict);

/**
 * Skew-safe write-side hygiene.  Drop
 * from the merged @json only those contacts THIS update set/unset
 * (@pairs) whose own `expires != 0 && expires + grace <= now` — never an
 * untouched merged-in contact (the drop set is built solely from @pairs,
 * so there is no collateral cross-node delete).  @grace is the max-skew
 * margin S (nats_reap_grace).
 *
 * @param json     merged row document.
 * @param len      byte length of @json.
 * @param pairs    the update's touched pairs (read-only; NULL allowed).
 * @param now      node-local current time.
 * @param grace    skew margin in seconds.
 * @param out_len  [out, NULL-able] result length.
 * @return a fresh pkg-allocated document — the CALLER frees it with
 *         pkg_free(); byte-identical copy when nothing is due; NULL on
 *         malformed input or pkg OOM.
 *
 * Locking: none.  Context: SIP worker update path, after the merge and
 * before finalize.
 */
char *cdbn_row_drop_expired_own(const char *json, int len, const cdb_dict_t *pairs,
	time_t now, int grace, int *out_len);

/**
 * Same-contact-subkey merge ordering.
 * Engages only when BOTH values carry a `cseq` (usrloc contacts);
 * otherwise returns 1 (last-writer-wins) — unchanged behavior for
 * non-usrloc subkeys / non-object values.
 *
 * @param new_json  the incoming value slice.
 * @param new_len   its length.
 * @param old_json  the existing (stored) value slice.
 * @param old_len   its length.
 * @return 1 if the NEW value supersedes the OLD (higher cseq, ties
 *         broken by higher last_mod; an exact duplicate does NOT
 *         supersede), else 0 (the stale write is discarded).
 *
 * Pure: no allocation, no locking; SIP worker update path (merge).
 */
int cdbn_cseq_new_wins(const char *new_json, int new_len,
	const char *old_json, int old_len);

/**
 * Is a serialized value of @len bytes
 * within the payload bound @max?  Checked on the final merged row
 * before the CAS write so an oversize save fails cleanly.
 *
 * @param len  serialized value length.
 * @param max  bound in bytes; <= 0 disables the guard.
 * @return 1 within bound (or guard disabled), 0 over the bound.
 *
 * Pure: no allocation, no locking; any process context.
 */
int cdbn_value_size_ok(int len, int max);

/**
 * Omit expired contacts from a parsed read
 * row before usrloc sees them — expires==0 kept (permanent),
 * expires+grace<=now omitted, absent/non-integer expires omitted
 * (fail-closed).  Pure read-side mutation, NO writes to NATS.  An
 * all-expired row keeps an empty contacts dict.
 *
 * @param row_dict  parsed row dict, mutated IN PLACE (NULL is a no-op).
 *                  Omitted contact pairs are unlinked and freed (pkg
 *                  memory, via osips_pkg_free).
 * @param now       node-local current time.
 * @param grace     visibility grace in seconds (nats_reap_grace).
 *
 * Locking: none.  Context: SIP worker read path, at row assembly.
 */
void cdbn_row_filter_expired_contacts(cdb_dict_t *row_dict, time_t now, int grace);

/**
 * Recompute the
 * cachedb_nats-private row_exp / schema_version top-level peers over the
 * merged contact set.  A usrloc row (top-level "contacts" object
 * present) gets row_exp = min of the non-zero per-contact `expires`
 * (0 if any permanent, int64, no 2038 clamp) and schema_version=1,
 * replacing any stale peers; a document with no top-level "contacts" is
 * returned byte-for-byte unchanged.
 *
 * @out_row_exp/@out_n_contacts/@out_all_same (all NULL-able) expose
 * the per-message-TTL eligibility inputs computed during finalize;
 * every early/error return leaves them at the safe "ineligible" values
 * (0/0/0).
 *
 * @param json            merged row document.
 * @param len             byte length of @json.
 * @param out_len         [out, NULL-able] result length.
 * @param out_row_exp     [out, NULL-able] recomputed row_exp.
 * @param out_n_contacts  [out, NULL-able] contact count.
 * @param out_all_same    [out, NULL-able] 1 when <=1 contact or all
 *                        contacts share one expiry.
 * @return a fresh pkg-allocated document — the CALLER frees it with
 *         pkg_free(); NULL on malformed input or pkg OOM.
 *
 * Locking: none.  Context: SIP worker update path (finalize before the
 * CAS write) and the reaper's survivor projection (stage 2, dedicated
 * reaper process).
 */
char *cdbn_row_finalize_metadata(const char *json, int len, int *out_len,
	int64_t *out_row_exp, int *out_n_contacts, int *out_all_same);

/**
 * Single-walk composition of cdbn_row_drop_expired_own
 * followed by cdbn_row_finalize_metadata(), byte-identical to running
 * the pair sequentially (locked by test/test_row_fold_equiv.c) but
 * with ONE output allocation and no intermediate document: the drop
 * filter, the row_exp/n/all_same accumulation (no expiry array), and
 * the private-peer re-emission all happen in the same emit walk.  The
 * update hot path calls this; the reaper (which has no drop set) keeps
 * calling cdbn_row_finalize_metadata().
 *
 * Parameters and out-param semantics are the union of the two folded
 * functions'; a document with no top-level "contacts" object follows
 * the reference pair exactly (verbatim copy when nothing is due,
 * rebuilt top level when a drop set exists).
 *
 * @return a fresh pkg-allocated document — the CALLER frees it with
 *         pkg_free(); NULL on malformed input or pkg OOM.
 *
 * Locking: none.  Context: SIP worker update path, before the CAS
 * write.
 */
char *cdbn_row_hygiene_finalize(const char *json, int len,
	const cdb_dict_t *pairs, time_t now, int grace, int *out_len,
	int64_t *out_row_exp, int *out_n_contacts, int *out_all_same);

/* Contact-object field parsers (rowmeta TU) shared with the reaper TU. */

/**
 * Read the int64 `expires` of one contact-object slice [vstart, vend)
 * (cdbn_contact_field_int64 for "expires").
 *
 * @param vstart  start of the contact-object slice.
 * @param vend    one past its last byte.
 * @param out     [out] the parsed value on success.
 * @return 0 + *out on success; -1 if the slice is not an object or the
 *         field is absent / not an integer.
 *
 * Pure: no allocation, no locking; any process context (rowmeta write
 * side, reaper due-checks, registration MI scan).
 */
int cdbn_contact_expires(const char *vstart, const char *vend, int64_t *out);

/**
 * Read any named int64 field of a JSON object slice [vstart, vend).
 * Integers only: a present-but-non-integer value is skipped (the scan
 * continues; fractions/exponents are rejected).
 *
 * @param vstart  start of the object slice.
 * @param vend    one past its last byte.
 * @param fname   field name bytes (raw, unescaped compare).
 * @param flen    name length.
 * @param out     [out] the parsed value on success.
 * @return 0 + *out on success; -1 if the slice is not an object or the
 *         field is absent / never integer-valued.
 *
 * Pure: no allocation, no locking; any process context (write-side
 * row_exp scan, read-side last_mod patch, reaper, MI handlers).
 */
int cdbn_contact_field_int64(const char *vstart, const char *vend,
	const char *fname, int flen, int64_t *out);

#endif /* CACHEDB_NATS_JSON_INTERNAL_H */
