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
 * nats_rpc.c -- script surface for NATS headers, reply-to, and sync
 * caller RPC:
 *     1. $nats_hdr pvar + nats_hdr_set script function.
 *     2. nats_reply (plain core publish onto the reply-to).
 *     3. nats_request (SYNC-ONLY core RPC).
 *
 * Headers (read)
 *   The ring slot carries a compact serialized header stream (see
 *   nats_ring.h).  pv_get_nats_hdr scans it lazily on each read: most
 *   messages carry a handful of headers so the O(n) scan per get is
 *   cheaper than building a hash on every fetch.  Keys compare
 *   case-insensitively per the NATS / HTTP convention.
 *
 * Headers (write)
 *   A per-worker static array g_staged[NATS_MAX_STAGED_HDRS] holds
 *   script-staged (name, value) pairs.  Both bytes are deep-copied
 *   into pkg_malloc buffers owned by the worker; later publish paths
 *   transfer them onto a natsMsg via natsMsgHeader_Set and clear the
 *   table.  Replacing an existing entry frees its old value buffer
 *   before installing the new one.
 *
 * Reply
 *   nats_reply takes the reply-to subject off the current ring slot
 *   and calls natsConnection_PublishMsg -- plain core NATS publish,
 *   not JetStream (replies are request/response affairs; the producer
 *   is a transient JetStream message but the reply hop typically
 *   targets a plain NATS subscriber).  Staged headers are attached
 *   to the outbound natsMsg; the staging table is cleared after the
 *   publish regardless of outcome so the next message starts clean.
 *
 * Request (SYNC-ONLY)
 *   nats_request is sync-only: natsConnection_RequestMsg blocks the
 *   calling worker for up to timeout_ms.  This is the correct choice
 *   for timer_route / startup_route callers where a worker stall is
 *   acceptable, but WRONG for SIP request_route on UDP/TCP workers
 *   -- calling it there stalls SIP processing for that worker until
 *   the RPC returns.  The docstring in nats_rpc.h and the script
 *   registration comment in nats_consumer.c both state this; script
 *   authors are responsible for honouring it.  A future change will
 *   add a non-blocking variant that routes the request through the
 *   dedicated consumer process.
 *
 *   On success, the reply natsMsg is unpacked into the per-worker
 *   current-message state so the script can read $nats_data /
 *   $nats_subject / $nats_hdr(...) in the continuation.  ack_token
 *   is cleared -- a core NATS reply is not JetStream-ackable -- and
 *   handle_idx is set to 0xFFFF to distinguish a synthetic reply
 *   state from a real ring-pop slot.
 */

#include <string.h>
#include <strings.h>
#include <stdio.h>

#include <nats/nats.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../pvar.h"
#include "../../sr_module.h"
#include "../nats/nats_bind.h"
#include "../nats/nats_pool.h"
#include "../nats/nats_rl.h"  /* rate-limited outage WARN */
#include "../nats/nats_validate.h"

#include "nats_fetch.h"
#include "nats_rpc.h"
#include "nats_rpc_async.h"

/* Operator-configurable outbound header name for the per-call
 * UUIDv7.  Owned by nats_consumer.c via the `request_id_header`
 * modparam; declared extern here so both the sync and async start
 * paths can read the current value at request time.  Empty /
 * NULL disables auto-staging. */
extern char *nats_request_id_header;
extern int   nats_request_id_header_len;   /* cached at mod_init */

/* ── shared helpers ──────────────────────────────────────────── */

/* Case-insensitive byte compare of two str-like inputs.  Inlined on
 * the hot path (every $nats_hdr(Name) read calls this per header in
 * the stream). */
static inline int hdr_name_eq_ci(const char *a, int alen,
                                 const char *b, int blen)
{
	int i;
	if (alen != blen) return 0;
	for (i = 0; i < alen; i++) {
		unsigned char ca = (unsigned char)a[i];
		unsigned char cb = (unsigned char)b[i];
		if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + 32);
		if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + 32);
		if (ca != cb) return 0;
	}
	return 1;
}

/* ── $nats_hdr: name parse + get ─────────────────────────────── */

/* Static pvar-name parser.  The name must be a plain literal: nested
 * $pvar(...) expansion inside $nats_hdr() is not supported yet. */
int pv_parse_nats_hdr_name(pv_spec_p sp, const str *in)
{
	if (!sp || !in || in->len <= 0 || !in->s)
		return -1;

	/* Static name -- we do NOT support dynamic expansion yet.
	 * If a caller passes $pvar(Name) they'll see the literal characters
	 * "$pvar(Name)" here because we don't parse them. */
	sp->pvp.pvn.type         = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = AVP_NAME_STR;
	sp->pvp.pvn.u.isname.name.s = *in;
	return 0;
}

/*
 * Scan the serialized header stream in `cur->slot.headers` for a name
 * matching `name` and, on hit, set `*value` to a pointer into the
 * slot's buffer.  Returns 1 on hit, 0 on miss.  The returned `value`
 * bytes live as long as the current message (i.e. until the next
 * nats_fetch / nats_fetch_clear); callers that need the value beyond
 * that must copy it.
 */
static int hdr_stream_find(const nats_cur_msg_t *cur, const str *name,
                           str *value)
{
	const char *p;
	const char *end;
	uint16_t    count;
	uint16_t    i;

	if (!cur || !cur->has_message) return 0;
	if (cur->slot.headers_len < 2)  return 0;
	if (!name || name->len <= 0)    return 0;

	p   = cur->slot.headers;
	end = p + cur->slot.headers_len;

	count = (uint16_t)((unsigned char)p[0] |
		((unsigned char)p[1] << 8));
	p += 2;

	for (i = 0; i < count && p + 2 <= end; i++) {
		uint16_t    klen;
		uint16_t    vlen;
		const char *kstart;
		const char *vstart;

		/* p + 2 <= end is the loop condition: klen is readable here */
		klen = (uint16_t)((unsigned char)p[0] |
			((unsigned char)p[1] << 8));
		p += 2;
		if (p + klen > end) return 0;
		kstart = p;
		p += klen;

		if (p + 2 > end) return 0;
		vlen = (uint16_t)((unsigned char)p[0] |
			((unsigned char)p[1] << 8));
		p += 2;
		if (p + vlen > end) return 0;
		vstart = p;
		p += vlen;

		if (hdr_name_eq_ci(kstart, klen, name->s, name->len)) {
			value->s   = (char *)vstart;
			value->len = (int)vlen;
			return 1;
		}
	}
	return 0;
}

/*
 * $nats_request_id -- writable.
 *
 * GET returns the UUIDv7 (or user-supplied value, if a write is
 * pending) of the most recent nats_request issued by this worker.
 * Persists across an async() yield so the resume route can read
 * it back for log / trace correlation.  Returns NULL when no
 * request has been issued on this worker yet AND no script
 * assignment has been made.
 *
 * SET stashes the value for the next nats_request call to consume
 * instead of minting a fresh UUIDv7.  Consume-once: the script's
 * assignment is honoured by exactly one subsequent nats_request,
 * after which the path reverts to minting unless another
 * assignment is made.  Empty / NULL value clears the pending
 * override and the last-used stash.
 *
 * Validation: value must be 1..63 bytes, no CR/LF (would break
 * NATS header serialisation).  Out-of-range values are rejected
 * with -1; the script can branch on `$retcode` after the
 * assignment if it cares (most scripts will not).
 */
int pv_set_nats_request_id(struct sip_msg *msg, pv_param_t *param,
                           int op, pv_value_t *val)
{
	int rc;
	(void)msg; (void)param; (void)op;

	if (!val || (val->flags & PV_VAL_NULL))
		return nats_rpc_async_request_id_user_set(NULL, 0);

	if (!(val->flags & PV_VAL_STR)) {
		LM_WARN("$nats_request_id: value must be a string\n");
		return -1;
	}
	rc = nats_rpc_async_request_id_user_set(val->rs.s, val->rs.len);
	if (rc < 0) {
		LM_WARN("$nats_request_id: rejecting value "
			"(over 63 bytes, embedded CR/LF, or both); the "
			"next nats_request will fall back to minting a "
			"fresh UUIDv7\n");
		return -1;
	}
	return 0;
}

int pv_get_nats_request_id(struct sip_msg *msg, pv_param_t *param,
                           pv_value_t *res)
{
	const char *id;
	int         id_len = 0;
	str         out;

	if (!res || !param) return -1;
	id = nats_rpc_async_request_id_get(&id_len);
	if (!id || id_len <= 0)
		return pv_get_null(msg, param, res);
	out.s   = (char *)id;
	out.len = id_len;
	return pv_get_strval(msg, param, res, &out);
}

int pv_get_nats_hdr(struct sip_msg *msg, pv_param_t *param,
                    pv_value_t *res)
{
	const nats_cur_msg_t *cur = nats_fetch_current();
	str                   name = {0, 0};
	str                   value = {0, 0};

	if (!res || !param) return -1;
	if (!cur || !cur->has_message) return pv_get_null(msg, param, res);

	/* Only static names are parsed (see pv_parse_nats_hdr_name). */
	if (param->pvn.type == PV_NAME_INTSTR)
		name = param->pvn.u.isname.name.s;
	else
		return pv_get_null(msg, param, res);

	if (name.len <= 0 || !name.s) return pv_get_null(msg, param, res);

	if (!hdr_stream_find(cur, &name, &value))
		return pv_get_null(msg, param, res);

	return pv_get_strval(msg, param, res, &value);
}

/* ── per-worker outbound header staging ──────────────────────── */

typedef struct nats_staged_hdr {
	str     name;    /* pkg_malloc'd, NUL-terminated */
	str     value;   /* pkg_malloc'd, NUL-terminated */
	int     in_use;
} nats_staged_hdr_t;

static nats_staged_hdr_t g_staged[NATS_MAX_STAGED_HDRS];

/* Free a staged entry's buffers and mark it free.  Safe on already-
 * free entries (no-op when in_use == 0). */
static void staged_free_entry(nats_staged_hdr_t *e)
{
	if (!e) return;
	if (e->name.s)  pkg_free(e->name.s);
	if (e->value.s) pkg_free(e->value.s);
	e->name.s = NULL;   e->name.len  = 0;
	e->value.s = NULL;  e->value.len = 0;
	e->in_use = 0;
}

void nats_rpc_staged_clear(void)
{
	int i;
	for (i = 0; i < NATS_MAX_STAGED_HDRS; i++)
		staged_free_entry(&g_staged[i]);
}

/* pkg-alloc a NUL-terminated copy of `src` and stash in `dst`. */
static int staged_dup(str *dst, const str *src)
{
	char *p;
	if (!dst || !src || src->len < 0) return -1;
	p = (char *)pkg_malloc((size_t)src->len + 1);
	if (!p) return -1;
	if (src->len > 0 && src->s) memcpy(p, src->s, src->len);
	p[src->len] = '\0';
	dst->s   = p;
	dst->len = src->len;
	return 0;
}

/*
 * Script entry point: stage a header onto the worker's outbound
 * buffer.  Replaces an existing entry with the same name (case-
 * insensitive -- matches the read-side behavior of $nats_hdr).
 * Returns 1 on success, -1 on OOM or full table (and DBGs why).
 */
int w_nats_hdr_set(struct sip_msg *msg, str *name, str *value)
{
	int i, free_slot = -1;
	str empty = { NULL, 0 };
	str *v = value ? value : &empty;

	(void)msg;

	if (!name || name->len <= 0 || !name->s) {
		LM_DBG("nats_hdr_set: empty/null name\n");
		return -1;
	}

	/* First pass: replace an existing entry (case-insensitive) and
	 * also note the first free slot for the fall-through branch. */
	for (i = 0; i < NATS_MAX_STAGED_HDRS; i++) {
		if (!g_staged[i].in_use) {
			if (free_slot < 0) free_slot = i;
			continue;
		}
		if (hdr_name_eq_ci(g_staged[i].name.s, g_staged[i].name.len,
				name->s, name->len)) {
			str new_val = {0, 0};
			if (staged_dup(&new_val, v) < 0) {
				LM_ERR("nats_hdr_set: pkg_malloc failed for value\n");
				return -1;
			}
			if (g_staged[i].value.s) pkg_free(g_staged[i].value.s);
			g_staged[i].value = new_val;
			return 1;
		}
	}

	if (free_slot < 0) {
		LM_WARN("nats_hdr_set: staged-header table full "
			"(cap=%d); dropping '%.*s'\n",
			NATS_MAX_STAGED_HDRS, name->len, name->s);
		return -1;
	}

	if (staged_dup(&g_staged[free_slot].name,  name) < 0 ||
	    staged_dup(&g_staged[free_slot].value, v) < 0) {
		staged_free_entry(&g_staged[free_slot]);
		LM_ERR("nats_hdr_set: pkg_malloc failed for header "
			"'%.*s'\n", name->len, name->s);
		return -1;
	}
	g_staged[free_slot].in_use = 1;
	return 1;
}

/*
 * Internal variant of w_nats_hdr_set used by the request_id
 * auto-stager: skip the header entirely if the script has
 * already staged a value for the same (case-insensitive) name.
 * Lets a deliberate `nats_hdr_set("X-Request-Id", ...)` in the
 * script win over the auto-mint.
 *
 * Returns 1 if the header was newly staged, 0 if an existing
 * stage was preserved, -1 on OOM / full table.
 */
int nats_rpc_staged_set_if_absent(const str *name, const str *value)
{
	int i, free_slot = -1;

	if (!name || name->len <= 0 || !name->s) return -1;

	for (i = 0; i < NATS_MAX_STAGED_HDRS; i++) {
		if (!g_staged[i].in_use) {
			if (free_slot < 0) free_slot = i;
			continue;
		}
		if (hdr_name_eq_ci(g_staged[i].name.s, g_staged[i].name.len,
				name->s, name->len)) {
			return 0;   /* already staged; leave the script's value alone */
		}
	}

	if (free_slot < 0) {
		LM_WARN("nats_rpc_staged_set_if_absent: staged-header "
			"table full (cap=%d); dropping '%.*s'\n",
			NATS_MAX_STAGED_HDRS, name->len, name->s);
		return -1;
	}

	{
		str empty = { NULL, 0 };
		const str *v = value ? value : &empty;
		if (staged_dup(&g_staged[free_slot].name,  name) < 0 ||
		    staged_dup(&g_staged[free_slot].value, v) < 0) {
			staged_free_entry(&g_staged[free_slot]);
			return -1;
		}
	}
	g_staged[free_slot].in_use = 1;
	return 1;
}

/* ── publish helpers ─────────────────────────────────────────── */

/* Apply every staged header onto `out` and clear the staging table
 * regardless of publish outcome.  The caller keeps ownership of `out`.
 */
void nats_rpc_staged_apply_and_clear_on(natsMsg *out)
{
	int i;
	if (!out) {
		/* Still clear so the next publish starts with an empty stage. */
		nats_rpc_staged_clear();
		return;
	}
	for (i = 0; i < NATS_MAX_STAGED_HDRS; i++) {
		if (!g_staged[i].in_use) continue;
		if (!g_staged[i].name.s) continue;
		/* natsMsgHeader_Set requires NUL-terminated keys/values;
		 * staged_dup appends a NUL past .len.  natsMsg stores a
		 * copy of the bytes internally so our pkg buffers can be
		 * freed right after. */
		(void)nats_dl.natsMsgHeader_Set(out,
			g_staged[i].name.s,
			g_staged[i].value.s ? g_staged[i].value.s : "");
	}
	nats_rpc_staged_clear();
}

/*
 * Serialize the staged-header table into the compact wire format
 * documented in nats_rpc.h / nats_ring.h.  Used by the async
 * nats_request worker side to embed staged headers into the SHM
 * slot's out_headers buffer; the consumer process deserializes via
 * nats_rpc_hdr_deserialize_to_msg() before publishing.
 *
 * Does NOT clear the staging table -- callers that own the publish
 * lifecycle (w_nats_request_async) call nats_rpc_staged_clear()
 * after the slot is fully published so a mid-flight failure does
 * not leak staged state into the next call.
 */
int nats_rpc_staged_serialize(char *out, int cap,
                              int *truncated, int *count_out)
{
	int i;
	int pos = 2;             /* reserve count prefix */
	int count = 0;
	int trunc = 0;

	if (truncated) *truncated = 0;
	if (count_out) *count_out = 0;
	if (!out || cap < 2) return 0;

	for (i = 0; i < NATS_MAX_STAGED_HDRS; i++) {
		int klen, vlen, need;
		const char *kbytes, *vbytes;

		if (!g_staged[i].in_use) continue;
		if (!g_staged[i].name.s) continue;

		klen = g_staged[i].name.len;
		vlen = g_staged[i].value.len;
		if (klen <= 0 || klen > 0xFFFF) continue;
		if (vlen < 0  || vlen > 0xFFFF) continue;

		need = 2 + klen + 2 + vlen;
		if (pos + need > cap) { trunc = 1; break; }

		kbytes = g_staged[i].name.s;
		vbytes = g_staged[i].value.s;

		out[pos++] = (char)(klen & 0xFF);
		out[pos++] = (char)((klen >> 8) & 0xFF);
		memcpy(out + pos, kbytes, (size_t)klen);
		pos += klen;
		out[pos++] = (char)(vlen & 0xFF);
		out[pos++] = (char)((vlen >> 8) & 0xFF);
		if (vlen > 0 && vbytes) memcpy(out + pos, vbytes, (size_t)vlen);
		pos += vlen;

		count++;
		if (count >= 0xFFFF) { trunc = 1; break; }
	}

	out[0] = (char)(count & 0xFF);
	out[1] = (char)((count >> 8) & 0xFF);
	if (truncated) *truncated = trunc;
	if (count_out) *count_out = count;
	return pos;
}

/*
 * Parse the compact wire-format header stream and apply each
 * (name, value) pair onto a libnats natsMsg via natsMsgHeader_Set.
 *
 * Format (little-endian length prefixes -- see nats_rpc.h):
 *   [count:2][ (klen:2)(key)(vlen:2)(value) ] * count
 *
 * `msg_void` is the natsMsg pointer cast through void* in the
 * public signature so callers don't need <nats/nats.h>.
 *
 * Returns the number of headers successfully applied.  Returns -1
 * if the byte stream is malformed (length prefix runs past the end
 * of the buffer); whatever was applied before the truncation point
 * remains on the msg.  An empty stream (count == 0) returns 0
 * without touching the msg.
 */
int nats_rpc_hdr_deserialize_to_msg(const char *buf, int len, void *msg_void)
{
	natsMsg *out = (natsMsg *)msg_void;
	int      pos = 0;
	int      count;
	int      i;
	int      applied = 0;
	/* Per-pair name + value land on the stack: bounded by the
	 * 16-bit klen / vlen wire limits, but in practice headers
	 * are tiny.  Use a small bounded buffer; oversize names or
	 * values are skipped rather than truncated. */
	char     kbuf[512];
	char     vbuf[2048];
	int      klen, vlen;

	if (!buf || len < 2 || !out) return 0;

	count = (unsigned char)buf[0] | ((unsigned char)buf[1] << 8);
	pos = 2;

	for (i = 0; i < count; i++) {
		if (pos + 2 > len) return -1;
		klen = (unsigned char)buf[pos] |
		       ((unsigned char)buf[pos + 1] << 8);
		pos += 2;
		if (klen < 0 || pos + klen > len) return -1;

		if (klen > 0 && klen < (int)sizeof(kbuf)) {
			memcpy(kbuf, buf + pos, (size_t)klen);
			kbuf[klen] = '\0';
		} else {
			/* Skip: empty or oversize name. */
			kbuf[0] = '\0';
		}
		pos += klen;

		if (pos + 2 > len) return -1;
		vlen = (unsigned char)buf[pos] |
		       ((unsigned char)buf[pos + 1] << 8);
		pos += 2;
		if (vlen < 0 || pos + vlen > len) return -1;

		if (vlen >= 0 && vlen < (int)sizeof(vbuf)) {
			if (vlen > 0) memcpy(vbuf, buf + pos, (size_t)vlen);
			vbuf[vlen] = '\0';
		} else {
			/* Skip: oversize value. */
			vbuf[0] = '\0';
		}
		pos += vlen;

		if (kbuf[0] == '\0') continue;
		if (nats_dl.natsMsgHeader_Set(out, kbuf, vbuf) == NATS_OK)
			applied++;
	}

	return applied;
}

/* Render a nats_cur subject (raw, possibly not NUL-terminated) into a
 * stack buffer with NUL termination, and return the pointer.  Returns
 * NULL on overflow (must not happen since slot.reply_to_len is bounded
 * by NATS_RING_SUBJECT_MAX). */
const char *nats_rpc_cstr_buf(char *buf, size_t cap, const char *src, int len)
{
	if (!src || len <= 0) return "";
	if ((size_t)len + 1 > cap) return NULL;
	memcpy(buf, src, len);
	buf[len] = '\0';
	return buf;
}

/* ── nats_reply ──────────────────────────────────────────────── */

int w_nats_reply(struct sip_msg *msg, str *payload)
{
	const nats_cur_msg_t *cur = nats_fetch_current();
	natsConnection       *nc;
	natsMsg              *out = NULL;
	natsStatus            s;
	char                  subj_buf[NATS_RING_SUBJECT_MAX + 1];
	const char           *subj_c;
	const char           *data_s;
	int                   data_len;

	(void)msg;

	if (!cur || !cur->has_message) {
		LM_DBG("nats_reply: no current message\n");
		return -1;
	}
	if (!cur->slot.has_reply || cur->slot.reply_to_len == 0) {
		LM_DBG("nats_reply: current message has no reply-to\n");
		nats_rpc_staged_clear();   /* don't leak stage across retries */
		return -2;
	}

	nc = nats_pool_get();
	if (!nc) {
		LM_ERR("nats_reply: no NATS connection\n");
		nats_rpc_staged_clear();
		return -3;
	}

	subj_c = nats_rpc_cstr_buf(subj_buf, sizeof(subj_buf),
		cur->slot.reply_to, (int)cur->slot.reply_to_len);
	if (!subj_c) {
		/* Should never happen: reply_to_len is bounded. */
		LM_ERR("nats_reply: reply_to overflow (%u bytes)\n",
			(unsigned)cur->slot.reply_to_len);
		nats_rpc_staged_clear();
		return -3;
	}

	/* The reply-to came from the inbound (broker-supplied) message; reject
	 * CR/LF, whitespace and wildcards before publishing onto the wire. */
	if (nats_validate_publish_subject(cur->slot.reply_to,
			(int)cur->slot.reply_to_len) < 0) {
		LM_ERR("nats_reply: invalid reply-to subject (control/whitespace/"
			"wildcard rejected)\n");
		nats_rpc_staged_clear();
		return -4;
	}

	data_s   = (payload && payload->s)   ? payload->s   : "";
	data_len = (payload && payload->len > 0) ? payload->len : 0;

	s = nats_dl.natsMsg_Create(&out, subj_c, NULL /* no reply-of-reply */,
		data_s, data_len);
	if (s != NATS_OK || !out) {
		LM_ERR("nats_reply: natsMsg_Create failed: %s\n",
			nats_dl.natsStatus_GetText(s));
		nats_rpc_staged_clear();
		return -4;
	}

	nats_rpc_staged_apply_and_clear_on(out);

	s = nats_dl.natsConnection_PublishMsg(nc, out);
	nats_dl.natsMsg_Destroy(out);

	if (s != NATS_OK) {
		LM_ERR("nats_reply: publish to '%s' failed: %s\n",
			subj_c, nats_dl.natsStatus_GetText(s));
		return -4;
	}
	return 1;
}

/* ── nats_request (sync-only) ────────────────────────────────── */

/*
 * Serialize the reply natsMsg's headers into the ring-slot header
 * stream format so the script's $nats_hdr(...) getter reads them
 * transparently after the RPC resumes.  Uses the same format as
 * nats_consumer_proc's serialize_headers(); kept separate here
 * rather than shared to avoid a public dependency on the consumer
 * process's internals.
 */
int nats_rpc_hdr_serialize_from_reply(natsMsg *m, char *out, int cap,
                                       int *truncated, int *count_out)
{
	const char * *keys = NULL;
	int nkeys = 0;
	natsStatus s;
	int pos;
	int count = 0;
	int trunc = 0;
	int i;

	*truncated = 0;
	*count_out = 0;
	if (!m || !out || cap < 2) return 0;

	pos = 2;   /* reserve count prefix */

	s = nats_dl.natsMsgHeader_Keys(m, &keys, &nkeys);
	if (s != NATS_OK || !keys || nkeys <= 0) {
		out[0] = 0; out[1] = 0;
		if (keys) free((void *)keys);
		return 2;
	}

	for (i = 0; i < nkeys; i++) {
		const char * *vals = NULL;
		int nvals = 0;
		natsStatus vs;
		int j;
		int klen;

		if (!keys[i]) continue;
		klen = (int)strlen(keys[i]);
		if (klen <= 0 || klen > 0xFFFF) continue;

		vs = nats_dl.natsMsgHeader_Values(m, keys[i], &vals, &nvals);
		if (vs != NATS_OK || !vals || nvals <= 0) {
			if (vals) free((void *)vals);
			continue;
		}
		for (j = 0; j < nvals; j++) {
			int vlen;
			int need;

			if (!vals[j]) continue;
			vlen = (int)strlen(vals[j]);
			if (vlen < 0 || vlen > 0xFFFF) continue;
			need = 2 + klen + 2 + vlen;
			if (pos + need > cap) { trunc = 1; goto done; }
			out[pos++] = (char)(klen & 0xFF);
			out[pos++] = (char)((klen >> 8) & 0xFF);
			memcpy(out + pos, keys[i], klen); pos += klen;
			out[pos++] = (char)(vlen & 0xFF);
			out[pos++] = (char)((vlen >> 8) & 0xFF);
			if (vlen) memcpy(out + pos, vals[j], vlen);
			pos += vlen;
			count++;
			if (count >= 0xFFFF) { trunc = 1; goto done; }
		}
done:
		free((void *)vals);
		if (trunc) break;
	}

	free((void *)keys);
	out[0] = (char)(count & 0xFF);
	out[1] = (char)((count >> 8) & 0xFF);
	*truncated = trunc;
	*count_out = count;
	return pos;
}

/*
 * Populate g_cur from a reply natsMsg so the script can read
 * $nats_data / $nats_subject / $nats_hdr(...) after the RPC returns.
 * We reuse the ring-slot layout by copying fields into the current-
 * message slot directly -- no ring push needed because no worker other
 * than the caller needs to see this message.
 *
 * Limitations of the reply-state handoff:
 *   - jsMsgMetaData is absent on core NATS replies; broker-metadata
 *     fields stay zero.
 *   - ack_token is cleared -- the reply is not a JetStream-ackable
 *     message.
 *   - handle_idx is set to 0xFFFF as a synthetic marker.
 */
void nats_rpc_cur_set_from_nats_reply(natsMsg *reply)
{
	nats_cur_msg_t  *cur = nats_fetch_current();
	const char      *subject;
	const char      *data;
	int              data_len;
	size_t           slen;
	int              hdr_len;
	int              hdr_trunc = 0;
	int              hdr_count = 0;

	memset(cur, 0, sizeof(*cur));
	if (!reply) return;

	cur->has_message = 1;
	cur->handle_idx  = 0xFFFF;   /* synthetic -- not tied to a handle */
	cur->ack_token   = 0;

	subject  = nats_dl.natsMsg_GetSubject(reply);
	data     = nats_dl.natsMsg_GetData(reply);
	data_len = nats_dl.natsMsg_GetDataLength(reply);
	slen     = subject ? strlen(subject) : 0;

	if (slen > NATS_RING_SUBJECT_MAX) slen = NATS_RING_SUBJECT_MAX;
	if (slen > 0 && subject)
		memcpy(cur->slot.subject, subject, slen);
	cur->slot.subject_len = (uint32_t)slen;

	if (data_len < 0) data_len = 0;
	if (data_len > NATS_RING_PAYLOAD_MAX) data_len = NATS_RING_PAYLOAD_MAX;
	if (data_len > 0 && data) memcpy(cur->slot.data, data, data_len);
	cur->slot.data_len = (uint32_t)data_len;

	cur->slot.has_reply    = 0;
	cur->slot.reply_to_len = 0;

	hdr_len = nats_rpc_hdr_serialize_from_reply(reply,
		cur->slot.headers, NATS_RING_HEADERS_MAX,
		&hdr_trunc, &hdr_count);
	cur->slot.headers_len       = (uint16_t)(hdr_len > 0 ? hdr_len : 0);
	cur->slot.headers_truncated = (uint8_t)(hdr_trunc ? 1 : 0);
}

/*
 * Plain-buffer variant of cur_set_from_nats_reply().  Mirrors the
 * natsMsg-driven version above but reads the reply fields out of
 * caller-supplied byte buffers; used by the async path, where the
 * natsMsg has already been destroyed back in the libnats callback
 * and the buffers were stashed in the in-flight ctx instead.
 */
void nats_rpc_cur_set_from_buffers(const nats_rpc_reply_view_t *rv)
{
	nats_cur_msg_t *cur = nats_fetch_current();
	uint32_t handle_idx = rv->handle_idx;
	const char *subject = rv->subject;   uint32_t slen = rv->subject_len;
	const char *data = rv->data;         uint32_t dlen = rv->data_len;
	const char *reply_to = rv->reply_to; uint32_t rlen = rv->reply_to_len;
	uint8_t has_reply = rv->has_reply;
	const char *headers = rv->headers;   uint16_t hlen = rv->headers_len;
	uint8_t hdr_truncated = rv->headers_truncated;

	memset(cur, 0, sizeof(*cur));
	cur->has_message = 1;
	cur->handle_idx  = handle_idx;
	cur->ack_token   = 0;

	if (slen > NATS_RING_SUBJECT_MAX) slen = NATS_RING_SUBJECT_MAX;
	if (slen > 0 && subject) memcpy(cur->slot.subject, subject, slen);
	cur->slot.subject_len = slen;

	if (dlen > NATS_RING_PAYLOAD_MAX) dlen = NATS_RING_PAYLOAD_MAX;
	if (dlen > 0 && data) memcpy(cur->slot.data, data, dlen);
	cur->slot.data_len = dlen;

	if (has_reply && reply_to && rlen > 0) {
		if (rlen > NATS_RING_SUBJECT_MAX) rlen = NATS_RING_SUBJECT_MAX;
		memcpy(cur->slot.reply_to, reply_to, rlen);
		cur->slot.reply_to_len = rlen;
		cur->slot.has_reply    = 1;
	}

	if (hlen > NATS_RING_HEADERS_MAX) hlen = NATS_RING_HEADERS_MAX;
	if (hlen > 0 && headers) memcpy(cur->slot.headers, headers, hlen);
	cur->slot.headers_len       = hlen;
	cur->slot.headers_truncated = hdr_truncated;
}

/*
 * Script-callable synchronous NATS request/reply.
 *
 * ### SYNC-ONLY -- BLOCKS THE CALLING WORKER ###
 *
 * natsConnection_RequestMsg blocks for up to timeout_ms.  Callers MUST
 * restrict this function to timer_route / startup_route (or another
 * context that tolerates blocking a worker for the full timeout).
 * Calling from a UDP/TCP SIP request_route stalls that worker's entire
 * SIP pipeline until the RPC returns -- avoid.  A non-blocking async
 * variant exists: async(nats_request(...)) dispatches to
 * w_nats_request_async, which routes the publish/reply through the
 * consumer process (the only libnats-safe context) and yields the
 * worker on a per-call private timerfd.  See nats_rpc_async.c.
 *
 * The function clears the per-worker staged-header table on every
 * exit path so a timeout does not leak stage bytes into the next
 * publish.
 */
int w_nats_request(struct sip_msg *msg, str *subject, str *payload,
                   int *timeout_ms)
{
	natsConnection *nc;
	natsMsg        *out   = NULL;
	natsMsg        *reply = NULL;
	natsStatus      s;
	char            subj_buf[NATS_RING_SUBJECT_MAX + 1];
	const char     *subj_c;
	int             tmo;
	const char     *data_s;
	int             data_len;

	(void)msg;

	if (!subject || subject->len <= 0 || !subject->s) {
		LM_DBG("nats_request: empty/null subject\n");
		nats_rpc_staged_clear();
		return -4;
	}
	if (subject->len > NATS_RING_SUBJECT_MAX) {
		LM_ERR("nats_request: subject too long (%d > %d)\n",
			subject->len, NATS_RING_SUBJECT_MAX);
		nats_rpc_staged_clear();
		return -4;
	}
	/* Reject CR/LF, whitespace and wildcards before the subject reaches
	 * the line-oriented NATS wire (protocol-injection guard). */
	if (nats_validate_publish_subject(subject->s, subject->len) < 0) {
		LM_ERR("nats_request: invalid subject '%.*s' (control/whitespace/"
			"wildcard rejected)\n", subject->len, subject->s);
		nats_rpc_staged_clear();
		return -4;
	}

	tmo = timeout_ms ? *timeout_ms : 0;
	if (tmo <= 0) {
		LM_DBG("nats_request: non-positive timeout %d; using 1000 ms\n", tmo);
		tmo = 1000;
	}

	nc = nats_pool_get();
	if (!nc) {
		LM_ERR("nats_request: no NATS connection\n");
		nats_rpc_staged_clear();
		return -3;
	}
	/* Fast-fail on a disconnected pool: natsConnection_RequestMsg on a
	 * reconnecting connection cannot succeed (no reply can arrive) and
	 * would block THIS process -- a timer/event route, per the route
	 * restriction -- for the full timeout_ms.  Mirror w_nats_fetch's
	 * disconnected fast-fail instead. */
	if (!nats_pool_is_connected()) {
		/* rate-limited WARN + per-call DBG: during an outage
		 * this fires per request per worker -- the old per-call WARN
		 * flooded the log at exactly the moment the box was unhappy. */
		static time_t rl_disc;
		if (nats_rl_pass(&rl_disc, time(NULL), 30))
			LM_WARN("nats_request: NATS disconnected; failing fast "
				"instead of blocking %d ms (repeats suppressed "
				"for 30s)\n", tmo);
		LM_DBG("nats_request: NATS disconnected; failing fast\n");
		nats_rpc_staged_clear();
		return -3;
	}

	subj_c = nats_rpc_cstr_buf(subj_buf, sizeof(subj_buf), subject->s, subject->len);
	if (!subj_c) {
		nats_rpc_staged_clear();
		return -4;
	}

	data_s   = (payload && payload->s) ? payload->s : "";
	data_len = (payload && payload->len > 0) ? payload->len : 0;

	/* Pick the correlation id: prefer a user-supplied value
	 * from a prior `$nats_request_id = "..."` assignment, else
	 * mint a fresh UUIDv7.  Stash for $nats_request_id and stage
	 * the operator-configured outbound header unless the script
	 * already set it explicitly via nats_hdr_set(). */
	{
		char id_buf[64];
		int  id_len;
		id_len = nats_rpc_async_request_id_consume_user(id_buf,
			sizeof(id_buf));
		if (id_len == 0)
			id_len = nats_rpc_async_uuidv7_mint(id_buf, sizeof(id_buf));
		if (id_len > 0) {
			nats_rpc_async_request_id_set(id_buf, id_len);
			if (nats_request_id_header && nats_request_id_header[0]) {
				str hname = { nats_request_id_header,
					nats_request_id_header_len };
				str hval  = { id_buf, id_len };
				(void)nats_rpc_staged_set_if_absent(&hname, &hval);
			}
		}
	}

	/* Build an outbound natsMsg so we can carry staged headers onto
	 * the request.  natsConnection_RequestMsg uses the msg's subject,
	 * headers and payload.  We construct with reply=NULL; nats.c
	 * assigns a private inbox internally. */
	s = nats_dl.natsMsg_Create(&out, subj_c, NULL, data_s, data_len);
	if (s != NATS_OK || !out) {
		LM_ERR("nats_request: natsMsg_Create failed: %s\n",
			nats_dl.natsStatus_GetText(s));
		nats_rpc_staged_clear();
		return -4;
	}

	nats_rpc_staged_apply_and_clear_on(out);

	/* SYNC RPC: blocks this worker until reply arrives or timeout. */
	s = nats_dl.natsConnection_RequestMsg(&reply, nc, out, (int64_t)tmo);
	nats_dl.natsMsg_Destroy(out);

	if (s == NATS_TIMEOUT) {
		LM_DBG("nats_request: timeout waiting for reply on '%s' "
			"after %d ms\n", subj_c, tmo);
		/* -1, not 0: returning 0 from a script-callable cmd
		 * sets ACT_FL_EXIT in run_action_list and silently
		 * terminates the calling route. */
		return -1;
	}
	if (s != NATS_OK || !reply) {
		LM_ERR("nats_request: request on '%s' failed: %s\n",
			subj_c, nats_dl.natsStatus_GetText(s));
		if (reply) nats_dl.natsMsg_Destroy(reply);
		return -4;
	}

	/* Install the reply into the per-worker current-message state
	 * so the script can read $nats_data etc. after this returns. */
	nats_rpc_cur_set_from_nats_reply(reply);
	nats_dl.natsMsg_Destroy(reply);
	return 1;
}
