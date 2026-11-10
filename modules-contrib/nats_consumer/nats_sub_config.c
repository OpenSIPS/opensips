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
 * nats_sub_config.c — pull-subscription configuration and lifecycle
 *
 * Owns the per-handle subscription state bookkeeping (g_subs entries),
 * the bind-option CSV parsers (backoff, filter subjects), enum mapping
 * to jsConsumerConfig, ensure_subscription_for_handle() (create or
 * rebuild the JetStream pull consumer for a bound handle) and the
 * registry reconcile callback driven by the consumer main loop.
 *
 * Split out of nats_consumer_proc.c (proc-TU split); cross-TU private
 * declarations live in nats_consumer_proc_internal.h.
 */

#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <stdatomic.h>
#include <sys/select.h>
#include <sys/timerfd.h>

#include <nats/nats.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../nats/nats_bind.h"
#include "../nats/nats_pool.h"
#include "../nats/nats_str.h"

#include "nats_handle_registry.h"
#include "nats_ring.h"
#include "nats_ack_ipc.h"
#include "nats_ack.h"
#include "nats_consumer_proc.h"
#include "nats_rpc_consumer.h"
#include "nats_rpc_ipc.h"
#include "nats_consumer_proc_internal.h"

/* ── enum mapping helpers ────────────────────────────────────── */

static jsDeliverPolicy map_deliver_policy(nats_deliver_policy_e p)
{
	switch (p) {
		case NATS_DELIVER_ALL:              return js_DeliverAll;
		case NATS_DELIVER_LAST:             return js_DeliverLast;
		case NATS_DELIVER_NEW:              return js_DeliverNew;
		case NATS_DELIVER_LAST_PER_SUBJECT: return js_DeliverLastPerSubject;
		case NATS_DELIVER_BY_START_SEQ:     return js_DeliverByStartSequence;
		case NATS_DELIVER_BY_START_TIME:    return js_DeliverByStartTime;
	}
	return js_DeliverAll;
}

static jsAckPolicy map_ack_policy(nats_ack_policy_e p)
{
	switch (p) {
		case NATS_ACK_EXPLICIT: return js_AckExplicit;
		case NATS_ACK_NONE:     return js_AckNone;
		case NATS_ACK_ALL:      return js_AckAll;
	}
	return js_AckExplicit;
}

static jsReplayPolicy map_replay_policy(nats_replay_policy_e p)
{
	switch (p) {
		case NATS_REPLAY_INSTANT:  return js_ReplayInstant;
		case NATS_REPLAY_ORIGINAL: return js_ReplayOriginal;
	}
	return js_ReplayInstant;
}

/* ── helpers ─────────────────────────────────────────────────── */

/* nats_str_to_cstr() was consolidated into modules-contrib/nats/nats_str.h as
 * nats_str_to_cstr().  It mallocs a process-local NUL-terminated
 * copy (nats.c wants C strings; registry str buffers are not NUL-terminated);
 * subscriptions are long-lived so the copies are kept on the proc_sub_state_t
 * and freed by the retire/reap teardown path. */

static int dup_str_local(str *dst, const str *src)
{
	dst->s = (char *)malloc((size_t)src->len);
	if (!dst->s)
		return -1;
	memcpy(dst->s, src->s, src->len);
	dst->len = src->len;
	return 0;
}

/* Match a proc-sub state by handle IDENTITY (the unique per-claim index),
 * NOT by id string.  Ids are reused on unbind+rebind, so an id match could
 * return a different (old or new) handle's sub; the index is unique among
 * live + retired-not-yet-reaped handles. */
proc_sub_state_t *find_sub_by_index(uint16_t index)
{
	proc_sub_state_t *s;
	for (s = g_subs; s; s = s->next) {
		if (s->handle_idx == index)
			return s;
	}
	return NULL;
}

/* Free all the malloc'd C-strings / arrays we stashed on ss during
 * ensure_subscription_for_handle().  nats.c's jsConsumerConfig holds
 * borrowed pointers for the life of the subscription; the retire/reap
 * teardown path calls us once the subscription is destroyed.
 *
 * Leaves ss itself alive -- caller decides whether to free the struct
 * (on full teardown) or to clear the slots for recreation (on an
 * ephemeral consumer rebuild). */
void free_proc_sub_strings(proc_sub_state_t *ss)
{
	int i;
	if (!ss)
		return;

	free(ss->c_durable);     ss->c_durable     = NULL;
	free(ss->c_filter);      ss->c_filter      = NULL;
	free(ss->c_stream);      ss->c_stream      = NULL;
	free(ss->c_domain);      ss->c_domain      = NULL;
	free(ss->c_api_prefix);  ss->c_api_prefix  = NULL;
	free(ss->c_sample_freq); ss->c_sample_freq = NULL;

	free(ss->backoff_arr);   ss->backoff_arr   = NULL;

	if (ss->filters_arr) {
		for (i = 0; i < ss->filters_arr_len; i++)
			free((void *)ss->filters_arr[i]);
		free(ss->filters_arr);
		ss->filters_arr     = NULL;
		ss->filters_arr_len = 0;
	}
}

/* ── subscription setup ──────────────────────────────────────── */

/*
 * Create a pull subscription for `h` if this process has not already
 * done so.  Succeeds idempotently: if we already have a proc_sub_state
 * for this id, returns 0 without touching the server.
 *
 * The c-string fields passed into nats.c config structs are stashed
 * on the proc_sub_state_t (see str_to_cstr comment) and freed by the
 * retire/reap teardown path when the subscription is destroyed.
 */
/* Parse a comma-separated list of durations into an allocated
 * `int64_t` array of nanoseconds.  Returns 0 on success and fills
 * `*out_arr` and `*out_len`; returns -1 on parse error.  Called only
 * when `csv` is non-empty.  The returned array is malloc'd (NOT SHM);
 * the caller owns it and should treat it as consumer-process-local
 * (freed by the retire/reap teardown path when the sub is destroyed).
 *
 * Grammar matches nats_handle_parse's duration syntax:
 *   <int>(ms|s|m|h|d), no suffix = ms.
 */
static int parse_backoff_csv(const str *csv, int64_t **out_arr, int *out_len)
{
	int64_t *arr = NULL;
	int      n = 0, cap = 0;
	const char *p = csv->s;
	const char *end = csv->s + csv->len;

	*out_arr = NULL;
	*out_len = 0;
	if (csv->len <= 0) return 0;

	while (p < end) {
		const char *tok_end;
		int tok_len;
		long long v = 0;
		int i = 0, digits = 0;
		long long mult;

		/* skip leading ws + commas */
		while (p < end && (*p == ' ' || *p == '\t' || *p == ','))
			p++;
		if (p >= end) break;

		tok_end = memchr(p, ',', end - p);
		if (!tok_end) tok_end = end;
		tok_len = (int)(tok_end - p);
		/* trim trailing ws */
		while (tok_len > 0 &&
		       (p[tok_len-1] == ' ' || p[tok_len-1] == '\t'))
			tok_len--;
		if (tok_len == 0) { p = tok_end; continue; }

		while (i < tok_len && p[i] >= '0' && p[i] <= '9') {
			v = v * 10 + (p[i] - '0');
			digits++;
			i++;
			/* clamp to keep v * mult * 1e6 within int64; INT64_MAX/1e6
			 * is ~9.2e12 ms, well past any sane backoff. */
			if (v > 9000000000000LL) { free(arr); return -1; }
		}
		if (!digits) { free(arr); return -1; }

		if (i == tok_len)                                 mult = 1LL;
		else if (i + 2 == tok_len && p[i]=='m' && p[i+1]=='s') mult = 1LL;
		else if (i + 1 == tok_len && p[i]=='s') mult = 1000LL;
		else if (i + 1 == tok_len && p[i]=='m') mult = 60LL * 1000LL;
		else if (i + 1 == tok_len && p[i]=='h') mult = 60LL*60LL*1000LL;
		else if (i + 1 == tok_len && p[i]=='d') mult = 24LL*60LL*60LL*1000LL;
		else { free(arr); return -1; }

		/* Reject if conversion to nanoseconds would overflow int64. */
		if (mult > 0 && v > INT64_MAX / mult / 1000000LL) {
			free(arr);
			return -1;
		}

		if (n == cap) {
			int newcap = cap ? cap * 2 : 8;
			int64_t *tmp = (int64_t *)realloc(arr,
				sizeof(int64_t) * (size_t)newcap);
			if (!tmp) { free(arr); return -1; }
			arr = tmp;
			cap = newcap;
		}
		arr[n++] = v * mult * 1000000LL;   /* ms -> ns */

		p = tok_end;
	}

	*out_arr = arr;
	*out_len = n;
	return 0;
}

/* Parse a comma-separated list of filter subjects into an allocated
 * `const char **` array.  Returns 0 and fills `*out_arr` + `*out_len`;
 * returns -1 on OOM.  Each element and the array are malloc'd; the
 * retire/reap teardown path frees them when the subscription is
 * destroyed. */
static int parse_filters_csv(const str *csv,
                             const char ***out_arr, int *out_len)
{
	const char **arr = NULL;
	int n = 0, cap = 0;
	const char *p = csv->s;
	const char *end = csv->s + csv->len;

	*out_arr = NULL;
	*out_len = 0;
	if (csv->len <= 0) return 0;

	while (p < end) {
		const char *tok_end;
		int tok_len;
		char *dup;

		while (p < end && (*p == ' ' || *p == '\t' || *p == ','))
			p++;
		if (p >= end) break;

		tok_end = memchr(p, ',', end - p);
		if (!tok_end) tok_end = end;
		tok_len = (int)(tok_end - p);
		while (tok_len > 0 &&
		       (p[tok_len-1] == ' ' || p[tok_len-1] == '\t'))
			tok_len--;
		if (tok_len == 0) { p = tok_end; continue; }

		dup = (char *)malloc((size_t)tok_len + 1);
		if (!dup) goto oom;
		memcpy(dup, p, tok_len);
		dup[tok_len] = '\0';

		if (n == cap) {
			int newcap = cap ? cap * 2 : 4;
			const char **tmp = (const char **)realloc(arr,
				sizeof(const char *) * (size_t)newcap);
			if (!tmp) { free(dup); goto oom; }
			arr = tmp;
			cap = newcap;
		}
		arr[n++] = dup;
		p = tok_end;
	}

	*out_arr = arr;
	*out_len = n;
	return 0;

oom:
	{
		int i;
		for (i = 0; i < n; i++) free((void *)arr[i]);
	}
	free(arr);
	return -1;
}

/* All heap allocations handed to nats.c for the life of one
 * subscription, gathered so the config-build / fail / commit paths can
 * pass them around as a unit.  On success they are stashed on the
 * proc_sub_state_t (which owns them until the retire/rebuild teardown);
 * on failure free_sub_allocs() releases the lot. */
typedef struct sub_allocs {
	char        *durable_c;
	char        *filter_c;
	char        *stream_c;
	char        *domain_c;
	char        *api_prefix_c;
	char        *sample_freq_c;
	int64_t     *backoff_arr;
	int          backoff_len;
	const char **filters_arr;
	int          filters_len;
} sub_allocs_t;

static void free_sub_allocs(sub_allocs_t *a)
{
	int i;
	for (i = 0; i < a->filters_len; i++) free((void *)a->filters_arr[i]);
	free(a->filters_arr);
	free(a->backoff_arr);
	free(a->sample_freq_c);
	free(a->domain_c);
	free(a->api_prefix_c);
	free(a->durable_c);
	free(a->filter_c);
	free(a->stream_c);
	memset(a, 0, sizeof(*a));
}

/* First-bind state construction: process-local proc_sub_state_t with a
 * local copy of the handle id (registry str buffers are SHM and not
 * NUL-terminated).  Returns NULL on allocation failure. */
static proc_sub_state_t *create_sub_state(nats_handle_t *h)
{
	proc_sub_state_t *ss;

	ss = (proc_sub_state_t *)calloc(1, sizeof(*ss));
	if (!ss) {
		LM_ERR("nats_consumer_proc: proc_sub_state calloc failed\n");
		return NULL;
	}
	if (dup_str_local(&ss->id, &h->id) < 0) {
		LM_ERR("nats_consumer_proc: id dup failed\n");
		free(ss);
		return NULL;
	}
	ss->ring       = h->ring;
	ss->handle_idx = h->index;
	ss->h_ref      = h;
	return ss;
}

	/* Pre-size the ref row so pull_one_batch doesn't pay for the
	 * first-use allocation under load.
	 *
	 * The ref-row capacity must be at least max_ack_pending: the broker
	 * may deliver that many messages before any acks come back, and
	 * each delivery occupies one ref slot until acked.  Sizing from
	 * ring_capacity alone (an earlier design) caused
	 * msg-ref-table-full drops at any handle where max_ack_pending >
	 * ring_capacity, which then triggered ack_wait redeliveries and
	 * stalled the ack floor at the broker.
	 *
	 * Take max(ring_capacity, max_ack_pending) -- ring_capacity is the
	 * worker-visible buffer; max_ack_pending is the broker's in-flight
	 * cap; the ref table needs to span the larger of the two.  When
	 * max_ack_pending is unset (0 = "unlimited"), fall back to
	 * ring_capacity. */
static int presize_msg_ref_row(nats_handle_t *h)
{
		uint32_t ref_cap = nats_ring_capacity(h->ring);
		if (h->max_ack_pending > 0 &&
		    (uint32_t)h->max_ack_pending > ref_cap)
			ref_cap = (uint32_t)h->max_ack_pending;
	if (ensure_row(h->index, ref_cap) < 0) {
		LM_ERR("nats_consumer_proc: ref-row init failed for "
			"id='%.*s'\n", h->id.len, h->id.s);
		return -1;
	}
	return 0;
}

/* Fill *cc from the full handle-config matrix, allocating the C strings
 * and arrays nats.c will borrow into *a (zeroed by the caller).  On
 * failure everything allocated so far is freed and *a stays zeroed. */
static int build_consumer_config(nats_handle_t *h, proc_sub_state_t *ss,
	int is_rebuild, jsConsumerConfig *cc, sub_allocs_t *a)
{
	char             *durable_c     = NULL;
	char             *filter_c      = NULL;
	char             *stream_c      = NULL;
	char             *sample_freq_c = NULL;
	char             *domain_c      = NULL;
	char             *api_prefix_c  = NULL;
	int64_t          *backoff_arr   = NULL;
	int               backoff_len   = 0;
	const char      **filters_arr   = NULL;
	int               filters_len   = 0;

	/* Build jsConsumerConfig with the full handle-config matrix. */
	nats_dl.jsConsumerConfig_Init(cc);

	durable_c    = nats_str_to_cstr(&h->durable);
	filter_c     = nats_str_to_cstr(&h->filter);
	stream_c     = nats_str_to_cstr(&h->stream);
	domain_c     = nats_str_to_cstr(&h->js_domain);
	api_prefix_c = nats_str_to_cstr(&h->api_prefix);

	/* `stream` is required and parser-guaranteed non-empty, so a NULL cstr
	 * here means nats_str_to_cstr hit OOM (not an empty source).  Fail the
	 * build rather than hand nats.c a NULL Stream downstream (so.Stream /
	 * js_AddConsumer would then dereference or error on it).  Likewise a
	 * durable consumer needs its durable name. */
	if (!stream_c ||
	    (h->type == NATS_CONSUMER_DURABLE && !durable_c)) {
		LM_ERR("nats_sub_config: OOM building required consumer cstr "
			"(stream%s)\n",
			(h->type == NATS_CONSUMER_DURABLE && !durable_c)
				? "/durable" : "");
		goto fail;
	}

	/* Render sample_freq as a string -- nats.c expects a C string here,
	 * e.g. "25" for 25% sampling.  Only set when the script supplied
	 * a non-zero value; zero means "disabled / don't sample".
	 *
	 * Buffer sized for any 32-bit int (max -2147483648 = 11 chars + NUL),
	 * not the validated 0..100 range, so gcc -Wformat-truncation is
	 * satisfied without relying on cross-translation-unit value tracking. */
	if (h->sample_freq > 0) {
		sample_freq_c = (char *)malloc(12);
		if (sample_freq_c)
			snprintf(sample_freq_c, 12, "%d", h->sample_freq);
	}

	if (h->type == NATS_CONSUMER_DURABLE && durable_c)
		cc->Durable = durable_c;
	if (filter_c)
		cc->FilterSubject = filter_c;

	/* Multi-filter: nats.c 3.13 exposes FilterSubjects (array) +
	 * FilterSubjectsLen.  Only honored when single-subject FilterSubject
	 * is unset -- the broker rejects the combination.  We parse the CSV
	 * at subscription time rather than keeping it pre-split in SHM so
	 * the parser output stays simple. */
	if (h->filters_csv.len > 0) {
		if (parse_filters_csv(&h->filters_csv,
				&filters_arr, &filters_len) < 0) {
			LM_ERR("nats_consumer_proc: filters= oom/parse failure "
				"for id='%.*s'\n", h->id.len, h->id.s);
			goto fail;
		}
		if (filter_c && filters_len > 0) {
			LM_WARN("nats_consumer_proc: both filter= and filters= set "
				"for id='%.*s'; ignoring multi-filter list\n",
				h->id.len, h->id.s);
		} else if (filters_len > 0) {
			cc->FilterSubjects    = filters_arr;
			cc->FilterSubjectsLen = filters_len;
		}
	}

	cc->DeliverPolicy  = map_deliver_policy(h->deliver_policy);
	cc->AckPolicy      = map_ack_policy(h->ack_policy);
	cc->ReplayPolicy   = map_replay_policy(h->replay_policy);

	/* ack_wait / max_deliver / max_ack_pending (ns vs unit-less in nats.c) */
	if (h->ack_wait_ms > 0)
		cc->AckWait = (int64_t)h->ack_wait_ms * 1000000LL;
	if (h->max_deliver > 0)
		cc->MaxDeliver = (int64_t)h->max_deliver;
	if (h->max_ack_pending > 0)
		cc->MaxAckPending = (int64_t)h->max_ack_pending;

	/* Backoff: nats.c takes int64_t[] in nanoseconds.  Drop in on top
	 * of MaxDeliver; the broker honours whichever CSV length we ship. */
	if (h->backoff_csv.len > 0) {
		if (parse_backoff_csv(&h->backoff_csv,
				&backoff_arr, &backoff_len) < 0) {
			LM_ERR("nats_consumer_proc: backoff= parse failed for "
				"id='%.*s'\n", h->id.len, h->id.s);
			goto fail;
		}
		if (backoff_len > 0) {
			cc->BackOff    = backoff_arr;
			cc->BackOffLen = backoff_len;
		}
	}

	if (h->deliver_policy == NATS_DELIVER_BY_START_SEQ)
		cc->OptStartSeq = h->start_seq;
	if (h->deliver_policy == NATS_DELIVER_BY_START_TIME)
		cc->OptStartTime = h->start_time_unix_ns;

	/* Replay-flood guard: a durable consumer that vanished (deleted server
	 * side / GC'd) and is being recreated with deliver_policy=all would
	 * otherwise replay the ENTIRE stream from sequence 1 -- a flood
	 * proportional to stream size.  If we have already delivered messages,
	 * bias the recreate to resume just past the last one instead.
	 *
	 * The watermark is only meaningful for the SAME stream incarnation:
	 * if the broker lost the stream since we last delivered (restart on
	 * memory storage, operator rm + re-create, backup restore), its
	 * sequences restart at 1 and a stale resume point would SILENTLY
	 * SKIP every new message until the sequence grows past it.  Check
	 * the incarnation (jsStreamInfo.Created) before biasing; on a
	 * mismatch drop the watermark and let the configured policy replay
	 * -- correct for a recreated stream. */
	if (is_rebuild && ss && ss->last_stream_seq > 0 &&
	    h->deliver_policy == NATS_DELIVER_ALL) {
		int64_t cur_created = 0;
		jsStreamInfo *si = NULL;

		if (nats_dl.js_GetStreamInfo(&si, g_js, stream_c, NULL,
				NULL) == NATS_OK && si) {
			cur_created = si->Created;
			nats_dl.jsStreamInfo_Destroy(si);
		}
		if (nats_rebuild_bias_stale(ss->stream_created_ns,
				cur_created)) {
			LM_WARN("nats_consumer_proc: stream '%s' is a different "
				"incarnation than the one handle '%.*s' delivered "
				"from (recreated/restored; sequences restarted) -- "
				"dropping the resume watermark (%llu) and replaying "
				"per deliver_policy\n",
				stream_c, (int)h->id.len, h->id.s,
				(unsigned long long)ss->last_stream_seq);
			ss->last_stream_seq   = 0;
			ss->stream_created_ns = 0;
		} else {
			LM_WARN("nats_consumer_proc: recreating consumer '%.*s' with "
				"deliver_policy=all would replay the whole stream; biasing "
				"to resume from stream_seq %llu\n",
				(int)h->id.len, h->id.s,
				(unsigned long long)(ss->last_stream_seq + 1));
			cc->DeliverPolicy = js_DeliverByStartSequence;
			cc->OptStartSeq   = ss->last_stream_seq + 1;
		}
	}

	/* Shaping + ephemeral options.  nats.c uses ns for InactiveThreshold. */
	if (h->inactive_threshold_ms > 0)
		cc->InactiveThreshold =
			(int64_t)h->inactive_threshold_ms * 1000000LL;
	if (h->rate_limit_bps > 0)
		cc->RateLimit = (uint64_t)h->rate_limit_bps;
	if (sample_freq_c)
		cc->SampleFrequency = sample_freq_c;
	if (h->headers_only)
		cc->HeadersOnly = true;

	if (h->replay_policy == NATS_REPLAY_ORIGINAL) {
		LM_INFO("nats_consumer_proc: id='%.*s' replay_policy=original; "
			"historical replay may introduce multi-second idle gaps "
			"between messages and is not a correctness issue\n",
			h->id.len, h->id.s);
	}

	a->durable_c     = durable_c;
	a->filter_c      = filter_c;
	a->stream_c      = stream_c;
	a->domain_c      = domain_c;
	a->api_prefix_c  = api_prefix_c;
	a->sample_freq_c = sample_freq_c;
	a->backoff_arr   = backoff_arr;
	a->backoff_len   = backoff_len;
	a->filters_arr   = filters_arr;
	a->filters_len   = filters_len;
	return 0;

fail:
	{
		int i;
		for (i = 0; i < filters_len; i++) free((void *)filters_arr[i]);
	}
	free(filters_arr);
	free(backoff_arr);
	free(sample_freq_c);
	free(domain_c);
	free(api_prefix_c);
	free(durable_c);
	free(filter_c);
	free(stream_c);
	return -1;
}

/* Create the pull subscription for *ss, working around the nats.c 3.10
 * single-subject js_PullSubscribe signature when multi-filter is in
 * play.  Returns the natsStatus of the subscribe call. */
static natsStatus pull_subscribe_with_workaround(proc_sub_state_t *ss,
	nats_handle_t *h, jsConsumerConfig *cc, jsSubOptions *so,
	jsOptions *js_opts_p, sub_allocs_t *a)
{
	natsStatus s;

	/* nats.c 3.10's js_PullSubscribe has no public multi-filter form:
	 * the public signature only takes a single `subject` string, and the
	 * library's internal _subscribeMulti validator rejects
	 *   ((numSubjects <= 0) || empty(subjects[0])) && !consBound
	 * with NATS_INVALID_ARG, even when Config.FilterSubjects is populated.
	 *
	 * Workaround: when FilterSubjects is in play we
	 *   1. js_AddConsumer up-front with the full config so the broker
	 *      materializes the multi-filter consumer (falling back to
	 *      js_UpdateConsumer if the consumer already exists with a
	 *      compatible config from a prior run);
	 *   2. flip jsSubOptions into the consBound branch (so.Stream +
	 *      so.Consumer) so js_PullSubscribe takes the "attach to existing
	 *      consumer" path instead of trying to create one from an empty
	 *      subject and a `Config.FilterSubject` it cannot use.
	 *
	 * Single-filter pull subscribe stays on the original direct path.
	 */
	if (!a->filter_c && cc->FilterSubjectsLen > 0 && a->durable_c) {
		jsConsumerInfo *ci_tmp = NULL;
		natsStatus      cs;

		cs = nats_dl.js_AddConsumer(&ci_tmp, g_js, a->stream_c, cc,
			js_opts_p, NULL);
		if (cs != NATS_OK) {
			natsStatus us;
			us = nats_dl.js_UpdateConsumer(&ci_tmp, g_js, a->stream_c, cc,
				js_opts_p, NULL);
			if (us != NATS_OK) {
				LM_ERR("nats_consumer_proc: nats_dl.js_AddConsumer('%.*s')"
					" failed: %s (update also %s)\n",
					h->id.len, h->id.s,
					nats_dl.natsStatus_GetText(cs),
					nats_dl.natsStatus_GetText(us));
				return us;
			}
		}
		if (ci_tmp)
			nats_dl.jsConsumerInfo_Destroy(ci_tmp);

		/* In the bound path nats.c does not consult so.Config; it
		 * looks up the existing consumer via Stream + Consumer. */
		so->Consumer = a->durable_c;

		s = nats_dl.js_PullSubscribe(&ss->sub, g_js,
			"" /* subject empty: bound path uses opts->Consumer */,
			NULL /* durable NULL: same reason */,
			js_opts_p,
			so,
			NULL);
	} else {
		s = nats_dl.js_PullSubscribe(&ss->sub, g_js,
			a->filter_c /* may be NULL when Config has FilterSubject */,
			a->durable_c /* may be NULL for ephemeral */,
			js_opts_p,
			so,
			NULL);
	}
	if (s != NATS_OK)
		LM_ERR("nats_consumer_proc: nats_dl.js_PullSubscribe('%.*s') failed: %s\n",
			h->id.len, h->id.s, nats_dl.natsStatus_GetText(s));
	return s;
}

int ensure_subscription_for_handle(nats_handle_t *h)
{
	proc_sub_state_t *ss;
	jsConsumerConfig  cc;
	jsSubOptions      so;
	jsOptions         js_opts;
	jsOptions        *js_opts_p = NULL;
	natsStatus        s;
	sub_allocs_t      a;
	int               is_rebuild    = 0;

	memset(&a, 0, sizeof(a));

	if (!h || !h->ring)
		return 0;   /* handle still being constructed or TEST_SHIM */

	/* Never attempt JetStream subscribe/create calls at a disconnected
	 * pool: each attempt blocks the consumer proc for a full JS
	 * request timeout per handle per reconcile tick, and racing the
	 * background first-connect mid-call crashed inside cnats
	 * (js_PullSubscribe SIGSEGV the moment the late broker arrived --
	 * test_boot_degraded_e2e).  Pending handles simply wait here; the
	 * reconnect epoch bump re-runs the reconcile against a live
	 * connection. */
	if (!nats_pool_is_connected())
		return 0;

	/* Dirty handles refresh in place -- the sub was destroyed
	 * on the epoch bump or on a fetch-time "consumer vanished" error,
	 * and we now rebuild the natsSubscription while keeping the
	 * proc_sub_state_t (and its counters) intact. */
	ss = find_sub_by_index(h->index);
	if (ss) {
		if (!ss->dirty)
			return 0;   /* clean + already subscribed */
		/* Rebuild path: free any strings we allocated last time so
		 * we can stash fresh ones below.  The old natsSubscription
		 * has already been destroyed by whoever set dirty. */
		free_proc_sub_strings(ss);
		ss->sub = NULL;
		is_rebuild = 1;
		if (h->type == NATS_CONSUMER_EPHEMERAL) {
			LM_DBG("nats_consumer_proc: re-creating ephemeral "
				"consumer for %.*s\n",
				(int)h->id.len, h->id.s);
		} else {
			LM_DBG("nats_consumer_proc: refreshing subscription for "
				"%.*s (epoch bump)\n",
				(int)h->id.len, h->id.s);
		}
	} else {
		ss = create_sub_state(h);
		if (!ss)
			return -1;
	}

	if (presize_msg_ref_row(h) < 0) {
		if (!is_rebuild) {
			free(ss->id.s);
			free(ss);
		}
		return -1;
	}

	if (build_consumer_config(h, ss, is_rebuild, &cc, &a) < 0)
		goto fail_free_sub;

	nats_dl.jsSubOptions_Init(&so);
	so.Stream    = a.stream_c;
	so.Config    = cc;
	/* We drive acks ourselves via the worker-driven ack-IPC path,
	 * not via nats.c's auto-ack. */
	so.ManualAck = true;

	/* Multi-env: when js_domain / api_prefix are set, build a per-call
	 * jsOptions and hand it to js_PullSubscribe.  nats.c uses
	 * jsOptions.Domain to route API calls to a mirror / leaf domain and
	 * jsOptions.Prefix to override the default "$JS.API" prefix when a
	 * site has a custom gateway. */
	if (a.domain_c || a.api_prefix_c) {
		nats_dl.jsOptions_Init(&js_opts);
		if (a.domain_c)     js_opts.Domain = a.domain_c;
		if (a.api_prefix_c) js_opts.Prefix = a.api_prefix_c;
		js_opts_p = &js_opts;
	}

	s = pull_subscribe_with_workaround(ss, h, &cc, &so, js_opts_p, &a);
	if (s != NATS_OK)
		goto fail_free_sub;

	ss->last_fetch = 0;
	ss->dirty      = 0;
	if (!is_rebuild) {
		ss->next = g_subs;
		g_subs = ss;
		if (ss->handle_idx < NATS_REGISTRY_MAX_HANDLES)
			g_subs_by_idx[ss->handle_idx] = ss;
	}

	/* Stash the allocations on ss so the retire / rebuild paths can
	 * free them without leaking.  nats.c has borrowed pointers into
	 * these for the life of the subscription, so they must outlive
	 * the nats_dl.natsSubscription_Destroy() call but NOT the
	 * proc_sub_state_t itself. */
	ss->c_durable       = a.durable_c;
	ss->c_filter        = a.filter_c;
	ss->c_stream        = a.stream_c;
	ss->c_domain        = a.domain_c;
	ss->c_api_prefix    = a.api_prefix_c;
	ss->c_sample_freq   = a.sample_freq_c;
	ss->backoff_arr     = a.backoff_arr;
	ss->filters_arr     = a.filters_arr;
	ss->filters_arr_len = a.filters_len;

	/* Stamp the stream incarnation the new subscription (and every
	 * delivery watermark it will advance) belongs to -- consumed by
	 * the rebuild bias above.  One extra round-trip on the cold
	 * bind/rebuild path only; 0 (unknown) on failure keeps the
	 * historical bias behavior. */
	{
		jsStreamInfo *si = NULL;

		ss->stream_created_ns = 0;
		if (nats_dl.js_GetStreamInfo(&si, g_js, a.stream_c, NULL,
				NULL) == NATS_OK && si) {
			ss->stream_created_ns = si->Created;
			nats_dl.jsStreamInfo_Destroy(si);
		}
	}

	/* Publish the subscription pointer back to the handle so MI can
	 * introspect it (read-only).  This is a process-local pointer the
	 * SIP workers must not dereference; they just observe non-NULL as
	 * "consumer process has a live sub". */
	h->subscription = (void *)ss->sub;

	LM_INFO("nats_consumer_proc: %s id='%.*s' index=%u "
		"stream='%.*s' filter='%.*s' durable='%.*s' filters_n=%d "
		"backoff_n=%d domain='%s' prefix='%s'\n",
		is_rebuild ? "refreshed" : "subscribed",
		h->id.len, h->id.s, (unsigned)h->index,
		h->stream.len, h->stream.s,
		h->filter.len, h->filter.s,
		h->durable.len, h->durable.s,
		a.filters_len, a.backoff_len,
		a.domain_c ? a.domain_c : "",
		a.api_prefix_c ? a.api_prefix_c : "");

	return 0;

fail_free_sub:
	free_sub_allocs(&a);
	/* On rebuild failure, keep the proc_sub_state_t on g_subs but
	 * leave dirty=1 so the next reconcile tick retries.  Reset any
	 * partially filled string slots (the locals were freed above, so
	 * the ss-> copies must not point at stale memory).  On first-bind
	 * failure, free the struct since it never landed on g_subs. */
	if (is_rebuild) {
		ss->c_durable     = NULL;
		ss->c_filter      = NULL;
		ss->c_stream      = NULL;
		ss->c_domain      = NULL;
		ss->c_api_prefix  = NULL;
		ss->c_sample_freq = NULL;
		ss->backoff_arr   = NULL;
		ss->filters_arr     = NULL;
		ss->filters_arr_len = 0;
		return -1;
	}
	free(ss->id.s);
	free(ss);
	return -1;
}

/* Exponential backoff for ensure_subscription_for_handle() failures.
 *
 * Capped at 60 s -- long enough that a wedged handle (e.g. broker-side
 * durable deleted by an operator) stops dominating tick CPU and log
 * noise, short enough that a transient broker outage clears within a
 * minute of recovery.  The shift on `failures` saturates harmlessly
 * once it exceeds the unsigned width, but the cap fires long before
 * that ever matters. */
#define ENSURE_BACKOFF_CAP_S 60u

static unsigned ensure_backoff_seconds(unsigned failures)
{
	unsigned shift;
	if (failures == 0)
		return 0;
	shift = failures - 1;
	if (shift >= 6)            /* 1<<6 = 64 > cap; saturate */
		return ENSURE_BACKOFF_CAP_S;
	return 1u << shift;
}

int reconcile_subs_cb(nats_handle_t *h, void *user)
{
	time_t now;
	int    rc;

	(void)user;
	/* Skip retired handles -- the teardown path owns them now.
	 * A retired handle is already off its bucket chain so registry
	 * foreach should not surface it, but defense-in-depth against a
	 * race where unbind fires between the foreach-global-lock
	 * acquisition and the bucket-lock acquisition. */
	if (__atomic_load_n(&h->retire, __ATOMIC_SEQ_CST))
		return 0;

	/* Backoff gate: a handle whose ensure_subscription_for_handle()
	 * has been failing keeps getting visited every reconcile tick,
	 * but we only actually retry once `ensure_next_retry_at` has
	 * elapsed.  Keeps a wedged handle from sucking IDLE_RETRY_MS of
	 * CPU per tick and flooding the log with the same "Error (update
	 * also Error)" line. */
	now = time(NULL);
	if (h->ensure_next_retry_at != 0 && now < h->ensure_next_retry_at)
		return 0;

	rc = ensure_subscription_for_handle(h);
	if (rc == 0) {
		/* Success or no-op (clean + already subscribed).  Either way,
		 * the broker is happy -- reset the backoff so the next failure
		 * starts at the 1 s base.  Only logs the recovery transition
		 * to avoid spamming every tick of a stable handle. */
		if (h->ensure_failures > 0) {
			LM_INFO("nats_consumer_proc: handle '%.*s' recovered after "
			        "%u failed ensure attempt(s)\n",
			        (int)h->id.len, h->id.s, h->ensure_failures);
		}
		h->ensure_failures = 0;
		h->ensure_next_retry_at = 0;
	} else {
		unsigned wait_s;
		h->ensure_failures++;
		wait_s = ensure_backoff_seconds(h->ensure_failures);
		h->ensure_next_retry_at = now + (time_t)wait_s;
		/* Log the saturation transition once so operators see when a
		 * handle has truly wedged versus when the backoff is still
		 * climbing -- the WARN at the cap is the signal to inspect or
		 * unbind. */
		if (h->ensure_failures == 7) {
			LM_WARN("nats_consumer_proc: handle '%.*s' has failed "
			        "ensure_subscription %u times; backoff now capped "
			        "at %u s.  Likely broker-side consumer was deleted; "
			        "run `nats_consumer_unbind` to clear or recreate the "
			        "durable.\n",
			        (int)h->id.len, h->id.s, h->ensure_failures,
			        ENSURE_BACKOFF_CAP_S);
		}
	}
	return 0;
}

#ifdef UNIT_TESTS
unsigned nc_ut_ensure_backoff_seconds(unsigned failures)
{
	return ensure_backoff_seconds(failures);
}

int nc_ut_build_consumer_config(nats_handle_t *h, proc_sub_state_t *ss,
	int is_rebuild, void (*inspect)(const jsConsumerConfig *cc, void *arg),
	void *arg)
{
	jsConsumerConfig cc;
	sub_allocs_t a;

	memset(&a, 0, sizeof a);
	if (build_consumer_config(h, ss, is_rebuild, &cc, &a) < 0)
		return -1;
	if (inspect)
		inspect(&cc, arg);
	free_sub_allocs(&a);
	return 0;
}
#endif
