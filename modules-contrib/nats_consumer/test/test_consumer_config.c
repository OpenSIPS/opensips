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
 *
 * The consumer config the subscribe path builds (build_consumer_config()
 * in nats_sub_config.c), driven with a parsed handle and a fake libnats.
 * Replaces tests/test_replay_bias.c (a carried copy of the recreate bias
 * plus greps) and tests/test_rebuild_bias_stale.c (the incarnation check
 * plus greps): both are asserted here on the real build.
 *
 * A durable consumer that is recreated with deliver_policy=all would
 * replay the whole stream, so a rebuild that has delivered resumes just
 * past the last sequence it delivered -- but only from the same stream
 * incarnation (jsStreamInfo.Created): a recreated stream restarts its
 * sequences, and the stale resume point would skip every new message.
 */

#include <tap.h>
#include <stdlib.h>
#include <string.h>

#include "../nats_handle_registry.h"
#include "../nats_handle_parse.h"
#include "../nats_consumer_proc_internal.h"

#include "nc_ut.h"

/* what a scenario's config said */
struct seen {
	int called;
	jsDeliverPolicy deliver;
	uint64_t start_seq;
};

static void inspect(const jsConsumerConfig *cc, void *arg)
{
	struct seen *s = arg;

	s->called = 1;
	s->deliver = cc->DeliverPolicy;
	s->start_seq = cc->OptStartSeq;
}

/* Builds the config of `bind` with a sub state that has delivered up to
 * `last_seq` from the stream incarnation `stamped`, the broker answering
 * `current` (0: the stream info request fails).  Returns the build's
 * result; the config is in *s and the state in *ss. */
static int build(const char *bind, int is_rebuild, uint64_t last_seq,
	int64_t stamped, int64_t current, struct seen *s, proc_sub_state_t *ss)
{
	str cfg = { (char *)bind, (int)strlen(bind) };
	const char *err = NULL;
	nats_handle_t *h;
	int rc;

	memset(s, 0, sizeof *s);
	memset(ss, 0, sizeof *ss);
	ss->last_stream_seq = last_seq;
	ss->stream_created_ns = stamped;

	h = nats_handle_parse(&cfg, &err);
	if (!h) {
		diag("bind '%s' refused: %s", bind, err ? err : "?");
		return -2;
	}
	nc_ut_begin();
	nf.stream_info_status = current ? NATS_OK : NATS_NOT_FOUND;
	nf.stream_created = current;
	rc = nc_ut_build_consumer_config(h, ss, is_rebuild, inspect, s);
	nc_ut_end();
	nats_handle_free(h);
	return rc;
}

#define ALL "id=cfg;stream=ORDERS;durable=d"
#define NEW "id=cfg;stream=ORDERS;durable=d;deliver_policy=new"

static void replay_bias(void)
{
	struct seen s;
	proc_sub_state_t ss;

	ok(build(ALL, 1, 100, 1500, 1500, &s, &ss) == 0 && s.called &&
		s.deliver == js_DeliverByStartSequence && s.start_seq == 101,
		"consumer_config: rebuild + deliver_all + delivered resumes at last_seq+1");
	is(nf.stream_info_name, "ORDERS",
		"consumer_config: the incarnation is asked of the handle's stream");
	ok(nf.n_stream_info_destroy == nf.n_stream_info,
		"consumer_config: the stream info is freed");
	ok(ss.last_stream_seq == 100,
		"consumer_config: same incarnation keeps the watermark");

	ok(build(ALL, 0, 0, 0, 1500, &s, &ss) == 0 &&
		s.deliver == js_DeliverAll && nf.n_stream_info == 0,
		"consumer_config: first build keeps deliver_all and asks nothing");
	ok(build(ALL, 0, 100, 1500, 1500, &s, &ss) == 0 &&
		s.deliver == js_DeliverAll,
		"consumer_config: first build is not biased even with a watermark");
	ok(build(ALL, 1, 0, 1500, 1500, &s, &ss) == 0 &&
		s.deliver == js_DeliverAll && nf.n_stream_info == 0,
		"consumer_config: rebuild with nothing delivered keeps deliver_all");
	ok(build(NEW, 1, 100, 1500, 1500, &s, &ss) == 0 &&
		s.deliver == js_DeliverNew && nf.n_stream_info == 0,
		"consumer_config: rebuild of deliver_new is not rewritten");
}

static void rebuild_bias(void)
{
	struct seen s;
	proc_sub_state_t ss;

	ok(build(ALL, 1, 100, 1500, 2000, &s, &ss) == 0 &&
		s.deliver == js_DeliverAll,
		"consumer_config: a recreated stream replays per deliver_policy");
	ok(ss.last_stream_seq == 0 && ss.stream_created_ns == 0,
		"consumer_config: a recreated stream drops the watermark");
	ok(build(ALL, 1, 100, 2000, 1500, &s, &ss) == 0 &&
		s.deliver == js_DeliverAll && ss.last_stream_seq == 0,
		"consumer_config: an older Created is a different incarnation too");
	ok(build(ALL, 1, 100, 1500, 0, &s, &ss) == 0 &&
		s.deliver == js_DeliverByStartSequence && s.start_seq == 101 &&
		ss.last_stream_seq == 100,
		"consumer_config: a failed stream info keeps the bias");
	ok(build(ALL, 1, 100, 0, 1500, &s, &ss) == 0 &&
		s.deliver == js_DeliverByStartSequence && s.start_seq == 101,
		"consumer_config: no stamped incarnation keeps the bias");
}

static void stale_decision(void)
{
	ok(nats_rebuild_bias_stale(1000, 2000) == 1,
		"consumer_config: different Created is stale");
	ok(nats_rebuild_bias_stale(2000, 1000) == 1,
		"consumer_config: backwards Created is stale");
	ok(nats_rebuild_bias_stale(1500, 1500) == 0,
		"consumer_config: same Created is not stale");
	ok(nats_rebuild_bias_stale(0, 1500) == 0,
		"consumer_config: no stamped incarnation is not stale");
	ok(nats_rebuild_bias_stale(1500, 0) == 0,
		"consumer_config: unknown current incarnation is not stale");
	ok(nats_rebuild_bias_stale(0, 0) == 0,
		"consumer_config: both unknown is not stale");
}

void nc_ut_consumer_config(void)
{
	stale_decision();
	replay_bias();
	rebuild_bias();
}
