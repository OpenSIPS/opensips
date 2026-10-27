/*
 * clusterer_controller - unit tests (make test module=clusterer_controller)
 *
 * Copyright (C) 2026 Yury Kirsanov
 *                          VoIPLine Telecom
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>

#include "../cl_ctr.h"

/* The replay window, through what its callers use: cl_ctr_replay_reset()
 * and cl_ctr_replay_check() on a window as the peer table zeroes it. */

#define HIGH (CL_CTR_REPLAY_MAX_JUMP + 1000000u)   /* a long-running sender */

static void test_window_basics(void)
{
	cl_ctr_replay_t r;

	memset(&r, 0, sizeof r);
	ok(cl_ctr_replay_check(&r, 1) == CL_CTR_SEQ_OK, "window: first packet accepted");
	ok(cl_ctr_replay_check(&r, 2) == CL_CTR_SEQ_OK, "window: next accepted");
	ok(cl_ctr_replay_check(&r, 2) == CL_CTR_SEQ_DUP, "window: repeat refused");
	ok(cl_ctr_replay_check(&r, 10) == CL_CTR_SEQ_OK, "window: a gap accepted");
	ok(cl_ctr_replay_check(&r, 5) == CL_CTR_SEQ_OK, "window: late inside the window accepted");
	ok(cl_ctr_replay_check(&r, 5) == CL_CTR_SEQ_DUP, "window: late repeat refused");
	ok(cl_ctr_replay_check(&r, 10 + CL_CTR_REPLAY_WIN_BITS) == CL_CTR_SEQ_OK,
	   "window: a window ahead accepted");
	ok(cl_ctr_replay_check(&r, 9) == CL_CTR_SEQ_OLD, "window: below the window refused");
	ok(cl_ctr_replay_check(&r, 10 + CL_CTR_REPLAY_WIN_BITS + CL_CTR_REPLAY_MAX_JUMP)
	   == CL_CTR_SEQ_JUMP, "window: an implausible jump refused");
	ok(cl_ctr_replay_check(&r, 11 + CL_CTR_REPLAY_WIN_BITS) == CL_CTR_SEQ_OK,
	   "window: a lone jump leaves the stream alone");
}

/* A sender numbered past CL_CTR_REPLAY_MAX_JUMP, met afresh: by a node that
 * restarted, one that has just learned it, or after a new key. */
static void test_window_long_running_sender(void)
{
	cl_ctr_replay_t r;
	uint32_t s;

	memset(&r, 0, sizeof r);                       /* a peer just learned */
	ok(cl_ctr_replay_check(&r, HIGH) == CL_CTR_SEQ_OK,
	   "long-running sender, newly learned: first packet accepted");
	ok(cl_ctr_replay_check(&r, HIGH + 1) == CL_CTR_SEQ_OK,
	   "long-running sender, newly learned: the stream goes on");
	ok(cl_ctr_replay_check(&r, HIGH) == CL_CTR_SEQ_DUP,
	   "long-running sender, newly learned: a repeat still refused");

	cl_ctr_replay_reset(&r);                       /* restart, new key */
	ok(cl_ctr_replay_check(&r, HIGH + 50) == CL_CTR_SEQ_OK,
	   "long-running sender after a reset: first packet accepted");
	for (s = HIGH + 51; s < HIGH + 60; s++)
		if (cl_ctr_replay_check(&r, s) != CL_CTR_SEQ_OK)
			break;
	ok(s == HIGH + 60, "long-running sender after a reset: every packet after it accepted");
}

/* A replayed old packet that arrives first after a reset sets the mark; the
 * live stream, far ahead, must still get through. */
static void test_window_bad_anchor(void)
{
	cl_ctr_replay_t r;
	int i, last = CL_CTR_SEQ_JUMP;

	memset(&r, 0, sizeof r);
	cl_ctr_replay_reset(&r);
	ok(cl_ctr_replay_check(&r, 100) == CL_CTR_SEQ_OK, "bad anchor: the replay is taken first");
	for (i = 0; i < 6 && last != CL_CTR_SEQ_OK; i++)
		last = cl_ctr_replay_check(&r, HIGH + i);
	ok(last == CL_CTR_SEQ_OK, "bad anchor: the live stream gets through");
	ok(i <= 3, "bad anchor: within three packets");
	ok(cl_ctr_replay_check(&r, HIGH + 10) == CL_CTR_SEQ_OK, "bad anchor: and stays through");
	ok(cl_ctr_replay_check(&r, 101) == CL_CTR_SEQ_OLD,
	   "bad anchor: the next replay is refused");
}

/* Jumps that are not one stream - scattered, as replays of packets from
 * more than 2^31 messages ago would be - never move the window. */
static void test_window_scattered_jumps(void)
{
	cl_ctr_replay_t r;
	int i, moved = 0;

	memset(&r, 0, sizeof r);
	ok(cl_ctr_replay_check(&r, 1000) == CL_CTR_SEQ_OK, "scattered jumps: anchored");
	for (i = 1; i <= 6; i++)
		if (cl_ctr_replay_check(&r, 1000 + CL_CTR_REPLAY_MAX_JUMP
		                            + (uint32_t)i * 10 * CL_CTR_REPLAY_WIN_BITS)
		        == CL_CTR_SEQ_OK)
			moved = 1;
	ok(!moved, "scattered jumps: none accepted");
	ok(cl_ctr_replay_check(&r, 1001) == CL_CTR_SEQ_OK, "scattered jumps: the stream goes on");
}

/* Terms: a node that knows none yet still refuses one no cluster could have
 * reached one election at a time. */
static cl_ctr_peers_t   t_peers;
static cl_ctr_cluster_t t_cl;

static void test_term_sanity(void)
{
	memset(&t_peers, 0, sizeof t_peers);
	memset(&t_cl, 0, sizeof t_cl);
	t_cl.peers = &t_peers;
	t_cl.cluster_id = 1;

	ok(cl_ctr_term_sane(&t_cl, 5, "test") == 1, "term: a fresh node takes a small term");
	ok(cl_ctr_term_sane(&t_cl, CL_CTR_TERM_JUMP_MAX, "test") == 1,
	   "term: a fresh node takes one jump's worth");
	ok(cl_ctr_term_sane(&t_cl, 0xFFFFFFFFu, "test") == 0,
	   "term: a fresh node refuses the last term there is");
	t_peers.term_seen = 10;
	ok(cl_ctr_term_sane(&t_cl, 11, "test") == 1, "term: the next term taken");
	ok(cl_ctr_term_sane(&t_cl, 11 + CL_CTR_TERM_JUMP_MAX, "test") == 0,
	   "term: more than a jump above what it knows refused");
}

/* Node ids are 1..CL_CTR_MAX_PEERS - every other id is in use or held. */
static void test_node_id_range(void)
{
	time_t now = cl_ctr_now();
	uint16_t id;
	int i;

	memset(&t_peers, 0, sizeof t_peers);
	memset(&t_cl, 0, sizeof t_cl);
	t_cl.peers = &t_peers;
	t_cl.cluster_id = 1;
	for (i = 0; i < 200; i++) {                    /* ids 1..200 in use */
		snprintf(t_peers.entries[i].ip, sizeof t_peers.entries[i].ip,
		         "10.0.%d.%d", i / 250, i % 250 + 1);
		t_peers.entries[i].node_id = (uint16_t)(i + 1);
	}
	t_peers.count = 200;
	for (i = 0; i < CL_CTR_MAX_PEERS - 200; i++) { /* the rest held */
		snprintf(t_peers.id_resv[i].ip, sizeof t_peers.id_resv[i].ip,
		         "10.1.0.%d", i + 1);
		t_peers.id_resv[i].node_id = (uint16_t)(201 + i);
		t_peers.id_resv[i].until = now + 3600;
	}
	id = cl_ctr_alloc_node_id_locked(&t_cl, "10.9.9.9");
	ok(id >= 1 && id <= CL_CTR_MAX_PEERS,
	   "node id: every id in use or held - one of them is reused, none past %d (got %u)",
	   CL_CTR_MAX_PEERS, id);
	for (i = 200; i < CL_CTR_MAX_PEERS; i++) {     /* now all 256 in use */
		snprintf(t_peers.entries[i].ip, sizeof t_peers.entries[i].ip,
		         "10.2.%d.%d", i / 250, i % 250 + 1);
		t_peers.entries[i].node_id = (uint16_t)(i + 1);
	}
	t_peers.count = CL_CTR_MAX_PEERS;
	ok(cl_ctr_alloc_node_id_locked(&t_cl, "10.9.9.9") == 0,
	   "node id: every id in use - none allocated");
}

void mod_tests(void)
{
	test_window_basics();
	test_window_long_running_sender();
	test_window_bad_anchor();
	test_window_scattered_jumps();
	test_term_sanity();
	test_node_id_range();
}
