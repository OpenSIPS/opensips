/*
 * clusterer_controller - unit tests (make test module=clusterer_controller)
 *
 * Copyright (C) 2026 Yury Kirsanov
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
#include "../cl_ctr_identity.h"
#include "../clusterer_ctrl.h"

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

/* a sender numbered past CL_CTR_REPLAY_MAX_JUMP, met afresh: by a node that
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

/* a replayed old packet that arrives first after a reset sets the mark; the
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

/* jumps that are not one stream - scattered, as replays of packets from
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

/* terms: a node that knows none yet still refuses one no cluster could have
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

/* node ids are 1..CL_CTR_MAX_PEERS - every other id is in use or held. */
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
	id = cl_ctr_alloc_node_id_locked(&t_cl, "10.9.9.9", 0);
	ok(id >= 1 && id <= CL_CTR_MAX_PEERS,
	   "node id: every id in use or held - one of them is reused, none past %d (got %u)",
	   CL_CTR_MAX_PEERS, id);
	for (i = 200; i < CL_CTR_MAX_PEERS; i++) {     /* now all 256 in use */
		snprintf(t_peers.entries[i].ip, sizeof t_peers.entries[i].ip,
		         "10.2.%d.%d", i / 250, i % 250 + 1);
		t_peers.entries[i].node_id = (uint16_t)(i + 1);
	}
	t_peers.count = CL_CTR_MAX_PEERS;
	ok(cl_ctr_alloc_node_id_locked(&t_cl, "10.9.9.9", 0) == 0,
	   "node id: every id in use - none allocated");
}

/* a joiner asks for an id: it gets it while it is free, a substitute while
 * it is in use or held for a node that left, and its own held id first */
static void test_node_id_proposal(void)
{
	time_t now = cl_ctr_now();
	unsigned char a[CL_CTR_IDENTITY_SZ] = {1}, b[CL_CTR_IDENTITY_SZ] = {2};
	uint16_t pa, pb;

	memset(&t_peers, 0, sizeof t_peers);
	memset(&t_cl, 0, sizeof t_cl);
	t_cl.peers = &t_peers;
	t_cl.cluster_id = 1;
	ok(cl_ctr_alloc_node_id_locked(&t_cl, "10.0.0.1", 77) == 77,
	   "proposal: a founder gets the id it proposes");
	snprintf(t_peers.entries[0].ip, sizeof t_peers.entries[0].ip, "10.0.0.1");
	t_peers.entries[0].node_id = 77;
	t_peers.count = 1;
	ok(cl_ctr_alloc_node_id_locked(&t_cl, "10.0.0.2", 78) == 78,
	   "proposal: a joiner gets a free id it proposes");
	ok(cl_ctr_alloc_node_id_locked(&t_cl, "10.0.0.2", 77) == 1,
	   "proposal: an id in use - the lowest free instead");
	snprintf(t_peers.id_resv[0].ip, sizeof t_peers.id_resv[0].ip, "10.0.0.9");
	t_peers.id_resv[0].node_id = 90;
	t_peers.id_resv[0].until = now + 3600;
	ok(cl_ctr_alloc_node_id_locked(&t_cl, "10.0.0.2", 90) == 1,
	   "proposal: an id held for a node that left - the lowest free instead");
	ok(cl_ctr_alloc_node_id_locked(&t_cl, "10.0.0.9", 50) == 90,
	   "proposal: a node that left gets its held id back, whatever it proposes");
	ok(cl_ctr_alloc_node_id_locked(&t_cl, "10.0.0.3", 300) == 1,
	   "proposal: an id past %d is not one - the lowest free instead", CL_CTR_MAX_PEERS);
	pa = cl_ctr_identity_proposal(a, CL_CTR_MAX_PEERS);
	pb = cl_ctr_identity_proposal(b, CL_CTR_MAX_PEERS);
	ok(pa >= 1 && pa <= CL_CTR_MAX_PEERS && pb >= 1 && pb <= CL_CTR_MAX_PEERS &&
	   pa == cl_ctr_identity_proposal(a, CL_CTR_MAX_PEERS) && pa != pb,
	   "proposal: an identity proposes an id in 1..%d, always the same one (%u, %u)",
	   CL_CTR_MAX_PEERS, pa, pb);
}

void test_data(void);   /* test_data.c */

static int opts(const char *s, int *cid, int *uc)
{
	str d = {(char *)s, (int)strlen(s)};

	*cid = -1;
	*uc  = 0;
	return cl_ctr_parse_options(&d, cid, uc);
}

static void test_cluster_options(void)
{
	int cid, uc;

	ok(opts("cluster_id=7, use_controller=1", &cid, &uc) == 0 && cid == 7 && uc == 1,
	   "options: both keys read");
	ok(opts(" use_controller = 1 ,cluster_id=7, ", &cid, &uc) == 0 && cid == 7 && uc == 1,
	   "options: spaces, either order, a trailing comma");
	ok(opts("cluster_id=7", &cid, &uc) == 0 && cid == 7 && uc == 0,
	   "options: use_controller left out stays 0");
	ok(opts("not_cluster_id=5", &cid, &uc) < 0 && cid == -1,
	   "options: a key containing a known one is refused");
	ok(opts("cluster_id=7, use_controler=1", &cid, &uc) < 0,
	   "options: a misspelt key is refused, not ignored");
	ok(opts("cluster_id=7, cluster_id=8", &cid, &uc) < 0, "options: a key given twice is refused");
	ok(opts("cluster_id 7", &cid, &uc) < 0, "options: a key without '=' is refused");
	ok(opts("cluster_id=7x", &cid, &uc) < 0, "options: a value that is not a number is refused");
	ok(opts("cluster_id=", &cid, &uc) < 0, "options: an empty value is refused");
	ok(opts("cluster_id=   , use_controller=1", &cid, &uc) < 0, "options: a blank value is refused");
	ok(opts(" , ,cluster_id=7", &cid, &uc) == 0 && cid == 7, "options: blank entries are skipped");
}

static void test_master_rank(void)
{
	ok(cl_ctr_master_outranks(4, 3, 0, "10.0.0.2", 4, 3, 1, "10.0.0.4"),
	   "rank: same count and term - a raised term beats an unraised one, whatever the IP");
	ok(!cl_ctr_master_outranks(4, 3, 1, "10.0.0.4", 4, 3, 0, "10.0.0.2"),
	   "rank: ... and the unraised one does not beat it");
	ok(cl_ctr_master_outranks(4, 3, 0, "10.0.0.4", 4, 3, 0, "10.0.0.2"),
	   "rank: both raised - the higher IP");
	ok(cl_ctr_master_outranks(4, 4, 1, "10.0.0.2", 4, 3, 0, "10.0.0.4"),
	   "rank: a higher term beats a raised lower one");
	ok(cl_ctr_master_outranks(5, 2, 1, "10.0.0.2", 4, 9, 0, "10.0.0.4"),
	   "rank: more members heard beats everything else");
}

void mod_tests(void)
{
	test_window_basics();
	test_window_long_running_sender();
	test_window_bad_anchor();
	test_window_scattered_jumps();
	test_term_sanity();
	test_node_id_range();
	test_node_id_proposal();
	test_cluster_options();
	test_master_rank();
	test_data();
}
