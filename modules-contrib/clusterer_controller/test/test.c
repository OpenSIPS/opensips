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
#include <unistd.h>

#include "../cl_ctr.h"
#include "../cl_ctr_identity.h"
#include "../cl_ctr_data.h"
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
	int i, used = CL_CTR_MAX_PEERS / 2;

	memset(&t_peers, 0, sizeof t_peers);
	memset(&t_cl, 0, sizeof t_cl);
	t_cl.peers = &t_peers;
	t_cl.cluster_id = 1;
	for (i = 0; i < used; i++) {                   /* ids 1..used in use */
		snprintf(t_peers.entries[i].ip, sizeof t_peers.entries[i].ip,
		         "10.0.%d.%d", i / 250, i % 250 + 1);
		t_peers.entries[i].node_id = (uint16_t)(i + 1);
	}
	t_peers.count = used;
	for (i = 0; i < CL_CTR_MAX_PEERS - used; i++) { /* the rest held */
		snprintf(t_peers.id_resv[i].ip, sizeof t_peers.id_resv[i].ip,
		         "10.1.0.%d", i + 1);
		t_peers.id_resv[i].node_id = (uint16_t)(used + 1 + i);
		t_peers.id_resv[i].until = now + 3600;
	}
	id = cl_ctr_alloc_node_id_locked(&t_cl, "10.9.9.9", 0);
	ok(id == used + 1,
	   "node id: every id in use or held - the lowest held one is reused, "
	   "none in use and none past %d (got %u)", CL_CTR_MAX_PEERS, id);
	for (i = used; i < CL_CTR_MAX_PEERS; i++) {    /* now every id in use */
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
	ok(cl_ctr_alloc_node_id_locked(&t_cl, "10.0.0.3", 128) == 1,
	   "proposal: 128 is not an id - the lowest free instead");
	ok(cl_ctr_alloc_node_id_locked(&t_cl, "10.0.0.4", 127) == 127,
	   "proposal: 127, the highest id, is granted");
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

/* a departed sender's recordings stay refused: its window outlives its entry,
 * and bootstrap packets need a higher number than the last of the same life */
static void test_sender_memory(void)
{
	static struct cl_ctr_smem sm[CL_CTR_SMEM_SZ];
	cl_ctr_peer_t *e;
	int i;

	memset(&t_peers, 0, sizeof t_peers);
	memset(&t_cl, 0, sizeof t_cl);
	memset(sm, 0, sizeof sm);
	t_cl.peers = &t_peers;
	t_cl.smem = sm;
	t_peers.lock = lock_init_rw();
	if (!t_peers.lock) {
		ok(0, "sender memory: no lock for the peer table");
		return;
	}
	e = &t_peers.entries[0];
	snprintf(e->ip, sizeof e->ip, "10.0.0.7");
	e->ip_num = ip_to_num("10.0.0.7");
	t_peers.count = 1;
	ok(cl_ctr_check_and_update_seq("10.0.0.7", 100, 5, &t_cl) == CL_CTR_SEQ_OK,
	   "sender memory: a member's packet is taken");
	ok(cl_ctr_check_and_update_seq("10.0.0.7", 99, 5, &t_cl) == CL_CTR_SEQ_OK
	   && cl_ctr_check_and_update_seq("10.0.0.7", 99, 5, &t_cl) != CL_CTR_SEQ_OK,
	   "sender memory: a packet just below a window's first is taken once");
	ok(cl_ctr_check_and_update_seq("10.0.0.7", 99 - CL_CTR_REPLAY_ANCHOR_SLACK, 5,
	                               &t_cl) != CL_CTR_SEQ_OK,
	   "sender memory: nothing further below a window's first packet is taken");
	cl_ctr_remember_sender_locked(&t_cl, e);
	memset(e, 0, sizeof *e);
	t_peers.count = 0;
	ok(cl_ctr_check_and_update_seq("10.0.0.7", 100, 5, &t_cl) == CL_CTR_SEQ_UNKNOWN
	   && cl_ctr_check_and_update_seq("10.0.0.7", 101, 4, &t_cl) == CL_CTR_SEQ_UNKNOWN
	   && cl_ctr_check_and_update_seq("10.0.0.7", 101, 5, &t_cl) == CL_CTR_SEQ_UNKNOWN,
	   "sender memory: once it left the table, nothing of it is taken");
	snprintf(e->ip, sizeof e->ip, "10.0.0.7");
	e->ip_num = ip_to_num("10.0.0.7");
	t_peers.count = 1;
	ok(cl_ctr_check_and_update_seq("10.0.0.7", 100, 5, &t_cl) != CL_CTR_SEQ_OK,
	   "sender memory: back in the table, it carries on from where it left");
	ok(cl_ctr_check_and_update_seq("10.0.0.7", 101, 5, &t_cl) == CL_CTR_SEQ_OK,
	   "sender memory: ... and its next packet is taken");
	ok(cl_ctr_check_and_update_seq("10.0.0.7", 102, 4, &t_cl) == CL_CTR_SEQ_STALE,
	   "sender memory: a packet of an older life is refused");
	ok(cl_ctr_check_and_update_seq("10.0.0.7", 1, 0xfffffffffffffff0ULL, &t_cl)
	   == CL_CTR_SEQ_OK,
	   "sender memory: a restart is told by its incarnation, no clock is compared");
	/* the master announces the life it admitted: the same one keeps its window */
	cl_ctr_remember_sender_locked(&t_cl, e);
	e->incarnation = 0;
	cl_ctr_replay_reset(&e->replay);
	cl_ctr_set_incarnation_locked(&t_cl, e, 0xfffffffffffffff0ULL);
	ok(cl_ctr_check_and_update_seq("10.0.0.7", 1, 0xfffffffffffffff0ULL, &t_cl)
	   != CL_CTR_SEQ_OK,
	   "sender memory: an announced life it had heard keeps its window");
	ok(!cl_ctr_boot_seq_replayed(&t_cl, "10.0.0.8", 7, 10)
	   && cl_ctr_boot_seq_replayed(&t_cl, "10.0.0.8", 7, 10)
	   && cl_ctr_boot_seq_replayed(&t_cl, "10.0.0.8", 7, 9)
	   && !cl_ctr_boot_seq_replayed(&t_cl, "10.0.0.8", 7, 11)
	   && cl_ctr_boot_seq_replayed(&t_cl, "10.0.0.8", 6, 50),
	   "bootstrap: a number not above the last of the same life, or an older life heard lately, is a replay");
	ok(!cl_ctr_boot_seq_replayed(&t_cl, "10.0.0.9", 0xfffffffffffffff0ULL, 1)
	   && cl_ctr_boot_seq_replayed(&t_cl, "10.0.0.9", 9, 1),
	   "bootstrap: a far-ahead incarnation is a life like any other");
	/* no expiry: a week out of the table, its window is still the one it left with */
	cl_ctr_remember_sender_locked(&t_cl, e);
	for (i = 0; i < CL_CTR_SMEM_SZ; i++)
		if (sm[i].ip == e->ip_num)
			sm[i].seen -= 7 * 86400;
	e->incarnation = 0;
	cl_ctr_replay_reset(&e->replay);
	ok(cl_ctr_check_and_update_seq("10.0.0.7", 1, 0xfffffffffffffff0ULL, &t_cl)
	   != CL_CTR_SEQ_OK,
	   "sender memory: a week later its recording is still refused");
	/* full: the slot unused for longest goes to a new sender */
	for (i = 0; i < CL_CTR_SMEM_SZ; i++) {
		memset(&sm[i], 0, sizeof sm[i]);
		sm[i].ip   = 0x0b000001u + (uint32_t)i;
		sm[i].seen = cl_ctr_now() - (i == 17 ? 5000 : 1000 - i);
	}
	ok(!cl_ctr_boot_seq_replayed(&t_cl, "10.0.0.8", 7, 10)
	   && sm[17].ip == ip_to_num("10.0.0.8"),
	   "sender memory: full, the slot unused for longest is taken");
	lock_destroy_rw(t_peers.lock);
	t_peers.lock = NULL;
	t_cl.smem = NULL;
}

/* a 'cluster' value is taken whole or refused: no key skipped, nothing cut */
static void test_cluster_str(void)
{
	static cl_ctr_cluster_t c;
	char long_pw[1100];

	memset(&c, 0, sizeof c);
	ok(cl_ctr_parse_cluster_str("id=5,multicast=239.0.0.5:4000,password=s3cret", &c) == 0
	   && c.cluster_id == 5 && c.multicast_port == 4000 && c.data_port == 4001
	   && strcmp(c.password, "s3cret") == 0, "cluster: a valid value is read");
	memset(&c, 0, sizeof c);
	ok(cl_ctr_parse_cluster_str("id=5,multicast=239.0.0.5:4000,pasword=x", &c) < 0,
	   "cluster: a misspelt key is refused, not ignored");
	memset(&c, 0, sizeof c);
	ok(cl_ctr_parse_cluster_str("id=5,multicast=239.0.0.5:4000,password=a,b", &c) < 0,
	   "cluster: a comma inside a value is refused, not cut");
	memset(&c, 0, sizeof c);
	ok(cl_ctr_parse_cluster_str("id=5x,multicast=239.0.0.5:4000", &c) < 0,
	   "cluster: a number with trailing junk is refused");
	memset(&c, 0, sizeof c);
	ok(cl_ctr_parse_cluster_str("id=5,multicast=239.0.0.5:4000,manage_shtags=2", &c) < 0,
	   "cluster: a flag other than 0 or 1 is refused");
	memset(long_pw, 'p', sizeof long_pw);
	memcpy(long_pw, "id=5,multicast=239.0.0.5,password=", 34);
	long_pw[sizeof long_pw - 1] = '\0';
	memset(&c, 0, sizeof c);
	ok(cl_ctr_parse_cluster_str(long_pw, &c) < 0,
	   "cluster: a password longer than the buffer is refused, not cut");
	memset(&c, 0, sizeof c);
	ok(cl_ctr_parse_cluster_str("id=5,id=6,multicast=239.0.0.5:4000", &c) < 0,
	   "cluster: a key given twice is refused");
	memset(&c, 0, sizeof c);
	ok(cl_ctr_parse_cluster_str("id=5,multicast=239.0.0.5 junk:4000", &c) < 0,
	   "cluster: text after the group address is refused");
	memset(&c, 0, sizeof c);
	ok(cl_ctr_parse_cluster_str("id=5,multicast=239.0.0.5x:4000", &c) < 0,
	   "cluster: a group address with a letter in it is refused");
	memset(&c, 0, sizeof c);
	ok(cl_ctr_parse_cluster_str("id=5,multicast=10.0.0.5:4000", &c) < 0,
	   "cluster: an address that is no multicast group is refused");
	memset(&c, 0, sizeof c);
	ok(cl_ctr_parse_cluster_str("id=5,multicast=239.5:4000", &c) == 0
	   && strcmp(c.multicast_address, "239.0.0.5") == 0,
	   "cluster: the group is kept in one spelling (%s)", c.multicast_address);
	memset(&c, 0, sizeof c);
	ok(cl_ctr_parse_cluster_str("id=5,multicast=239.0.0.5:4000,"
	       "uuid=00000000-0000-0000-0000-000000000000", &c) < 0,
	   "cluster: a uuid of all zeros is refused");
	memset(&c, 0, sizeof c);
	ok(cl_ctr_parse_cluster_str("id=5,multicast=239.0.0.5:4000,uuid=fleet-a", &c) == 0
	   && c.cid_pinned && !cl_ctr_cid_is_zero(c.cid_pin),
	   "cluster: a name as uuid pins an identity");
	memset(&c, 0, sizeof c);
	ok(cl_ctr_parse_cluster_str(" id=5, ,multicast=239.0.0.5:4000, ", &c) == 0
	   && c.cluster_id == 5 && c.multicast_port == 4000,
	   "cluster: a blank part is skipped");
	memset(&c, 0, sizeof c);
	ok(cl_ctr_parse_cluster_str("id=5,multicast=239.0.0.5:65535", &c) < 0,
	   "cluster: port 65535 leaves no port for broadcasts");
	memset(&c, 0, sizeof c);
	ok(cl_ctr_parse_cluster_str("id=5,multicast=239.0.0.5:65535,data_port=4002", &c) == 0
	   && c.data_port == 4002,
	   "cluster: ... unless data_port names one");
}

/* packets as a node takes them off the wire: the handlers get any payload a
 * holder of the session key can seal, and must return with the table as it was */

#define T_MASTER  "10.0.0.9"
#define T_MEMBER  "10.0.0.7"
#define T_OTHER   "10.0.0.99"   /* in no table */
/* the longest payload a datagram this module takes can carry */
#define T_PAY_MAX (CL_CTR_LIST_PKT_MAX_SZ - CL_CTR_WIRE_HDR_SZ \
                   - CL_CTR_PLAIN_HDR_SZ - CL_CTR_TAG_SZ)

static cl_ctr_peers_t t_before;
static char           t_pay[T_PAY_MAX + 64];

/* a settled member's view: this node (id 1), the master it follows (2) and one
 * more member (3); no socket, no timers, no cluster of test/opensips.cfg */
static int t_view(void)
{
	const char *ips[3];
	time_t      now = cl_ctr_now();
	int         i;

	ips[0] = my_ip;
	ips[1] = T_MASTER;
	ips[2] = T_MEMBER;
	memset(&t_peers, 0, sizeof t_peers);
	memset(&t_cl, 0, sizeof t_cl);
	t_cl.peers      = &t_peers;
	t_cl.cluster_id = 77;
	t_cl.sock       = -1;
	t_cl.alive_tfd  = t_cl.beat_tfd = t_cl.join_tfd = t_cl.rejoin_tfd = -1;
	t_cl.master_alive_tfd = t_cl.master_dead_tfd = -1;
	t_cl.retx_tfd   = t_cl.stall_tfd = -1;
	t_peers.lock = lock_init_rw();
	if (!t_peers.lock)
		return -1;
	t_peers.node_state     = CL_CTR_NODE_ACTIVE;
	t_peers.worker_proc_no = -1;
	for (i = 0; i < 3; i++) {
		cl_ctr_peer_t *e = &t_peers.entries[i];

		snprintf(e->ip, sizeof e->ip, "%s", ips[i]);
		e->ip_num      = ip_to_num(e->ip);
		e->node_id     = (uint16_t)(i + 1);
		e->last_seen   = now;
		e->in_election = 1;
	}
	t_peers.entries[1].is_master = 1;
	t_peers.count = 3;
	snprintf(t_peers.last_master, sizeof t_peers.last_master, "%s", T_MASTER);
	t_peers.term_seen    = t_peers.master_term = 5;
	t_peers.master_count = t_peers.master_live = 3;
	return 0;
}

static void t_view_done(void)
{
	lock_destroy_rw(t_peers.lock);
	t_peers.lock = NULL;
}

static void t_keep(void)
{
	memcpy(&t_before, &t_peers, sizeof t_before);
}

/* the members, their ids, roles and states, the master, the pin and this
 * node's own state are what t_keep() saw */
static int t_kept(void)
{
	int i;

	if (t_peers.count != t_before.count ||
	        strcmp(t_peers.last_master, t_before.last_master) != 0 ||
	        t_peers.shtag_forced_node_id != t_before.shtag_forced_node_id ||
	        t_peers.node_state != t_before.node_state ||
	        t_peers.my_maint != t_before.my_maint)
		return 0;
	for (i = 0; i < t_peers.count; i++) {
		const cl_ctr_peer_t *a = &t_peers.entries[i], *b = &t_before.entries[i];

		if (strcmp(a->ip, b->ip) != 0 || a->node_id != b->node_id ||
		        a->is_master != b->is_master || a->is_backup != b->is_backup ||
		        a->maint != b->maint || a->connecting != b->connecting ||
		        a->last_seen != b->last_seen || a->bin_count != b->bin_count)
			return 0;
	}
	return 1;
}

/* @len bytes of @fill in t_pay; after them, as in the receive buffer, the
 * bytes of a tag - no NUL ends a string that the payload does not end */
static const char *t_fill(int fill, int len)
{
	memset(t_pay, 0xA5, sizeof t_pay);
	memset(t_pay, fill, (size_t)len);
	return t_pay;
}

/* the same, beginning with the @hlen bytes at @head */
static const char *t_head(const void *head, int hlen, int fill, int len)
{
	t_fill(fill, len);
	memcpy(t_pay, head, (size_t)(hlen < len ? hlen : len));
	return t_pay;
}

/* [ip NUL] and @body bytes of @fill in t_pay; the payload's length */
static int t_named(const char *ip, int fill, int body)
{
	int l = (int)strlen(ip) + 1;

	t_fill(fill, l + body);
	memcpy(t_pay, ip, (size_t)l);
	return l + body;
}

static void test_member_list(void)
{
	/* [count 2B][pin 2B][entries][term 4B][list number 4B], no entries */
	static const unsigned char absurd[] = { 0, 0, 0, 77, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 1 };
	static const unsigned char stale[]  = { 0, 0, 0, 77, 0, 0, 0, 4, 0, 0, 0, 9 };
	static const unsigned char fresh[]  = { 0, 0, 0, 77, 0, 0, 0, 6, 0, 0, 0, 1 };
	static const unsigned char five[]   = { 0, 5, 0, 0 };
	static const unsigned char many[]   = { 0, 128, 0, 0 };
	int len;

	if (t_view() < 0) {
		ok(0, "member list: no lock for the peer table");
		return;
	}
	t_keep();
	for (len = 0; len < CL_CTR_LIST_COUNT_SZ + CL_CTR_NODE_ID_SZ; len++)
		cl_ctr_handle_member_list(t_fill(0, len), len, T_MASTER, &t_cl);
	ok(t_kept(), "member list: too short for its count and pin - nothing changes");
	len = 4 + 5 * CL_CTR_IP_ENTRY_SZ - 1;
	cl_ctr_handle_member_list(t_head(five, 4, '1', len), len, T_MASTER, &t_cl);
	ok(t_kept(), "member list: a byte short of the members it counts - nothing changes");
	cl_ctr_handle_member_list(t_head(many, 4, '1', T_PAY_MAX), T_PAY_MAX, T_MASTER,
	                          &t_cl);
	cl_ctr_handle_member_list(t_fill(0xff, T_PAY_MAX), T_PAY_MAX, T_MASTER, &t_cl);
	ok(t_kept(), "member list: more members than a cluster has - nothing changes");
	cl_ctr_handle_member_list(t_head(absurd, (int)sizeof absurd, 0, (int)sizeof absurd),
	                          (int)sizeof absurd, T_MASTER, &t_cl);
	ok(t_kept() && t_peers.terms_refused == 1,
	   "member list: stamped with a term no cluster reached - refused, its pin not taken");
	cl_ctr_handle_member_list(t_head(stale, (int)sizeof stale, 0, (int)sizeof stale),
	                          (int)sizeof stale, T_MASTER, &t_cl);
	ok(t_kept(), "member list: of a term before the master's - refused, its pin not taken");
	cl_ctr_handle_member_list(t_head(fresh, (int)sizeof fresh, 0, (int)sizeof fresh),
	                          (int)sizeof fresh, T_MEMBER, &t_cl);
	ok(t_kept(), "member list: from a member that is not the master - nothing changes");
	cl_ctr_handle_member_list(t_head(fresh, (int)sizeof fresh, 0, (int)sizeof fresh),
	                          (int)sizeof fresh, T_MASTER, &t_cl);
	ok(t_peers.shtag_forced_node_id == 77 && t_peers.count == 3,
	   "member list: the same one from the master is taken");
	t_view_done();
}

/* @ip is the master this node follows from now on, as after an election or
 * that node's keepalive */
static void t_follow(const char *ip)
{
	int i;

	for (i = 0; i < t_peers.count; i++)
		t_peers.entries[i].is_master = strcmp(t_peers.entries[i].ip, ip) == 0;
	snprintf(t_peers.last_master, sizeof t_peers.last_master, "%s", ip);
}

/* the list of @len bytes at @list arrives from @from; the pin in force after it */
static int t_list(const unsigned char *list, int len, const char *from)
{
	cl_ctr_handle_member_list(t_head(list, len, 0, len), len, from, &t_cl);
	return t_peers.shtag_forced_node_id;
}

/* list order is kept per master: when the master before is master again, a
 * list of its earlier mastership is still older than the last one taken */
static void test_member_list_order(void)
{
	/* [count 2B][pin 2B][term 4B][list number 4B], no entries; one term, as
	 * two masters share after an election that did not raise it */
	static const unsigned char a5[] = { 0, 0, 0, 71, 0, 0, 0, 6, 0, 0, 0, 5 };
	static const unsigned char b1[] = { 0, 0, 0, 72, 0, 0, 0, 6, 0, 0, 0, 1 };
	static const unsigned char a4[] = { 0, 0, 0, 73, 0, 0, 0, 6, 0, 0, 0, 4 };
	static const unsigned char a6[] = { 0, 0, 0, 74, 0, 0, 0, 6, 0, 0, 0, 6 };
	static const unsigned char b2[] = { 0, 0, 0, 75, 0, 0, 0, 6, 0, 0, 0, 2 };

	if (t_view() < 0) {
		ok(0, "list order: no lock for the peer table");
		return;
	}
	ok(t_list(a5, (int)sizeof a5, T_MASTER) == 71,
	   "list order: the master's list number 5 is taken");
	t_follow(T_MEMBER);
	ok(t_list(b1, (int)sizeof b1, T_MEMBER) == 72,
	   "list order: another master numbers its own lists - its number 1 is taken");
	t_follow(T_MASTER);
	t_list(a4, (int)sizeof a4, T_MASTER);
	ok(t_list(a5, (int)sizeof a5, T_MASTER) == 72,
	   "list order: the first master again - its numbers 4 and 5 are refused");
	ok(t_list(a6, (int)sizeof a6, T_MASTER) == 74,
	   "list order: ... and its number 6 is taken");
	t_follow(T_MEMBER);
	ok(t_list(b1, (int)sizeof b1, T_MEMBER) == 74,
	   "list order: the second master again - its number 1 is refused as well");
	ok(t_list(b2, (int)sizeof b2, T_MEMBER) == 75 && t_peers.count == 3,
	   "list order: ... and its number 2 is taken");
	t_view_done();
}

static void test_node_assign(void)
{
	/* [node_id 2B][ip NUL][socket count 1B] */
	static const char good[]    = "\0\004" "10.0.0.8\0";
	static const char no_end[]  = "\0\004" "10.0.0.8";
	static const char id_zero[] = "\0\0"   "10.0.0.8\0";
	static const char id_128[]  = "\0\200" "10.0.0.8\0";
	static const char short_ip[] = "\0\004" "10.0.0\0";
	static const char zero_ip[] = "\0\004" "0.0.0.0\0";
	static const char big_ip[]  = "\0\004" "999.1.1.1\0";
	int len;

	if (t_view() < 0) {
		ok(0, "node assign: no lock for the peer table");
		return;
	}
	t_keep();
	for (len = 0; len < CL_CTR_NODE_ID_SZ + 2; len++)
		cl_ctr_handle_node_assign(t_fill(0, len), len, T_MASTER, &t_cl);
	/* sizeof - 1: without the NUL the compiler appends, so the address is not ended */
	len = (int)sizeof no_end - 1;
	cl_ctr_handle_node_assign(t_head(no_end, len, 0, len), len, T_MASTER, &t_cl);
	ok(t_kept(), "node assign: too short, or its address not ended - nothing changes");
	cl_ctr_handle_node_assign(id_zero, (int)sizeof id_zero, T_MASTER, &t_cl);
	cl_ctr_handle_node_assign(id_128, (int)sizeof id_128, T_MASTER, &t_cl);
	ok(t_kept(), "node assign: node id 0 or 128 - nothing changes");
	cl_ctr_handle_node_assign(short_ip, (int)sizeof short_ip, T_MASTER, &t_cl);
	cl_ctr_handle_node_assign(zero_ip, (int)sizeof zero_ip, T_MASTER, &t_cl);
	cl_ctr_handle_node_assign(big_ip, (int)sizeof big_ip, T_MASTER, &t_cl);
	ok(t_kept(), "node assign: no address of a node - nothing changes");
	cl_ctr_handle_node_assign(t_fill(0xff, T_PAY_MAX), T_PAY_MAX, T_MASTER, &t_cl);
	cl_ctr_handle_node_assign(t_fill(0, T_PAY_MAX), T_PAY_MAX, T_MASTER, &t_cl);
	ok(t_kept(), "node assign: the largest payload of 0xff or of zeros - nothing changes");
	cl_ctr_handle_node_assign(good, (int)sizeof good, T_MEMBER, &t_cl);
	ok(t_kept(), "node assign: from a member that is not the master - nothing changes");
	cl_ctr_handle_node_assign(good, (int)sizeof good, T_MASTER, &t_cl);
	ok(t_peers.count == 4 && strcmp(t_peers.entries[3].ip, "10.0.0.8") == 0
	   && t_peers.entries[3].node_id == 4,
	   "node assign: the same one from the master is taken");
	t_view_done();
}

/* the master gives this node's id to another address: this node holds none
 * any more and asks to be admitted again (the request finds no socket here) */
static void test_node_assign_lost_id(void)
{
	/* [node_id 2B][ip NUL][socket count 1B]: node id 1, this node's, for 10.0.0.8 */
	static const char taken[] = "\0\001" "10.0.0.8\0";

	if (t_view() < 0) {
		ok(0, "node assign: no lock for the peer table");
		return;
	}
	cl_ctr_handle_node_assign(taken, (int)sizeof taken, T_MASTER, &t_cl);
	ok(t_peers.count == 4 && t_peers.entries[0].node_id == 0
	   && strcmp(t_peers.entries[3].ip, "10.0.0.8") == 0
	   && t_peers.entries[3].node_id == 1,
	   "node assign: this node's id given to another address - that node holds "
	   "it, this one holds none");
	ok(t_cl.join_pending == 1 && t_peers.my_seq == 1,
	   "node assign: ... and this node asks to be admitted again");
	t_view_done();
}

static void test_master_alive(void)
{
	/* [count 2B][digest 8B][heard 16B][term 4B] */
	const int          len = CL_CTR_DIGEST_SZ + CL_CTR_ALIVE_BITMAP_SZ + CL_CTR_TERM_SZ;
	struct sockaddr_in from;

	if (t_view() < 0) {
		ok(0, "master alive: no lock for the peer table");
		return;
	}
	cl_ctr_sockaddr_in(T_MASTER, 4000, &from);
	t_keep();
	cl_ctr_handle_master_alive(T_MASTER, &t_cl, t_fill(0xff, 200), 200,
	                           (const struct sockaddr *)&from, sizeof from);
	cl_ctr_handle_master_alive(my_ip, &t_cl, t_fill(0xff, T_PAY_MAX), T_PAY_MAX,
	                           (const struct sockaddr *)&from, sizeof from);
	ok(t_kept() && t_peers.master_term == 5,
	   "master alive: member counts no cluster has - nothing changes");
	/* three members, at the last term there is */
	t_fill(0, len);
	t_pay[1] = 3;
	memset(t_pay + CL_CTR_DIGEST_SZ + CL_CTR_ALIVE_BITMAP_SZ, 0xff, CL_CTR_TERM_SZ);
	cl_ctr_handle_master_alive(T_MASTER, &t_cl, t_pay, len,
	                           (const struct sockaddr *)&from, sizeof from);
	ok(t_kept() && t_peers.terms_refused == 1 && t_peers.master_term == 5,
	   "master alive: a term no cluster reached - refused, the master's term as it was");
	/* one member, term 0, from a member: no rival of the master followed */
	t_fill(0, len);
	t_pay[1] = 1;
	cl_ctr_handle_master_alive(T_MEMBER, &t_cl, t_pay, len,
	                           (const struct sockaddr *)&from, sizeof from);
	ok(t_kept() && t_peers.master_term == 5 && t_peers.master_count == 3,
	   "master alive: a member claiming a cluster of one - the master followed stays");
	t_view_done();
}

static void test_key_handoff(void)
{
	/* [next master's ip NUL][the salt, sealed to its public key: 48 + 32 bytes] */
	const int box = (int)crypto_box_SEALBYTES + CL_CTR_MASTER_SALT_SZ;
	int       len;

	if (t_view() < 0) {
		ok(0, "key handoff: no lock for the peer table");
		return;
	}
	if (cl_ctr_gen_ecdh_keypair(t_cl.my_privkey, t_cl.my_pubkey) < 0) {
		ok(0, "key handoff: no key pair");
		t_view_done();
		return;
	}
	t_keep();
	cl_ctr_handle_key_handoff(t_fill('A', 10), 10, T_MASTER, &t_cl);
	cl_ctr_handle_key_handoff(t_fill('A', T_PAY_MAX), T_PAY_MAX, T_MASTER, &t_cl);
	len = t_named(T_OTHER, 0x5a, box);
	cl_ctr_handle_key_handoff(t_pay, len, T_MASTER, &t_cl);
	ok(t_kept() && !t_cl.have_session_key,
	   "key handoff: no name ended, or another node's - no key taken");
	len = t_named(my_ip, 0x5a, box);
	cl_ctr_handle_key_handoff(t_pay, len, T_MEMBER, &t_cl);
	ok(t_kept() && !t_cl.have_session_key,
	   "key handoff: for this node, from a member that is not the master - no key taken");
	len = t_named(my_ip, 0x5a, box - 1);
	cl_ctr_handle_key_handoff(t_pay, len, T_MASTER, &t_cl);
	len = t_named(my_ip, 0x5a, box);
	cl_ctr_handle_key_handoff(t_pay, len, T_MASTER, &t_cl);
	len = t_named(my_ip, 0, box);
	cl_ctr_handle_key_handoff(t_pay, len, T_MASTER, &t_cl);
	len = t_named(my_ip, 0xff, T_PAY_MAX - (int)strlen(my_ip) - 1);
	cl_ctr_handle_key_handoff(t_pay, len, T_MASTER, &t_cl);
	ok(t_kept() && !t_cl.have_session_key,
	   "key handoff: for this node, from the master, a byte short or sealed to "
	   "nobody - no key taken");
	t_view_done();
}

static void test_maint_set(void)
{
	/* [node_id 2B][state 1B]; this node is node 1, in service */
	static const unsigned char no_state[] = { 0, 1, 3 }, wild[] = { 0, 1, 0xff };
	static const unsigned char other[] = { 0, 2, 1 }, nobody[] = { 0, 0, 2 };
	static const unsigned char no_id[] = { 0xff, 0xff, 1 }, same[] = { 0, 1, 0 };
	int len;

	if (t_view() < 0) {
		ok(0, "maint set: no lock for the peer table");
		return;
	}
	t_keep();
	for (len = 0; len < 3; len++)
		cl_ctr_handle_maint_set(T_MEMBER, t_fill(0, len), len, &t_cl);
	cl_ctr_handle_maint_set(T_MEMBER, (const char *)no_state, 3, &t_cl);
	cl_ctr_handle_maint_set(T_MEMBER, (const char *)wild, 3, &t_cl);
	cl_ctr_handle_maint_set(T_MEMBER, t_fill(0xff, T_PAY_MAX), T_PAY_MAX, &t_cl);
	ok(t_kept() && t_cl.maint_adv == CL_CTR_MAINT_NONE,
	   "maint set: too short, or a state there is not - nothing changes");
	cl_ctr_handle_maint_set(T_MEMBER, (const char *)other, 3, &t_cl);
	cl_ctr_handle_maint_set(T_MEMBER, (const char *)nobody, 3, &t_cl);
	cl_ctr_handle_maint_set(T_MEMBER, (const char *)no_id, 3, &t_cl);
	cl_ctr_handle_maint_set(T_MEMBER, (const char *)same, 3, &t_cl);
	ok(t_kept() && t_cl.maint_adv == CL_CTR_MAINT_NONE,
	   "maint set: for another node, for none, or the state this node is in - "
	   "nothing changes");
	t_view_done();
}

static void test_master_probe(void)
{
	const int          name = (int)strlen(T_MASTER);
	struct sockaddr_in from;
	int                len;

	if (t_view() < 0) {
		ok(0, "master probe: no lock for the peer table");
		return;
	}
	cl_ctr_sockaddr_in(T_OTHER, 4000, &from);
	t_keep();
	/* MASTER_PROBE [master's ip NUL], answered to members only: none asks here */
	cl_ctr_handle_master_probe(T_OTHER, t_fill(0, 0), 0, &t_cl,
	                           (const struct sockaddr *)&from, sizeof from);
	cl_ctr_handle_master_probe(T_OTHER, t_head(T_MASTER, name, 0, name), name, &t_cl,
	                           (const struct sockaddr *)&from, sizeof from);
	len = t_named(T_MASTER, 0, 0);
	cl_ctr_handle_master_probe(my_ip, t_pay, len, &t_cl,
	                           (const struct sockaddr *)&from, sizeof from);
	cl_ctr_handle_master_probe(T_OTHER, t_pay, len, &t_cl,
	                           (const struct sockaddr *)&from, sizeof from);
	cl_ctr_handle_master_probe(T_OTHER, t_fill(0xff, T_PAY_MAX), T_PAY_MAX, &t_cl,
	                           (const struct sockaddr *)&from, sizeof from);
	ok(t_kept() && t_peers.my_seq == 0,
	   "master probe: empty, not ended, this node's own, or from no member - "
	   "not answered, nothing changes");

	/* MASTER_PROBE_ACK [master's ip NUL][ms since it was heard 4B] */
	len = t_named(T_MASTER, 0, 4);
	cl_ctr_handle_master_probe_ack(T_MEMBER, t_pay, len, &t_cl);
	ok(t_kept() && t_cl.probe_heard + t_cl.probe_silent + t_cl.probe_answered_n == 0,
	   "probe answer: with no question out - ignored");
	t_cl.probing = 1;
	snprintf(t_cl.probe_master, sizeof t_cl.probe_master, "%s", T_MASTER);
	cl_ctr_handle_master_probe_ack(T_MEMBER, t_fill(0, 0), 0, &t_cl);
	cl_ctr_handle_master_probe_ack(T_MEMBER, t_head(T_MASTER, name, 0, name), name,
	                               &t_cl);
	len = t_named(T_MASTER, 0, 3);
	cl_ctr_handle_master_probe_ack(T_MEMBER, t_pay, len, &t_cl);
	len = t_named("10.0.0.8", 0, 4);
	cl_ctr_handle_master_probe_ack(T_MEMBER, t_pay, len, &t_cl);
	len = t_named("10.0.0.90", 0, 4);
	cl_ctr_handle_master_probe_ack(T_MEMBER, t_pay, len, &t_cl);
	len = t_named(T_MASTER, 0, 4);
	cl_ctr_handle_master_probe_ack(T_MASTER, t_pay, len, &t_cl);
	cl_ctr_handle_master_probe_ack(T_MEMBER, t_fill(0xff, T_PAY_MAX), T_PAY_MAX, &t_cl);
	ok(t_kept() && t_cl.probe_heard + t_cl.probe_silent + t_cl.probe_answered_n == 0,
	   "probe answer: cut short, about another master, or the master's own - "
	   "not counted");
	len = t_named(T_MASTER, 0, 4);
	cl_ctr_handle_master_probe_ack(T_OTHER, t_pay, len, &t_cl);
	ok(t_kept() && t_cl.probe_heard + t_cl.probe_silent == 0,
	   "probe answer: from no member - not counted");
	cl_ctr_handle_master_probe_ack(T_MEMBER, t_pay, len, &t_cl);
	cl_ctr_handle_master_probe_ack(T_MEMBER, t_pay, len, &t_cl);
	ok(t_cl.probe_heard == 1 && t_cl.probe_silent == 0 && t_peers.count == 3,
	   "probe answer: a member's is counted, once");
	t_view_done();
}

/* an election held because peers still hear the master: each heartbeat round
 * keeps that master in the election window until the next watchdog round */
static void test_held_election(void)
{
	cl_ctr_peer_t *m;
	time_t         old;

	if (t_view() < 0) {
		ok(0, "held election: no lock for the peer table");
		return;
	}
	m   = &t_peers.entries[1];
	old = cl_ctr_now() - 3600;
	m->last_seen = old;
	cl_ctr_beat(&t_cl);
	ok(m->last_seen == old && t_peers.my_seq == 0,
	   "held election: with none held, a heartbeat round leaves the master's "
	   "age as it is");
	t_cl.hold_since_ms = cl_ctr_now_ms();
	snprintf(t_cl.probe_master, sizeof t_cl.probe_master, "%s", T_MASTER);
	cl_ctr_beat(&t_cl);
	ok(m->last_seen > old && t_peers.my_seq == 0,
	   "held election: while one is held, each round keeps the master in the "
	   "window");
	t_view_done();
}

static void test_key_grant(void)
{
	/* [joiner's ip NUL][the second handshake message, 80 bytes] */
	static const unsigned char no_cid[CL_CTR_CID_SZ] = { 0 };
	struct sockaddr_in from;
	int                len;

	if (t_view() < 0) {
		ok(0, "key grant: no lock for the peer table");
		return;
	}
	cl_ctr_sockaddr_in(T_MASTER, 4000, &from);
	t_keep();
	cl_ctr_handle_key_grant(t_fill('A', 10), 10, T_MASTER, &t_cl, 1, no_cid,
	                        (const struct sockaddr *)&from, sizeof from);
	cl_ctr_handle_key_grant(t_fill('A', T_PAY_MAX), T_PAY_MAX, T_MASTER, &t_cl, 1,
	                        no_cid, (const struct sockaddr *)&from, sizeof from);
	len = t_named(T_OTHER, 0x5a, CL_CTR_NOISE_MSG2_SZ);
	cl_ctr_handle_key_grant(t_pay, len, T_MASTER, &t_cl, 1, no_cid,
	                        (const struct sockaddr *)&from, sizeof from);
	len = t_named(my_ip, 0x5a, CL_CTR_NOISE_MSG2_SZ - 1);
	cl_ctr_handle_key_grant(t_pay, len, T_MASTER, &t_cl, 1, no_cid,
	                        (const struct sockaddr *)&from, sizeof from);
	len = t_named(my_ip, 0x5a, CL_CTR_NOISE_MSG2_SZ);
	cl_ctr_handle_key_grant(t_pay, len, T_MASTER, &t_cl, 1, no_cid,
	                        (const struct sockaddr *)&from, sizeof from);
	len = t_named(my_ip, 0xff, T_PAY_MAX - (int)strlen(my_ip) - 1);
	cl_ctr_handle_key_grant(t_pay, len, T_MASTER, &t_cl, 1, no_cid,
	                        (const struct sockaddr *)&from, sizeof from);
	ok(t_kept() && !t_cl.have_session_key && t_cl.grant_from[0] == '\0'
	   && t_peers.my_seq == 0,
	   "key grant: no name ended, another node's, a byte short, or answering no "
	   "request of this node - no key taken, none acknowledged");
	t_view_done();
}

/* the master's side of a JOIN_REQ: a member heard in the life it runs gets the
 * key again and stays a member; any other request is an admission (CONNECTING) */
static void test_join_req_same_life(void)
{
	static const unsigned char nonce[CL_CTR_NONCE_SZ] = { 0 };
	struct sockaddr_in from;
	cl_ctr_peer_t     *m;
	int                len;

	if (t_view() < 0) {
		ok(0, "join req: no lock for the peer table");
		return;
	}
	/* this node is the master, the member (node 3) runs life 7; the answers
	 * find no socket here, which is logged and changes nothing */
	t_follow(my_ip);
	m = &t_peers.entries[2];
	m->incarnation = 7;
	cl_ctr_sockaddr_in(T_MEMBER, 4000, &from);
	/* [ip NUL][BIN sockets: none] */
	len = t_named(T_MEMBER, 0, 1);
	cl_ctr_handle_join_req(-1, t_pay, len, 7, nonce, T_MEMBER, &t_cl,
	                       (const struct sockaddr *)&from, sizeof from);
	ok(!m->connecting && m->node_id == 3 && t_peers.count == 3,
	   "join req: a member heard in this life asks again - it stays a member, "
	   "not CONNECTING");
	m->last_seen = cl_ctr_now() - 3600;
	cl_ctr_handle_join_req(-1, t_pay, len, 7, nonce, T_MEMBER, &t_cl,
	                       (const struct sockaddr *)&from, sizeof from);
	ok(m->connecting == 1 && m->node_id == 3 && t_peers.count == 3,
	   "join req: the same from a member not heard for an hour - admitted "
	   "anew, CONNECTING");
	m->connecting = 0;
	cl_ctr_handle_join_req(-1, t_pay, len, 8, nonce, T_MEMBER, &t_cl,
	                       (const struct sockaddr *)&from, sizeof from);
	ok(m->connecting == 1 && m->node_id == 3 && t_peers.count == 3,
	   "join req: the same in another life, a restart - admitted anew, "
	   "CONNECTING");
	t_view_done();
}

/* an acknowledgement releases a packet waiting for it only from the address it
 * was sent to and for its own type */
static void test_ack(void)
{
	unsigned char      ack[CL_CTR_ACK_SZ];
	struct sockaddr_in to;
	uint32_t           seq_be = htonl(41);
	int                len;

	if (t_view() < 0) {
		ok(0, "ack: no lock for the peer table");
		return;
	}
	t_cl.retx_tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (t_cl.retx_tfd < 0) {
		ok(0, "ack: no timer");
		t_view_done();
		return;
	}
	cl_ctr_sockaddr_in(T_MEMBER, 4000, &to);
	cl_ctr_retx_enqueue(&t_cl, 41, CL_CTR_PKT_KEY_GRANT,
	                    (const unsigned char *)t_fill(0x11, 100), 100,
	                    (const struct sockaddr *)&to, sizeof to);
	for (len = 0; len < (int)sizeof seq_be; len++)
		cl_ctr_handle_ack(t_fill(0, len), len, &t_cl, T_MEMBER);
	memcpy(ack, &seq_be, sizeof seq_be);
	ack[sizeof seq_be] = CL_CTR_PKT_NODE_ASSIGN;
	cl_ctr_handle_ack((const char *)ack, CL_CTR_ACK_SZ, &t_cl, T_MEMBER);
	ack[sizeof seq_be] = CL_CTR_PKT_KEY_GRANT;
	cl_ctr_handle_ack((const char *)ack, CL_CTR_ACK_SZ, &t_cl, T_OTHER);
	cl_ctr_handle_ack(t_fill(0xff, T_PAY_MAX), T_PAY_MAX, &t_cl, T_MEMBER);
	ok(t_cl.retx_count == 1,
	   "ack: too short, of another type, from another address, of no packet - "
	   "the packet still waits");
	cl_ctr_handle_ack((const char *)ack, CL_CTR_ACK_SZ, &t_cl, T_MEMBER);
	ok(t_cl.retx_count == 0, "ack: its own releases it");
	cl_ctr_retx_flush(&t_cl);
	close(t_cl.retx_tfd);
	t_view_done();
}

/* a session packet as @sender seals it, [type][number][incarnation][sender] and
 * @plen bytes of payload, for this test's cluster; the datagram's length */
static int t_seal(char *buf, const unsigned char *key, unsigned char type,
                  uint32_t seq, uint64_t inc, const char *sender,
                  const void *payload, int plen)
{
	unsigned char      *plain = (unsigned char *)buf + CL_CTR_WIRE_HDR_SZ;
	uint16_t            cid_be = htons((uint16_t)t_cl.cluster_id);
	uint32_t            seq_be = htonl(seq);
	unsigned long long  clen = 0;
	struct in_addr      a;
	int                 k;

	memset(buf, 0, CL_CTR_WIRE_HDR_SZ);
	memcpy(buf, CL_CTR_PACKET_MAGIC, CL_CTR_MAGIC_SZ);
	memcpy(buf + CL_CTR_MAGIC_SZ, &cid_be, CL_CTR_CLUSTER_ID_SZ);
	randombytes_buf(buf + CL_CTR_NONCE_OFF, CL_CTR_NONCE_SZ);
	plain[0] = type;
	memcpy(plain + 1, &seq_be, CL_CTR_SEQ_SZ);
	for (k = 0; k < CL_CTR_INC_SZ; k++)
		plain[1 + CL_CTR_SEQ_SZ + k] = (unsigned char)(inc >> (56 - 8 * k));
	a.s_addr = 0;
	inet_pton(AF_INET, sender, &a);
	memcpy(plain + 1 + CL_CTR_SEQ_SZ + CL_CTR_INC_SZ, &a.s_addr, CL_CTR_SENDER_SZ);
	if (plen > 0)
		memcpy(plain + CL_CTR_PLAIN_HDR_SZ, payload, (size_t)plen);
	if (crypto_aead_xchacha20poly1305_ietf_encrypt(plain, &clen, plain,
	        (unsigned long long)(CL_CTR_PLAIN_HDR_SZ + plen),
	        (const unsigned char *)buf, CL_CTR_AAD_SZ, NULL,
	        (const unsigned char *)buf + CL_CTR_NONCE_OFF, key) != 0)
		return 0;
	return CL_CTR_WIRE_HDR_SZ + (int)clen;
}

/* @n bytes arriving from @src; 1 when they got as far as a session packet's
 * handler: decrypted, from their sender's address, not seen before */
static int t_arrives(const char *buf, int n, const char *src)
{
	struct sockaddr_in from;

	cl_ctr_sockaddr_in(src, 4000, &from);
	t_cl.session_heard_ms = 0;
	cl_ctr_recv_one(-1, &t_cl, buf, n, &from);
	return t_cl.session_heard_ms != 0;
}

/* the receive path up to the handlers, with the two parsers that live in it
 * (ALIVE, GOODBYE); datagrams go in as those a sibling cluster's worker passes on */
static void test_recv(void)
{
	static cl_ctr_rate_entry_t rate[CL_CTR_RATE_TBL_SZ];
	static char                pkt[CL_CTR_LIST_PKT_MAX_SZ + 64];
	const unsigned char       *key = t_cl.session_key;
	unsigned char              other_key[sizeof t_cl.session_key];
	unsigned long              fails;
	int                        len, n, got = 0;

	if (t_view() < 0) {
		ok(0, "recv: no lock for the peer table");
		return;
	}
	memset(rate, 0, sizeof rate);
	t_cl.rate_tbl = rate;
	/* the packets-per-second budget is not what this tests */
	t_cl.rate_grace_until_ms = cl_ctr_now_ms() + 600000;
	t_cl.have_session_key    = 1;
	memset(t_cl.session_key, 0x5a, sizeof t_cl.session_key);
	memset(other_key, 0x3c, sizeof other_key);
	t_keep();

	for (len = 0; len <= 200; len++) {
		n = t_seal(pkt, key, CL_CTR_PKT_ALIVE, 100 + (uint32_t)len, 7, T_MEMBER,
		           t_fill('x', len), len);
		got += t_arrives(pkt, n, T_MEMBER);
	}
	ok(got == 201 && t_kept(),
	   "recv: an ALIVE of any length naming no node is parsed and changes "
	   "nothing (%d of 201 reached the parser)", got);

	len = t_named(T_MASTER, 0xff, 150);
	n   = t_seal(pkt, key, CL_CTR_PKT_ALIVE, 400, 7, T_MEMBER, t_pay, len);
	got = t_arrives(pkt, n, T_MEMBER);
	n   = t_seal(pkt, key, CL_CTR_PKT_GOODBYE, 401, 7, T_MEMBER, T_MASTER,
	             (int)strlen(T_MASTER));
	got += t_arrives(pkt, n, T_MEMBER);
	n   = t_seal(pkt, key, CL_CTR_PKT_GOODBYE, 402, 7, T_MEMBER, t_fill(0xff, 2000),
	             2000);
	got += t_arrives(pkt, n, T_MEMBER);
	n   = t_seal(pkt, key, CL_CTR_PKT_GOODBYE, 403, 7, T_MEMBER, t_pay, 0);
	got += t_arrives(pkt, n, T_MEMBER);
	n   = t_seal(pkt, key, 0x7f, 404, 7, T_MEMBER, t_fill(0xff, 300), 300);
	got += t_arrives(pkt, n, T_MEMBER);
	ok(got == 5 && t_kept(),
	   "recv: an ALIVE or a GOODBYE in another node's name, a GOODBYE in none, "
	   "a type no build has - nothing changes (%d of 5 reached the parser)", got);

	n   = t_seal(pkt, key, CL_CTR_PKT_ALIVE, 500, 7, T_MEMBER, t_fill('x', 40), 40);
	got = t_arrives(pkt, n, T_MEMBER);
	ok(got == 1 && !t_arrives(pkt, n, T_MEMBER) && t_cl.warn_replay.pkts == 1,
	   "recv: a packet sent again from its sender's own address is taken once");
	n = t_seal(pkt, key, CL_CTR_PKT_ALIVE, 501, 7, T_MEMBER, t_fill('x', 40), 40);
	ok(!t_arrives(pkt, n, T_OTHER) && t_cl.warn_spoof.pkts == 1
	   && t_arrives(pkt, n, T_MEMBER),
	   "recv: a packet from another address than it seals is dropped, and still "
	   "taken from its own");
	n = t_seal(pkt, key, CL_CTR_PKT_ALIVE, 1, 3, T_OTHER, t_fill('x', 40), 40);
	ok(!t_arrives(pkt, n, T_OTHER) && t_cl.warn_unknown.pkts == 1,
	   "recv: a session packet of a node the master has not listed is ignored");
	n = t_seal(pkt, key, CL_CTR_PKT_ALIVE, 9000, 6, T_MEMBER, t_fill('x', 40), 40);
	ok(!t_arrives(pkt, n, T_MEMBER),
	   "recv: a packet of a life before the one heard is refused");
	n = t_seal(pkt, key, CL_CTR_PKT_ALIVE, 1, 8, T_MEMBER, t_fill('x', 40), 40);
	ok(t_arrives(pkt, n, T_MEMBER), "recv: a newer life starts its numbers again");
	fails = t_peers.st_auth_failures;
	n = t_seal(pkt, other_key, CL_CTR_PKT_ALIVE, 2, 8, T_MEMBER, t_fill('x', 40), 40);
	ok(!t_arrives(pkt, n, T_MEMBER) && t_peers.st_auth_failures == fails + 1,
	   "recv: a packet sealed with another key is counted and dropped");
	memset(pkt, 0xff, sizeof pkt);
	ok(!t_arrives(pkt, CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_TAG_SZ - 1,
	              T_MEMBER)
	   && !t_arrives(pkt, CL_CTR_LIST_PKT_MAX_SZ + 1, T_MEMBER)
	   && t_cl.warn_short.pkts == 2,
	   "recv: a datagram shorter or longer than any packet is dropped before any key");
	ok(t_kept(), "recv: after all of them the table is as it was");
	t_cl.rate_tbl = NULL;
	t_view_done();
}

/* a node id outside 1..127 names no node: 0 is every joiner not given one yet */
static void test_node_id_lookups(void)
{
	int cid = 1, zero = 0, over = CL_CTR_MAX_PEERS + 1;

	ok(cl_ctr_find_peer(cid, zero, NULL, NULL, NULL, NULL, 0) == -1
	   && cl_ctr_find_peer(cid, over, NULL, NULL, NULL, NULL, 0) == -1,
	   "lookup: node id 0 and %d find no node", over);
	ok(w_cl_ctr_node_present(NULL, &cid, &zero) == -1
	   && w_cl_ctr_node_present(NULL, &cid, &over) == -1
	   && w_cl_ctr_node_is_master(NULL, &cid, &zero) == -1,
	   "script: cl_ctr_node_present() and cl_ctr_node_is_master() are false for them");
	ok(w_cl_ctr_get_node_role(NULL, &cid, &zero, NULL) == -1
	   && w_cl_ctr_get_node_maint(NULL, &cid, &over, NULL) == -1
	   && w_cl_ctr_get_node_ip(NULL, &cid, &zero, NULL) == -1,
	   "script: the functions that return a value fail for them, writing none");
}

/* a peer's BIN url must name an address: a host name would be resolved, with
 * blocking DNS, while the cluster list is locked - it is refused before that */
static void test_add_node_url(void)
{
	str url = str_init("bin:node7.example:5566");

	ok(clusterer_ctrl_add_node(1, 7, &url) == -1,
	   "add node: a url whose host is a name, not an address, is refused");
}

/* the launcher counts the processes before mod_init, so the modparams set
 * every count; test/opensips.cfg has one cluster, a second one is added */
static void test_proc_counts(void)
{
	int bc = mcast_broadcasts, mw = mcast_workers;

	ok(cl_ctr_add_cluster_param(STR_PARAM, "id=2,multicast=239.0.99.2:3998") == 0
	   && cl_ctr_procs[0].no == 2,
	   "procs: a worker per 'cluster' modparam (%d)", cl_ctr_procs[0].no);
	cl_ctr_set_mcast_broadcasts(INT_PARAM, (void *)1L);
	cl_ctr_set_mcast_workers(INT_PARAM, (void *)3L);
	ok(cl_ctr_procs[1].no == 3,
	   "procs: mcast_workers readers (%d)", cl_ctr_procs[1].no);
	cl_ctr_set_mcast_broadcasts(INT_PARAM, (void *)0L);
	ok(cl_ctr_procs[1].no == 0,
	   "procs: no readers with mcast_broadcasts=0 (%d)", cl_ctr_procs[1].no);
	cl_ctr_set_mcast_broadcasts(INT_PARAM, (void *)(long)bc);
	cl_ctr_set_mcast_workers(INT_PARAM, (void *)(long)mw);
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
	test_cluster_str();
	test_sender_memory();
	test_member_list();
	test_member_list_order();
	test_node_assign();
	test_node_assign_lost_id();
	test_master_alive();
	test_key_handoff();
	test_maint_set();
	test_master_probe();
	test_held_election();
	test_key_grant();
	test_join_req_same_life();
	test_ack();
	test_recv();
	test_node_id_lookups();
	test_add_node_url();
	test_data();
	test_proc_counts();     /* last: it adds a cluster */
}
