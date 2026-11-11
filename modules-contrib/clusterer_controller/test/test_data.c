/*
 * clusterer_controller - unit tests of the broadcast receive path
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
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../cl_ctr.h"
#include "../cl_ctr_data.h"
#include "../../../bin_interface.h"

#define SENDER    7
#define CC_SENDER 9
#define SELF      3     /* this node's own id, where a test gives it one */

/* a broadcast as clusterer makes it, to pass the check on its way to the modules: a BIN
 * header, the text, the trailer [last broadcast number][cluster id][source][destination] */
#define WRAP_HDR  16
#define WRAP_TRL  (4 * (int)sizeof(int))
#define WRAP_MAX  (WRAP_HDR + 64 + WRAP_TRL)

static int wrap(char *b, int cid, int src, const char *text, int tlen)
{
	unsigned int len = WRAP_HDR + tlen + WRAP_TRL;
	int          zero = 0;

	memset(b, 0, WRAP_HDR);
	memcpy(b, BIN_PACKET_MARKER, BIN_PACKET_MARKER_SIZE);
	memcpy(b + BIN_PACKET_MARKER_SIZE, &len, sizeof len);
	memcpy(b + WRAP_HDR, text, tlen);
	memcpy(b + len - 4 * sizeof(int), &zero, sizeof(int));
	memcpy(b + len - 3 * sizeof(int), &cid, sizeof(int));
	memcpy(b + len - 2 * sizeof(int), &src, sizeof(int));
	memcpy(b + len - sizeof(int), &zero, sizeof(int));
	return (int)len;
}

/* what reached the sink, as one string: "p1 p2 T:x ..." - the text of a broadcast,
 * or after T: a released TCP message */
static char got[1024];

static void sink(int sender, int match, const char *bin, int len)
{
	size_t n = strlen(got);

	if (match >= 0) {
		bin += WRAP_HDR;
		len -= WRAP_HDR + WRAP_TRL;
	}
	if (sender != SENDER || len < 0)
		len = 0;
	snprintf(got + n, sizeof got - n, "%s%s%.*s", n ? " " : "",
	         match < 0 ? "T:" : "", len, bin);
}

static void take(cl_ctr_cluster_t *cl, uint64_t inc, uint64_t seq, const char *s)
{
	char b[WRAP_MAX];
	int  len = wrap(b, cl->cluster_id, SENDER, s, (int)strlen(s));

	cl_ctr_data_accept(cl, SENDER, inc, seq, 0, 0, 1, b, len);
}

/* fragment @fi of @fn of a broadcast whose text is @total bytes, @s being this
 * fragment's share of it: the first carries the header, the last the trailer */
static void take_frag(cl_ctr_cluster_t *cl, uint64_t seq, int fi, int fn,
                      const char *s, int total)
{
	char whole[WRAP_MAX], text[64], b[WRAP_MAX];
	int  n = (int)strlen(s), len = 0, wl;

	memset(text, 0, sizeof text);
	wl = wrap(whole, cl->cluster_id, SENDER, text, total);
	if (fi == 0) {
		memcpy(b, whole, WRAP_HDR);
		len = WRAP_HDR;
	}
	memcpy(b + len, s, n);
	len += n;
	if (fi == fn - 1) {
		memcpy(b + len, whole + wl - WRAP_TRL, WRAP_TRL);
		len += WRAP_TRL;
	}
	cl_ctr_data_accept(cl, SENDER, 1, seq, 0, fi, fn, b, len);
}

/* the peer table of a test cluster: SENDER and CC_SENDER, both in incarnation 1 */
static cl_ctr_peers_t *peers_alloc(void)
{
	cl_ctr_peers_t *t = shm_malloc(sizeof *t);

	if (!t)
		return NULL;
	memset(t, 0, sizeof *t);
	t->lock = lock_init_rw();
	if (!t->lock) {
		shm_free(t);
		return NULL;
	}
	snprintf(t->entries[0].ip, sizeof t->entries[0].ip, "127.0.0.1");
	t->entries[0].node_id = SENDER;
	t->entries[0].incarnation = 1;
	snprintf(t->entries[1].ip, sizeof t->entries[1].ip, "127.0.0.2");
	t->entries[1].node_id = CC_SENDER;
	t->entries[1].incarnation = 1;
	t->count = 2;
	return t;
}

static void peers_free(cl_ctr_peers_t *t)
{
	if (!t)
		return;
	lock_destroy_rw(t->lock);
	shm_free(t);
}

/* what the controller learns from ALIVE or NODE_ASSIGN */
static void set_inc(cl_ctr_cluster_t *cl, int node, uint64_t inc)
{
	int i;

	lock_start_write(cl->peers->lock);
	for (i = 0; i < cl->peers->count; i++)
		if (cl->peers->entries[i].node_id == node)
			cl->peers->entries[i].incarnation = inc;
	lock_stop_write(cl->peers->lock);
	cl_ctr_data_skew_ms += CL_CTR_DATA_SRC_TTL_MS;    /* what readers cached is old */
}

static int park(int cluster_id, unsigned int barrier, const char *s)
{
	struct receive_info ri;

	memset(&ri, 0, sizeof ri);
	return cl_ctr_data_park(cluster_id, SENDER, barrier, s, (int)strlen(s), &ri);
}

static void test_widen(void)
{
	ok(cl_ctr_data_widen(0x100000005ull, 3) == 0x100000003ull,
	   "widen: a little behind, same epoch");
	ok(cl_ctr_data_widen(0x100000001ull, 0xffffffffu) == 0xffffffffull,
	   "widen: just before the 32-bit wrap");
	ok(cl_ctr_data_widen(0xfffffffeull, 2) == 0x100000002ull,
	   "widen: just after the 32-bit wrap");
	ok(cl_ctr_data_widen(10, 0xfffffff0u) == 0xfffffff0ull,
	   "widen: never below zero");
}

/* nothing was heard of SENDER yet */
static void test_life_start(cl_ctr_cluster_t *cl)
{
	unsigned long refused = cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED);
	uint64_t      mine = cl_ctr_incarnation;

	got[0] = '\0';
	take(cl, 1, 1, "r1");
	take(cl, 1, 2, "r2");
	ok(got[0] == '\0' && cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED) == refused + 2,
	   "life: a broadcast before its sender's heartbeat is not dispatched - it may "
	   "be a recording resent to a node that has just started (%s)", got);
	/* its life began after this node's and its heartbeat says 2 were sent: both
	 * are still this node's to take, as test_order() goes on to do */
	cl_ctr_incarnation = 0;
	cl_ctr_data_note_seq(cl, SENDER, 1, 2);
	cl_ctr_incarnation = mine;
}

static void test_order(cl_ctr_cluster_t *cl)
{
	unsigned long refused = cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED);

	got[0] = '\0';
	take(cl, 1, 1, "p1");
	take(cl, 1, 2, "p2");
	ok(!strcmp(got, "p1 p2"), "order: a life that began after this node's is taken "
	   "from its first number; in sequence, dispatched at once (%s)", got);

	got[0] = '\0';
	take(cl, 1, 4, "p4");
	ok(got[0] == '\0', "order: one ahead of a gap is held");
	take(cl, 1, 3, "p3");
	ok(!strcmp(got, "p3 p4"), "order: the gap filled, both go in order (%s)", got);

	got[0] = '\0';
	take(cl, 1, 4, "p4");
	take(cl, 1, 2, "p2");
	ok(got[0] == '\0', "order: duplicates are dropped");

	/* its sender restarted, as the peer table knows: what the life before still sends */
	set_inc(cl, SENDER, 2);
	take(cl, 1, 5, "old");
	ok(got[0] == '\0' && cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED) == refused + 1,
	   "order: a previous life is dropped (%s)", got);
	set_inc(cl, SENDER, 1);         /* the tests go on in life 1 */
}

static void test_fragments(cl_ctr_cluster_t *cl)
{
	got[0] = '\0';
	take_frag(cl, 5, 0, 3, "ab", 6);
	take_frag(cl, 6, 1, 3, "cd", 6);
	ok(got[0] == '\0', "fragments: nothing until the last");
	take_frag(cl, 7, 2, 3, "ef", 6);
	ok(!strcmp(got, "abcdef"), "fragments: reassembled (%s)", got);

	got[0] = '\0';
	take_frag(cl, 10, 2, 3, "ZZ", 6);
	take_frag(cl, 8, 0, 3, "XX", 6);
	take_frag(cl, 9, 1, 3, "YY", 6);
	ok(!strcmp(got, "XXYYZZ"), "fragments: out of order, reassembled in order (%s)",
	   got);
}

/* @cl keeps 64 for repair; its senders may keep more */
static void test_overflow(cl_ctr_cluster_t *cl)
{
	unsigned long gaps = cl_ctr_data_stat(cl, CL_CTR_DST_GAPS);

	/* next is 11: 11 is lost, 12 waits, then one arrives past this node's window */
	got[0] = '\0';
	take(cl, 1, 12, "p12");
	take(cl, 1, 12 + 64, "far");
	ok(got[0] == '\0' && cl_ctr_data_stat(cl, CL_CTR_DST_GAPS) == gaps,
	   "overflow: past this node's own window nothing is given up (%s)", got);
	take(cl, 1, 11, "p11");
	ok(!strcmp(got, "p11 p12"), "overflow: the repair from a sender keeping more "
	   "fills the gap (%s)", got);
	got[0] = '\0';
	take(cl, 1, 13, "p13");
	ok(!strcmp(got, "p13"), "overflow: the stream goes on (%s)", got);
}

/* @cl keeps 2048 for repair, more than the hold */
static void test_ring(cl_ctr_cluster_t *cl)
{
	unsigned long gaps = cl_ctr_data_stat(cl, CL_CTR_DST_GAPS);

	set_inc(cl, SENDER, 1);
	cl_ctr_data_note_seq(cl, SENDER, 1, 0);
	got[0] = '\0';
	take(cl, 1, 1, "r1");
	take(cl, 1, 3, "r3");
	take(cl, 1, 3 + CL_CTR_DATA_HOLD, "far");
	ok(!strcmp(got, "r1") &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_GAPS) == gaps,
	   "ring: past the hold but within the sender's ring, nothing is given up (%s)",
	   got);
	take(cl, 1, 2, "r2");
	ok(!strcmp(got, "r1 r2 r3"), "ring: the repair fills the gap (%s)", got);
	cl_ctr_data_node_gone(cl, SENDER);     /* nothing left for the tick to give up */
}

/* @cl keeps 2048 for repair; a sender purged while it was only cut off comes back */
static void test_same_life(cl_ctr_cluster_t *cl)
{
	set_inc(cl, SENDER, 7);
	cl_ctr_data_note_seq(cl, SENDER, 7, 0);
	take(cl, 7, 1, "a1");
	take(cl, 7, 2, "a2");
	take(cl, 7, 3, "a3");
	cl_ctr_data_node_gone(cl, SENDER);
	/* heard again in the same life: it sent 4 and 5 meanwhile */
	got[0] = '\0';
	cl_ctr_data_note_seq(cl, SENDER, 7, 5);
	take(cl, 7, 1, "a1");
	take(cl, 7, 3, "a3");
	take(cl, 7, 5, "a5");
	ok(got[0] == '\0', "same life: back after a purge, what it sent before is not "
	   "taken a second time (%s)", got);
	take(cl, 7, 4, "a4");
	ok(!strcmp(got, "a4 a5"), "same life: ... and what it sent while away is "
	   "waited for and taken (%s)", got);
	/* purged again, and this time it restarted */
	cl_ctr_data_node_gone(cl, SENDER);
	got[0] = '\0';
	set_inc(cl, SENDER, 8);
	cl_ctr_data_note_seq(cl, SENDER, 8, 2);
	take(cl, 8, 2, "b2");
	take(cl, 8, 1, "b1");
	ok(!strcmp(got, "b1 b2"), "same life: another life after a purge is taken "
	   "from its first number (%s)", got);
	/* away for longer than its ring keeps: 3 .. 2060 were sent meanwhile */
	cl_ctr_data_node_gone(cl, SENDER);
	got[0] = '\0';
	cl_ctr_data_note_seq(cl, SENDER, 8, 2060);
	take(cl, 8, 3, "b3");
	take(cl, 8, 2061, "b2061");
	ok(!strcmp(got, "b2061"), "same life: away for more than the ring keeps, it "
	   "is taken from its heartbeat's number on (%s)", got);
	cl_ctr_data_node_gone(cl, SENDER);
}

/* a capped sender's waiting messages as they reach the sink: "k<n>", in the order
 * they were parked */
static int cap_n, cap_bad;

static void cap_sink(int sender, int match, const char *bin, int len)
{
	char m[16];
	int  n = snprintf(m, sizeof m, "k%d", cap_n);

	if (sender != SENDER || match >= 0 || len <= n || memcmp(bin, m, n + 1))
		cap_bad++;
	cap_n++;
}

/* TCP message @k of @len bytes, sent after broadcast 1: "k<k>", then zeros */
static int park_k(int cluster_id, int k, char *buf, int len)
{
	struct receive_info ri;

	memset(&ri, 0, sizeof ri);
	memset(buf, 0, len);
	snprintf(buf, len, "k%d", k);
	return cl_ctr_data_park(cluster_id, SENDER, 1, buf, len, &ri);
}

/* waiting TCP messages are capped per sender, by count and by bytes: at the cap a
 * reader's next tick releases them all, at twice the cap no more are kept */
static void test_park_cap(cl_ctr_cluster_t *cl)
{
	static char   big[65536];
	unsigned long late;
	char          m[16];
	int           k, waited;

	/* after a node_gone its heartbeat says nothing was sent yet: a message sent
	 * after broadcast 1 waits, and there is no gap for the tick to give up */
	set_inc(cl, SENDER, 6);
	cl_ctr_data_note_seq(cl, SENDER, 6, 0);
	cl_ctr_data_sink = cap_sink;

	late = cl_ctr_data_stat(cl, CL_CTR_DST_BARRIER_LATE);
	cap_n = cap_bad = waited = 0;
	for (k = 0; k <= CL_CTR_DATA_PARK_MAX; k++)
		waited += park_k(cl->cluster_id, k, m, (int)sizeof m);
	ok(waited == CL_CTR_DATA_PARK_MAX + 1 && !cap_n &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_BARRIER_LATE) == late,
	   "park cap: one past %d waits too - the process that parks dispatches "
	   "nothing (%d)", CL_CTR_DATA_PARK_MAX, cap_n);
	cl_ctr_data_ticks();
	ok(cap_n == CL_CTR_DATA_PARK_MAX + 1 && !cap_bad &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_BARRIER_LATE) ==
	   late + CL_CTR_DATA_PARK_MAX + 1,
	   "park cap: at the cap a reader's next tick releases them all in order, "
	   "counted as late (%d, %d out of order)", cap_n, cap_bad);

	late = cl_ctr_data_stat(cl, CL_CTR_DST_BARRIER_LATE);
	cap_n = cap_bad = waited = 0;
	for (k = 0; k <= 2 * CL_CTR_DATA_PARK_MAX; k++)
		waited += park_k(cl->cluster_id, k, m, (int)sizeof m);
	ok(waited == 2 * CL_CTR_DATA_PARK_MAX && !cap_n &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_BARRIER_LATE) == late + 1,
	   "park cap: at twice the cap a message is not kept - its caller dispatches "
	   "it, counted as late (%d kept)", waited);
	cl_ctr_data_ticks();
	ok(cap_n == 2 * CL_CTR_DATA_PARK_MAX && !cap_bad,
	   "park cap: ... and those kept still go in order (%d, %d out of order)",
	   cap_n, cap_bad);

	/* 64 KB each: 64 of them are the 4 MB, far below the count */
	late = cl_ctr_data_stat(cl, CL_CTR_DST_BARRIER_LATE);
	cap_n = cap_bad = waited = 0;
	for (k = 0; k <= CL_CTR_DATA_PARK_BYTES / (int)sizeof big; k++)
		waited += park_k(cl->cluster_id, k, big, (int)sizeof big);
	cl_ctr_data_ticks();
	ok(waited == 65 && cap_n == 65 && !cap_bad &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_BARRIER_LATE) == late + 65,
	   "park cap: past 4 MB waiting they are all released too (%d waited, %d "
	   "released, %d out of order)", waited, cap_n, cap_bad);

	late = cl_ctr_data_stat(cl, CL_CTR_DST_BARRIER_LATE);
	cap_n = cap_bad = waited = 0;
	for (k = 0; k <= 2 * (CL_CTR_DATA_PARK_BYTES / (int)sizeof big); k++)
		waited += park_k(cl->cluster_id, k, big, (int)sizeof big);
	ok(waited == 128 && !cap_n &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_BARRIER_LATE) == late + 1,
	   "park cap: at 8 MB waiting a message is not kept (%d kept)", waited);
	cl_ctr_data_ticks();
	ok(cap_n == 128 && !cap_bad,
	   "park cap: ... and those kept still go in order (%d, %d out of order)",
	   cap_n, cap_bad);

	cl_ctr_data_sink = sink;
	cl_ctr_data_node_gone(cl, SENDER);
}

/* @cl keeps 2048 for repair; nothing heard of SENDER yet */
static void test_new_life(cl_ctr_cluster_t *cl)
{
	unsigned long refused = cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED);

	got[0] = '\0';
	cl_ctr_data_note_seq(cl, SENDER, 1, 4);
	take(cl, 1, 4, "f4");
	take(cl, 1, 5, "f5");
	ok(!strcmp(got, "f5"), "new life: a sender that was there before this node "
	   "started is taken from its heartbeat's number on (%s)", got);
	got[0] = '\0';
	set_inc(cl, SENDER, 2);
	take(cl, 2, 3, "s3");
	ok(got[0] == '\0' && cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED) == refused + 1,
	   "new life: a restart's broadcast before its heartbeat is not dispatched "
	   "(%s)", got);
	cl_ctr_data_note_seq(cl, SENDER, 2, 3);
	take(cl, 2, 3, "s3");
	ok(got[0] == '\0', "new life: a restart whose heartbeat says 3 were sent "
	   "waits for 1 and 2 (%s)", got);
	take(cl, 2, 1, "s1");
	take(cl, 2, 2, "s2");
	ok(!strcmp(got, "s1 s2 s3"), "new life: ... which its sender still keeps (%s)",
	   got);
	got[0] = '\0';
	set_inc(cl, SENDER, 3);
	cl_ctr_data_note_seq(cl, SENDER, 3, 2);
	take(cl, 3, 1, "h1");
	take(cl, 3, 2, "h2");
	ok(!strcmp(got, "h1 h2"), "new life: a restart first heard in its heartbeat "
	   "(2 sent) still takes 1 and 2 (%s)", got);
	cl_ctr_data_node_gone(cl, SENDER);
	got[0] = '\0';
	set_inc(cl, SENDER, 4);
	cl_ctr_data_note_seq(cl, SENDER, 4, 2);
	take(cl, 4, 2, "g2");
	ok(got[0] == '\0', "new life: after a GOODBYE, its next life (2 sent) waits "
	   "for 1 (%s)", got);
	take(cl, 4, 1, "g1");
	ok(!strcmp(got, "g1 g2"), "new life: ... which can be asked for (%s)", got);
	cl_ctr_data_node_gone(cl, SENDER);
}

static void test_barrier(cl_ctr_cluster_t *cl)
{
	/* next is 14 */
	got[0] = '\0';
	ok(park(cl->cluster_id, 13, "tcp0") == 0,
	   "barrier: what it waits for is out - dispatched now");
	take(cl, 1, 15, "p15");
	ok(park(cl->cluster_id, 15, "tcp1") == 1,
	   "barrier: a broadcast before it is missing - it waits");
	ok(park(cl->cluster_id, 3, "tcp2") == 1,
	   "barrier: behind one that waits, it waits too");
	take(cl, 1, 14, "p14");
	ok(!strcmp(got, "p14 p15 T:tcp1 T:tcp2"),
	   "barrier: broadcasts first, then the TCP messages in arrival order (%s)", got);
	ok(park(cl->cluster_id, (unsigned int)15, "tcp3") == 0,
	   "barrier: nothing waiting, nothing missing - dispatched now");
}

static void test_restart(cl_ctr_cluster_t *cl)
{
	unsigned long refused = cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED);

	got[0] = '\0';
	set_inc(cl, SENDER, 2);
	cl_ctr_data_note_seq(cl, SENDER, 2, 99);
	take(cl, 2, 100, "n100");
	ok(!strcmp(got, "n100"), "restart: a new life whose first numbers its sender "
	   "no longer keeps is taken from its heartbeat's number on (%s)", got);
	take(cl, 1, 16, "old");
	ok(!strcmp(got, "n100") &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED) == refused + 1,
	   "restart: the old life is dropped (%s)", got);

	got[0] = '\0';
	set_inc(cl, SENDER, 3);
	cl_ctr_data_note_seq(cl, SENDER, 3, 500);
	take(cl, 3, 500, "before");
	take(cl, 3, 501, "n501");
	ok(!strcmp(got, "n501"), "heartbeat: tracking starts after the number it "
	   "announced (%s)", got);
}

static void test_incarnation(cl_ctr_cluster_t *cl)
{
	unsigned long refused = cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED);

	/* the table holds 3, the one being heard; next is 503 */
	got[0] = '\0';
	take(cl, 2, 5000, "o5000");
	take(cl, 4, 5000, "n5000");
	ok(got[0] == '\0' && cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED) == refused + 2,
	   "incarnation: an older and a newer one than the table holds are refused (%s)",
	   got);
	cl_ctr_data_note_seq(cl, SENDER, 4, 4999);
	take(cl, 4, 5000, "n5000");
	ok(got[0] == '\0', "incarnation: ... and a heartbeat in it does not start it");
	take(cl, 3, 503, "p503");
	ok(!strcmp(got, "p503"), "incarnation: the table's one goes on (%s)", got);
	got[0] = '\0';
	set_inc(cl, SENDER, 2);
	take(cl, 2, 5000, "early");
	cl_ctr_data_note_seq(cl, SENDER, 2, 4999);
	take(cl, 2, 5000, "o5000");
	take(cl, 2, 5001, "o5001");
	ok(!strcmp(got, "o5000 o5001"), "incarnation: an older one is taken once the "
	   "table holds it and its heartbeat is heard (%s)", got);
}

static void test_node_gone(cl_ctr_cluster_t *cl)
{
	static cl_ctr_cluster_t none;
	unsigned long dropped = cl_ctr_data_stat(cl, CL_CTR_DST_PARK_DROPPED);

	/* incarnation 2, next is 5002 */
	got[0] = '\0';
	take(cl, 2, 5003, "o5003");
	ok(park(cl->cluster_id, 5002, "tcpG") == 1,
	   "node gone: a TCP message waits for the broadcast before it");
	cl_ctr_data_node_gone(cl, SENDER);
	ok(got[0] == '\0' && cl_ctr_data_stat(cl, CL_CTR_DST_PARK_DROPPED) == dropped + 1,
	   "node gone: what waited and what was held are dropped, not released after "
	   "clusterer removed the node (%s)", got);
	got[0] = '\0';
	take(cl, 1, 7, "x7");
	ok(got[0] == '\0', "node gone: no incarnation is taken then but the one the "
	   "table holds (%s)", got);
	set_inc(cl, SENDER, 5);
	cl_ctr_data_note_seq(cl, SENDER, 5, 6999);
	take(cl, 5, 7000, "x7000");
	ok(!strcmp(got, "x7000"), "node gone: the id's next holder starts clean (%s)",
	   got);
	/* a cluster without a broadcast state, or none at all, is left alone */
	memset(&none, 0, sizeof none);
	cl_ctr_data_node_gone(&none, SENDER);
	cl_ctr_data_node_gone(NULL, SENDER);
}

static void test_maintenance(cl_ctr_cluster_t *cl)
{
	unsigned long gaps = cl_ctr_data_stat(cl, CL_CTR_DST_GAPS);

	/* incarnation 5, next is 7001 */
	got[0] = '\0';
	cl->peers->my_maint = CL_CTR_MAINT_FULL;
	take(cl, 5, 7001, "m7001");
	take(cl, 5, 7003, "m7003");
	take(cl, 5, 7002, "m7002");
	ok(got[0] == '\0', "maintenance: at the full level broadcasts are not applied "
	   "(%s)", got);
	cl->peers->my_maint = CL_CTR_MAINT_NONE;
	take(cl, 5, 7002, "m7002");
	take(cl, 5, 7004, "m7004");
	ok(!strcmp(got, "m7004") && cl_ctr_data_stat(cl, CL_CTR_DST_GAPS) == gaps,
	   "maintenance: their numbers were followed - after it the next one is taken "
	   "at once and none before it is asked for again (%s)", got);
}

/* a datagram with a valid clear header for @cl, nothing sealed */
static void dgram_hdr(cl_ctr_cluster_t *cl, char *b, int len)
{
	uint16_t cid = htons((uint16_t)cl->cluster_id);

	memset(b, 0, len);
	b[0] = (char)CL_CTR_WIRE_MAGIC0;
	b[1] = (char)CL_CTR_DATA_TIER;
	memcpy(b + CL_CTR_MAGIC_SZ, &cid, sizeof cid);
}

static void test_size_cap(cl_ctr_cluster_t *cl)
{
	static char   b[CL_CTR_DATA_DGRAM_MAX + 64];
	unsigned long refused = cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED);
	struct sockaddr_in from;

	memset(&from, 0, sizeof from);
	from.sin_family = AF_INET;
	from.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	dgram_hdr(cl, b, sizeof b);
	cl_ctr_data_recv(b, CL_CTR_DATA_DGRAM_MAX, &from);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED) == refused,
	   "size: a datagram of the largest size is not refused for its size");
	cl_ctr_data_recv(b, CL_CTR_DATA_DGRAM_MAX + 1, &from);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED) == refused + 1,
	   "size: one byte over is refused before decryption");
}

/* a BIN message of 64 bytes whose trailer is [cluster id][source][destination] */
static void bin_msg(char *b, int cid, int src)
{
	unsigned int len = 64;
	int          dst = 0;

	memset(b, 0, len);
	memcpy(b, BIN_PACKET_MARKER, BIN_PACKET_MARKER_SIZE);
	memcpy(b + BIN_PACKET_MARKER_SIZE, &len, sizeof len);
	memcpy(b + len - 3 * sizeof(int), &cid, sizeof(int));
	memcpy(b + len - 2 * sizeof(int), &src, sizeof(int));
	memcpy(b + len - sizeof(int), &dst, sizeof(int));
}

static void test_trailer(cl_ctr_cluster_t *cl)
{
	unsigned long refused = cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED);
	char          b[64], w[WRAP_MAX];
	int           n;

	bin_msg(b, cl->cluster_id, SENDER);
	ok(cl_ctr_data_bin_ok(cl->cluster_id, SENDER, b, sizeof b),
	   "trailer: this cluster and the sealed sender - dispatched");
	bin_msg(b, cl->cluster_id + 1, SENDER);
	ok(!cl_ctr_data_bin_ok(cl->cluster_id, SENDER, b, sizeof b),
	   "trailer: another cluster's id - dropped");
	bin_msg(b, cl->cluster_id, SENDER + 1);
	ok(!cl_ctr_data_bin_ok(cl->cluster_id, SENDER, b, sizeof b),
	   "trailer: another source than the sealed sender - dropped");
	bin_msg(b, cl->cluster_id + 1, SENDER);
	ok(!cl_ctr_data_dispatch_ok(cl, SENDER, b, sizeof b) &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED) == refused + 1,
	   "trailer: the dispatch path drops another cluster's id and counts it");
	bin_msg(b, cl->cluster_id, SENDER);
	ok(cl_ctr_data_dispatch_ok(cl, SENDER, b, sizeof b) &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED) == refused + 1,
	   "trailer: ... and passes this cluster's");

	/* incarnation 5, next is 7005: the same check where a broadcast is dispatched */
	refused = cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED);
	got[0] = '\0';
	n = wrap(w, cl->cluster_id + 1, SENDER, "t1", 2);
	cl_ctr_data_accept(cl, SENDER, 5, 7005, 0, 0, 1, w, n);
	n = wrap(w, cl->cluster_id, SENDER + 1, "t2", 2);
	cl_ctr_data_accept(cl, SENDER, 5, 7006, 0, 0, 1, w, n);
	ok(got[0] == '\0' && cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED) == refused + 2,
	   "trailer: a broadcast naming another cluster, or another source than its "
	   "sealed sender, is not dispatched and is counted (%s)", got);
	take(cl, 5, 7007, "t3");
	ok(!strcmp(got, "t3") && cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED) == refused + 2,
	   "trailer: ... and the next one in order is (%s)", got);
}

static void test_tcp_count(cl_ctr_cluster_t *cl)
{
	unsigned long  tcp = cl_ctr_data_stat(cl, CL_CTR_DST_TCP);
	cl_ctr_data_t *d = cl->data;

	cl_ctr_data_count_tcp(cl->cluster_id);
	cl->data = NULL;        /* as with mcast_broadcasts=0, or no broadcast socket */
	cl_ctr_data_count_tcp(cl->cluster_id);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_TCP) == tcp + 2,
	   "tcp: a broadcast sent by TCP is counted with a broadcast state and "
	   "without one (%lu)", cl_ctr_data_stat(cl, CL_CTR_DST_TCP) - tcp);
	cl->data = d;
}

/* the tests below run in a cluster with a key and a socket, on sealed datagrams as
 * the readers take them */

static void be64(char *p, uint64_t v)
{
	int k;

	for (k = 0; k < 8; k++)
		p[k] = (char)(v >> (56 - 8 * k));
}

static uint64_t rd64(const char *p)
{
	uint64_t v = 0;
	int      k;

	for (k = 0; k < 8; k++)
		v = (v << 8) | (unsigned char)p[k];
	return v;
}

/* gives @cl a key and a loopback socket that is its own destination, so that what
 * this node sends - to the group, or to SENDER at 127.0.0.1 - can be read back */
static int keyed_setup(cl_ctr_cluster_t *cl)
{
	struct sockaddr_in a;
	socklen_t          al = sizeof a;
	char               junk[CL_CTR_DATA_OVERHEAD];
	int                s, sz = 1 << 20;

	snprintf(cl->password, sizeof cl->password, "unit-tests-only-not-a-secret");
	cl_ctr_data_set_key(cl);
	cl_ctr_data_round(cl);          /* a key, and no live member without multicast */
	/* this process reads the new key: nothing opens, the key cache is filled */
	memset(junk, 0, sizeof junk);
	cl_ctr_data_open((int)(cl - cl_ctr_clusters), junk, (int)sizeof junk);
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;
	/* room for a burst of 256 repairs sent to itself */
	setsockopt(s, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
	setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s, (struct sockaddr *)&a, sizeof a) < 0 ||
	        getsockname(s, (struct sockaddr *)&a, &al) < 0 ||
	        fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK) < 0) {
		close(s);
		return -1;
	}
	cl->data_sock = s;
	cl->data_port = ntohs(a.sin_port);
	cl->data_dest = a;
	return 0;
}

/* a datagram as @sender would seal it in its incarnation @inc; its length */
static int seal_as(cl_ctr_cluster_t *cl, char *out, int sender, uint64_t inc,
                   uint64_t seq, int type, const char *body, int blen)
{
	uint64_t mine = cl_ctr_incarnation;
	int      n;

	cl_ctr_incarnation = inc;
	n = cl_ctr_data_seal(cl, (int)(cl - cl_ctr_clusters), out, (uint16_t)sender,
	                     seq, type, 0, 0, type == CL_CTR_DATA_T_DATA ? 1 : 0,
	                     body, blen);
	cl_ctr_incarnation = mine;
	return n;
}

/* as a reader takes a datagram that came from @ip; it is opened in place */
static void feed(char *d, int n, const char *ip)
{
	struct sockaddr_in from;

	memset(&from, 0, sizeof from);
	from.sin_family = AF_INET;
	from.sin_addr.s_addr = inet_addr(ip);
	cl_ctr_data_recv(d, n, &from);
}

/* a NACK or GONE of @sender (at @ip, in incarnation 1) numbered @cseq arrives: for
 * node @target, about the one range @a..@b */
static void ctl(cl_ctr_cluster_t *cl, int sender, const char *ip, int type,
                uint64_t cseq, int target, uint64_t a, uint64_t b)
{
	char     d[CL_CTR_DATA_DGRAM_MAX], body[3 + 16];
	uint16_t t = htons((uint16_t)target);
	int      n;

	memcpy(body, &t, 2);
	body[2] = 1;
	be64(body + 3, a);
	be64(body + 11, b);
	n = seal_as(cl, d, sender, 1, cseq, type, body, (int)sizeof body);
	if (n > 0)
		feed(d, n, ip);
}

/* what this node sent since the last call, read back from its socket: how many
 * broadcasts or repairs, how many GONE, and the last GONE's target and first range */
struct sent {
	int      data, gone, target;
	uint64_t from, to, cseq;
};

static void sent_read(cl_ctr_cluster_t *cl, struct sent *s)
{
	char d[CL_CTR_DATA_DGRAM_MAX + 64], *p;
	int  n, plen;

	memset(s, 0, sizeof *s);
	while ((n = (int)recv(cl->data_sock, d, sizeof d, 0)) > 0) {
		plen = cl_ctr_data_open((int)(cl - cl_ctr_clusters), d, n);
		if (plen < CL_CTR_DATA_PLAIN_SZ)
			continue;
		p = d + CL_CTR_DATA_HDR_SZ;
		if (p[18] == CL_CTR_DATA_T_DATA) {
			s->data++;
		} else if (p[18] == CL_CTR_DATA_T_GONE &&
		        plen >= CL_CTR_DATA_PLAIN_SZ + 3 + 16) {
			s->gone++;
			s->cseq = rd64(p + 10);
			p += CL_CTR_DATA_PLAIN_SZ;
			s->target = ((unsigned char)p[0] << 8) | (unsigned char)p[1];
			s->from = rd64(p + 3);
			s->to = rd64(p + 11);
		}
	}
}

/* the numbers SENDER gives its NACKs and GONEs, rising as on a real node */
static uint64_t ctl_no;

/* @cl has a key; nothing was heard of SENDER or CC_SENDER yet */
static void test_source(cl_ctr_cluster_t *cl)
{
	unsigned long refused = cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED);
	char          m[WRAP_MAX], d[CL_CTR_DATA_DGRAM_MAX], copy[CL_CTR_DATA_DGRAM_MAX];
	int           n, len;

	cl_ctr_data_note_seq(cl, SENDER, 1, 0);
	n = wrap(m, cl->cluster_id, SENDER, "s1", 2);
	len = seal_as(cl, d, SENDER, 1, 1, CL_CTR_DATA_T_DATA, m, n);
	ok(len > 0, "source: a broadcast sealed with the cluster's key (%d bytes)", len);
	if (len < 0)
		len = 0;
	memcpy(copy, d, len);
	got[0] = '\0';
	feed(copy, len, "127.0.0.2");
	ok(got[0] == '\0' && cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED) == refused + 1,
	   "source: sealed right, but from another address than that of the node it "
	   "names, it is refused (%s)", got);
	feed(d, len, "127.0.0.1");
	ok(!strcmp(got, "s1"), "source: from that node's own address it is dispatched "
	   "(%s)", got);

	refused = cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED);
	ctl(cl, CC_SENDER, "127.0.0.2", CL_CTR_DATA_T_NACK, 1, SELF, 1, 1);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED) == refused + 1,
	   "life: a NACK before its sender's heartbeat is refused");
}

/* @cl has a key; SENDER is in incarnation 1, next is 2 */
static void test_far_behind(cl_ctr_cluster_t *cl)
{
	unsigned long gaps = cl_ctr_data_stat(cl, CL_CTR_DST_GAPS);
	unsigned long reports = cl_ctr_data_stat(cl, CL_CTR_DST_LOSS_REPORTS);
	unsigned long refused = cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED);

	/* its heartbeat says 5000 were sent; it answers GONE to all this node asks */
	cl_ctr_data_note_seq(cl, SENDER, 1, 5000);
	ctl(cl, SENDER, "127.0.0.1", CL_CTR_DATA_T_GONE, ++ctl_no, SELF, 2, 1025);
	ctl(cl, SENDER, "127.0.0.1", CL_CTR_DATA_T_GONE, ++ctl_no, SELF, 1026, 2049);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_GAPS) == gaps + 2048 &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_LOSS_REPORTS) == reports + 1,
	   "far behind: a second skip while still behind is counted, not reported "
	   "again (%lu lost, %lu reports)",
	   cl_ctr_data_stat(cl, CL_CTR_DST_GAPS) - gaps,
	   cl_ctr_data_stat(cl, CL_CTR_DST_LOSS_REPORTS) - reports);
	ctl(cl, SENDER, "127.0.0.1", CL_CTR_DATA_T_GONE, ctl_no, SELF, 2050, 3000);
	ctl(cl, SENDER, "127.0.0.1", CL_CTR_DATA_T_GONE, 0, SELF, 2050, 3000);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_GAPS) == gaps + 2048 &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED) == refused + 2,
	   "control: a GONE numbered as one taken before, or not numbered after "
	   "numbered ones, is refused (%lu)",
	   cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED) - refused);
	ctl(cl, SENDER, "127.0.0.1", CL_CTR_DATA_T_GONE, ++ctl_no, SELF, 2050, 5000);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_GAPS) == gaps + 4999 &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_LOSS_REPORTS) == reports + 1,
	   "far behind: caught up, with one report for all of it (%lu lost, %lu "
	   "reports)", cl_ctr_data_stat(cl, CL_CTR_DST_GAPS) - gaps,
	   cl_ctr_data_stat(cl, CL_CTR_DST_LOSS_REPORTS) - reports);
	cl_ctr_data_note_seq(cl, SENDER, 1, 5010);
	ctl(cl, SENDER, "127.0.0.1", CL_CTR_DATA_T_GONE, ++ctl_no, SELF, 5001, 5010);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_GAPS) == gaps + 5009 &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_LOSS_REPORTS) == reports + 2,
	   "far behind: a loss after it had caught up is reported (%lu reports)",
	   cl_ctr_data_stat(cl, CL_CTR_DST_LOSS_REPORTS) - reports);

	/* behind again: 5011 .. 5015 are reported, then what was sent after that
	 * report is lost too before this node has caught up */
	cl_ctr_data_note_seq(cl, SENDER, 1, 5020);
	ctl(cl, SENDER, "127.0.0.1", CL_CTR_DATA_T_GONE, ++ctl_no, SELF, 5011, 5015);
	cl_ctr_data_note_seq(cl, SENDER, 1, 5030);
	ctl(cl, SENDER, "127.0.0.1", CL_CTR_DATA_T_GONE, ++ctl_no, SELF, 5016, 5025);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_LOSS_REPORTS) == reports + 3,
	   "far behind: what is lost of the numbers sent after the report waits for "
	   "this node to catch up (%lu reports)",
	   cl_ctr_data_stat(cl, CL_CTR_DST_LOSS_REPORTS) - reports);
	ctl(cl, SENDER, "127.0.0.1", CL_CTR_DATA_T_GONE, ++ctl_no, SELF, 5026, 5030);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_GAPS) == gaps + 5029 &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_LOSS_REPORTS) == reports + 4,
	   "far behind: ... and is then reported once (%lu lost, %lu reports)",
	   cl_ctr_data_stat(cl, CL_CTR_DST_GAPS) - gaps,
	   cl_ctr_data_stat(cl, CL_CTR_DST_LOSS_REPORTS) - reports);

	/* CC_SENDER runs a build that numbers none of them */
	cl_ctr_data_note_seq(cl, CC_SENDER, 1, 10);
	cl_ctr_data_note_seq(cl, CC_SENDER, 1, 20);
	gaps = cl_ctr_data_stat(cl, CL_CTR_DST_GAPS);
	refused = cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED);
	ctl(cl, CC_SENDER, "127.0.0.2", CL_CTR_DATA_T_GONE, 0, SELF, 11, 12);
	ctl(cl, CC_SENDER, "127.0.0.2", CL_CTR_DATA_T_GONE, 0, SELF, 13, 14);
	ctl(cl, CC_SENDER, "127.0.0.2", CL_CTR_DATA_T_GONE, 7, SELF, 15, 16);
	ctl(cl, CC_SENDER, "127.0.0.2", CL_CTR_DATA_T_GONE, 0, SELF, 17, 20);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_GAPS) == gaps + 6 &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED) == refused + 1,
	   "control: an unnumbered GONE is taken from a life that has numbered none, "
	   "and no more once it has (%lu lost, %lu refused)",
	   cl_ctr_data_stat(cl, CL_CTR_DST_GAPS) - gaps,
	   cl_ctr_data_stat(cl, CL_CTR_DST_REFUSED) - refused);
	cl_ctr_data_node_gone(cl, CC_SENDER);   /* no gap is left for a tick */
}

/* @cl has a key and keeps 512 for repair; this node is the sender, SENDER asks */
static void test_nack(cl_ctr_cluster_t *cl)
{
	unsigned long sent = cl_ctr_data_stat(cl, CL_CTR_DST_SENT);
	unsigned long errs = cl_ctr_data_stat(cl, CL_CTR_DST_SEND_ERRORS);
	unsigned long rep;
	struct sent   s;
	char          m[WRAP_MAX];
	str           bin;
	long long     sec = 0;
	int           k, tries, sock, rc;

	/* it broadcast 600: the ring keeps 89 .. 600 */
	bin.s = m;
	for (k = 1; k <= 600; k++) {
		bin.len = wrap(m, cl->cluster_id, SELF, "b", 1);
		cl_ctr_data_send(cl->cluster_id, &bin, 0);
		if (!(k % 64))
			sent_read(cl, &s);
	}
	sent_read(cl, &s);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_SENT) == sent + 600 &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_SEND_ERRORS) == errs,
	   "nack: 600 broadcasts went out (%lu, %lu refused by the kernel)",
	   cl_ctr_data_stat(cl, CL_CTR_DST_SENT) - sent,
	   cl_ctr_data_stat(cl, CL_CTR_DST_SEND_ERRORS) - errs);

	rep = cl_ctr_data_stat(cl, CL_CTR_DST_REPAIRS);
	ctl(cl, SENDER, "127.0.0.1", CL_CTR_DATA_T_NACK, ++ctl_no, SELF, 1, 50);
	sent_read(cl, &s);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_REPAIRS) == rep && !s.data && s.gone == 1 &&
	   s.target == SENDER && s.from == 1 && s.to == 50 && s.cseq,
	   "nack: what has left the ring is answered with one numbered GONE for all "
	   "of it (%d resent, %d GONE for %llu..%llu)", s.data, s.gone,
	   (unsigned long long)s.from, (unsigned long long)s.to);
	ctl(cl, SENDER, "127.0.0.1", CL_CTR_DATA_T_NACK, ++ctl_no, SELF, 80, 95);
	sent_read(cl, &s);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_REPAIRS) == rep + 7 && s.data == 7 &&
	   s.gone == 1 && s.from == 80 && s.to == 88,
	   "nack: of a range across the ring's edge the part still kept is resent, "
	   "the rest is GONE (%d resent, %d GONE for %llu..%llu)", s.data, s.gone,
	   (unsigned long long)s.from, (unsigned long long)s.to);
	ctl(cl, SENDER, "127.0.0.1", CL_CTR_DATA_T_NACK, ++ctl_no, SELF, 89, 600);
	sent_read(cl, &s);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_REPAIRS) == rep + 7 + CL_CTR_DATA_RETX_MAX &&
	   !s.gone, "nack: one NACK is answered with %d repairs at most (%lu)",
	   CL_CTR_DATA_RETX_MAX, cl_ctr_data_stat(cl, CL_CTR_DST_REPAIRS) - rep - 7);

	/* this node's id changes: what it sent as SELF cannot be repaired by SELF + 1 */
	cl_ctr_data_self_test = SELF + 1;
	rep = cl_ctr_data_stat(cl, CL_CTR_DST_REPAIRS);
	ctl(cl, SENDER, "127.0.0.1", CL_CTR_DATA_T_NACK, ++ctl_no, SELF + 1, 590, 600);
	sent_read(cl, &s);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_REPAIRS) == rep && !s.data && s.gone == 1 &&
	   s.from == 590 && s.to == 600,
	   "nack: what was sent under a former id is answered with GONE, not resent "
	   "(%d resent, %d GONE for %llu..%llu)", s.data, s.gone,
	   (unsigned long long)s.from, (unsigned long long)s.to);
	cl_ctr_data_self_test = SELF;

	/* the kernel refuses a send */
	sent = cl_ctr_data_stat(cl, CL_CTR_DST_SENT);
	bin.len = wrap(m, cl->cluster_id, SELF, "e", 1);
	sock = cl->data_sock;
	cl->data_sock = -1;
	rc = cl_ctr_data_send(cl->cluster_id, &bin, 0);
	cl->data_sock = sock;
	ok(rc == 0 && cl_ctr_data_stat(cl, CL_CTR_DST_SENT) == sent &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_SEND_ERRORS) == errs + 1,
	   "send: a broadcast the kernel refused is counted in mcast_send_errors, not "
	   "in mcast_sent (%lu)", cl_ctr_data_stat(cl, CL_CTR_DST_SEND_ERRORS) - errs);
	rep = cl_ctr_data_stat(cl, CL_CTR_DST_REPAIRS);
	ctl(cl, SENDER, "127.0.0.1", CL_CTR_DATA_T_NACK, ++ctl_no, SELF, 601, 601);
	sent_read(cl, &s);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_REPAIRS) == rep + 1 && s.data == 1,
	   "send: ... and it is kept all the same: a NACK has it repaired (%d)", s.data);

	/* 4096 repairs a second to one node: within one second the 17th NACK for 256
	 * gets none; tried again if the second turned in between */
	for (tries = 0; tries < 3; tries++) {
		sec = cl_ctr_now_ms() / 1000;
		while (cl_ctr_now_ms() / 1000 == sec)
			usleep(1000);
		sec = cl_ctr_now_ms() / 1000;
		rep = cl_ctr_data_stat(cl, CL_CTR_DST_REPAIRS);
		for (k = 0; k < 17; k++) {
			ctl(cl, SENDER, "127.0.0.1", CL_CTR_DATA_T_NACK, ++ctl_no, SELF,
			    100, 601);
			sent_read(cl, &s);
		}
		if (cl_ctr_now_ms() / 1000 == sec)
			break;
	}
	ok(tries < 3 &&
	   cl_ctr_data_stat(cl, CL_CTR_DST_REPAIRS) == rep + CL_CTR_DATA_REPAIR_RATE,
	   "nack: %d repairs a second to one node and no more (%lu)",
	   CL_CTR_DATA_REPAIR_RATE, cl_ctr_data_stat(cl, CL_CTR_DST_REPAIRS) - rep);
}

/* a TCP message arriving while the broadcast it waits for is being dispatched */
static int inflight_cid, inflight_rc = -1;

static void sink_inflight(int sender, int match, const char *bin, int len)
{
	if (match >= 0 && len == WRAP_HDR + 4 + WRAP_TRL &&
	        !memcmp(bin + WRAP_HDR, "q502", 4)) {
		inflight_rc = park(inflight_cid, 502, "tcpI");
		if (inflight_rc == 0)
			sink(SENDER, -1, "tcpI", 4);    /* its caller dispatches it now */
	}
	sink(sender, match, bin, len);
}

static void test_barrier_in_flight(cl_ctr_cluster_t *cl)
{
	/* next is 502 */
	got[0] = '\0';
	inflight_cid = cl->cluster_id;
	cl_ctr_data_sink = sink_inflight;
	take(cl, 3, 502, "q502");
	cl_ctr_data_sink = sink;
	ok(inflight_rc == 1, "barrier: a TCP message waits while the broadcast "
	   "before it is being dispatched");
	ok(!strcmp(got, "q502 T:tcpI"), "barrier: it goes right after that broadcast "
	   "(%s)", got);
}

/* readers and the tick at once, as the broadcast processes run them */
#define CC_N       20000        /* broadcasts 1..CC_N */
#define CC_FEEDERS 3            /* each takes them all, shuffled 8 at a time */
#define CC_AHEAD   512          /* as a sender's window keeps them, within the hold */
#define CC_TCP     200          /* TCP message k waits for broadcast (k+1)*100 */

struct cc_log {
	int      n, done, kept;
	uint32_t seq[CC_N];
	int      tcp_at[CC_TCP], tcp_n[CC_TCP];
};
static struct cc_log *cc;

static void cc_sink(int sender, int match, const char *bin, int len)
{
	uint32_t v;
	int      i;

	if (sender != CC_SENDER)
		return;
	if (match >= 0) {
		bin += WRAP_HDR;
		len -= WRAP_HDR + WRAP_TRL;
	}
	if (len != (int)sizeof v)
		return;
	memcpy(&v, bin, sizeof v);
	if (match < 0) {
		if (v < CC_TCP) {
			cc->tcp_at[v] = __atomic_load_n(&cc->n, __ATOMIC_SEQ_CST);
			__atomic_fetch_add(&cc->tcp_n[v], 1, __ATOMIC_SEQ_CST);
		}
		return;
	}
	i = __atomic_fetch_add(&cc->n, 1, __ATOMIC_SEQ_CST);
	if (i < CC_N)
		cc->seq[i] = v;
}

static void cc_feed(cl_ctr_cluster_t *cl, unsigned int seed)
{
	uint32_t  s[8], t;
	int       base, i, j, n;
	char      b[WRAP_MAX];
	long long deadline;

	for (base = 1; base <= CC_N; base += 8) {
		/* no repair here: a feeder past the hold would lose what it drops */
		deadline = cl_ctr_now_ms() + 3000;
		while (base > __atomic_load_n(&cc->n, __ATOMIC_SEQ_CST) + CC_AHEAD &&
		        cl_ctr_now_ms() < deadline)
			sched_yield();
		for (i = 0; i < 8; i++)
			s[i] = base + i;
		for (i = 7; i > 0; i--) {
			j = rand_r(&seed) % (i + 1);
			t = s[i]; s[i] = s[j]; s[j] = t;
		}
		for (i = 0; i < 8; i++) {
			n = wrap(b, cl->cluster_id, CC_SENDER, (const char *)&s[i],
			         (int)sizeof s[i]);
			cl_ctr_data_accept(cl, CC_SENDER, 1, s[i], 0, 0, 1, b, n);
		}
		if (!(rand_r(&seed) % 64))
			sched_yield();
	}
}

static void cc_park(int cluster_id)
{
	struct receive_info ri;
	uint32_t k, barrier;
	long     spins;
	char     b[sizeof(uint32_t)];

	memset(&ri, 0, sizeof ri);
	for (k = 0; k < CC_TCP; k++) {
		barrier = (k + 1) * (CC_N / CC_TCP);
		/* arrive about when its broadcast does: before, during or just after */
		for (spins = 0; spins < 2000000 &&
		        __atomic_load_n(&cc->n, __ATOMIC_SEQ_CST) + 20 < (int)barrier; spins++)
			sched_yield();
		memcpy(b, &k, sizeof b);
		if (cl_ctr_data_park(cluster_id, CC_SENDER, barrier, b, sizeof b, &ri))
			__atomic_fetch_add(&cc->kept, 1, __ATOMIC_SEQ_CST);
		else
			cc_sink(CC_SENDER, -1, b, sizeof b);    /* its caller dispatches it now */
	}
}

static void cc_tick(void)
{
	int i, after = 0;

	for (i = 0; i < 20000 && after < 50; i++) {
		cl_ctr_data_ticks();
		usleep(1000);
		if (__atomic_load_n(&cc->done, __ATOMIC_SEQ_CST))
			after++;
	}
}

/* 1 when @p exited with 0 */
static int cc_wait(pid_t p)
{
	pid_t r;
	int   st;

	do
		r = waitpid(p, &st, 0);
	while (r < 0 && errno == EINTR);
	return r == p && WIFEXITED(st) && !WEXITSTATUS(st);
}

static void test_concurrent(cl_ctr_cluster_t *cl)
{
	unsigned long gaps = cl_ctr_data_stat(cl, CL_CTR_DST_GAPS);
	unsigned long late = cl_ctr_data_stat(cl, CL_CTR_DST_BARRIER_LATE);
	pid_t         pid[CC_FEEDERS + 2];
	int           i, k, n, ran = 1, order = 1, once = 1, before = 0;

	cc = shm_malloc(sizeof *cc);
	if (!cc) {
		ok(0, "concurrent: shm for the log");
		return;
	}
	memset(cc, 0, sizeof *cc);
	cl_ctr_data_sink = cc_sink;
	set_inc(cl, CC_SENDER, 1);
	/* its heartbeat: nothing sent yet, so tracking starts at 1 */
	cl_ctr_data_note_seq(cl, CC_SENDER, 1, 0);
	for (i = 0; i < CC_FEEDERS + 2; i++) {
		pid[i] = fork();
		if (pid[i] == 0) {
			if (i < CC_FEEDERS)
				cc_feed(cl, 1000 + i);
			else if (i == CC_FEEDERS)
				cc_park(cl->cluster_id);
			else
				cc_tick();
			_exit(0);
		}
		ran &= pid[i] > 0;
	}
	for (i = 0; i <= CC_FEEDERS; i++)
		if (pid[i] > 0 && !cc_wait(pid[i]))
			ran = 0;
	__atomic_store_n(&cc->done, 1, __ATOMIC_SEQ_CST);
	if (pid[CC_FEEDERS + 1] > 0 && !cc_wait(pid[CC_FEEDERS + 1]))
		ran = 0;
	cl_ctr_data_sink = sink;

	n = cc->n;
	for (i = 0; i < n && i < CC_N; i++)
		order &= cc->seq[i] == (uint32_t)(i + 1);
	for (k = 0; k < CC_TCP; k++) {
		once &= cc->tcp_n[k] == 1;
		before += cc->tcp_at[k] < (k + 1) * (CC_N / CC_TCP);
	}
	ok(ran, "concurrent: %d readers, one TCP sender and the tick ran to the end",
	   CC_FEEDERS);
	ok(n == CC_N, "concurrent: every broadcast dispatched once (%d of %d)", n, CC_N);
	ok(order, "concurrent: in the order sent");
	ok(once, "concurrent: every TCP message dispatched once");
	ok((unsigned long)before <= cl_ctr_data_stat(cl, CL_CTR_DST_BARRIER_LATE) - late,
	   "concurrent: each TCP message after its broadcast, unless it waited out its "
	   "time (%d before it)", before);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_GAPS) == gaps, "concurrent: nothing given up");
	diag("concurrent: %d of %d TCP messages waited; gaps %lu, late %lu", cc->kept,
	     CC_TCP, cl_ctr_data_stat(cl, CL_CTR_DST_GAPS) - gaps,
	     cl_ctr_data_stat(cl, CL_CTR_DST_BARRIER_LATE) - late);
	shm_free(cc);
}

void test_data(void)
{
	static cl_ctr_cluster_t cl, cl2, cl3;
	cl_ctr_cluster_t saved = cl_ctr_clusters[0], saved2 = cl_ctr_clusters[1];
	cl_ctr_cluster_t saved3 = cl_ctr_clusters[2];
	int              saved_n = cl_ctr_cluster_count;

	test_widen();

	memset(&cl, 0, sizeof cl);
	cl.cluster_id = 77;
	cl.data_sock = -1;
	cl.peers = peers_alloc();
	if (!cl.peers || cl_ctr_data_alloc(&cl, 64) < 0) {
		ok(0, "broadcast state allocated");
		return;
	}
	memset(&cl2, 0, sizeof cl2);
	cl2.cluster_id = 78;
	cl2.data_sock = -1;
	cl2.peers = peers_alloc();
	if (!cl2.peers || cl_ctr_data_alloc(&cl2, 2048) < 0) {
		ok(0, "broadcast state allocated (2048)");
		return;
	}
	memset(&cl3, 0, sizeof cl3);
	cl3.cluster_id = 79;
	cl3.data_sock = -1;
	cl3.peers = peers_alloc();
	if (!cl3.peers || cl_ctr_data_alloc(&cl3, 512) < 0) {
		ok(0, "broadcast state allocated (512)");
		return;
	}
	cl_ctr_clusters[0] = cl;        /* park() finds clusters by id */
	cl_ctr_clusters[1] = cl2;
	cl_ctr_clusters[2] = cl3;
	cl_ctr_cluster_count = 3;
	cl_ctr_data_sink = sink;

	test_life_start(&cl_ctr_clusters[0]);
	test_order(&cl_ctr_clusters[0]);
	test_fragments(&cl_ctr_clusters[0]);
	test_overflow(&cl_ctr_clusters[0]);
	test_new_life(&cl_ctr_clusters[1]);
	test_ring(&cl_ctr_clusters[1]);
	test_same_life(&cl_ctr_clusters[1]);
	test_barrier(&cl_ctr_clusters[0]);
	test_restart(&cl_ctr_clusters[0]);
	test_barrier_in_flight(&cl_ctr_clusters[0]);
	test_incarnation(&cl_ctr_clusters[0]);
	test_node_gone(&cl_ctr_clusters[0]);
	test_maintenance(&cl_ctr_clusters[0]);
	test_size_cap(&cl_ctr_clusters[0]);
	test_trailer(&cl_ctr_clusters[0]);
	test_tcp_count(&cl_ctr_clusters[0]);
	if (keyed_setup(&cl_ctr_clusters[2]) < 0) {
		ok(0, "a key and a loopback socket for the third cluster");
	} else {
		cl_ctr_data_self_test = SELF;
		test_source(&cl_ctr_clusters[2]);
		test_far_behind(&cl_ctr_clusters[2]);
		test_nack(&cl_ctr_clusters[2]);
		cl_ctr_data_self_test = 0;
		close(cl_ctr_clusters[2].data_sock);
		cl_ctr_clusters[2].data_sock = -1;
	}
	/* these run the tick: only once no sender is left with a gap to give up */
	test_park_cap(&cl_ctr_clusters[1]);
	test_concurrent(&cl_ctr_clusters[0]);

	cl_ctr_data_sink = NULL;
	cl_ctr_data_skew_ms = 0;
	cl_ctr_clusters[0] = saved;
	cl_ctr_clusters[1] = saved2;
	cl_ctr_clusters[2] = saved3;
	cl_ctr_cluster_count = saved_n;
	peers_free(cl.peers);
	peers_free(cl2.peers);
	peers_free(cl3.peers);
}
