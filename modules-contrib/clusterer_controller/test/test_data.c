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

#define SENDER 7

/* what reached the sink, as one string: "p1 p2 T:x ..." (T: a released TCP message) */
static char got[1024];

static void sink(int sender, int match, const char *bin, int len)
{
	size_t n = strlen(got);

	if (sender != SENDER)
		len = 0;
	snprintf(got + n, sizeof got - n, "%s%s%.*s", n ? " " : "",
	         match < 0 ? "T:" : "", len, bin);
}

static void take(cl_ctr_cluster_t *cl, uint64_t inc, uint64_t seq, const char *s)
{
	char b[64];
	int  len = (int)strlen(s);

	memcpy(b, s, len);
	cl_ctr_data_accept(cl, SENDER, inc, seq, 0, 0, 1, b, len);
}

static void take_frag(cl_ctr_cluster_t *cl, uint64_t seq, int fi, int fn,
                      const char *s)
{
	char b[64];
	int  len = (int)strlen(s);

	memcpy(b, s, len);
	cl_ctr_data_accept(cl, SENDER, 1, seq, 0, fi, fn, b, len);
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

static void test_order(cl_ctr_cluster_t *cl)
{
	got[0] = '\0';
	take(cl, 1, 1, "p1");
	take(cl, 1, 2, "p2");
	ok(!strcmp(got, "p1 p2"), "order: in sequence, dispatched at once (%s)", got);

	got[0] = '\0';
	take(cl, 1, 4, "p4");
	ok(got[0] == '\0', "order: one ahead of a gap is held");
	take(cl, 1, 3, "p3");
	ok(!strcmp(got, "p3 p4"), "order: the gap filled, both go in order (%s)", got);

	got[0] = '\0';
	take(cl, 1, 4, "p4");
	take(cl, 1, 2, "p2");
	ok(got[0] == '\0', "order: duplicates are dropped");

	take(cl, 0, 5, "old");
	ok(got[0] == '\0', "order: a previous life is dropped");
}

static void test_fragments(cl_ctr_cluster_t *cl)
{
	got[0] = '\0';
	take_frag(cl, 5, 0, 3, "ab");
	take_frag(cl, 6, 1, 3, "cd");
	ok(got[0] == '\0', "fragments: nothing until the last");
	take_frag(cl, 7, 2, 3, "ef");
	ok(!strcmp(got, "abcdef"), "fragments: reassembled (%s)", got);

	got[0] = '\0';
	take_frag(cl, 10, 2, 3, "ZZ");
	take_frag(cl, 8, 0, 3, "XX");
	take_frag(cl, 9, 1, 3, "YY");
	ok(!strcmp(got, "XXYYZZ"), "fragments: out of order, reassembled in order (%s)",
	   got);
}

static void test_overflow(cl_ctr_cluster_t *cl)
{
	unsigned long gaps = cl_ctr_data_stat(cl, CL_CTR_DST_GAPS);

	/* next is 11, the window 64: 11 is lost, 12 waits, then one arrives that
	 * puts 11 and 12 out of the sender's ring */
	got[0] = '\0';
	take(cl, 1, 12, "p12");
	take(cl, 1, 12 + 64, "far");
	ok(!strcmp(got, "p12"), "overflow: what left the sender's ring is given up, "
	   "what was held goes (%s)", got);
	ok(cl_ctr_data_stat(cl, CL_CTR_DST_GAPS) == gaps + 1,
	   "overflow: the loss is counted");
	got[0] = '\0';
	take(cl, 1, 13, "p13");
	ok(!strcmp(got, "p13"), "overflow: the stream goes on (%s)", got);
}

/* @cl keeps 2048 for repair, more than the hold */
static void test_ring(cl_ctr_cluster_t *cl)
{
	unsigned long gaps = cl_ctr_data_stat(cl, CL_CTR_DST_GAPS);

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

/* @cl keeps 2048 for repair; nothing tracked of SENDER */
static void test_new_life(cl_ctr_cluster_t *cl)
{
	got[0] = '\0';
	take(cl, 1, 5, "f5");
	ok(!strcmp(got, "f5"), "new life: a sender first heard of is tracked from "
	   "where it is heard (%s)", got);
	got[0] = '\0';
	take(cl, 2, 3, "s3");
	ok(got[0] == '\0', "new life: a restart first heard at 3 waits for 1 and 2");
	take(cl, 2, 1, "s1");
	take(cl, 2, 2, "s2");
	ok(!strcmp(got, "s1 s2 s3"), "new life: ... which its sender still keeps (%s)",
	   got);
	got[0] = '\0';
	cl_ctr_data_note_seq(cl, SENDER, 3, 2);
	take(cl, 3, 1, "h1");
	take(cl, 3, 2, "h2");
	ok(!strcmp(got, "h1 h2"), "new life: a restart first heard in its heartbeat "
	   "(2 sent) still takes 1 and 2 (%s)", got);
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
	got[0] = '\0';
	take(cl, 2, 100, "n100");
	ok(!strcmp(got, "n100"), "restart: a new life starts where it is first heard "
	   "(%s)", got);
	take(cl, 1, 16, "old");
	ok(!strcmp(got, "n100"), "restart: the old life is dropped");

	got[0] = '\0';
	cl_ctr_data_note_seq(cl, SENDER, 3, 500);
	take(cl, 3, 500, "before");
	take(cl, 3, 501, "n501");
	ok(!strcmp(got, "n501"), "heartbeat: tracking starts after the number it "
	   "announced (%s)", got);
}

static void test_older_life(cl_ctr_cluster_t *cl)
{
	/* incarnation 3 is being heard, next is 503 */
	got[0] = '\0';
	take(cl, 2, 5000, "o5000");
	ok(got[0] == '\0', "incarnation: an older one is refused while the newer is "
	   "heard");
	cl_ctr_data_note_seq(cl, SENDER, 2, 4999);
	take(cl, 2, 5000, "o5000");
	ok(got[0] == '\0', "incarnation: ... and its heartbeat does not start it");
	cl_ctr_data_skew_ms += CL_CTR_DATA_INC_STALE_MS + 1000;
	take(cl, 2, 5000, "o5000");
	take(cl, 2, 5001, "o5001");
	ok(!strcmp(got, "o5000 o5001"), "incarnation: an older one is taken once the "
	   "newer has been quiet %d s (%s)", CL_CTR_DATA_INC_STALE_MS / 1000, got);
}

static void test_node_gone(cl_ctr_cluster_t *cl)
{
	static cl_ctr_cluster_t none;

	/* incarnation 2, next is 5002 */
	got[0] = '\0';
	take(cl, 2, 5003, "o5003");
	ok(park(cl->cluster_id, 5002, "tcpG") == 1,
	   "node gone: a TCP message waits for the broadcast before it");
	cl_ctr_data_node_gone(cl, SENDER);
	ok(!strcmp(got, "T:tcpG"), "node gone: what waited goes, what was held is "
	   "dropped (%s)", got);
	got[0] = '\0';
	take(cl, 1, 7, "x7");
	ok(!strcmp(got, "x7"), "node gone: the id's next holder starts clean, older "
	   "incarnation or not (%s)", got);
	memset(&none, 0, sizeof none);
	cl_ctr_data_node_gone(&none, SENDER);
	cl_ctr_data_node_gone(NULL, SENDER);
	ok(1, "node gone: a cluster without a broadcast state is left alone");
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
	char b[64];

	bin_msg(b, cl->cluster_id, SENDER);
	ok(cl_ctr_data_bin_ok(cl->cluster_id, SENDER, b, sizeof b),
	   "trailer: this cluster and the sealed sender - dispatched");
	bin_msg(b, cl->cluster_id + 1, SENDER);
	ok(!cl_ctr_data_bin_ok(cl->cluster_id, SENDER, b, sizeof b),
	   "trailer: another cluster's id - dropped");
	bin_msg(b, cl->cluster_id, SENDER + 1);
	ok(!cl_ctr_data_bin_ok(cl->cluster_id, SENDER, b, sizeof b),
	   "trailer: another source than the sealed sender - dropped");
}

/* a TCP message arriving while the broadcast it waits for is being dispatched */
static int inflight_cid, inflight_rc = -1;

static void sink_inflight(int sender, int match, const char *bin, int len)
{
	if (match >= 0 && len == 4 && !memcmp(bin, "q502", 4)) {
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
#define CC_SENDER  9
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

	if (sender != CC_SENDER || len != (int)sizeof v)
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
	int       base, i, j;
	char      b[sizeof(uint32_t)];
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
			memcpy(b, &s[i], sizeof b);
			cl_ctr_data_accept(cl, CC_SENDER, 1, s[i], 0, 0, 1, b, sizeof b);
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
	/* its heartbeat: nothing sent yet, so tracking starts at 1, not at the
	 * first number a shuffled reader happens to take */
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
	static cl_ctr_cluster_t cl, cl2;
	cl_ctr_cluster_t saved = cl_ctr_clusters[0], saved2 = cl_ctr_clusters[1];
	int              saved_n = cl_ctr_cluster_count;

	test_widen();

	memset(&cl, 0, sizeof cl);
	cl.cluster_id = 77;
	if (cl_ctr_data_alloc(&cl, 64) < 0) {
		ok(0, "broadcast state allocated");
		return;
	}
	memset(&cl2, 0, sizeof cl2);
	cl2.cluster_id = 78;
	if (cl_ctr_data_alloc(&cl2, 2048) < 0) {
		ok(0, "broadcast state allocated (2048)");
		return;
	}
	cl_ctr_clusters[0] = cl;        /* park() finds clusters by id */
	cl_ctr_clusters[1] = cl2;
	cl_ctr_cluster_count = 2;
	cl_ctr_data_sink = sink;

	test_order(&cl_ctr_clusters[0]);
	test_fragments(&cl_ctr_clusters[0]);
	test_overflow(&cl_ctr_clusters[0]);
	test_ring(&cl_ctr_clusters[1]);
	test_new_life(&cl_ctr_clusters[1]);
	test_barrier(&cl_ctr_clusters[0]);
	test_restart(&cl_ctr_clusters[0]);
	test_barrier_in_flight(&cl_ctr_clusters[0]);
	test_older_life(&cl_ctr_clusters[0]);
	test_node_gone(&cl_ctr_clusters[0]);
	test_size_cap(&cl_ctr_clusters[0]);
	test_trailer(&cl_ctr_clusters[0]);
	test_concurrent(&cl_ctr_clusters[0]);

	cl_ctr_data_sink = NULL;
	cl_ctr_data_skew_ms = 0;
	cl_ctr_clusters[0] = saved;
	cl_ctr_clusters[1] = saved2;
	cl_ctr_cluster_count = saved_n;
}
