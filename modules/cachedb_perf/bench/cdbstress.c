/*
 * CP-16 multi-process correctness soak for cachedb_perf.  Throwaway - NOT
 * for the PR.  W worker PROCESSES hammer one backend with a get/set/remove/
 * add mix while the maintenance timer splits buckets underneath them, then
 * four invariants are checked:
 *
 *   1. no torn read   - every value is written all-bytes-equal; any hit read
 *                       back with mixed bytes means a reader saw a half-done
 *                       write (a seqlock failure).
 *   2. no lost update - N adds of +1 across all workers must equal the sum of
 *                       the counter values (add's RMW under the bucket lock).
 *   3. no lost key     - "immortal" keys inserted once and never removed must
 *                       be found, with the right value, all through the run
 *                       and after all the splits (a split must not drop one).
 *   4. no crash        - the whole thing runs to completion (run under a
 *                       redzone allocator to also catch use-after-free).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../str.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../cachedb/cachedb.h"

static int mod_init(void);

static char *stress_url = NULL;
static int n_workers = 8;
static int n_ops = 2000000;     /* per worker */
static int n_imm = 5000;        /* immortal keys (read-only after init) */
static int n_chn = 5000;        /* churn keys (set/remove) */
static int n_ctr = 64;          /* counters (add +1) */
static int val_sz = 200;

#define MAXW 64
struct ctrl {
	volatile int ready, done;
	unsigned long adds[MAXW];        /* per-worker +1 count on counters */
	unsigned long torn[MAXW];        /* mixed-byte reads seen */
	unsigned long imm_lost[MAXW];    /* immortal miss/wrong-value */
	unsigned long gets[MAXW], sets[MAXW], rems[MAXW];
};
static struct ctrl *C;
static str url_s;
static cachedb_funcs cdbf;

static const param_export_t params[] = {
	{"url",       STR_PARAM, &stress_url},
	{"n_workers", INT_PARAM, &n_workers},
	{"n_ops",     INT_PARAM, &n_ops},
	{"n_imm",     INT_PARAM, &n_imm},
	{"n_chn",     INT_PARAM, &n_chn},
	{"n_ctr",     INT_PARAM, &n_ctr},
	{0,0,0}
};

/* key layout: [0,n_imm) immortal | [n_imm,n_imm+n_chn) churn | rest counters */
static void mkkey(char *buf, int idx)
{
	if (idx < n_imm)              sprintf(buf, "imm-%08x", idx);
	else if (idx < n_imm+n_chn)  sprintf(buf, "chn-%08x", idx);
	else                         sprintf(buf, "ctr-%08x", idx);
}

/* a hit value must be all-bytes-equal (that is how every set writes it);
 * returns 1 if consistent, 0 if torn */
static int val_ok(const str *v)
{
	int i;
	if (v->len == 0)
		return 1;
	for (i = 1; i < v->len; i++)
		if (v->s[i] != v->s[0])
			return 0;
	return 1;
}

static void stress_worker(int no)
{
	cachedb_con *con;
	unsigned seed = 12345 + no * 7919;
	char kb[32], vbuf[8192];
	str a, v;
	int i;

	if (no >= MAXW) return;
	con = cdbf.init(&url_s);
	if (!con) { LM_ERR("worker %d init failed\n", no); return; }

	__sync_add_and_fetch(&C->ready, 1);
	while (C->ready < n_workers) usleep(200);

	for (i = 0; i < n_ops; i++) {
		seed = seed * 1103515245u + 12345u;
		unsigned r = seed >> 8;
		int cls = r % 100;
		if (cls < 45) {
			/* GET + verify (immortal or churn) */
			int idx = (n_imm + n_chn) ? r % (n_imm + n_chn) : 0;
			mkkey(kb, idx); a.s = kb; a.len = strlen(kb);
			v.s = NULL; v.len = 0;
			cdbf.get(con, &a, &v);
			C->gets[no]++;
			if (v.s) {
				if (!val_ok(&v))
					C->torn[no]++;
				pkg_free(v.s);
			} else if (idx < n_imm) {
				C->imm_lost[no]++;     /* immortal must always exist */
			}
		} else if (cls < 70) {
			/* SET a churn key, all-bytes-equal */
			int idx = n_chn ? n_imm + (r % n_chn) : 0;
			mkkey(kb, idx); a.s = kb; a.len = strlen(kb);
			memset(vbuf, (int)(seed & 0xFF), val_sz);
			v.s = vbuf; v.len = val_sz;
			cdbf.set(con, &a, &v, 0);
			C->sets[no]++;
		} else if (cls < 80) {
			/* REMOVE a churn key (churn -> arena reuse + relink) */
			int idx = n_chn ? n_imm + (r % n_chn) : 0;
			mkkey(kb, idx); a.s = kb; a.len = strlen(kb);
			cdbf.remove(con, &a);
			C->rems[no]++;
		} else {
			/* ADD +1 to a counter */
			int idx = n_imm + n_chn + (n_ctr ? r % n_ctr : 0);
			int nv = 0;
			mkkey(kb, idx); a.s = kb; a.len = strlen(kb);
			if (cdbf.add(con, &a, 1, 0, &nv) == 0)
				C->adds[no]++;
		}
	}

	if (__sync_add_and_fetch(&C->done, 1) == n_workers) {
		unsigned long adds=0, torn=0, ilost=0, gets=0, sets=0, rems=0;
		unsigned long csum=0, imiss=0, iwrong=0;
		int j;
		for (j=0;j<n_workers;j++){ adds+=C->adds[j]; torn+=C->torn[j];
			ilost+=C->imm_lost[j]; gets+=C->gets[j]; sets+=C->sets[j];
			rems+=C->rems[j]; }
		/* verify counters: sum of values == sum of successful adds */
		for (j = 0; j < n_ctr; j++) {
			char b[32]; str ka, cv; long long cval;
			mkkey(b, n_imm + n_chn + j); ka.s=b; ka.len=strlen(b);
			cv.s=NULL; cv.len=0;
			if (cdbf.get(con, &ka, &cv) == 0 && cv.s) {
				cval = strtoll(cv.s, NULL, 10); csum += cval;
				pkg_free(cv.s);
			}
		}
		/* verify every immortal is present with its exact value */
		for (j = 0; j < n_imm; j++) {
			char b[32]; str ka, iv; int q;
			mkkey(b, j); ka.s=b; ka.len=strlen(b);
			iv.s=NULL; iv.len=0;
			if (cdbf.get(con, &ka, &iv) != 0 || !iv.s) { imiss++; continue; }
			for (q = 0; q < iv.len; q++)
				if ((unsigned char)iv.s[q] != (unsigned char)(j & 0xFF))
					{ iwrong++; break; }
			pkg_free(iv.s);
		}
		LM_NOTICE("CP16 STRESS: workers=%d ops/w=%d gets=%lu sets=%lu "
			"rems=%lu adds=%lu\n", n_workers, n_ops, gets, sets, rems, adds);
		LM_NOTICE("CP16 RESULT: torn_reads=%lu | counters sum=%lu vs "
			"adds=%lu (%s) | immortals miss=%lu wrong=%lu (%s) => %s\n",
			torn, csum, adds, csum==adds?"OK":"LOST-UPDATE",
			imiss, iwrong, (imiss==0&&iwrong==0)?"OK":"LOST-KEY",
			(torn==0 && csum==adds && imiss==0 && iwrong==0) ?
				"PASS" : "*** FAIL ***");
	}
	while (1) sleep(60);
}

static proc_export_t procs[] = {
	{"cdbstress worker", 0, 0, stress_worker, 0, PROC_FLAG_INITCHILD},
	{0,0,0,0,0,0}
};

struct module_exports exports = {
	"cdbstress", MOD_TYPE_DEFAULT, MODULE_VERSION, DEFAULT_DLFLAGS,
	0, 0, 0, 0, params, 0, 0, 0, 0, procs,
	0, mod_init, (response_function)0, 0, 0, 0
};

static int mod_init(void)
{
	cachedb_con *con;
	char kb[32], *val;
	str a, v;
	int i;

	if (!stress_url) { LM_ERR("url required\n"); return -1; }
	url_s.s = stress_url; url_s.len = strlen(stress_url);
	procs[0].no = n_workers;

	if (cachedb_bind_mod(&url_s, &cdbf) < 0) {
		LM_ERR("cannot bind %s\n", stress_url); return -1; }
	if (!cdbf.get||!cdbf.set||!cdbf.remove||!cdbf.add) {
		LM_ERR("backend lacks ops\n"); return -1; }

	C = shm_malloc(sizeof *C); memset(C, 0, sizeof *C);

	con = cdbf.init(&url_s);
	if (!con) { LM_ERR("init failed\n"); return -1; }
	val = pkg_malloc(val_sz);

	/* immortals: value = all bytes (i & 0xFF), never touched again */
	for (i = 0; i < n_imm; i++) {
		mkkey(kb, i); a.s=kb; a.len=strlen(kb);
		memset(val, i & 0xFF, val_sz); v.s=val; v.len=val_sz;
		cdbf.set(con, &a, &v, 0);
	}
	pkg_free(val);
	LM_NOTICE("cdbstress: seeded %d immortals; %d workers x %d ops "
		"(growth runs concurrently)\n", n_imm, n_workers, n_ops);
	return 0;
}
