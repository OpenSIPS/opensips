/*
 * Read-path protocol comparison for cachedb_perf — DESIGN.md 2.7.
 *
 *   S  seqlock   : DESIGN.md 3.2 as written - optimistic read, version pair,
 *                  every write (incl. TTL bump) takes lock + 2 version bumps
 *   H  hybrid    : same seqlock read; TTL-bump writes skip the version bumps
 *                  (only mutation is one aligned 4B expires store, readers
 *                  cannot tear) - value rewrites still bump
 *   Q  qsbr      : no version on reads at all - slot pointer is the unit of
 *                  publication (acquire load), entries immutable-while-visible,
 *                  value rewrite = write shadow entry + release ptr swap,
 *                  TTL bump = atomic expires store under lock
 *
 * Mixes: 100% read; 95/5 with writes = 7/8 TTL bump + 1/8 value rewrite
 * (th_store refresh pattern); hot-bucket 50/50 (all threads on one bucket).
 * Reports Mops/s and, for seqlock reads, retries per 1k reads.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>

typedef struct { char *s; int len; } str;
#define ch_h_inc h+=v^(v>>3)
static inline unsigned core_hash(const str *s1,const str *s2,const unsigned size)
{ char *p,*end; register unsigned v; register unsigned h=0;
  end=s1->s+s1->len;
  for(p=s1->s;p<=(end-4);p+=4){v=(*p<<24)+(p[1]<<16)+(p[2]<<8)+p[3];ch_h_inc;}
  v=0; for(;p<end;p++){v<<=8;v+=*p;} ch_h_inc;
  h=((h)+(h>>11))+((h>>13)+(h>>23));
  return size?((h)&(size-1)):h; }

#define NKEYS   50000
#define VALLEN  200
#define KLEN    16
#define SECS    1
#define BSLOTS  6
#define BNB     16384

typedef struct { unsigned short klen; unsigned vlen; volatile unsigned expires;
                 char *val; char key[]; } brec;
typedef struct __attribute__((aligned(64))) {
	volatile unsigned version;
	volatile unsigned lock;
	unsigned char     tags[BSLOTS];
	unsigned char     used;
	unsigned char     _pad;
	brec * volatile   slot[BSLOTS];
} bbucket;

static bbucket *B;
static char (*keys)[20];
static unsigned khash[NKEYS];
static brec *rec0[NKEYS], *rec1[NKEYS];      /* shadow pair for Q swaps */
static volatile int go, stop;

/* hot-bucket mode: the few keys landing in one chosen bucket */
static int hotkeys[64], nhot;

static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+1e-9*t.tv_nsec;}
static inline void spin_lock(volatile unsigned *l){ while(__sync_lock_test_and_set(l,1)) while(*l) __builtin_ia32_pause(); }
static inline void spin_unlock(volatile unsigned *l){ __sync_lock_release(l); }

struct arg { int id, design, wpct, hot, rewrite_shift; unsigned long ops, retries, reads; };

static void *worker(void *p)
{
	struct arg *a = p;
	unsigned seed = 12345 + a->id * 7919;
	unsigned long ops = 0, retries = 0, reads = 0;
	char vbuf[VALLEN] = {0};

	while (!go) __builtin_ia32_pause();

	while (!stop) {
		for (int rep = 0; rep < 512; rep++) {
			seed = seed * 1103515245u + 12345u;
			int ki = a->hot ? hotkeys[(seed >> 8) % nhot] : (int)((seed >> 8) % NKEYS);
			int isw = a->wpct && ((seed >> 3) % 100) < (unsigned)a->wpct;
			int isrw = isw && (((seed >> 13) & 7) == 0);   /* 1/8 of writes rewrite value */
			unsigned h = khash[ki];
			unsigned b = h & (BNB - 1);
			unsigned char tag = (unsigned char)(h >> 24); if (!tag) tag = 1;

			if (!isw) {
				reads++;
				if (a->design == 2) {                    /* Q: no version at all */
					for (int s = 0; s < BSLOTS; s++) {
						if (B[b].tags[s] != tag) continue;
						brec *r = __atomic_load_n(&B[b].slot[s], __ATOMIC_ACQUIRE);
						if (!r || r->klen != KLEN) continue;
						if (memcmp(r->key, keys[ki], KLEN) == 0) {
							memcpy(vbuf, r->val, 8);
							(void)r->expires;
							break;
						}
					}
				} else {                                 /* S/H: seqlock */
					unsigned v1, v2;
					do {
						v1 = __atomic_load_n(&B[b].version, __ATOMIC_ACQUIRE);
						if (v1 & 1) { __builtin_ia32_pause(); retries++; continue; }
						for (int s = 0; s < BSLOTS; s++) {
							if (B[b].tags[s] != tag) continue;
							brec *r = B[b].slot[s];
							if (!r || r->klen != KLEN) continue;
							if (memcmp(r->key, keys[ki], KLEN) == 0) { memcpy(vbuf, r->val, 8); break; }
						}
						__atomic_thread_fence(__ATOMIC_ACQUIRE);
						v2 = __atomic_load_n(&B[b].version, __ATOMIC_RELAXED);
						if (v1 != v2) retries++;
					} while (v1 != v2 || (v1 & 1));
				}
			} else {
				spin_lock(&B[b].lock);
				/* find our slot (writer-side scan, as concur.c does) */
				int s;
				brec *r = NULL;
				for (s = 0; s < BSLOTS; s++)
					if (B[b].tags[s] == tag && B[b].slot[s] &&
					    memcmp(B[b].slot[s]->key, keys[ki], KLEN) == 0) { r = B[b].slot[s]; break; }
				if (r) {
					if (!isrw) {                         /* TTL bump */
						if (a->design == 0) {            /* S: full protocol */
							__atomic_add_fetch(&B[b].version, 1, __ATOMIC_RELEASE);
							r->expires = (unsigned)ops;
							__atomic_add_fetch(&B[b].version, 1, __ATOMIC_RELEASE);
						} else {                         /* H/Q: atomic store, no bumps */
							__atomic_store_n(&r->expires, (unsigned)ops, __ATOMIC_RELAXED);
						}
					} else {                             /* value rewrite */
						if (a->design == 2) {            /* Q: shadow + ptr swap */
							brec *other = (r == rec0[ki]) ? rec1[ki] : rec0[ki];
							memcpy(other->val, vbuf, 8);
							memset(other->val + 8, (int)seed, VALLEN - 8);
							other->expires = (unsigned)ops;
							__atomic_store_n(&B[b].slot[s], other, __ATOMIC_RELEASE);
						} else {                         /* S/H: in-place under version */
							__atomic_add_fetch(&B[b].version, 1, __ATOMIC_RELEASE);
							memset(r->val, (int)seed, VALLEN);
							r->expires = (unsigned)ops;
							__atomic_add_fetch(&B[b].version, 1, __ATOMIC_RELEASE);
						}
					}
				}
				spin_unlock(&B[b].lock);
			}
			ops++;
		}
	}
	a->ops = ops; a->retries = retries; a->reads = reads;
	return NULL;
}

static void run(int nthr, int design, int wpct, int hot, double *mops, double *ret1k)
{
	pthread_t th[16]; struct arg ar[16];
	go = stop = 0;
	for (int i = 0; i < nthr; i++) {
		ar[i] = (struct arg){ i, design, wpct, hot, 3, 0, 0, 0 };
		pthread_create(&th[i], NULL, worker, &ar[i]);
	}
	double t0 = now(); go = 1;
	struct timespec ts = { SECS, 0 }; nanosleep(&ts, NULL);
	stop = 1;
	unsigned long tot = 0, retr = 0, rds = 0;
	for (int i = 0; i < nthr; i++) { pthread_join(th[i], NULL); tot += ar[i].ops; retr += ar[i].retries; rds += ar[i].reads; }
	*mops = tot / (now() - t0) / 1e6;
	*ret1k = rds ? 1000.0 * retr / rds : 0;
}

int main(void)
{
	keys = malloc(NKEYS * 20);
	for (int i = 0; i < NKEYS; i++) sprintf(keys[i], "%016x", (unsigned)(i * 2654435761u));

	B = aligned_alloc(64, BNB * sizeof *B); memset(B, 0, BNB * sizeof *B);
	printf("sizeof(bbucket) = %zu (want 64)\n", sizeof(bbucket));

	int placed = 0;
	for (int i = 0; i < NKEYS; i++) {
		str k = { keys[i], KLEN };
		unsigned h = core_hash(&k, NULL, 0);
		khash[i] = h;
		for (int v = 0; v < 2; v++) {
			brec *r = malloc(sizeof(brec) + KLEN + VALLEN);
			r->klen = KLEN; r->vlen = VALLEN; r->expires = 0;
			memcpy(r->key, keys[i], KLEN); r->val = r->key + KLEN;
			memset(r->val, 'a' + (i % 26), VALLEN);
			if (v) rec1[i] = r; else rec0[i] = r;
		}
		unsigned bb = h & (BNB - 1);
		unsigned char tag = (unsigned char)(h >> 24); if (!tag) tag = 1;
		for (int s = 0; s < BSLOTS; s++)
			if (!B[bb].slot[s]) { B[bb].slot[s] = rec0[i]; B[bb].tags[s] = tag;
			                      B[bb].used++; placed++; break; }
	}
	/* hot-bucket key list: everything that landed where key 0 did */
	unsigned tb = khash[0] & (BNB - 1);
	for (int i = 0; i < NKEYS && nhot < 64; i++)
		if ((khash[i] & (BNB - 1)) == tb) hotkeys[nhot++] = i;
	printf("%d/%d keys placed, hot bucket holds %d keys\n\n", placed, NKEYS, nhot);

	const char *dn[] = { "S seqlock", "H hybrid", "Q qsbr" };
	struct { const char *name; int wpct, hot; } mixes[] = {
		{ "100% read, uniform", 0, 0 },
		{ "95/5 r/w, uniform (bump-heavy)", 5, 0 },
		{ "50/50 r/w, ONE hot bucket", 50, 1 },
	};
	int thr[] = { 1, 2, 4, 8 };

	for (unsigned m = 0; m < 3; m++) {
		printf("== %s ==\n", mixes[m].name);
		printf("%-8s", "threads");
		for (int d = 0; d < 3; d++) printf(" %14s", dn[d]);
		printf("   %s\n", "S retries/1k reads");
		for (unsigned t = 0; t < 4; t++) {
			printf("%-8d", thr[t]);
			double sret = 0;
			for (int d = 0; d < 3; d++) {
				double mo, rk;
				run(thr[t], d, mixes[m].wpct, mixes[m].hot, &mo, &rk);
				if (d == 0) sret = rk;
				printf(" %11.2f M/s", mo);
			}
			printf("   %.3f\n", sret);
		}
		printf("\n");
	}
	return 0;
}
