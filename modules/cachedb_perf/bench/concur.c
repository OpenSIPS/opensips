/*
 * The claim under test: cachedb_local's read path takes a WRITE lock on every
 * fetch, so N workers reading disjoint keys still ping-pong bucket cache lines.
 *
 *   A  current   : chained bucket, spinlock acquired on every read
 *   B  proposed  : 64-byte bucket, 1-byte tags, seqlock optimistic read
 *                  (readers never write -> lines stay Shared)
 *
 * Scaled 1..8 threads, 100% read and 95/5 read/write.
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
#define SECS    2

/* ---------------- A: current ---------------- */
typedef struct centry { str attr, value; unsigned expires, ttl; int synced;
                        struct centry *next; } centry;
typedef struct { centry *e; volatile int lock; } abucket;
#define ANB 65536
static abucket *A;

/* ---------------- B: cache-line bucket, tags, seqlock ---------------- */
#define BSLOTS 6
#define BNB    16384
typedef struct { unsigned short klen; unsigned vlen; char *val; char key[]; } brec;
typedef struct __attribute__((aligned(64))) {
	volatile unsigned version;      /* even = stable, odd = writer in bucket */
	volatile unsigned lock;         /* writers only */
	unsigned char     tags[BSLOTS]; /* 1 byte of hash per slot */
	unsigned char     used;
	unsigned char     _pad;
	brec             *slot[BSLOTS];
} bbucket;                          /* 4+4+6+1+1+48 = 64 */
static bbucket *B;

static char (*keys)[20];
static volatile int go, stop;

static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+1e-9*t.tv_nsec;}
static inline void spin_lock(volatile unsigned *l){ while(__sync_lock_test_and_set(l,1)) while(*l) __builtin_ia32_pause(); }
static inline void spin_unlock(volatile unsigned *l){ __sync_lock_release(l); }
static inline void aspin_lock(volatile int *l){ while(__sync_lock_test_and_set(l,1)) while(*l) __builtin_ia32_pause(); }
static inline void aspin_unlock(volatile int *l){ __sync_lock_release(l); }

/* ---------------- workers ---------------- */
struct arg { int id, nthr, design, wpct; unsigned long ops; };

static void *worker(void *p)
{
	struct arg *a = p;
	unsigned seed = 12345 + a->id * 7919;
	unsigned long ops = 0;
	char vbuf[VALLEN];

	while (!go) __builtin_ia32_pause();

	while (!stop) {
		for (int rep = 0; rep < 512; rep++) {
			seed = seed * 1103515245u + 12345u;
			int ki = (seed >> 8) % NKEYS;
			int isw = a->wpct && ((seed >> 3) % 100) < (unsigned)a->wpct;
			str k = { keys[ki], KLEN };

			if (a->design == 0) {
				unsigned b = core_hash(&k, NULL, ANB);
				aspin_lock(&A[b].lock);                 /* read takes the lock */
				for (centry *e = A[b].e; e; e = e->next)
					if (e->attr.len == KLEN && memcmp(e->attr.s, k.s, KLEN) == 0) {
						memcpy(vbuf, e->value.s, 8);
						if (isw) e->expires++;          /* TTL bump */
						break;
					}
				aspin_unlock(&A[b].lock);
			} else {
				unsigned h = core_hash(&k, NULL, 0);
				unsigned b = h & (BNB - 1);
				unsigned char tag = (unsigned char)(h >> 24) | 1;

				if (!isw) {                              /* optimistic read */
					unsigned v1, v2;
					do {
						v1 = __atomic_load_n(&B[b].version, __ATOMIC_ACQUIRE);
						if (v1 & 1) { __builtin_ia32_pause(); continue; }
						for (int s = 0; s < BSLOTS; s++) {
							if (B[b].tags[s] != tag) continue;
							brec *r = B[b].slot[s];
							if (!r || r->klen != KLEN) continue;
							if (memcmp(r->key, k.s, KLEN) == 0) { memcpy(vbuf, r->val, 8); break; }
						}
						__atomic_thread_fence(__ATOMIC_ACQUIRE);
						v2 = __atomic_load_n(&B[b].version, __ATOMIC_RELAXED);
					} while (v1 != v2 || (v1 & 1));
				} else {                                 /* writer */
					spin_lock(&B[b].lock);
					__atomic_add_fetch(&B[b].version, 1, __ATOMIC_RELEASE);
					for (int s = 0; s < BSLOTS; s++)
						if (B[b].tags[s] == tag && B[b].slot[s] &&
						    memcmp(B[b].slot[s]->key, k.s, KLEN) == 0) break;
					__atomic_add_fetch(&B[b].version, 1, __ATOMIC_RELEASE);
					spin_unlock(&B[b].lock);
				}
			}
			ops++;
		}
	}
	a->ops = ops;
	return NULL;
}

static double run(int nthr, int design, int wpct)
{
	pthread_t th[16]; struct arg ar[16];
	go = stop = 0;
	for (int i = 0; i < nthr; i++) {
		ar[i] = (struct arg){ i, nthr, design, wpct, 0 };
		pthread_create(&th[i], NULL, worker, &ar[i]);
	}
	double t0 = now(); go = 1;
	struct timespec ts = { SECS, 0 }; nanosleep(&ts, NULL);
	stop = 1;
	unsigned long tot = 0;
	for (int i = 0; i < nthr; i++) { pthread_join(th[i], NULL); tot += ar[i].ops; }
	return tot / (now() - t0) / 1e6;      /* Mops/sec */
}

int main(void)
{
	keys = malloc(NKEYS * 20);
	for (int i = 0; i < NKEYS; i++) sprintf(keys[i], "%016x", (unsigned)(i * 2654435761u));

	A = aligned_alloc(64, ANB * sizeof *A); memset(A, 0, ANB * sizeof *A);
	B = aligned_alloc(64, BNB * sizeof *B); memset(B, 0, BNB * sizeof *B);
	printf("sizeof(bbucket) = %zu (want 64)\n", sizeof(bbucket));

	int placed = 0;
	for (int i = 0; i < NKEYS; i++) {
		str k = { keys[i], KLEN };
		unsigned h = core_hash(&k, NULL, 0);

		centry *e = malloc(sizeof(centry) + KLEN + VALLEN);
		memset(e, 0, sizeof *e);
		e->attr.s = (char*)e + sizeof(centry); memcpy(e->attr.s, k.s, KLEN); e->attr.len = KLEN;
		e->value.s = e->attr.s + KLEN; e->value.len = VALLEN;
		unsigned ab = h & (ANB - 1);
		e->next = A[ab].e; A[ab].e = e;

		brec *r = malloc(sizeof(brec) + KLEN + VALLEN);
		r->klen = KLEN; r->vlen = VALLEN; memcpy(r->key, k.s, KLEN); r->val = r->key + KLEN;
		unsigned bb = h & (BNB - 1);
		for (int s = 0; s < BSLOTS; s++)
			if (!B[bb].slot[s]) { B[bb].slot[s] = r; B[bb].tags[s] = (unsigned char)(h >> 24) | 1;
			                      B[bb].used++; placed++; break; }
	}
	printf("%d/%d keys placed in B (%.1f%% bucket occupancy)\n\n",
	       placed, NKEYS, 100.0 * placed / (BNB * BSLOTS));

	int thr[] = { 1, 2, 4, 8 };
	for (int w = 0; w < 2; w++) {
		int wpct = w ? 5 : 0;
		printf("== %s ==\n", wpct ? "95% read / 5% write" : "100% read");
		printf("%-8s %12s %12s %10s\n", "threads", "A (Mops/s)", "B (Mops/s)", "B/A");
		double a1 = 0, b1 = 0;
		for (unsigned i = 0; i < sizeof(thr)/sizeof(*thr); i++) {
			double a = run(thr[i], 0, wpct);
			double b = run(thr[i], 1, wpct);
			if (!i) { a1 = a; b1 = b; }
			printf("%-8d %12.2f %12.2f %9.2fx\n", thr[i], a, b, b/a);
			if (thr[i] == 8)
				printf("%-8s %11.2fx %11.2fx %10s   <- scaling 1->8\n","scaling",a/a1,b/b1,"");
		}
		printf("\n");
	}
	return 0;
}
