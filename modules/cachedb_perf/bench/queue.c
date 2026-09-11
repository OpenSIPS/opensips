/*
 * Queued write path (RabbitMQ-shaped): producers enqueue, consumers apply.
 *
 * Fair comparison: a FIXED budget of 8 threads, split between producers and
 * consumers, versus 8 threads writing directly. What is counted is APPLIED
 * writes - work that actually landed in the table - not enqueue rate, because
 * an enqueue that never gets applied is not a write.
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
#define KLEN    16
#define BNB     16384
#define BSLOTS  6
#define TOTALTHR 8
#define RINGSZ  8192               /* entries per producer ring */
#define SECS    2

typedef struct __attribute__((aligned(64))) {
	volatile unsigned version;
	volatile unsigned lock;
	unsigned char tags[BSLOTS];
	unsigned short used;
	void *slot[BSLOTS];
} bucket;
static bucket *T;

/* one SPSC ring per producer; consumers each own a disjoint set of rings */
typedef struct { unsigned hash; unsigned ki; } item;
typedef struct __attribute__((aligned(64))) {
	_Alignas(64) volatile unsigned long head;   /* producer writes */
	_Alignas(64) volatile unsigned long tail;   /* consumer writes */
	item slot[RINGSZ];
} ring;
static ring *rings;

static char (*keys)[20];
static volatile int go, stop;
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+1e-9*t.tv_nsec;}
static inline void spin_lock(volatile unsigned *l){ while(__sync_lock_test_and_set(l,1)) while(*l) __builtin_ia32_pause(); }
static inline void spin_unlock(volatile unsigned *l){ __sync_lock_release(l); }

static inline void apply_write(unsigned h)
{
	unsigned b = h & (BNB-1);
	spin_lock(&T[b].lock);
	__atomic_add_fetch(&T[b].version, 1, __ATOMIC_RELEASE);
	T[b].tags[h % BSLOTS] = (unsigned char)(h>>24)|1;
	__atomic_add_fetch(&T[b].version, 1, __ATOMIC_RELEASE);
	spin_unlock(&T[b].lock);
}

struct arg { int id, role, nprod, ncons; unsigned long applied, enq, full; };

static void *runner(void *p)
{
	struct arg *a = p;
	unsigned seed = 4242 + a->id*7919;
	unsigned long applied=0, enq=0, full=0;

	while (!go) __builtin_ia32_pause();

	if (a->role == 0) {                       /* direct writer */
		while (!stop) for (int r=0;r<256;r++){
			seed=seed*1103515245u+12345u;
			int ki=(seed>>8)%NKEYS; str k={keys[ki],KLEN};
			apply_write(core_hash(&k,NULL,0)); applied++;
		}
	} else if (a->role == 1) {                /* producer */
		ring *R = &rings[a->id];
		while (!stop) for (int r=0;r<256;r++){
			seed=seed*1103515245u+12345u;
			int ki=(seed>>8)%NKEYS; str k={keys[ki],KLEN};
			unsigned long h_ = R->head, t_ = __atomic_load_n(&R->tail,__ATOMIC_ACQUIRE);
			if (h_ - t_ >= RINGSZ) { full++; continue; }      /* ring full: back-pressure */
			R->slot[h_ & (RINGSZ-1)].hash = core_hash(&k,NULL,0);
			__atomic_store_n(&R->head, h_+1, __ATOMIC_RELEASE);
			enq++;
		}
	} else {                                  /* consumer: drain its share of rings */
		int c = a->id - a->nprod;
		while (!stop) {
			for (int q = c; q < a->nprod; q += a->ncons) {
				ring *R = &rings[q];
				unsigned long t_ = R->tail, h_ = __atomic_load_n(&R->head,__ATOMIC_ACQUIRE);
				int n = (int)(h_ - t_); if (n > 64) n = 64;
				for (int i=0;i<n;i++){
					apply_write(R->slot[(t_+i) & (RINGSZ-1)].hash);
					applied++;
				}
				if (n) __atomic_store_n(&R->tail, t_+n, __ATOMIC_RELEASE);
			}
		}
	}
	a->applied=applied; a->enq=enq; a->full=full;
	return NULL;
}

static void run(int nprod, int ncons, double *applied_mops, double *enq_mops, double *fullpct)
{
	pthread_t th[TOTALTHR]; struct arg ar[TOTALTHR];
	int n = nprod + ncons;
	for (int i=0;i<TOTALTHR;i++){ rings[i].head=0; rings[i].tail=0; }
	go=stop=0;
	for (int i=0;i<n;i++){
		ar[i]=(struct arg){i, ncons? (i<nprod?1:2) : 0, nprod, ncons, 0,0,0};
		pthread_create(&th[i],NULL,runner,&ar[i]);
	}
	double t0=now(); go=1;
	struct timespec ts={SECS,0}; nanosleep(&ts,NULL);
	stop=1;
	unsigned long ap=0, eq=0, fl=0;
	for (int i=0;i<n;i++){ pthread_join(th[i],NULL); ap+=ar[i].applied; eq+=ar[i].enq; fl+=ar[i].full; }
	double el = now()-t0;
	*applied_mops = ap/el/1e6;
	*enq_mops = eq/el/1e6;
	*fullpct = (eq+fl) ? 100.0*fl/(eq+fl) : 0.0;
}

int main(void)
{
	keys = malloc(NKEYS*20);
	for (int i=0;i<NKEYS;i++) sprintf(keys[i],"%016x",(unsigned)(i*2654435761u));
	T = aligned_alloc(64, BNB*sizeof *T); memset(T,0,BNB*sizeof *T);
	rings = aligned_alloc(64, TOTALTHR*sizeof *rings); memset(rings,0,TOTALTHR*sizeof *rings);

	printf("fixed budget: %d threads. counting APPLIED writes (landed in the table).\n\n", TOTALTHR);

	double ap, eq, fp;
	run(TOTALTHR, 0, &ap, &eq, &fp);
	double base = ap;
	printf("%-26s %14s %14s %12s\n","split","applied Mops/s","enqueued","vs direct");
	printf("%-26s %14.2f %14s %11.2fx\n","8 direct writers", ap, "-", 1.0);

	int splits[][2] = { {7,1}, {6,2}, {4,4}, {2,6} };
	for (unsigned i=0;i<sizeof(splits)/sizeof(*splits);i++){
		run(splits[i][0], splits[i][1], &ap, &eq, &fp);
		char lbl[64]; snprintf(lbl,sizeof lbl,"%d producers + %d consumers",splits[i][0],splits[i][1]);
		printf("%-26s %14.2f %14.2f %11.2fx   ring-full %.0f%%\n", lbl, ap, eq, ap/base, fp);
	}

	printf("\nnote: 'enqueued' above 'applied' means the queue is falling behind -\n"
	       "      those writes are not yet visible to any reader.\n");
	return 0;
}
