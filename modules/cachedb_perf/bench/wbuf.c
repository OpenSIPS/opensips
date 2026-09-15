/*
 * Does a write-staging buffer (LSM memtable) help cachedb_perf?
 *
 * WRITE PATH, 1..8 threads:
 *   A  per-bucket lock (the current design)
 *   B  shared 1MB append buffer, atomic fetch_add on one head  <- "no lock"
 *   C  per-process append buffer, no atomic at all
 *
 * READ PATH: what it costs if a reader must also consult the buffers.
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
#define VALLEN  200
#define ENTSZ   (KLEN + VALLEN + 16)      /* what one staged write costs */
#define BUFSZ   (1024*1024)               /* the proposed 1 MB */
#define BNB     16384
#define BSLOTS  6
#define SECS    2
#define MAXTHR  8

typedef struct { unsigned short klen; unsigned vlen; char *val; char key[]; } brec;
typedef struct __attribute__((aligned(64))) {
	volatile unsigned version;
	volatile unsigned lock;
	unsigned char tags[BSLOTS];
	unsigned short used;
	brec *slot[BSLOTS];
} bucket;
static bucket *T;

/* B: one shared buffer, one shared head */
static struct { _Alignas(64) volatile unsigned long head; char data[BUFSZ]; } shared_buf;

/* C: per-thread buffers, each with its own head */
static struct { _Alignas(64) unsigned long head; char data[BUFSZ/MAXTHR]; } priv_buf[MAXTHR];

static char (*keys)[20];
static volatile int go, stop;
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+1e-9*t.tv_nsec;}
static inline void spin_lock(volatile unsigned *l){ while(__sync_lock_test_and_set(l,1)) while(*l) __builtin_ia32_pause(); }
static inline void spin_unlock(volatile unsigned *l){ __sync_lock_release(l); }

struct arg { int id, design; unsigned long ops, wrapped; };

static void *writer(void *p)
{
	struct arg *a = p;
	unsigned seed = 999 + a->id*7919;
	unsigned long ops = 0, wrapped = 0;
	char payload[ENTSZ];
	memset(payload, 'x', sizeof payload);

	while (!go) __builtin_ia32_pause();
	while (!stop) {
		for (int rep = 0; rep < 256; rep++) {
			seed = seed*1103515245u + 12345u;
			int ki = (seed >> 8) % NKEYS;
			str k = { keys[ki], KLEN };
			unsigned h = core_hash(&k, NULL, 0);

			if (a->design == 0) {                 /* A: per-bucket lock */
				unsigned b = h & (BNB-1);
				spin_lock(&T[b].lock);
				__atomic_add_fetch(&T[b].version, 1, __ATOMIC_RELEASE);
				T[b].tags[h % BSLOTS] = (unsigned char)(h>>24)|1;   /* mutate */
				__atomic_add_fetch(&T[b].version, 1, __ATOMIC_RELEASE);
				spin_unlock(&T[b].lock);
			} else if (a->design == 1) {          /* B: shared buffer, atomic head */
				unsigned long off = __atomic_fetch_add(&shared_buf.head, ENTSZ, __ATOMIC_RELAXED);
				if (off + ENTSZ > BUFSZ) {        /* full: reorganiser must drain */
					__atomic_store_n(&shared_buf.head, 0, __ATOMIC_RELAXED);
					wrapped++; off = 0;
				}
				memcpy(shared_buf.data + off, payload, ENTSZ);
			} else {                              /* C: private buffer, no atomic */
				unsigned long off = priv_buf[a->id].head;
				if (off + ENTSZ > BUFSZ/MAXTHR) { priv_buf[a->id].head = 0; wrapped++; off = 0; }
				memcpy(priv_buf[a->id].data + off, payload, ENTSZ);
				priv_buf[a->id].head = off + ENTSZ;
			}
			ops++;
		}
	}
	a->ops = ops; a->wrapped = wrapped;
	return NULL;
}

static double run(int nthr, int design, unsigned long *wrapped)
{
	pthread_t th[MAXTHR]; struct arg ar[MAXTHR];
	go = stop = 0;
	for (int i=0;i<nthr;i++){ ar[i]=(struct arg){i,design,0,0}; pthread_create(&th[i],NULL,writer,&ar[i]); }
	double t0=now(); go=1;
	struct timespec ts={SECS,0}; nanosleep(&ts,NULL);
	stop=1;
	unsigned long tot=0, w=0;
	for (int i=0;i<nthr;i++){ pthread_join(th[i],NULL); tot+=ar[i].ops; w+=ar[i].wrapped; }
	if (wrapped) *wrapped = w;
	return tot/(now()-t0)/1e6;
}

int main(void)
{
	keys = malloc(NKEYS*20);
	for (int i=0;i<NKEYS;i++) sprintf(keys[i],"%016x",(unsigned)(i*2654435761u));
	T = aligned_alloc(64, BNB*sizeof *T); memset(T,0,BNB*sizeof *T);

	printf("staged entry = %d B, buffer = %d KB -> holds %d writes\n",
	       ENTSZ, BUFSZ/1024, BUFSZ/ENTSZ);
	printf("at 6000 CPS with one write per call, that is %.2f seconds of headroom\n\n",
	       (double)(BUFSZ/ENTSZ)/6000.0);

	printf("== WRITE throughput (Mops/s) ==\n");
	printf("%-8s %14s %16s %16s\n","threads","A bucket lock","B shared buf","C private buf");
	int thr[]={1,2,4,8};
	double a1=0,b1=0,c1=0;
	for (unsigned i=0;i<sizeof(thr)/sizeof(*thr);i++){
		double a=run(thr[i],0,NULL), b=run(thr[i],1,NULL), c=run(thr[i],2,NULL);
		if(!i){a1=a;b1=b;c1=c;}
		printf("%-8d %14.2f %16.2f %16.2f\n",thr[i],a,b,c);
		if(thr[i]==8) printf("%-8s %13.2fx %15.2fx %15.2fx  <- scaling 1->8\n",
		                     "scaling",a/a1,b/b1,c/c1);
	}

	/* ---- read penalty: reader must also consult N buffers ---- */
	printf("\n== READ cost when the reader must also check staged writes ==\n");
	brec *r = malloc(sizeof(brec)+KLEN+VALLEN);
	r->klen=KLEN; memcpy(r->key,keys[0],KLEN); r->val=r->key+KLEN;
	for (int i=0;i<NKEYS;i++){
		str k={keys[i],KLEN}; unsigned h=core_hash(&k,NULL,0); unsigned b=h&(BNB-1);
		for(int s=0;s<BSLOTS;s++) if(!T[b].slot[s]){T[b].slot[s]=r;T[b].tags[s]=(unsigned char)(h>>24)|1;break;}
	}
	/* per-buffer index: one extra hash probe per buffer consulted */
	unsigned *idx[MAXTHR];
	for (int i=0;i<MAXTHR;i++){ idx[i]=calloc(4096,sizeof(unsigned)); for(int j=0;j<4096;j++) idx[i][j]=j; }

	int probes[] = {0,1,2,4,8};
	char vbuf[8]; volatile unsigned long hits=0;
	for (unsigned pi=0; pi<sizeof(probes)/sizeof(*probes); pi++){
		int np = probes[pi];
		double t=now();
		for (int it=0; it<3000000; it++){
			int ki=(int)(((long)it*7919)%NKEYS);
			str k={keys[ki],KLEN}; unsigned h=core_hash(&k,NULL,0);
			for(int q=0;q<np;q++) hits += idx[q][(h>>(q&7)) & 4095];   /* buffer index probe */
			unsigned b=h&(BNB-1);
			for(int s=0;s<BSLOTS;s++) if(T[b].tags[s]==((unsigned char)(h>>24)|1)){
				brec *rr=T[b].slot[s]; if(rr && rr->klen==KLEN){memcpy(vbuf,rr->val,8);hits++;} break; }
		}
		double ns=(now()-t)*1e9/3000000;
		printf("  table + %d buffer probe(s)   %7.1f ns/read   %s\n", np, ns,
		       pi==0 ? "<- baseline (no staging)" : "");
	}
	printf("  (hits=%lu)\n", hits);
	return 0;
}
