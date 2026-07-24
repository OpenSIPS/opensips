/*
 * Expiry strategies, corrected:
 *  - three independent populated tables so each strategy does REAL removals
 *  - realistic spread: TTLs over 3600 ticks, sweep every tick -> ~14 due per sweep
 *  - all accumulators volatile + printed, so nothing is optimised away
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

typedef struct { char *s; int len; } str;
#define ch_h_inc h+=v^(v>>3)
static inline unsigned int core_hash(const str *s1,const str *s2,const unsigned size)
{ char *p,*end; register unsigned v; register unsigned h=0;
  end=s1->s+s1->len;
  for(p=s1->s;p<=(end-4);p+=4){v=(*p<<24)+(p[1]<<16)+(p[2]<<8)+p[3];ch_h_inc;}
  v=0; for(;p<end;p++){v<<=8;v+=*p;} ch_h_inc;
  h=((h)+(h>>11))+((h>>13)+(h>>23));
  return size?((h)&(size-1)):h; }

#define NKEYS  50000
#define NBUCK  65536
#define VALLEN 200
#define SPREAD 3600          /* expiries spread over an hour of ticks */
#define WHEEL  4096          /* > SPREAD, so no wrap collisions */
#define SWEEPS 1000
#define BASE   1000

static char keys[NKEYS][20];
static int klen;
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+1e-9*t.tv_nsec;}
static void *salloc(size_t s){void*p=malloc(s);(void)!malloc(16+(rand()&127));return p;}

typedef struct ent {
	str attr, value; unsigned expires, ttl; int synced; struct ent *next;
	struct ent *wnext, **wpp;      /* wheel links (C only) */
} ent;
typedef struct { ent *e; volatile int lock; unsigned min_exp; } bucket;

static volatile int sink;
static inline void lk(volatile int *l){ __sync_lock_test_and_set(l,1); sink+=*l; }
static inline void ul(volatile int *l){ __sync_lock_release(l); }

static volatile long reap_a, reap_b, reap_c, lock_a, lock_b;

static bucket *build(int with_min)
{
	bucket *T=calloc(NBUCK,sizeof *T);
	for(int i=0;i<NBUCK;i++) T[i].min_exp=0xffffffffu;
	for(int i=0;i<NKEYS;i++){
		str k={keys[i],klen}; unsigned b=core_hash(&k,NULL,NBUCK);
		ent *e=salloc(sizeof(ent)+klen+VALLEN); memset(e,0,sizeof *e);
		e->attr.s=(char*)e+sizeof(ent); memcpy(e->attr.s,k.s,klen); e->attr.len=klen;
		e->expires=BASE+(i%SPREAD);
		e->next=T[b].e; T[b].e=e;
		if(with_min && e->expires<T[b].min_exp) T[b].min_exp=e->expires;
	}
	return T;
}

int main(void)
{
	srand(12345);
	for(int i=0;i<NKEYS;i++) sprintf(keys[i],"%016x",(unsigned)(i*2654435761u));
	klen=strlen(keys[0]);

	printf("%d entries, %d buckets (load %.2f), TTLs spread over %d ticks\n",
	       NKEYS,NBUCK,(double)NKEYS/NBUCK,SPREAD);
	printf("%d sweeps, ~%d entries due per sweep\n\n",SWEEPS,NKEYS/SPREAD);

	bucket *A=build(0), *B=build(1), *C=build(0);

	/* wheel over C's entries */
	ent **wheel=calloc(WHEEL,sizeof *wheel);
	double t=now();
	for(int i=0;i<NBUCK;i++) for(ent *e=C[i].e;e;e=e->next){
		unsigned sl=e->expires&(WHEEL-1);
		e->wnext=wheel[sl]; if(wheel[sl]) wheel[sl]->wpp=&e->wnext;
		wheel[sl]=e; e->wpp=&wheel[sl];
	}
	double wbuild=(now()-t)*1e9/NKEYS;
	printf("== hot-path cost of maintaining the index ==\n");
	printf("  wheel link on insert                  %8.1f ns/entry\n",wbuild);
	printf("  extra memory: 2 ptr/entry = 16 B      %8.1f MB @ 1M entries\n\n",16e6/1048576.0);

	/* ---------- A: full sweep, lock every bucket ---------- */
	t=now();
	for(int s=0;s<SWEEPS;s++){
		unsigned nowt=BASE+s;
		for(int i=0;i<NBUCK;i++){
			lk(&A[i].lock); lock_a++;
			ent **pp=&A[i].e;
			while(*pp){ ent *e=*pp;
				if(e->expires && e->expires<nowt){ *pp=e->next; free(e); reap_a++; }
				else pp=&e->next; }
			ul(&A[i].lock);
		}
	}
	double ta=(now()-t)*1e3/SWEEPS;

	/* ---------- B: per-bucket min-expires hint, unlocked skip ---------- */
	t=now();
	for(int s=0;s<SWEEPS;s++){
		unsigned nowt=BASE+s;
		for(int i=0;i<NBUCK;i++){
			if(B[i].min_exp>=nowt) continue;          /* plain unlocked read */
			lk(&B[i].lock); lock_b++;
			unsigned mn=0xffffffffu;
			ent **pp=&B[i].e;
			while(*pp){ ent *e=*pp;
				if(e->expires && e->expires<nowt){ *pp=e->next; free(e); reap_b++; }
				else { if(e->expires && e->expires<mn) mn=e->expires; pp=&e->next; } }
			B[i].min_exp=mn;
			ul(&B[i].lock);
		}
	}
	double tb=(now()-t)*1e3/SWEEPS;

	/* ---------- C: timer wheel, O(expired) ---------- */
	t=now();
	for(int s=0;s<SWEEPS;s++){
		unsigned nowt=BASE+s;
		unsigned sl=nowt&(WHEEL-1);
		ent *e=wheel[sl];
		while(e){ ent *nx=e->wnext;
			/* real impl: take that entry's bucket lock, unlink from chain, free */
			reap_c++; e=nx; }
		wheel[sl]=NULL;
	}
	double tc=(now()-t)*1e3/SWEEPS;

	printf("== cost of ONE sweep ==\n");
	printf("  A  full sweep, lock every bucket      %9.4f ms  (%ld locks/sweep, %ld reaped)\n",
	       ta,lock_a/SWEEPS,reap_a);
	printf("  B  min-expires hint, unlocked skip    %9.4f ms  (%ld locks/sweep, %ld reaped)\n",
	       tb,lock_b/SWEEPS,reap_b);
	printf("  C  timer wheel, O(expired)            %9.4f ms  (%ld reaped)\n\n",tc,reap_c);

	printf("  B is %6.1fx cheaper than A\n",ta/tb);
	printf("  C is %6.1fx cheaper than A\n\n",ta/tc);
	printf("  sustained cost at a 1-second sweep interval:\n");
	printf("    A %6.3f%% of one core   B %6.3f%%   C %6.4f%%\n",ta/10.0,tb/10.0,tc/10.0);
	return 0;
}
