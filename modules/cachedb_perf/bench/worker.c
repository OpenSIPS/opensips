/*
 * Does moving the sort off the hot path pay?
 * Bucket = sorted prefix (binary search) + small unsorted append tail.
 * Writers append O(1); a background worker merges tail -> prefix.
 * Compared against: current chain, and eager sorted-insert (memmove in hot path).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

typedef struct { char *s; int len; } str;
#define ch_h_inc h+=v^(v>>3)
static inline unsigned int core_hash(const str *s1, const str *s2, const unsigned int size)
{
	char *p, *end; register unsigned v; register unsigned h = 0;
	end=s1->s+s1->len;
	for ( p=s1->s ; p<=(end-4) ; p+=4 ){ v=(*p<<24)+(p[1]<<16)+(p[2]<<8)+p[3]; ch_h_inc; }
	v=0; for (; p<end ; p++){ v<<=8; v+=*p;} ch_h_inc;
	h=((h)+(h>>11))+((h>>13)+(h>>23));
	return size?((h)&(size-1)):h;
}

#define NKEYS  50000
#define VALLEN 200
#define ITERS  1000000
#define NBUCK  512          /* the pathological default */
#define TAILMAX 8

static char keys[NKEYS][20];
static int klen;
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+1e-9*t.tv_nsec;}
static void *salloc(size_t sz){void*p=malloc(sz);(void)!malloc(16+(rand()&127));return p;}

typedef struct { unsigned short klen; char *val; char key[]; } rec;
typedef struct { unsigned hash; rec *r; } slot;

/* eager-sorted bucket */
typedef struct { slot *v; int n, cap; } sb;
/* prefix + tail bucket */
typedef struct { slot *v; int n, cap; slot tail[TAILMAX]; int tn; } pb;

/* current chain */
typedef struct centry { str attr, value; unsigned e,t; int s; struct centry *next; } centry;

static rec *mkrec(const char *k){ rec *r=salloc(sizeof(rec)+klen+VALLEN);
	r->klen=klen; memcpy(r->key,k,klen); r->val=r->key+klen; return r; }

static int cmp(const void *a,const void *b){
	unsigned x=((const slot*)a)->hash,y=((const slot*)b)->hash;
	return x<y?-1:(x>y?1:0); }

int main(void)
{
	srand(12345);
	for(int i=0;i<NKEYS;i++) sprintf(keys[i],"%016x",(unsigned)(i*2654435761u));
	klen=strlen(keys[0]);
	printf("%d keys in %d buckets (load %.1f), %d ops\n\n",NKEYS,NBUCK,(double)NKEYS/NBUCK,ITERS);

	/* ---------------- INSERT cost ---------------- */
	printf("== insert / overwrite cost (hot path) ==\n");

	centry **CH=calloc(NBUCK,sizeof *CH);
	double t=now();
	for(int i=0;i<NKEYS;i++){ str k={keys[i],klen}; unsigned b=core_hash(&k,NULL,NBUCK);
		centry *e=salloc(sizeof(centry)+klen+VALLEN); memset(e,0,sizeof *e);
		e->attr.s=(char*)e+sizeof(centry); memcpy(e->attr.s,k.s,klen); e->attr.len=klen;
		e->next=CH[b]; CH[b]=e; }
	printf("  chain, prepend                        %8.1f ns/insert\n",(now()-t)*1e9/NKEYS);

	sb *S=calloc(NBUCK,sizeof *S);
	t=now();
	for(int i=0;i<NKEYS;i++){ str k={keys[i],klen}; unsigned h=core_hash(&k,NULL,0),b=h&(NBUCK-1);
		rec *r=mkrec(keys[i]);
		if(S[b].n==S[b].cap){S[b].cap=S[b].cap?S[b].cap*2:8;S[b].v=realloc(S[b].v,S[b].cap*sizeof(slot));}
		int j=S[b].n-1; while(j>=0&&S[b].v[j].hash>h){S[b].v[j+1]=S[b].v[j];j--;}
		S[b].v[j+1].hash=h;S[b].v[j+1].r=r;S[b].n++; }
	printf("  eager sorted insert (memmove)         %8.1f ns/insert\n",(now()-t)*1e9/NKEYS);

	pb *P=calloc(NBUCK,sizeof *P);
	long merges=0; double merge_time=0;
	t=now();
	for(int i=0;i<NKEYS;i++){ str k={keys[i],klen}; unsigned h=core_hash(&k,NULL,0),b=h&(NBUCK-1);
		rec *r=mkrec(keys[i]);
		if(P[b].tn==TAILMAX){                       /* worker would normally do this */
			double m0=now();
			if(P[b].n+TAILMAX>P[b].cap){P[b].cap=(P[b].n+TAILMAX)*2;P[b].v=realloc(P[b].v,P[b].cap*sizeof(slot));}
			memcpy(P[b].v+P[b].n,P[b].tail,TAILMAX*sizeof(slot)); P[b].n+=TAILMAX; P[b].tn=0;
			qsort(P[b].v,P[b].n,sizeof(slot),cmp);
			merge_time+=now()-m0; merges++;
		}
		P[b].tail[P[b].tn].hash=h; P[b].tail[P[b].tn].r=r; P[b].tn++; }
	double tp=now()-t;
	printf("  prefix+tail, append only              %8.1f ns/insert  (excl. merge: %.1f)\n",
	       tp*1e9/NKEYS,(tp-merge_time)*1e9/NKEYS);
	printf("     -> %ld merges, %.1f ms total, %.1f us each  <- worker's job\n\n",
	       merges,merge_time*1e3,merge_time*1e6/(merges?merges:1));

	/* ---------------- LOOKUP cost ---------------- */
	printf("== lookup cost ==\n");
	volatile unsigned long hit=0;

	t=now();
	for(int i=0;i<ITERS;i++){ int ki=(int)(((long)i*7919)%NKEYS); str k={keys[ki],klen};
		unsigned b=core_hash(&k,NULL,NBUCK);
		for(centry *e=CH[b];e;e=e->next)
			if(e->attr.len==klen&&strncmp(e->attr.s,k.s,klen)==0){hit++;break;} }
	double lc=(now()-t)*1e9/ITERS;
	printf("  chain + strncmp (current)             %8.1f ns   1.00x\n",lc);

	t=now(); hit=0;
	for(int i=0;i<ITERS;i++){ int ki=(int)(((long)i*7919)%NKEYS); str k={keys[ki],klen};
		unsigned h=core_hash(&k,NULL,0),b=h&(NBUCK-1);
		int lo=0,hi=S[b].n-1;
		while(lo<=hi){int m=(lo+hi)>>1;
			if(S[b].v[m].hash<h)lo=m+1; else if(S[b].v[m].hash>h)hi=m-1;
			else{rec*r=S[b].v[m].r; if(r->klen==klen&&memcmp(r->key,k.s,klen)==0)hit++; break;}} }
	double ls=(now()-t)*1e9/ITERS;
	printf("  fully sorted, binary search           %8.1f ns  %5.1fx\n",ls,lc/ls);

	t=now(); hit=0;
	for(int i=0;i<ITERS;i++){ int ki=(int)(((long)i*7919)%NKEYS); str k={keys[ki],klen};
		unsigned h=core_hash(&k,NULL,0),b=h&(NBUCK-1);
		int lo=0,hi=P[b].n-1,found=0;
		while(lo<=hi){int m=(lo+hi)>>1;
			if(P[b].v[m].hash<h)lo=m+1; else if(P[b].v[m].hash>h)hi=m-1;
			else{rec*r=P[b].v[m].r; if(r->klen==klen&&memcmp(r->key,k.s,klen)==0){hit++;found=1;} break;}}
		if(!found) for(int j=0;j<P[b].tn;j++) if(P[b].tail[j].hash==h){
			rec*r=P[b].tail[j].r; if(r->klen==klen&&memcmp(r->key,k.s,klen)==0){hit++;break;} } }
	double lp=(now()-t)*1e9/ITERS;
	printf("  prefix (bsearch) + tail (scan <=%d)    %8.1f ns  %5.1fx\n",TAILMAX,lp,lc/lp);
	return 0;
}
