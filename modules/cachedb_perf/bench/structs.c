/*
 * cachedb_local index-structure shootout.
 * 50k keys, 200-byte out-of-line values, allocations scattered to mimic shm
 * fragmentation after a busy run.  Measures SUCCESSFUL point lookups (hot path).
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

static char keys[NKEYS][20];
static int  klen;

static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+1e-9*t.tv_nsec; }
static void *salloc(size_t sz){ void *p = malloc(sz); (void)!malloc(16+(rand()&127)); return p; }

/* ============ A: current - chained list, str pointers, strncmp ============ */
typedef struct centry { str attr, value; unsigned expires, ttl; int synced; struct centry *next; } centry;
typedef struct { centry *e; int lock; } cbucket;

/* ============ B: chained, hash cached in node ============ */
typedef struct hentry { struct hentry *next; unsigned hash; unsigned short klen; char *val; char key[]; } hentry;
typedef struct { hentry *e; int lock; } hbucket;

/* ============ C: sorted array per bucket (binary search, contiguous) ============ */
typedef struct { unsigned hash; void *rec; } slot;
typedef struct { slot *v; int n, cap; int lock; } sbucket;
typedef struct { unsigned short klen; char *val; char key[]; } srec;

/* ============ D: cache-line bucket, 4 inline (hash,ptr) + overflow ============ */
typedef struct dovf { struct dovf *next; unsigned h[4]; void *p[4]; int n; } dovf;
typedef struct { unsigned h[4]; void *p[4]; int n; dovf *ovf; } dbucket;   /* 64B-ish */

/* ============ E: flat open addressing, linear probe (Swiss-lite) ============ */
typedef struct { unsigned hash; void *rec; } fslot;   /* hash==0 means empty */

int main(void)
{
	srand(12345);
	for (int i = 0; i < NKEYS; i++) sprintf(keys[i], "%016x", (unsigned)(i * 2654435761u));
	klen = strlen(keys[0]);
	char *val = malloc(VALLEN);

	printf("50000 keys, %d-byte keys, %d-byte values, %d lookups each\n\n", klen, VALLEN, ITERS);
	printf("%-46s %10s %9s %10s\n", "design", "ns/lookup", "speedup", "index MB");
	printf("%-46s %10s %9s %10s\n", "------", "---------", "-------", "--------");

	double base512 = 0, base64k = 0;

	for (int si = 0; si < 2; si++) {
		int nb = si ? 65536 : 512;

		/* ---------- A ---------- */
		cbucket *A = calloc(nb, sizeof *A);
		for (int i = 0; i < NKEYS; i++) {
			str k = { keys[i], klen };
			unsigned b = core_hash(&k, NULL, nb);
			centry *e = salloc(sizeof(centry) + klen + VALLEN);
			memset(e, 0, sizeof *e);
			e->attr.s = (char*)e + sizeof(centry); memcpy(e->attr.s, k.s, klen); e->attr.len = klen;
			e->value.s = e->attr.s + klen; e->value.len = VALLEN;
			e->next = A[b].e; A[b].e = e;
		}
		double t = now(); volatile unsigned long hit = 0;
		for (int i = 0; i < ITERS; i++) {
			int ki = (int)(((long)i*7919)%NKEYS);
			str k = { keys[ki], klen };
			unsigned b = core_hash(&k, NULL, nb);
			for (centry *e = A[b].e; e; e = e->next)
				if (e->attr.len == klen && strncmp(e->attr.s, k.s, klen)==0) { hit++; break; }
		}
		double ta = (now()-t)*1e9/ITERS;
		double memA = (double)nb*sizeof(cbucket)/1048576.0;
		if (si) base64k = ta; else base512 = ta;
		printf("\n-- %d buckets (load factor %.1f) --\n", nb, (double)NKEYS/nb);
		printf("%-46s %10.1f %9s %10.2f\n", "A  current: chained list + strncmp", ta, "1.00x", memA);

		/* ---------- B ---------- */
		hbucket *B = calloc(nb, sizeof *B);
		for (int i = 0; i < NKEYS; i++) {
			str k = { keys[i], klen };
			unsigned h = core_hash(&k, NULL, 0); unsigned b = h & (nb-1);
			hentry *e = salloc(sizeof(hentry) + klen + VALLEN);
			e->hash=h; e->klen=klen; memcpy(e->key,k.s,klen); e->val=e->key+klen;
			e->next=B[b].e; B[b].e=e;
		}
		t = now(); hit = 0;
		for (int i = 0; i < ITERS; i++) {
			int ki = (int)(((long)i*7919)%NKEYS);
			str k = { keys[ki], klen };
			unsigned h = core_hash(&k,NULL,0); unsigned b = h&(nb-1);
			for (hentry *e = B[b].e; e; e = e->next)
				if (e->hash==h && e->klen==klen && memcmp(e->key,k.s,klen)==0){hit++;break;}
		}
		double tb = (now()-t)*1e9/ITERS;
		printf("%-46s %10.1f %8.2fx %10.2f\n", "B  chained + hash cached in node", tb, ta/tb,
		       (double)nb*sizeof(hbucket)/1048576.0);

		/* ---------- C ---------- */
		sbucket *C = calloc(nb, sizeof *C);
		for (int i = 0; i < NKEYS; i++) {
			str k = { keys[i], klen };
			unsigned h = core_hash(&k,NULL,0); unsigned b = h&(nb-1);
			srec *r = salloc(sizeof(srec)+klen+VALLEN);
			r->klen=klen; memcpy(r->key,k.s,klen); r->val=r->key+klen;
			if (C[b].n==C[b].cap){ C[b].cap = C[b].cap?C[b].cap*2:4; C[b].v=realloc(C[b].v,C[b].cap*sizeof(slot)); }
			int j=C[b].n-1; while(j>=0 && C[b].v[j].hash>h){C[b].v[j+1]=C[b].v[j];j--;}
			C[b].v[j+1].hash=h; C[b].v[j+1].rec=r; C[b].n++;
		}
		t = now(); hit = 0;
		for (int i = 0; i < ITERS; i++) {
			int ki = (int)(((long)i*7919)%NKEYS);
			str k = { keys[ki], klen };
			unsigned h = core_hash(&k,NULL,0); unsigned b = h&(nb-1);
			int lo=0, hi2=C[b].n-1;
			while(lo<=hi2){ int m=(lo+hi2)/2;
				if(C[b].v[m].hash<h) lo=m+1; else if(C[b].v[m].hash>h) hi2=m-1;
				else { srec *r=C[b].v[m].rec; if(r->klen==klen&&memcmp(r->key,k.s,klen)==0)hit++; break; } }
		}
		double tc = (now()-t)*1e9/ITERS;
		printf("%-46s %10.1f %8.2fx %10.2f\n", "C  sorted array/bucket + binary search", tc, ta/tc,
		       (double)nb*sizeof(sbucket)/1048576.0 + (double)NKEYS*sizeof(slot)/1048576.0);

		free(A); free(B); free(C);
	}

	/* ---------- D: cache-line buckets, sized so ~3 entries fit inline ---------- */
	{
		int nb = 16384;
		dbucket *D = calloc(nb, sizeof *D);
		for (int i = 0; i < NKEYS; i++) {
			str k = { keys[i], klen };
			unsigned h = core_hash(&k,NULL,0); unsigned b = h&(nb-1);
			srec *r = salloc(sizeof(srec)+klen+VALLEN);
			r->klen=klen; memcpy(r->key,k.s,klen); r->val=r->key+klen;
			if (D[b].n<4){ D[b].h[D[b].n]=h; D[b].p[D[b].n]=r; D[b].n++; }
			else { dovf *o=D[b].ovf; if(!o||o->n==4){ dovf *n2=salloc(sizeof(dovf)); memset(n2,0,sizeof *n2);
					n2->next=D[b].ovf; D[b].ovf=n2; o=n2; }
				o->h[o->n]=h; o->p[o->n]=r; o->n++; }
		}
		double t = now(); volatile unsigned long hit=0;
		for (int i = 0; i < ITERS; i++) {
			int ki = (int)(((long)i*7919)%NKEYS);
			str k = { keys[ki], klen };
			unsigned h = core_hash(&k,NULL,0); unsigned b = h&(nb-1);
			int found=0;
			for(int j=0;j<D[b].n;j++) if(D[b].h[j]==h){ srec*r=D[b].p[j];
				if(r->klen==klen&&memcmp(r->key,k.s,klen)==0){hit++;found=1;break;} }
			if(!found) for(dovf*o=D[b].ovf;o&&!found;o=o->next)
				for(int j=0;j<o->n;j++) if(o->h[j]==h){ srec*r=o->p[j];
					if(r->klen==klen&&memcmp(r->key,k.s,klen)==0){hit++;found=1;break;} }
		}
		double td=(now()-t)*1e9/ITERS;
		printf("\n-- alternative layouts, self-sized --\n");
		printf("%-46s %10.1f %8.2fx %10.2f\n","D  64B cache-line bucket, 4 inline slots",td,base512/td,
		       (double)nb*sizeof(dbucket)/1048576.0);
		printf("%-46s %10s %8.2fx %10s\n","   (vs well-sized chained, B@64k)","", base64k/td, "");
	}

	/* ---------- E: flat open addressing, load 0.38 ---------- */
	{
		int ns = 131072;
		fslot *E = calloc(ns, sizeof *E);
		for (int i = 0; i < NKEYS; i++) {
			str k = { keys[i], klen };
			unsigned h = core_hash(&k,NULL,0); if(!h)h=1;
			srec *r = salloc(sizeof(srec)+klen+VALLEN);
			r->klen=klen; memcpy(r->key,k.s,klen); r->val=r->key+klen;
			unsigned p = h&(ns-1);
			while(E[p].hash) p=(p+1)&(ns-1);
			E[p].hash=h; E[p].rec=r;
		}
		double t=now(); volatile unsigned long hit=0;
		for (int i = 0; i < ITERS; i++) {
			int ki=(int)(((long)i*7919)%NKEYS);
			str k={keys[ki],klen};
			unsigned h=core_hash(&k,NULL,0); if(!h)h=1;
			unsigned p=h&(ns-1);
			while(E[p].hash){ if(E[p].hash==h){ srec*r=E[p].rec;
					if(r->klen==klen&&memcmp(r->key,k.s,klen)==0){hit++;break;} }
				p=(p+1)&(ns-1); }
		}
		double te=(now()-t)*1e9/ITERS;
		printf("%-46s %10.1f %8.2fx %10.2f\n","E  flat open addressing (linear probe)",te,base512/te,
		       (double)ns*sizeof(fslot)/1048576.0);
		printf("%-46s %10s %8.2fx %10s\n","   (vs well-sized chained, B@64k)","", base64k/te, "");
	}
	free(val);
	return 0;
}
