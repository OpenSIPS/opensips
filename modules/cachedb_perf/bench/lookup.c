/* Cost of a cachedb_local lookup: chain walk + strncmp, vs stored-hash, vs resized */
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

/* current entry layout, verbatim field order */
typedef struct lcache_entry {
	str attr; str value;
	unsigned int expires; unsigned int ttl; int synced;
	struct lcache_entry *next;
} entry_t;

/* proposed: hash cached in the entry, no redundant pointers */
typedef struct entry2 {
	struct entry2 *next;
	unsigned int hash;
	unsigned int expires;
	unsigned short attr_len; unsigned short pad;
	unsigned int val_len;
	char data[];
} entry2_t;

typedef struct { entry_t  *e; char _pad[8]; } bucket_t;   /* ptr + lock, as today */
typedef struct { entry2_t *e; char _pad[8]; } bucket2_t;

#define NKEYS  50000
#define VALLEN 200
#define ITERS  2000000

static char keys[NKEYS][20];

static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+1e-9*t.tv_nsec; }

/* scatter allocations the way shm_malloc would after a busy run */
static void *scatter_alloc(size_t sz)
{
	void *p = malloc(sz);
	void *junk = malloc(16 + (rand() & 127));   /* fragment the heap between entries */
	(void)junk;
	return p;
}

int main(void)
{
	srand(12345);
	for (int i = 0; i < NKEYS; i++) sprintf(keys[i], "%016x", (unsigned)(i * 2654435761u));

	printf("sizeof(lcache_entry_t) = %zu   proposed = %zu\n\n",
	       sizeof(entry_t), sizeof(entry2_t));

	int sizes[] = { 512, 65536 };
	for (int si = 0; si < 2; si++) {
		int nb = sizes[si];
		bucket_t  *t1 = calloc(nb, sizeof(bucket_t));
		bucket2_t *t2 = calloc(nb, sizeof(bucket2_t));

		for (int i = 0; i < NKEYS; i++) {
			str k = { keys[i], (int)strlen(keys[i]) };
			unsigned h = core_hash(&k, NULL, 0);
			unsigned b = h & (nb - 1);

			entry_t *e = scatter_alloc(sizeof(entry_t) + k.len + VALLEN);
			memset(e, 0, sizeof *e);
			e->attr.s = (char*)e + sizeof(entry_t); memcpy(e->attr.s, k.s, k.len); e->attr.len = k.len;
			e->value.s = e->attr.s + k.len;         e->value.len = VALLEN;
			e->next = t1[b].e; t1[b].e = e;

			entry2_t *f = scatter_alloc(sizeof(entry2_t) + k.len + VALLEN);
			f->hash = h; f->attr_len = k.len; f->val_len = VALLEN; f->expires = 0;
			memcpy(f->data, k.s, k.len);
			f->next = t2[b].e; t2[b].e = f;
		}

		/* --- A: current --- */
		double t = now(); unsigned long hits = 0;
		for (int i = 0; i < ITERS; i++) {
			int ki = (int)(((long)i * 7919) % NKEYS);
			str k = { keys[ki], (int)strlen(keys[ki]) };
			unsigned b = core_hash(&k, NULL, nb);
			for (entry_t *e = t1[b].e; e; e = e->next)
				if (e->attr.len == k.len && strncmp(e->attr.s, k.s, k.len) == 0) { hits++; break; }
		}
		double ta = now() - t;

		/* --- B: hash stored in entry, memcmp only on hash match --- */
		t = now(); unsigned long hits2 = 0;
		for (int i = 0; i < ITERS; i++) {
			int ki = (int)(((long)i * 7919) % NKEYS);
			str k = { keys[ki], (int)strlen(keys[ki]) };
			unsigned h = core_hash(&k, NULL, 0);
			unsigned b = h & (nb - 1);
			for (entry2_t *e = t2[b].e; e; e = e->next)
				if (e->hash == h && e->attr_len == k.len &&
				    memcmp(e->data, k.s, k.len) == 0) { hits2++; break; }
		}
		double tb = now() - t;

		printf("-- %d buckets (load %.1f) --\n", nb, (double)NKEYS/nb);
		printf("   A current  (walk + strncmp)   : %6.2f s   %8.1f ns/lookup   (%lu hits)\n",
		       ta, ta*1e9/ITERS, hits);
		printf("   B stored hash + memcmp        : %6.2f s   %8.1f ns/lookup   (%.2fx)\n",
		       tb, tb*1e9/ITERS, ta/tb);
	}
	return 0;
}
