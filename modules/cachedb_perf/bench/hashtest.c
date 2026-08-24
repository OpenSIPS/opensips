/* Measure core_hash() distribution vs alternatives on realistic cachedb_local keys */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct { char *s; int len; } str;

/* ---- verbatim from opensips hash_func.h ---- */
#define ch_h_inc h+=v^(v>>3)
static inline unsigned int core_hash(const str *s1, const str *s2, const unsigned int size)
{
	char *p, *end;
	register unsigned v;
	register unsigned h;
	h=0;
	end=s1->s+s1->len;
	for ( p=s1->s ; p<=(end-4) ; p+=4 ){
		v=(*p<<24)+(p[1]<<16)+(p[2]<<8)+p[3];
		ch_h_inc;
	}
	v=0;
	for (; p<end ; p++){ v<<=8; v+=*p;}
	ch_h_inc;
	if (s2) {
		end=s2->s+s2->len;
		for (p=s2->s; p<=(end-4); p+=4){
			v=(*p<<24)+(p[1]<<16)+(p[2]<<8)+p[3];
			ch_h_inc;
		}
		v=0;
		for (; p<end ; p++){ v<<=8; v+=*p;}
		ch_h_inc;
	}
	h=((h)+(h>>11))+((h>>13)+(h>>23));
	return size?((h)&(size-1)):h;
}

/* ---- candidate: FNV-1a 64 + fibonacci/murmur finalizer ---- */
static inline uint64_t fnv1a(const char *s, int len)
{
	uint64_t h = 1469598103934665603ULL;
	for (int i = 0; i < len; i++) { h ^= (unsigned char)s[i]; h *= 1099511628211ULL; }
	h ^= h >> 33; h *= 0xff51afd7ed558ccdULL; h ^= h >> 33;
	return h;
}

/* ---- key generators ---- */
static void hexkey(char *b, int i)          { sprintf(b, "%016x", (unsigned)(i * 2654435761u)); }   /* TH thid style */
static void dlgkey(char *b, int i)          { sprintf(b, "dlg_%d_%d", i, i * 7919); }
static void aorkey(char *b, int i)          { sprintf(b, "%d@sip4c.au.voipcloud.dev", 500000 + i); }
static void callidkey(char *b, int i)       { sprintf(b, "%08x-%04x-4%03x@10.22.23.%d", i*2654435761u, i&0xffff, i&0xfff, 100+(i%150)); }

struct kind { const char *name; void (*gen)(char*,int); };

static void run(const char *name, void (*gen)(char*,int), int n, int nbuck)
{
	int *c1 = calloc(nbuck, sizeof(int));
	int *c2 = calloc(nbuck, sizeof(int));
	char buf[128]; str s;

	for (int i = 0; i < n; i++) {
		gen(buf, i);
		s.s = buf; s.len = strlen(buf);
		c1[core_hash(&s, NULL, nbuck)]++;
		c2[fnv1a(buf, s.len) & (nbuck - 1)]++;
	}

	double ideal = (double)n / nbuck;
	for (int pass = 0; pass < 2; pass++) {
		int *c = pass ? c2 : c1;
		int empty = 0, max = 0; double chi = 0, walk = 0;
		for (int i = 0; i < nbuck; i++) {
			if (!c[i]) empty++;
			if (c[i] > max) max = c[i];
			chi += (c[i] - ideal) * (c[i] - ideal) / ideal;
			/* expected compares for a successful lookup landing in this bucket */
			walk += (double)c[i] * (c[i] + 1) / 2.0;
		}
		printf("  %-22s %-9s buckets=%-6d empty=%5.1f%%  max_chain=%-5d  chi2/df=%6.2f  avg_cmp=%5.1f\n",
		       name, pass ? "fnv1a" : "core_hash", nbuck,
		       100.0 * empty / nbuck, max, chi / nbuck, walk / n);
	}
	free(c1); free(c2);
}

int main(void)
{
	struct kind kinds[] = {
		{"th 16-hex thid",  hexkey},
		{"dialog id",       dlgkey},
		{"usrloc aor",      aorkey},
		{"call-id",         callidkey},
	};
	int n = 50000;

	printf("== %d keys ==\n", n);
	for (int b = 0; b < 2; b++) {
		int nb = b ? 65536 : 512;
		printf("\n-- hash_size %s (%d buckets), load factor %.1f --\n",
		       b ? "16" : "9 (default)", nb, (double)n / nb);
		for (unsigned k = 0; k < sizeof(kinds)/sizeof(*kinds); k++)
			run(kinds[k].name, kinds[k].gen, n, nb);
	}
	return 0;
}
