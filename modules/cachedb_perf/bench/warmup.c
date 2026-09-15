/*
 * Two costs OpenSIPS shm currently pays, neither addressed:
 *
 *  1. FIRST TOUCH. mmap(MAP_ANON) is demand-paged, so the first write to each
 *     4K page takes a minor fault. This is what pre-warming would remove.
 *  2. TLB PRESSURE. A large cache accessed randomly through 4K pages misses
 *     the TLB on nearly every access. Huge pages would remove that - and it is
 *     an ONGOING cost, not a one-time one.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/mman.h>
#include <unistd.h>

#define REGION (256UL*1024*1024)
#define ENTSZ  256
#define NENT   (REGION/ENTSZ)

static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+1e-9*t.tv_nsec;}

static void *map_region(int huge)
{
	void *p = mmap(NULL, REGION, PROT_READ|PROT_WRITE,
	               MAP_SHARED|MAP_ANONYMOUS, -1, 0);   /* exactly what shm_getmem does */
	if (p == MAP_FAILED) { perror("mmap"); exit(1); }
#ifdef MADV_HUGEPAGE
	madvise(p, REGION, huge ? MADV_HUGEPAGE : MADV_NOHUGEPAGE);
#endif
	return p;
}

int main(void)
{
	char payload[ENTSZ];
	memset(payload, 'x', sizeof payload);
	printf("region %lu MB, entry %d B, %lu entries, page %ld B\n\n",
	       REGION/1024/1024, ENTSZ, NENT, sysconf(_SC_PAGESIZE));

	/* ---------- 1. first-touch cost ---------- */
	printf("== cost of the FIRST write to each page (what pre-warming removes) ==\n");

	char *cold = map_region(0);
	double t = now();
	for (unsigned long i = 0; i < NENT; i++) memcpy(cold + i*ENTSZ, payload, ENTSZ);
	double t_cold = now() - t;

	char *warm = map_region(0);
	t = now();
	memset(warm, 0, REGION);                       /* the proposed warm-up */
	double t_warm = now() - t;
	t = now();
	for (unsigned long i = 0; i < NENT; i++) memcpy(warm + i*ENTSZ, payload, ENTSZ);
	double t_pre = now() - t;

	printf("  fill cold (faults inline)     %8.1f ms   %6.1f ns/entry\n", t_cold*1e3, t_cold*1e9/NENT);
	printf("  fill pre-warmed               %8.1f ms   %6.1f ns/entry\n", t_pre*1e3,  t_pre*1e9/NENT);
	printf("  warm-up pass itself           %8.1f ms   (one-time, %.0f MB memset)\n",
	       t_warm*1e3, (double)REGION/1024/1024);
	printf("  -> first touch costs %.1f ns/entry, %.0f ms total for %lu MB\n",
	       (t_cold-t_pre)*1e9/NENT, (t_cold-t_pre)*1e3, REGION/1024/1024);
	printf("  -> net saving of pre-warming: %.0f ms (it moves cost, it does not remove it)\n\n",
	       (t_cold - t_pre - t_warm)*1e3);
	munmap(cold, REGION);

	/* ---------- 2. ongoing TLB cost: 4K vs huge pages ---------- */
	printf("== ONGOING cost: random access, 4K pages vs transparent huge pages ==\n");
	char *h4 = map_region(0), *h2 = map_region(1);
	memset(h4, 1, REGION); memset(h2, 1, REGION);

	unsigned long n = 20000000;
	volatile unsigned long sink = 0;
	for (int pass = 0; pass < 2; pass++) {
		char *r = pass ? h2 : h4;
		unsigned seed = 12345;
		t = now();
		for (unsigned long i = 0; i < n; i++) {
			seed = seed*1103515245u + 12345u;
			unsigned long off = ((unsigned long)seed % NENT) * ENTSZ;
			sink += r[off];                      /* one random line per iteration */
		}
		double el = now() - t;
		printf("  %-28s %7.1f ns/access   %6.1f M/s\n",
		       pass ? "transparent huge pages" : "4K pages (as today)",
		       el*1e9/n, n/el/1e6);
	}
	printf("  (sink=%lu)\n", sink);

	FILE *f = fopen("/sys/kernel/mm/transparent_hugepage/enabled","r");
	if (f) { char b[128]; if (fgets(b,sizeof b,f)) printf("\n  system THP setting: %s", b); fclose(f); }
	return 0;
}
