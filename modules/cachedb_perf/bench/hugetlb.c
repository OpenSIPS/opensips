/*
 * Do huge pages actually help a cachedb_perf-shaped workload?
 *
 * Compares, over the SAME region size:
 *   A  MAP_SHARED|MAP_ANONYMOUS            <- exactly what OpenSIPS shm does
 *   B  MAP_SHARED|MAP_ANONYMOUS|MAP_HUGETLB (2 MB pages)
 *
 * Two access patterns, because they stress the TLB very differently:
 *   independent : random reads, CPU overlaps many misses (hides TLB cost)
 *   dependent   : pointer chase, one miss at a time (exposes TLB cost)
 * A hash lookup is a dependent chain: bucket -> deref slot -> compare key.
 *
 * Also times MADV_POPULATE_WRITE (Linux 5.14+) as a pre-fault mechanism.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif
#ifndef MADV_POPULATE_WRITE
#define MADV_POPULATE_WRITE 23
#endif

#define REGION (256UL*1024*1024)
#define LINE   64
#define NLINE  (REGION/LINE)
#define NITER  20000000UL

static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+1e-9*t.tv_nsec;}

static void *try_map(int huge)
{
	int fl = MAP_SHARED|MAP_ANONYMOUS | (huge?MAP_HUGETLB:0);
	void *p = mmap(NULL, REGION, PROT_READ|PROT_WRITE, fl, -1, 0);
	if (p == MAP_FAILED) return NULL;
	return p;
}

/* build a random cyclic pointer chase through the region */
static void build_chain(char *base)
{
	unsigned long n = NLINE;
	unsigned long *ord = malloc(n*sizeof(unsigned long));
	for (unsigned long i=0;i<n;i++) ord[i]=i;
	unsigned seed=12345;
	for (unsigned long i=n-1;i>0;i--){
		seed=seed*1103515245u+12345u;
		unsigned long j=(unsigned long)(seed>>8)%(i+1);
		unsigned long t=ord[i]; ord[i]=ord[j]; ord[j]=t;
	}
	for (unsigned long i=0;i<n;i++)
		*(void**)(base + ord[i]*LINE) = (void*)(base + ord[(i+1)%n]*LINE);
	free(ord);
}

static double indep(char *base, unsigned long iters)
{
	unsigned seed=999; volatile unsigned long sink=0;
	double t=now();
	for (unsigned long i=0;i<iters;i++){
		seed=seed*1103515245u+12345u;
		sink += *(volatile unsigned char*)(base + ((unsigned long)(seed>>8)%NLINE)*LINE);
	}
	double el=now()-t; (void)sink;
	return el*1e9/iters;
}

static double depend(char *base, unsigned long iters)
{
	void *p = *(void**)base;
	double t=now();
	for (unsigned long i=0;i<iters;i++) p = *(void**)p;
	double el=now()-t;
	__asm__ volatile("" :: "r"(p));
	return el*1e9/iters;
}

int main(void)
{
	printf("region %lu MB, %lu cache lines\n", REGION/1024/1024, NLINE);

	char *a = try_map(0);
	if (!a) { perror("mmap 4K"); return 1; }
	char *b = try_map(1);
	if (!b) {
		printf("\n!! MAP_HUGETLB failed: %s\n", strerror(errno));
		printf("   need reserved pages: sysctl -w vm.nr_hugepages=N\n");
		return 2;
	}

	/* pre-fault both so we measure access, not faults */
	memset(a, 1, REGION);
	memset(b, 1, REGION);
	build_chain(a);
	build_chain(b);

	printf("\n%-34s %14s %14s\n", "access pattern", "4K pages", "2M hugepages");
	double ia = indep(a, NITER), ib = indep(b, NITER);
	printf("%-34s %11.2f ns %11.2f ns   %5.2fx\n", "independent random reads", ia, ib, ia/ib);
	double da = depend(a, NITER/4), db = depend(b, NITER/4);
	printf("%-34s %11.2f ns %11.2f ns   %5.2fx\n", "dependent pointer chase", da, db, da/db);

	/* ---- pre-fault mechanisms ---- */
	printf("\n== pre-fault cost for %lu MB ==\n", REGION/1024/1024);
	char *c = try_map(0);
	double t = now(); memset(c, 0, REGION); double t_memset = now()-t;
	munmap(c, REGION);

	c = try_map(0);
	t = now();
	for (unsigned long off=0; off<REGION; off+=4096) c[off] = 0;
	double t_touch = now()-t;
	munmap(c, REGION);

	c = try_map(0);
	t = now();
	int rc = madvise(c, REGION, MADV_POPULATE_WRITE);
	double t_pop = now()-t;
	munmap(c, REGION);

	printf("  memset whole region        %8.1f ms\n", t_memset*1e3);
	printf("  touch 1 byte per 4K page   %8.1f ms\n", t_touch*1e3);
	if (rc == 0) printf("  MADV_POPULATE_WRITE        %8.1f ms   <- 5.14+, no data written\n", t_pop*1e3);
	else         printf("  MADV_POPULATE_WRITE        unavailable (%s)\n", strerror(errno));

	munmap(a, REGION); munmap(b, REGION);
	return 0;
}
