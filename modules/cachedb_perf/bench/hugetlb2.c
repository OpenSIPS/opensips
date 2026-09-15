/*
 * Modern-kernel huge page routes for a MAP_SHARED|MAP_ANON region
 * (which is byte-for-byte what OpenSIPS shm_getmem() maps).
 *
 * modes:
 *   base      4K, as today
 *   madvise   MADV_HUGEPAGE before fill      (needs shmem_enabled=advise)
 *   collapse  fill on 4K, then MADV_COLLAPSE (6.1+; claims to ignore sysfs)
 *   hugetlb   MAP_HUGETLB 2M                 (needs reserved/overcommit pool)
 *   huge1g    MAP_HUGETLB|MAP_HUGE_1GB       (needs 1G pages in pool)
 *
 * Prints ShmemHugePages/HugePages delta so we verify pages were ACTUALLY
 * huge - the mistake to avoid is benchmarking 4K against 4K and calling it
 * a null result.
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

#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25
#endif
#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif
#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#define MAP_HUGE_1GB (30 << MAP_HUGE_SHIFT)
#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif

#define REGION_DEF (256UL*1024*1024)
static unsigned long REGION = REGION_DEF;
#define LINE 64

static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+1e-9*t.tv_nsec;}

static long meminfo(const char *key)
{
	FILE *f = fopen("/proc/meminfo","r"); char k[64]; long v = -1;
	if (!f) return -1;
	while (fscanf(f, "%63s %ld kB\n", k, &v) == 2)
		if (!strncmp(k, key, strlen(key))) { fclose(f); return v; }
	fclose(f); return -1;
}

static void build_chain(char *base)
{
	unsigned long n = REGION/LINE;
	unsigned long *ord = malloc(n*sizeof *ord);
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

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "base";
	if (argc > 2) REGION = strtoul(argv[2], NULL, 0) * 1024UL * 1024UL;

	long shmem0 = meminfo("ShmemHugePages"), huge0 = meminfo("HugePages_Free");

	int fl = MAP_SHARED|MAP_ANONYMOUS;
	if (!strcmp(mode,"hugetlb")) fl |= MAP_HUGETLB|MAP_HUGE_2MB;
	if (!strcmp(mode,"huge1g"))  fl |= MAP_HUGETLB|MAP_HUGE_1GB;

	void *p = mmap(NULL, REGION, PROT_READ|PROT_WRITE, fl, -1, 0);
	if (p == MAP_FAILED) { printf("%-9s mmap FAILED: %s\n", mode, strerror(errno)); return 2; }

	if (!strcmp(mode,"madvise"))
		if (madvise(p, REGION, MADV_HUGEPAGE))
			printf("%-9s MADV_HUGEPAGE: %s\n", mode, strerror(errno));

	/* fill = the fault cost, timed */
	double t = now();
	memset(p, 1, REGION);
	double t_fill = now() - t;

	double t_col = 0;
	if (!strcmp(mode,"collapse")) {
		t = now();
		if (madvise(p, REGION, MADV_COLLAPSE)) {
			printf("%-9s MADV_COLLAPSE FAILED: %s\n", mode, strerror(errno));
			munmap(p, REGION); return 3;
		}
		t_col = now() - t;
	}

	long shmem1 = meminfo("ShmemHugePages"), huge1 = meminfo("HugePages_Free");
	long huge_mb = (shmem1-shmem0)/1024 + (huge0-huge1)*2;   /* THP kB delta + hugetlb 2M pages used */

	build_chain(p);

	/* dependent chase */
	unsigned long iters = 5000000;
	void *q = *(void**)p;
	t = now();
	for (unsigned long i=0;i<iters;i++) q = *(void**)q;
	double chase = (now()-t)*1e9/iters;
	__asm__ volatile("" :: "r"(q));

	/* independent reads */
	unsigned seed=999; volatile unsigned long sink=0;
	unsigned long n = REGION/LINE;
	t = now();
	for (unsigned long i=0;i<20000000UL;i++){
		seed=seed*1103515245u+12345u;
		sink += *(volatile unsigned char*)((char*)p + ((unsigned long)(seed>>8)%n)*LINE);
	}
	double indep = (now()-t)*1e9/20000000UL; (void)sink;

	printf("%-9s fill %7.1f ms%s  huge %4ld/%lu MB  indep %6.2f ns  chase %7.2f ns\n",
	       mode, t_fill*1e3,
	       t_col ? ({ static char b[32]; snprintf(b,sizeof b," +collapse %.0f ms",t_col*1e3); b; }) : "",
	       huge_mb, REGION/1024/1024, indep, chase);

	munmap(p, REGION);
	return 0;
}
