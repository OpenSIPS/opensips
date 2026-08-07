/*
 * Can the arena be pinned against swap, and what does it cost?
 *
 *  - mlock() on the MAP_SHARED|MAP_ANON region OpenSIPS shm uses
 *  - verified via /proc/meminfo Mlocked/Unevictable deltas, never assumed
 *  - fork test: locks are NOT inherited (man mlock2), but the pages are
 *    SHARED - so a lock held by the pre-fork process pins them for every
 *    worker. This decides where the call must live: mod_init.
 *  - mlock doubles as a pre-fault (it must populate to pin) - timed against
 *    MADV_POPULATE_WRITE.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MADV_POPULATE_WRITE
#define MADV_POPULATE_WRITE 23
#endif

static unsigned long REGION = 256UL*1024*1024;

static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+1e-9*t.tv_nsec;}
static long mi(const char *key)
{
	FILE *f = fopen("/proc/meminfo","r"); char k[64]; long v=-1;
	while (f && fscanf(f,"%63s %ld kB\n",k,&v)==2)
		if (!strncmp(k,key,strlen(key))) { fclose(f); return v; }
	if (f) fclose(f); return -1;
}

int main(int argc, char **argv)
{
	if (argc > 1) REGION = strtoul(argv[1],NULL,0)*1024UL*1024UL;

	struct rlimit rl;
	getrlimit(RLIMIT_MEMLOCK, &rl);
	printf("RLIMIT_MEMLOCK: cur=%ld KB  (region: %lu MB)\n",
	       rl.rlim_cur==RLIM_INFINITY?-1:(long)(rl.rlim_cur/1024), REGION/1024/1024);

	void *p = mmap(NULL, REGION, PROT_READ|PROT_WRITE,
	               MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	if (p==MAP_FAILED){perror("mmap");return 1;}

	long l0 = mi("Mlocked"), u0 = mi("Unevictable");

	/* cold mlock: populates AND pins in one call */
	double t = now();
	if (mlock(p, REGION)) { printf("mlock FAILED: %s\n", strerror(errno)); return 2; }
	double t_mlock = now()-t;

	long l1 = mi("Mlocked"), u1 = mi("Unevictable");
	printf("mlock cold (populate+pin):  %7.1f ms   Mlocked +%ld MB, Unevictable +%ld MB\n",
	       t_mlock*1e3, (l1-l0)/1024, (u1-u0)/1024);

	/* fork: child has NO lock of its own, but pages stay pinned because the
	 * parent (i.e. the pre-fork attendant in OpenSIPS) still holds the lock */
	pid_t pid = fork();
	if (pid == 0) {
		memset(p, 7, REGION);                      /* child writes shared pages */
		long lc = mi("Mlocked");
		printf("in child (no own lock):              Mlocked still +%ld MB globally\n",
		       (lc-l0)/1024);
		fflush(stdout);
		_exit(0);
	}
	waitpid(pid, NULL, 0);

	munlock(p, REGION);
	long l2 = mi("Mlocked");
	printf("after munlock:                        Mlocked +%ld MB (back to baseline)\n",
	       (l2-l0)/1024);

	/* compare: populate-then-lock as two steps */
	munmap(p, REGION);
	p = mmap(NULL, REGION, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	t = now();
	int rc = madvise(p, REGION, MADV_POPULATE_WRITE);
	double t_pop = now()-t;
	t = now();
	rc |= mlock(p, REGION);
	double t_lock2 = now()-t;
	if (!rc)
		printf("two-step: POPULATE_WRITE %7.1f ms + warm mlock %7.1f ms = %7.1f ms total\n",
		       t_pop*1e3, t_lock2*1e3, (t_pop+t_lock2)*1e3);
	munlock(p, REGION); munmap(p, REGION);
	return 0;
}
