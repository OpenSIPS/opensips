#ifndef parallel_malloc_h
#define parallel_malloc_h

#include <stdio.h>
#include "meminfo.h"
#include "common.h"

#undef ROUNDTO

#if defined(__CPU_sparc64) || defined(__CPU_sparc)
/* tricky, on sun in 32 bits mode long long must be 64 bits aligned
 * but long can be 32 bits aligned => malloc should return long long
 * aligned memory */
	#define ROUNDTO		sizeof(long long)
#else
	#define ROUNDTO		sizeof(void *) /* address alignment, in bytes (2^n) */
#endif

#define F_PARALLEL_MALLOC_OPTIMIZE_FACTOR 14UL /*used below */

/* size to optimize for, (most allocs <= this size), must be 2^k */
#define F_PARALLEL_MALLOC_OPTIMIZE  (1UL << F_PARALLEL_MALLOC_OPTIMIZE_FACTOR)

#define F_PARALLEL_HASH_SIZE (F_PARALLEL_MALLOC_OPTIMIZE/ROUNDTO + \
		(sizeof(long)*8-F_PARALLEL_MALLOC_OPTIMIZE_FACTOR)+1)

/* get the fragment which corresponds to a pointer */
#define F_PARALLEL_FRAG(p) \
	((struct parallel_frag *)((char *)(p) - sizeof(struct parallel_frag)))

/* hash structure:
 * 0 .... F_MALLOC_OPTIMIZE/ROUNDTO  - small buckets, size increases with
 *                            ROUNDTO from bucket to bucket
 * +1 .... end -  size = 2^k, big buckets */

struct parallel_frag {
	unsigned long size;
	union {
		struct parallel_frag *nxt_free;
		long reserved;
	} u;
	struct parallel_frag **prev;
#ifdef DBG_MALLOC
	const char *file;
	const char *func;
	unsigned long line;
#endif

	/* we are hashing, need to know which is the big block for this allocation */
	struct parallel_block *block_ptr;

#ifdef SHM_EXTRA_STATS
	unsigned long statistic_index;
#endif
} __attribute__ ((aligned (ROUNDTO)));

#define F_PARALLEL_FRAG_OVERHEAD (sizeof(struct parallel_frag))

struct parallel_frag_lnk {
	struct parallel_frag *first;
	unsigned long no;
};

struct parallel_block {
	char *name; /* purpose of this memory block */

	unsigned long size; /* total size */
	unsigned long fragments; /* number of fragments in use */
#if defined(DBG_MALLOC) || defined(STATISTICS)
	unsigned long used; /* alloc'ed size */
	unsigned long real_used; /* used + malloc overhead */
	unsigned long max_real_used;
#endif

	int idx;

	struct parallel_frag *first_frag;
	struct parallel_frag *last_frag;

	struct parallel_frag_lnk free_hash[F_PARALLEL_HASH_SIZE];
} __attribute__ ((aligned (ROUNDTO)));

struct parallel_block *parallel_malloc_init(char *address, unsigned long size, char *name,int idx);

#ifdef DBG_MALLOC
void *parallel_malloc(struct parallel_block *fm, unsigned long size,
                const char *file, const char *func, unsigned int line);
void parallel_free(struct parallel_block *fm, void *p, const char *file,
             const char *func, unsigned int line);
void *parallel_realloc(struct parallel_block *fm, void *p, unsigned long size,
                 const char *file, const char *func, unsigned int line);
#ifndef INLINE_ALLOC
void *parallel_malloc_dbg(struct parallel_block *fm, unsigned long size,
                    const char *file, const char *func, unsigned int line);
void parallel_free_dbg(struct parallel_block *fm, void *p, const char *file,
                 const char *func, unsigned int line);
void *parallel_realloc_dbg(struct parallel_block *fm, void *p, unsigned long size,
                     const char *file, const char *func, unsigned int line);
#endif
#else
void *parallel_malloc(struct parallel_block *fm, unsigned long size);
void parallel_free(struct parallel_block *fm, void *p);
void *parallel_realloc(struct parallel_block *fm, void *p, unsigned long size);
#endif

void parallel_status(struct parallel_block *);
#if !defined INLINE_ALLOC && defined DBG_MALLOC
void parallel_status_dbg(struct parallel_block *);
#endif
void parallel_info(struct parallel_block *, struct mem_info *);

static inline unsigned long parallel_frag_size(void *p)
{
	if (!p)
		return 0;

	return F_PARALLEL_FRAG(p)->size;
}

#ifdef SHM_EXTRA_STATS
void parallel_stats_core_init(struct parallel_block *fm, int core_index);
unsigned long parallel_stats_get_index(void *ptr);
void parallel_stats_set_index(void *ptr, unsigned long idx);

#ifdef DBG_MALLOC
static inline const char *parallel_frag_file(void *p) { return F_PARALLEL_FRAG(p)->file; }
static inline const char *parallel_frag_func(void *p) { return F_PARALLEL_FRAG(p)->func; }
static inline unsigned long parallel_frag_line(void *p) { return F_PARALLEL_FRAG(p)->line; }
#else
static inline const char *parallel_frag_file(void *p) { return NULL; }
static inline const char *parallel_frag_func(void *p) { return NULL; }
static inline unsigned long parallel_frag_line(void *p) { return 0; }
#endif
#endif

#ifdef STATISTICS
static inline unsigned long parallel_get_size(struct parallel_block *fm)
{
	int i;
	unsigned long total_size=0;

	for (i=0;i<128;i++) {
		total_size += ((struct parallel_block *)shm_blocks[i])->size;
	}

	return total_size;
}
static inline unsigned long parallel_get_used(struct parallel_block *fm)
{
	int i;
	unsigned long total_size=0;

	for (i=0;i<128;i++) {
		total_size += ((struct parallel_block *)shm_blocks[i])->used;
	}

	return total_size;
}
static inline unsigned long parallel_get_free(struct parallel_block *fm)
{
	int i;
	unsigned long total_size=0;

	for (i=0;i<128;i++) {
		total_size += ((struct parallel_block *)shm_blocks[i])->size - 
			((struct parallel_block *)shm_blocks[i])->real_used;
	}

	return total_size;
}
static inline unsigned long parallel_get_real_used(struct parallel_block *fm)
{
	int i;
	unsigned long total_size=0;

	for (i=0;i<128;i++) {
		total_size += ((struct parallel_block *)shm_blocks[i])->real_used;
	}

	return total_size;
}
static inline unsigned long parallel_get_max_real_used(struct parallel_block *fm)
{
	int i;
	unsigned long total_size=0;

	for (i=0;i<128;i++) {
		total_size += ((struct parallel_block *)shm_blocks[i])->max_real_used;
	}

	return total_size;
}
static inline unsigned long parallel_get_frags(struct parallel_block *fm)
{
	int i;
	unsigned long total_size=0;

	for (i=0;i<128;i++) {
		total_size += ((struct parallel_block *)shm_blocks[i])->fragments;
	}

	return total_size;
}

#endif /*STATISTICS*/

#endif
