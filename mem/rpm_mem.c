/*
 * Shared memory functions
 *
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */


#include <stdlib.h>

#include "shm_mem.h"
#include "rpm_mem.h"
#include "../config.h"
#include "../globals.h"

#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h> /*open*/
#include <sys/stat.h>
#include <fcntl.h>


enum osips_mm mem_allocator_rpm = MM_NONE;
unsigned long rpm_mem_size = 0;
char *rpm_mem_file = RESTART_PERSISTENCY_MEM_FILE;

#ifndef INLINE_ALLOC
#ifdef DBG_MALLOC
void *(*gen_rpm_malloc)(void *blk, unsigned long size,
                        const char *file, const char *func, unsigned int line);
void *(*gen_rpm_malloc_unsafe)(void *blk, unsigned long size,
                        const char *file, const char *func, unsigned int line);
void *(*gen_rpm_realloc)(void *blk, void *p, unsigned long size,
                        const char *file, const char *func, unsigned int line);
void *(*gen_rpm_realloc_unsafe)(void *blk, void *p, unsigned long size,
                        const char *file, const char *func, unsigned int line);
void (*gen_rpm_free)(void *blk, void *p,
                      const char *file, const char *func, unsigned int line);
void (*gen_rpm_free_unsafe)(void *blk, void *p,
                      const char *file, const char *func, unsigned int line);
#else
void *(*gen_rpm_malloc)(void *blk, unsigned long size);
void *(*gen_rpm_malloc_unsafe)(void *blk, unsigned long size);
void *(*gen_rpm_realloc)(void *blk, void *p, unsigned long size);
void *(*gen_rpm_realloc_unsafe)(void *blk, void *p, unsigned long size);
void (*gen_rpm_free)(void *blk, void *p);
void (*gen_rpm_free_unsafe)(void *blk, void *p);
#endif
void (*gen_rpm_info)(void *blk, struct mem_info *info);
void (*gen_rpm_status)(void *blk);
unsigned long (*gen_rpm_get_size)(void *blk);
unsigned long (*gen_rpm_get_used)(void *blk);
unsigned long (*gen_rpm_get_rused)(void *blk);
unsigned long (*gen_rpm_get_mused)(void *blk);
unsigned long (*gen_rpm_get_free)(void *blk);
unsigned long (*gen_rpm_get_frags)(void *blk);
#endif

void rpm_mem_destroy(void);

struct rpmem_zone {
	char key[RPM_MAX_ZONE_NAME];
	void *address;
};

struct _rpm_map_block {
	unsigned magic;						/* magic code used to check if file is valid -
										   should match - RPM_MAGIC_CODE */
	unsigned long size;					/* size of the block */
	int max_zone_name;					/* used to check consistency of file -
										   should  match RPM_MAX_ZONE_NAME */
	int max_zones_no;					/* used to check consistency of file -
										   should match RPM_MAX_ZONES_NO */
	enum osips_mm alloc;				/* allocator type */
	int zones_no;						/* number of zones allocated yet */
	void *mapped_address;				/* address where file should be mapped */
	void *block_address;				/* block where the OpenSIPS memory starts */
	struct rpmem_zone zones[0];			/* info about zones */
} __attribute__((__packed__)) *rpm_map_block;


#if defined F_MALLOC || defined Q_MALLOC
gen_lock_t *rpmem_lock;
#endif

#ifdef HP_MALLOC
gen_lock_t *rpmem_locks;
#endif

static void* rpm_mempool=INVALID_MAP;
void *rpm_block;

#if !defined INLINE_ALLOC && defined HP_MALLOC
/* startup optimization */
int rpm_use_global_lock;
#endif

int rpm_mem_init_allocs(void)
{
#ifdef HP_MALLOC
	int i;
#endif

#ifndef INLINE_ALLOC
	if (mem_allocator_rpm == MM_NONE)
		mem_allocator_rpm = mem_allocator;

#ifdef HP_MALLOC
	if (mem_allocator_rpm != MM_HP_MALLOC
	        && mem_allocator_rpm != MM_HP_MALLOC_DBG)
		rpm_use_global_lock = 1;
#endif
	switch (mem_allocator_rpm) {
#ifdef F_MALLOC
	case MM_F_MALLOC:
		gen_rpm_malloc         = (osips_malloc_f)fm_malloc;
		gen_rpm_malloc_unsafe  = (osips_malloc_f)fm_malloc;
		gen_rpm_realloc        = (osips_realloc_f)fm_realloc;
		gen_rpm_realloc_unsafe = (osips_realloc_f)fm_realloc;
		gen_rpm_free           = (osips_free_f)fm_free;
		gen_rpm_free_unsafe    = (osips_free_f)fm_free;
		break;
#ifdef Q_MALLOC
	case MM_Q_MALLOC:
		gen_rpm_malloc         = (osips_malloc_f)qm_malloc;
		gen_rpm_malloc_unsafe  = (osips_malloc_f)qm_malloc;
		gen_rpm_realloc        = (osips_realloc_f)qm_realloc;
		gen_rpm_realloc_unsafe = (osips_realloc_f)qm_realloc;
		gen_rpm_free           = (osips_free_f)qm_free;
		gen_rpm_free_unsafe    = (osips_free_f)qm_free;
		break;
#endif
#ifdef HP_MALLOC
	case MM_HP_MALLOC:
		gen_rpm_malloc         = (osips_malloc_f)hp_rpm_malloc;
		gen_rpm_malloc_unsafe  = (osips_malloc_f)hp_rpm_malloc_unsafe;
		gen_rpm_realloc        = (osips_realloc_f)hp_rpm_realloc;
		gen_rpm_realloc_unsafe = (osips_realloc_f)hp_rpm_realloc_unsafe;
		gen_rpm_free           = (osips_free_f)hp_rpm_free;
		gen_rpm_free_unsafe    = (osips_free_f)hp_rpm_free_unsafe;
		break;
#endif
#ifdef DBG_MALLOC
#ifdef F_MALLOC
	case MM_F_MALLOC_DBG:
		gen_rpm_malloc         = (osips_malloc_f)fm_malloc_dbg;
		gen_rpm_malloc_unsafe  = (osips_malloc_f)fm_malloc_dbg;
		gen_rpm_realloc        = (osips_realloc_f)fm_realloc_dbg;
		gen_rpm_realloc_unsafe = (osips_realloc_f)fm_realloc_dbg;
		gen_rpm_free           = (osips_free_f)fm_free_dbg;
		gen_rpm_free_unsafe    = (osips_free_f)fm_free_dbg;
		break;
#endif
#ifdef Q_MALLOC
	case MM_Q_MALLOC_DBG:
		gen_rpm_malloc         = (osips_malloc_f)qm_malloc_dbg;
		gen_rpm_malloc_unsafe  = (osips_malloc_f)qm_malloc_dbg;
		gen_rpm_realloc        = (osips_realloc_f)qm_realloc_dbg;
		gen_rpm_realloc_unsafe = (osips_realloc_f)qm_realloc_dbg;
		gen_rpm_free           = (osips_free_f)qm_free_dbg;
		gen_rpm_free_unsafe    = (osips_free_f)qm_free_dbg;
		break;
#endif
#ifdef HP_MALLOC
	case MM_HP_MALLOC_DBG:
		gen_rpm_malloc         = (osips_malloc_f)hp_rpm_malloc_dbg;
		gen_rpm_malloc_unsafe  = (osips_malloc_f)hp_rpm_malloc_unsafe_dbg;
		gen_rpm_realloc        = (osips_realloc_f)hp_rpm_realloc_dbg;
		gen_rpm_realloc_unsafe = (osips_realloc_f)hp_rpm_realloc_unsafe_dbg;
		gen_rpm_free           = (osips_free_f)hp_rpm_free_dbg;
		gen_rpm_free_unsafe    = (osips_free_f)hp_rpm_free_unsafe_dbg;
		break;
#endif
#endif
	default:
		LM_ERR("current build does not include support for "
		       "selected allocator (%s)\n", mm_str(mem_allocator_rpm));
		return -1;
	}

#endif
#endif

	/* store locks in sharem memory, so we don't have to clean them up */
#ifdef HP_MALLOC
	/* lock_alloc cannot be used yet! */
	rpmem_locks = shm_malloc(HP_TOTAL_HASH_SIZE * sizeof *rpmem_locks);
	if (!rpmem_locks) {
		LM_CRIT("could not allocate the rp shm lock array\n");
		return -1;
	}

	for (i = 0; i < HP_TOTAL_HASH_SIZE; i++)
		if (!lock_init(&rpmem_locks[i])) {
			LM_CRIT("could not initialize rp lock\n");
			return -1;
		}
#endif

#if defined F_MALLOC || defined Q_MALLOC
	rpmem_lock = shm_malloc(sizeof *rpmem_lock);
	if (!rpmem_lock) {
		LM_CRIT("could not allocate the rp shm lock\n");
		return -1;
	}

	if (!lock_init(rpmem_lock)) {
		LM_CRIT("could not initialize rp lock\n");
		return -1;
	}
#endif
	return 0;
}

int rpm_mem_init_mallocs(void* mempool, unsigned long pool_size)
{
#ifndef INLINE_ALLOC
	if (mem_allocator_rpm == MM_NONE)
		mem_allocator_rpm = mem_allocator;
#endif

#ifdef INLINE_ALLOC
#if defined F_MALLOC
	rpm_block = fm_malloc_init(mempool, pool_size, "rpm");
#elif defined Q_MALLOC
	rpm_block = qm_malloc_init(mempool, pool_size, "rpm");
#elif defined HP_MALLOC
	rpm_block = hp_pkg_malloc_init(mempool, pool_size, "rpm");
#endif
#else
	switch (mem_allocator_rpm) {
#ifdef F_MALLOC
	case MM_F_MALLOC:
		rpm_block = fm_malloc_init(mempool, pool_size, "rpm");
		break;
#endif
#ifdef Q_MALLOC
	case MM_Q_MALLOC:
		rpm_block = qm_malloc_init(mempool, pool_size, "rpm");
		break;
#endif
#ifdef HP_MALLOC
	case MM_HP_MALLOC:
		rpm_block = hp_rpm_malloc_init(mempool, pool_size, "rpm");
		break;
#endif
#ifdef DBG_MALLOC
#ifdef F_MALLOC
	case MM_F_MALLOC_DBG:
		rpm_block = fm_malloc_init(mempool, pool_size, "rpm");
		break;
#endif
#ifdef Q_MALLOC
	case MM_Q_MALLOC_DBG:
		rpm_block = qm_malloc_init(mempool, pool_size, "rpm");
		break;
#endif
#ifdef HP_MALLOC
	case MM_HP_MALLOC_DBG:
		rpm_block = hp_pkg_malloc_init(mempool, pool_size, "rpm");
		break;
#endif
#endif
	default:
		LM_ERR("current build does not include support for "
		       "selected allocator (%s)\n", mm_str(mem_allocator_rpm));
		return -1;
	}

#endif

	if (!rpm_block){
		LM_CRIT("could not initialize restart persistent malloc\n");
		return -1;
	}

	LM_DBG("success\n");

	return 0;
}

/* Loads a restart persistency file in memory
 * Returns 0 if load is success, -1 on error, or 1 if the cache is invalid */
int load_rpm_file(void)
{
	struct _rpm_map_block tmp;
	int fd, ret;
	int bytes_needed, bytes_read;
	enum osips_mm alloc;

	fd = open(rpm_mem_file, O_RDWR);
	if (fd < 0) {
		LM_ERR("cannot open restart persistency file: %s\n", rpm_mem_file);
		return -1;
	}
	/* read the block */
	bytes_read = 0;
	bytes_needed = sizeof(tmp);
	do {
		ret = read(fd, ((char *)&tmp) + bytes_read, bytes_needed);
		if (ret < 0 && errno != EINTR) {
			LM_ERR("could not read from restart persistency file: %s (%d: %s)\n",
					rpm_mem_file, errno, strerror(errno));
			close(fd);
			return -1;
		}
		bytes_read += ret;
		bytes_needed -= ret;
	} while(bytes_needed > 0);

	/* check if the file is a valid cache file */
	if (tmp.magic != RPM_MAGIC_CODE) {
		LM_WARN("restart persistency file %s does not have the expected magic: %u\n",
				rpm_mem_file, *(unsigned*)(&tmp.magic));
		goto recreate;
	}
	if (tmp.size != rpm_mem_size) {
		LM_WARN("restart persistency file %s size=%lu != expected size=%lu\n",
				rpm_mem_file, tmp.size, rpm_mem_size);
		goto recreate;
	}

	if (tmp.max_zone_name != RPM_MAX_ZONE_NAME) {
		LM_WARN("restart persistency file %s max_zone_name size=%d != expected size=%d\n",
				rpm_mem_file, tmp.max_zone_name, RPM_MAX_ZONE_NAME);
		goto recreate;
	}

	if (tmp.max_zones_no != RPM_MAX_ZONES_NO) {
		LM_WARN("restart persistency file %s max_zones_no size=%d != expected size=%d\n",
				rpm_mem_file, tmp.max_zones_no, RPM_MAX_ZONE_NAME);
		goto recreate;
	}

#ifdef INLINE_ALLOC
	alloc = MM_NONE;
#else
	if (mem_allocator_rpm != MM_NONE)
		alloc = mem_allocator;
	else
		alloc = mem_allocator_rpm;
#endif

	if (tmp.alloc != alloc) {
		LM_WARN("restart persistency file %s different alloc==%d != expected=%d\n",
				rpm_mem_file, tmp.alloc, alloc);
		goto recreate;
	}

	/* rewind the head of the fd */
	lseek(fd, 0, SEEK_SET);

	/* it all looks good here - lets map it */
	rpm_mempool = shm_getmem(fd, tmp.mapped_address, rpm_mem_size);
	if (rpm_mempool == INVALID_MAP) {
		LM_CRIT("could not map persistency file  %s at expected location: %p\n",
				rpm_mem_file, tmp.mapped_address);
		goto recreate;
	}
	close(fd);

	rpm_block = tmp.block_address;
	rpm_map_block = rpm_mempool;
	if (rpm_mem_init_allocs() < 0) {
		rpm_mem_destroy();
		goto recreate;
	}

	LM_INFO("XXX: block is %p %p\n", rpm_map_block, rpm_block);
	return 0;

recreate:
	close(fd);
	return 1;
}


int init_rpm_mallocs(void)
{
	struct stat fst;
	int n, fd;
	int header_meta_size;

	/* if any of the rpm settings is set, then we should turn rpm_enabled on */
	/* if no custom memory was set, then use the shm size */
	if (!rpm_mem_size)
		rpm_mem_size = shm_mem_size;

	LM_INFO("using %ld Mb of restart persistent shared memory\n",
			rpm_mem_size/1024/1024);

	/* check if the file exists */
	n = stat(rpm_mem_file, &fst);
	if (n == 0) {
		/* check the size of the file */
		if (fst.st_size != rpm_mem_size) {
			LM_WARN("restart persistency cache (%s) size %ld is different than "
					"the size we are running with %ld: creating a new cache!\n",
					rpm_mem_file, fst.st_size, rpm_mem_size);
		} else if (load_rpm_file() == 0)
			return 0; /* memblock loaded just fine */
		LM_INFO("restart persistent cache is invalid: creating a new one!\n");
	} else if (errno != ENOENT) {
		LM_ERR("could not access file (or path) to the cache: %s (%d: %s)\n",
				rpm_mem_file, errno, strerror(errno));
		return -1;
	} else
		LM_DBG("restart persistent cache does not exist: %s. Creating it!\n",
				rpm_mem_file);

	fd = open(rpm_mem_file, O_RDWR|O_CREAT|O_TRUNC, 0600);
	if (fd < 0) {
		LM_ERR("could not create the restart persistency memory file %s (%d: %s)\n",
				rpm_mem_file, errno, strerror(errno));
		return -1;
	}
	lseek(fd, 0, SEEK_SET);
	if (ftruncate(fd, rpm_mem_size) < 0) {
		LM_ERR("could not set restart persistency file size %lu\n", rpm_mem_size);
		goto error;
	}

	/* all good - let's map the file */
	for (n = 0; n < RPM_MAP_RETRIES; n++) {
		rpm_mempool = shm_getmem(fd, RPM_MAP_ADDRESS + n * rpm_mem_size,
				rpm_mem_size);
		if (rpm_mempool != INVALID_MAP)
			break;
		LM_WARN("could not map file at address %p - tried %d times\n",
				RPM_MAP_ADDRESS + n * rpm_mem_size, n);
	}
	if (n == RPM_MAP_RETRIES) {
		/* last chance: map it anywhere and hope it will be available next
		 * time */
		rpm_mempool = shm_getmem(fd, NULL, rpm_mem_size);
		if (rpm_mempool == INVALID_MAP) {
			LM_CRIT("could not find available memory zone for restart persistent file!\n");
			goto error;
		}
	}
	close(fd);

	/* finally, we've got a mempool - populate the block */
	rpm_map_block = rpm_mempool;
	header_meta_size = sizeof(*rpm_map_block) +
			RPM_MAX_ZONES_NO * sizeof(struct rpmem_zone);
	memset(rpm_mempool, 0, header_meta_size);

	rpm_map_block->magic = RPM_MAGIC_CODE;
	rpm_map_block->size = rpm_mem_size;
	rpm_map_block->max_zone_name = RPM_MAX_ZONE_NAME;
	rpm_map_block->max_zones_no = RPM_MAX_ZONES_NO;
	rpm_map_block->mapped_address = rpm_mempool;
	rpm_map_block->block_address = (char *)rpm_map_block + header_meta_size;

	if (rpm_mem_init_mallocs(rpm_map_block->block_address,
			rpm_mem_size - header_meta_size) < 0) {
		rpm_mem_destroy();
		return -1;
	}
	/* update in case of realigned */
	rpm_map_block->block_address = rpm_block;

	if (rpm_mem_init_allocs() < 0) {
		rpm_mem_destroy();
		return -1;
	}

	return 0;

error:
	close(fd);
	return -1;
}

void **get_rpm_zone(char *key)
{
	int zone;
	unsigned len;
	void **ret;

	if (rpm_mempool==INVALID_MAP) {
		/* memory pool not yet initialized */
		if (init_rpm_mallocs() < 0) {
			LM_ERR("could not initialize restart persistent memory!\n");
			rpm_mempool = 0;
			return NULL;
		}
	}
	if (rpm_mempool == 0) {
		/* memory pool could not be init */
		return NULL;
	}

	len = strlen(key);
	if (len > RPM_MAX_ZONE_NAME) {
		LM_ERR("zone key too large for peristent memory (max is %d)!\n",
				RPM_MAX_ZONE_NAME);
		return NULL;
	}

	/* we now have a valid mem pool - search for the requested zone */
	for (zone = 0; zone < rpm_map_block->zones_no; zone++)
		if (strncmp(rpm_map_block->zones[zone].key, key, RPM_MAX_ZONE_NAME) == 0)
			return rpm_map_block->zones[zone].address;

	/* could not find the zone! - try to allocate slot data for it */
	if (rpm_map_block->zones_no == RPM_MAX_ZONES_NO) {
		LM_ERR("maximum number of zones reached - %d\n", RPM_MAX_ZONES_NO);
		return NULL;
	}
	ret = rpm_malloc(sizeof(void *));
	if (!ret) {
		LM_ERR("cannot allocate space for another zones!\n");
		return NULL;
	}
	/* reset the mem to NULL, to indicate that the zone is new */
	*ret = NULL;
	memcpy(rpm_map_block->zones[rpm_map_block->zones_no].key, key, len + 1);
	rpm_map_block->zones[rpm_map_block->zones_no].address = ret;
	rpm_map_block->zones_no++;
	return ret;
}

void rpm_relmem(void *mempool, unsigned long size)
{
	if (mempool && (mempool!=INVALID_MAP))
		munmap(mempool, size);
}

void rpm_mem_destroy(void)
{
#ifdef HP_MALLOC
	int j;
#endif
	if (0
#if defined F_MALLOC || defined Q_MALLOC
		|| rpmem_lock
#endif
#ifdef HP_MALLOC
		|| rpmem_locks
#endif
	) {
	#if defined F_MALLOC || defined Q_MALLOC
		if (rpmem_lock) {
			LM_DBG("destroying the shared memory lock\n");
			lock_destroy(rpmem_lock); /* we don't need to dealloc it*/
			rpmem_lock = NULL;
		}
	#endif

	#if defined HP_MALLOC
		if (rpmem_locks) {
			for (j = 0; j < HP_TOTAL_HASH_SIZE; j++)
				lock_destroy(&rpmem_locks[j]);
			rpmem_locks = NULL;
		}
	#endif
	}
	rpm_relmem(rpm_mempool, rpm_mem_size);
	rpm_mempool=INVALID_MAP;
	rpm_block = NULL;
}

