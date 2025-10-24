/*
 * Copyright (C) 2015 OpenSIPS Foundation
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 *
 */

#ifndef _OPENSSL_HELPERS_H_
#define _OPENSSL_HELPERS_H_

#include <openssl/ui.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>

#include "../tls_mgm/tls_helper.h"
#include "../../locking.h"

#if OPENSSL_VERSION_NUMBER < 0x00908000L
        #error "using an unsupported version of OpenSSL (< 0.9.8)"
#endif

#if OPENSSL_VERSION_NUMBER < 0x10001000L
	#warning ""
	#warning "=============================================================="
	#warning "Your version of OpenSSL is < 1.0.1."
	#warning " Upgrade for better compatibility, features and security fixes!"
	#warning "============================================================="
	#warning ""
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
int ssl_versions[TLS_USE_TLSv1_3 + 1];
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
int ssl_versions[TLS_USE_TLSv1_2 + 1];
#else
SSL_METHOD     *ssl_methods[TLS_USE_TLSv1_2 + 1];
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10000000L && defined __OS_linux
#include <sys/types.h>
#if (__GLIBC__ < 2) || (__GLIBC_MINOR__ < 30)
#include <sys/syscall.h>
#endif
#endif



/*
 * Wrappers around OpenSIPS shared memory functions
 * (which can be macros)
 *
 * These are only used for OpenSSL 1.x. For OpenSSL 3.x, we use
 * pkg_malloc wrappers with double-free protection (see below).
 */
#if OPENSSL_VERSION_NUMBER < 0x30000000L

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void* os_malloc(size_t size, const char *file, int line)
#else
static void* os_malloc(size_t size)
#endif
{
#if (defined DBG_MALLOC  && OPENSSL_VERSION_NUMBER >= 0x10100000L)
	return _shm_malloc(size, file, __FUNCTION__, line);
#else
	return shm_malloc(size);
#endif
}


#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void* os_realloc(void *ptr, size_t size, const char *file, int line)
#else
static void* os_realloc(void *ptr, size_t size)
#endif
{
#if (defined DBG_MALLOC  && OPENSSL_VERSION_NUMBER >= 0x10100000L)
	return _shm_realloc(ptr, size, file, __FUNCTION__, line);
#else
	return shm_realloc(ptr, size);
#endif
}


#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void os_free(void *ptr, const char *file, int line)
#else
static void os_free(void *ptr)
#endif
{
	/* TODO: also handle free file and line */
	if (ptr)
#if (defined DBG_MALLOC  && OPENSSL_VERSION_NUMBER >= 0x10100000L)
		_shm_free(ptr, file, __FUNCTION__, line);
#else
		shm_free(ptr);
#endif
}

#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
/*
 * Wrappers around OpenSIPS package (private) memory functions with
 * double-free protection for OpenSSL 3.x fork() safety
 *
 * === WHY THIS TRACKING LAYER IS NEEDED ===
 *
 * OpenSSL 3.x introduced extensive use of thread-local storage (TLS) for:
 * - Error queues (per-thread error state)
 * - RNG state (random number generator context)
 * - Provider dispatch tables (crypto algorithm implementations)
 * - Internal caches and buffers
 *
 * THE PROBLEM: OpenSSL 3.x + fork() + pkg_malloc causes double-free crashes
 *
 * 1. Parent process: OpenSSL allocates buffer X using pkg_malloc
 *    - Stores pointer to X in thread-local storage
 *    - May duplicate reference in multiple TLS slots
 *
 * 2. fork() happens:
 *    - Child process gets copy of all thread-local storage
 *    - Both parent and child have pointers to buffer X
 *    - Copy-on-write means both point to same physical memory initially
 *
 * 3. Connection cleanup (e.g., tcpconn_destroy):
 *    - OpenSSL walks through thread-local cleanup lists
 *    - Finds buffer X in multiple TLS slots (duplicated references)
 *    - Calls free() on X multiple times
 *    - pkg_malloc's debug allocator (qm_free_dbg) detects second free
 *    - CRITICAL ERROR: "freeing already freed pointer" -> process aborts
 *
 * THE SOLUTION: Thin tracking layer that:
 *
 * 1. Adds 12-byte header to each allocation:
 *    - magic number (validates pointer came from our allocator)
 *    - freed flag (prevents double-free)
 *    - size (for debugging)
 *
 * 2. On first free(): Set freed=1, actually call pkg_free()
 * 3. On second free(): Detect freed=1, silently skip the free()
 * 4. Invalid pointers: Detect wrong magic, log warning, skip free()
 *
 * BENEFITS:
 * - Keeps pkg_malloc (memory tracking, statistics, debug, limits)
 * - Prevents crash (works around OpenSSL bug)
 * - Detects and logs the issue (debug visibility)
 * - Minimal overhead (12 bytes per allocation)
 * - Fork-safe (each process has its own tracking)
 *
 * ALTERNATIVE REJECTED: Using system malloc/free
 * - Would hide the bug instead of fixing it
 * - Loses all pkg_malloc benefits (no tracking, no stats, no limits)
 * - Makes debugging harder (can't see OpenSSL memory usage)
 *
 * NOTE: This is a workaround for OpenSSL 3.x behavior. The real bug is in
 * how OpenSSL manages thread-local storage across fork() boundaries.
 */
struct openssl_mem_hdr {
	unsigned int magic;      /* Magic: 0x4F53534C validates our allocation */
	unsigned int freed;      /* 0=allocated, 1=freed (prevents double-free) */
	size_t size;             /* Allocation size (for debugging/stats) */
};

#define OPENSSL_MEM_MAGIC 0x4F53534C  /* "OSSL" in hex */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void* os_pkg_malloc(size_t size, const char *file, int line)
#else
static void* os_pkg_malloc(size_t size)
#endif
{
	struct openssl_mem_hdr *hdr;

	hdr = (struct openssl_mem_hdr *)pkg_malloc(sizeof(*hdr) + size);
	if (!hdr)
		return NULL;

	hdr->magic = OPENSSL_MEM_MAGIC;
	hdr->freed = 0;
	hdr->size = size;

	return (void *)(hdr + 1);
}


#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void* os_pkg_realloc(void *ptr, size_t size, const char *file, int line)
#else
static void* os_pkg_realloc(void *ptr, size_t size)
#endif
{
	struct openssl_mem_hdr *old_hdr, *new_hdr;

	if (!ptr)
		return os_pkg_malloc(size
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			, file, line
#endif
		);

	old_hdr = ((struct openssl_mem_hdr *)ptr) - 1;

	/* Validate magic number */
	if (old_hdr->magic != OPENSSL_MEM_MAGIC) {
		LM_ERR("OpenSSL realloc: invalid magic 0x%x for ptr %p\n",
			old_hdr->magic, ptr);
		return NULL;
	}

	/* Check if already freed */
	if (old_hdr->freed) {
		LM_ERR("OpenSSL realloc on freed pointer %p\n", ptr);
		return NULL;
	}

	new_hdr = (struct openssl_mem_hdr *)pkg_realloc(old_hdr, sizeof(*new_hdr) + size);
	if (!new_hdr)
		return NULL;

	new_hdr->size = size;

	return (void *)(new_hdr + 1);
}


#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void os_pkg_free(void *ptr, const char *file, int line)
#else
static void os_pkg_free(void *ptr)
#endif
{
	struct openssl_mem_hdr *hdr;

	if (!ptr)
		return;

	hdr = ((struct openssl_mem_hdr *)ptr) - 1;

	/* Validate magic number */
	if (hdr->magic != OPENSSL_MEM_MAGIC) {
		LM_WARN("OpenSSL free: invalid magic 0x%x for ptr %p, skipping free\n",
			hdr->magic, ptr);
		return;
	}

	/* Check for double-free */
	if (hdr->freed) {
		LM_DBG("OpenSSL double-free prevented for ptr %p (OpenSSL 3.x fork issue)\n", ptr);
		return;
	}

	/* Mark as freed */
	hdr->freed = 1;

	/* Actually free the memory */
	pkg_free(hdr);
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */


inline static unsigned long tls_get_id(void)
{
#if defined __OS_linux
#if (__GLIBC__ >= 2) && (__GLIBC_MINOR__ >= 30)
	return gettid();
#else
	return syscall(SYS_gettid);
#endif
#else /* __OS_linux */
	return my_pid(); /* TODO: fix on non linux systems, where we have to
						1. include a thread id alongside with the PID
						2. alocate a new structure that indicates PID + thread id */
#endif /* __OS_linux */
}

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
void tls_get_thread_id(CRYPTO_THREADID *tid)
{
	CRYPTO_THREADID_set_numeric(tid, tls_get_id());
}
#endif /* OPENSSL_VERSION_NUMBER */

/* these locks can not be used in 1.1.0, because the interface has changed */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
struct CRYPTO_dynlock_value {
	gen_lock_t lock;
};

static struct CRYPTO_dynlock_value* tls_dyn_lock_create(const char* file,
																	int line)
{
	struct CRYPTO_dynlock_value* new_lock;

	new_lock=shm_malloc(sizeof(struct CRYPTO_dynlock_value));
	if (new_lock==0){
		LM_ERR("Failed to allocated new dynamic lock\n");
		return 0;
	}
	if (lock_init(&new_lock->lock)==0) {
		LM_ERR("Failed to init new dynamic lock\n");
		shm_free(new_lock);
		return 0;
	}

	return new_lock;
}


static void tls_dyn_lock_ops(int mode, struct CRYPTO_dynlock_value* dyn_lock,
												const char* file, int line)
{
	if (mode & CRYPTO_LOCK) {
		lock_get(&dyn_lock->lock);
	} else {
		lock_release(&dyn_lock->lock);
	}
}


static void tls_dyn_lock_destroy(struct CRYPTO_dynlock_value *dyn_lock,
													const char* file, int line)
{
	lock_destroy(&dyn_lock->lock);
	shm_free(dyn_lock);
}

static int tls_static_locks_no=0;
static gen_lock_set_t* tls_static_locks=NULL;

static void tls_static_locks_ops(int mode, int n, const char* file, int line)
{
	if (n<0 || n>tls_static_locks_no) {
		LM_ERR("BUG - SSL Lib attempting to acquire bogus lock\n");
		abort();
	}

	if (mode & CRYPTO_LOCK) {
		lock_set_get(tls_static_locks,n);
	} else {
		lock_set_release(tls_static_locks,n);
	}
}



static int tls_init_multithread(void)
{
	/* init static locks support */
	tls_static_locks_no = CRYPTO_num_locks();

	if (tls_static_locks_no>0) {
		/* init a lock set & pass locking function to SSL */
		tls_static_locks = lock_set_alloc(tls_static_locks_no);
		if (tls_static_locks == NULL) {
			LM_ERR("Failed to alloc static locks\n");
			return -1;
		}
		if (lock_set_init(tls_static_locks)==0) {
				LM_ERR("Failed to init static locks\n");
				lock_set_dealloc(tls_static_locks);
				return -1;
		}
		CRYPTO_set_locking_callback(tls_static_locks_ops);
	}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
	CRYPTO_set_id_callback(tls_get_id);
#else /* between 1.0.0 and 1.1.0 */
	CRYPTO_THREADID_set_callback(tls_get_thread_id);
#endif /* OPENSSL_VERSION_NUMBER */

	/* dynamic locks support*/
	CRYPTO_set_dynlock_create_callback(tls_dyn_lock_create);
	CRYPTO_set_dynlock_lock_callback(tls_dyn_lock_ops);
	CRYPTO_set_dynlock_destroy_callback(tls_dyn_lock_destroy);

	return 0;
}
#endif


#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#define SSL_LOCK_REENTRANT(_cmd) \
	do { \
		int __ssl_lock_unlock; \
		if (ssl_lock_pid != process_no) { \
			lock_get(ssl_lock); \
			ssl_lock_pid = process_no; \
			__ssl_lock_unlock = 1; \
		} else { \
			__ssl_lock_unlock = 0; \
		} \
		_cmd; \
		if (__ssl_lock_unlock) { \
			ssl_lock_pid = -1; \
			lock_release(ssl_lock); \
		} \
	} while (0)

static gen_lock_t *ssl_lock;
static int ssl_lock_pid = -1;
static const RAND_METHOD *os_ssl_method;

static int os_ssl_seed(const void *buf, int num)
{
	int ret;
	if (!os_ssl_method || !ssl_lock || !os_ssl_method->seed)
		return 0;
	SSL_LOCK_REENTRANT(ret = os_ssl_method->seed(buf, num));
	return ret;
}

static int os_ssl_bytes(unsigned char *buf, int num)
{
	int ret;
	if (!os_ssl_method || !ssl_lock || !os_ssl_method->bytes)
		return 0;
	SSL_LOCK_REENTRANT(ret = os_ssl_method->bytes(buf, num));
	return ret;
}

static void os_ssl_cleanup(void)
{
	if (!os_ssl_method || !ssl_lock || !os_ssl_method->cleanup)
		return;
	SSL_LOCK_REENTRANT(os_ssl_method->cleanup());
}

static int os_ssl_add(const void *buf, int num, double entropy)
{
	int ret;
	if (!os_ssl_method || !ssl_lock || !os_ssl_method->add)
		return 0;
	SSL_LOCK_REENTRANT(ret = os_ssl_method->add(buf, num, entropy));
	return ret;
}

static int os_ssl_pseudorand(unsigned char *buf, int num)
{
	int ret;
	if (!os_ssl_method || !ssl_lock || !os_ssl_method->pseudorand)
		return 0;
	SSL_LOCK_REENTRANT(ret = os_ssl_method->pseudorand(buf, num));
	return ret;
}

static int os_ssl_status(void)
{
	int ret;
	if (!os_ssl_method || !ssl_lock || !os_ssl_method->status)
		return 0;
	SSL_LOCK_REENTRANT(ret = os_ssl_method->status());
	return ret;
}

static RAND_METHOD opensips_ssl_method = {
	os_ssl_seed,
	os_ssl_bytes,
	os_ssl_cleanup,
	os_ssl_add,
	os_ssl_pseudorand,
	os_ssl_status
};
#endif

#endif /* _OPENSSL_HELPERS_H_ */
