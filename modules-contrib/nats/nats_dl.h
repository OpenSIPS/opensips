/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 * nats_dl.h -- libnats function-pointer table.
 *
 * Why this exists
 *   The NATS modules used to link libnats statically via DT_NEEDED.
 *   That made it impossible to choose the libnats variant (openssl-
 *   built vs wolfssl-built) at runtime: the dynamic linker resolved
 *   the dependency at module load time, before any OpenSIPS code
 *   could run.
 *
 *   This table replaces every direct libnats call across modules-contrib/nats
 *   and the NATS user modules (cachedb_nats, cachedb_nats_fts,
 *   event_nats, nats_consumer) with an indirect call through a function-pointer
 *   table populated at modules-contrib/nats init time via dlopen + dlsym.
 *
 *   Result: no .so produced from this tree carries DT_NEEDED for
 *   libnats.so.  Operators select which libnats variant to load
 *   via standard ld.so mechanisms (LD_LIBRARY_PATH, ldconfig) or
 *   via the $NATS_DL_LIBNATS_PATH env-var override that
 *   nats_dl_load honours when called with a NULL path.
 *
 * Single source of truth
 *   The list of every libnats function this codebase calls lives in
 *   nats_dl_table.def.  That file is included twice in the project:
 *   once here (with NATS_DL_FN expanded to declare a struct field)
 *   and once in nats_dl.c (with NATS_DL_FN expanded to dlsym the
 *   matching libnats symbol).  Adding or removing a libnats call in
 *   any NATS source file means: edit nats_dl_table.def, and the
 *   header + loader update automatically.
 *
 * Usage from a NATS source file
 *   #include "nats_dl.h"
 *   ...
 *   natsStatus s = nats_dl.natsConnection_Connect(&nc, opts);
 *
 * Lifecycle
 *   nats_dl_load(libnats_path) is called once per process from
 *   nats_pool_register() (on first registration).  Subsequent calls are
 *   no-ops (idempotent).
 *   nats_dl_unload() is called once at modules-contrib/nats teardown.
 */

#ifndef LIB_NATS_NATS_DL_H
#define LIB_NATS_NATS_DL_H

#include <stdint.h>
#include <nats/nats.h>

/*
 * The function-pointer table.  Each entry has the same signature as
 * the corresponding libnats function, derived via __typeof__ so the
 * declarations stay in sync with libnats's headers automatically.
 *
 * Typical compiler diagnostic: if libnats removes or renames a
 * function this codebase calls, `__typeof__(missing_function)` is
 * an error at THIS header's compile, not at the call site -- which
 * keeps error messages localised to the table.
 */
typedef struct nats_dl_funcs {
#define NATS_DL_FN(sym) __typeof__(sym) *sym;
#include "nats_dl_table.def"
#undef NATS_DL_FN
} nats_dl_funcs_t;

/*
 * Global instance.  Defined in nats_dl.c.  Every NATS source file
 * makes calls of the form `nats_dl.<funcname>(<args>)`; the indirect
 * jump through the populated pointer is one extra branch per call,
 * predicted perfectly by modern CPUs.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
extern nats_dl_funcs_t nats_dl;
#endif

/**
 * nats_dl_load -- dlopen libnats and populate the table.
 *
 * @param libnats_path Explicit path or SONAME passed to dlopen().  If
 *                non-NULL, no fallback is attempted -- if the
 *                explicit path fails, the function returns -1.
 *                Not copied: on success with a non-NULL argument the
 *                pointer is kept (returned by nats_dl_path()), so it
 *                must outlive the load (string literals / modparams do).
 *                Pass NULL to use the default load order:
 *                  1. $NATS_DL_LIBNATS_PATH if set (env-var
 *                     override; on failure, falls back to step 2
 *                     with LM_WARN).
 *                  2. dlopen("libnats.so") -- the dev-package
 *                     symlink, which ld.so resolves via the
 *                     standard LD_LIBRARY_PATH / ldconfig search.
 *
 * modules-contrib/nats deliberately does NOT bake in libnats version numbers
 * or install-prefix conventions.  Operators with multiple libnats
 * installs (e.g. openssl-built and wolfssl-built side-by-side)
 * select via $NATS_DL_LIBNATS_PATH or via standard ld.so
 * mechanisms (LD_LIBRARY_PATH, ldconfig priorities).
 *
 * @return 0 on success (table populated, every entry non-NULL),
 *         -1 on dlopen failure or missing required symbol (the table
 *         is zeroed and the handle closed -- fail closed).  Idempotent:
 *         subsequent calls return 0 without re-loading.
 *
 * Allocation: only the dlopen handle, owned by nats_dl.c and released
 * by nats_dl_unload(); nothing for the caller to free.
 *
 * Locking: none -- NOT thread-safe against concurrent loads.
 * Context: called once per process from nats_pool_register() on first
 * registration, i.e. mod_init (pre-fork, single-threaded); do not call
 * from worker/callback contexts.
 *
 * Caller MUST ensure nats_dl_load returns 0 before any nats_dl.*
 * call.  Calling through a NULL function pointer is undefined
 * behaviour; this loader is the explicit guard.
 */
int  nats_dl_load(const char *libnats_path);

/**
 * nats_dl_unload -- dlclose libnats and zero the table.
 *
 * Safe to call when nothing has been loaded (no-op).  After it
 * returns, every nats_dl.* pointer is NULL -- no libnats call may
 * follow in this process.
 *
 * @return none.
 *
 * Allocation: releases the dlopen handle owned by nats_dl.c.
 * Locking: none -- NOT thread-safe against concurrent nats_dl use.
 * Context: shutdown only -- nats_pool_destroy / mod_destroy paths,
 * after all NATS threads and callbacks are gone.
 */
void nats_dl_unload(void);

/**
 * nats_dl_is_loaded -- true if dlopen has succeeded.
 *
 * Useful from secondary mod_init paths that need to lazy-load
 * libnats only if it hasn't been loaded yet:
 *   if (!nats_dl_is_loaded()) {
 *       if (nats_dl_load(NULL) < 0) return -1;
 *   }
 *
 * @return 1 if the table is populated (load succeeded), 0 otherwise.
 *
 * Allocation: none.  Locking: none (plain pointer read; pair it with
 * the single-threaded load/unload contexts above).
 * Context: any process; intended for mod_init (pre-fork) probing.
 */
int  nats_dl_is_loaded(void);

/**
 * nats_dl_path -- the path/SONAME that dlopen succeeded with.
 *
 * Useful for diagnostic LM_INFO logs after init.
 *
 * @return Borrowed pointer owned by nats_dl (a string literal, the
 *         env value, or the caller's original argument) -- do not
 *         free; NULL if not loaded.  Valid until nats_dl_unload().
 *
 * Allocation: none.  Locking: none (plain pointer read).
 * Context: any process after nats_dl_load() returned 0.
 */
const char *nats_dl_path(void);

/**
 * nats_dl_version_compatible -- can code compiled against libnats headers
 * @compiled run against a libnats reporting @runtime?  Both are
 * NATS_VERSION_NUMBER-encoded ((major << 16) | (minor << 8) | patch).
 *
 * Structs cross the dlopen boundary by value and by caller-allocated
 * pointer (e.g. kvWatchOptions grew from 40 to 56 bytes between 3.14 and
 * 3.15, and kvWatchOptions_Init() clears the whole runtime-sized struct),
 * so major.minor must match exactly; patch releases keep layouts.
 *
 * Returns 1 when compatible, 0 otherwise.
 */
int nats_dl_version_compatible(uint32_t compiled, uint32_t runtime);

/**
 * nats_dl_check_version -- ask a dlopen()ed libnats for its version
 * (nats_GetVersionNumber) and refuse it unless it is compatible with the
 * headers modules-contrib/nats was compiled against.  Logs the reason on refusal.
 * @path is used in the log line only.
 *
 * Returns 0 when compatible, -1 otherwise (including a library that does
 * not export nats_GetVersionNumber).
 */
int nats_dl_check_version(void *handle, const char *path);

#ifdef UNIT_TESTS
/*
 * Unit-test seam (test/nats_ut_fake.c): on = 1 puts an empty table in
 * place of the library and reports it as loaded, so nats_dl_load() does
 * not open libnats and the test fills in the functions it scripts; on = 0
 * puts back what was there.
 */
void nats_dl_test_fake(int on);

/*
 * Unit-test seam: the libnats version nats_dl_load() takes as the one of
 * the compiled headers; 0 puts the real one back.
 */
void nats_dl_test_compiled_version(uint32_t version);
#endif

#endif  /* LIB_NATS_NATS_DL_H */
