/*
 * version and compile flags macros
 *
 * Copyright (C) 2004 FhG Fokus
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

#ifndef version_h
#define version_h

#define OPENSIPS_FULL_VERSION  NAME " " VERSION " (" ARCH "/" OS ")"


#ifdef STATISTICS
#define STATS_STR  "STATS: On"
#else
#define STATS_STR  "STATS: Off"
#endif

#ifdef SHM_EXTRA_STATS
#define EXTRA_STATS_STR ", SHM_EXTRA_STATS"
#else
#define EXTRA_STATS_STR ""
#endif

#ifdef DISABLE_NAGLE
#define DISABLE_NAGLE_STR ", DISABLE_NAGLE"
#else
#define DISABLE_NAGLE_STR ""
#endif

#ifdef USE_MCAST
#define USE_MCAST_STR ", USE_MCAST"
#else
#define USE_MCAST_STR ""
#endif


#ifdef NO_DEBUG
#define NO_DEBUG_STR ", NO_DEBUG"
#else
#define NO_DEBUG_STR ""
#endif

#ifdef NO_LOG
#define NO_LOG_STR ", NO_LOG"
#else
#define NO_LOG_STR ""
#endif

#ifdef EXTRA_DEBUG
#define EXTRA_DEBUG_STR ", EXTRA_DEBUG"
#else
#define EXTRA_DEBUG_STR ""
#endif

#ifdef SHM_MMAP
#define SHM_MMAP_STR ", SHM_MMAP"
#else
#define SHM_MMAP_STR ""
#endif

#ifdef PKG_MALLOC
#define PKG_MALLOC_STR ", PKG_MALLOC"
#else
#define PKG_MALLOC_STR ""
#endif

#ifdef Q_MALLOC
#define Q_MALLOC_STR ", Q_MALLOC"
#else
#define Q_MALLOC_STR ""
#endif

#ifdef F_MALLOC
#define F_MALLOC_STR ", F_MALLOC"
#else
#define F_MALLOC_STR ""
#endif

#ifdef HP_MALLOC
#define HP_MALLOC_STR ", HP_MALLOC"
#else
#define HP_MALLOC_STR ""
#endif

#ifdef DBG_MALLOC
#define DBG_MALLOC_STR ", DBG_MALLOC"
#else
#define DBG_MALLOC_STR ""
#endif

#ifdef CC_O0
#define CC_O0_STR ", CC_O0"
#else
#define CC_O0_STR ""
#endif

#ifdef DEBUG_DMALLOC
#define DEBUG_DMALLOC_STR ", DEBUG_DMALLOC"
#else
#define DEBUG_DMALLOC_STR ""
#endif

#ifdef QM_JOIN_FREE
#define QM_JOIN_FREE_STR ", QM_JOIN_FREE"
#else
#define QM_JOIN_FREE_STR ""
#endif

#ifdef FAST_LOCK
#ifdef USE_FUTEX
#ifdef ADAPTIVE_WAIT
#define FAST_LOCK_STR ", FAST_LOCK-FUTEX-ADAPTIVE_WAIT"
#else
#define FAST_LOCK_STR ", FAST_LOCK-FUTEX"
#endif
#elif defined (BUSY_WAIT)
#define FAST_LOCK_STR ", FAST_LOCK-BUSY_WAIT"
#elif defined (ADAPTIVE_WAIT)
#define FAST_LOCK_STR ", FAST_LOCK-ADAPTIVE_WAIT"
#else
#define FAST_LOCK_STR ", FAST_LOCK"
#endif
#else
#define FAST_LOCK_STR ""
#endif

#ifdef USE_PTHREAD_MUTEX
#define USE_PTHREAD_MUTEX_STR ", USE_PTHREAD_MUTEX"
#else
#define USE_PTHREAD_MUTEX_STR ""
#endif

#ifdef USE_UMUTEX
#define USE_UMUTEX_STR ", USE_UMUTEX"
#else
#define USE_UMUTEX_STR ""
#endif

#ifdef USE_POSIX_SEM
#define USE_POSIX_SEM_STR ", USE_POSIX_SEM"
#else
#define USE_POSIX_SEM_STR ""
#endif

#ifdef USE_SYSV_SEM
#define USE_SYSV_SEM_STR ", USE_SYSV_SEM"
#else
#define USE_SYSV_SEM_STR ""
#endif

#ifdef DBG_LOCK
#define DBG_LOCK_STR ", DBG_LOCK"
#else
#define DBG_LOCK_STR ""
#endif

#ifdef NOSMP
#define NOSMP_STR "-NOSMP"
#else
#define NOSMP_STR ""
#endif

#define OPENSIPS_COMPILE_FLAGS \
	STATS_STR EXTRA_STATS_STR EXTRA_DEBUG_STR \
	DISABLE_NAGLE_STR USE_MCAST_STR NO_DEBUG_STR NO_LOG_STR \
	SHM_MMAP_STR PKG_MALLOC_STR Q_MALLOC_STR F_MALLOC_STR \
	HP_MALLOC_STR DBG_MALLOC_STR CC_O0_STR \
	DEBUG_DMALLOC_STR QM_JOIN_FREE_STR FAST_LOCK_STR NOSMP_STR \
	USE_PTHREAD_MUTEX_STR USE_UMUTEX_STR USE_POSIX_SEM_STR \
	USE_SYSV_SEM_STR DBG_LOCK_STR


#endif
