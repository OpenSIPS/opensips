/*
 * $Id$ *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * History:
 * --------
 *  2002-12-16  created by andrei
 *  2003-02-20  s/gen_lock_t/gen_lock_t/ to avoid a type conflict
 *               on solaris  (andrei)
 *  2003-03-05  lock set support added for FAST_LOCK & SYSV (andrei)
 *  2003-03-06  removed *_alloc,*_dealloc & moved them to lock_alloc.h
 *              renamed locking.h to lock_ops.h (all this to solve
 *              the locking.h<->shm_mem.h interdependency) (andrei)
 *  2003-03-10  lock set support added also for PTHREAD_MUTEX & POSIX_SEM
 *               (andrei)
 *  2003-03-17  possible signal interruptions treated for sysv (andrei)
 *  2004-07-28  s/lock_set_t/gen_lock_set_t/ because of a type conflict
 *              on darwin (andrei)
 */

/*!
 * \file
 * \brief OpenSIPS locking operations
 *
 * Implements simple locks and lock sets.
 *
 * simple locks:
 * - gen_lock_t* lock_init(gen_lock_t* lock); - inits the lock
 * - void    lock_destroy(gen_lock_t* lock);  - removes the lock (e.g sysv rmid)
 * - void    lock_get(gen_lock_t* lock);      - lock (mutex down)
 * - void    lock_release(gen_lock_t* lock);  - unlock (mutex up)
 *
 * lock sets: [implemented only for FL & SYSV so far]
 * - gen_lock_set_t* lock_set_init(gen_lock_set_t* set);  - inits the lock set
 * - void lock_set_destroy(gen_lock_set_t* s);      - removes the lock set
 * - void lock_set_get(gen_lock_set_t* s, int i);   - locks sem i from the set
 * - void lock_set_release(gen_lock_set_t* s, int i)- unlocks sem i from the set
 *
 * WARNING:
 * - lock_set_init may fail for large number of sems (e.g. sysv).
 * - signals are not treated! (some locks are "awakened" by the signals)
 *
 * \note Warning: do not include this file directly, use instead locking.h
 * (unless you don't need to alloc/dealloc locks).
 * \todo investigate futex support on linux
 */


#ifndef _lock_ops_h
#define _lock_ops_h


#ifdef FAST_LOCK

#ifdef USE_FUTEX
#include "futex_lock.h"

typedef fx_lock_t gen_lock_t;

#elif defined FAST_LOCK
#include "fastlock.h"

typedef fl_lock_t gen_lock_t;

#endif

#define lock_destroy(lock) /* do nothing */

inline static gen_lock_t* lock_init(gen_lock_t* lock)
{
	init_lock(*lock);
	return lock;
}

#define lock_get(lock) get_lock(lock)
#define lock_release(lock) release_lock(lock)

#elif defined USE_PTHREAD_MUTEX
#include <pthread.h>

typedef pthread_mutex_t gen_lock_t;

#define lock_destroy(lock) /* do nothing */

inline static gen_lock_t* lock_init(gen_lock_t* lock)
{
	pthread_mutexattr_t attr;

	if (pthread_mutexattr_init(&attr) != 0)
		return 0;

	if (pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0) {
		pthread_mutexattr_destroy(&attr);
		return 0;
	}

	if (pthread_mutex_init(lock, &attr) != 0) {
		pthread_mutexattr_destroy(&attr);
		return 0;
	}

	pthread_mutexattr_destroy(&attr);
	return lock;
}

#define lock_get(lock) pthread_mutex_lock(lock)
#define lock_release(lock) pthread_mutex_unlock(lock)



#elif defined USE_POSIX_SEM
#include <semaphore.h>

typedef sem_t gen_lock_t;

#define lock_destroy(lock) /* do nothing */

inline static gen_lock_t* lock_init(gen_lock_t* lock)
{
	if (sem_init(lock, 1, 1)<0) return 0;
	return lock;
}

#define lock_get(lock) sem_wait(lock)
#define lock_release(lock) sem_post(lock)


#elif defined USE_SYSV_SEM
#include <sys/ipc.h>
#include <sys/sem.h>

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "dprint.h"
extern int uid; /* from main.c */

#if ((defined(HAVE_UNION_SEMUN) || defined(__GNU_LIBRARY__) )&& !defined(_SEM_SEMUN_UNDEFINED))

	/* union semun is defined by including sem.h */
#else
	/* according to X/OPEN we have to define it ourselves */
	union semun {
		int val;                      /* value for SETVAL */
		struct semid_ds *buf;         /* buffer for IPC_STAT, IPC_SET */
		unsigned short int *array;    /* array for GETALL, SETALL */
		struct seminfo *__buf;        /* buffer for IPC_INFO */
	};
#endif

typedef int gen_lock_t;




inline static gen_lock_t* lock_init(gen_lock_t* lock)
{
	union semun su;
	int euid;

	euid=geteuid();
	if (uid && uid!=euid)
		seteuid(uid); /* set euid to the cfg. requested one */
	*lock=semget(IPC_PRIVATE, 1, 0700);
	if (uid && uid!=euid)
		seteuid(euid); /* restore it */
	if (*lock==-1) return 0;
	su.val=1;
	if (semctl(*lock, 0, SETVAL, su)==-1){
		/* init error*/
		return 0;
	}
	return lock;
}

inline static void lock_destroy(gen_lock_t* lock)
{
	union semun su;

	su.val = 0;
	semctl(*lock, 0, IPC_RMID, su);
}


inline static void lock_get(gen_lock_t* lock)
{
	struct sembuf sop;

	sop.sem_num=0;
	sop.sem_op=-1; /* down */
	sop.sem_flg=0;
tryagain:
	if (semop(*lock, &sop, 1)==-1){
		if (errno==EINTR){
			LM_DBG("signal received while waiting for on a mutex\n");
			goto tryagain;
		}else{
			LM_CRIT("%s (%d)\n", strerror(errno), errno);
		}
	}
}

inline static void lock_release(gen_lock_t* lock)
{
	struct sembuf sop;

	sop.sem_num=0;
	sop.sem_op=1; /* up */
	sop.sem_flg=0;
tryagain:
	if (semop(*lock, &sop, 1)==-1){
		if (errno==EINTR){
			/* very improbable*/
			LM_DBG("signal received while releasing a mutex\n");
			goto tryagain;
		}else{
			LM_CRIT("%s (%d)\n", strerror(errno), errno);
		}
	}
}


#else
#error "no locking method selected"
#endif


/* lock sets */

#if defined(FAST_LOCK) || defined(USE_PTHREAD_MUTEX) || defined(USE_POSIX_SEM)
#define GEN_LOCK_T_PREFERED

struct gen_lock_set_t_ {
	long size;
	gen_lock_t* locks;
}; /* must be  aligned (32 bits or 64 depending on the arch)*/
typedef struct gen_lock_set_t_ gen_lock_set_t;


#define lock_set_destroy(lock_set) /* do nothing */

inline static gen_lock_set_t* lock_set_init(gen_lock_set_t* s)
{
	int r;
	for (r=0; r<s->size; r++) if (lock_init(&s->locks[r])==0) return 0;
	return s;
}

/* WARNING: no boundary checks!*/
#define lock_set_get(set, i) lock_get(&set->locks[i])
#define lock_set_release(set, i) lock_release(&set->locks[i])

#elif defined(USE_SYSV_SEM)
#undef GEN_LOCK_T_PREFERED

struct gen_lock_set_t_ {
	int size;
	int semid;
};


typedef struct gen_lock_set_t_ gen_lock_set_t;
inline static gen_lock_set_t* lock_set_init(gen_lock_set_t* s)
{
	union semun su;
	int r;
	int euid;

	euid=geteuid();
	if (uid && uid!=euid)
		seteuid(uid); /* set euid to the cfg. requested one */
	s->semid=semget(IPC_PRIVATE, s->size, 0700);
	if (uid && uid!=euid)
		seteuid(euid); /* restore euid */
	if (s->semid==-1){
		LM_CRIT("semget (..., %d, 0700) failed: %s\n",
				s->size, strerror(errno));
		return 0;
	}
	su.val=1;
	for (r=0; r<s->size; r++){
		if (semctl(s->semid, r, SETVAL, su)==-1){
			LM_CRIT("semctl failed on sem %d: %s\n",
				r, strerror(errno));
			su.val = 0;
			semctl(s->semid, 0, IPC_RMID, su);
			return 0;
		}
	}
	return s;
}

inline static void lock_set_destroy(gen_lock_set_t* s)
{
	union semun su;

	su.val = 0;
	semctl(s->semid, 0, IPC_RMID, su);
}

inline static void lock_set_get(gen_lock_set_t* s, int n)
{
	struct sembuf sop;
	sop.sem_num=n;
	sop.sem_op=-1; /* down */
	sop.sem_flg=0;
tryagain:
	if (semop(s->semid, &sop, 1)==-1){
		if (errno==EINTR){
			LM_DBG("signal received while waiting on a mutex\n");
			goto tryagain;
		}else{
			LM_CRIT("%s (%d)\n", strerror(errno), errno);
		}
	}
}

inline static void lock_set_release(gen_lock_set_t* s, int n)
{
	struct sembuf sop;
	sop.sem_num=n;
	sop.sem_op=1; /* up */
	sop.sem_flg=0;
tryagain:
	if (semop(s->semid, &sop, 1)==-1){
		if (errno==EINTR){
			/* very improbable */
			LM_DBG("signal received while releasing mutex\n");
			goto tryagain;
		}else{
			LM_CRIT("%s (%d)\n", strerror(errno), errno);
		}
	}
}
#else
#error "no lock set method selected"
#endif


#endif
