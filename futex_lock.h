/*
 * Copyright (C) 2012-2013 Ryan Bullock
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
 *
 * History:
 * --------
 *  2012-09-04  created by Ryan Bullock
 *  2016-12-07  Add support for arm architectures (razvanc)
 */

/*!
 * \file
 * \brief Support for Linux futex locks
 *
 * Implementation based off http://people.redhat.com/drepper/futex.pdf
 * Modified to add support for an adapative spinlock before sleeping on the lock
 *
 * Contains the assembler routines for the fast architecture dependend
 * locking primitives used by the server. This routines are needed e.g.
 * to protect shared data structures that are accessed from muliple processes.
 * \todo replace this with the assembler routines provided by the linux kernel
 *
 * Uses GCC atomic builtin for atomic cmpxchg operation
 */

#ifndef futex_lock_h
#define futex_lock_h

#include <unistd.h>
#include <sys/syscall.h>
#include <linux/futex.h>

/*! The actual lock */
#ifndef DBG_LOCK
typedef  volatile int fx_lock_t;
#else
typedef struct fx_lock_t_{
	volatile int lock;
	char* file;
	char* func;
	unsigned long line;
} fx_lock_t;
#endif

/*
 * Possible Lock values:
 * 0 - Not locked
 * 1 - Locked, but no other processes sleeping on lock
 * 2 - Locked and other processes sleeping on lock (requires a call to futex() with FUTEX_WAKUP on unlock)
 */

/*! Initialize a lock, zero is unlocked. */
#ifndef DBG_LOCK
	#define init_lock( l ) (l)=0
#else 
	#define init_lock( l ) (l).lock = 0
#endif
/*
 * Wait on a futex
 * param lock - futex to wait on
 * param val - value to check against lock
 */
#define futex_wait(lock, val) syscall(SYS_futex, lock, FUTEX_WAIT, val, 0, 0, 0)

/*
 * Wake up waiters
 * param lock - futex to wake up
 * param val - number of processes to wakeup
 */
#define futex_wake(lock, val) syscall(SYS_futex, lock, FUTEX_WAKE, val, 0, 0 ,0)

/*
 * Atomic cmpxchg operation
 * Conditionally sets lock to newval if current value of lock is oldval
 * param lock is lock to check/set
 * param oldval is the value that must be in lock for newval to be set
 * param newval is the new value to assign to lock if lock contains oldval
 * returns value of lock before the operation
*/
#define atomic_cmpxchg(lock, oldval, newval) __sync_val_compare_and_swap(lock, oldval, newval)

/*
 * Atomic xchg operation
 * Adapted tsl() from fastlock.h
 * Used as fall back from gcc atomic builtin for unsupported targets
 * Atomically writes value into lock, returning the previously value of lock
 * param lock is lock to set
 * param val is the value to write to the lock
 * returns previous value of lock
 */
#ifndef DBG_LOCK
inline static int _atomic_xchg(fx_lock_t* lock, int newval)
#else
inline static int _atomic_xchg(volatile int *lock, int newval)
#endif
{
	int val;
#if defined(__CPU_arm6) || defined(__CPU_arm7)
	unsigned int tmp;
#endif
#if defined(__CPU_i386) || defined(__CPU_x86_64)

#ifdef NOSMP
	asm volatile(
		" btsl $0, %1 \n\t"
		" adcl $0, %0 \n\t"
		: "=q" (val), "=m" (*lock) : "0"(val) : "memory", "cc" /* "cc" */
	);
#else
	asm volatile(
		" xchg %1, %0" : "=q" (val), "=m" (*lock) : "0" (val) : "memory"
	);
#endif /*NOSMP*/
#elif defined(__CPU_sparc64) || defined(__CPU_sparc)
	asm volatile(
			"ldstub [%1], %0 \n\t"
#ifndef NOSMP
			"membar #StoreStore | #StoreLoad \n\t"
#endif
			: "=r"(val) : "r"(lock):"memory"
	);

#elif defined __CPU_arm
	asm volatile(
			"swpb %0, %1, [%2] \n\t"
			: "=&r" (val)
			: "r"(newval), "r" (lock) : "memory"
	);

#elif defined(__CPU_arm6) || defined(__CPU_arm7)
	asm volatile(
			"1: ldrex %0, [%3] \n\t"
			"   strex %1, %2, [%3] \n\t"
			"   teq   %1, #0 \n\t"
			"   bne 1b \n\t"
#ifndef NOSMP
#if defined(__CPU_arm7)
			"dmb \n\t"
#else
			"mcr p15, #0, r1, c7, c10, #5\n\t"
#endif
#endif
			: "=&r" (val), "=&r" (tmp)
			: "r"(newval), "r" (lock) : "memory"
	);

#elif defined(__CPU_ppc) || defined(__CPU_ppc64)
	asm volatile(
			"1: lwarx  %0, 0, %2\n\t"
			"   cmpwi  %0, 0\n\t"
			"   bne    0f\n\t"
			"   stwcx. %1, 0, %2\n\t"
			"   bne-   1b\n\t"
			"   lwsync\n\t" /* lwsync or isync, lwsync is faster
							   and should work, see
							   [ IBM Programming environments Manual, D.4.1.1]
							 */
			"0:\n\t"
			: "=r" (val)
			: "r"(1), "b" (lock) :
			"memory", "cc"
        );
#elif defined(__CPU_mips2) || defined(__CPU_mips32) || defined(__CPU_mips64)
	long tmp;
	tmp=1; /* just to kill a gcc 2.95 warning */

	asm volatile(
		".set noreorder\n\t"
		"1:  ll %1, %2   \n\t"
		"    li %0, 1 \n\t"
		"    sc %0, %2  \n\t"
		"    beqz %0, 1b \n\t"
		"    nop \n\t"
		".set reorder\n\t"
		: "=&r" (tmp), "=&r" (val), "=m" (*lock)
		: "0" (tmp), "2" (*lock)
		: "cc"
	);
#elif defined __CPU_alpha
	long tmp;
	tmp=0;
	/* lock low bit set to 1 when the lock is hold and to 0 otherwise */
	asm volatile(
		"1:  ldl %0, %1   \n\t"
		"    blbs %0, 2f  \n\t"  /* optimization if locked */
		"    ldl_l %0, %1 \n\t"
		"    blbs %0, 2f  \n\t"
		"    lda %2, 1    \n\t"  /* or: or $31, 1, %2 ??? */
		"    stl_c %2, %1 \n\t"
		"    beq %2, 1b   \n\t"
		"    mb           \n\t"
		"2:               \n\t"
		:"=&r" (val), "=m"(*lock), "=r"(tmp)
		:"1"(*lock)  /* warning on gcc 3.4: replace it with m or remove
						it and use +m in the input line ? */
		: "memory"
	);
#else
#error "unknown architecture"
#endif
	return val;
}

/*
 * Atomic xchg
 * Use gcc atomic builtin on supported platforms, fail back to assembly
 * might want to also check for compiler support
 */
#if !defined(NOSMP) && (defined(__CPU_i386) || defined(__CPU_x86_64))
#define atomic_xchg(lock, val) __sync_lock_test_and_set(lock, val)
#else
#define atomic_xchg(lock, val) _atomic_xchg(lock, val)
#endif


/*! \brief
 * Get a lock.
 * \param lock the lock that should be gotten
 */
#ifndef DBG_LOCK
inline static void get_lock(fx_lock_t* lock)
{
#else
inline static void get_lock(fx_lock_t* lock_struct, const char* file, const char* func, unsigned int line)
{
	volatile int *lock = &lock_struct->lock;
#endif

	int c;
#ifdef ADAPTIVE_WAIT
	register int i = ADAPTIVE_WAIT_LOOPS;
#endif

	//Getting lock failed
	if ((c = atomic_cmpxchg(lock, 0, 1)) != 0) {
		//Ensure a wakeup gets scheduled
		if (c != 2) {
#ifdef ADAPTIVE_WAIT
			//No sleepers on the lock, try spinning for a bit first
			while(i > 0) {
				if ((c = atomic_cmpxchg(lock, 0, 1)) == 0) {
					return;
				}
				i--;
			}
#endif
			//Going to need a wakeup
			c = atomic_xchg(lock, 2);
		}

		//Wait for wakeup
		while (c != 0) {
			futex_wait(lock, 2);
			c = atomic_xchg(lock, 2);
		}
	}

#ifdef DBG_LOCK
	lock_struct->file = (char*)file;
	lock_struct->func = (char*)func;
	lock_struct->line = line;
#endif

}

/*! \brief
 * Release a lock
 * \param lock the lock that should be released
 */
#ifndef DBG_LOCK
inline static void release_lock(fx_lock_t* lock)
{
#else
inline static void release_lock(fx_lock_t* lock_struct)
{
	volatile int *lock = &lock_struct->lock;
#endif

	int c;
#ifdef DBG_LOCK
	lock_struct->file = NULL;
	lock_struct->func = NULL;
	lock_struct->line = 0;
#endif
	c = atomic_xchg(lock, 0);

	//Only do wakekup if others are waiting on the lock (value of 2)
	if (c != 1) {
		futex_wake(lock, 1);
	}
}

#endif
