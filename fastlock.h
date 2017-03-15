/*
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
 *
 * History:
 * --------
 *  2002-02-05  created by andrei
 *  2003-01-16  added PPC locking code contributed by Dinos Dorkofikis
 *               <kdor@intranet.gr>
 *  2004-09-12  added MIPS locking for ISA>=2 (>r3000)  (andrei)
 *  2004-12-16  for now use the same locking code for sparc32 as for sparc64
 *               (it will work only if NOSMP is defined) (andrei)
 *
 *  2005-04-27  added alpha locking code (andrei)
 *  2005-05-25  PPC locking code enabled for PPC64; added a lwsync to
 *               the tsl part and replaced the sync with a lwsync for the
 *               unlock part (andrei)
 *  2016-12-07  Add support for armv6 (razvanc)
 *  2016-12-07  Add support for armv7 - not tested (razvanc)
 */

/*!
 * \file
 * \brief Assembler routines for fast architecture dependend locking.
 *
 * Contains the assembler routines for the fast architecture dependend
 * locking primitives used by the server. This routines are needed e.g.
 * to protect shared data structures that are accessed from muliple processes.
 * \todo replace this with the assembler routines provided by the linux kernel
 */


#ifndef fastlock_h
#define fastlock_h

#ifdef HAVE_SCHED_YIELD
#include <sched.h>
#else
#include <unistd.h>
/** Fake sched_yield if no unistd.h include is available */
	#define sched_yield()	sleep(0)
#endif

/*! The actual lock */
#ifndef DBG_LOCK
typedef  volatile int fl_lock_t;
#else
typedef struct fl_lock_t_{
	volatile int lock;
	char* file;
	char* func;
	unsigned long line;
} fl_lock_t;
#endif

/*! Initialize a lock, zero is unlocked. */
#ifndef DBG_LOCK
	#define init_lock( l ) (l)=0
#else 
	#define init_lock( l ) (l).lock = 0
#endif



/*! \brief
 * Test and set a lock. Used by the get_lock function.
 * \param lock the lock that should be set
 * \return 1 if the lock is held by someone else, 0 otherwise
 * \see get_lock
 */
#ifndef DBG_LOCK
inline static int tsl(fl_lock_t* lock)
#else
inline static int tsl(volatile int* lock)
#endif
{
	int val;

#if defined(__CPU_i386) || defined(__CPU_x86_64)

#ifdef NOSMP
	val=0;
	asm volatile(
		" btsl $0, %1 \n\t"
		" adcl $0, %0 \n\t"
		: "=q" (val), "=m" (*lock) : "0"(val) : "memory", "cc" /* "cc" */
	);
#else
	val=1;
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
			"# here \n\t"
			"swpb %0, %1, [%2] \n\t"
			: "=&r" (val)
			: "r"(1), "r" (lock) : "memory"
	);

#elif defined(__CPU_arm6) || defined(__CPU_arm7)
	asm volatile(
			"ldrex   %0, [%2] \n\t"
			"cmp     %0, #0 \n\t"
			"strexeq %0, %1, [%2] \n\t"
#ifndef NOSMP
#if defined(__CPU_arm7)
			"dmb \n\t"
#else
			"mcr p15, #0, r1, c7, c10, #5\n\t"
#endif
#endif
			: "=&r" (val)
			: "r"(1), "r" (lock) : "memory"
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


/*! \brief
 * Set a lock.
 * \param lock the lock that should be set
 * \see tsl
 */
#ifndef DBG_LOCK
inline static void get_lock(fl_lock_t* lock)
{
#else
inline static void get_lock(fl_lock_t* lock_struct,  const char* file, const char* func, unsigned int line)
{
	volatile int *lock = &lock_struct->lock;
#endif

#ifdef ADAPTIVE_WAIT
	int i=ADAPTIVE_WAIT_LOOPS;
#endif

	while(tsl(lock)){
#ifdef BUSY_WAIT
#elif defined ADAPTIVE_WAIT
		if (i>0) i--;
		else sched_yield();
#else
		sched_yield();
#endif
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
inline static void release_lock(fl_lock_t* lock)
{
#else 
inline static void release_lock(fl_lock_t* lock_struct)
{
	volatile int *lock = &lock_struct->lock;
	lock_struct->file = 0;
	lock_struct->func = 0;
	lock_struct->line = 0;
#endif

#if defined(__CPU_i386) || defined(__CPU_x86_64)
/*	char val;
	val=0; */
	asm volatile(
		" movb $0, (%0)" : /*no output*/ : "r"(lock): "memory"
		/*" xchg %b0, %1" : "=q" (val), "=m" (*lock) : "0" (val) : "memory"*/
	);
#elif defined(__CPU_sparc64) || defined(__CPU_sparc)
	asm volatile(
	#ifndef NOSMP
				"membar #LoadStore | #StoreStore \n\t" /*is this really needed?*/
	#endif
			"stb %%g0, [%0] \n\t"
			: /*no output*/
			: "r" (lock)
			: "memory"
	);
#elif defined(__CPU_arm) || defined(__CPU_arm6) || defined(__CPU_arm7)
	asm volatile(
#ifndef NOSMP
#if defined(__CPU_arm7)
		"dmb \n\t"
#else
		"mcr p15, #0, r1, c7, c10, #5\n\t"
#endif
#endif
		" str %0, [%1] \n\r"
		: /*no outputs*/
		: "r"(0), "r"(lock)
		: "memory"
	);
#elif defined(__CPU_ppc) || defined(__CPU_ppc64)
	asm volatile(
			/* "sync\n\t"  lwsync is faster and will work
			 *             here too
			 *             [IBM Programming Environments Manual, D.4.2.2]
			 */
			"lwsync\n\t"
			"stw %0, 0(%1)\n\t"
			: /* no output */
			: "r"(0), "b" (lock)
			: "memory"
    );
	*lock = 0;
#elif defined(__CPU_mips2) || defined(__CPU_mips32) || defined(__CPU_mips64)
	asm volatile(
		".set noreorder \n\t"
		"    sync \n\t"
		"    sw $0, %0 \n\t"
		".set reorder \n\t"
		: /*no output*/  : "m" (*lock) : "memory"
	);
#elif defined __CPU_alpha
	asm volatile(
		"    mb          \n\t"
		"    stl $31, %0 \n\t"
		: "=m"(*lock) :/* no input*/ : "memory"  /* because of the mb */
	);
#else
#error "unknown architecture"
#endif

}


#endif
