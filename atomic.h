/*
 * Copyright (C) 2006 kernel.org
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

/*!
 * \file
 * \brief Assembler routines for atomic operations
 *
 * ======================== Deprecation Notice (2020) =========================
 * Although the C11 standard is available for nearly 10 years now and would
 * help us remove this file in favour of libc's stdatomic.h, some old and
 * popular OS'es for VoIP unfortunately have extended periods of support.
 * For example, CentOS 7 has a 10-year lifetime: 2014 - 2024!
 *
 * Several of the above-mentioned OS'es use old gcc builds (4.8 or older), with
 * partial support for C11, so stdatomic.h is not present.  Dropping support
 * for these OS'es would affect a significant number of OpenSIPS deployments,
 * which is undesirable, at least for now.
 * ============================================================================
 */

#ifndef _ATOMIC_OPS_H_
#define _ATOMIC_OPS_H_

/************************* i386 & x86_64 ARCH ****************************/

#if defined(__CPU_i386) || defined(__CPU_x86_64)
#if defined(__SMP_yes)
	#define LOCK "lock ; "
#else
	#define LOCK ""
#endif
#endif

#if defined(__CPU_i386)

/*! \brief
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
#define atomic_set(v,i)		(((v)->counter) = (i))

/*! \brief
 * Make sure gcc doesn't try to be clever and move things around
 * on us. We need to use _exactly_ the address the user gave us,
 * not some alias that contains the same information.
 */
typedef struct { volatile unsigned int counter; } atomic_t;

/*! \brief
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v.
 */
static __inline__ void atomic_add(int i, atomic_t *v)
{
	__asm__ __volatile__(
		LOCK "addl %1,%0"
		:"=m" (v->counter)
		:"ir" (i), "m" (v->counter));
}

/*! \brief
 * atomic_sub - subtract the atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v.
 */
static __inline__ void atomic_sub(int i, atomic_t *v)
{
	__asm__ __volatile__(
		LOCK "subl %1,%0"
		:"=m" (v->counter)
		:"ir" (i), "m" (v->counter));
}

/*! \brief
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1.
 */
static __inline__ void atomic_inc(atomic_t *v)
{
	__asm__ __volatile__(
		LOCK "incl %0"
		:"=m" (v->counter)
		:"m" (v->counter));
}

/*! \brief
 * atomic_dec - decrement atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1.
 */
static __inline__ void atomic_dec(atomic_t *v)
{
	__asm__ __volatile__(
		LOCK "decl %0"
		:"=m" (v->counter)
		:"m" (v->counter));
}

#undef NO_ATOMIC_OPS

#elif defined(__CPU_x86_64) /* __CPU_i386 */

/*! \brief
 * Make sure gcc doesn't try to be clever and move things around
 * on us. We need to use _exactly_ the address the user gave us,
 * not some alias that contains the same information.
 */
typedef struct { volatile unsigned long counter; } atomic_t;

/*! \brief
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
#define atomic_set(v,i)		(((v)->counter) = (i))

/*! \brief
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v.
 */
static __inline__ void atomic_add(unsigned long i, atomic_t *v)
{
	__asm__ __volatile__(
		LOCK "addq %1,%0"
		:"=m" (v->counter)
		:"er" (i), "m" (v->counter));
}

/*! \brief
 * atomic_sub - subtract the atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v.
 */
static __inline__ void atomic_sub(unsigned long i, atomic_t *v)
{
	__asm__ __volatile__(
		LOCK "subq %1,%0"
		:"=m" (v->counter)
		:"er" (i), "m" (v->counter));
}

/*! \brief
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1.
 */
static __inline__ void atomic_inc(atomic_t *v)
{
	__asm__ __volatile__(
		LOCK "incq %0"
		:"=m" (v->counter)
		:"m" (v->counter));
}

/*! \brief
 * atomic_dec - decrement atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1.
 */
static __inline__ void atomic_dec(atomic_t *v)
{
	__asm__ __volatile__(
		LOCK "decq %0"
		:"=m" (v->counter)
		:"m" (v->counter));
}

#undef NO_ATOMIC_OPS

/************************* other ARCH ****************************/

#else

#define NO_ATOMIC_OPS

#endif

/* C11 stdatomics wrappers */
#define atomic_init(a, v) atomic_set(a, v)
#define atomic_store(a, v) atomic_set(a, v)
#define atomic_load(a) ((a)->counter)
#define atomic_fetch_add(a, v) \
	if ((long)(v) >= 0L) \
		atomic_add(v, a);\
	else \
		atomic_sub(-(v), a);

#endif
