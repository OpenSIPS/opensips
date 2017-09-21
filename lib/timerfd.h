/*
 * Copyright (C) 2017 OpenSIPS Solutions
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
 *  2017-01-26 initial version (liviu)
 */

#ifndef __LIB_TIMERFD__
#define __LIB_TIMERFD__

#if (defined __OS_linux) && (__GLIBC__ >= 2) && (__GLIBC_MINOR__ >= 8)
	#include <sys/timerfd.h>  /* for timer FD */
	#define HAVE_TIMER_FD 1
#endif

#endif /* __LIB_TIMERFD__ */
