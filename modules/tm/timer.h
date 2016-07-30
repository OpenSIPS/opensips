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
 *  2003-09-12  timer_link.tg exists only if EXTRA_DEBUG (andrei)
 *  2004-02-13  timer_link.payload removed (bogdan)
 *  2007-02-02  retransmission timers have milliseconds resolution (bogdan)
 */


#ifndef _TIMER_H
#define _TIMER_H

#include "../../timer.h"
#include "../../rw_locking.h"
#include "lock.h"

#define MIN_TIMER_VALUE  2

/* identifiers of timer lists;*/
/* fixed-timer retransmission lists (benefit: fixed timer$
   length allows for appending new items to the list as$
   opposed to inserting them which is costly */
enum lists
{
	FR_TIMER_LIST, FR_INV_TIMER_LIST,
	WT_TIMER_LIST,
	DELETE_LIST,
	RT_T1_TO_1, RT_T1_TO_2, RT_T1_TO_3,
	RT_T2,
	NR_OF_TIMER_LISTS
};


/* all you need to put a cell in a timer list
   links to neighbors and timer value */
typedef struct timer_link
{
	struct timer_link     *next_tl;
	struct timer_link     *prev_tl;
	struct timer_link     *ld_tl;
	volatile utime_t      time_out;
	struct timer          *timer_list;
	unsigned short        deleted;
	unsigned short        set;
#ifdef EXTRA_DEBUG
	enum timer_groups  tg;
#endif
}timer_link_type ;


/* timer list: includes head, tail and protection semaphore */
typedef struct  timer
{
	struct timer_link  first_tl;
	struct timer_link  last_tl;
	ser_lock_t*        mutex;
	enum lists         id;
} timer_type;


/* transaction table */
struct timer_table
{
	rw_lock_t      *ex_lock;
	/* table of timer lists */
	struct timer   timers[ NR_OF_TIMER_LISTS ];
};





extern int timer_group[NR_OF_TIMER_LISTS];
extern unsigned int timer_id2timeout[NR_OF_TIMER_LISTS];



struct timer_table * tm_init_timers( unsigned int sets );
void unlink_timer_lists();
void free_timer_table();
void init_timer_list( unsigned int set, enum lists list_id);
void reset_timer_list( unsigned int set, enum lists list_id);

void reset_timer( struct timer_link* tl );

/* determine timer length and put on a correct timer list */
void set_timer( struct timer_link *new_tl, enum lists list_id,
		utime_t* ext_timeout );

/* similar to set_timer, except it allows only one-time
   timer setting and all later attempts are ignored */
void set_1timer( struct timer_link *new_tl, enum lists list_id,
		utime_t* ext_timeout );

void timer_routine( unsigned int, void*);

void utimer_routine( utime_t, void*);

struct timer_table *get_timertable();

#endif
