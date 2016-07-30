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
 *  2003-03-17  converted to locking.h (andrei)
 *  2004-07-28  s/lock_set_t/gen_lock_set_t/ because of a type conflict
 *              on darwin (andrei)
 */


#include <errno.h>

#include "lock.h"
#include "timer.h"
#include "../../dprint.h"



#ifndef GEN_LOCK_T_PREFERED
/* semaphore probing limits */
#define SEM_MIN		16
#define SEM_MAX		4096

/* we implement mutex here using lock sets; as the number of
   semaphores may be limited (e.g. sysv) and number of synchronized
   elements high, we partition the synced SER elements and share
   semaphores in each of the partitions; we try to use as many
   semaphores as OS gives us for finest granularity.

   we allocate the locks according to the following plans:

   1) transaction timer lists have each a semaphore in
      a semaphore set
   2) retransmission timer lists have each a semaphore
      in a semaphore set
   3) we allocate a semaphore set for hash_entries and
      try to use as many semaphores in it as OS allows;
      we partition the hash_entries by available
      semaphores which are shared  in each partition
   4) cells get always the same semaphore as its hash
      entry in which they live

*/

/* and the maximum number of semaphores in the entry_semaphore set */
static int sem_nr;
gen_lock_set_t* timer_semaphore=0;
gen_lock_set_t* entry_semaphore=0;
gen_lock_set_t* reply_semaphore=0;
#endif

/* timer group locks */


static ser_lock_t* timer_group_lock=0; /* pointer to a TG_NR lock array,
								    it's safer if we alloc this in shared mem
									( required for fast lock ) */

/* initialize the locks; return 0 on success, -1 otherwise
*/
int lock_initialize( unsigned int timer_sets )
{
	int i;
#ifndef GEN_LOCK_T_PREFERED
	int probe_run;
#endif

	/* first try allocating semaphore sets with fixed number of semaphores */
	LM_DBG("lock initialization started\n");

	timer_group_lock=shm_malloc(timer_sets*TG_NR*sizeof(ser_lock_t));
	if (timer_group_lock==0){
		LM_CRIT("no more share mem\n");
		goto error;
	}
#ifdef GEN_LOCK_T_PREFERED
	for(i=0;i<timer_sets*TG_NR;i++) lock_init(&timer_group_lock[i]);
#else
	/* transaction timers */
	if (((timer_semaphore= lock_set_alloc( TG_NR ) ) == 0)||
			(lock_set_init(timer_semaphore)==0)){
		if (timer_semaphore) lock_set_destroy(timer_semaphore);
		LM_CRIT("transaction timer semaphore initialization failure: %s\n",
				strerror(errno));
		goto error;
	}

	for (i=0; i<TG_NR; i++) {
		timer_group_lock[i].semaphore_set = timer_semaphore;
		timer_group_lock[i].semaphore_index = timer_group[ i ];
	}


	i=SEM_MIN;
	/* probing phase: 0=initial, 1=after the first failure */
	probe_run=0;
again:
	do {
		if (entry_semaphore!=0){ /* clean-up previous attempt */
			lock_set_destroy(entry_semaphore);
			lock_set_dealloc(entry_semaphore);
		}
		if (reply_semaphore!=0){
			lock_set_destroy(reply_semaphore);
			lock_set_dealloc(reply_semaphore);
		}

		if (i==0){
			LM_CRIT("failed allocate semaphore sets\n");
			goto error;
		}

		if (((entry_semaphore=lock_set_alloc(i))==0)||
			(lock_set_init(entry_semaphore)==0)) {
			LM_DBG("entry semaphore initialization failure:  %s\n",
					strerror( errno ) );
			if (entry_semaphore){
				lock_set_dealloc(entry_semaphore);
				entry_semaphore=0;
			}
			/* first time: step back and try again */
			if (probe_run==0) {
					LM_DBG("first time semaphore allocation failure\n");
					i--;
					probe_run=1;
					continue;
				/* failure after we stepped back; give up */
			} else {
					LM_DBG("second time semaphore allocation failure\n");
					goto error;
			}
		}
		/* allocation succeeded */
		if (probe_run==1) { /* if ok after we stepped back, we're done */
			break;
		} else { /* if ok otherwise, try again with larger set */
			if (i==SEM_MAX) break;
			else {
				i++;
				continue;
			}
		}
	} while(1);
	sem_nr=i;

	if (((reply_semaphore=lock_set_alloc(i))==0)||
		(lock_set_init(reply_semaphore)==0)){
			if (reply_semaphore){
				lock_set_dealloc(reply_semaphore);
				reply_semaphore=0;
			}
			LM_DBG("reply semaphore initialization failure: %s\n",
					strerror(errno));
			probe_run=1;
			i--;
			goto again;
	}

	/* return success */
	LM_INFO("semaphore arrays of size %d allocated\n", sem_nr );
#endif /* GEN_LOCK_T_PREFERED*/
	return 0;
error:
	lock_cleanup();
	return -1;
}


#ifdef GEN_LOCK_T_PREFERED
void lock_cleanup(void)
{
	/* must check if someone uses them, for now just leave them allocated*/
	if (timer_group_lock) shm_free((void*)timer_group_lock);
}

#else

/* remove the semaphore set from system */
void lock_cleanup(void)
{
	/* that's system-wide; all other processes trying to use
	   the semaphore will fail! call only if it is for sure
	   no other process lives
	*/

	/* sibling double-check missing here; install a signal handler */

	if (entry_semaphore !=0){
		lock_set_destroy(entry_semaphore);
		lock_set_dealloc(entry_semaphore);
	};
	if (timer_semaphore !=0){
		lock_set_destroy(timer_semaphore);
		lock_set_dealloc(timer_semaphore);
	};
	if (reply_semaphore !=0) {
		lock_set_destroy(reply_semaphore);
		lock_set_dealloc(reply_semaphore);
	};
	entry_semaphore = timer_semaphore = reply_semaphore = 0;
	if (timer_group_lock) shm_free(timer_group_lock);

}
#endif /*GEN_LOCK_T_PREFERED*/





int init_cell_lock( struct cell *cell )
{
#ifdef GEN_LOCK_T_PREFERED
	lock_init(&cell->reply_mutex);
#else
	cell->reply_mutex.semaphore_set=reply_semaphore;
	cell->reply_mutex.semaphore_index = cell->hash_index % sem_nr;
#endif /* GEN_LOCK_T_PREFERED */
	return 0;
}

int init_entry_lock( struct s_table* ht, struct entry *entry )
{
#ifdef GEN_LOCK_T_PREFERED
	lock_init(&entry->mutex);
#else
	/* just advice which of the available semaphores to use;
	   specifically, all entries are partitioned into as
	   many partitions as number of available semaphores allows
        */
	entry->mutex.semaphore_set=entry_semaphore;
	entry->mutex.semaphore_index = ( ((char *)entry - (char *)(ht->entrys ) )
               / sizeof(struct entry) ) % sem_nr;
#endif
	return 0;
}



int release_cell_lock( struct cell *cell )
{
#ifndef GEN_LOCK_T_PREFERED
	/* don't do anything here -- the init_*_lock procedures
	   just advised on usage of shared semaphores but did not
	   generate them
	*/
#endif
	return 0;
}



int release_entry_lock( struct entry *entry )
{
	/* the same as above */
	return 0;
}



int release_timerlist_lock( struct timer *timerlist )
{
	/* the same as above */
	return 0;
}

int init_timerlist_lock( unsigned int set, enum lists timerlist_id)
{
	get_timertable()[set].timers[timerlist_id].mutex=
		&(timer_group_lock[ set*TG_NR + timer_group[timerlist_id] ]);
	return 0;
}
