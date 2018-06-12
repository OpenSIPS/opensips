#include <errno.h>

#include "lock.h"
#include "globals.h"
#include "timer.h"

/* we implement mutex here using System V semaphores; as number of
   sempahores is limited and number of synchronized elements
   high, we partition the sync'ed SER elements and share semaphores 
   in each of the partitions; we try to use as many semaphores as OS
   gives us for finest granularity; perhaps later we will
   add some arch-dependent mutex code that will not have
   ipc's dimensioning limitations and will provide us with
   fast unlimited (=no sharing) mutexing

   we allocate the locks according to the following plans:

   1) transaction timer lists have each a semaphore in
      a semaphore set
   2) retransmission timer lists have each a semaphore
      in a semaphore set
   3) we allocate a semaphore set for hash_entries and
      try to use as many semaphores in it as OS allows;
      we partition the the hash_entries by available
      semaphores which are shared  in each partition
   4) cells get always the same semaphore as its hash
      entry in which they live

*/

/* keep the semaphore here */
int entry_semaphore=0, transaction_timer_semaphore=0, retrasmission_timer_semaphore=0;
/* and the number of semaphores in the entry_semaphore set */
int sem_nr;


/* intitialize the locks; return 0 on success, -1 otherwise 
*/


int lock_initialize()
{
	/* first try allocating semaphore sets with fixed number of semaphores */

	/* transaction timers */
	if ((transaction_timer_semaphore=init_semaphore_set( NR_OF_TIMER_LISTS) )==-1) {
		DBG("transaction timer semaphore allocation failure\n");
		goto error;
	}

	/* message retransmission timers */
        if ((retrasmission_timer_semaphore=init_semaphore_set( NR_OF_RT_LISTS) )==-1) {
                DBG("retransmission timer semaphore initialization failure\n");
                goto error;
        }
	
	sem_nr=12;
	/* probing should return if too big:
		Solaris: EINVAL
		Linux: ENOSPC
	*/
        if ((entry_semaphore=init_semaphore_set( sem_nr ) )==-1) {
                DBG("retransmission timer semaphore initialization failure\n");
                goto error;
        }
	
	/* return number of  sempahores in the set */
	return 0;
error:
	lock_cleanup();
	return -1;
}

int init_semaphore_set( int size )
{
	int new_semaphore, i;

	new_semaphore=semget ( IPC_PRIVATE, size, IPC_CREAT | IPC_PERMISSIONS );
	if (new_semaphore==-1) return new_semaphore;
	for (i=0; i<size; i++) {
                union semun {
                        int val;
                        struct semid_ds *buf;
                        ushort *array;
                } argument;
                /* binary lock */
                argument.val = +1;
                if (semctl( new_semaphore, i , SETVAL , argument )==-1) {
			DBG("ERROR: failure to initialize a semaphore\n");
			if (semctl( entry_semaphore, 0 , IPC_RMID , 0 )==-1)
				DBG("ERROR: failure to release a semaphore\n");
			return -1;
                }
        }
	return new_semaphore;
}



/* remove the semaphore set from system */
void lock_cleanup()
{
	/* that's system-wide; all othe processes trying to use
	   the semaphore will fail! call only if it is for sure
	   no other process lives 
	*/

	DBG("clean-up still not implemented properly\n");
	/* sibling double-check missing here; install a signal handler */

	if (entry_semaphore > 0 && 
	    semctl( entry_semaphore, 0 , IPC_RMID , 0 )==-1)
		DBG("ERROR: entry_semaphore cleanup failed\n"); 
	if (transaction_timer_semaphore > 0 && 
	    semctl( transaction_timer_semaphore, 0 , IPC_RMID , 0 )==-1)
		DBG("ERROR: transaction_timer_semaphore cleanup failed\n"); 
	if (retrasmission_timer_semaphore > 0 &&
	    semctl( retrasmission_timer_semaphore, 0 , IPC_RMID , 0 )==-1)
		DBG("ERROR: retrasmission_timer_semaphore cleanup failed\n"); 
	
}

/* lock sempahore s */
int lock( lock_t s )
{
	return change_sem( s, -1 );
}
	
int unlock( lock_t s )
{
	return change_sem( s, +1 );
}


int change_semaphore( lock_t s  , int val )
{
   struct sembuf pbuf;
   int r;

   pbuf.sem_num = s.semaphore_index ;
   pbuf.sem_op =val;
   pbuf.sem_flg = 0;

tryagain:
   r=semop( s.semaphore_set, &pbuf ,  1 /* just 1 op */ );

   if (r==-1) {
	printf("ERROR occured in change_semaphore: %s\n", 
		strerror(errno));
	if (errno=EINTR) {
		DBG("signal received in a semaphore\n");
		goto tryagain;
	}
    }
   return r;
}

int init_cell_lock( struct cell *cell )
{
	/* just advice which of the available semaphores to use;
	   specifically, all cells in an entry use the same one
	   shared with its entry lock
        */
	cell->mutex.semaphore_set=entry_semaphore, 
	cell->mutex.semaphore_index=cell->transaction.hash_index / sem_nr;
}

int init_entry_lock( struct s_table* hash_table, struct entry *entry )
{
	/* just advice which of the available semaphores to use;
	   specifically, all entries are partitioned into as
	   many partitions as number of available semaphors allows
        */
	entry->mutex.semaphore_set=entry_semaphore;
	entry->mutex.semaphore_index = 
		((void *)entry - (void *)(hash_table->entrys ) )
			/ ( sizeof(struct entry) * sem_nr );
}

int init_timerlist_lock( struct s_table* hash_table, enum lists timerlist_id)
{
	/* each timer list has its own semaphore */
	hash_table->timers[timerlist_id].mutex.semaphore_set=transaction_timer_semaphore;
	hash_table->timers[timerlist_id].mutex.semaphore_index=timerlist_id;
}

int init_retr_timer_lock( struct s_table* hash_table, enum retransmission_lists list_id )
{
	hash_table->retr_timers[list_id].mutex.semaphore_set=retrasmission_timer_semaphore;
 	hash_table->retr_timers[list_id].mutex.semaphore_index=list_id;
}


int release_cell_lock( struct cell *cell )
{
	/* don't do anything here -- the init_*_lock procedures
	   just advised on usage of shared semaphores but did not 
	   generate them
	*/
}
int release_entry_lock( struct entry *entry )
{
	/* the same as above */
}

release_timerlist_lock( struct timer *timerlist )
{
	/* the same as above */
}
int release_retr_timer_lock( struct timer *timerlist )
{
	
}
