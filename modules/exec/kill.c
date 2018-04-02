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
 *  2003-03-11  changed to the new locking scheme: locking.h (andrei)
 *
 *
 * in this file, we implement the ability to send a kill signal to
 * a child after some time; its a quick ugly hack, for example kill
 * is sent without any knowledge whether the kid is still alive
 *
 * also, it was never compiled without FAST_LOCK -- nothing will
 * work if you turn it off
 *
 * there is also an ugly s/HACK
 *
 * and last but not least -- we don't know the child pid (we use popen)
 * so we cannot close anyway
 *
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../timer.h"
#include "../../locking.h"

#include "kill.h"


static gen_lock_t *kill_lock=NULL;


static struct timer_list *kill_list;



#define lock() lock_get(kill_lock)

#define unlock() lock_release(kill_lock)



/* copy and paste from TM -- might consider putting in better
   in some utils part of core
*/
static void timer_routine(unsigned int ticks , void * attr)
{
	struct timer_link *tl, *tmp_tl, *end, *ret;
	int killr;
	UNUSED(killr);

	/* check if it worth entering the lock */
	if (kill_list->first_tl.next_tl==&kill_list->last_tl
			|| kill_list->first_tl.next_tl->time_out > ticks )
		return;

	lock();
	end = &kill_list->last_tl;
	tl = kill_list->first_tl.next_tl;
	while( tl!=end && tl->time_out <= ticks ) {
		tl=tl->next_tl;
	}

	/* nothing to delete found */
	if (tl->prev_tl==&kill_list->first_tl) {
		unlock();
		return;
	}
	/* the detached list begins with current beginning */
	ret = kill_list->first_tl.next_tl;
	/* and we mark the end of the split list */
	tl->prev_tl->next_tl = 0;
	/* the shortened list starts from where we suspended */
	kill_list->first_tl.next_tl = tl;
	tl->prev_tl=&kill_list->first_tl;
	unlock();

	/* process the list now */
	while (ret) {
		tmp_tl=ret->next_tl;
		ret->next_tl=ret->prev_tl=0;
		if (ret->time_out>0) {
			LM_DBG("pid %d -> sending SIGTERM\n", ret->pid);
			killr=kill(ret->pid, SIGTERM);
			LM_DBG("child process (%d) kill status: %d\n", ret->pid, killr );
		}
		shm_free(ret);
		ret=tmp_tl;
	}
}

pid_t __popen3(const char* cmd, FILE** strm_w, FILE** strm_r, FILE** strm_e)
{
#define OPEN_PIPE(strm, fds) \
	do { \
		if (strm) { \
			if (pipe(fds) != 0) { \
				LM_ERR("failed to create reading pipe (%d: %s)\n", \
							errno, strerror(errno)); \
				return -1; \
			} \
		} \
	} while (0);

/*
 * cl - pipe end to be closed
 * op - pipe end to be redirected
 * re - fds where to redirect 'op'
 */
#define CLOSE_AND_REDIRECT(strm, fds, cl, op, re) \
	do { \
		if (strm) { \
			close(fds[cl]); \
			dup2(fds[op], re); \
			close(fds[op]); \
		} \
	} while (0);

#define CLOSE_END_AND_OPEN_STREAM(strm, way, fds, end2close) \
	do { \
		if (strm) { \
			close(fds[end2close]); \
			*strm = fdopen(fds[(1^end2close)], way); \
		} \
	}while (0);

	pid_t ret;
	int r_fds[2], w_fds[2], e_fds[2];

	if (strm_r == NULL && strm_w == NULL && strm_e == NULL) {
		LM_WARN("no descriptor redirect required\n");
	}

	OPEN_PIPE(strm_w, w_fds);
	OPEN_PIPE(strm_r, r_fds);
	OPEN_PIPE(strm_e, e_fds);

	ret=fork();

	if (ret==0) {
		/* write pipe */
		CLOSE_AND_REDIRECT(strm_w, w_fds, 1, 0, STDIN_FILENO);

		/* read pipe  */
		CLOSE_AND_REDIRECT(strm_r, r_fds, 0, 1, STDOUT_FILENO);

		/* error pipe */
		CLOSE_AND_REDIRECT(strm_e, e_fds, 0, 1, STDERR_FILENO);

		execl("/bin/sh", "/bin/sh", "-c", cmd, NULL);

		exit(-1);
	}

	CLOSE_END_AND_OPEN_STREAM(strm_w, "w", w_fds, 0);
	CLOSE_END_AND_OPEN_STREAM(strm_r, "r", r_fds, 1);
	CLOSE_END_AND_OPEN_STREAM(strm_e, "r", e_fds, 1);

	return ret;

#undef OPEN_PIPE
#undef CLOSE_AND_REDIRECT
#undef CLOSE_AND_OPEN_STREAM

}

int schedule_to_kill( int pid )
{
	struct timer_link *tl;

	if (time_to_kill <= 0)
		return 0;

	tl = shm_malloc(sizeof *tl);
	if (!tl) {
		LM_ERR("no shmem\n");
		return -1;
	}
	memset(tl, 0, sizeof *tl);

	lock();
	tl->pid=pid;
	tl->time_out=get_ticks()+time_to_kill;
	tl->prev_tl = kill_list->last_tl.prev_tl;
	tl->next_tl = &kill_list->last_tl;
	kill_list->last_tl.prev_tl=tl;
	tl->prev_tl->next_tl=tl;
	unlock();

	return 0;
}

int initialize_kill(void)
{
	/* if disabled ... */
	if (time_to_kill == 0)
		return 0;

	if (register_timer("exec_kill", timer_routine, NULL /* param */,
	    1 /* period */, TIMER_FLAG_SKIP_ON_DELAY) < 0) {
		LM_ERR("no exec timer registered\n");
		return -1;
	}

	kill_list = shm_malloc(sizeof *kill_list);
	if (!kill_list) {
		LM_ERR("no more shm!\n");
		return -1;
	}

	kill_list->first_tl.next_tl = &kill_list->last_tl;
	kill_list->last_tl.prev_tl  = &kill_list->first_tl;
	kill_list->first_tl.prev_tl =
	kill_list->last_tl.next_tl  = NULL;

	kill_list->last_tl.time_out = -1;

	kill_lock = lock_alloc();
	if (!kill_lock) {
		LM_ERR("no shm mem for mutex\n");
		return -1;
	}
	lock_init(kill_lock);

	LM_DBG("kill initialized\n");
	return 0;
}

void destroy_kill(void)
{
	/* if disabled ... */
	if (time_to_kill==0)
		return;

	if (kill_lock) {
		lock_destroy(kill_lock);
		lock_dealloc(kill_lock);
	}
}
