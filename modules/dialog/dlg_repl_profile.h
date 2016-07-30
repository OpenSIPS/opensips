/*
 * dialog module - basic support for dialog tracking
 *
 * Copyright (C) 2013 OpenSIPS Solutions
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
 *  2015-06-10 initial version (razvanc)
 */

#include "../../ut.h"
#include "../../bin_interface.h"
#include "../../socket_info.h"
#include "../../timer.h"

#ifndef _DIALOG_DLG_PROFILE_REPLICATION_H_
#define _DIALOG_DLG_PROFILE_REPLICATION_H_

typedef struct repl_prof_count {
	int counter;
	time_t update;
        int machine_id;
        struct repl_prof_count *next;
} repl_prof_count_t;

typedef struct repl_prof_novalue {
	gen_lock_t lock;
	struct repl_prof_count *dsts;
} repl_prof_novalue_t;

typedef struct repl_prof_value {
	int counter;
	repl_prof_novalue_t *noval;
} repl_prof_value_t;

/* profiles functions */
extern int accept_repl_profiles;
extern int accept_replicated_profile_timeout;
extern int repl_prof_auth_check;
extern int repl_prof_buffer_th;
extern int repl_prof_utimer;
extern int repl_prof_timer_check;
extern int repl_prof_timer_expire;
int repl_prof_init(void);
int repl_prof_remove(str *name, str *value);
int repl_prof_dest(modparam_t type, void *val);
int replicate_profiles_count(repl_prof_novalue_t *rp);


#define REPLICATION_DLG_PROFILE		4
#define DLG_REPL_PROF_TIMER			10
#define DLG_REPL_PROF_EXPIRE_TIMER	10
#define DLG_REPL_PROF_BUF_THRESHOLD	1400

static void free_profile_val_t (repl_prof_value_t *val){
    repl_prof_count_t *head = val->noval->dsts;
    repl_prof_count_t *tmp;
    while(head){
        tmp = head;
        head = head->next;
        shm_free(tmp);
    }
    shm_free(val);
}

static inline void free_profile_val(void *val){
    free_profile_val_t(( repl_prof_value_t*) val);
}


static inline repl_prof_novalue_t *repl_prof_allocate(void)
{
	repl_prof_novalue_t *rp;

	rp = shm_malloc(sizeof(repl_prof_novalue_t));
	if (!rp) {
		/* if there is no more shm memory, there's not much that you can do
		 * anyway */
		LM_WARN("no more shm mem\n");
		return NULL;
	}

	memset(rp, 0, sizeof(repl_prof_novalue_t));
	lock_init(&rp->lock);

	return rp;
}

static inline void repl_prof_inc(void **dst)
{
	repl_prof_value_t *rp;

	if (accept_repl_profiles) {
		/* if the destination does not exist, create it */
		if (!*dst) {
			rp = shm_malloc(sizeof(repl_prof_value_t));
			if (!rp) {
				LM_ERR("no more shm memory to allocate repl_prof_value\n");
				return;
			}
			memset(rp, 0, sizeof(repl_prof_value_t));
			*dst = rp;
		} else {
			rp = (repl_prof_value_t *)(*dst);
		}
		rp->counter++;
	} else {
		(*dst) = (void*)((long)(*dst) + 1);
	}
}

static inline int repl_prof_get_all(void **dst)
{
	repl_prof_value_t *rp;
	if (accept_repl_profiles) {
		rp = (repl_prof_value_t *)(*dst);
		if (!rp->noval)
			return rp->counter;
		return rp->counter + replicate_profiles_count(rp->noval);
	} else {
		return (int)(long)(*dst);
	}
}

static inline void repl_prof_dec(void **dst)
{
	repl_prof_value_t *rp;
	int counter;

	if (accept_repl_profiles) {
		rp = (repl_prof_value_t *)(*dst);
		rp->counter--;
		/* check all the others to see if we should delete the profile */
		counter = repl_prof_get_all(dst);
		if (counter == 0) {
			if (rp->noval)
				shm_free(rp->noval);
			shm_free(rp);
			*dst = 0;
		}
	} else {
		(*dst) = (void*)((long)(*dst) - 1);
	}
}

static inline int repl_prof_get(void **dst)
{
	repl_prof_value_t *rp;

	if (accept_repl_profiles) {
		rp = (repl_prof_value_t *)(*dst);
		return rp->counter;
	} else {
		return (int)(long)(*dst);
	}
}


#endif /* _DIALOG_DLG_PROFILE_REPLICATION_H_ */
