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

#include "dlg_replication.h"

#ifndef _DIALOG_DLG_PROFILE_REPLICATION_H_
#define _DIALOG_DLG_PROFILE_REPLICATION_H_

typedef struct repl_prof_count {
	int counter;
	time_t update;
    int node_id;
    struct repl_prof_count *next;
} repl_prof_count_t;

typedef struct repl_prof_novalue {
	gen_lock_t lock;
	struct repl_prof_count *dsts;
} repl_prof_novalue_t;

struct prof_local_count;

typedef struct repl_prof_value {
	struct prof_local_count local_counter;
	repl_prof_novalue_t *noval;  /* info about received counters */
} prof_value_info_t;

extern int repl_prof_buffer_th;
extern int repl_prof_utimer;
extern int repl_prof_timer_check;
extern int repl_prof_timer_expire;

/* profiles functions */
int repl_prof_init(void);
int repl_prof_remove(str *name, str *value);
int repl_prof_dest(modparam_t type, void *val);
int replicate_profiles_count(repl_prof_novalue_t *rp);
void receive_prof_repl(bin_packet_t *packet);

#define REPLICATION_DLG_PROFILE		4
#define DLG_REPL_PROF_TIMER			10
#define DLG_REPL_PROF_EXPIRE_TIMER	10
#define DLG_REPL_PROF_BUF_THRESHOLD	1400

static void free_profile_val_t (prof_value_info_t *val){
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
    free_profile_val_t(( prof_value_info_t*) val);
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

static inline void prof_val_local_inc(void **dst, struct dlg_cell *dlg)
{
	prof_value_info_t *rp;

	if (profile_repl_cluster) {
		/* if the destination does not exist, create it */
		if (!*dst) {
			rp = shm_malloc(sizeof(prof_value_info_t));
			if (!rp) {
				LM_ERR("no more shm memory to allocate repl_prof_value\n");
				return;
			}
			memset(rp, 0, sizeof(prof_value_info_t));
			rp->local_counter.dlg = dlg;
			*dst = rp;
		} else {
			rp = (prof_value_info_t *)(*dst);
		}
		rp->local_counter.n++;
	} else {
		(*dst) = (void*)((long)(*dst) + 1);
	}
}

static inline int prof_val_get_count(void **dst)
{
	prof_value_info_t *rp;
	if (profile_repl_cluster) {
		rp = (prof_value_info_t *)(*dst);
		if (dialog_repl_cluster) {
			if (get_shtag_state(rp->local_counter.dlg) != SHTAG_STATE_BACKUP) {
				if (!rp->noval)
					return rp->local_counter.n;
				return rp->local_counter.n + replicate_profiles_count(rp->noval);
			} else /* don't count dialogs for which we have a backup role */
				return replicate_profiles_count(rp->noval); /* only received counters */
		} else {
			if (!rp->noval)
				return rp->local_counter.n;
			return rp->local_counter.n + replicate_profiles_count(rp->noval);
		}
	} else {
		return (int)(long)(*dst);
	}
}

static inline void prof_val_local_dec(void **dst)
{
	prof_value_info_t *rp;
	int counter;

	if (profile_repl_cluster) {
		rp = (prof_value_info_t *)(*dst);
		rp->local_counter.n--;
		/* check all the others to see if we should delete the profile */
		counter = prof_val_get_count(dst);
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

static inline int prof_val_get_local_count(void **dst)
{
	prof_value_info_t *rp;

	if (profile_repl_cluster) {
		rp = (prof_value_info_t *)(*dst);
		if (dialog_repl_cluster) {
			if (get_shtag_state(rp->local_counter.dlg) != SHTAG_STATE_BACKUP)
				return rp->local_counter.n;
			else /* don't count dialogs for which we have a backup role */
				return 0;
		} else
			return rp->local_counter.n;
	} else {
		return (int)(long)(*dst);
	}
}

#endif /* _DIALOG_DLG_PROFILE_REPLICATION_H_ */
