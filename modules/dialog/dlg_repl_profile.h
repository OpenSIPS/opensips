/*
 * Copyright (C) 2013-2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

typedef struct prof_rcv_count {
	gen_lock_t lock;
	struct repl_prof_count *dsts;
} prof_rcv_count_t;

struct prof_local_count;

typedef struct prof_value_info {
	struct prof_local_count *local_counters;
	prof_rcv_count_t *rcv_counters;
} prof_value_info_t;

extern int repl_prof_buffer_th;
extern int repl_prof_utimer;
extern int repl_prof_timer_check;
extern int repl_prof_timer_expire;

/* profiles functions */
int repl_prof_init(void);
int repl_prof_remove(str *name, str *value);
int repl_prof_dest(modparam_t type, void *val);
int replicate_profiles_count(prof_rcv_count_t *rp);
void receive_prof_repl(bin_packet_t *packet);

#define REPLICATION_DLG_PROFILE		4
#define DLG_REPL_PROF_TIMER			10
#define DLG_REPL_PROF_EXPIRE_TIMER	10
#define DLG_REPL_PROF_BUF_THRESHOLD	1400

static void free_profile_val_t (prof_value_info_t *val){
    repl_prof_count_t *head = NULL, *tmp;

    if (val->rcv_counters)
		head = val->rcv_counters->dsts;
    while (head){
        tmp = head;
        head = head->next;
        shm_free(tmp);
    }

	if (val->rcv_counters)
		shm_free(val->rcv_counters);

    shm_free(val);
}

static inline void free_profile_val(void *val){
    free_profile_val_t(( prof_value_info_t*) val);
}


static inline prof_rcv_count_t *repl_prof_allocate(void)
{
	prof_rcv_count_t *rp;

	rp = shm_malloc(sizeof(prof_rcv_count_t));
	if (!rp) {
		LM_ERR("no more shm mem\n");
		return NULL;
	}

	memset(rp, 0, sizeof(prof_rcv_count_t));
	lock_init(&rp->lock);

	return rp;
}

static inline struct prof_local_count *get_local_counter(
						struct prof_local_count **list, str *shtag)
{
	struct prof_local_count *cnt;

	for (cnt = *list; cnt &&
		(shtag->len != cnt->shtag.len || memcmp(shtag->s, cnt->shtag.s, shtag->len));
		cnt = cnt->next);

	if (!cnt) {
		cnt = shm_malloc(sizeof *cnt);
		if (!cnt) {
			LM_ERR("oom\n");
			return NULL;
		}
		memset(cnt, 0, sizeof *cnt);

		if (shtag->len && shm_str_dup(&cnt->shtag, shtag) < 0) {
			LM_ERR("oom\n");
			return NULL;
		}

		cnt->next = *list;
		*list = cnt;
	}

	return cnt;
}

static inline void remove_local_counter(struct prof_local_count **list,
									str *shtag)
{
	struct prof_local_count *cnt, *cnt_prev = NULL;

	for (cnt = *list; cnt &&
		(shtag->len != cnt->shtag.len || memcmp(shtag->s, cnt->shtag.s, shtag->len));
		cnt_prev = cnt, cnt = cnt->next) ;
	if (!cnt) {
		LM_ERR("Failed to decrement profile counter, shtag not found\n");
		return;
	}

	cnt->n--;
	if (cnt->n == 0) {
		if (cnt_prev)
			cnt_prev->next = cnt->next;
		else
			*list = cnt->next;

		if (cnt->shtag.s)
			shm_free(cnt->shtag.s);
		shm_free(cnt);
	}
}

static inline void prof_val_local_inc(void **pv_info, str *shtag, int is_repl)
{
	prof_value_info_t *pvi;
	struct prof_local_count *cnt;

	/* if we accept replicated stuff, we have to allocate the
	 * structure for it and treat the counter differently */
	if (is_repl && profile_repl_cluster) {
		/* if info does not exist, create it */
		if (!*pv_info) {
			pvi = shm_malloc(sizeof(prof_value_info_t));
			if (!pvi) {
				LM_ERR("no more shm memory\n");
				return;
			}
			memset(pvi, 0, sizeof(prof_value_info_t));
			*pv_info = pvi;

			cnt = get_local_counter(&pvi->local_counters, shtag);
			if (!cnt)
				return;
		} else {
			pvi = (prof_value_info_t *)(*pv_info);
			cnt = get_local_counter(&pvi->local_counters, shtag);
			if (!cnt)
				return;
		}

		cnt->n++;
	} else {
		*pv_info = (void*)((long)(*pv_info) + 1);
	}
}

/* This function is used only for /b profiles
 * @all - all counters(including dialogs tagged as backup) */
static inline int prof_val_get_local_count(void **pv_info, int all)
{
	prof_value_info_t *pvi;
	struct prof_local_count *cnt;
	int n = 0;
	int rc;

	pvi = (prof_value_info_t *)(*pv_info);
	for (cnt = pvi->local_counters; cnt; cnt = cnt->next)
		if (!all && dialog_repl_cluster && cnt->shtag.s) {
			/* don't count dialogs for which we have a backup role */
			if ((rc = clusterer_api.shtag_get(&cnt->shtag,
				dialog_repl_cluster)) < 0)
				LM_ERR("Failed to get state for sharing tag: <%.*s>\n",
					cnt->shtag.len, cnt->shtag.s);

			if (rc != SHTAG_STATE_BACKUP)
				n += cnt->n;
		} else
			n += cnt->n;
	return n;
}

/* @all - all counters(including local dialogs tagged as backup) */
static inline int prof_val_get_count(void **pv_info, int all, int is_repl)
{
	prof_value_info_t *pvi;
	if (is_repl && profile_repl_cluster) {
		pvi = (prof_value_info_t *)(*pv_info);
		return prof_val_get_local_count(pv_info, all) +
				replicate_profiles_count(pvi->rcv_counters);
	} else {
		return (int)(long)(*pv_info);
	}
}

static inline void prof_val_local_dec(void **pv_info, str *shtag, int is_repl)
{
	prof_value_info_t *pvi;

	if (is_repl	&& profile_repl_cluster) {
		pvi = (prof_value_info_t *)(*pv_info);

		remove_local_counter(&pvi->local_counters, shtag);

		/* check all the other counters(local + received) to see if we should
		 * delete the profile */
		if (prof_val_get_count(pv_info, 1, 1) == 0) {
			free_profile_val_t(pvi);
			*pv_info = 0;
		}
	} else {
		(*pv_info) = (void*)((long)(*pv_info) - 1);
	}
}

#endif /* _DIALOG_DLG_PROFILE_REPLICATION_H_ */
