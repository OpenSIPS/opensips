/**
 *
 * qrouting module: qrouting.c
 *
 * Copyright (C) 2004-2005 FhG Fokus
 * Copyright (C) 2006-2010 Voice Sistem SRL
 * Copyright (C) 2014 OpenSIPS Foundation
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History
 * -------
 *  2014-08-28  initial version (Mihai Tiganus)
 */
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

#include "../../str.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"

#include "qr_stats.h"

/* create the samples for a gateway's history */
qr_sample_t * create_history(void) {
	qr_sample_t * history, *tmp;
	int i;

	history = (qr_sample_t*)shm_malloc(sizeof(qr_sample_t));
	if(history == NULL) {
		LM_ERR("no more shm_memory\n");
		return NULL;
	}
	for(tmp = history, i = 0; i < qr_n-1; tmp = tmp->next, ++i) {
		tmp->next = (qr_sample_t*)shm_malloc(sizeof(qr_sample_t));
		if(tmp->next == NULL)
			return NULL;
	}
	tmp->next = history;
	return history;
}

/* create a gateway */
qr_gw_t * qr_create_gw(void){
	qr_gw_t *gw;
	if ((gw = shm_malloc(sizeof(qr_gw_t))) == NULL) {
		LM_ERR("no more shm memory\n");
		return NULL;
	}
	memset(gw, 0, sizeof(qr_gw_t));
	gw->acc_lock = (gen_lock_t*)lock_alloc();
	if (!lock_init(gw->acc_lock)) {
		LM_ERR("failed to init lock\n");
		return NULL;
	}
	if ((gw->ref_lock = lock_init_rw()) == NULL) {
		LM_ERR("failed to init RW lock\n");
		return NULL;
	}
	if( (gw->next_interval = create_history()) == NULL) {
		LM_ERR("failed to create history\n");
		return NULL;
	}
	return gw;
}

/* free all the samples in a gateway's history */
void free_history(qr_sample_t * history) {
	qr_sample_t *tmp;
	while(history) {
		tmp = history;
		history = history->next;
		shm_free(tmp);
	}
}

/* free gateway information */
void qr_free_gw(qr_gw_t * gw) {
	free_history(gw->next_interval);
	if(gw->acc_lock) {
		lock_destroy(gw->acc_lock);
		lock_dealloc(gw->acc_lock);
	}
	if(gw->ref_lock) {
		lock_destroy_rw(gw->ref_lock);
	}
	shm_free(gw);
}

/* a call for this gateway returned 200OK */
inline void qr_add_200OK(qr_gw_t * gw) {
	lock_get(gw->acc_lock);
	++(gw->current_interval.call_stats.as);
	++(gw->current_interval.call_stats.cc);
	lock_release(gw->acc_lock);
}

/* a call for this gateway returned 4XX */
void qr_add_4xx(qr_gw_t * gw) {
	++(gw->current_interval.call_stats.cc);
}
