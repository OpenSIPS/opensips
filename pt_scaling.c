/*
 * Copyright (C) 2019 OpenSIPS Project
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

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include "mem/shm_mem.h"
#include "socket_info.h"
#include "dprint.h"
#include "pt.h"
#include "ipc.h"
#include "daemonize.h"


struct process_group {
	enum process_type type;
	struct socket_info *si_filter;
	fork_new_process_f *fork_func;
	terminate_process_f *term_func;
	unsigned int max_procs;
	unsigned int min_procs;
	/* some reference to a profile to give us params for fork/rip procs  */
	unsigned char history_size;
	unsigned char history_idx;
	unsigned short no_downscale_cycles;
	unsigned char *history_map;
	struct process_group *next;
};

#define PG_HISTORY_DEFAULT_SIZE  5 /*to be replaced with val from profile*/
#define PG_HIGH_MIN_SCORE        4 /*to be replaced with val from profile*/
#define PG_HLOAD_TRESHOLD       50 /*to be replaced with val from profile*/
#define PG_LLOAD_TRESHOLD       20 /*to be replaced with val from profile*/

struct process_group *pg_head = NULL;

int create_process_group(enum process_type type,
						struct socket_info *si_filter,
						unsigned int min_procs, unsigned int max_procs,
						fork_new_process_f *f1, terminate_process_f *f2)
{
	struct process_group *pg, *it;

	pg = (struct process_group*)shm_malloc( sizeof(struct process_group) +
		sizeof(char)*PG_HISTORY_DEFAULT_SIZE );
	if (pg==NULL) {
		LM_ERR("failed to allocate memory for a new process group\n");
		return -1;
	}
	memset( pg, 0, sizeof(struct process_group) +
		sizeof(char)*PG_HISTORY_DEFAULT_SIZE );

	LM_DBG("registering group of processes type %d, socket filter %p, "
		"process range [%d,%d]\n", type, si_filter, min_procs, max_procs );

	pg->type = type;
	pg->si_filter = si_filter;
	pg->max_procs = max_procs;
	pg->min_procs = min_procs;
	pg->fork_func = f1;
	pg->term_func = f2;
	pg->next = NULL;

	pg->history_size = PG_HISTORY_DEFAULT_SIZE;
	pg->history_map = (unsigned char*)(pg+1);
	pg->history_idx = 0;
	pg->no_downscale_cycles = 10*PG_HISTORY_DEFAULT_SIZE;

	/* add at the end of list, to avoid changing the head of the list due
	 * forking */
	for( it=pg_head ; it && it->next ; it=it->next);
	if (it==NULL)
		pg_head = pg;
	else
		it->next = pg;

	return 0;
}


void rescale_group_history(struct process_group *pg, unsigned int idx,
		int org_size, int offset)
{
	unsigned int k;
	unsigned char old;

	k = idx;
	do {
		old = pg->history_map[k] ;
		pg->history_map[k] = (pg->history_map[k]*org_size)/(org_size+offset);
		LM_DBG("rescaling old %d to %d [idx %d]\n",
			old, pg->history_map[k], k);

		k = k ? (k-1) : (PG_HISTORY_DEFAULT_SIZE-1) ;
	} while(k!=idx);
}


void check_and_adjust_number_of_workers(void)
{
	struct process_group *pg;
	unsigned int i, k, idx;
	unsigned int load;
	unsigned int procs_no;
	unsigned char cnt_under, cnt_over;
	int p_id, last_idx_in_pg;

	/* iterate all the groups we have */
	for ( pg=pg_head ; pg ; pg=pg->next ) {

		load = 0;
		procs_no = 0;
		last_idx_in_pg = -1;

		/* find the processes belonging to this group */
		for ( i=0 ; i<counted_max_processes ; i++) {

			if (pt[i].type != pg->type || pg->si_filter!=pt[i].pg_filter)
				continue;

			load += get_stat_val( pt[i].load_rt );
			last_idx_in_pg = i;
			procs_no++;

		}

		/* set the current value */
		idx = (pg->history_idx+1)%PG_HISTORY_DEFAULT_SIZE;
		pg->history_map[idx] = (unsigned char) ( load / procs_no );

		LM_DBG("group %d (with %d procs) has average load of %d\n",
			pg->type, procs_no, pg->history_map[idx]);

		/* do the check over the history */
		cnt_over = 0;
		cnt_under = 0;
		k = idx;
		do {
			if (pg->history_map[k]>PG_HLOAD_TRESHOLD)
				cnt_over++;
			else if (pg->history_map[k]<PG_LLOAD_TRESHOLD)
				cnt_under++;

			k = k ? (k-1) : (PG_HISTORY_DEFAULT_SIZE-1) ;
		} while(k!=idx);

		/* decide what to do */
		if (cnt_over>=PG_HIGH_MIN_SCORE) {
			if (procs_no<pg->max_procs) {
				LM_NOTICE("score %d/%d -> forking new proc in group %d "
					"(with %d procs)\n", cnt_over, PG_HISTORY_DEFAULT_SIZE,
					pg->type, procs_no);
				/* we need to fork one more process here */
				if ( (p_id=pg->fork_func(pg->si_filter))<0 ||
				wait_for_one_child()<0 ) {
					LM_ERR("failed to fork new process for group %d "
						"(current %d procs)\n",pg->type,procs_no);
				} else {
					rescale_group_history( pg, idx, procs_no, +1);
					pg->no_downscale_cycles = 10*PG_HISTORY_DEFAULT_SIZE;
				}
			}
		} else if (cnt_under==PG_HISTORY_DEFAULT_SIZE) {
			if (procs_no>pg->min_procs && procs_no!=1 &&
			pg->no_downscale_cycles==0) {
				/* try to estimate the load after downscaling */
				load = 0;
				k = idx;
				do {
					load += pg->history_map[k];
					k = k ? (k-1) : (PG_HISTORY_DEFAULT_SIZE-1) ;
				} while(k!=idx);
				load = (load*procs_no) / (procs_no-1);
				if (load<PG_HLOAD_TRESHOLD) {
					/* down scale one more process here */
					LM_DBG("score %d/%d -> ripping one proc from group %d "
						"(with %d procs), estimated load -> %d\n", cnt_under,
						PG_HISTORY_DEFAULT_SIZE, pg->type, procs_no,
						load );
					ipc_send_rpc( last_idx_in_pg, pg->term_func, NULL);
				}
			}
		}

		pg->history_idx++;
		if (pg->no_downscale_cycles) pg->no_downscale_cycles--;
	}
}

