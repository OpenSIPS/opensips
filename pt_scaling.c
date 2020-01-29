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
	struct scaling_profile *prof;
	unsigned char history_size;
	unsigned char *history_map;
	unsigned char history_idx;
	unsigned short no_downscale_cycles;
	struct process_group *next;
};

static struct process_group *pg_head = NULL;

static struct scaling_profile *profiles_head = NULL;



int create_auto_scaling_profile( char *name,
	unsigned int max_procs, unsigned int up_threshold,
	unsigned int up_cycles_needed, unsigned int up_cycles_tocheck,
	unsigned int min_procs, unsigned int down_threshold,
	unsigned int down_cycles_tocheck, unsigned short down_cycles_delay)
{
	struct scaling_profile *p;

	/* check for duplicates */
	if ( get_scaling_profile(name) ) {
		LM_ERR("profile <%s> (case insensitive) already created"
			" - double definition?? \n", name);
		return -1;
	}

	/* some sanity checks */
	if (min_procs==0) {
		down_threshold = 0;
		down_cycles_tocheck = 0;
		down_cycles_delay = 0;
	}
	if (max_procs==0 || max_procs <= min_procs || max_procs>=1000) {
		LM_ERR("invalid relation or range for MIN/MAX processes [%d,%d]\n",
			min_procs, max_procs);
		return -1;
	}
	if (up_threshold==0 || up_threshold <= down_threshold ||
	up_threshold>100 || down_threshold>100) {
		LM_ERR("invalid relation or range DOWN/UP thresholds percentages "
			"[%d,%d]\n", down_threshold, up_threshold);
		return -1;
	}
	if (up_cycles_needed==0 || up_cycles_tocheck==0 ||
	up_cycles_tocheck<up_cycles_needed) {
		LM_ERR("invalid relation or values for upscaling check [%d of %d]\n",
			up_cycles_needed, up_cycles_tocheck);
		return -1;
	}

	/* all good, create it*/

	p = (struct scaling_profile*)pkg_malloc( sizeof(struct scaling_profile) +
		strlen(name) + 1 );
	if (p==NULL) {
		LM_ERR("failed to allocate memory for a new auto-scaling profile\n");
		return -1;
	}

	/* not really need, more to be safe for future expansions */
	memset( p, 0, sizeof(struct scaling_profile));

	p->max_procs = max_procs;
	p->up_threshold = up_threshold;
	p->up_cycles_needed = up_cycles_needed;
	p->up_cycles_tocheck = up_cycles_tocheck;
	p->min_procs = min_procs;
	p->down_threshold = down_threshold;
	p->down_cycles_tocheck = down_cycles_tocheck;
	p->down_cycles_delay = down_cycles_delay;
	p->name = (char*)(p+1);
	strcpy( p->name, name);

	LM_DBG("profile <%s> created UP [max=%d, th=%d%%, check %d/%d] DOWN "
		"[min=%d, th=%d%%, check %d, delay=%d]\n", name,
		max_procs, up_threshold, up_cycles_needed, up_cycles_tocheck,
		min_procs, down_threshold, down_cycles_tocheck, down_cycles_delay);

	p->next = profiles_head;
	profiles_head = p;

	return 0;
}


struct scaling_profile *get_scaling_profile(char *name)
{
	struct scaling_profile *p;

	for ( p=profiles_head ; p ; p=p->next )
		if (strcasecmp(name, p->name)==0)
			return p;

	return NULL;
}


int create_process_group(enum process_type type,
		struct socket_info *si_filter, struct scaling_profile *prof,
		fork_new_process_f *f1, terminate_process_f *f2)
{
	struct process_group *pg, *it;
	int h_size;

	/* how much of a history do we need in order to cover both up and down
	 * tranzitions ? */
	h_size = (prof->up_cycles_tocheck > prof->down_cycles_tocheck) ?
		prof->up_cycles_tocheck : prof->down_cycles_tocheck;

	pg = (struct process_group*)shm_malloc( sizeof(struct process_group) +
		sizeof(char)*h_size );
	if (pg==NULL) {
		LM_ERR("failed to allocate memory for a new process group\n");
		return -1;
	}
	memset( pg, 0, sizeof(struct process_group) + sizeof(char)*h_size );

	LM_DBG("registering group of processes type %d, socket filter %p, "
		"scaling profile <%s>\n", type, si_filter, prof->name );

	pg->type = type;
	pg->si_filter = si_filter;
	pg->prof = prof;
	pg->fork_func = f1;
	pg->term_func = f2;
	pg->next = NULL;

	pg->history_size = h_size;
	pg->history_map = (unsigned char*)(pg+1);
	pg->history_idx = 0;
	pg->no_downscale_cycles = pg->prof->down_cycles_delay;

	/* add at the end of list, to avoid changing the head of the list due
	 * forking */
	for( it=pg_head ; it && it->next ; it=it->next);
	if (it==NULL)
		pg_head = pg;
	else
		it->next = pg;

	return 0;
}


static void _pt_raise_event(struct process_group *pg, int p_id, int load,
																char *scale)
{
	static str pt_ev_type = str_init("group_type");
	static str pt_ev_filter = str_init("group_filter");
	static str pt_ev_load = str_init("group_load");
	static str pt_ev_scale = str_init("scale");
	static str pt_ev_p_id = str_init("process_id");
	static str pt_ev_pid = str_init("pid");
	evi_params_p list = NULL;
	str s;

	if (!evi_probe_event(EVI_PROC_AUTO_SCALE_ID))
		return;

	list = evi_get_params();
	if (!list) {
		LM_ERR("cannot create event params\n");
		return;
	}

	if (pg->type==TYPE_UDP) {
		s.s = "UDP"; s.len = 3;
	} else if (pg->type==TYPE_TCP) {
		s.s = "TCP"; s.len = 3;
	} else if (pg->type==TYPE_TIMER) {
		s.s = "TIMER"; s.len = 5;
	} else {
		LM_BUG("trying to raise event for unsupported group %d\n",pg->type);
		return;
	}
	if (evi_param_add_str(list, &pt_ev_type, &s) < 0) {
		LM_ERR("cannot add group type\n");
		goto error;
	}

	if (pg->si_filter==NULL) {
		s.s = "none"; s.len = 4;
	} else {
		s = pg->si_filter->sock_str;
	}
	if (evi_param_add_str(list, &pt_ev_filter, &s) < 0) {
		LM_ERR("cannot add group filter\n");
		goto error;
	}

	if (evi_param_add_int(list, &pt_ev_load, &load) < 0) {
		LM_ERR("cannot add group load\n");
		goto error;
	}

	s.s = scale; s.len = strlen(s.s);
	if (evi_param_add_str(list, &pt_ev_scale, &s) < 0) {
		LM_ERR("cannot add scaling type\n");
		goto error;
	}

	if (evi_param_add_int(list, &pt_ev_p_id, &p_id) < 0) {
		LM_ERR("cannot add process id\n");
		goto error;
	}

	if (evi_param_add_int(list, &pt_ev_pid, &(pt[p_id].pid)) < 0) {
		LM_ERR("cannot add process pid\n");
		goto error;
	}

	if (evi_raise_event(EVI_PROC_AUTO_SCALE_ID, list)) {
		LM_ERR("unable to send auto scaling event\n");
	}
	return;

error:
	evi_free_params(list);
}


static void rescale_group_history(struct process_group *pg, unsigned int idx,
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

		k = k ? (k-1) : (pg->history_size-1) ;
	} while(k!=idx);
}


void do_workers_auto_scaling(void)
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

			/* skip processes:
			 * - not running
			 * - runing, but marked for termination
			 * - not part of the group
			 * - with a different group filter (socket interface) */
			if (!is_process_running(i) || pt[i].flags&OSS_PROC_TO_TERMINATE ||
			pt[i].type != pg->type || pg->si_filter!=pt[i].pg_filter)
				continue;

			load += get_stat_val( pt[i].load_rt );
			last_idx_in_pg = i;
			procs_no++;

		}

		if (!procs_no) {
			LM_BUG("no process beloging to group %d\n", pg->type);
			continue;
		}

		/* set the current value */
		idx = (pg->history_idx+1)%pg->history_size;
		pg->history_map[idx] = (unsigned char) ( load / procs_no );

		LM_DBG("group %d (with %d procs) has average load of %d\n",
			pg->type, procs_no, pg->history_map[idx]);

		/* do the check over the history */
		cnt_over = 0;
		cnt_under = 0;
		k = idx;
		i = 1;
		do {
			if ( pg->history_map[k] > pg->prof->up_threshold &&
			i <= pg->prof->up_cycles_tocheck )
				cnt_over++;
			else if ( pg->history_map[k] < pg->prof->down_threshold &&
			i <= pg->prof->down_cycles_tocheck )
				cnt_under++;

			i++;
			k = k ? (k-1) : (pg->history_size-1) ;
		} while(k!=idx);

		/* decide what to do */
		if ( cnt_over >= pg->prof->up_cycles_needed ) {
			if ( procs_no < pg->prof->max_procs ) {
				LM_NOTICE("score %d/%d -> forking new proc in group %d "
					"(with %d procs)\n", cnt_over, pg->prof->up_cycles_tocheck,
					pg->type, procs_no);
				/* we need to fork one more process here */
				if ( (p_id=pg->fork_func(pg->si_filter))<0 ||
				wait_for_one_child()<0 ) {
					LM_ERR("failed to fork new process for group %d "
						"(current %d procs)\n",pg->type,procs_no);
				} else {
					_pt_raise_event( pg, p_id, pg->history_map[idx] ,"up");
					rescale_group_history( pg, idx, procs_no, +1);
					pg->no_downscale_cycles = pg->prof->down_cycles_delay;
				}
			}
		} else if ( pg->prof->down_cycles_tocheck != 0 &&
		cnt_under == pg->prof->down_cycles_tocheck ) {
			if ( procs_no > pg->prof->min_procs &&
			pg->no_downscale_cycles==0) {
				/* try to estimate the load after downscaling */
				load = 0;
				k = idx;
				i = 0;
				do {
					load += pg->history_map[k];
					k = k ? (k-1) : (pg->history_size-1) ;
					i++;
				} while( k != idx && i <= pg->prof->down_cycles_tocheck );
				load = (load*procs_no) /
					(pg->prof->down_cycles_tocheck * (procs_no-1));
				if ( load < pg->prof->up_threshold ) {
					/* down scale one more process here */
					LM_NOTICE("score %d/%d -> ripping proc %d from group %d "
						"(with %d procs), estimated load -> %d\n", cnt_under,
						pg->prof->down_cycles_tocheck, last_idx_in_pg,
						pg->type, procs_no, load );
					pt[last_idx_in_pg].flags |= OSS_PROC_TO_TERMINATE;
					ipc_send_rpc( last_idx_in_pg, pg->term_func, NULL);
					_pt_raise_event( pg, last_idx_in_pg,
						pg->history_map[idx], "down");
				}
			}
		}

		pg->history_idx++;
		if (pg->no_downscale_cycles) pg->no_downscale_cycles--;
	}
}

