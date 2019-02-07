/*
 * Process auto-scaling related code
 *
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


#ifndef _PT_SCALING_H
#define _PT_SCALING_H

#include <sys/types.h>
#include <unistd.h>

#include "pt_load.h"
#include "socket_info.h"
#include "ipc.h"



struct scaling_profile {
	/* the name of the profile */
	char *name;

	/* the maximum number of processes to scale to */
	unsigned int max_procs;
	/* the load threshold (in percentages) to trigger up scaling */
	unsigned int up_threshold;
	/* the number of cycles needed to be over the TH in order to up scale */
	unsigned int up_cycles_needed;
	/* the number of cycles to check for spotting the needed ones */
	unsigned int up_cycles_tocheck;

	/* the minimum number of processes to scale (if 0 -> no downscale) */
	unsigned int min_procs;
	/* the load threshold (in percentages) to trigger down scaling */
	unsigned int down_threshold;
	/* the number of cycles needed to be below the TH in order to down scale */
	unsigned int down_cycles_tocheck;
	/* the number of cycles to wait before down scaling (after up or start) */
	unsigned short down_cycles_delay;

	struct scaling_profile *next;
};


int create_auto_scaling_profile( char *name,
	unsigned int max_procs, unsigned int up_threshold,
	unsigned int up_cycles_needed, unsigned int up_cycles_tocheck,
	unsigned int min_procs, unsigned int down_threshold,
	unsigned int down_cycles_tocheck, unsigned short down_cycles_delay);

struct scaling_profile *get_scaling_profile(char *name);


typedef int (fork_new_process_f)(void *);
typedef ipc_rpc_f terminate_process_f;

int create_process_group(enum process_type type,
		struct socket_info *si_filter, struct scaling_profile *prof,
		fork_new_process_f *f1, terminate_process_f *f2);

void do_workers_auto_scaling(void);


#endif
