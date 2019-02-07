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

typedef int (fork_new_process_f)(void *);
typedef ipc_rpc_f terminate_process_f;

int create_process_group(enum process_type type,
		struct socket_info *si_filter,
		unsigned int min_procs, unsigned int max_procs,
		fork_new_process_f *f1, terminate_process_f *f2);

void check_and_adjust_number_of_workers(void);


#endif
