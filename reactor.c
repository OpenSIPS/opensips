/*
 * Copyright (C) 2014 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2014-08-23  created (bogdan)
 */

#include <sys/time.h>
#include <sys/resource.h>

#include "io_wait.h"
#include "globals.h"

/* one reactor per process variable */
io_wait_h _worker_io;
/* max number of fds per reactor */
unsigned int reactor_size = 0;

#define FD_MEM_PERCENT  10

int init_reactor_size(void)
{
	struct rlimit lim;
	int n, pc;

	n = sizeof(struct fd_map) + sizeof(struct pollfd);

	if (open_files_limit>0) {

		/* the fd limit was explicitly set, so just follow but only warn 
		 * if too much memory is to consumed by reactor */
		pc = 100*n*open_files_limit / pkg_mem_size;
		if (pc>=80) {
			LM_ERR("required memory for a %d files reactor is over 80%% of"
				" the configured pkg mem (%luMb)\n",
				open_files_limit, pkg_mem_size);
			LM_ERR("Please consider increasing the pkg memory or reduce the"
				" limit of open files...Exiting\n");
			return -1;
		} else if (pc>=50) {
			LM_WARN("required memory for a %d files reactor is over 50%% of"
				" the configured pkg mem (%luMb)\n",
				open_files_limit, pkg_mem_size);
			LM_WARN("PKG memory may not be enough at runtime (consider "
				"increasing it), still continuing\n");
		}
		/* seems to have enough mem -> size the reactor based on open files */
		reactor_size = open_files_limit;

	} else {

		/* auto detect the limit of open files */
		if (getrlimit(RLIMIT_NOFILE, &lim)<0){
			LM_ERR("cannot get the maximum number of file descriptors: %s\n",
				strerror(errno));
			return -1;
		}

		/* calculate the size to fit into 10% PKG mem */
		reactor_size = pkg_mem_size * FD_MEM_PERCENT / (100*n);

		if (reactor_size<lim.rlim_cur) {
			LM_WARN("shrinking reactor size from %lu (autodetected via rlimit)"
				" to %d (limited by memory of %d%% from %luMb)\n",
				lim.rlim_cur,reactor_size,FD_MEM_PERCENT,pkg_mem_size);
			LM_WARN("use 'open_files_limit' to enforce other limit or "
				"increase PKG memory\n");
		} else {
			/* enouhg memory, use as limit the fd limit */
			reactor_size = lim.rlim_cur;
		}
	}

	LM_DBG("using reactor size %d\n",reactor_size);

	return 0;
}

