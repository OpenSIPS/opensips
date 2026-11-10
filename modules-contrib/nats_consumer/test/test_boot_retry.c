/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
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
 * The consumer process stays up when no broker answers.  Replaces
 * tests/test_consumer_proc_boot_retry.c (greps for a bare return in the
 * boot wait): a module process that returns takes OpenSIPS down.  The
 * suite runs with no broker; the pool still hands out a connection that
 * reconnects in the background, so the process is in its main loop, not
 * in the boot wait, which runs only when the pool has no connection at
 * all and which this suite cannot reach.
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../../../pt.h"

#include "nc_ut.h"

static int consumer_pid(void)
{
	int i;

	for (i = 0; i < counted_max_processes; i++)
		if (pt[i].pid > 0 && strcmp(pt[i].desc, "NATS consumer") == 0)
			return pt[i].pid;
	return 0;
}

/* Whether `pid` is running: present and not a zombie (an exited child
 * that has not been reaped yet still answers kill(pid, 0)). */
static int running(int pid)
{
	char path[64], buf[256], *state;
	FILE *f;
	size_t n;

	snprintf(path, sizeof path, "/proc/%d/stat", pid);
	f = fopen(path, "r");
	if (!f)
		return 0;
	n = fread(buf, 1, sizeof buf - 1, f);
	fclose(f);
	buf[n] = '\0';
	state = strrchr(buf, ')');   /* "pid (comm) S ..." */
	return state && state[1] == ' ' && state[2] != 'Z' && state[2] != 'X';
}

void nc_ut_boot_retry(void)
{
	int pid = consumer_pid(), i, up = 1;

	ok(pid > 0, "boot_retry: the NATS consumer process was started");
	if (pid <= 0)
		return;
	/* long enough for a process that gives up at once to be gone */
	for (i = 0; i < 20 && up; i++) {
		usleep(100 * 1000);
		up = running(pid);
	}
	ok(up, "boot_retry: with no broker the consumer process stays up");
}
