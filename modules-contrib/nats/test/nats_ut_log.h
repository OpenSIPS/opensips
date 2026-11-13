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
 * Log capture for the unit tests of the NATS modules: what the code under
 * test logs -- through LM_*(), or with write(2) from a libnats thread
 * callback -- goes to fd 2; for the length of a scenario fd 2 is a file
 * the test reads back.
 *
 * Static functions: include it from one file of a suite.
 */

#ifndef NATS_UT_LOG_H
#define NATS_UT_LOG_H

#include <tap.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "../../../dprint.h"

static int ut_log_fd = -1;        /* the capture file */
static int ut_log_saved_stderr = -1;
static int ut_log_saved_level;
static char ut_log_buf[32768];

/* fd 2 into a file; log level @level until ut_log_stop() */
static void ut_log_start(int level)
{
	char path[] = "/tmp/nats_ut_logXXXXXX";

	fflush(stderr);
	ut_log_fd = mkstemp(path);
	if (ut_log_fd < 0)
		BAIL_OUT("log capture: mkstemp failed");
	unlink(path);
	/* appended, so the capture can be emptied under the writer */
	if (fcntl(ut_log_fd, F_SETFL, O_APPEND) < 0)
		BAIL_OUT("log capture: O_APPEND failed");
	ut_log_saved_stderr = dup(STDERR_FILENO);
	if (ut_log_saved_stderr < 0 || dup2(ut_log_fd, STDERR_FILENO) < 0)
		BAIL_OUT("log capture: redirect failed");
	ut_log_saved_level = *log_level;
	*log_level = level;
}

static void ut_log_stop(void)
{
	fflush(stderr);
	*log_level = ut_log_saved_level;
	dup2(ut_log_saved_stderr, STDERR_FILENO);
	close(ut_log_saved_stderr);
	close(ut_log_fd);
	ut_log_saved_stderr = ut_log_fd = -1;
}

/* the raw bytes captured so far: their number, and a copy in @buf */
static size_t ut_log_raw(char *buf, size_t size)
{
	ssize_t n;

	fflush(stderr);
	n = pread(ut_log_fd, buf, size, 0);
	return n > 0 ? (size_t)n : 0;
}

/* everything captured so far, as a string */
static const char *ut_log(void)
{
	size_t n = ut_log_raw(ut_log_buf, sizeof(ut_log_buf) - 1);

	ut_log_buf[n] = '\0';
	return ut_log_buf;
}

static void ut_log_clear(void)
{
	fflush(stderr);
	if (ftruncate(ut_log_fd, 0) < 0)
		BAIL_OUT("log capture: truncate failed");
}

#endif /* NATS_UT_LOG_H */
