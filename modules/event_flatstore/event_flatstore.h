/*
 * Copyright (C) 2015 OpenSIPS Project
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
 *  2015-06-20  created  by Ionel Cerghit, Robert-Vladut Patrascu, Marius Cristian Eseanu
 */

#ifndef _EV_FLAT_H_
#define _EV_FLAT_H_

#include "../../str.h"

#define FLAT_NAME	"flatstore"
#define FLAT_STR		{ FLAT_NAME, sizeof(FLAT_NAME) - 1}
#define FLAT_FLAG (1<<25)

#define FLAT_DEFAULT_MAX_FD 100

#define ROTATE_REASON_COUNT  "count"
#define ROTATE_REASON_SIZE   "size"
#define ROTATE_REASON_PERIOD "period"
#define ROTATE_REASON_MI     "mi"

struct flat_file {
	str path; // original path from module config (may include $var(...) placeholders)
	char *pathname; // resolved absolute path after variable expansion
	char *old_pathname; // previous pathname kept between rotations (used in ROTATION events)
	unsigned long record_count;
	unsigned long bytes_written;
	unsigned int file_index_process;
	unsigned int counter_open;
	unsigned int rotate_version;
	unsigned int flat_socket_ref;
	struct flat_file *next;
	struct flat_file *prev;
};

struct flat_socket {
	struct flat_file *file;
	struct flat_socket *next;
};

struct flat_delete {
	struct flat_file *file;
	struct flat_delete *next;
};

#endif
