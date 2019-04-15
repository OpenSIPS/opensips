/*
 * Flatstore module interface
 *
 * Copyright (C) 2004 FhG Fokus
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2003-03-11  updated to the new module exports interface (andrei)
 *  2003-03-16  flags export parameter added (janakj)
 */

#ifndef FLATSTORE_MOD_H
#define FLATSTORE_MOD_H

#include <time.h>

#include "../../pvar.h"

/*
 * Process number used in filenames
 */
extern int flat_pid;


/*
 * Should we flush after each write to the database ?
 */
extern int flat_flush;


/*
 * Delmiter delimiting columns
 */
extern char* flat_delimiter;


/*
 * The timestamp of log rotation request from
 * the FIFO interface
 */
extern time_t* flat_rotate;


/*
 * Local timestamp marking the time of the
 * last log rotation in the process
 */
extern time_t local_timestamp;


/*
 * Default suffix for logs
 */
#define FILE_SUFFIX ".log"
#define FILE_SUFFIX_LEN (sizeof(FILE_SUFFIX)-1)

/*
 * Suffix and prefix for logs
 */
extern pv_elem_t *flat_suffix;
extern pv_elem_t *flat_prefix;

extern int flat_single_file;


#endif /* FLATSTORE_MOD_H */
