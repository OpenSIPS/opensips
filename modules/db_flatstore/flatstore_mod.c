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

#include "../../sr_module.h"
#include "../../mem/shm_mem.h"
#include "../../db/db.h"
#include "flatstore.h"
#include "flat_mi.h"
#include "flatstore_mod.h"



static int child_init(int rank);

static int mod_init(void);

static void mod_destroy(void);

int db_flat_bind_api(const str* mod, db_func_t *dbb);

/*
 * Process number used in filenames
 */
int flat_pid;

/*
 * Should we flush after each write to the database ?
 */
int flat_flush = 1;

/*
 * Should we store all accounting into a single file ?
 */
int flat_single_file = 0;


/*
 * Delimiter delimiting columns
 */
char* flat_delimiter = "|";

/*
 * suffix and prefix of the logging file
 * can be a formatted string
 */
char * flat_suffix_s = FILE_SUFFIX;
gparam_p flat_suffix;
char * flat_prefix_s = NULL;
gparam_p flat_prefix;

/*
 * Timestamp of the last log rotation request from
 * the FIFO interface
 */
time_t* flat_rotate;

time_t local_timestamp;

/*
 * Flatstore database module interface
 */
static cmd_export_t cmds[] = {
	{"db_bind_api",    (cmd_function)db_flat_bind_api,      0, 0, 0, 0},
	{0, 0, 0, 0, 0, 0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"flush", INT_PARAM, &flat_flush},
	{"delimiter", STR_PARAM, &flat_delimiter},
	{"suffix", STR_PARAM, &flat_suffix_s},
	{"prefix", STR_PARAM, &flat_prefix_s},
	{"single_file", INT_PARAM, &flat_single_file},
	{0, 0, 0}
};


#define MI_FLAT_HELP "Params: none ; Rotates the logging file."
/*
 * Exported parameters
 */
static mi_export_t mi_cmds[] = {
	{ MI_FLAT_ROTATE, MI_FLAT_HELP, mi_flat_rotate_cmd,
		MI_NO_INPUT_FLAG, 0,  0 },
	{ 0, 0, 0, 0, 0, 0}
};

struct module_exports exports = {
	"db_flatstore",
	MOD_TYPE_SQLDB,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	cmds,
	0,
	params,      /*  module parameters */
	0,           /* exported statistics */
	mi_cmds,     /* exported MI functions */
	0,           /* exported pseudo-variables */
	0,           /* extra processes */
	mod_init,    /* module initialization function */
	0,           /* response function*/
	mod_destroy, /* destroy function */
	child_init   /* per-child init function */
};


static int mod_init(void)
{
	if (strlen(flat_delimiter) != 1) {
		LM_ERR("delimiter has to be exactly one character\n");
		return -1;
	}

	flat_rotate = (time_t*)shm_malloc(sizeof(time_t));
	if (!flat_rotate) {
		LM_ERR("no shared memory left\n");
		return -1;
	}

	*flat_rotate = time(0);
	local_timestamp = *flat_rotate;

	/* parse prefix and suffix */
	if (flat_suffix_s && strlen(flat_suffix_s)) {
		if (fixup_spve((void **)&flat_suffix_s)) {
			LM_ERR("cannot parse log suffix\n");
			return -1;
		}
		flat_suffix = (gparam_p)flat_suffix_s;
	} else {
		flat_suffix = 0;
	}
	if (flat_prefix_s && strlen(flat_prefix_s)) {
		if (fixup_spve((void **)&flat_prefix_s)) {
			LM_ERR("cannot parse log prefix\n");
			return -1;
		}
		flat_prefix = (gparam_p)flat_prefix_s;
	} else {
		flat_prefix = 0;
	}

	return 0;
}


static void mod_destroy(void)
{
	if (flat_rotate) shm_free(flat_rotate);
}


static int child_init(int rank)
{
	if (rank <= 0) {
		flat_pid = - rank;
	} else {
		flat_pid = rank - PROC_TCP_MAIN;
	}
	return 0;
}

int db_flat_bind_api(const str* mod, db_func_t *dbb)
{
	if(dbb==NULL)
		return -1;

	memset(dbb, 0, sizeof(db_func_t));

	dbb->use_table        = flat_use_table;
	dbb->init             = flat_db_init;
	dbb->close            = flat_db_close;
	dbb->insert           = flat_db_insert;

	return 0;
}

