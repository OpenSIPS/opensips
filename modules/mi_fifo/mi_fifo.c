/*
 * Copyright (C) 2006 Voice Sistem SRL
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
 * History:
 * ---------
 *  2006-09-25  first version (bogdan)
 */



#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"
#include "mi_fifo.h"
#include "mi_parser.h"
#include "mi_writer.h"
#include "fifo_fnc.h"

static int mi_mod_init(void);
static int mi_child_init(int rank);
static void fifo_process(int rank);
static int mi_destroy(void);

/* FIFO server vars */
/* FIFO name */
static char *mi_fifo = 0;
/* dir where reply fifos are allowed */
static char *mi_fifo_reply_dir = DEFAULT_MI_REPLY_DIR;
static char *mi_reply_indent = DEFAULT_MI_REPLY_IDENT;
static int  mi_fifo_uid = -1;
static char *mi_fifo_uid_s = 0;
static int  mi_fifo_gid = -1;
static char *mi_fifo_gid_s = 0;
static int  mi_fifo_mode = S_IRUSR| S_IWUSR| S_IRGRP| S_IWGRP; /* rw-rw---- */
static int  read_buf_size = MAX_MI_FIFO_READ;



static param_export_t mi_params[] = {
	{"fifo_name",        STR_PARAM, &mi_fifo},
	{"fifo_mode",        INT_PARAM, &mi_fifo_mode},
	{"fifo_group",       STR_PARAM, &mi_fifo_gid_s},
	{"fifo_group",       INT_PARAM, &mi_fifo_gid},
	{"fifo_user",        STR_PARAM, &mi_fifo_uid_s},
	{"fifo_user",        INT_PARAM, &mi_fifo_uid},
	{"reply_dir",        STR_PARAM, &mi_fifo_reply_dir},
	{"reply_indent",     STR_PARAM, &mi_reply_indent},
	{0,0,0}
};


static proc_export_t mi_procs[] = {
	{"MI FIFO",  0,  0,  fifo_process,  1 , PROC_FLAG_INITCHILD },
	{0,0,0,0,0,0}
};


struct module_exports exports = {
	"mi_fifo",                     /* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,               /* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	0,                             /* exported functions */
	0,                             /* exported async functions */
	mi_params,                     /* exported parameters */
	0,                             /* exported statistics */
	0,                             /* exported MI functions */
	0,                             /* exported pseudo-variables */
	mi_procs,                      /* extra processes */
	mi_mod_init,                   /* module initialization function */
	(response_function) 0,         /* response handling function */
	(destroy_function) mi_destroy, /* destroy function */
	mi_child_init                  /* per-child init function */
};



static int mi_mod_init(void)
{
	int n;
	struct stat filestat;

	/* checking the mi_fifo module param */
	if (mi_fifo==NULL || *mi_fifo == 0) {
		LM_ERR("no fifo configured\n");
		return -1;
	}

	LM_DBG("testing fifo existence ...\n");
	n=stat(mi_fifo, &filestat);
	if (n==0){
		/* FIFO exist, delete it (safer) */
		if (unlink(mi_fifo)<0){
			LM_ERR("cannot delete old fifo (%s): %s\n",
				mi_fifo, strerror(errno));
			return -1;
		}
	}else if (n<0 && errno!=ENOENT){
		LM_ERR("FIFO stat failed: %s\n", strerror(errno));
		return -1;
	}

	/* checking the mi_fifo_reply_dir param */
	if(!mi_fifo_reply_dir || *mi_fifo_reply_dir == 0){
		LM_ERR("mi_fifo_reply_dir parameter is empty\n");
		return -1;
	}

	n = stat(mi_fifo_reply_dir, &filestat);
	if(n < 0){
		LM_ERR("directory stat failed: %s\n", strerror(errno));
		return -1;
	}

	if(S_ISDIR(filestat.st_mode) == 0){
		LM_ERR("mi_fifo_reply_dir parameter is not a directory\n");
		return -1;
	}

	/* check mi_fifo_mode */
	if(!mi_fifo_mode){
		LM_WARN("cannot specify mi_fifo_mode = 0, forcing it to rw-------\n");
		mi_fifo_mode = S_IRUSR| S_IWUSR;
	}

	if (mi_fifo_uid_s){
		if (user2uid(&mi_fifo_uid, &mi_fifo_gid, mi_fifo_uid_s)<0){
			LM_ERR("bad user name %s\n", mi_fifo_uid_s);
			return -1;
		}
	}

	if (mi_fifo_gid_s){
		if (group2gid(&mi_fifo_gid, mi_fifo_gid_s)<0){
			LM_ERR("bad group name %s\n", mi_fifo_gid_s);
			return -1;
		}
	}

	return 0;
}


static int mi_child_init(int rank)
{
	if (rank>PROC_MAIN ) {
		if ( mi_writer_init(read_buf_size, mi_reply_indent)!=0 ) {
			LM_CRIT("failed to init the reply writer\n");
			return -1;
		}
	}

	return 0;
}


static void fifo_process(int rank)
{
	FILE *fifo_stream;

	LM_DBG("new process with pid = %d created\n",getpid());

	fifo_stream = mi_init_fifo_server( mi_fifo, mi_fifo_mode,
		mi_fifo_uid, mi_fifo_gid, mi_fifo_reply_dir);
	if ( fifo_stream==NULL ) {
		LM_CRIT("The function mi_init_fifo_server returned with error!!!\n");
		exit(-1);
	}

	if( init_mi_child()!=0) {
		LM_CRIT("faild to init the mi process\n");
		exit(-1);
	}

	if ( mi_parser_init(read_buf_size)!=0 ) {
		LM_CRIT("failed to init the command parser\n");
		exit(-1);
	}

	if ( mi_writer_init(read_buf_size, mi_reply_indent)!=0 ) {
		LM_CRIT("failed to init the reply writer\n");
		exit(-1);
	}

	mi_fifo_server( fifo_stream );

	LM_CRIT("the function mi_fifo_server returned with error!!!\n");
	exit(-1);
}


static int mi_destroy(void)
{
	int n;
	struct stat filestat;

	/* destroying the fifo file */
	n=stat(mi_fifo, &filestat);
	if (n==0){
		/* FIFO exist, delete it (safer) */
		if (unlink(mi_fifo)<0){
			LM_ERR("cannot delete the fifo (%s): %s\n",
				mi_fifo, strerror(errno));
			goto error;
		}
	} else if (n<0 && errno!=ENOENT) {
		LM_ERR("FIFO stat failed: %s\n", strerror(errno));
		goto error;
	}

	return 0;
error:
	return -1;
}

