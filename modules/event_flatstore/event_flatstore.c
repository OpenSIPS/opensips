/*
 * Copyright (C) 2011 OpenSIPS Project
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2015-06-20  created  
 */


#include "event_flatstore.h"

#include "../../sr_module.h"
#include "../../evi/evi_transport.h"
#include "../../mem/shm_mem.h"

static int mod_init(void);
static void destroy(void);
static int child_init(int rank);

static struct mi_root* mi_rotate(struct mi_root* root, void *param);

static int flat_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
static evi_reply_sock* flat_parse(str socket);
static int flat_raise(struct sip_msg *msg, str* ev_name,
					 evi_reply_sock *sock, evi_params_t * params);
static void flat_free(evi_reply_sock *sock);
static str flat_print(evi_reply_sock *sock);

unsigned int *opened_fds;
unsigned int *rotate_version;

struct flat_socket **list_files;
struct deleted **list_deleted_files;


static mi_export_t mi_cmds[] = {
	{ "rotate","make processes ",mi_rotate,MI_NO_INPUT_FLAG,0,0},
	{0,0,0,0,0,0}
};

struct module_exports exports= {
	"event_flatstore",			/* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	0,							/* exported functions */
	0,							/* exported async functions */
	0,							/* exported parameters */
	0,							/* exported statistics */
	mi_cmds,							/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,						/* extra processes */
	mod_init,					/* module initialization function */
	0,							/* response handling function */
	destroy,					/* destroy function */
	child_init					/* per-child init function */
};

static evi_export_t trans_export_flat = {
	FLAT_STR,					/* transport module name */
	flat_raise,					/* raise function */
	flat_parse,					/* parse function */
	flat_match,					/* sockets match function */
	flat_free,					/* free function */
	flat_print,					/* print socket */
	FLAT_FLAG					/* flags */
};


static int mod_init(void) {
	LM_NOTICE("initializing module ...\n");

	if (register_event_mod(&trans_export_flat)) {
		LM_ERR("cannot register transport functions for SCRIPTROUTE\n");
		return -1;
	}

	opened_fds = NULL;
    rotate_version = NULL;

	list_files =  shm_malloc(sizeof(struct flat_socket*));

	if (!list_files) {
		LM_ERR("no more memory for list pointer\n");
		return -1;
	}

	list_deleted_files = shm_malloc(sizeof(struct deleted*));

	if (!list_deleted_files) {
		LM_ERR("no more memory for list pointer\n");
		return -1;
	}

	return 0;
}

static void destroy(void){
	LM_NOTICE("destroying module ...\n");
}
static int child_init(int rank){
	return 0;
}

static struct mi_root* mi_rotate(struct mi_root* root, void *param){
	return 0;
}

static int flat_match(evi_reply_sock *sock1, evi_reply_sock *sock2){
	return 0;
}
static evi_reply_sock* flat_parse(str socket){
	return 0;
}
static int flat_raise(struct sip_msg *msg, str* ev_name,
					 evi_reply_sock *sock, evi_params_t * params){
	return 0;
}

static void flat_free(evi_reply_sock *sock){
	return ;
}
static str flat_print(evi_reply_sock *sock){
	str ret = {0,0};
	return ret;
}