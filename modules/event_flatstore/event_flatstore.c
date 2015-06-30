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
int buff_convert_len;

char *buff;

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
	*list_files = NULL;
	buff = NULL;
	buff_convert_len = 0;

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

static void insert(struct flat_socket *entry){
	struct flat_socket *head = *list_files, *aux, *parent = NULL;
	int expected = CAPACITY - 1; 

	lock_get(gen_lock);
	if (head == NULL) {
		entry->file_index_process = 0;
		*list_files = entry;
		entry->prev = NULL;
		entry->next = NULL;
		lock_release(gen_lock);
		return;
	}

	if (head->file_index_process < CAPACITY - 1) {
		entry->file_index_process = head->file_index_process + 1;
		entry->prev = NULL;
		entry->next = head;
		head->prev = entry;
		*list_files = entry;
		lock_release(gen_lock);
		return;
	}

	for (aux = head; aux != NULL; aux = aux->next, expected--) {
		if(aux->file_index_process != expected){
			entry->file_index_process = expected;
			entry->prev = aux->prev;
			entry->next = aux;
			aux->prev =entry;
			entr->prev->next = entry;
			lock_release(gen_lock);
			return;
		}
		parent = aux;
	}

	if(expected != 0){
		entry->file_index_process = expected;
		entry->prev = parent;
		entry->next = NULL;
		parent->next = entry;
		lock_release(gen_lock);
		return;
	}


	LM_ERR("no more free sockets\n");		

}

static evi_reply_sock* flat_parse(str socket){
	evi_reply_sock *sock;
	struct flat_socket* entry;
	int full_vec = 0;

	if(!socket.s || !socket.len){
		LM_ERR("no socket specified\n");
		return NULL;
	}

	entry = shm_malloc(sizeof(struct flat_socket) + socket.len + 1 + sizeof(evi_reply_sock));
	if (!entry){
		LM_ERR("not enough shared memory\n");
		return NULL;
	}
	entry->path.s = (char *)(entry + 1);
	entry->path.len = socket.len + 1;
	memcpy(entry->address.s, socket.s, socket.len);
	entry->address.s[socket.len] = '\0';

	insert_in_list(entry);
	
	entry->rotate_version = 0;
	entry->counter_version = 0;



	sock = (evi_reply_sock *)((char*)(entry + 1) + socket.len + 1);
	memset(sock, 0, sizeof(evi_reply_sock));
	sock->address.s = (char *)(entry + 1);
	sock->address.len = socket.len + 1;
	sock->params = entry;

	sock->flags |= EVI_PARAMS;
	sock->flags |= EVI_ADDRESS;

	return 0;
}


static int flat_raise(struct sip_msg *msg, str* ev_name,
					 evi_reply_sock *sock, evi_params_t *params){

	int SIZE = 1024, cap_params = 10, idx = 0, offset_buff = 0, tmp, 
		required_length, nwritten;
	char delim = ',', points = ':', equals = '=';
	char delim_len = 1;
	struct iovec *io_param;
	evi_param_p param;
	struct flat_socket *entry = (struct flat_socket*) sock->param;

	//check version
	//check deleted

	if(!sock || !(sock->params)){
		LM_ERR("invalid socket specification\n");
		return -1;
	}

	
	
	io_param = pkg_malloc(cap_params * sizeof(struct iovec));

	if(ev_name && ev_name.s){
		io_param[idx].iov_base = ev_name->s;
		io_param[idx].iov_len = ev_name->len;
		idx++;
		io_param[idx].iov_base = &points;
		io_param[idx].iov_len = delim_len;
		idx++;
	}



	if(params){
		for (param = params->first; param; param = param->next) 
			if (param->flags & EVI_INT_VAL){
				required_length += INT2STR_MAX_LEN;
			}

		if(buff == NULL || required_length > buff_convert_len){
			buff = pkg_realloc(buff, required_length * sizeof(char) + 1);
			buff_convert_len = required_length;
		}

		memset(buff, 0, SIZE);
		
		for (param = params->first; param; param = param->next) {

			if(idx + 5 > cap_params){
				pkg_realloc(io_param, cap_params * 2 * sizeof(struct iovec));
				cap_params *= 2;
			}

			if(param->name.len && param->name.s){
				io_param[idx].iov_base = param->name.s;
				io_param[idx].iov_len = param->name.len;
				idx++;
				io_param[idx].iov_base = &equals;
				io_param[idx].iov_len = delim_len;
				idx++;
			}

			if (param->flags & EVI_INT_VAL) {
				sprintf(buff + offset_buff, "%d,", param->val.n);
				io_param[idx].iov_base = buff + offset_buff;
				tmp = strlen(buff + offset_buff);
				io_param[idx].iov_len = tmp;
				offset_buff += tmp;
			} else if ((param->flags & EVI_STR_VAL) && param->val.s.len && param->val.s.s) {
				io_param[idx].iov_base = param->val.s.s;
				io_param[idx].iov_len = param->val.s.len;
				idx++;
				io_param[idx].iov_base = &delim;
				io_param[idx].iov_len = delim_len;
				idx++;
			}
		}
	}

	nwritten = writev(opened_fds[entry->file_index_process], iov, 2);

	if(nwritten < 0){
		LM_ERR("cannot write to socket\n");
		return -1;
	}

	return 0;
	
}

static void flat_free(evi_reply_sock *sock){
	return ;
}
static str flat_print(evi_reply_sock *sock){
	str ret = {0,0};
	return ret;
}