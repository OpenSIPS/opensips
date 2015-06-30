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


#include <fcntl.h>
#include <unistd.h>

#include "event_flatstore.h"
#include "../../mem/mem.h"
#include "../../locking.h"
#include "../../sr_module.h"
#include "../../evi/evi_transport.h"
#include "../../mem/shm_mem.h"
#include "../../locking.h"
#include "../../ut.h"


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

static void verify_delete(void);

int *opened_fds;
int *rotate_version;
int buff_convert_len;
int cap_params;

char *buff;
static struct iovec *io_param ;


struct flat_socket **list_files;
struct deleted **list_deleted_files;

static gen_lock_t *global_lock;

static int initial_capacity;

static mi_export_t mi_cmds[] = {
	{ "rotate","make processes ",mi_rotate,MI_NO_INPUT_FLAG,0,0},
	{0,0,0,0,0,0}
};

static param_export_t mod_params[] = {
	{"max_open_sockets",INT_PARAM, &initial_capacity},
	{0,0,0}
};

struct module_exports exports= {
	"event_flatstore",			/* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	0,							/* exported functions */
	0,							/* exported async functions */
	mod_params,							/* exported parameters */
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

/* initialize function */
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
	io_param = NULL;
	cap_params = 10;
        if ( initial_capacity <= 0 || initial_capacity > 65535) {
		LM_WARN("wrong maximum open sockets according to the modparam configuration\n");
		initial_capacity = 100;
	}

	if (!list_files) {
		LM_ERR("no more memory for list pointer\n");
		return -1;
	}

	list_deleted_files = shm_malloc(sizeof(struct deleted*));

	if (!list_deleted_files) {
		LM_ERR("no more memory for list pointer\n");
		return -1;
	}
	global_lock = lock_alloc();
	global_lock = lock_init(global_lock);
        
        /*
        opened_fds = pkg_malloc(initial_capacity * sizeof(int));
        rotate_version = pkg_malloc(initial_capacity * sizeof(int));
        */	
	
        return 0;
}

/* free allocated memory */
static void destroy(void){
	LM_NOTICE("destroying module ...\n");
        /* lock destroy and deallocate */
	lock_destroy(global_lock);
	lock_dealloc(global_lock);
        /* free opened file descriptors list */
        pkg_free(opened_fds);
        /* free rotate version list */
        pkg_free(rotate_version);
        /* free io_params structure used for raise event */
        pkg_free(io_param);
        /* free buffer used for raise event */
        pkg_free(buff);
        /* free file descriptors list from shared memory */
        struct flat_socket* list_header = *list_files;
        while(list_header!=NULL){
            struct flat_socket* tmp = list_header;
            list_header = list_header->next;
            shm_free(tmp->path.s);
            shm_free(tmp);
        }
        shm_free(list_files);
        /* free deleted files from shared memory */
        shm_free(list_deleted_files);
}

/* it does not do nothing */
static int child_init(int rank){
	return 0;
}

/* compare two str values */
static int str_cmp(str a , str b){
	if(a.len == b.len && strncmp(a.s,b.s,a.len)==0)
		return 1;
	return 0;
}

/* search for a file descriptor using the file's path */
static struct flat_socket *search_for_fd(str value){
	struct flat_socket *list = *list_files;
	while(list!=NULL){
		if(str_cmp(list->path, value)){
			/* file descriptor found */
			return list;
		}
		list = list->next;
	}
	/* file descriptor not found */
	return NULL;
}


static struct mi_root* mi_rotate(struct mi_root* root, void *param){

	struct mi_root *return_root = init_mi_tree( 200, MI_SSTR(MI_OK));
	
	/* sanity checks */
	if (!return_root) {
	LM_ERR("failed initializing MI return root tree\n");
	return NULL;
	}
	if(!root){
		LM_ERR("empty root tree\n");
	return NULL;
	}
	if(root->node.value.s == NULL || root->node.value.len == 0){
		LM_ERR("Missing value\n");
	return NULL;
	}
	
	/* search for a flat_socket structure that contains the file descriptor
	 * we need to rotate
	 */
	lock_get(global_lock);
	struct flat_socket *found_fd = search_for_fd(root->node.value);
	
	if(found_fd == NULL){
		LM_ERR("Bad file descriptor\n");
		lock_release(global_lock);
	return NULL;
	}
	
	found_fd->rotate_version++;
	lock_release(global_lock);
	
	
	/* return a mi_root structure with a success return code*/
	return return_root;
}

static int flat_match(evi_reply_sock *sock1, evi_reply_sock *sock2){
	struct flat_socket *fs1;
	struct flat_socket *fs2;
	   
	if(sock1 != NULL && sock2 != NULL
				&& sock1->params != NULL && sock2->params != NULL){
		
		fs1 = (struct flat_socket *) sock1->params;
		fs2 = (struct flat_socket *) sock2->params;
		/* if the path is equal then the file descriptor structures are equal*/
		return str_cmp(fs1->path, fs2->path);
	}
	/* not equal */
	return 0;
}

static void insert_in_list(struct flat_socket *entry){
	struct flat_socket *head = *list_files, *aux, *parent = NULL;
	int expected = CAPACITY - 1; 

	lock_get(global_lock);
	if (head == NULL) {
		entry->file_index_process = 0;
		*list_files = entry;
		entry->prev = NULL;
		entry->next = NULL;
		lock_release(global_lock);
		return;
	}

	if (head->file_index_process < CAPACITY - 1) {
		entry->file_index_process = head->file_index_process + 1;
		entry->prev = NULL;
		entry->next = head;
		head->prev = entry;
		*list_files = entry;
		lock_release(global_lock);
		return;
	}

	for (aux = head; aux != NULL; aux = aux->next, expected--) {
		if(aux->file_index_process != expected){
			entry->file_index_process = expected;
			entry->prev = aux->prev;
			entry->next = aux;
			aux->prev =entry;
			entry->prev->next = entry;
			lock_release(global_lock);
			return;
		}
		parent = aux;
	}

	if(expected != 0){
		entry->file_index_process = expected;
		entry->prev = parent;
		entry->next = NULL;
		parent->next = entry;
		lock_release(global_lock);
		return;
	}


	LM_ERR("no more free sockets\n");		

}

static evi_reply_sock* flat_parse(str socket){
	evi_reply_sock *sock;
	struct flat_socket* entry;

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
	memcpy(entry->path.s, socket.s, socket.len);
	entry->path.s[socket.len] = '\0';

	insert_in_list(entry);
	
	entry->rotate_version = 0;
	entry->counter_open = 0;



	sock = (evi_reply_sock *)((char*)(entry + 1) + socket.len + 1);
	memset(sock, 0, sizeof(evi_reply_sock));
	sock->address.s = (char *)(entry + 1);
	sock->address.len = socket.len + 1;
	sock->params = entry;

	sock->flags |= EVI_PARAMS;
	sock->flags |= EVI_ADDRESS;

	return 0;
}

/*  check if the local 'version' of the file descriptor asociated with entry fs
	is different from the global version, if it is different reopen the file
*/
static void rotating(struct flat_socket *fs){
	int index = fs->file_index_process;
	int rc;

	lock_get(global_lock);
	if(rotate_version[index] != fs->rotate_version && opened_fds[index] != -1){
		
	   /* update version */
		rotate_version[index] = fs->rotate_version;
		lock_release(global_lock);

		/* rotate */
		rc = close(opened_fds[index]);
		if(rc < 0){
			LM_ERR("Closing socket error\n");
			return;
		}
		
		opened_fds[index] = open(fs->path.s,O_RDWR | O_APPEND | O_CREAT, 0644);
		if(opened_fds[index] < 0){
			LM_ERR("Opening socket error\n");
			return;
		}
		
	} else {
		lock_release(global_lock);
	}
}

static int flat_raise(struct sip_msg *msg, str* ev_name,
					 evi_reply_sock *sock, evi_params_t *params){

	int idx = 0, offset_buff = 0, tmp, 
		required_length = 0, nwritten;
	char delim = ',', points = ':', equals = '=';
	char delim_len = 1;
	evi_param_p param;
	struct flat_socket *entry = (struct flat_socket*) sock->params;
	int index = entry->file_index_process;

	verify_delete();

	if(opened_fds[index] == -1)
		return -1;

	rotating(entry);

	if(!sock || !(sock->params)){
		LM_ERR("invalid socket specification\n");
		return -1;
	}

	
	if(io_param == NULL)
		io_param = pkg_malloc(cap_params * sizeof(struct iovec));

	if(ev_name && ev_name->s){
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

		memset(buff, 0, buff_convert_len);
		
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


	do {
		nwritten = writev(opened_fds[entry->file_index_process], io_param, idx);
	} while (nwritten < 0 && errno == EINTR);

	

	if(nwritten < 0){
		LM_ERR("cannot write to socket\n");
		return -1;
	}

	return 0;
}


static void flat_free(evi_reply_sock *sock) {
	struct deleted *head = *list_deleted_files;
	struct deleted *new;

	if(sock->params == NULL) {
		LM_ERR("socket not found\n");
	}

	new = shm_malloc(sizeof(struct deleted));
	new->socket = (struct flat_socket*)sock->params;
	new->next = NULL;	

	lock_get(global_lock);

	if(head	!= NULL)
		new->next = head;

	head = new;

	lock_release(global_lock);
        
        verify_delete();

}

static str flat_print(evi_reply_sock *sock){

	struct flat_socket * fs = (struct flat_socket *)sock->params;
	return fs->path;
}

static void verify_delete(void) {
	struct deleted *head = *list_deleted_files;
	struct deleted *aux, *prev, *tmp;

	if (head == NULL && opened_fds == NULL)
		return;

	lock_get(global_lock);

	/* close fd if necessary */
	aux = head;
	prev = NULL;
	while (aux != NULL) {
		if(opened_fds[aux->socket->file_index_process] != -1) {
			close(opened_fds[aux->socket->file_index_process]);
			aux->socket->counter_open--;
			opened_fds[aux->socket->file_index_process] = -1;
		}

		/* free file from lists if all other processes closed it */
		if(aux->socket->counter_open == 0) {
			aux->socket->prev->next = aux->socket->next;
			aux->socket->next->prev = aux->socket->prev;
			shm_free(aux->socket->path.s);
			shm_free(aux->socket);

			if(prev	!= NULL)
				prev->next = aux->next;
			tmp = aux;
			aux = aux->next;
			shm_free(tmp);
		} else {
			prev = aux;
			aux = aux->next;
		}
	}

	lock_release(global_lock);
}