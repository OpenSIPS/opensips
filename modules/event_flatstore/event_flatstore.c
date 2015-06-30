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

static gen_lock_t *global_lock;

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
		global_lock = lock_alloc();
		global_lock = lock_init(global_lock);
		
	return 0;
}

static void destroy(void){
	LM_NOTICE("destroying module ...\n");
}
static int child_init(int rank){
	return 0;
}

/* compare two str values */
static int str_cmp(str a , str b){
	if(strcmp(a.s,b.s)==0 && a.len == b.len)
		return 1;
	return 0;
}

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
	/* updating the rotate version */
	/*unsigned int index = found_fd->file_index_process;
	if(found_fd->rotate_version != rotate_version[index]){
		rotate_version[index] = found_fd->rotate_version; 
	}else{
		found_fd->rotate_version++;
		rotate_version[index]++;
	}
	
	/* verify that the socket is opened */
	/*if(opened_fds[index]==-1){
		LM_ERR("Socket not opened\n");
	return NULL;
	}
	
	
	*/
	
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
static evi_reply_sock* flat_parse(str socket){
	return 0;
}

static void rotating(struct flat_socket *fs){
   int index = fs->file_index_process;
   int rc;
   
   if(rotate_version[index] != fs->rotate_version){
		
	   /* update version */
		rotate_version[index] = fs->rotate_version;
		
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
		
   }
}

static int flat_raise(struct sip_msg *msg, str* ev_name,
					 evi_reply_sock *sock, evi_params_t * params){
	
	flat_iov = pkg_malloc(IOV_LEN * sizeof(struct iovec));
	struct flat_socket *fs = (struct flat_socket *)sock->params;
	int index = fs->file_index_process;
	int rc;
	rotating(fs);
	
	int fd = opened_fds[index];
	if(fd == -1){
		LM_ERR("Bad file descriptor\n");
		return -1;
	}
	//flat_iov = pkg_malloc(100 * sizoef(struct iovec));
	char buffer[BUF_LEN];
	str delim={",",1};
	
	int cnt = 0;
	int max_len = IOV_LEN;
	
	flat_iov[cnt].iov_base= ev_name->s;
	flat_iov[cnt].iov_len= ev_name->len;
	cnt++;
	//strncat(buffer,ev_name->s,ev_name->len);
	
	//write(fd, ev_name->s, ev_name->len);
	//writev()
	
	evi_param_p param = params->first;
 
	if(params == NULL){
		while((rc = writev(fd, flat_iov, cnt))>0);
		if(rc == -1){
			LM_ERR("write error\n");
			return -1;
		}
		return 0;
	}
	
	
	
	
	do{
		if(cnt + 1 > max_len){
			flat_iov = pkg_realloc(flat_iov,max_len * 2);
			max_len = max_len * 2;
		}
		
		flat_iov[cnt].iov_base= delim.s;
		flat_iov[cnt].iov_len= delim.len;
		cnt++;
		
		/* de gandit */
		if(param->flags==EVI_INT_VAL){            
			int len = strlen(buffer);
			sprintf(buffer, "%s%d", buffer,param->val.n);
			
			flat_iov[cnt].iov_base = buffer + len;
			flat_iov[cnt].iov_len = strlen(buffer) - len;
			cnt++;
		}else{
			flat_iov[cnt].iov_base = param->val.s.s;
			flat_iov[cnt].iov_len = param->val.s.len;
			cnt++;
		}
		
		param = param->next;
		
	}while(param != params->last);
	
	while((rc = writev(fd, flat_iov, cnt))>0);
	if(rc == -1){
		LM_ERR("write error\n");
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

}

static str flat_print(evi_reply_sock *sock){

	struct flat_socket * fs = (struct flat_socket *)sock->params;
	return fs->path;
}

static void verify_delete(void) {
	struct deleted *head = *list_deleted_files;
	struct deleted *aux, *prev, *tmp;

	if (head != NULL)
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