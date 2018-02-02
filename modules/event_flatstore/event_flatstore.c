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

#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>

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
static void verify_delete(void);
static void flat_free(evi_reply_sock *sock);
static str flat_print(evi_reply_sock *sock);
static int flat_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
static evi_reply_sock* flat_parse(str socket);
static struct mi_root* mi_rotate(struct mi_root* root, void *param);
static int flat_raise(struct sip_msg *msg, str* ev_name,
					 evi_reply_sock *sock, evi_params_t * params);

static int *opened_fds;
static int *rotate_version;
static int buff_convert_len;
static int cap_params;
static str delimiter;
static char *dirc;
static int dir_size;
static char *buff;
static struct iovec *io_param ;
static struct flat_socket **list_files;
static struct flat_deleted **list_deleted_files;
static gen_lock_t *global_lock;
static int initial_capacity = FLAT_DEFAULT_MAX_FD;
static str file_permissions;
static mode_t file_permissions_oct;

static mi_export_t mi_cmds[] = {
	{ "evi_flat_rotate","rotates the files the module dumps events into",mi_rotate,0,0,0},
	{0,0,0,0,0,0}
};

static param_export_t mod_params[] = {
	{"max_open_sockets",INT_PARAM, &initial_capacity},
	{"delimiter",STR_PARAM, &delimiter.s},
	{"file_permissions", STR_PARAM, &file_permissions.s},
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
	int i;

	opened_fds = NULL;
	rotate_version = NULL;
	buff = NULL;
	buff_convert_len = 0;
	io_param = NULL;
	cap_params = 20;
	dirc = NULL;

	LM_NOTICE("initializing module ...\n");

	if (register_event_mod(&trans_export_flat)) {
		LM_ERR("cannot register transport functions for SCRIPTROUTE\n");
		return -1;
	}

	list_files =  shm_malloc(sizeof(struct flat_socket*) + sizeof(struct flat_deleted*));
	*list_files = NULL;

	if (!delimiter.s) {
		delimiter.s = pkg_malloc(sizeof(char));
		delimiter.s[0] = ',';
		delimiter.len = 1;
	} else {
		delimiter.len = strlen(delimiter.s);
		LM_DBG("The delimiter for separating columns in files was set at %.*s\n", delimiter.len, delimiter.s);
	}

    if (initial_capacity <= 0 || initial_capacity > 65535) {
		LM_WARN("bad value for maximum open sockets (%d)\n", initial_capacity);
		initial_capacity = FLAT_DEFAULT_MAX_FD;
	} else
		LM_DBG("Number of files descriptors was set at %d\n", initial_capacity);

	if (!file_permissions.s)
		file_permissions_oct = 0644;
	else {
		char *endptr = NULL;
		file_permissions_oct = strtol(file_permissions.s, &endptr, 8);
		if (*endptr != '\0') {
			LM_DBG("file permissions invalid\n");
			file_permissions_oct = 0644;
		}
	}

	LM_DBG("file permissions set to: %o\n", file_permissions_oct);

	if (!list_files) {
		LM_ERR("no more memory for list pointer\n");
		return -1;
	}

	list_deleted_files = (struct flat_deleted**)(list_files + 1);
	*list_deleted_files = NULL;

	global_lock = lock_alloc();

	if (global_lock == NULL) {
		LM_ERR("Failed to allocate lock \n");
		return -1;
	}

	if (lock_init(global_lock) == NULL) {
		LM_ERR("Failed to init lock \n");
		return -1;
	}

	opened_fds = pkg_malloc(initial_capacity * sizeof(int));
	rotate_version = pkg_malloc(initial_capacity * sizeof(int));

	memset(rotate_version, 0, initial_capacity * sizeof(int));

	for(i = 0; i < initial_capacity; i++)
		opened_fds[i] = -1;

	return 0;
}

/* free allocated memory */
static void destroy(void){
	struct flat_socket* list_header = *list_files;
	struct flat_socket* tmp;
	struct flat_deleted *deleted_header = *list_deleted_files;
	struct flat_deleted *aux;

	LM_NOTICE("destroying module ...\n");

	/* lock destroy and deallocate */
	lock_destroy(global_lock);
	lock_dealloc(global_lock);

	/* free file descriptors list from shared memory */
	while (list_header != NULL) {
		tmp = list_header;
		list_header = list_header->next;
		shm_free(tmp);
	}

	/* free deleted files from shared memory */
	while (deleted_header != NULL) {
		aux = deleted_header;
		deleted_header = deleted_header->next;
		shm_free(aux);
	}

	shm_free(list_files);

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
	while (list != NULL) {
		if (str_cmp(list->path, value)) {
			/* file descriptor found */
			return list;
		}
		list = list->next;
	}
	/* file descriptor not found */
	return NULL;
}

static struct mi_root* mi_rotate(struct mi_root* root, void *param){
	/* sanity checks */

	if (!root || !root->node.kids) {
		LM_ERR("empty root tree\n");
		return init_mi_tree( 400, MI_SSTR(MI_MISSING_PARM));
	}

	if (root->node.kids->value.s == NULL || root->node.kids->value.len == 0) {
		LM_ERR("Missing value\n");
		return init_mi_tree( 400, MI_SSTR(MI_MISSING_PARM));
	}

	/* search for a flat_socket structure that contains the file descriptor
	 * we need to rotate
	 */
	lock_get(global_lock);

	struct flat_socket *found_fd = search_for_fd(root->node.kids->value);

	if (found_fd == NULL) {
		LM_DBG("Not found path %.*s [lung : %d]\n",root->node.kids->value.len, root->node.kids->value.s, root->node.kids->value.len);
		lock_release(global_lock);
		return init_mi_tree( 400, MI_SSTR(MI_MISSING_PARM));;
	}

	LM_DBG("Found file descriptor and updating rotating version for %s, to %d\n",found_fd->path.s, found_fd->rotate_version + 1);

	found_fd->rotate_version++;

	lock_release(global_lock);

	/* return a mi_root structure with a success return code*/
	return init_mi_tree( 200, MI_SSTR(MI_OK));
}

static int flat_match (evi_reply_sock *sock1, evi_reply_sock *sock2) {
	struct flat_socket *fs1;
	struct flat_socket *fs2;

	if (sock1 != NULL && sock2 != NULL
			&& sock1->params != NULL && sock2->params != NULL) {

		fs1 = (struct flat_socket *)sock1->params;
		fs2 = (struct flat_socket *)sock2->params;
		/* if the path is equal then the file descriptor structures are equal*/
		return str_cmp(fs1->path, fs2->path);
	}
	/* not equal */
	return 0;
}

static int insert_in_list(struct flat_socket *entry) {
	struct flat_socket *head = *list_files, *aux, *parent = NULL;
	int expected = initial_capacity - 1;

	lock_get(global_lock);

	if (head == NULL) {
		LM_DBG("Its the single entry in list [%s]\n", entry->path.s);
		entry->file_index_process = 0;
		*list_files = entry;
		entry->prev = NULL;
		entry->next = NULL;
		lock_release(global_lock);
		return 0;
	}

	if (head->file_index_process < initial_capacity - 1) {
		LM_DBG("Inserting [%s] at the head of the list, index: [%d]\n",entry->path.s, head->file_index_process + 1);
		entry->file_index_process = head->file_index_process + 1;
		entry->prev = NULL;
		entry->next = head;
		head->prev = entry;
		*list_files = entry;
		lock_release(global_lock);
		return 0;
	}

	for (aux = head; aux != NULL; aux = aux->next, expected--) {
		if(aux->file_index_process != expected){
			LM_DBG("Inserting [%s] in a gap, index: [%d]\n", entry->path.s, expected);
			entry->file_index_process = expected;
			entry->prev = aux->prev;
			entry->next = aux;
			aux->prev =entry;
			entry->prev->next = entry;
			lock_release(global_lock);
			return 0;
		}
		parent = aux;
	}

	if (expected >= 0) {
		LM_DBG("Inserting [%s] at end of list, index: [%d]\n", entry->path.s, expected);
		entry->file_index_process = expected;
		entry->prev = parent;
		entry->next = NULL;
		parent->next = entry;
		lock_release(global_lock);
		return 0;
	}

	lock_release(global_lock);

	LM_ERR("no more free sockets\n");
	return -1;
}

static evi_reply_sock* flat_parse(str socket){
	evi_reply_sock *sock;
	struct flat_socket* entry;
	struct stat st_buf;
	struct flat_deleted *head = *list_deleted_files;
	struct flat_deleted *aux, *tmp;
	char *dname;

	if (!socket.s || !socket.len) {
		LM_ERR("no socket specified\n");
		return NULL;
	}

	/* if not all processes finished closing the file
	   find the structure and reuse it */
	if (head) {
		if (str_cmp(socket, head->socket->path)) {
			LM_DBG("Found structure at head of deleted list, reusing it [%s]\n", head->socket->path.s);
			*list_deleted_files = head->next;
			entry = head->socket;
			shm_free(head);
			return (evi_reply_sock *)((char*)(entry + 1) + socket.len + 1);
		} else {
			for (aux = head; aux->next != NULL; aux=aux->next)
				if (str_cmp(socket, aux->next->socket->path)) {
					LM_DBG("Found structure inside deleted list, reusing it [%s]\n", aux->next->socket->path.s);
					tmp = aux->next;
					aux->next = aux->next->next;
					entry = tmp->socket;
					shm_free(tmp);
					return (evi_reply_sock *)((char*)(entry + 1) + socket.len + 1);
				}
		}
	}

	entry = shm_malloc(sizeof(struct flat_socket) + socket.len + 1 + sizeof(evi_reply_sock));

	if (!entry) {
		LM_ERR("not enough shared memory\n");
		return NULL;
	}

	entry->path.s = (char *)(entry + 1);
	entry->path.len = socket.len;
	memcpy(entry->path.s, socket.s, socket.len);
	entry->path.s[socket.len] = '\0';

	/* verify if the path is valid (not a directory) and a file can be created
	*/
	if (dirc == NULL || dir_size < (socket.len + 1)) {
		dirc = pkg_realloc(dirc, (socket.len + 1) * sizeof(char));
		dir_size = socket.len + 1;
	}

	memcpy(dirc, entry->path.s, socket.len + 1);

	dname = dirname(dirc);

	if (stat(dname, &st_buf) < 0) {
		LM_ERR("invalid directory name\n");
		shm_free(entry);
		return NULL;
	}

	memset(&st_buf, 0, sizeof(struct stat));

	if (stat(entry->path.s, &st_buf) == 0 && S_ISDIR (st_buf.st_mode)) {
		LM_ERR("path is a directory\n");
		shm_free(entry);
		return NULL;
	}

	if (insert_in_list(entry) < 0) {
		shm_free(entry);
		return NULL;
	}

	entry->rotate_version = 0;
	entry->counter_open = 0;

	sock = (evi_reply_sock *)((char*)(entry + 1) + socket.len + 1);
	memset(sock, 0, sizeof(evi_reply_sock));
	sock->address.s = (char *)(entry + 1);
	sock->address.len = socket.len + 1;
	sock->params = entry;

	sock->flags |= EVI_PARAMS;
	sock->flags |= EVI_ADDRESS;
	sock->flags |= EVI_EXPIRE;

	return sock;
}

/*  check if the local 'version' of the file descriptor asociated with entry fs
	is different from the global version, if it is different reopen the file
*/
static void rotating(struct flat_socket *fs){
	int index = fs->file_index_process;
	int rc;

	lock_get(global_lock);

	if (opened_fds[index] == -1) {
		opened_fds[index] = open(fs->path.s,O_RDWR | O_APPEND | O_CREAT, file_permissions_oct);
		if (opened_fds[index] < 0) {
			LM_ERR("Opening socket error\n");
			lock_release(global_lock);
			return;
		}
		rotate_version[index] = fs->rotate_version;
		fs->counter_open++;
		LM_DBG("File %s is opened %d time\n", fs->path.s, fs->counter_open);

		lock_release(global_lock);
		return;
	}

	if (rotate_version[index] != fs->rotate_version && opened_fds[index] != -1) {

	   /* update version */
		rotate_version[index] = fs->rotate_version;
		lock_release(global_lock);

		/* rotate */
		rc = close(opened_fds[index]);
		if(rc < 0){
			LM_ERR("Closing socket error\n");
			return;
		}

		opened_fds[index] = open(fs->path.s,O_RDWR | O_APPEND | O_CREAT, file_permissions_oct);
		if (opened_fds[index] < 0) {
			LM_ERR("Opening socket error\n");
			return;
		}
		LM_DBG("Rotating file %s\n",fs->path.s);

	} else
		lock_release(global_lock);
}

static int flat_raise(struct sip_msg *msg, str* ev_name,
					 evi_reply_sock *sock, evi_params_t *params) {

	int idx = 0, offset_buff = 0, len, required_length = 0, nwritten;
	evi_param_p param;
	struct flat_socket *entry = (struct flat_socket*)(sock ? sock->params: NULL);
	char endline = '\n';
	char *ptr_buff;
	int nr_params = 0;

	if (entry)
		rotating(entry);

	verify_delete();

	if (!sock || !(sock->params)) {
		LM_ERR("invalid socket specification\n");
		return -1;
	}

	if (io_param == NULL)
		io_param = pkg_malloc(cap_params * sizeof(struct iovec));

	if (ev_name && ev_name->s) {
		io_param[idx].iov_base = ev_name->s;
		io_param[idx].iov_len = ev_name->len;
		idx++;
	}

	if (params) {
		for (param = params->first; param; param = param->next) {
			if (param->flags & EVI_INT_VAL)
				required_length += INT2STR_MAX_LEN;
			nr_params++;
		}

		if (buff == NULL || required_length > buff_convert_len) {
			buff = pkg_realloc(buff, required_length * sizeof(char) + 1);
			buff_convert_len = required_length;
		}

		memset(buff, 0, buff_convert_len);

		for (param = params->first; param; param = param->next) {

			if(idx + 3 > cap_params){
				io_param = pkg_realloc(io_param, (cap_params + 20) * sizeof(struct iovec));
				cap_params += 20;
			}

			io_param[idx].iov_base = delimiter.s;
			io_param[idx].iov_len = delimiter.len;
			idx++;

			if (param->flags & EVI_INT_VAL) {
				ptr_buff =  sint2str(param->val.n, &len);
				memcpy(buff + offset_buff, ptr_buff, len);
				io_param[idx].iov_base = buff + offset_buff;
				io_param[idx].iov_len = len;
				offset_buff += len;
				idx++;
			} else if ((param->flags & EVI_STR_VAL) && param->val.s.len && param->val.s.s) {
				io_param[idx].iov_base = param->val.s.s;
				io_param[idx].iov_len = param->val.s.len;
				idx++;
			}
		}
	}

	io_param[idx].iov_base = &endline;
	io_param[idx].iov_len = 1;
	idx++;

	do {
		nwritten = writev(opened_fds[entry->file_index_process], io_param, idx);
	} while (nwritten < 0 && errno == EINTR);

	if (ev_name && ev_name->s)
		LM_DBG("raised event: %.*s has %d parameters\n", ev_name->len, ev_name->s, nr_params);

	if (nwritten < 0){
		LM_ERR("cannot write to socket\n");
		return -1;
	}

	return 0;
}

static void flat_free(evi_reply_sock *sock) {
	struct flat_deleted *head = *list_deleted_files;
	struct flat_deleted *new;

	if (sock->params == NULL) {
		LM_ERR("socket not found\n");
	}

	new = shm_malloc(sizeof(struct flat_deleted));
	if (!new) {
		LM_ERR("no more shm mem\n");
		return;
	}
	new->socket = (struct flat_socket*)sock->params;
	LM_DBG("File %s is being deleted...\n",new->socket->path.s);
	new->next = NULL;

	lock_get(global_lock);

	if(head	!= NULL)
		new->next = head;

	*list_deleted_files = new;

	lock_release(global_lock);

    verify_delete();
}

static str flat_print(evi_reply_sock *sock){
	struct flat_socket * fs = (struct flat_socket *)sock->params;
	return fs->path;
}

static void verify_delete(void) {
	struct flat_deleted *head = *list_deleted_files;
	struct flat_deleted *aux, *prev, *tmp;

	if (head == NULL && opened_fds == NULL)
		return;

	lock_get(global_lock);

	/* close fd if necessary */
	aux = head;
	prev = NULL;
	while (aux != NULL) {
		if (opened_fds[aux->socket->file_index_process] != -1) {
			LM_DBG("File %s is closed locally, open_counter is %d\n", aux->socket->path.s, aux->socket->counter_open - 1);
			close(opened_fds[aux->socket->file_index_process]);
			aux->socket->counter_open--;
			opened_fds[aux->socket->file_index_process] = -1;
		}

		/* free file from lists if all other processes closed it */
		if (aux->socket->counter_open == 0) {
			LM_DBG("File %s is deleted globally, count open reached 0\n", aux->socket->path.s);
			if (aux->socket->prev)
				aux->socket->prev->next = aux->socket->next;
			else
				*list_files = aux->socket->next;

			if (aux->socket->next)
				aux->socket->next->prev = aux->socket->prev;

			shm_free(aux->socket);

			if (prev != NULL)
				prev->next = aux->next;
			else
				*list_deleted_files = aux->next;

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
