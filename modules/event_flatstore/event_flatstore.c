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
#include <time.h>
#include <ctype.h>

#include "event_flatstore.h"
#include "../../mem/mem.h"
#include "../../locking.h"
#include "../../sr_module.h"
#include "../../evi/evi_transport.h"
#include "../../evi/evi_params.h"
#include "../../mem/shm_mem.h"
#include "../../locking.h"
#include "../../timer.h"
#include "../../ipc.h"
#include "../../ut.h"

static int mod_init(void);
static void destroy(void);
static int child_init(int rank);
static void verify_delete(void);
static void flat_free(evi_reply_sock *sock);
static str flat_print(evi_reply_sock *sock);
static int flat_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
static evi_reply_sock* flat_parse(str socket);
mi_response_t *mi_rotate(const mi_params_t *params,
								struct mi_handler *async_hdl);
static int flat_raise(struct sip_msg *msg, str* ev_name, evi_reply_sock *sock,
	evi_params_t *params, evi_async_ctx_t *async_ctx);

static void event_flatstore_timer(unsigned int ticks, void *param);

static int *opened_fds;
static int *rotate_version;

static int buff_convert_len;
static int cap_params;
static str delimiter;
static char *dirc;
static int dir_size;
static char *buff;
static struct iovec *io_param ;
static struct flat_socket **list_sockets;
static struct flat_file **list_files;
static struct flat_delete **list_delete;
static gen_lock_t *global_lock;
static int initial_capacity = FLAT_DEFAULT_MAX_FD;
static int suppress_event_name = 0;
static str file_permissions;
static mode_t file_permissions_oct;
static int file_rotate_period;
static unsigned long file_rotate_count;
static unsigned long file_rotate_size;
static str file_suffix;
static pv_elem_p file_suffix_format;
static str escape_delimiter = {0, 0};

static void raise_rotation_event(struct flat_file *file, const char *reason);
static void update_counters_and_rotate(struct flat_file *file,
                                       ssize_t bytes_inc);

static char *ensure_file_path(struct flat_file *file, int reset);
static void event_flatstore_rotate(int sender, void *param);
static int rotate_count_param(modparam_t type, void *val);
static int rotate_size_param(modparam_t type, void *val);

/* event */
static str flatstore_event = str_init("E_FLATSTORE_ROTATION");
static event_id_t flatstore_evi_id;
static const char flat_empty_str[] = "";

static const mi_export_t mi_cmds[] = {
	{ "evi_flat_rotate", "rotates the files the module dumps events into", 0,0,{
		{mi_rotate, {"path_to_file", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static const param_export_t mod_params[] = {
	{"max_open_sockets",INT_PARAM, &initial_capacity},
	{"delimiter",STR_PARAM, &delimiter.s},
	{"file_permissions", STR_PARAM, &file_permissions.s},
	{"suppress_event_name", INT_PARAM, &suppress_event_name},
	{"rotate_period", INT_PARAM,  &file_rotate_period},
	{"rotate_count",  INT_PARAM|STR_PARAM|USE_FUNC_PARAM, (void*)rotate_count_param},
	{"rotate_size",   INT_PARAM|STR_PARAM|USE_FUNC_PARAM, (void*)rotate_size_param},
	{"suffix", STR_PARAM, &file_suffix.s},
	{"escape_delimiter", STR_PARAM, &escape_delimiter.s},
	{0,0,0}
};

struct module_exports exports= {
	"event_flatstore",			/* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* load function */
	NULL,            /* OpenSIPS module dependencies */
	0,							/* exported functions */
	0,							/* exported async functions */
	mod_params,							/* exported parameters */
	0,							/* exported statistics */
	mi_cmds,							/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,			 				/* exported transformations */
	0,						/* extra processes */
	0,							/* module pre-initialization function */
	mod_init,					/* module initialization function */
	0,							/* response handling function */
	destroy,					/* destroy function */
	child_init,					/* per-child init function */
	0							/* reload confirm function */
};

static const evi_export_t trans_export_flat = {
	FLAT_STR,					/* transport module name */
	flat_raise,					/* raise function */
	flat_parse,					/* parse function */
	flat_match,					/* sockets match function */
	flat_free,					/* free function */
	flat_print,					/* print socket */
	FLAT_FLAG					/* flags */
};

static int rotate_count_param(modparam_t type, void *val)
{
	if (type == INT_PARAM) {
		file_rotate_count = (unsigned long)(long)val;
		return 0;
	}

	/* STR_PARAM: accept plain number */
	char *s = (char *)val;
	char *end = NULL;
	unsigned long num = strtoul(s, &end, 10);

	if (end == s) {
		LM_ERR("rotate_count: invalid numeric value '%s'\n", s);
		return -1;
	}

	file_rotate_count = num;
	LM_DBG("rotate_count parsed as %lu lines\n", file_rotate_count);

	return 0;
}

/* convert KB / MB / GB suffix to multiplier */
static unsigned long suffix_mult(char suf)
{
	switch (tolower((unsigned char)suf)) {
	case 'k': return 1024UL;
	case 'm': return 1024UL * 1024UL;
	case 'g': return 1024UL * 1024UL * 1024UL;
	default:  return 1UL;
	}
}

static int rotate_size_param(modparam_t type, void *val)
{
	if (type == INT_PARAM) {
		file_rotate_size = (unsigned long)(long)val;
		return 0;
	}

	/* STR_PARAM: accept plain number or number+suffix */
	char *s = (char *)val;
	char *end = NULL;
	unsigned long num = strtoul(s, &end, 10);

	if (end == s) {
		LM_ERR("rotate_size: invalid numeric value '%s'\n", s);
		return -1;
	}

	/* optional multiplier suffix */
	file_rotate_size = num * suffix_mult(*end);
	LM_DBG("rotate_size parsed as %lu bytes\n", file_rotate_size);

	return 0;
}

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

	if (file_rotate_period && file_rotate_period < 0) {
		LM_WARN("\"rotate_period\" parameter needs to be a positive integer (%d)! "
				"Disabling auto-rotate!\n", file_rotate_period);
		file_rotate_period = 0;
	}

	if (file_suffix.s) {
		file_suffix.len = strlen(file_suffix.s);
		if (pv_parse_format(&file_suffix, &file_suffix_format) < 0) {
			LM_ERR("could not parse file suffix format!\n");
			return -1;
		}
	}

	if (register_event_mod(&trans_export_flat)) {
		LM_ERR("cannot register transport functions for SCRIPTROUTE\n");
		return -1;
	}

	flatstore_evi_id = evi_publish_event(flatstore_event);
	if (flatstore_evi_id == EVI_ERROR) {
		LM_ERR("cannot register %.*s event\n", flatstore_event.len, flatstore_event.s);
		return -1;
	}

	list_files =  shm_malloc(sizeof(struct flat_file*));
	if (!list_files) {
		LM_ERR("oom!\n");
		return -1;
	}
	*list_files = NULL;

	list_delete =  shm_malloc(sizeof(struct flat_delete*));
	if (!list_delete) {
		LM_ERR("oom!\n");
		return -1;
	}
	*list_delete = NULL;

	list_sockets =  shm_malloc(sizeof(struct flat_socket*));
	if (!list_sockets) {
		LM_ERR("oom!\n");
		return -1;
	}
	*list_sockets = NULL;

	if (!delimiter.s) {
		delimiter.s = pkg_malloc(sizeof(char));
		if (!delimiter.s) {
			LM_ERR("oom!\n");
			return -1;
		}
		delimiter.s[0] = ',';
		delimiter.len = 1;
	} else {
		delimiter.len = strlen(delimiter.s);
		LM_DBG("The delimiter for separating columns in files was set at %.*s\n", delimiter.len, delimiter.s);
	}

	if (escape_delimiter.s) {
		escape_delimiter.len = strlen(escape_delimiter.s);
		if (escape_delimiter.len != delimiter.len) {
			LM_ERR("\"escape_delimiter\" length (%d) must match \"delimiter\" length (%d)\n",
			escape_delimiter.len, delimiter.len);
			return -1;
		}
		LM_DBG("Delimiter escaping enabled: \"%.*s\" → \"%.*s\"\n",
			delimiter.len,  delimiter.s, escape_delimiter.len, escape_delimiter.s);
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
	if (!opened_fds) {
		LM_ERR("oom\n");
		return -1;
	}
	rotate_version = pkg_malloc(initial_capacity * sizeof(int));
	if (!rotate_version) {
		LM_ERR("oom\n");
		return -1;
	}

	memset(rotate_version, 0, initial_capacity * sizeof(int));

	for(i = 0; i < initial_capacity; i++)
		opened_fds[i] = -1;

	if (file_rotate_period &&
		register_timer("event_flatstore", event_flatstore_timer, 0,
			1, TIMER_FLAG_DELAY_ON_DELAY) < 0) {
		LM_ERR("could not add event flatstore routine\n");
		return -1;
	}

	return 0;
}

/* free allocated memory */
static void destroy(void){
	struct flat_socket* list_header = *list_sockets;
	struct flat_socket* tmp;
	struct flat_file* file_it = *list_files;
	struct flat_file* file_tmp;
	struct flat_delete* del_it = *list_delete;
	struct flat_delete* del_tmp;

	LM_NOTICE("destroying module ...\n");

	/* lock destroy and deallocate */
	lock_destroy(global_lock);
	lock_dealloc(global_lock);

	/* free files list from shared memory */
	while (file_it != NULL) {
		file_tmp = file_it;
		file_it = file_it->next;
		if (file_tmp->old_pathname &&
			file_tmp->old_pathname != file_tmp->path.s &&
			file_tmp->old_pathname != flat_empty_str)

			shm_free(file_tmp->old_pathname);
		if (file_tmp->pathname && file_tmp->pathname != file_tmp->path.s)
			shm_free(file_tmp->pathname);
		shm_free(file_tmp);
	}

	shm_free(list_files);

	/* free delete list from shared memory */
	while (del_it != NULL) {
		del_tmp = del_it;
		del_it = del_it->next;
		shm_free(del_tmp);
	}

	shm_free(list_delete);

	/* free flatstore sockets list from shared memory */
	while (list_header != NULL) {
		tmp = list_header;
		list_header = list_header->next;
		shm_free(tmp);
	}

	shm_free(list_sockets);

	if (buff)
		pkg_free(buff);
	if (io_param)
		pkg_free(io_param);
	if (dirc)
		pkg_free(dirc);

	if (opened_fds)
		pkg_free(opened_fds);
	if (rotate_version)
		pkg_free(rotate_version);
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
static struct flat_file *search_for_fd(str value){
	struct flat_file *list = *list_files;
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

mi_response_t *mi_rotate(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str path;

	if (get_mi_string_param(params, "path_to_file", &path.s, &path.len) < 0)
		return init_mi_param_error();

	/* search for a flat_socket structure that contains the file descriptor
	 * we need to rotate
	 */
	lock_get(global_lock);

	struct flat_file *found_fd = search_for_fd(path);

	if (found_fd == NULL) {
		LM_DBG("Path: %.*s is not valid\n", path.len,
			path.s);
		lock_release(global_lock);
		return init_mi_error(400, MI_SSTR("File not found"));
	}

	LM_DBG("Found file descriptor and updating rotating version for %s, to %d\n",
		found_fd->path.s, found_fd->rotate_version + 1);

	found_fd->rotate_version++;
	found_fd->record_count  = 0;
	found_fd->bytes_written = 0;
	ensure_file_path(found_fd, 1);

	lock_release(global_lock);

	raise_rotation_event(found_fd, ROTATE_REASON_MI);
	ipc_send_rpc_all(event_flatstore_rotate, 0);

	return init_mi_result_ok();
}

static int flat_match (evi_reply_sock *sock1, evi_reply_sock *sock2) {
	struct flat_socket *fs1;
	struct flat_socket *fs2;

	if (sock1 != NULL && sock2 != NULL
			&& sock1->params != NULL && sock2->params != NULL) {

		fs1 = (struct flat_socket *)sock1->params;
		fs2 = (struct flat_socket *)sock2->params;
		/* if the path is equal then the file descriptor structures are equal*/
		return str_cmp(fs1->file->path, fs2->file->path);
	}
	/* not equal */
	return 0;
}

static int insert_in_list(struct flat_file *entry) {
	struct flat_file *head = *list_files, *aux, *parent = NULL;
	int expected = initial_capacity - 1;

	if (head == NULL) {
		LM_DBG("Its the single entry in list [%s]\n", entry->path.s);
		entry->file_index_process = 0;
		*list_files = entry;
		entry->prev = NULL;
		entry->next = NULL;
		return 0;
	}

	if (head->file_index_process < initial_capacity - 1) {
		LM_DBG("Inserting [%s] at the head of the list, index: [%d]\n",
			entry->path.s, head->file_index_process + 1);
		entry->file_index_process = head->file_index_process + 1;
		entry->prev = NULL;
		entry->next = head;
		head->prev = entry;
		*list_files = entry;
		return 0;
	}

	for (aux = head; aux != NULL; aux = aux->next, expected--) {
		if(aux->file_index_process != expected){
			LM_DBG("Inserting [%s] in a gap, index: [%d]\n",
				entry->path.s, expected);
			entry->file_index_process = expected;
			entry->prev = aux->prev;
			entry->next = aux;
			aux->prev =entry;
			entry->prev->next = entry;
			return 0;
		}
		parent = aux;
	}

	if (expected >= 0) {
		LM_DBG("Inserting [%s] at end of list, index: [%d]\n",
			entry->path.s, expected);
		entry->file_index_process = expected;
		entry->prev = parent;
		entry->next = NULL;
		parent->next = entry;
		return 0;
	}

	LM_ERR("no more free sockets\n");
	return -1;
}

static evi_reply_sock* flat_parse(str socket){
	evi_reply_sock *sock;
	struct flat_socket* entry;
	struct stat st_buf;
	struct flat_file *file = NULL;
	char *dname;

	if (!socket.s || !socket.len) {
		LM_ERR("no socket specified\n");
		return NULL;
	}

	lock_get(global_lock);

	entry = shm_malloc(sizeof(struct flat_socket) + sizeof(evi_reply_sock));
	if (!entry) {
		LM_ERR("not enough shared memory\n");
		lock_release(global_lock);
		return NULL;
	}

	/* check if other flatstore sockets already use this file */
	for (file = *list_files; file; file = file->next)
		if (str_cmp(socket, file->path))
			break;
	if (!file) {
		file = shm_malloc(sizeof *file + socket.len + 1);
		if (!file) {
			LM_ERR("oom!\n");
			goto error;
		}
		memset(file, 0, sizeof *file);

		file->path.s = (char *)(file + 1);
		file->path.len = socket.len;
		memcpy(file->path.s, socket.s, socket.len);
		file->path.s[socket.len] = '\0';

		/* verify if the path is valid (not a directory) and a file can be created
		*/
		if (dirc == NULL || dir_size < (socket.len + 1)) {
			dirc = pkg_realloc(dirc, (socket.len + 1) * sizeof(char));
			if (!dirc) {
				LM_ERR("oom!\n");
				goto error;
			}
			dir_size = socket.len + 1;
		}

		memcpy(dirc, file->path.s, socket.len + 1);

		dname = dirname(dirc);

		if (stat(dname, &st_buf) < 0) {
			LM_ERR("invalid directory name\n");
			goto error;
		}

		memset(&st_buf, 0, sizeof(struct stat));

		if (stat(file->path.s, &st_buf) == 0 && S_ISDIR (st_buf.st_mode)) {
			LM_ERR("path is a directory\n");
			goto error;
		}

		if (insert_in_list(file) < 0)
			goto error;
	}

	sock = (evi_reply_sock *)((char*)(entry + 1));
	memset(sock, 0, sizeof(evi_reply_sock));
	sock->address.s = (char *)(file + 1);
	sock->address.len = socket.len + 1;
	sock->params = entry;

	sock->flags |= EVI_PARAMS;
	sock->flags |= EVI_ADDRESS;
	sock->flags |= EVI_EXPIRE;

	entry->file = file;
	file->flat_socket_ref++;

	entry->next = *list_sockets;
	*list_sockets = entry;

	lock_release(global_lock);

	return sock;

error:
	lock_release(global_lock);
	if (file && !file->next)
		shm_free(file);
	shm_free(entry);
	return NULL;
}

/* Builds (or rebuilds) the suffixed pathname for a flat_file.
 * file  – target structure
 * reset – if non-zero, force recreation: free old suffixed name,
 *         clear pathname and build a fresh one
 * Returns: valid pathname */
static char *ensure_file_path(struct flat_file *file, int reset)
{
	str format;
	char *filepath;
	static struct sip_msg req;

	if (reset) { /* free old pathname before saving a new one */
		if (file->old_pathname &&
			file->old_pathname != file->path.s &&
			file->old_pathname != flat_empty_str) {

			shm_free(file->old_pathname);
		}
		file->old_pathname = NULL;
	}

	/* reuse existing pathname when no reset requested */
	if (!reset && file->pathname)
		return file->pathname;

	/* save current pathname before regenerating */
	if (reset) {
		if (file->pathname) {
			size_t len = strlen(file->pathname);
			char *dup  = shm_malloc(len + 1);
			if (!dup) {
				LM_ERR("OOM while duplicating old pathname\n");
				return NULL;
			} else {
				memcpy(dup, file->pathname, len + 1);
				file->old_pathname = dup;
			}
		} else {
			file->old_pathname = (char *)flat_empty_str;
		}
	}

	/* drop current suffixed name if it was allocated */
	if (reset && file->pathname && file->pathname != file->path.s) {
		shm_free(file->pathname);
		file->pathname = NULL;
	}

	/*  if suffix disabled use original path */
	if (!file_suffix_format) {
		file->pathname = file->path.s;
		return file->pathname;
	}

	req.first_line.u.request.method.s= "DUMMY";
	req.first_line.u.request.method.len= 5;
	req.first_line.u.request.uri.s= "sip:user@domain.com";
	req.first_line.u.request.uri.len= 19;
	req.rcv.src_ip.af = AF_INET;
	req.rcv.dst_ip.af = AF_INET;

	if (pv_printf_s(&req, file_suffix_format, &format) < 0) {
		LM_ERR("could not print the file's format!\n");
		goto error;
	}

	if (!file->pathname) {
		filepath = shm_malloc(file->path.len + format.len + 1);
		if (!filepath) {
			LM_ERR("could not allocate new file's name!\n");
			goto error;
		}
		/* the file path is always the same */
		memcpy(filepath, file->path.s, file->path.len);
	} else {
		filepath = shm_realloc(file->pathname, file->path.len + format.len + 1);
		if (!filepath) {
			LM_ERR("could not re-allocate new file's name!\n");
			goto error;
		}
	}
	memcpy(filepath + file->path.len, format.s, format.len);
	filepath[file->path.len + format.len] = '\0';
	file->pathname = filepath;
	goto end;

error:
	if (file->old_pathname &&
		file->old_pathname != file->path.s &&
		file->old_pathname != flat_empty_str) {

		shm_free(file->old_pathname);
	}
	file->old_pathname = NULL;

	if (!file->pathname)
		file->pathname = file->path.s;
end:
	LM_DBG("filepath for socket [%s] is [%s]\n", file->path.s, file->pathname);
	return file->pathname;
}

/*  check if the local 'version' of the file descriptor asociated with entry fs
	is different from the global version, if it is different reopen the file
*/
static void rotating(struct flat_file *file){
	int index;
	int rc;

	if (!file)
		return;

	lock_get(global_lock);

	index = file->file_index_process;

	if (opened_fds[index] == -1) {
		/* fd not opened in this process */

		ensure_file_path(file, 0);
		if (!file->pathname) {
			LM_ERR("no pathname for %s\n", file->path.s);
			lock_release(global_lock);
			return;
		}
		opened_fds[index] = open(file->pathname, O_RDWR | O_APPEND | O_CREAT, file_permissions_oct);
		if (opened_fds[index] < 0) {
			LM_ERR("Opening socket error\n");
			lock_release(global_lock);
			return;
		}
		rotate_version[index] = file->rotate_version;
		file->counter_open++;
		LM_DBG("File %s is opened %d time\n", file->pathname, file->counter_open);

		lock_release(global_lock);
		return;

	} else if (rotate_version[index] != file->rotate_version) {
		/* fd is opened in this process */

	   /* update version */
		rotate_version[index] = file->rotate_version;
		lock_release(global_lock);

		/* rotate */
		rc = close(opened_fds[index]);
		if(rc < 0){
			LM_ERR("Closing socket error\n");
			return;
		}

		opened_fds[index] = open(file->pathname, O_RDWR | O_APPEND | O_CREAT, file_permissions_oct);
		if (opened_fds[index] < 0) {
			LM_ERR("Opening socket error\n");
			return;
		}
		LM_DBG("Rotating file %s\n",file->path.s);

	} else
		lock_release(global_lock);
}

static int flat_raise(struct sip_msg *msg, str* ev_name, evi_reply_sock *sock,
	evi_params_t *params, evi_async_ctx_t *async_ctx) {

	int idx = 0, offset_buff = 0, len, required_length = 0, nwritten;
	evi_param_p param;
	struct flat_socket *entry = (struct flat_socket*)(sock ? sock->params: NULL);
	char endline = '\n';
	char *ptr_buff;
	int nr_params = 0;
	int f_idx;
	int i;

	if (!entry) {
		LM_ERR("invalid socket specification\n");
		return -1;
	}

	rotating(entry->file);

	/* check list of files to be deleted */
	verify_delete();

	if (io_param == NULL) {
		io_param = pkg_malloc(cap_params * sizeof(struct iovec));
		if (!io_param) {
			LM_ERR("oom!\n");
			return -1;
		}
	}


	if (!suppress_event_name && ev_name && ev_name->s) {
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
			if (!buff) {
				LM_ERR("oom!\n");
				return -1;
			}
			buff_convert_len = required_length;
		}

		memset(buff, 0, buff_convert_len);

		for (param = params->first; param; param = param->next) {

			if(idx + 3 > cap_params){
				io_param = pkg_realloc(io_param, (cap_params + 20) * sizeof(struct iovec));
				if (!io_param) {
					LM_ERR("oom!\n");
					return -1;
				}
				cap_params += 20;
			}

			if (!suppress_event_name || idx != 0) {
				io_param[idx].iov_base = delimiter.s;
				io_param[idx].iov_len = delimiter.len;
				idx++;
			}

			if (param->flags & EVI_INT_VAL) {
				ptr_buff =  sint2str(param->val.n, &len);
				memcpy(buff + offset_buff, ptr_buff, len);
				io_param[idx].iov_base = buff + offset_buff;
				io_param[idx].iov_len = len;
				offset_buff += len;
				idx++;
			} else if ((param->flags & EVI_STR_VAL) && param->val.s.len && param->val.s.s) {
				for(i=0; i<param->val.s.len; i++) {
					if (param->val.s.s[i] == delimiter.s[0]) {
						param->val.s.s[i] = ' ';
					}
				}

				/* if escape_delimiter is configured, replace any in-value
				 * occurrences of the delimiter with the escape sequence     */
				if (escape_delimiter.s) {
					if (delimiter.len == 1) {           /* fast single-char */
						for (i = 0; i < param->val.s.len; i++)
							if (param->val.s.s[i] == delimiter.s[0])
								param->val.s.s[i] = escape_delimiter.s[0];
					} else {                            /* multi-char delim  */
						char *p   = param->val.s.s;
						char *end = p + param->val.s.len - delimiter.len;
						while (p <= end) {
							if (memcmp(p, delimiter.s, delimiter.len) == 0) {
								memcpy(p, escape_delimiter.s, delimiter.len);
								p += delimiter.len;
								end = param->val.s.s + param->val.s.len - delimiter.len;
							} else {
								p++;
							}
						}
					}
				}
				io_param[idx].iov_base = param->val.s.s;
				io_param[idx].iov_len = param->val.s.len;
				idx++;
			}
		}
	}

	io_param[idx].iov_base = &endline;
	io_param[idx].iov_len = 1;
	idx++;

	lock_get(global_lock);
	f_idx = entry->file->file_index_process;
	lock_release(global_lock);

	do {
		nwritten = writev(opened_fds[f_idx], io_param, idx);
	} while (nwritten < 0 && errno == EINTR);

	if (ev_name && ev_name->s)
		LM_DBG("raised event: %.*s has %d parameters\n", ev_name->len, ev_name->s, nr_params);

	if (nwritten < 0){
		LM_ERR("cannot write to socket\n");
		return -1;
	}

	update_counters_and_rotate(entry->file, nwritten);

	return 0;
}

static void flat_free(evi_reply_sock *sock) {
	struct flat_socket *fs, *it;
	struct flat_file *file;
	struct flat_delete *new_del, *del_it;

	if (sock->params == NULL) {
		LM_ERR("socket not found\n");
		return;
	}
	fs = (struct flat_socket*)sock->params;
	file = fs->file;

	LM_DBG("Socket '%s' is being deleted...\n",file->path.s);

	lock_get(global_lock);

	file->flat_socket_ref--;

	/* free flatstore socket */
	if (fs == *list_sockets) {
		*list_sockets = fs->next;
		shm_free(fs);
	} else {
		for (it = *list_sockets; it->next && fs != it->next; it = it->next) ;
		if (it->next) {
			it->next = it->next->next;
			shm_free(it->next);
		}
	}

	/* add to list of files to be deleted if not already present */
	for (del_it = *list_delete; del_it && del_it->file != file; del_it = del_it->next) ;
	if (!del_it) {
		new_del = shm_malloc(sizeof *new_del);
		if (!new_del) {
			lock_release(global_lock);
			LM_ERR("oom!\n");
			return;
		}
		new_del->file = file;

		new_del->next = *list_delete;
		*list_delete = new_del;
	}

	lock_release(global_lock);

	/* check if we can close the file and actually delete it */
    verify_delete();
}

static str flat_print(evi_reply_sock *sock){
	struct flat_socket * fs = (struct flat_socket *)sock->params;
	return fs->file->path;
}

void event_flatstore_rotate(int sender, void *param)
{
	/* we've been instructed to double check the versions of our sockets */
	struct flat_file* file;
	int index;

	lock_get(global_lock);
	for (file = *list_files; file; file = file->next) {
		index = file->file_index_process;
		if (opened_fds[index] != -1 && rotate_version[index] != file->rotate_version) {
			close(opened_fds[index]);
			opened_fds[index] = -1; /* open it next time we have an event */
			if (file->counter_open > 0)
				file->counter_open--;
		}
	}
	lock_release(global_lock);
}

static void event_flatstore_timer(unsigned int ticks, void *param)
{
	struct flat_file* file;

	/* we only run when ticks is multiple of file_rotate_period */
	if (time(NULL) % file_rotate_period != 0)
		return;

	lock_get(global_lock);
	for (file = *list_files; file; file = file->next) {
		file->rotate_version++;
		file->record_count  = 0;
		file->bytes_written = 0;
		ensure_file_path(file, 1);
		raise_rotation_event(file, ROTATE_REASON_PERIOD);
		LM_DBG("File %s is being rotated at %u - new file is %s\n",
				file->path.s, ticks, file->pathname);
	}
	/* inform everyone they need to rotate */
	lock_release(global_lock);
	ipc_send_rpc_all(event_flatstore_rotate, 0);
}

static void verify_delete(void) {
	struct flat_delete *del_it, *del_prev, *del_tmp;

	lock_get(global_lock);

	del_it = *list_delete;
	del_prev = NULL;

	while (del_it) {
		if (del_it->file->flat_socket_ref != 0) {
			del_it = del_it->next;
			continue;
		}

		if (opened_fds[del_it->file->file_index_process] != -1) {
			LM_DBG("Closing file %s from current process, open_counter is %d\n",
				del_it->file->path.s, del_it->file->counter_open - 1);
			close(opened_fds[del_it->file->file_index_process]);
			if (del_it->file->counter_open > 0)
				del_it->file->counter_open--;
			opened_fds[del_it->file->file_index_process] = -1;
		}

		/* free file from list if all other processes closed it */
		if (del_it->file->counter_open == 0) {
			char *pname = NULL, *oldp = NULL;

			/* save extra buffers before we lose the struct */
			if (del_it->file->pathname &&
				del_it->file->pathname != del_it->file->path.s) {

				pname = del_it->file->pathname;
			}

			if (del_it->file->old_pathname &&
				del_it->file->old_pathname != del_it->file->path.s &&
				del_it->file->old_pathname != flat_empty_str) {

				oldp = del_it->file->old_pathname;
			}

			LM_DBG("File %s is deleted globally, count open reached 0\n",
				del_it->file->path.s);
			if (del_it->file->prev)
				del_it->file->prev->next = del_it->file->next;
			else
				*list_files = del_it->file->next;

			if (del_it->file->next)
				del_it->file->next->prev = del_it->file->prev;

			shm_free(del_it->file);

			/* remove file from delete list */
			if (del_prev != NULL)
				del_prev->next = del_it->next;
			else
				*list_delete = del_it->next;

			/* free extra buffers after struct is gone */
			if (pname)
				shm_free(pname);
			if (oldp)
				shm_free(oldp);

			del_tmp = del_it;
			del_it = del_it->next;
			shm_free(del_tmp);
		} else {
			del_prev = del_it;
			del_it = del_it->next;
		}
	}

	lock_release(global_lock);
}

static str ts_name = str_init("timestamp");
static str rn_name = str_init("reason");
static str fn_name = str_init("filename");
static str oldfn_name = str_init("old_filename");


static void raise_rotation_event(struct flat_file *file, const char *reason)
{
	if (flatstore_evi_id == EVI_ERROR || !evi_probe_event(flatstore_evi_id))
		return;

	evi_params_p list = evi_get_params();
	if (!list) {
		LM_ERR("cannot create event params\n");
		return;
	}

	/* build strings */
	char ts_buf[32];
	str  ts_val  = { ts_buf, 0 };

	str fn_val = { file->pathname, strlen(file->pathname) };

	if (!file->old_pathname)
		file->old_pathname = (char *)flat_empty_str;

	str oldfn_val = { file->old_pathname, strlen(file->old_pathname) };


	str reason_val = { (char*)reason, strlen(reason) };

	ts_val.len = snprintf(ts_buf, sizeof(ts_buf), "%ld", (long)time(NULL));

	if (evi_param_add_str(list, &ts_name, &ts_val) < 0 ||
		evi_param_add_str(list, &rn_name, &reason_val) < 0 ||
		evi_param_add_str(list, &fn_name, &fn_val) < 0 ||
		evi_param_add_str(list, &oldfn_name, &oldfn_val) < 0) {

		evi_free_params(list);
		return;
	}

	if (evi_raise_event(flatstore_evi_id, list))
		LM_ERR("unable to send flatstore rotation event\n");

	/* clean old_pathname */
	if (file->old_pathname && file->old_pathname != file->path.s && file->old_pathname != flat_empty_str) {
		shm_free(file->old_pathname);
	}
	file->old_pathname = NULL;
}

static void update_counters_and_rotate(struct flat_file *file, ssize_t bytes_inc)
{
	int hit_cnt = 0, hit_sz = 0;

	lock_get(global_lock);
	file->record_count++;
	file->bytes_written += (unsigned long)bytes_inc;

	if (file_rotate_count &&
		file->record_count >= file_rotate_count)
		hit_cnt = 1;

	if (!hit_cnt && file_rotate_size &&
		file->bytes_written >= file_rotate_size)
		hit_sz = 1;

	if (hit_cnt || hit_sz) {
		file->rotate_version++;
		file->record_count  = 0;
		file->bytes_written = 0;
		ensure_file_path(file, 1);
	}
	lock_release(global_lock);

	if (hit_cnt || hit_sz) {
		raise_rotation_event(file,
			hit_cnt ? ROTATE_REASON_COUNT : ROTATE_REASON_SIZE);
		ipc_send_rpc_all(event_flatstore_rotate, 0);
	}
}
