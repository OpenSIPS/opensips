/*
 * Copyright (C) 2025 OpenSIPS Solutions
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
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../pt.h"
#include "../../db/db.h"
#include "sockets_mgm.h"
#include "../../reactor_defs.h"
#include "../../reactor_proc.h"
#include "../../io_wait.h"
#include "../../lib/list.h"
#include "../../reactor.h"
#include "../../cfg_reload.h"

/* DB support for loading proxies */
static str sock_mgm_db_url = {NULL, 0};
static str sock_mgm_table = str_init("sockets");
static str sock_mgm_socket_col = str_init("socket");
static str sock_mgm_pool_col = str_init("pool");
static db_con_t *sock_mgm_db_con = NULL;
static db_func_t sock_mgm_db_func;

static OSIPS_LIST_HEAD(sock_mgm_pool_head);
static int sock_mgm_pool_no;
static struct sock_mgm_pool *proc_pool;

static unsigned long *sock_mgm_version;
static gen_lock_t *sock_mgm_version_lock;

enum socket_info_flags {
	SOCK_MGM_INIT    = 0,
	SOCK_MGM_ERROR   = (1 << 0),
	SOCK_MGM_REACTOR = (1 << 1),
};

struct socket_info_mgm {
	enum socket_info_flags flags;
	struct socket_info_full sif;
};

struct sock_mgm_pool {
	str name;
	int procs;
	unsigned long version;
	int procs_rank_start;
	int max_sockets;
	int sockets_last;
	gen_lock_t lock;
	struct list_head list;
	struct list_head sockets_layout;
	proc_export_t *mod_proc;
	int *process_no;
	char *sockets_used;
	struct socket_info_mgm *sockets;
	char desc[SOCKETS_MGM_DEFAULT_POOL_DESC_NAME];
};

static int mod_init(void);
static int mod_load(void);
static int child_init(int rank);
static void destroy(void);

static void sockets_mgm_proc(int rank);
static mi_response_t *mi_sockets_reload(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_sockets_list(const mi_params_t *params,
								struct mi_handler *async_hdl);
static int sock_mgm_pool_add(modparam_t type, void *val);
static struct sock_mgm_pool *sock_mgm_pool_new(str *name);
static int sock_mgm_update_pools(void);
static int sock_mgm_fix_pools(void);
static void rpc_sockets_reload(int sender_id, void *unused);
static void rpc_socket_reload_proc(int sender_id, void *_sock);
static proc_export_t *mod_procs;
static struct sock_mgm_pool *sock_mgm_pool_get(str *name);

static const cmd_export_t cmds[] =
{
	{0,0,{{0,0,0}},0}
};

static const param_export_t params[]={
	{ "db_url",          STR_PARAM, &sock_mgm_db_url.s},
	{ "table_name",      STR_PARAM, &sock_mgm_table.s},
	{ "socket_column",   STR_PARAM, &sock_mgm_socket_col.s},
	{ "pool_column",     STR_PARAM, &sock_mgm_pool_col.s},
	{ "pool",            STR_PARAM|USE_FUNC_PARAM,
		(void*)sock_mgm_pool_add },
	{0,0,0}
};

static const mi_export_t mi_cmds[] = {
	{ "sockets_reload", 0, 0, 0, {
		{mi_sockets_reload, {NULL}},
		{EMPTY_MI_RECIPE}}
	},
	{ "sockets_list", 0, 0, 0, {
		{mi_sockets_list, { NULL}},
		{mi_sockets_list, {"full", NULL}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

/*
static proc_export_t procs[] = {
	{"sockets mgm pool",  0,  0, sockets_mgm_proc, 0,
		PROC_FLAG_INITCHILD|PROC_FLAG_HAS_IPC|PROC_FLAG_NEEDS_SCRIPT},
	{0,0,0,0,0,0}
};
*/

/** module exports */
struct module_exports exports= {
	"sockets_mgm",			/* module name */
	MOD_TYPE_DEFAULT,			/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	mod_load,					/* load function */
	0,							/* OpenSIPS module dependencies */
	cmds,						/* exported functions */
	0,							/* exported asynchronous functions */
	params,						/* exported parameters */
	0,							/* exported statistics */
	mi_cmds,					/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,							/* exported transformations */
	0,							/* extra processes */
	0,							/* module pre-initialization function */
	mod_init,					/* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function)destroy,	/* destroy function */
	child_init,					/* per-child init function */
	0							/* reload-ack function */
};


/**
 * init module function
 */
static int mod_init(void)
{
	LM_NOTICE("initializing sockets management module ...\n");

	/* if not specified, it means that it had never been done anything */
	init_db_url(sock_mgm_db_url , 1 /*can be null*/);

	sock_mgm_table.len = strlen(sock_mgm_table.s);
	sock_mgm_socket_col.len = strlen(sock_mgm_socket_col.s);

	if(db_bind_mod(&sock_mgm_db_url, &sock_mgm_db_func) == -1) {
		LM_ERR("Failed bind to database\n");
		return -1;
	}

	if (!DB_CAPABILITY(sock_mgm_db_func, DB_CAP_QUERY|DB_CAP_FETCH)) {
		LM_ERR("Database module does not implement all functions"
				" needed by sockets_mgm module\n");
		return -1;
	}

	sock_mgm_db_con = sock_mgm_db_func.init(&sock_mgm_db_url);
	if (!sock_mgm_db_con) {
		LM_ERR("Failed to connect to database\n");
		return -1;
	}

	/*verify table versions */
	if(db_check_table_version(&sock_mgm_db_func, sock_mgm_db_con,
			&sock_mgm_table, SOCKETS_MGM_TABLE_VERSION) < 0) {
		LM_ERR("error during table version check\n");
		return -1;
	}

	sock_mgm_version = shm_malloc(sizeof *sock_mgm_version);
	if (!sock_mgm_version) {
		LM_ERR("oom for sock_mgm_version\n");
		return -1;
	}
	*sock_mgm_version = 0;
	sock_mgm_version_lock = lock_alloc();
	if (!sock_mgm_version || !lock_init(sock_mgm_version_lock)) {
		LM_ERR("initializing sock_mgm_version lock\n");
		return -1;
	}

	if (sock_mgm_fix_pools() < 0) {
		LM_ERR("error fixing sockets pools\n");
		return -1;
	}

	sock_mgm_db_func.close(sock_mgm_db_con);
	sock_mgm_db_con = NULL;
	return 0;
}

static int mod_load(void)
{
	static str default_pool = str_init(SOCKETS_MGM_DEFAULT_POOL);

	/* we need to initialize the default pool */
	if (!sock_mgm_pool_new(&default_pool)) {
		LM_ERR("could not add %s pool\n", SOCKETS_MGM_DEFAULT_POOL);
		return -1;
	}
	if (sock_mgm_update_pools() < 0) {
		LM_ERR("could not fix pool's settings\n");
		return -1;
	}
	return 0;
}

static int child_init(int rank)
{
	LM_DBG("initializing sockets management child ...\n");

	if (!sock_mgm_db_func.init) {
		LM_CRIT("database not bound\n");
		return -1;
	}

	sock_mgm_db_con = sock_mgm_db_func.init(&sock_mgm_db_url);
	if (!sock_mgm_db_con) {
		LM_ERR("Failed to connect to database\n");
		return -1;
	}

	LM_DBG("Database connection opened successfully\n");
	LM_NOTICE("Initializing child %d\n", rank);

	/* designate someone else to load sockets and init everyting */
	if (rank == 1 && ipc_dispatch_rpc(rpc_sockets_reload, NULL) < 0) {
		LM_CRIT("could not reload sockets\n");
		return -1;
	}

	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	LM_NOTICE("destroying sockets management module ...\n");
}

struct sock_mgm_db {
	int ref;
	str host;
	int index;
	int port, proto;
	unsigned long version;
	struct sock_mgm_pool *pool;
	struct list_head list;
};

#define sock_mgm_db_list list_head

static struct sock_mgm_db_list *sock_mgm_db_new_list(void)
{
	struct sock_mgm_db_list *lst = pkg_malloc(sizeof *lst);
	if (!lst) {
		LM_ERR("oom for lst\n");
		return NULL;
	}
	memset(lst, 0, sizeof *lst);
	INIT_LIST_HEAD(lst);
	LM_DBG("new sockets list %p\n", lst);
	return lst;
}

static struct sock_mgm_db *sock_mgm_db_new(str *socket, unsigned long version, struct sock_mgm_pool *pool)
{
	str host;
	int port, proto;
	struct sock_mgm_db *db;

	if (parse_phostport(socket->s, socket->len, &host.s, &host.len,
		&port, &proto) != 0) {
		LM_ERR("could not parse socket %.*s\n", socket->len, socket->s);
		return NULL;
	}
	if (proto != PROTO_UDP) {
		LM_ERR("unsupported protocol %s for dynamic sockets\n", proto2a(proto));
		return NULL;
	}

	db = shm_malloc(sizeof *db + host.len + 1);
	if (!db) {
		LM_ERR("oom for a new socket db\n");
		return NULL;
	}
	memset(db, 0, sizeof *db);
	db->version = version;
	db->proto = proto;
	db->port = port;
	db->host.len = host.len;
	db->host.s = (char *)(db + 1);
	memcpy(db->host.s, host.s, host.len);
	db->host.s[host.len] = '\0';
	db->pool = pool;
	db->ref = 1; /* only the current process */
	LM_DBG("sock=%p new\n", db);
	return db;
}

static void sock_mgm_db_free(struct sock_mgm_db *sock, int forced)
{
	LM_DBG("sock=%p ref=%d%s\n", sock, sock->ref, forced?" forced":"");
	if (--sock->ref != 0)
		return;
	LM_DBG("sock=%p free\n", sock);
	sock->pool->sockets_used[sock->index] = 0;
	list_del(&sock->list);
	shm_free(sock);
}

static void sock_mgm_db_move(struct sock_mgm_db *sock, struct list_head *lst)
{
	list_del(&sock->list);
	list_add(&sock->list, lst);
	sock->ref = sock->pool->procs;
	sock->pool->sockets_used[sock->index] = 1;
}

static void sock_mgm_db_destroy_list(struct sock_mgm_db_list *lst)
{
	struct list_head *it, *safe;

	list_for_each_safe(it, safe, lst) {
		sock_mgm_db_free(list_entry(it, struct sock_mgm_db, list), 1);
	}
	pkg_free(lst);
}


/* this is being called with lock taken */
static inline struct sock_mgm_db *sock_mgm_db_find(struct sock_mgm_db *sock)
{
	struct list_head *it;
	struct sock_mgm_db *old;

	list_for_each(it, &sock->pool->sockets_layout) {
		old = list_entry(it, struct sock_mgm_db, list);
		if (old->proto == sock->proto && old->port == sock->port &&
				str_match(&old->host, &sock->host))
			return old;
	}
	return NULL;
}

static inline int sock_mgm_db_index(struct sock_mgm_pool *pool)
{
	int last = (pool->sockets_last + 1) % pool->max_sockets;

	while (1) {
		if (last == pool->sockets_last)
			return -1;
		if (pool->sockets_used[last] == 0)
			break;
		last = (last + 1) % pool->max_sockets;
	}
	pool->sockets_last = last;
	LM_DBG("allocated index %d\n", last);
	return last;
}

static struct sock_mgm_db_list *load_sockets(unsigned long version)
{
	db_key_t colsToReturn[2];
	db_res_t *result = NULL;
	str socket, pool_s;
	int rowCount = 0;
	db_row_t *row;
	struct sock_mgm_db_list *ret = NULL;
	struct sock_mgm_db *head = NULL;
	struct sock_mgm_pool *pool;
	static str default_pool = str_init(SOCKETS_MGM_DEFAULT_POOL);

	colsToReturn[0] = &sock_mgm_socket_col;
	colsToReturn[1] = &sock_mgm_pool_col;

	if (sock_mgm_db_func.use_table(sock_mgm_db_con, &sock_mgm_table) < 0) {
		LM_ERR("Error trying to use %.*s table\n", sock_mgm_table.len, sock_mgm_table.s);
		return NULL;
	}

	if (sock_mgm_db_func.query(sock_mgm_db_con, 0, 0, 0,colsToReturn, 0, 2, 0,
				&result) < 0) {
		LM_ERR("Error querying database\n");
		goto error;
	}

	if (!result) {
		LM_ERR("mysql query failed - NULL result\n");
		return NULL;
	}

	ret = sock_mgm_db_new_list();
	if (!ret) {
		LM_ERR("could not create new list\n");
		goto error;
	}

	if (RES_ROW_N(result)<=0 || RES_ROWS(result)[0].values[0].nul != 0) {
		LM_DBG("No dynamic sockets found found\n");
		goto end;
	}

	for (rowCount=0; rowCount < RES_ROW_N(result); rowCount++) {

		row = &result->rows[rowCount];

		if (VAL_NULL(ROW_VALUES(row))) {
			LM_ERR("NULL socket - skipping\n");
			continue;
		}
		switch (VAL_TYPE(ROW_VALUES(row))) {
			case DB_STR:
				socket = VAL_STR(ROW_VALUES(row));
				break;
			case DB_STRING:
				socket.s = (char *)VAL_STRING(ROW_VALUES(row));
				socket.len = strlen(socket.s);
				break;
			default:
				LM_ERR("unknown socket column type %d\n", VAL_TYPE(ROW_VALUES(row)));
				continue;
		}

		if (!VAL_NULL(ROW_VALUES(row) + 1)) {
			switch (VAL_TYPE(ROW_VALUES(row))) {
				case DB_STR:
					pool_s = VAL_STR(ROW_VALUES(row) + 1);
					break;
				case DB_STRING:
					pool_s.s = (char *)VAL_STRING(ROW_VALUES(row) + 1);
					LM_NOTICE("STRING: %s\n", pool_s.s);
					pool_s.len = strlen(pool_s.s);
					break;
				default:
					LM_ERR("unknown pool column type %d\n", VAL_TYPE(ROW_VALUES(row) + 1));
					continue;
			}
		} else {
			LM_DBG("no pool defined, using %s\n", SOCKETS_MGM_DEFAULT_POOL);
			pool_s = default_pool;
		}
		pool = sock_mgm_pool_get(&pool_s);
		if (!pool) {
			LM_ERR("unknown pool %.*s for socket %.*s\n", pool_s.len, pool_s.s,
					socket.len, socket.s);
			continue;
		}

		head = sock_mgm_db_new(&socket, version, pool);
		if (!head) {
			LM_ERR("could not create new socket struct for %.*s\n",
					socket.len, socket.s);
			continue;
		}
		list_add(&head->list, ret);
	}

end:
	sock_mgm_db_func.free_result(sock_mgm_db_con, result);

	return ret;
error:
	if(result)
		sock_mgm_db_func.free_result(sock_mgm_db_con, result);
	return NULL;
}

static int reload_sockets(void)
{
	int proc;
	struct list_head *it, *safe;
	struct sock_mgm_pool *pool = NULL;
	struct sock_mgm_db_list *lst;
	struct sock_mgm_db *sock, *old;
	unsigned long version;

	lock_get(sock_mgm_version_lock);
	version = ++(*sock_mgm_version);
	lock_release(sock_mgm_version_lock);

	lst = load_sockets(version);
	if (!lst)
		return -1;

	/* we now need to bump the version and update the sockets */
	lock_get(sock_mgm_version_lock);
	if (version != (*sock_mgm_version)) {
		lock_release(sock_mgm_version_lock);
		sock_mgm_db_destroy_list(lst);
		LM_WARN("a more recent version is being reloaded!\n");
		return -2;
	}
	list_for_each_safe(it, safe, lst) {
		sock = list_entry(it, struct sock_mgm_db, list);
		lock_get(&sock->pool->lock);
		old = sock_mgm_db_find(sock);
		if (old) {
			/* we've got the same socket, but might have different values -
			 * update it, but keep the same index */
			sock->index = old->index;
			sock_mgm_db_free(old, 1);
		} else {
			/* alocate a new, free index */
			sock->index = sock_mgm_db_index(sock->pool);
			if (sock->index < 0)
				LM_ERR("no more indexes for socket\n");
		}
		sock_mgm_db_move(sock, &sock->pool->sockets_layout);
		sock->pool->version = version;
		lock_release(&sock->pool->lock);
	}
	lock_release(sock_mgm_version_lock);

	/* we need to reload all of our processes */
	list_for_each(it, &sock_mgm_pool_head) {
		pool = list_entry(it, struct sock_mgm_pool, list);
		for (proc = 0; proc < pool->procs; proc++) {
			/* wait for a process_no */
			while (!pool->process_no[proc])
				usleep(10); /* TODO: add some guards here */
			if (ipc_send_rpc(pool->process_no[proc], rpc_socket_reload_proc,
					(void *)(unsigned long)version) < 0)
				LM_ERR("could not inform process about socket changes\n");
		}
	}
	sock_mgm_db_destroy_list(lst);
	return 0;
}

static mi_response_t *mi_sockets_reload(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	if (reload_sockets() < 0)
		return init_mi_error(500, MI_SSTR("Could not reload sockets"));

	return init_mi_result_ok();
}

static mi_response_t *mi_sockets_list(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int full;
	switch (try_get_mi_int_param(params, "full", &full)) {
	case -2:
		full = 0;
	case -1:
		return init_mi_param_error();
	default:
		break;
	}
	/* TODO: list */
	return init_mi_error(500, MI_SSTR("Not implemented yet"));

	return init_mi_result_ok();
}

static struct sock_mgm_pool *sock_mgm_pool_new(str *name)
{
	struct sock_mgm_pool *pool = NULL;

	pool = shm_malloc(sizeof *pool);
	if (!pool) {
		LM_ERR("oom for pool\n");
		return NULL;
	}
	memset(pool, 0, sizeof *pool);
	if (!lock_init(&pool->lock)) {
		LM_ERR("cannot init lock\n");
		goto release;
	}
	pool->name = *name;
	pool->procs = SOCKETS_MGM_DEFAULT_POOL_PROCESSES;
	pool->max_sockets = SOCKETS_MGM_DEFAULT_POOL_MAX_SOCKS;
	list_add(&pool->list, &sock_mgm_pool_head);
	INIT_LIST_HEAD(&pool->sockets_layout);

	/* add new proc to modules proc */
	if (mod_procs)
		mod_procs = pkg_realloc(mod_procs,
				(sock_mgm_pool_no + 2) * sizeof(proc_export_t));
	else
		mod_procs = pkg_malloc((sock_mgm_pool_no + 2) * sizeof(proc_export_t));
	if (!mod_procs) {
		LM_ERR("oom for new proc\n");
		goto release;
	}
	memset(mod_procs + sock_mgm_pool_no, 0, 2 * sizeof(proc_export_t));
	pool->mod_proc = mod_procs + sock_mgm_pool_no;
	exports.procs = mod_procs;
	sock_mgm_pool_no++;
	return pool;
release:
	shm_free(pool);
	return NULL;
}

static struct sock_mgm_pool *sock_mgm_pool_get(str *name)
{
	struct sock_mgm_pool *pool = NULL;
	struct list_head *it;

	list_for_each(it, &sock_mgm_pool_head) {
		pool = list_entry(it, struct sock_mgm_pool, list);
		if (!str_strcasecmp(&pool->name, name))
			return pool;
	}
	return NULL;
}

static struct sock_mgm_pool *sock_mgm_pool_get_by_rank(int rank)
{
	struct sock_mgm_pool *pool = NULL;
	struct list_head *it;

	list_for_each(it, &sock_mgm_pool_head) {
		pool = list_entry(it, struct sock_mgm_pool, list);
		if (rank >= pool->procs_rank_start &&
				rank < pool->procs_rank_start + pool->procs)
			return pool;
	}
	return NULL;
}

static struct sock_mgm_pool *sock_mgm_pool_parse(str *pool_s)
{
	/* TODO: FIXME */
	str name = str_init(SOCKETS_MGM_DEFAULT_POOL);
	struct sock_mgm_pool *pool = NULL;

	/* TODO: parse pool name */
	pool = sock_mgm_pool_get(&name);
	if (!pool) {
		pool = sock_mgm_pool_new(&name);
		if (!pool) {
			LM_ERR("could not create new pool\n");
			return NULL;
		}
	}
	/* TODO: parse */
	str2int(pool_s, (unsigned int *)&pool->procs);

	if (sock_mgm_update_pools() < 0) {
		LM_ERR("could not fix pool's settings\n");
		return NULL;
	}
	return pool;
}

static int sock_mgm_pool_add(modparam_t type, void *val)
{
	str pool_s;
	struct sock_mgm_pool *pool;

	pool_s.s = (char *)val;
	pool_s.len = strlen(pool_s.s);

	pool = sock_mgm_pool_parse(&pool_s);
	if (!pool) {
		LM_ERR("could not parse pool parameter: %s\n", (char *)val);
		return -1;
	}
	return 1;
}

static int sock_mgm_fix_pools(void)
{
	struct list_head *it;
	struct sock_mgm_pool *pool = NULL;

	list_for_each(it, &sock_mgm_pool_head) {
		pool = list_entry(it, struct sock_mgm_pool, list);

		pool->sockets_last = pool->max_sockets;

		pool->process_no = shm_malloc(pool->procs * sizeof *pool->process_no);
		if (!pool->process_no) {
			LM_ERR("oom for process_no!\n");
			goto error;
		}
		memset(pool->process_no, 0, pool->procs * sizeof *pool->process_no);

		pool->sockets_used = shm_malloc(pool->max_sockets * sizeof *pool->sockets_used);
		if (!pool->sockets_used) {
			LM_ERR("oom for sockets_used!\n");
			goto error;
		}
		memset(pool->process_no, 0, pool->max_sockets * sizeof *pool->sockets_used);

		pool->sockets = pkg_malloc(pool->max_sockets * sizeof *pool->sockets);
		if (!pool->sockets) {
			LM_ERR("oom for sockets!\n");
			goto error;
		}
		memset(pool->sockets, 0, pool->max_sockets * sizeof *pool->sockets);
	}
	return 0;
error:
	if (pool->lock)
		lock_destroy(pool->lock);
	if (pool->process_no)
		shm_free(pool->process_no);
	if (pool->sockets_used)
		shm_free(pool->sockets_used);
	return -1;
}

static int sock_mgm_update_pools(void)
{
	int procs_no = 0;
	struct list_head *it;
	struct sock_mgm_pool *pool = NULL;
	str desc_prefix = str_init("Sockets Management ");
	str desc_suffix = str_init(" pool");
	str desc_name;

	list_for_each(it, &sock_mgm_pool_head) {
		pool = list_entry(it, struct sock_mgm_pool, list);
		pool->procs_rank_start = procs_no;
		procs_no += pool->procs;
		pool->mod_proc->no = pool->procs;
		/* if name already built, continue */
		if (pool->mod_proc->name)
			continue;
		pool->mod_proc->function = sockets_mgm_proc;
		pool->mod_proc->no = pool->procs;
		pool->mod_proc->flags =
			PROC_FLAG_INITCHILD|PROC_FLAG_HAS_IPC|PROC_FLAG_NEEDS_SCRIPT;
		desc_name = pool->name;
		if (desc_prefix.len + desc_name.len + desc_suffix.len + 1 >
				SOCKETS_MGM_DEFAULT_POOL_DESC_NAME) {
			desc_name.len = SOCKETS_MGM_DEFAULT_POOL_DESC_NAME - desc_prefix.len -
				desc_suffix.len - 1;
			if (desc_name.len < 0) {
				LM_BUG("increase SOCKETS_MGM_DEFAULT_POOL_DESC_NAME to fit pool name\n");
				return -1;
			}
		}
		memcpy(pool->desc, desc_prefix.s, desc_prefix.len);
		memcpy(pool->desc + desc_prefix.len, desc_name.s, desc_name.len);
		memcpy(pool->desc + desc_prefix.len + desc_name.len, desc_suffix.s, desc_suffix.len);
		pool->mod_proc->name = pool->desc;
	}
	return 0;
}

inline static int handle_io(struct fd_map* fm, int idx,int event_type)
{
	int n = 0;
	int read;

	pt_become_active();

	pre_run_handle_script_reload(fm->app_flags);

	switch(fm->type){
		case F_UDP_READ:
			n = protos[((struct socket_info*)fm->data)->proto].net.
				dgram.read( fm->data /*si*/, &read);
			break;
		case F_SCRIPT_ASYNC:
			async_script_resume_f( fm->fd, fm->data,
				(event_type==IO_WATCH_TIMEOUT)?1:0 );
			break;
		case F_FD_ASYNC:
			async_fd_resume( fm->fd, fm->data);
			break;
		case F_LAUNCH_ASYNC:
			async_launch_resume( fm->fd, fm->data);
			break;
		case F_IPC:
			ipc_handle_job(fm->fd);
			break;
		default:
			LM_CRIT("unknown fd type %d in UDP worker\n", fm->type);
			n = -1;
			break;
	}

	if (reactor_is_empty() && _termination_in_progress==1) {
		LM_WARN("reactor got empty while termination in progress\n");
		ipc_handle_all_pending_jobs(IPC_FD_READ_SELF);
		if (reactor_is_empty())
			dynamic_process_final_exit();
	}

	post_run_handle_script_reload();

	pt_become_idle();
	return n;
}

static void sockets_mgm_proc(int rank)
{
	proc_pool = sock_mgm_pool_get_by_rank(rank);
	if (!proc_pool) {
		LM_BUG("no pool available for rank %d\n", rank);
		return;
	}
	LM_DBG("registering process_no in pool\n");
	proc_pool->process_no[rank - proc_pool->procs_rank_start] = process_no;

	/* create a custom reactor reactor */
	if (init_worker_reactor(proc_pool->desc, RCT_PRIO_MAX)<0 ) {
		LM_ERR("failed to init reactor\n");
		goto error;
	}

	/* init: start watching for the IPC jobs */
	if (reactor_add_reader(IPC_FD_READ_SELF, F_IPC, RCT_PRIO_ASYNC, NULL)<0){
		LM_CRIT("failed to add IPC pipe to reactor\n");
		goto error;
	}

	reactor_main_loop(REACTOR_PROC_TIMEOUT, error,);
error:
	destroy_worker_reactor();
}

static void rpc_sockets_reload(int sender_id, void *unused)
{
	if (reload_sockets() < 0)
		LM_ERR("could not reload sockets\n");
}

static int sock_mgm_fill_socket(struct sock_mgm_db *sock, struct socket_info_full *sif)
{
	struct socket_info *si = &sif->socket_info;
	memset(sif, 0, sizeof(*sif));
	si->socket=-1;
	if (pkg_nt_str_dup(&si->name, &sock->host) < 0) {
		LM_ERR("oom for si name\n");
		return -1;
	}
	si->last_real_ports = &sif->last_real_ports;
	si->port_no=sock->port;
	si->proto=sock->proto;
	//si->flags=sock->flags;
	return 0;
}

static int sock_mgm_update_socket(struct sock_mgm_db *sock, struct socket_info_full *sif)
{
	//struct socket_info *si = &sif->socket_info;
	return 0;
}

static void rpc_socket_reload_proc(int sender_id, void *_ver)
{
	unsigned long version = (unsigned long)_ver;
	struct socket_info_full *sif;
	struct socket_info_mgm *sim;
	struct socket_info *si;
	struct sock_mgm_db *sock;
	struct list_head *it, *safe;

	LM_NOTICE("Reloading process for version %lu\n", version);
	lock_get(&proc_pool->lock);
	if (proc_pool->version > version) {
		LM_WARN("new version %lu available\n", proc_pool->version);
		goto release;
	}

	lock_release(&proc_pool->lock);
	list_for_each_safe(it, safe, &proc_pool->sockets_layout) {
		sock = list_entry(it, struct sock_mgm_db, list);
		sim = &sock->pool->sockets[sock->index];
		sif = &sim->sif;
		si = &sif->socket_info;
		if (sock->version < version) {
			if (sim->flags & SOCK_MGM_REACTOR) {
				LM_DBG("removing socket %d from reactor (%p)\n", si->socket, sock);
				if (reactor_del_reader(si->socket, -1, IO_FD_CLOSING)<0) {
					LM_ERR("could not add to reactor\n");
					continue;
				}
				close(si->socket);
				sim->flags &= ~SOCK_MGM_REACTOR;
			}
			sock_mgm_db_free(sock, 0);
			free_sock_info(sif);
			continue;
		}
		if (!(sim->flags & SOCK_MGM_REACTOR)) {
			if (sock_mgm_fill_socket(sock, sif) < 0) {
				LM_ERR("could not create socket_info_full struct for socket\n");
				sim->flags |= SOCK_MGM_ERROR;
				free_sock_info(sif);
				continue;
			}
			if (is_localhost(si))
				si->flags |= SI_IS_LO;
			if (fix_socket(sif, 0) < 0) {
				LM_ERR("could not fix socket\n");
				sim->flags |= SOCK_MGM_ERROR;
				free_sock_info(sif);
				continue;
			}
			if (protos[sock->proto].tran.init_listener(si) < 0) {
				LM_ERR("failed to init listener [%.*s], proto %s\n",
					si->name.len, si->name.s,
					protos[sock->proto].name);
				sim->flags |= SOCK_MGM_ERROR;
				free_sock_info(sif);
				continue;
			}
			LM_DBG("adding socket %d to reactor (%p)\n", si->socket, sock);
			if (reactor_add_reader(si->socket, F_UDP_READ, RCT_PRIO_NET, si)<0) {
				LM_ERR("could not add to reactor\n");
				sim->flags |= SOCK_MGM_ERROR;
				close(si->socket);
				free_sock_info(sif);
				continue;
			}
			sim->flags |= SOCK_MGM_REACTOR;
		} else {
			sock_mgm_update_socket(sock, sif);
		}
	}
release:
	lock_release(&proc_pool->lock);
}
