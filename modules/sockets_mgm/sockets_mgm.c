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
#include <netinet/ip.h>

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
#include "../../net/tcp_passfd.h"
#include "../../mod_fix.h"

#define SOCKET_MGM_INTERNAL_TIMEOUT 100000 /* microseconds */
#define SOCKET_MGM_INTERNAL_INCREMENT 10   /* microseconds */
#define SOCKET_MGM_INTERNAL_RETRY \
	(SOCKET_MGM_INTERNAL_TIMEOUT/SOCKET_MGM_INTERNAL_INCREMENT)

/* DB support for loading proxies */
static str sock_mgm_db_url = {NULL, 0};
static str sock_mgm_table = str_init("sockets");
static str sock_mgm_socket_col = str_init("socket");
static str sock_mgm_adv_col = str_init("advertised");
static str sock_mgm_tag_col = str_init("tag");
static str sock_mgm_flags_col = str_init("flags");
static str sock_mgm_tos_col = str_init("tos");
static db_con_t *sock_mgm_db_con = NULL;
static db_func_t sock_mgm_db_func;

static unsigned long *sock_mgm_version;
static unsigned int sock_mgm_max_sockets = SOCKETS_MGM_DEFAULT_MAX_SOCKS;
static gen_lock_t *sock_mgm_lock;
static int *sock_mgm_proc_no;
static int sock_mgm_unix[2];
extern int is_tcp_main;

enum socket_info_flags {
	SOCK_MGM_NEW     = 0,
	SOCK_MGM_INIT    = (1 << 0),
	SOCK_MGM_FREE    = (1 << 1),
	SOCK_MGM_ERROR   = (1 << 2),
	SOCK_MGM_REACTOR = (1 << 3),
};

struct socket_info_mgm {
	enum socket_info_flags flags;
	struct socket_info_full sif;
};

static struct sock_mgm_pool {
	unsigned int last_index;
	struct list_head running;
	char *used;
} *sockets_pool;
struct socket_info_mgm *sockets_info;

static int mod_init(void);
static int child_init(int rank);
static void destroy(void);

static int sockets_pool_init(void);
static void sockets_mgm_proc(int rank);
static mi_response_t *mi_sockets_reload(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_sockets_list(const mi_params_t *params,
								struct mi_handler *async_hdl);
static int sock_mgm_procs_func(modparam_t type, void *val);
static void rpc_sockets_reload(int sender_id, void *unused);
static void rpc_sockets_send(int sender_id, void *_sock);
static void rpc_socket_reload_proc(int sender_id, void *_ver);

static const cmd_export_t cmds[] =
{
	{0,0,{{0,0,0}},0}
};

static proc_export_t procs[] = {
	{"sockets mgm pool",  0,  0, sockets_mgm_proc, SOCKETS_MGM_DEFAULT_PROCESSES,
		PROC_FLAG_INITCHILD|PROC_FLAG_HAS_IPC|PROC_FLAG_NEEDS_SCRIPT},
	{0,0,0,0,0,0}
};

static const param_export_t params[]={
	{ "db_url",           STR_PARAM, &sock_mgm_db_url.s},
	{ "table_name",       STR_PARAM, &sock_mgm_table.s},
	{ "socket_column",    STR_PARAM, &sock_mgm_socket_col.s},
	{ "advertised_column",STR_PARAM, &sock_mgm_adv_col.s},
	{ "tag_column",       STR_PARAM, &sock_mgm_tag_col.s},
	{ "flags_column",     STR_PARAM, &sock_mgm_flags_col.s},
	{ "tos_column",       STR_PARAM, &sock_mgm_tos_col.s},
	{ "processes",        INT_PARAM|USE_FUNC_PARAM,
		&sock_mgm_procs_func},
	{ "max_sockets",      INT_PARAM, &sock_mgm_max_sockets},
	{0,0,0}
};

static const mi_export_t mi_cmds[] = {
	{ "sockets_reload", 0, 0, 0, {
		{mi_sockets_reload, {NULL}},
		{EMPTY_MI_RECIPE}}
	},
	{ "sockets_list", 0, 0, 0, {
		{mi_sockets_list, {NULL}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

/** module exports */
struct module_exports exports= {
	"sockets_mgm",			/* module name */
	MOD_TYPE_DEFAULT,			/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* load function */
	0,							/* OpenSIPS module dependencies */
	cmds,						/* exported functions */
	0,							/* exported asynchronous functions */
	params,						/* exported parameters */
	0,							/* exported statistics */
	mi_cmds,					/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,							/* exported transformations */
	procs,						/* extra processes */
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
	sock_mgm_adv_col.len = strlen(sock_mgm_adv_col.s);
	sock_mgm_tag_col.len = strlen(sock_mgm_tag_col.s);
	sock_mgm_flags_col.len = strlen(sock_mgm_flags_col.s);
	sock_mgm_tos_col.len = strlen(sock_mgm_tos_col.s);

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
	sock_mgm_proc_no = shm_malloc(sizeof *sock_mgm_proc_no);
	if (!sock_mgm_proc_no) {
		LM_ERR("oom for sock_mgm_proc_no\n");
		return -1;
	}
	*sock_mgm_proc_no = -1;
	sock_mgm_lock = lock_alloc();
	if (!sock_mgm_version || !lock_init(sock_mgm_lock)) {
		LM_ERR("initializing sock_mgm_version lock\n");
		return -1;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock_mgm_unix) < 0) {
		LM_ERR("socketpair failed %d/%s\n",
			errno, strerror(errno));
		return -1;
	}

	if (sockets_pool_init() < 0) {
		LM_ERR("initializing sockets pool\n");
		return -1;
	}

	sock_mgm_db_func.close(sock_mgm_db_con);
	sock_mgm_db_con = NULL;
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

	if (rank != PROC_MODULE) {
		close(sock_mgm_unix[1]);
		sock_mgm_unix[1] = -1;
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

struct sock_mgm {
	int ref;
	str host;
	int index;
	int port, proto;
	str socket;
	str adv, tag;
	str adv_str;
	str adv_port_str;
	int adv_port;
	int tos;
	unsigned int flags;
	unsigned long version;
	struct list_head list;
};

#define sock_mgm_list list_head

static struct sock_mgm_list *sock_mgm_new_list(void)
{
	struct sock_mgm_list *lst = pkg_malloc(sizeof *lst);
	if (!lst) {
		LM_ERR("oom for lst\n");
		return NULL;
	}
	memset(lst, 0, sizeof *lst);
	INIT_LIST_HEAD(lst);
	LM_DBG("new sockets list %p\n", lst);
	return lst;
}

static struct sock_mgm *sock_mgm_new(str *socket, str *adv, int adv_port,
		str *tag, unsigned int flags, int tos)
{
	str host;
	int port, proto;
	struct sock_mgm *sock;
	str port_str;
	char *p;

	if (parse_phostport(socket->s, socket->len, &host.s, &host.len,
		&port, &proto) != 0) {
		LM_ERR("could not parse socket %.*s\n", socket->len, socket->s);
		return NULL;
	}
	if (!is_sip_proto(proto)) {
		LM_ERR("unsupported protocol %s for dynamic sockets\n", proto2a(proto));
		return NULL;
	}
	if (adv->len) {
		if (!adv_port)
			adv_port = port;
		port_str.s = int2str(adv_port, &port_str.len);
	} else {
		port_str = str_init("");
	}

	sock = shm_malloc(sizeof *sock + socket->len +
			host.len + 1 /* '\0' */ +
			tag->len + 1 /* '\0' */ +
			2 * (adv->len + 1 /* '\0' */ +
			     port_str.len + 1 /* '\0' */));
	if (!sock) {
		LM_ERR("oom for a new socket sock\n");
		return NULL;
	}
	memset(sock, 0, sizeof *sock);
	sock->proto = proto;
	sock->port = port;
	sock->socket.s = (char *)(sock + 1);
	sock->socket.len = socket->len;
	memcpy(sock->socket.s, socket->s, socket->len);
	sock->host.s = sock->socket.s + socket->len;
	sock->host.len = host.len;
	memcpy(sock->host.s, host.s, host.len);
	sock->host.s[host.len] = '\0';
	p = sock->host.s + sock->host.len + 1;
	sock->adv_port = adv_port;
	if (tag->len) {
		sock->tag.s = p;
		memcpy(sock->tag.s, tag->s, tag->len);
		sock->tag.len = tag->len;
		sock->tag.s[sock->tag.len] = '\0';
		p += tag->len + 1;
	}
	if (adv->len) {
		sock->adv.s = p;
		memcpy(sock->adv.s, adv->s, adv->len);
		sock->adv.len = adv->len;
		sock->adv.s[sock->adv.len] = '\0';
		p += adv->len + 1;
		sock->adv_port_str.s = p;
		memcpy(sock->adv_port_str.s, port_str.s, port_str.len);
		sock->adv_port_str.len = port_str.len;
		sock->adv_port_str.s[sock->adv_port_str.len] = '\0';
		p += port_str.len + 1;
		sock->adv_str.s = p;
		sock->adv_str.len = adv->len;
		memcpy(sock->adv_str.s, adv->s, adv->len);
		sock->adv_str.s[sock->adv_str.len++] = ':';
		p += sock->adv_str.len;
		memcpy(p, port_str.s, port_str.len);
		sock->adv_str.len += port_str.len;
		sock->adv_str.s[sock->adv_str.len] = '\0';
	}
	sock->flags = flags;
	sock->tos = tos;
	sock->index = -1;
	sock->ref = 1; /* the current process */
	LM_DBG("sock=%p new\n", sock);
	return sock;
}

static void sock_mgm_free(struct sock_mgm *sock)
{
	if (--sock->ref != 0)
		return;
	LM_DBG("sock=%p(%.*s) free\n", sock, sock->socket.len, sock->socket.s);
	if (sock->index >= 0) {
		sockets_pool->used[sock->index] = 0;
		LM_DBG("sock=%p(%.*s) release slot %d\n", sock,
				sock->socket.len, sock->socket.s, sock->index);
	}
	list_del(&sock->list);
	shm_free(sock);
}

static void sock_mgm_use(struct sock_mgm *sock)
{
	list_del(&sock->list);
	list_add_tail(&sock->list, &sockets_pool->running);
}

static void sock_mgm_add_listener(struct socket_info_full *sif)
{
	push_sock2list(sif);
	update_default_socket_info(&sif->socket_info);
}

static void sock_mgm_rm_listener(struct socket_info_full *sif)
{
	pop_sock2list(sif);
	remove_default_socket_info(&sif->socket_info);
}


static void sock_mgm_list_cleanup(struct sock_mgm_list *lst)
{
	struct list_head *it, *safe;

	list_for_each_safe(it, safe, lst)
		sock_mgm_free(list_entry(it, struct sock_mgm, list));
	pkg_free(lst);
}


/* this is being called with lock taken */
static inline int sock_mgm_match(struct sock_mgm *sock1, struct sock_mgm *sock2)
{
	if (sock1->proto != sock2->proto)
		return 0;
	if (sock1->port != sock2->port)
		return 0;
	if (!str_match(&sock1->host, &sock2->host))
		return 0;
	if (!str_match(&sock1->adv_str, &sock2->adv_str))
		return 0;
	if (!str_match(&sock1->tag, &sock2->tag))
		return 0;
	if (sock1->tos != sock2->tos)
		return 0;
	if (sock1->flags != sock2->flags)
		return 0;
	return 1;
}

static inline struct sock_mgm *sock_mgm_find(struct sock_mgm *sock)
{
	struct list_head *it;
	struct sock_mgm *old;

	list_for_each(it, &sockets_pool->running) {
		old = list_entry(it, struct sock_mgm, list);
		if (sock_mgm_match(sock, old))
			return old;
	}
	return NULL;
}

static inline int sock_mgm_get_index(void)
{
	int last = (sockets_pool->last_index + 1) % sock_mgm_max_sockets;

	while (1) {
		if (last == sockets_pool->last_index)
			return -1;
		if (!sockets_pool->used[last])
			break;
		last = (last + 1) % sock_mgm_max_sockets;
	}
	sockets_pool->last_index = last;
	sockets_pool->used[last] = 1;
	LM_DBG("allocated index %d\n", last);
	return last;
}

static int sock_mgm_parse_adv(str *adv, int *adv_port)
{
	char *p = q_memchr(adv->s, ':', adv->len);
	str tmp;

	if (!p) {
		*adv_port = 0;
		return 0;
	}
	tmp.s = p + 1;
	tmp.len = adv->s + adv->len - tmp.s;
	adv->len = p - adv->s;
	if (tmp.len <= 0)
		return -1;
	if (str2sint(&tmp, adv_port) < 0)
		return -1;
	LM_DBG("advertised socket: %.*s:%d\n", adv->len, adv->s, *adv_port);
	return 0;
}

static str sock_mgm_flag_names[] = {
	str_init("anycast"),   /* SI_ANYCAST */
	str_init("frag"),      /* SI_FRAG */
	str_init("reuse_port"),/* SI_REUSEPORT */
	STR_NULL
};

static int sock_mgm_parse_flags(str *adv, unsigned int *flags)
{
	void *param = adv;
	unsigned int tmp;
	*flags = 0;
	if (fixup_named_flags(&param, sock_mgm_flag_names, NULL, NULL) < 0) {
		LM_ERR("Failed to parse flags\n");
		return -1;
	}
	tmp = (unsigned int)(unsigned long)(void *)param;
	/* translate to SI flags */
	if (tmp & 0x1)
		*flags |=  SI_IS_ANYCAST;
	if (tmp & 0x2)
		*flags |=  SI_FRAG;
	if (tmp & 0x4)
		*flags |=  SI_REUSEPORT;
	return 0;
}

static str *sock_mgm_print_flags(unsigned int flags)
{
	static char buf[256];
	static str sflags = { NULL, 0};
	char *p = buf;
	if (!sflags.s)
		sflags.s = buf;
	if (flags & SI_IS_ANYCAST) {
		memcpy(p, "anycast", 7);
		p += 7;
	}
	if (flags & SI_FRAG) {
		if (p != buf)
			*p++ = ',';
		memcpy(p, "frag", 4);
		p += 4;
	}
	if (flags & SI_REUSEPORT) {
		if (p != buf)
			*p++ = ',';
		memcpy(p, "reuse_port", 11);
		p += 11;
	}
	sflags.len = p - buf;

	return &sflags;
}

static int sock_mgm_parse_tos(str *adv, int *tos)
{
	*tos = 0;
	if (str_match(adv, const_str("IPTOS_LOWDELAY")))
		*tos = IPTOS_LOWDELAY;
	else if (str_match(adv, const_str("IPTOS_THROUGHPUT")))
		*tos = IPTOS_THROUGHPUT;
	else if (str_match(adv, const_str("IPTOS_RELIABILITY")))
		*tos = IPTOS_RELIABILITY;
#if defined(IPTOS_MINCOST)
	else if (str_match(adv, const_str("IPTOS_MINCOST")))
		*tos = IPTOS_MINCOST;
#endif
#if defined(IPTOS_LOWCOST)
	else if (str_match(adv, const_str("IPTOS_LOWCOST")))
		*tos = IPTOS_LOWCOST;
#endif
	return 0;
}

static struct sock_mgm_list *load_sockets(void)
{
	db_key_t colsToReturn[5];
	db_res_t *result = NULL;
	str socket;
	str adv, tag, tmp;
	int adv_port = 0;
	int rowCount = 0;
	db_row_t *row;
	int tos;
	unsigned int flags;
	struct sock_mgm_list *ret = NULL;
	struct sock_mgm *head = NULL;

	colsToReturn[0] = &sock_mgm_socket_col;
	colsToReturn[1] = &sock_mgm_adv_col;
	colsToReturn[2] = &sock_mgm_tag_col;
	colsToReturn[3] = &sock_mgm_flags_col;
	colsToReturn[4] = &sock_mgm_tos_col;

	if (sock_mgm_db_func.use_table(sock_mgm_db_con, &sock_mgm_table) < 0) {
		LM_ERR("Error trying to use %.*s table\n", sock_mgm_table.len, sock_mgm_table.s);
		return NULL;
	}

	if (sock_mgm_db_func.query(sock_mgm_db_con, 0, 0, 0,colsToReturn, 0, 5, 0,
				&result) < 0) {
		LM_ERR("Error querying database\n");
		goto error;
	}

	if (!result) {
		LM_ERR("mysql query failed - NULL result\n");
		return NULL;
	}

	ret = sock_mgm_new_list();
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
			switch (VAL_TYPE(ROW_VALUES(row) + 1)) {
				case DB_STR:
					adv = VAL_STR(ROW_VALUES(row) + 1);
					break;
				case DB_STRING:
					adv.s = (char *)VAL_STRING(ROW_VALUES(row) + 1);
					adv.len = strlen(adv.s);
					break;
				default:
					LM_ERR("unknown advertised column type %d\n", VAL_TYPE(ROW_VALUES(row) + 1));
					continue;
			}
			if (sock_mgm_parse_adv(&adv, &adv_port) < 0) {
				LM_ERR("could not parse advertised column %.*s\n", adv.len, adv.s);
				continue;
			}
		} else {
			adv = str_init("");
			adv_port = 0;
		}

		if (!VAL_NULL(ROW_VALUES(row) + 2)) {
			switch (VAL_TYPE(ROW_VALUES(row) + 2)) {
				case DB_STR:
					tag = VAL_STR(ROW_VALUES(row) + 2);
					break;
				case DB_STRING:
					tag.s = (char *)VAL_STRING(ROW_VALUES(row) + 2);
					tag.len = strlen(tag.s);
					break;
				default:
					LM_ERR("unknown tag column type %d\n", VAL_TYPE(ROW_VALUES(row) + 2));
					continue;
			}
		} else {
			tag = str_init("");
		}

		if (!VAL_NULL(ROW_VALUES(row) + 3)) {
			switch (VAL_TYPE(ROW_VALUES(row) + 3)) {
				case DB_STR:
					tmp = VAL_STR(ROW_VALUES(row) + 3);
					break;
				case DB_STRING:
					tmp.s = (char *)VAL_STRING(ROW_VALUES(row) + 3);
					tmp.len = strlen(tmp.s);
					break;
				default:
					LM_ERR("unknown flags column type %d\n", VAL_TYPE(ROW_VALUES(row) + 3));
					continue;
			}
			if (sock_mgm_parse_flags(&tmp, &flags) < 0) {
				LM_ERR("could not parse flags column %.*s\n", tmp.len, tmp.s);
				continue;
			}
		} else {
			flags = 0;
		}

		if (!VAL_NULL(ROW_VALUES(row) + 4)) {
			switch (VAL_TYPE(ROW_VALUES(row) + 4)) {
				case DB_STR:
					tmp = VAL_STR(ROW_VALUES(row) + 4);
					break;
				case DB_STRING:
					tmp.s = (char *)VAL_STRING(ROW_VALUES(row) + 4);
					tmp.len = strlen(tmp.s);
					break;
				default:
					LM_ERR("unknown tos column type %d\n", VAL_TYPE(ROW_VALUES(row) + 4));
					continue;
			}
			if (sock_mgm_parse_tos(&tmp, &tos) < 0) {
				LM_ERR("could not parse tos column %.*s\n", tmp.len, tmp.s);
				continue;
			}
		} else {
			tos = 0;
		}

		head = sock_mgm_new(&socket, &adv, adv_port, &tag, flags, tos);
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
	struct list_head *it, *safe;
	struct sock_mgm_list *lst;
	struct sock_mgm *sock, *old;
	unsigned long version;
	int changes = 0;

	lst = load_sockets();
	if (!lst)
		return -1;

	/* we now need to bump the version and update the sockets */
	lock_get(sock_mgm_lock);
	version = ++(*sock_mgm_version);

	list_for_each_safe(it, safe, lst) {
		sock = list_entry(it, struct sock_mgm, list);
		old = sock_mgm_find(sock);
		if (!old) {
			/* alocate a new, free index */
			sock->index = sock_mgm_get_index();
			if (sock->index < 0) {
				LM_ERR("no more indexes for socket\n");
				continue;
			}
			sock_mgm_use(sock);
			sock->version = version;
			LM_DBG("new %p with version %lu\n", sock, version);
			changes = 1;
		} else {
			LM_DBG("update %p with version %lu\n", old, version);
			old->version = version;
		}
	}
	/* now go through each socket and remove any with an older version */
	list_for_each_safe(it, safe, &sockets_pool->running) {
		sock = list_entry(it, struct sock_mgm, list);
		if (sock->version < version) {
			sock_mgm_free(sock);
			changes = 1;
		}
	}
	lock_release(sock_mgm_lock);
	sock_mgm_list_cleanup(lst);

	/* now inform all processes about the changes */
	if (changes)
		ipc_send_rpc_all(rpc_socket_reload_proc, (void *)(unsigned long)version);
	else
		LM_DBG("no socket changes\n");
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
	struct list_head *it;
	struct sock_mgm *sock;
	mi_response_t *resp;
	mi_item_t *arr, *item;
	str *flags;

	resp = init_mi_result_array(&arr);
	if (!resp)
		return 0;

	lock_get(sock_mgm_lock);
	list_for_each(it, &sockets_pool->running) {
		sock = list_entry(it, struct sock_mgm, list);
		item = add_mi_object(arr, NULL, 0);
		if (!item)
			goto error;
		if (add_mi_string(item, MI_SSTR("socket"), sock->socket.s, sock->socket.len) < 0)
			goto error;
		if (sock->adv_str.len && add_mi_string(item, MI_SSTR("advertised"),
				sock->adv_str.s, sock->adv_str.len) < 0)
			goto error;
		if (sock->tag.len && add_mi_string(item, MI_SSTR("tag"),
				sock->tag.s, sock->tag.len) < 0)
			goto error;
		if (sock->flags) {
			flags = sock_mgm_print_flags(sock->flags);
			if (add_mi_string(item, MI_SSTR("flags"),
					flags->s, flags->len) < 0)
				goto error;
		}
		if (sock->tos && add_mi_number(item, MI_SSTR("tos"), sock->tos) < 0)
			goto error;
	}
	lock_release(sock_mgm_lock);

	return resp;
error:
	lock_release(sock_mgm_lock);
	if (resp)
		free_mi_response(resp);
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

static int sock_mgm_dynamic_proc = 0;
static void sockets_mgm_proc(int rank)
{
	sock_mgm_dynamic_proc = 1;
	/* the first one advertises itself as the proc_no, so that the other
	 * static workers can come and ask for socket information */
	if (*sock_mgm_proc_no < 0)
		*sock_mgm_proc_no = process_no;

	close(sock_mgm_unix[0]);
	sock_mgm_unix[0] = -1;

	/* create a custom reactor reactor */
	if (init_worker_reactor("Sockets Management", RCT_PRIO_MAX)<0 ) {
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

static void rpc_sockets_send(int sender_id, void *_sock)
{
	int fd;
	struct sock_mgm *sock = _sock;
	struct socket_info_mgm *sim = &sockets_info[sock->index];

	if (sim->flags & SOCK_MGM_INIT)
		fd = sim->sif.socket_info.socket;
	else if (sim->flags & SOCK_MGM_ERROR)
		fd = -1;
	/* else loop it back, until we get it initialized */
	else if (ipc_send_rpc(process_no, rpc_sockets_send, sock) < 0)
		fd = -1;
	else
		return; /* here we've successfully dispatched the job */

	/* we're interested in the local socket for this particular socket */
	if (send_fd(sock_mgm_unix[1], &sock, sizeof(sock), fd) < 0)
		LM_CRIT("Could not pass fd to %d\n", sender_id);
}

static int sock_mgm_fill_socket(struct sock_mgm *sock, struct socket_info_full *sif)
{
	struct socket_info *si = &sif->socket_info;
	memset(sif, 0, sizeof(*sif));
	si->socket=-1;
	if (pkg_nt_str_dup(&si->name, &sock->host) < 0) {
		LM_ERR("oom for si name\n");
		return -1;
	}
	if (sock->tag.len) {
		if (pkg_nt_str_dup(&si->tag, &sock->tag) < 0) {
			LM_ERR("oom for si tag\n");
			goto error;
		}
	}
	if (sock->adv.len) {
		if (pkg_nt_str_dup(&si->adv_name_str, &sock->adv) < 0) {
			LM_ERR("oom for si advertised\n");
			goto error;
		}
		if (pkg_nt_str_dup(&si->adv_port_str, &sock->adv_port_str) < 0) {
			LM_ERR("oom for si advertised port\n");
			goto error;
		}
	}
	si->adv_port = sock->adv_port;
	si->flags = sock->flags;
	si->tos = sock->tos;
	si->last_real_ports = &sif->last_real_ports;
	si->port_no=sock->port;
	si->proto=sock->proto;
	if (is_udp_based_proto(sock->proto))
		si->flags |= SI_REUSEPORT;
	return 0;
error:
	pkg_free(si->name.s);
	if (si->tag.s)
		pkg_free(si->tag.s);
	if (si->adv_name_str.s)
		pkg_free(si->adv_name_str.s);
	if (si->adv_port_str.s)
		pkg_free(si->adv_port_str.s);
	return -1;
}

static void sock_mgm_update_fd(struct sock_mgm *sock, int fd)
{
	struct socket_info_full *sif;
	struct socket_info_mgm *sim;

	lock_get(sock_mgm_lock);
	sim = &sockets_info[sock->index];
	sif = &sim->sif;
	sif->socket_info.socket = fd;
	sock->ref++; /* we ref the socket so we can unref when released */
	lock_release(sock_mgm_lock);
	sock_mgm_add_listener(sif);
}

static void sock_mgm_use_socket(struct sock_mgm *sock, struct socket_info_mgm *sim,
		int *sock_update_count)
{
	struct socket_info_full *sif = &sim->sif;
	struct socket_info *si = &sif->socket_info;

	if (sim->flags & SOCK_MGM_INIT)
		return;

	if (sim->flags & SOCK_MGM_FREE)
		free_sock_info(sif);

	if (sock_mgm_fill_socket(sock, sif) < 0) {
		LM_ERR("could not create socket_info_full struct for socket\n");
		goto error;
	}
	/* reset whatever older flags */
	sim->flags &= ~SOCK_MGM_ERROR;
	if (is_localhost(si))
		si->flags |= SI_IS_LO;
	if (fix_socket(sif, 0) < 0) {
		LM_ERR("could not fix socket\n");
		goto error;
	}
	if (is_udp_based_proto(sock->proto)) {
		if (protos[sock->proto].tran.init_listener(si) < 0) {
			LM_ERR("failed to init listener [%.*s], proto %s\n",
				si->name.len, si->name.s,
				protos[sock->proto].name);
			goto error;
		}
		if (!sock_mgm_dynamic_proc) {
			/* if we are not a dynamic process, we need to ask a dynamic one
			 * for the right socket information */
			busy_wait_for((*sock_mgm_proc_no) >= 0,
					SOCKET_MGM_INTERNAL_TIMEOUT, SOCKET_MGM_INTERNAL_INCREMENT);
			close(si->socket); /* we close the socket waiting for a new one */
			if (ipc_send_rpc(*sock_mgm_proc_no, rpc_sockets_send, sock) < 0) {
				LM_ERR("could not request socket update\n");
				goto error;
			}
			(*sock_update_count)++;
		} else {
			sock->ref++; /* we ref the socket so we can unref when released */
			sock_mgm_add_listener(sif);
		}
	} else {
		if (is_tcp_main) {
			if (protos[sock->proto].tran.init_listener(si) < 0) {
				LM_ERR("failed to init listener [%.*s], proto %s\n",
					si->name.len, si->name.s,
					protos[sock->proto].name);
				goto error;
			}
		}
		sock->ref++; /* we ref the socket so we can unref when released */
		sock_mgm_add_listener(sif);
	}
	sim->flags |= SOCK_MGM_INIT;

	if (is_udp_based_proto(sock->proto) && !sock_mgm_dynamic_proc)
		return;
	if (is_tcp_based_proto(sock->proto) && !is_tcp_main)
		return;
	if (sim->flags & SOCK_MGM_REACTOR)
		return;

	if (protos[sock->proto].tran.bind_listener &&
			protos[sock->proto].tran.bind_listener(si) < 0) {
		LM_ERR("failed to bind listener [%.*s], proto %s\n",
				si->name.len, si->name.s,
				protos[sock->proto].name);
		goto error;
	}
	LM_DBG("adding sock=%p(%.*s)\n", sock, sock->socket.len, sock->socket.s);
	if (reactor_add_reader(si->socket,
			(is_udp_based_proto(sock->proto)?F_UDP_READ:F_TCP_LISTENER),
			RCT_PRIO_NET, si)<0) {
		LM_ERR("could not add to reactor\n");
		close(si->socket);
		goto error;
	}
	sim->flags |= SOCK_MGM_REACTOR;
	return;
error:
	sim->flags &= ~SOCK_MGM_ERROR;
	sim->flags |= SOCK_MGM_ERROR;
	free_sock_info(sif);
}

static void sock_mgm_rm_socket(struct sock_mgm *sock, struct socket_info_mgm *sim)
{
	struct socket_info_full *sif = &sim->sif;
	struct socket_info *si = &sif->socket_info;

	/* if it was an error and we didn't even bind, we don't need to do
	 * anything */
	if (sim->flags & SOCK_MGM_ERROR)
		return;
	if (is_tcp_main && !is_tcp_based_proto(sock->proto))
		return;
	if (sim->flags & SOCK_MGM_REACTOR) {
		LM_DBG("removing socket %d from reactor (%p)\n", si->socket, sock);
		if (reactor_del_reader(si->socket, -1, IO_FD_CLOSING)<0) {
			LM_ERR("could not add to reactor\n");
			return;
		}
		sim->flags &= ~SOCK_MGM_REACTOR;
	}
	LM_DBG("removing sock=%p(%.*s) %d\n", sock,
			sock->socket.len, sock->socket.s, si->socket);
	sock_mgm_rm_listener(sif);
	sock_mgm_free(sock);
	/* we do not close the socket now, since it may be used,
	 * but we mark it as free */
	if (si->socket >= 0)
		close(si->socket);
	sim->flags |= SOCK_MGM_FREE;
	sim->flags &= ~SOCK_MGM_INIT;
}

static void rpc_socket_reload_proc(int sender_id, void *_ver)
{
	unsigned long version = (unsigned long)_ver;
	struct socket_info_mgm *sim;
	struct sock_mgm *sock;
	struct list_head *it, *safe;
	int sockets_update_count = 0, fd;

	LM_NOTICE("Reloading process for version %lu\n", version);
	lock_get(sock_mgm_lock);
	if (*sock_mgm_version > version) {
		LM_WARN("new version %lu available (current=%lu)\n", *sock_mgm_version, version);
		goto release;
	}

	list_for_each_safe(it, safe, &sockets_pool->running) {
		sock = list_entry(it, struct sock_mgm, list);
		sim = &sockets_info[sock->index];
		LM_DBG("handling sock=%p(%.*s)\n", sock, sock->socket.len, sock->socket.s);
		if (sock->version < version)
			sock_mgm_rm_socket(sock, sim);
		else
			sock_mgm_use_socket(sock, sim, &sockets_update_count);
	}
release:
	lock_release(sock_mgm_lock);
	while (sockets_update_count-- > 0) {
		if (receive_fd(sock_mgm_unix[0], &sock, sizeof(sock), &fd, MSG_WAITALL) < 0) {
			LM_ERR("could not get fd\n");
			sim = &sockets_info[sock->index];
			sim->flags |= SOCK_MGM_ERROR;
		} else {
			sock_mgm_update_fd(sock, fd);
		}
	}
}

static int sockets_pool_init(void)
{
	int len;

	sockets_info = pkg_malloc(sock_mgm_max_sockets * sizeof *sockets_info);
	if (!sockets_info) {
		LM_ERR("oom for sockets info\n");
		return -1;
	}
	memset(sockets_info, 0, sock_mgm_max_sockets * sizeof *sockets_info);

	len = (sizeof *sockets_pool)+
			(sock_mgm_max_sockets * sizeof *sockets_pool->used);
	sockets_pool = shm_malloc(len);
	if (!sockets_pool) {
		LM_ERR("oom for sockets pool\n");
		return -1;
	}
	memset(sockets_pool, 0, len);
	INIT_LIST_HEAD(&sockets_pool->running);
	sockets_pool->last_index = sock_mgm_max_sockets;
	sockets_pool->used = (char *)(sockets_pool + 1);
	return 0;
}

static int sock_mgm_procs_func(modparam_t type, void *val)
{
	unsigned int no = (unsigned long)val;
	procs[0].no = no;
	return 0;
};
