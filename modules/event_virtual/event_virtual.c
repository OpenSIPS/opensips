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
 *  2015-07-xx created (rvlad-patrascu)
 */

#include "event_virtual.h"
#include "../../mem/mem.h"
#include "../../locking.h"
#include "../../sr_module.h"
#include "../../mem/shm_mem.h"
#include "../../ut.h"
#include "../../timer.h"

static int mod_init(void);
static void destroy(void);
static void virtual_free(evi_reply_sock *sock);
static str virtual_print(evi_reply_sock *sock);
static int virtual_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
static evi_reply_sock* virtual_parse(str socket);
static int virtual_raise(struct sip_msg *msg, str* ev_name,
					 evi_reply_sock *sock, evi_params_t * params);

static struct virtual_socket **list_sockets;

static int failover_timeout = DEFAULT_FAILOVER_TIMEOUT;

static gen_lock_t *global_lock;
static gen_lock_t *rrobin_lock;

/* module parameters */
static param_export_t mod_params[] = {
	{"failover_timeout", INT_PARAM, &failover_timeout},
	{0,0,0}
};

struct module_exports exports = {
	"event_virtual",	/* module name */
	MOD_TYPE_DEFAULT,	/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,	/* dlopen flags */
	0,					/* load function */
	NULL,				/* OpenSIPS module dependencies */
	0,					/* exported functions */
	0,					/* exported async functions */
	mod_params,			/* exported parameters */
	0,					/* exported statistics */
	0,					/* exported MI functions */
	0,					/* exported pseudo-variables */
	0,			 		/* exported transformations */
	0,					/* extra processes */
	0,					/* module pre-initialization function */
	mod_init,			/* module initialization function */
	0,					/* response handling function */
	destroy,			/* destroy function */
	0,					/* per-child init function */
	0					/* reload confirm function */
};

static evi_export_t trans_export_virtual = {
	VIRT_STR,					/* transport module name */
	virtual_raise,					/* raise function */
	virtual_parse,					/* parse function */
	virtual_match,					/* sockets match function */
	virtual_free,					/* free function */
	virtual_print,					/* print socket */
	VIRT_FLAG					/* flags */
};

/* initialize function */
static int mod_init(void) {	
	LM_NOTICE("initializing module ...\n");

	if (register_event_mod(&trans_export_virtual)) {
		LM_ERR("cannot register transport functions for SCRIPTROUTE\n");
		return -1;
	}

	list_sockets =  shm_malloc(sizeof(struct virtual_socket*));
	*list_sockets = NULL;

	if (!list_sockets) {
		LM_ERR("no more memory for list_sockets header\n");
		return -1;
	}

	global_lock = lock_alloc();
	rrobin_lock = lock_alloc();

	if (!global_lock || !rrobin_lock) {
		LM_ERR("Failed to allocate locks\n");
		return -1;
	}

	if (!lock_init(global_lock) || !lock_init(rrobin_lock)) {
		LM_ERR("Failed to init locks\n");
		return -1;
	}

	return 0;
}

/* free allocated memory */
static void destroy(void) {
	struct virtual_socket* header = *list_sockets;
	struct virtual_socket* tmp;
	struct sub_socket *sub_list, *tmp_s;

	LM_NOTICE("destroying module ...\n");

	lock_destroy(global_lock);
	lock_destroy(rrobin_lock);
	lock_dealloc(global_lock);
	lock_dealloc(rrobin_lock);

	/* free the list of virtual sockets */
	while (header) {
		/* free the list of sockets for this virtual socket */
		sub_list = header->list_sockets;
		while (sub_list) {
			tmp_s = sub_list;
			sub_list = sub_list->next;
			shm_free(tmp_s);
		}

		tmp = header;
		header = header->next;
		shm_free(tmp);
	}
	shm_free(list_sockets);
}

/* compare two str values */
inline static int str_cmp(str a , str b) {
	if (a.len == b.len && strncmp(a.s, b.s, a.len) == 0)
		return 1;
	return 0;
}

static int virtual_match (evi_reply_sock *sock1, evi_reply_sock *sock2) {
	struct virtual_socket *vsock1, *vsock2;
	struct sub_socket *h_list1, *h_list2;
	unsigned int found_sock;

	if (!sock1 || !sock2 || !sock1->params || !sock2->params)
		return 0;
	else {
		vsock1 = sock1->params;
		vsock2 = sock2->params;
	}

	if ((vsock1->type != vsock2->type) ||
		(vsock1->nr_sockets != vsock2->nr_sockets))
		return 0;

	h_list1 = vsock1->list_sockets;

	if (vsock1->type ==	FAILOVER_TYPE || vsock1->type == RROBIN_TYPE) {
		h_list2 = vsock2->list_sockets;
		for (; h_list1 != NULL && h_list2 != NULL;
				h_list1 = h_list1->next, h_list2 = h_list2->next)
			if (!str_cmp(h_list1->sock_str, h_list2->sock_str))
				return 0;
		return 1;
	} else {	/* if the virtual socket type is parallel, match two virtual sockets that have the same actual sockets in any order*/
		for (; h_list1 != NULL; h_list1 = h_list1->next) {
			h_list2 = vsock2->list_sockets;
			found_sock = 0;
			for (; h_list2 != NULL; h_list2 = h_list2->next) {
				if (str_cmp(h_list1->sock_str, h_list2->sock_str)) {
					found_sock = 1;
					break;
				}
			}
			if (!found_sock) {
				return 0;
			}
		}
		return 1;
	}
}

/* insert entry in global list of virtual sockets */
static void insert_in_list_sockets(struct virtual_socket *new) {
	struct virtual_socket *head = *list_sockets;

	new->next = NULL;
	new->prev = NULL;

	lock_get(global_lock);

	if (head != NULL) {
		head->prev = new;
		new->next = head;
	}
	
	*list_sockets = new;
	
	lock_release(global_lock);
}

/* insert an actual socket in the list of sockets of one virtual socket */
/* returns a newly created sub_socket structure*/
static struct sub_socket *insert_sub_socket(struct virtual_socket *vsock) {
	struct sub_socket *new_entry, *head;

	new_entry = shm_malloc(sizeof(struct sub_socket));
	if (!new_entry) {
		LM_ERR("oom\n");
		return NULL;
	}
	memset(new_entry, 0, sizeof *new_entry);

	new_entry->lock = lock_alloc();
	if (!new_entry->lock) {
		LM_ERR("Failed to allocate lock\n");
		goto error;
	}
	if (!lock_init(new_entry->lock)) {
		LM_ERR("Failed to init lock\n");
		goto error;
	}

	if (!vsock->list_sockets) {
		vsock->list_sockets = new_entry;
		return new_entry;
	}

	head = vsock->list_sockets;
	
	if (!head->next) {
		head->next = new_entry;
		return new_entry;
	}

	while (head->next->next) {
		head = head->next;
	}
	head->next->next = new_entry;
	return new_entry;

error:
	shm_free(new_entry);
	return NULL;
}

static evi_reply_sock* virtual_parse(str socket) {
	evi_reply_sock *ret_sock;
	struct virtual_socket *new_vsocket;
	struct sub_socket *socket_entry;
	char *p1, *p_token = NULL;
	unsigned int tmp_len, tmp_len_addr = 0, pos;
	unsigned int token_is_socket;

	if (!socket.s || !socket.len) {
		LM_ERR("no socket specified\n");
		return NULL;
	}

	new_vsocket = shm_malloc(sizeof(struct virtual_socket) + socket.len + sizeof(evi_reply_sock));
	if (!new_vsocket) {
		LM_ERR("no memory for new list_sockets entry\n");
		return NULL;
	}

	new_vsocket->list_sockets = NULL;
	new_vsocket->current_sock = NULL;
	new_vsocket->nr_sockets = 0;

	ret_sock = (evi_reply_sock *)((char *)(new_vsocket + 1) + socket.len);
	memset(ret_sock, 0, sizeof(evi_reply_sock));

	ret_sock->address.s = (char *)(new_vsocket + 1);
	ret_sock->address.len = socket.len;

	ret_sock->params = new_vsocket;

	ret_sock->flags |= EVI_ADDRESS;
	ret_sock->flags |= EVI_EXPIRE;

	/* jump over initial whitespaces */
	for (p1 = socket.s, pos = 0; (*p1 == ' ' || *p1 == '\t') && pos < socket.len; p1++, pos++) {}

	/* parse the virtual socket type ("PARALLEL" etc.) */
	if (!memcmp(p1, PARALLEL_STR, PARALLEL_LEN)) {
		new_vsocket->type = PARALLEL_TYPE;
		p1 = p1 + PARALLEL_LEN;
		pos += PARALLEL_LEN;
		memcpy(ret_sock->address.s, PARALLEL_STR, PARALLEL_LEN);
		memcpy(ret_sock->address.s + PARALLEL_LEN, " ", 1);
		tmp_len_addr = PARALLEL_LEN + 1;
	} else
	if (!memcmp(p1, FAILOVER_STR, FAILOVER_LEN)) {
		new_vsocket->type = FAILOVER_TYPE;
		p1 = p1 + FAILOVER_LEN;
		pos += FAILOVER_LEN;
		memcpy(ret_sock->address.s, FAILOVER_STR, FAILOVER_LEN);
		memcpy(ret_sock->address.s + FAILOVER_LEN, " ", 1);
		tmp_len_addr = FAILOVER_LEN + 1;
	} else
	if (!memcmp(p1, RROBIN_STR, RROBIN_LEN)) {
		new_vsocket->type = RROBIN_TYPE;
		p1 = p1 + RROBIN_LEN;
		pos += RROBIN_LEN;
		memcpy(ret_sock->address.s, RROBIN_STR, RROBIN_LEN);
		memcpy(ret_sock->address.s + RROBIN_LEN, " ", 1);
		tmp_len_addr = RROBIN_LEN + 1;
	} else {
		LM_ERR("invalid virtual socket type\n");
		shm_free(new_vsocket);
		return NULL;
	}

	tmp_len = 0;
	token_is_socket = 0;

	/* parse the actual sockets of this virtual socket */
	for (; pos < socket.len; p1++, pos++) {
		/* jump over whitespaces and parse the last socket before whitespaces*/
		if (*p1 == SEP_SPACE || *p1 == SEP_TAB) {
			if (token_is_socket) {
				socket_entry = insert_sub_socket(new_vsocket);
				if(!socket_entry) {
					LM_ERR("no memory for sub_socket entry\n");
					shm_free(new_vsocket);
					return NULL;
				}
				new_vsocket->nr_sockets++;
				socket_entry->sock_str.len = tmp_len;
				socket_entry->sock_str.s = shm_malloc(tmp_len);
				memcpy(socket_entry->sock_str.s, p_token, tmp_len);

				memcpy(ret_sock->address.s + tmp_len_addr, p_token, tmp_len);
				tmp_len_addr += tmp_len;
				memcpy(ret_sock->address.s + tmp_len_addr, " ", 1);
				tmp_len_addr++;

				LM_DBG("parsed socket %.*s\n", tmp_len, socket_entry->sock_str.s);

				token_is_socket = 0;
				tmp_len = 0;
			}
		} else {
			if (!token_is_socket)
				p_token = p1;
			token_is_socket = 1;
			tmp_len++;
		}
	}

	/* parse the last socket */
	if (token_is_socket) {
		socket_entry = insert_sub_socket(new_vsocket);
		if(!socket_entry) {
			LM_ERR("no memory for sub_socket entry\n");
			shm_free(new_vsocket);
			return NULL;
		}
		new_vsocket->nr_sockets++;
		socket_entry->sock_str.len = tmp_len;
		socket_entry->sock_str.s = shm_malloc(tmp_len);
		memcpy(socket_entry->sock_str.s, p_token, tmp_len);

		memcpy(ret_sock->address.s + tmp_len_addr, p_token, tmp_len);
		tmp_len_addr += tmp_len;

		LM_DBG("parsed socket %.*s\n", tmp_len, socket_entry->sock_str.s);
	}

	ret_sock->address.len = tmp_len_addr;

	insert_in_list_sockets(new_vsocket);

	return ret_sock;
}

/* get the transport module of an actual socket and call the parse function */
static int parse_socket(struct sub_socket *socket) {
	socket->trans_mod = get_trans_mod(&(socket->sock_str));
	if (!socket->trans_mod) {
		LM_ERR("couldn't find a protocol to support %.*s\n",
				socket->sock_str.len, socket->sock_str.s);
		return 0;
	}

	socket->sock_str.s += socket->trans_mod->proto.len + 1;
	socket->sock_str.len -= (socket->trans_mod->proto.len + 1);

	/* parse socket and get the evi_reply_sock */
	socket->sock = socket->trans_mod->parse(socket->sock_str);
	if (!socket->sock) {
		return 0;
	}

	socket->sock_str.s -= socket->trans_mod->proto.len + 1;
	socket->sock_str.len += (socket->trans_mod->proto.len + 1);

	return 1;
}

static int virtual_raise(struct sip_msg *msg, str* ev_name, evi_reply_sock *sock, evi_params_t *params) {
	struct virtual_socket *vsock;
	struct sub_socket *h_list;

	if (!sock || !(sock->params)) {
		LM_ERR("invalid socket\n");
		return -1;
	}

	vsock = (struct virtual_socket *)sock->params;
	h_list = vsock->list_sockets;

	switch (vsock->type) {
		/* raise all the sockets at once*/
		case PARALLEL_TYPE : {
			while (h_list) {
				if (!h_list->trans_mod && !parse_socket(h_list)) {
					LM_ERR("unable to parse socket %.*s\n",
							h_list->sock_str.len, h_list->sock_str.s);
					return -1;
				}

				if (h_list->trans_mod->raise(msg, ev_name, h_list->sock, params)) {
					LM_ERR("unable to raise socket %.*s\n",
							h_list->sock_str.len, h_list->sock_str.s);
					return -1;
				}

				h_list = h_list->next;
			}
			break;
		}
		/* try to raise all sockets until first successful raise*/
		case FAILOVER_TYPE : {
			while (h_list) {
				lock_get(h_list->lock);

				if (h_list->last_failed &&
					(get_ticks() - h_list->last_failed <= failover_timeout)) {
					lock_release(h_list->lock);

					LM_DBG("skipping already failed socket %.*s\n",
						h_list->sock_str.len, h_list->sock_str.s);
					h_list = h_list->next;
					continue;
				}

				if (!h_list->trans_mod && !parse_socket(h_list)) {
					h_list->last_failed = get_ticks();
					lock_release(h_list->lock);

					LM_DBG("unable to parse socket %.*s trying next socket\n",
							h_list->sock_str.len, h_list->sock_str.s);
					h_list = h_list->next;
					continue;
				}

				if (h_list->trans_mod->raise(msg, ev_name, h_list->sock, params)) {
					h_list->last_failed = get_ticks();
					lock_release(h_list->lock);

					LM_DBG("unable to raise socket %.*s trying next socket\n",
							h_list->sock_str.len, h_list->sock_str.s);
					h_list = h_list->next;
					continue;
				}

				h_list->last_failed = 0;

				lock_release(h_list->lock);

				break;
			}

			if (!h_list) {
				LM_ERR("unable to raise any socket\n");
				return -1;
			}
			break;
		}
		/* raise the sockets alternatively (in the order they have been parsed) */
		case RROBIN_TYPE : {
			lock_get(rrobin_lock);

			if (!vsock->current_sock)
				vsock->current_sock = h_list;

			if (!vsock->current_sock->trans_mod && !parse_socket(vsock->current_sock)) {
					LM_ERR("unable to parse socket %.*s\n",
							vsock->current_sock->sock_str.len,
							vsock->current_sock->sock_str.s);
					return -1;
			}

			if (vsock->current_sock->trans_mod->raise(msg, ev_name,
												vsock->current_sock->sock, params)) {
					LM_ERR("unable to raise socket %.*s\n",
							vsock->current_sock->sock_str.len, vsock->current_sock->sock_str.s);
					return -1;
			}

			vsock->current_sock = vsock->current_sock->next;

			lock_release(rrobin_lock);
			break;
		}

		default : {
			LM_ERR("invalid virtual socket type\n");
			return -1;
		}
	}

	return 0;
}

static void virtual_free(evi_reply_sock *sock) {
	struct virtual_socket *vsock;
	struct sub_socket *sub_list, *tmp_s;

	LM_DBG("freeing socket %.*s\n", sock->address.len ,sock->address.s);

	lock_get(global_lock);

	vsock = (struct virtual_socket *)sock->params;
	if (!vsock)
		return;

	/* free the list of sockets for this virtual socket */
	sub_list = vsock->list_sockets;
	while (sub_list) {
		/* call the free function of the subscriber */
		if (sub_list->trans_mod) {
			sub_list->trans_mod->free(sub_list->sock);
		}
		tmp_s = sub_list;
		sub_list = sub_list->next;
		shm_free(tmp_s->sock_str.s);
		shm_free(tmp_s);
	}

	/* free the virtual socket from the global list */
	if (vsock->next)
			vsock->next->prev = vsock->prev;
	if (vsock == *list_sockets)
		*list_sockets = vsock->next;
	else
		vsock->prev->next = vsock->next;

	if (!vsock->next && !vsock->prev)
		*list_sockets = NULL;

	shm_free(vsock);

	lock_release(global_lock);
}

static str virtual_print(evi_reply_sock *sock) {
	return sock->address;
}
