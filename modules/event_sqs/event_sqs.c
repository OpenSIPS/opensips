/*
 * Copyright (C) 2024 OpenSIPS Solutions
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
 */

#include "../../sr_module.h"
#include "../../evi/evi_transport.h"
#include "../../ut.h"
#include "../../lib/list.h"
#include "../../mod_fix.h"
#include "../../str_list.h"

#include "sqs_lib.h"
#include "sqs_producer.h"

static int mod_init(void);
static int child_init(int);
static void mod_destroy(void);


static int sqs_evi_raise(struct sip_msg *msg, str* ev_name,
	evi_reply_sock *sock, evi_params_t *params, evi_async_ctx_t *async_ctx);
static evi_reply_sock *sqs_evi_parse(str socket);
static int sqs_evi_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
static void sqs_evi_free(evi_reply_sock *sock);
static str sqs_evi_print(evi_reply_sock *sock);

static int add_script_url(modparam_t type, void *val);

static int fixup_url(void **param);
static int send_message(struct sip_msg *msg, str *queue_id, str *message_body);

struct list_head *sqs_urls;
int sqs_pipe[2];


static const proc_export_t procs[] = {
	{"SQS worker",  0,  0, sqs_process, 1, 0},
	{0,0,0,0,0,0}
};

static const param_export_t mod_params[] = {
	{"queue_url", STR_PARAM | USE_FUNC_PARAM, (void *)add_script_url},
	{0, 0, 0}
};

static const cmd_export_t cmds[] = {
	{"sqs_send_message", (cmd_function)send_message, {
		{CMD_PARAM_STR, fixup_url, 0},
		{CMD_PARAM_STR, 0, 0},
		{0, 0, 0}},
		ALL_ROUTES},
	{0, 0, {{0, 0, 0}}, 0}
};



struct module_exports exports = {
	"event_sqs",				/* module name */
	MOD_TYPE_DEFAULT,			/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* load function */
	NULL,						/* OpenSIPS module dependencies */
	cmds,						/* exported functions */
	0,							/* exported async functions */
	mod_params,					/* exported parameters */
	0,							/* exported statistics */
	0,							/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,							/* exported transformations */
	procs,						/* extra processes */
	0,							/* module pre-initialization function */
	mod_init,					/* module initialization function */
	0,							/* response handling function */
	mod_destroy,				/* destroy function */
	child_init,					/* per-child init function */
	0							/* reload confirm function */
};

/* exported functions for core event interface */
static const evi_export_t trans_export_sqs = {
	SQS_STR,					/* transport module name */
	sqs_evi_raise,				/* raise function */
	sqs_evi_parse,				/* parse function */
	sqs_evi_match,				/* sockets match function */
	sqs_evi_free,				/* free function */
	sqs_evi_print,				/* print socket */
	SQS_FLAG
};

static int mod_init(void) {
	LM_NOTICE("initializing event_sqs module......\n");

	if (register_event_mod(&trans_export_sqs)) {
		LM_ERR("cannot register transport functions for SQS\n");
		return -1;
	}

	if (sqs_create_pipe() < 0) {
		LM_ERR("cannot create communication pipe\n");
		return -1;
	}

	if (!sqs_urls) {
		sqs_urls = shm_malloc(sizeof *sqs_urls);
		if (!sqs_urls) {
			LM_ERR("oom!\n");
			return -1;
		}
		INIT_LIST_HEAD(sqs_urls);
	}
	
	return 0;
}

static int child_init(int rank) {

	if (sqs_init_writer() < 0) {
		LM_ERR("cannot init writing pipe\n");
		return -1;
	}

	return 0;
}

static void mod_destroy(void) {
	struct list_head *it, *tmp;
	sqs_queue_t *queue;

	LM_NOTICE("destroy event_sqs module ...\n");

	list_for_each_safe(it, tmp, sqs_urls) {
		queue = list_entry(it, sqs_queue_t, list);
		list_del(&queue->list);
		shm_free(queue);
	
	}

	shm_free(sqs_urls);

	sqs_destroy_pipe();
}


sqs_queue_t *get_script_url(str *id) {
	struct list_head *it;
	sqs_queue_t *queue;

	LM_DBG("get_script_url called with id: %.*s\n", id->len, id->s);
	list_for_each(it, sqs_urls) {
		queue = list_entry(it, sqs_queue_t, list);
		if (queue->id.len == id->len && memcmp(queue->id.s, id->s, id->len) == 0) {
			return queue;
		}
	}
	LM_DBG("No url found with id: %.*s\n", id->len, id->s);
	return NULL;
}

static inline int dupl_string(str *dst, char *begin, char *end)
{
	str s;

	s.s = begin;
	s.len = end - begin;
	if (pkg_nt_str_dup(dst, &s) < 0) {
		LM_ERR("oom!\n");
		return -1;
	}

	return 0;
}

#define IS_WS(_c) ((_c) == ' ' || (_c) == '\t' || (_c) == '\r' || (_c) == '\n')

static int add_script_url(modparam_t type, void *val) {
	str s, id;
	str queues_str = {0,0};
	sqs_queue_t *queue = NULL;

	if (type != STR_PARAM) {
		LM_ERR("invalid parameter type %d\n", type);
		return -1;
	}

	s.s = (char *)val;
	s.len = strlen(s.s);

	for (; s.len > 0; s.s++, s.len--)
		if (!IS_WS(*s.s))
			break;
	if (s.len <= 0 || *s.s != '[') {
		LM_ERR("cannot find id start: %.*s\n", s.len, s.s);
		return -1;
	}
	id.s = s.s + 1;
	for (s.s++, s.len--; s.len > 0; s.s++, s.len--)
		if (*s.s == ']')
			break;
	if (s.len <= 0 || *s.s != ']') {
		LM_ERR("cannot find id end: %.*s\n", s.len, s.s);
		return -1;
	}

	id.len = s.s - id.s;

	if (!sqs_urls) {
		sqs_urls = shm_malloc(sizeof *sqs_urls);
		if (!sqs_urls) {
			LM_ERR("oom!\n");
			return -1;
		}
		INIT_LIST_HEAD(sqs_urls);
	}

	if (get_script_url(&id)) {
		LM_ERR("ID [%.*s] already defined\n", id.len, id.s);
		return -1;
	}

	s.s++;
	s.len--;
	
	for (; s.len > 0; s.s++, s.len--)
		if (!IS_WS(*s.s))
			break;

	queue = shm_malloc(sizeof *queue + id.len + s.len);
	if (!queue) {
		LM_ERR("oom!\n");
		pkg_free(queues_str.s);
		return -1;
	}
	memset(queue, 0, sizeof *queue + id.len + s.len);

	queue->id.s = (char *)(queue + 1);
	queue->id.len = id.len;
	memcpy(queue->id.s, id.s, id.len);

	queue->url.s = (char *)(queue + 1) + id.len;
	queue->url.len = s.len;
	memcpy(queue->url.s, s.s, s.len);

	queue->config = shm_malloc(sizeof(sqs_config));
	if (!queue->config) {
		LM_ERR("oom!\n");
		return -1;
	}


	INIT_LIST_HEAD(&queue->list);

	list_add(&queue->list, sqs_urls);

	return 0;
}

static evi_reply_sock *sqs_evi_parse(str socket)
{
	evi_reply_sock *sock = NULL;
	sqs_queue_t *queue = NULL;

	if (socket.len <= 0 || !socket.s) {
		LM_ERR("No socket specified\n");
		return NULL;
	}
	
	queue = shm_malloc(sizeof *queue);
	if (!queue) {
		LM_ERR("No more pkg mem\n");
		return NULL;
	}
	queue->url.s = socket.s;
	queue->url.len = socket.len;

	sock = shm_malloc(sizeof(*sock) + queue->url.len);
	if (!sock) {
		LM_ERR("oom!\n");
		return NULL;
	}

	memset(sock, 0, sizeof(*sock) + queue->url.len);
	sock->address.s = (char *)(sock + 1);
	memcpy(sock->address.s, queue->url.s, queue->url.len);
	sock->address.len = queue->url.len;
	sock->params = queue;
	sock->flags |= EVI_ADDRESS | EVI_PARAMS | EVI_EXPIRE | EVI_ASYNC_STATUS;

	return sock;
}

static int sqs_evi_match(evi_reply_sock *sock1, evi_reply_sock *sock2)
{
	if (!sock1 || !sock2)
		return 0;

	if (!(sock1->flags & EVI_PARAMS) || !(sock2->flags & EVI_PARAMS) ||
		sock1->params != sock2->params)
		return 0;

	return 1;
}

static void sqs_evi_free(evi_reply_sock *sock)
{
	sqs_queue_t *queue;
	if (!sock) {
		return;
	}

	if (sock->params) {
		queue = (sqs_queue_t *)sock->params;
		if (queue->config) {
			shm_free(queue->config);
		}
		shm_free(queue);
	}

	shm_free(sock);
}

static str sqs_evi_print(evi_reply_sock *sock)
{
	return sock->address;
}

static int sqs_evi_raise(struct sip_msg *msg, str* ev_name, evi_reply_sock *sock, evi_params_t *params, evi_async_ctx_t *async_ctx) {
	sqs_queue_t *queue = (sqs_queue_t *)sock->params;
	int ret;
	str payload, message_body;
	char *start, *end, *region, *endpoint;

	queue = (sqs_queue_t *)sock->params;
	queue->url = sock->address;

	if (!queue->config) {
		region = NULL;
		endpoint = NULL;
		if (parse_queue_url(&queue->url, &region, &endpoint) != 0) {
			LM_ERR("Failed to parse queue URL\n");
			shm_free(queue->config);
			return -1;
		}
		queue->config = pkg_malloc(sizeof(sqs_config));
		if (!queue->config) {
			LM_ERR("No more pkg mem\n");
			free(region);
			free(endpoint);
			return -1;
		}
		ret = init_sqs(queue->config, region, endpoint);

		free(region);
		free(endpoint);

		if (ret == -1) {
			LM_ERR("Cannot init the configuration\n");
			return -1;
		}

	}

	if (!sock || !queue || !queue->config) {
		LM_ERR("Invalid queue or config in sqs_evi_raise\n");
		return -1;
	}

	payload.s = evi_build_payload(params, ev_name, 0, NULL, NULL);
	if (!payload.s) {
		LM_ERR("Failed to build event payload\n");
		return -1;
	}
	payload.len = strlen(payload.s);

	/* Extract the message body */
	start = strstr(payload.s, "params");
	if (!start) {
		return -1;
	}
	start = start + 10; /* "params":["Message"] */
	end = strstr(start, "\"");
	if (!end) {
		return -1;
	}

	message_body.len = end - start;
	message_body.s = start;

	if (sqs_send_message(queue->config, queue->url, message_body) != 0) {
		LM_ERR("Failed to send message to SQS\n");
		evi_free_payload(payload.s);
		return -1;
	}

	evi_free_payload(payload.s);
	return 0;

}




static int fixup_url(void **param) {
	str *s;
	s = (str *)*param;
	LM_DBG("fixup_url called with id: %.*s\n", s->len, s->s);

	*param = get_script_url(s);
	if (*param == NULL) {
		LM_ERR("Unknown id: %.*s\n", s->len, s->s);
		return E_CFG;
	}

	return 0;
}


static int send_message(struct sip_msg *msg, str *queue_id, str *message_body) {
	sqs_queue_t *queue;
	size_t msg_len;
	ssize_t written;
	char *buffer;
	int queue_len, body_len;

	LM_INFO("sqs_send_message called with id: %.*s\n", queue_id->len, queue_id->s);

	queue = get_script_url(queue_id);
	if (!queue) {
		LM_ERR("Unknown broker id: %.*s\n", queue_id->len, queue_id->s);
		return -1;
	}

	msg_len = sizeof(int) + sizeof(int) + message_body->len + queue_id->len;
	buffer = (char *)pkg_malloc(msg_len);
	if (!buffer) {
		LM_ERR("Failed to allocate memory for pipe message\n");
		return -1;
	}

	queue_len = queue_id->len;
	body_len = message_body->len;

	memcpy(buffer, &queue_len, sizeof(int));
	memcpy(buffer + sizeof(int), &body_len, sizeof(int));
	memcpy(buffer + 2 * sizeof(int), queue_id->s, queue_len);
	memcpy(buffer + 2 * sizeof(int) + queue_len, message_body->s, body_len);

	written = write(sqs_pipe[1], buffer, msg_len);
	pkg_free(buffer);
	if (written != msg_len) {
		LM_ERR("Failed to notify SQS worker, error: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

