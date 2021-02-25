/*
 * Copyright (C) 2020 OpenSIPS Solutions
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

#include <librdkafka/rdkafka.h>

#include "../../sr_module.h"
#include "../../evi/evi_transport.h"
#include "../../ut.h"
#include "../../lib/cJSON.h"
#include "../../lib/list.h"
#include "../../mod_fix.h"
#include "../../str_list.h"
#include "event_kafka.h"
#include "kafka_producer.h"

static int mod_init(void);
static int child_init(int);
static void mod_destroy(void);

static evi_reply_sock* kafka_evi_parse(str socket);
static int kafka_evi_raise(struct sip_msg *msg, str* ev_name,
	evi_reply_sock *sock, evi_params_t *params, evi_async_ctx_t *async_ctx);
static int kafka_evi_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
static void kafka_evi_free(evi_reply_sock *sock);
static str kafka_evi_print(evi_reply_sock *sock);

static int add_script_broker(modparam_t type, void * val);

static int fixup_broker(void **param);
static int fixup_report_route(void **param);
static int kafka_publish(struct sip_msg *sip_msg, kafka_broker_t *broker,
	str *msg, str *key, void *report_rt_p);

struct list_head *kafka_brokers;

static proc_export_t procs[] = {
	{"Kafka worker",  0,  0, kafka_process, 1, 0},
	{0,0,0,0,0,0}
};

static param_export_t mod_params[] = {
	{"broker_id", STR_PARAM|USE_FUNC_PARAM, (void *)add_script_broker},
	{0,0,0}
};

static cmd_export_t cmds[] = {
	{"kafka_publish",(cmd_function)kafka_publish, {
		{CMD_PARAM_STR, fixup_broker, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_STATIC,
			fixup_report_route, 0}, {0,0,0}},
		ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

struct module_exports exports = {
	"event_kafka",				/* module name */
	MOD_TYPE_DEFAULT,			/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* load function */
	NULL,            			/* OpenSIPS module dependencies */
	cmds,						/* exported functions */
	0,							/* exported async functions */
	mod_params,					/* exported parameters */
	0,							/* exported statistics */
	0,							/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,			 				/* exported transformations */
	procs,						/* extra processes */
	0,							/* module pre-initialization function */
	mod_init,					/* module initialization function */
	0,							/* response handling function */
	mod_destroy,				/* destroy function */
	child_init,					/* per-child init function */
	0						    /* reload confirm function */
};

/* exported functions for core event interface */
static evi_export_t trans_export_kafka = {
	KAFKA_STR,					/* transport module name */
	kafka_evi_raise,			/* raise function */
	kafka_evi_parse,			/* parse function */
	kafka_evi_match,			/* sockets match function */
	kafka_evi_free,				/* free function */
	kafka_evi_print,			/* print socket */
	KAFKA_FLAG					/* flags */
};

static int mod_init(void)
{
	LM_NOTICE("initializing module ......\n");

	if (register_event_mod(&trans_export_kafka)) {
		LM_ERR("cannot register transport functions for Kafka\n");
		return -1;
	}

	if (kafka_create_pipe() < 0) {
		LM_ERR("cannot create communication pipe\n");
		return -1;
	}

	if (!kafka_brokers) {
		kafka_brokers = shm_malloc(sizeof *kafka_brokers);
		if (!kafka_brokers) {
			LM_ERR("oom!\n");
			return -1;
		}
		INIT_LIST_HEAD(kafka_brokers);
	}

	return 0;
}

static int child_init(int rank)
{
	if (kafka_init_writer() < 0) {
		LM_ERR("cannot init writing pipe\n");
		return -1;
	}

	return 0;
}

static void mod_destroy(void)
{
	struct list_head *it, *tmp;
	kafka_broker_t *broker;

	LM_NOTICE("destroy module ...\n");

	list_for_each_safe(it, tmp, kafka_brokers) {
		broker = list_entry(it, kafka_broker_t, list);
		list_del(&broker->list);
		shm_free(broker);
	}

	shm_free(kafka_brokers);

	kafka_destroy_pipe();
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

/* parse kafka socket components */
static int kafka_parse_socket(str *socket, str *brokers, str *topic, str *props)
{
	unsigned int i;
	char *p;

	/* parse a kafka socket up to the properties */
	for (i = 0, p = socket->s; i < socket->len; i++) {
		if (socket->s[i] == '/') {
			if (brokers->s) {
				LM_ERR("Unexpected char '/' at [%d]\n", i);
				goto error;
			}

			if (dupl_string(brokers, p, socket->s + i) < 0)
				goto error;

			p = socket->s + i + 1;
		} else if (socket->s[i] == '?') {
			if (!brokers->s) {
				LM_ERR("Missing topic\n");
				goto error;
			}
			if (topic->s) {
				LM_ERR("Unexpected char '?' at [%d]\n", i);
				goto error;
			}

			if (dupl_string(topic, p, socket->s + i) < 0)
				goto error;

			break;
		}
	}

	if (!brokers->s) {
		LM_ERR("Missing topic\n");
		goto error;
	}
	if (!topic->s) {
		if (socket->len - brokers->len - 1 == 0) {
			LM_ERR("Missing topic\n");
			goto error;
		}

		if (dupl_string(topic, socket->s + brokers->len + 1,
			socket->s + socket->len) < 0)
			goto error;
	} else {
		props->len = socket->len - brokers->len - 1 - topic->len - 1;
		if (!props->len) {
			LM_ERR("Missing properties after '?' char\n");
			goto error;
		}
		props->s = socket->s + brokers->len + 1 + topic->len + 1;
	}

	return 0;

error:
	if (brokers->s)
		pkg_free(brokers->s);
	if (topic->s)
		pkg_free(topic->s);
	return -1;
}

static int s_list_add(struct s_list **list, str *src)
{
	struct s_list *elem;

	elem = shm_malloc(sizeof *elem + src->len + 1);
	if (!elem) {
		LM_ERR("oom!\n");
		return -1;
	}

	elem->s = (char *)(elem + 1);
	memcpy(elem->s, src->s, src->len + 1);

	elem->next = *list;
	*list = elem;

	return 0;
}

static int kafka_add_prop(str *pname, str *pval,
	struct s_list **conf_strings, int *flags)
{
	if (pname->len == PROP_KEY_NAME_LEN &&
		!memcmp(pname->s, PROP_KEY_NAME, PROP_KEY_NAME_LEN)) {
		if (pval->len == PROP_KEY_VAL_LEN &&
			!memcmp(pval->s, PROP_KEY_VAL, PROP_KEY_VAL_LEN)) {
			*flags |= PROD_MSG_KEY_CALLID;
		} else {
			LM_ERR("Unsupported value <%.*s> for the [%s] property\n",
				pval->len, pval->s, PROP_KEY_NAME);
		}
	} else {
		if (s_list_add(conf_strings, pval) < 0) {
			LM_ERR("Failed to add property value to config strings list\n");
			return -1;
		}
		if (s_list_add(conf_strings, pname) < 0) {
			LM_ERR("Failed to add property name to config strings list\n");
			return -1;
		}
	}

	pkg_free(pname->s);
	pkg_free(pval->s);
	pname->s = NULL;
	pval->s = NULL;

	return 0;
}

static int parse_kafka_properties(str *props,
	struct s_list **conf_strings, int *flags)
{
	str pname = {0,0}, pval = {0,0};
	char *p;
	unsigned int i;

	for (i = 0, p = props->s; i < props->len; i++) {
		if (props->s[i] == '=') {
			if (pname.s) {
				LM_ERR("Unexpected char '=' at [%d]\n", i);
				goto error;
			}

			if (dupl_string(&pname, p, props->s + i) < 0)
				goto error;

			p = props->s + i + 1;
		} else if (props->s[i] == '&') {
			if (!pname.s) {
				LM_ERR("Missing property name\n");
				goto error;
			}

			if (dupl_string(&pval, p, props->s + i) < 0)
				goto error;

			if (kafka_add_prop(&pname, &pval, conf_strings, flags) < 0)
				goto error;

			p = props->s + i + 1;
		}
	}

	if (props->s) {
		if (!pname.s) {
			LM_ERR("Missing property name\n");
			goto error;
		}

		if (dupl_string(&pval, p, props->s + props->len) < 0)
			goto error;

		if (kafka_add_prop(&pname, &pval, conf_strings, flags) < 0)
			goto error;
	}

	return 0;

error:
	if (pname.s)
		pkg_free(pname.s);
	if (pval.s)
		pkg_free(pval.s);
	return -1;
}

static int parse_conf_strings(kafka_producer_t *prod,
	str *brokers, str *topic, str *props)
{
	struct s_list *conf_strings = NULL;
	int flags = 0;

	/* build the following list: brokers -> topic -> prop name -> prop val -> ... */

	if (parse_kafka_properties(props, &conf_strings, &flags) < 0) {
		LM_ERR("Failed to parse properties\n");
		goto error;
	}

	if (s_list_add(&conf_strings, topic) < 0) {
		LM_ERR("Failed to add topic to config strings list\n");
		goto error;
	}

	if (s_list_add(&conf_strings, brokers) < 0) {
		LM_ERR("Failed to add brokers to config strings list\n");
		goto error;
	}

	prod->conf_strings = conf_strings;
	prod->flags |= flags;

	return 0;
error:
	s_list_free(conf_strings);
	return -1;
}

kafka_broker_t *get_script_broker(str *id)
{
	struct list_head *it;
	kafka_broker_t *broker;

	list_for_each(it, kafka_brokers) {
		broker = container_of(it, kafka_broker_t, list);
		if (broker->id.len == id->len && memcmp(broker->id.s, id->s, id->len) == 0)
			return broker;
	}
	return NULL;
}

#define IS_WS(_c) ((_c) == ' ' || (_c) == '\t' || (_c) == '\r' || (_c) == '\n')

static int add_script_broker(modparam_t type, void * val)
{
	str s, id;
	str brokers_str = {0,0}, topic = {0,0}, props = {0,0};
	kafka_broker_t *broker = NULL;
	kafka_producer_t *prod = NULL;

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
		LM_ERR("cannot find broker id start: %.*s\n", s.len, s.s);
		return -1;
	}
	id.s = s.s + 1;
	for (s.s++, s.len--; s.len > 0; s.s++, s.len--)
		if (*s.s == ']')
			break;
	if (s.len <= 0 || *s.s != ']') {
		LM_ERR("cannot find broker id end: %.*s\n", s.len, s.s);
		return -1;
	}
	id.len = s.s - id.s;

	if (!kafka_brokers) {
		kafka_brokers = shm_malloc(sizeof *kafka_brokers);
		if (!kafka_brokers) {
			LM_ERR("oom!\n");
			goto error;
		}
		INIT_LIST_HEAD(kafka_brokers);
	}

	if (get_script_broker(&id)) {
		LM_ERR("Broker ID [%.*s] already defined\n", id.len, id.s);
		return -1;
	}

	s.s++;
	s.len--;

	for (; s.len > 0; s.s++, s.len--)
		if (!IS_WS(*s.s))
			break;

	if (kafka_parse_socket(&s, &brokers_str, &topic, &props) < 0) {
		LM_ERR("Failed to parse kafka socket: %.*s\n", s.len, s.s);
		return -1;
	}

	broker = shm_malloc(sizeof *broker + id.len + sizeof *prod);
	if (!broker) {
		LM_ERR("oom!\n");
		pkg_free(brokers_str.s);
		return -1;
	}
	memset(broker, 0, sizeof *broker + id.len + sizeof *prod);

	broker->id.s = (char *)(broker + 1);
	memcpy(broker->id.s, id.s, id.len);
	broker->id.len = id.len;

	prod = (kafka_producer_t*)((char *)(broker + 1) + id.len);
	broker->prod = prod;

	prod->queue_event_fd[0] = -1;
	prod->queue_event_fd[1] = -1;

	if (parse_conf_strings(prod, &brokers_str, &topic, &props) < 0) {
		LM_ERR("Failed to prepare config strings\n");
		goto error;
	}

	pkg_free(brokers_str.s);
	pkg_free(topic.s);

	list_add(&broker->list, kafka_brokers);

	LM_DBG("Added kafka broker: %s/%s\n", brokers_str.s, topic.s);

	return 0;

error:
	if (brokers_str.s)
		pkg_free(brokers_str.s);
	if (topic.s)
		pkg_free(topic.s);
	if (prod && prod->conf_strings)
		s_list_free(prod->conf_strings);
	if (broker)
		shm_free(broker);

	return -1;
}

/* The socket grammar is:
 *   "brokers/topic?properties", where "properties" is a list of
 *    prop=value separated by '&'
 */
static evi_reply_sock *kafka_evi_parse(str socket)
{
	evi_reply_sock *sock = NULL;
	kafka_broker_t *broker = NULL;
	unsigned int addrlen;
	str brokers = {0,0}, topic = {0,0}, props = {0,0};

	if (!socket.len || !socket.s) {
		LM_ERR("no socket specified\n");
		return NULL;
	}

	if (kafka_parse_socket(&socket, &brokers, &topic, &props) < 0)
		goto error;

	/* evi address length */
	addrlen = brokers.len + 1 + topic.len;

	sock = shm_malloc(sizeof *sock + addrlen);
	if (!sock) {
		LM_ERR("oom!\n");
		goto error;
	}
	memset(sock, 0, sizeof *sock + addrlen);

	sock->address.s = (char *)(sock + 1);
	memcpy(sock->address.s, socket.s, addrlen);
	sock->address.len = addrlen;

	broker = shm_malloc(sizeof *broker + sizeof(kafka_producer_t));
	if (!broker) {
		LM_ERR("oom!\n");
		goto error;
	}
	memset(broker, 0, sizeof *broker + sizeof(kafka_producer_t));

	broker->prod = (kafka_producer_t *)(broker + 1);

	list_add(&broker->list, kafka_brokers);

	sock->params = broker;

	broker->prod->queue_event_fd[0] = -1;
	broker->prod->queue_event_fd[1] = -1;

	if (parse_conf_strings(broker->prod, &brokers, &topic, &props) < 0) {
		LM_ERR("Failed to prepare config strings\n");
		goto error;
	}

	pkg_free(brokers.s);
	pkg_free(topic.s);

	LM_DBG("Parsed kafka socket: %.*s\n", sock->address.len, sock->address.s);

	sock->flags |= EVI_ADDRESS|EVI_PARAMS|EVI_EXPIRE|EVI_ASYNC_STATUS;

	return sock;

error:
	LM_ERR("error while parsing socket: %.*s\n", socket.len, socket.s);
	if (brokers.s)
		pkg_free(brokers.s);
	if (topic.s)
		pkg_free(topic.s);
	if (broker && broker->prod && broker->prod->conf_strings)
		s_list_free(broker->prod->conf_strings);
	if (sock)
		shm_free(sock);
	return NULL;
}

static int kafka_evi_match(evi_reply_sock *sock1, evi_reply_sock *sock2)
{
	if (!sock1 || !sock2)
		return 0;

	if (!(sock1->flags & EVI_PARAMS) || !(sock2->flags & EVI_PARAMS) ||
		sock1->params != sock2->params)
		return 0;

	return 1;
}

static void kafka_evi_free(evi_reply_sock *sock)
{
	kafka_job_t *job;

	job = shm_malloc(sizeof *job + 1 + sizeof(evi_job_data_t));
	if (!job) {
		LM_ERR("oom!\n");
		goto error;
	}
	memset(job, 0, sizeof *job + 1 + sizeof(evi_job_data_t));

	job->payload.s = (char *)(job + 1);
	job->payload.len = 1;

	job->type = KAFKA_JOB_EVI;

	job->data = (void*)((char *)(job + 1) + 1);
	((evi_job_data_t *)job->data)->evi_sock = sock;

	if (kafka_send_job(job) < 0) {
		LM_ERR("cannot send job to worker\n");
		goto error;
	}

	return;

error:
	s_list_free(((kafka_producer_t*)sock->params)->conf_strings);
	shm_free(sock);
	if (job)
		shm_free(job);
}

static str kafka_evi_print(evi_reply_sock *sock)
{
	return sock->address;
}

static int kafka_evi_raise(struct sip_msg *msg, str* ev_name,
	evi_reply_sock *sock, evi_params_t *params, evi_async_ctx_t *async_ctx)
{
	kafka_job_t *job;
	kafka_producer_t *prod = (kafka_producer_t *)sock->params;
	str payload;
	str key = {0,0};

	if (!sock) {
		LM_ERR("invalid evi socket\n");
		return -1;
	}
	if (!prod) {
		LM_ERR("Invalid producer instance in evi sock params\n");
		return -1;
	}

	payload.s = evi_build_payload(params, ev_name, 0, NULL, NULL);
	if (!payload.s) {
		LM_ERR("Failed to build event payload\n");
		return -1;
	}
	payload.len = strlen(payload.s);

	if (prod->flags & PROD_MSG_KEY_CALLID) {
		if (parse_headers(msg, HDR_CALLID_F, 0) < 0) {
			LM_ERR("failed to parse SIP message\n");
			goto err_free;
		}
		if (msg->callid && msg->callid->body.len)
			key = msg->callid->body;
	}

	job = shm_malloc(sizeof *job + payload.len + key.len + sizeof(evi_job_data_t));
	if (!job) {
		LM_ERR("oom!\n");
		goto err_free;
	}
	memset(job, 0, sizeof *job + payload.len + key.len + sizeof(evi_job_data_t));

	job->payload.s = (char *)(job + 1);
	memcpy(job->payload.s, payload.s, payload.len);
	job->payload.len = payload.len;

	evi_free_payload(payload.s);

	if (key.len) {
		job->key.s = (char *)(job + 1) + payload.len;
		memcpy(job->key.s, key.s, key.len);
		job->key.len = key.len;
	}

	job->type = KAFKA_JOB_EVI;

	job->data = (void*)((char *)(job + 1) + payload.len + key.len);
	((evi_job_data_t *)job->data)->evi_sock = sock;
	((evi_job_data_t *)job->data)->evi_async_ctx = *async_ctx;

	if (kafka_send_job(job) < 0) {
		LM_ERR("cannot send job to worker\n");
		shm_free(job);
		return -1;
	}

	return 0;
err_free:
	evi_free_payload(payload.s);
	return -1;
}

static int fixup_broker(void **param)
{
	str *s = (str*)*param;

	*param = get_script_broker(s);
	if (*param == NULL) {
		LM_ERR("Unknown broker id: %.*s\n", s->len, s->s);
		return E_CFG;	
	}

	return 0;
}

static int fixup_report_route(void **param)
{
	int route_idx;
	str name;

	if (pkg_nt_str_dup(&name, (str*)*param) < 0) {
		LM_ERR("oom!\n");
		return -1;
	}

	route_idx = get_script_route_ID_by_name(name.s, sroutes->request, RT_NO);
	if (route_idx==-1) {
		LM_ERR("report route <%s> not defined in script\n", (char*)*param);
		return -1;
	}

	pkg_free(name.s);

	*param = (void*)(long)route_idx;

	return 0;
}

static int kafka_publish(struct sip_msg *sip_msg, kafka_broker_t *broker,
	str *msg, str *key, void *report_rt_p)
{
	int report_rt_idx = report_rt_p ? (int)(long)report_rt_p : -1;
	kafka_job_t *job;

	job = shm_malloc(sizeof *job + msg->len + key->len + sizeof(script_job_data_t));
	if (!job) {
		LM_ERR("oom!\n");
		return -1;
	}
	memset(job, 0, sizeof *job + msg->len + key->len + sizeof(script_job_data_t));

	job->payload.s = (char *)(job + 1);
	memcpy(job->payload.s, msg->s, msg->len);
	job->payload.len = msg->len;

	if (key->len) {
		job->key.s = (char *)(job + 1) + msg->len;
		memcpy(job->key.s, key->s, key->len);
		job->key.len = key->len;
	}

	job->type = KAFKA_JOB_SCRIPT;

	job->data = (void*)((char *)(job + 1) + msg->len + key->len);
	((script_job_data_t *)job->data)->broker = broker;
	((script_job_data_t *)job->data)->report_rt_idx = report_rt_idx;

	if (kafka_send_job(job) < 0) {
		LM_ERR("cannot send job to worker\n");
		shm_free(job);
		return -1;
	}

	return 1;
}
