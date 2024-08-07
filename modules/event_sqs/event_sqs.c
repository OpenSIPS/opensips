#include "../../sr_module.h"
#include "../../evi/evi_transport.h"
#include "../../ut.h"
#include "../../lib/list.h"
#include "../../mod_fix.h"
#include "../../str_list.h"
#include "sqs_lib.h"

#define IS_WS(_c) ((_c) == ' ' || (_c) == '\t' || (_c) == '\r' || (_c) == '\n')

static int mod_init(void);
static int child_init(int);
static void mod_destroy(void);
static int send_message(struct sip_msg *msg, str *broker_id, str *message_body);

static int add_script_broker(modparam_t type, void *val);
sqs_broker_t *get_script_broker(str *id);
static int fixup_broker(void **param);

struct list_head *sqs_brokers;
sqs_config config;

static const proc_export_t procs[] = {
	{0, 0, 0, 0, 0, 0}
};

static const param_export_t mod_params[] = {
	{"broker_id", STR_PARAM | USE_FUNC_PARAM, (void *)add_script_broker},
	{0, 0, 0}
};

static const cmd_export_t cmds[] = {
	{"sqs_send_message", (cmd_function)send_message, {
		{CMD_PARAM_STR, fixup_broker, 0},
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
	0,							/* xported transformations */
	procs,						/* extra processes */
	0,							/* module pre-initialization function */
	mod_init,					/* module initialization function */
	0,							/* response handling function */
	mod_destroy,				/* destroy function */
	child_init,					/* per-child init function */
	0							/* reload confirm function */
};

static int mod_init(void) {
	LM_NOTICE("initializing module ......\n");
	if (!sqs_brokers) {
		sqs_brokers = shm_malloc(sizeof *sqs_brokers);
		if (!sqs_brokers) {
			LM_ERR("oom!\n");
			return -1;
		}
		INIT_LIST_HEAD(sqs_brokers);
	}
	
	init_sqs(&config);

	return 0;
}

static int child_init(int rank) {
	return 0;
}

static void mod_destroy(void) {
	struct list_head *it, *tmp;
	sqs_broker_t *broker;

	LM_NOTICE("destroy module ...\n");

	list_for_each_safe(it, tmp, sqs_brokers) {
		broker = list_entry(it, sqs_broker_t, list);
		list_del(&broker->list);
		shm_free(broker);
	}

	shutdown_sqs(&config);
}

static int send_message(struct sip_msg *msg, str *broker_id, str *message_body) {
	LM_INFO("sqs_send_message called with broker_id: %.*s\n", broker_id->len, broker_id->s);
	sqs_broker_t *broker = get_script_broker(broker_id);
	if (!broker) {
		LM_ERR("Unknown broker id: %.*s\n", broker_id->len, broker_id->s);
		return -1;
	}

	return sqs_send_message(&config, broker->queue_url, *message_body) ? 0 : -1;
}

static int add_script_broker(modparam_t type, void *val) {
	str s, id;
	str queue_url = {0, 0};
	sqs_broker_t *broker = NULL;

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

	s.s++;
	s.len--;
	
	for (; s.len > 0; s.s++, s.len--)
		if (!IS_WS(*s.s))
			break;
	
	queue_url.s = s.s;
	queue_url.len = s.len;

	if (!sqs_brokers) {
		sqs_brokers = shm_malloc(sizeof *sqs_brokers);
		if (!sqs_brokers) {
			LM_ERR("oom!\n");
			return -1;
		}
		INIT_LIST_HEAD(sqs_brokers);
	}

	broker = shm_malloc(sizeof *broker + id.len + queue_url.len);
	if (!broker) {
		LM_ERR("oom!\n");
		return -1;
	}
	memset(broker, 0, sizeof *broker + id.len + queue_url.len);

	broker->id.s = (char *)(broker + 1);
	broker->id.len = id.len;
	memcpy(broker->id.s, id.s, id.len);

	broker->queue_url.s = (char *)(broker + 1) + id.len;
	broker->queue_url.len = queue_url.len;
	memcpy(broker->queue_url.s, queue_url.s, queue_url.len);


	INIT_LIST_HEAD(&broker->list);
	list_add(&broker->list, sqs_brokers);

	LM_NOTICE("Added SQS broker: %.*s\n", queue_url.len, queue_url.s);

	return 0;
}

static int fixup_broker(void **param) {
	str *s = (str *)*param;
	LM_NOTICE("fixup_broker called with broker_id: %.*s\n", s->len, s->s);

	*param = get_script_broker(s);
	if (*param == NULL) {
		LM_ERR("Unknown broker id: %.*s\n", s->len, s->s);
		return E_CFG;
	}

	return 0;
}

sqs_broker_t *get_script_broker(str *id) {
	struct list_head *it;
	sqs_broker_t *broker;

	LM_NOTICE("get_script_broker called with broker_id: %.*s\n", id->len, id->s);
	list_for_each(it, sqs_brokers) {
		broker = list_entry(it, sqs_broker_t, list);
		if (broker->id.len == id->len && memcmp(broker->id.s, id->s, id->len) == 0) {
			LM_NOTICE("Found broker with id: %.*s\n", id->len, id->s);
			return broker;
		}
	}
	LM_NOTICE("No broker found with id: %.*s\n", id->len, id->s);
	return NULL;
}
