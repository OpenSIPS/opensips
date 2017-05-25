/*
 * Copyright (C) 2012 OpenSIPS Solutions
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
 *  2012-12-xx  created (razvancrainea)
 */

#include "../../sr_module.h"
#include "../../evi/evi_transport.h"
#include "../../evi/evi_modules.h"
#include "../../ut.h"
#include "event_route.h"
#include "route_send.h"
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>

/* default PVAR names */

/**
 * module functions
 */
static int mod_init(void);
static void destroy(void);
static int child_init(int rank);
static int scriptroute_fetch(struct sip_msg *msg, char *list);
static int fixup_scriptroute_fetch(void **param, int param_no);


/**
 * exported functions
 */
static evi_reply_sock* scriptroute_parse(str socket);
static int scriptroute_raise(struct sip_msg *msg, str* ev_name,
							 evi_reply_sock *sock, evi_params_t * params);
static int scriptroute_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
static str scriptroute_print(evi_reply_sock *sock);
static inline int get_script_event_route_ID_by_name(char* name, struct script_event_route *sr, int size);

#define SR_SOCK_ROUTE(_s) ((int)(unsigned long)(_s->params))
#define EVENT_ROUTE_MODE_SEP '/'
#define EVENT_ROUTE_SYNC  0
#define EVENT_ROUTE_ASYNC 1

/**
 *  * module process
 *   */
static proc_export_t procs[] = {
	{"event-route handler",  0,  0, event_route_handler, 1, 0},
	{0,0,0,0,0,0}
};
/**
 * module exported functions
 */
static cmd_export_t cmds[]={
	{"fetch_event_params", (cmd_function)scriptroute_fetch, 1,
		fixup_scriptroute_fetch, 0, EVENT_ROUTE|REQUEST_ROUTE },
	{0,0,0,0,0,0}
};

static param_export_t params[] = {
	{0, 0, 0}
};

/**
 * module exports
 */
struct module_exports exports= {
	"event_route",			/* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,		/* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	cmds,					/* exported functions */
	0,						/* exported async functions */
	params,						/* exported parameters */
	0,						/* exported statistics */
	0,						/* exported MI functions */
	0,						/* exported pseudo-variables */
	0,			 			/* exported transformations */
	procs,					/* extra processes */
	mod_init,				/* module initialization function */
	0,						/* response handling function */
	destroy,				/* destroy function */
	child_init				/* per-child init function */
};


/**
 * exported functions for core event interface
 */
static evi_export_t trans_export_scriptroute = {
	SCRIPTROUTE_NAME_STR,	/* transport module name */
	scriptroute_raise,		/* raise function */
	scriptroute_parse,		/* parse function */
	scriptroute_match,		/* sockets match function */
	0,						/* no free function */
	scriptroute_print,		/* socket print function */
	SCRIPTROUTE_FLAG		/* flags */
};

/**
 * init module function
 */
static int mod_init(void)
{
	LM_NOTICE("initializing module ...\n");

	if (register_event_mod(&trans_export_scriptroute)) {
		LM_ERR("cannot register transport functions for SCRIPTROUTE\n");
		return -1;
	}

	if (create_pipe() < 0) {
		LM_ERR("cannot create communication pipe\n");
		return -1;
	}

	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	LM_NOTICE("destroy module ...\n");
	/* closing sockets */
	destroy_pipe();
}

static int child_init(int rank)
{

	char buffer[EV_SCRIPTROUTE_MAX_SOCK];
	str sock_name;
	str event_name;
	int idx;

	if (init_writer() < 0) {
		LM_ERR("cannot init writing pipe\n");
		return -1;
	}

	/*
	 * Only the first process registers the subscribers
	 *
	 * We do this in child init because here we are sure that all
	 * the events were subscribed
	 */
	if (rank != 1)
		return 0;

	/* init the socket buffer */
	sock_name.s = buffer;
	memcpy(buffer, SCRIPTROUTE_NAME, sizeof(SCRIPTROUTE_NAME) - 1);
	buffer[sizeof(SCRIPTROUTE_NAME) - 1] = COLON_C;

	/* subscribe the route events - idx starts at 1 */
	for (idx = 1; event_rlist[idx].a && event_rlist[idx].name; idx++) {
		/* build the socket */
		event_name.s = event_rlist[idx].name;
		event_name.len = strlen(event_rlist[idx].name);

		/* first check if the event exists */
		if (evi_get_id(&event_name) == EVI_ERROR) {
			LM_ERR("Event %s not registered\n", event_name.s);
			return -1;
		}
		LM_DBG("Registering event %s\n", event_rlist[idx].name);

		if (sizeof(SCRIPTROUTE_NAME)+event_name.len > EV_SCRIPTROUTE_MAX_SOCK) {
			LM_ERR("socket name too big %d (max: %d)\n",
				   (int)(sizeof(SCRIPTROUTE_NAME) + event_name.len),
				   EV_SCRIPTROUTE_MAX_SOCK);
			return -1;
		}
		memcpy(buffer + sizeof(SCRIPTROUTE_NAME), event_name.s, event_name.len);
		sock_name.len = event_name.len + sizeof(SCRIPTROUTE_NAME);

		if (sock_name.len + event_rlist[idx].mode+4 /*"sync"*/
				+1 /*'/'*/ > EV_SCRIPTROUTE_MAX_SOCK) {
			LM_ERR("not enough room in socket name buffer\n");
			return -1;
		}

		sock_name.s[sock_name.len++] = EVENT_ROUTE_MODE_SEP;
		switch (event_rlist[idx].mode) {
			case 0: /*sync*/
				memcpy(sock_name.s+sock_name.len, "sync", 4);
				sock_name.len += 4;
				break;
			case 1: /*async*/
				memcpy(sock_name.s+sock_name.len, "async", 5);
				sock_name.len += 5;
				break;
			default:
				LM_ERR("invalid route mode value (%d)\n!"
					"Possibility of memory corruption\n",
						event_rlist[idx].mode);
				return -1;
		}

		/* register the subscriber - does not expire */
		if (evi_event_subscribe(event_name, sock_name, 0, 0) < 0) {
			LM_ERR("cannot subscribe to event %s\n", event_name.s);
			return -1;
		}
	}

	return 0;
}


/* returns 0 if sockets match */
static int scriptroute_match(evi_reply_sock *sock1, evi_reply_sock *sock2)
{
	if (!sock1 || !sock2)
		return 0;
	if (!(sock1->flags & EVI_PARAMS) || !(sock2->flags & EVI_PARAMS) ||
		SR_SOCK_ROUTE(sock1) != SR_SOCK_ROUTE(sock2))
		return 0;
	return 1;
}


static evi_reply_sock* scriptroute_parse(str socket)
{
	#define SET_MSB(value, type) ((type)value << (sizeof(type) * 8 /*BYTE SIZE*/ - 1))

	evi_reply_sock *sock = NULL;
	static char *dummy_buffer = 0, *name;
	int idx, mode=-1, name_len = 0;
	char* mode_pos;

	if (!socket.len || !socket.s) {
		LM_ERR("no socket specified\n");
		return NULL;
	}

	mode_pos = q_memrchr(socket.s, EVENT_ROUTE_MODE_SEP, socket.len);
	if (mode_pos == NULL)
		mode = 0; /*default 'sync'*/
	else
		mode_pos++;

	if (mode_pos) {
		if (!strncmp(mode_pos, "sync", 4)) {
			mode = 0;
		} else if (!strncmp(mode_pos, "async", 5)) {
			mode = 1;
		} else {
			LM_ERR("invalid sync/async mode\n");
			return NULL;
		}
		name_len = socket.len-(mode/*if async add 1*/+4/*sync len*/+1/*'/'*/);
		name = pkg_realloc(dummy_buffer, name_len + 1);
	} else {
		name_len = 0;
		name = pkg_realloc(dummy_buffer, socket.len+1);
	}

	if (!name) {
		LM_ERR("no more pkg memory\n");
		return NULL;
	}


	if (mode_pos) {
		memcpy(name, socket.s, name_len);
		name[name_len] = '\0';
	} else {
		memcpy(name, socket.s, socket.len);
		name[socket.len] = '\0';
	}

	dummy_buffer = name;

	/* try to "resolve" the name of the route */
	idx = get_script_event_route_ID_by_name(name,event_rlist,EVENT_RT_NO);
	if (idx < 0) {
		LM_ERR("cannot find route %s\n", name);
		return NULL;
	}

	if (mode_pos)
		sock = shm_malloc(sizeof(evi_reply_sock) + name_len + 1);
	else
		sock = shm_malloc(sizeof(evi_reply_sock) + socket.len + 1);

	if (!sock) {
		LM_ERR("no more memory for socket\n");
		return NULL;
	}
	memset(sock, 0, sizeof(evi_reply_sock));

	sock->address.s = (char *)(sock + 1);

	if (mode_pos) {
		memcpy(sock->address.s, name, name_len + 1);
		sock->address.len = name_len;
	} else {
		memcpy(sock->address.s, name, socket.len + 1);
		sock->address.len = socket.len;
	}

	sock->params = (void *)(unsigned long)idx;
	sock->params = (void *)((unsigned long)sock->params |
					SET_MSB(mode, unsigned long));

	sock->flags |= EVI_PARAMS;

	LM_DBG("route is <%.*s> idx %d mode %s\n", sock->address.len, sock->address.s, idx, mode==0?"snyc":"async");
	sock->flags |= EVI_ADDRESS;

	return sock;

	#undef SET_MSB
}

static str scriptroute_print(evi_reply_sock *sock)
{
	/* return only the route's name */
	return sock->address;
}

/* static parameters list retrieved by the fetch_event_params */
evi_params_t *parameters = NULL;
str *event_name = NULL; // mostly used for debugging

static int scriptroute_raise(struct sip_msg *msg, str* ev_name,
							 evi_reply_sock *sock, evi_params_t *params)
{
	#define GET_MSB(value, type) ((type)((type)value & (((type)1 << (sizeof(type) * 8 /*BYTE SIZE*/ - 1)))))
	#define UNSET_MSB(value, type) ((type)value & (~((type)1 << (sizeof(type) * 8  - 1))))
	#define SET_MSB(value, type) ((type)value << (sizeof(type) * 8 /*BYTE SIZE*/ - 1))

	evi_params_t * backup_params;
	str * backup_name;
	route_send_t *buf = NULL;
	int sync_mode;


	if (!sock || !(sock->flags & EVI_PARAMS)) {
		LM_ERR("no socket found\n");
		return -1;
	}

	/* check the socket type */
	if (!(sock->flags & SCRIPTROUTE_FLAG)) {
		LM_ERR("invalid socket type\n");
		return -1;
	}

	sync_mode = GET_MSB(sock->params, unsigned long) ? 0 : 1;
	sock->params = (void*)UNSET_MSB(sock->params, unsigned long);

	if (sync_mode) {
		if (exports.procs)
			exports.procs = 0;

		/* save the previous parameters */
		backup_params = parameters;
		backup_name = event_name;

		parameters = params;
		event_name = ev_name;

		run_top_route(event_rlist[SR_SOCK_ROUTE(sock)].a, msg);

		/* restore previous parameters */
		parameters = backup_params;
		event_name = backup_name;

	} else {
		if (route_build_buffer(ev_name, sock, params, &buf) < 0) goto reset_msb;
		buf->a = event_rlist[SR_SOCK_ROUTE(sock)].a;

		if (route_send(buf) < 0) goto reset_msb;

		sock->params = (void *)((unsigned long)sock->params |
						SET_MSB(1, unsigned long));
	}

	return 0;


reset_msb:
	sock->params = (void *)((unsigned long)sock->params |
					SET_MSB(1, unsigned long));
	return -1;

	#undef GET_MSB
	#undef UNSET_MSB
	#undef SET_MSB
}

struct scriptroute_params {
	int index;		// index of the param
	str name;		// the name of the param
	pv_spec_t spec;	// pvar spec
	struct scriptroute_params *next; // next element
};


static int scriptroute_add_param(struct sip_msg *msg,
								 struct scriptroute_params *param) {

	int index;
	evi_param_t *it = parameters->first;
	pv_value_t val;

	if (param->index) {
		/* search the parameter by it's index */
		for (index = 1; it && index != param->index; it = it->next, index++);
		if (!it) {
			LM_WARN("Parameter %d not found - max %d\n", param->index, index);
			return 0;
		}
	} else {
		/* specified by name */
		for (; it; it = it->next) {
			if (it->name.s && it->name.len == param->name.len &&
					memcmp(it->name.s, param->name.s, it->name.len) == 0)
				break;
		}
		if (!it) {
			LM_WARN("Parameter <%.*s> not found for event <%.*s>\n",
					param->name.len, param->name.s,
					event_name->len, event_name->s);
			return 0;
		}
	}

	/* parameter found - populate it */
	if (it->flags & EVI_INT_VAL) {
		val.ri = it->val.n;
		val.flags = PV_VAL_INT|PV_TYPE_INT;
	} else {
		val.rs.len = it->val.s.len;
		val.rs.s = it->val.s.s;
		val.flags = PV_VAL_STR;
	}

	if (pv_set_value(msg, &param->spec, 0, &val) < 0) {
		LM_WARN("cannot populate parameter\n");
		return 0;
	}

	return 1;
}


/**
 * Functions used to fetch the event's parameters
 */
static int scriptroute_fetch(struct sip_msg *msg, char *_list)
{
	int nr = 0;
	struct scriptroute_params *list = (struct scriptroute_params*)_list;

	if (!list) {
		LM_ERR("BUG: no parameters specified\n");
		return -1;
	}
	if (!event_name) {
		LM_ERR("No event raised in this scope\n");
		return -1;
	}

	/* check if no parameters were specified */
	if (!parameters) {
		LM_DBG("This event does not have any parameters\n");
		return -2;
	}

	LM_DBG("Fetching parameters for event %.*s\n",
		   event_name->len, event_name->s);

	for (; list; list = list->next)
		nr += scriptroute_add_param(msg, list);

	LM_DBG("Successfully fetched %d parameters\n", nr);

	return nr ? nr : -3;
}

static int fixup_scriptroute_fetch(void **param, int param_no)
{
	char *end, *p, *e;
	str s, name;
	int index = 0;
	struct scriptroute_params *list = NULL;
	struct scriptroute_params *elem = NULL;
	struct scriptroute_params *next = NULL;


	if (param_no != 1) {
		LM_ERR("BUG: No such parameters %d\n", param_no);
		return E_BUG;
	}

	p = (char*)(*param);
	end = p + strlen(p);

	while (p < end) {
		name.s = 0;
		s.s = p;
		while (p < end && *p != ';')
			p++;

		// check if equal is found
		for (e = s.s; e < p && *e != '='; e++);
		// avoid old gcc versions warning
		name.len = 0;
		if (e == p) {
			s.len = e - s.s;
			trim_spaces_lr(s);
			if (s.len <= 0) {
				LM_WARN("No pvar specified near <%.*s>\n",
						(int)(p - s.s), s.s);
				goto next;
			}
			index++;
			name.s = 0;
			// the pvar is in s
		} else {
			name.s = s.s;
			name.len = e - s.s;
			trim_spaces_lr(name);
			if (name.len <= 0) {
				LM_WARN("No name specified near <%.*s>\n",
						(int)(p - s.s), s.s);
				goto next;
			}
			s.s = e + 1;
			s.len = p - s.s;
			trim_spaces_lr(s);
			if (s.len <= 0) {
				LM_WARN("No pvar specified near %.*s\n",
						(int)(p - s.s), s.s);
				goto next;
			}
		}
		elem = shm_malloc(sizeof(struct scriptroute_params));
		if (!elem) {
			LM_ERR("no more shm memory\n");
			return E_OUT_OF_MEM;
		}
		memset(elem, 0, sizeof(struct scriptroute_params));
		if (pv_parse_spec(&s, &elem->spec) == NULL) {
			LM_ERR("cannot parse spec <%.*s>\n", s.len, s.s);
			shm_free(elem);
			goto error;
		}
		/* if name specified, use it - otherwise param index */
		if (name.s) {
			elem->name = name;
			LM_DBG("Parameter %.*s will be set in %.*s\n",
				   name.len, name.s, s.len, s.s);
		} else {
			elem->index = index;
			LM_DBG("Parameter %d will be set in %.*s\n", index,
				   s.len, s.s);
		}
		/* link it to parameters list */
		elem->next = list;
		list = elem;

next:
		p++;
	}

	*param = (void*)list;
	return 0;
error:
	for (elem = list; elem; elem = next) {
		next = elem->next;
		shm_free(elem);
	}
	return E_CFG;
}

static inline int get_script_event_route_ID_by_name(char* name, struct script_event_route *sr, int size)
{
	unsigned int i;

	for (i=1;i<size;i++) {
		if (sr[i].name==0)
			return -1;
		if (strcmp(sr[i].name, name) == 0)
			return i;
	}

	return -1;
}
