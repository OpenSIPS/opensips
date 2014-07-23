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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>

/* default PVAR names */

/**
 * module functions
 */
static int mod_init(void);
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

#define SR_SOCK_ROUTE(_s) ((int)(unsigned long)(_s->params))

/**
 * module exported functions
 */
static cmd_export_t cmds[]={
	{"fetch_event_params", (cmd_function)scriptroute_fetch, 1,
		fixup_scriptroute_fetch, 0, EVENT_ROUTE|REQUEST_ROUTE },
	{0,0,0,0,0,0}
};


/**
 * module exports
 */
struct module_exports exports= {
	"event_route",			/* module name */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,		/* dlopen flags */
	cmds,					/* exported functions */
	0,						/* exported parameters */
	0,						/* exported statistics */
	0,						/* exported MI functions */
	0,						/* exported pseudo-variables */
	0,						/* extra processes */
	mod_init,				/* module initialization function */
	0,						/* response handling function */
	0,						/* destroy function */
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
	return 0;
}

static int child_init(int rank)
{
	char buffer[EV_SCRIPTROUTE_MAX_SOCK];
	str sock_name;
	str event_name;
	int idx;

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
	evi_reply_sock *sock = NULL;
	static char *dummy_buffer = 0, *name;
	int idx;

	if (!socket.len || !socket.s) {
		LM_ERR("no socket specified\n");
		return NULL;
	}

	/* try to normalize the route name */
	name = pkg_realloc(dummy_buffer, socket.len + 1);
	if (!name) {
		LM_ERR("no more pkg memory\n");
		return NULL;
	}
	memcpy(name, socket.s, socket.len);
	name[socket.len] = '\0';
	dummy_buffer = name;

	/* try to "resolve" the name of the route */
	idx = get_script_route_ID_by_name(name,event_rlist,EVENT_RT_NO);
	if (idx < 0) {
		LM_ERR("cannot found route %.*s\n", socket.len, socket.s);
		return NULL;
	}

	sock = shm_malloc(sizeof(evi_reply_sock) + socket.len + 1);
	if (!sock) {
		LM_ERR("no more memory for socket\n");
		return NULL;
	}
	memset(sock, 0, sizeof(evi_reply_sock));

	sock->address.s = (char *)(sock + 1);
	sock->address.len = socket.len;
	memcpy(sock->address.s, name, socket.len + 1);

	sock->params = (void *)(unsigned long)idx;
	sock->flags |= EVI_PARAMS;

	LM_DBG("route is <%.*s> idx %d\n", sock->address.len, sock->address.s, idx);
	sock->flags |= EVI_ADDRESS;

	return sock;
}

static str scriptroute_print(evi_reply_sock *sock)
{
	/* return only the route's name */
	return sock->address;
}

/* static parameters list retrieved by the fetch_event_params */
static evi_params_t *parameters = NULL;
str *event_name = NULL; // mostly used for debugging

static int scriptroute_raise(struct sip_msg *msg, str* ev_name,
							 evi_reply_sock *sock, evi_params_t *params)
{
	evi_params_t * backup_params;
	str * backup_name;

	if (!sock || !(sock->flags & EVI_PARAMS)) {
		LM_ERR("no socket found\n");
		return -1;
	}

	/* check the socket type */
	if (!(sock->flags & SCRIPTROUTE_FLAG)) {
		LM_ERR("invalid socket type\n");
		return -1;
	}

	/* save the previous parameters */
	backup_params = parameters;
	backup_name = event_name;

	parameters = params;
	event_name = ev_name;

	run_top_route(event_rlist[SR_SOCK_ROUTE(sock)].a, msg);

	/* restore previous parameters */
	parameters = backup_params;
	event_name = backup_name;

	return 0;
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
		if (pv_parse_spec(&s, &elem->spec) < 0) {
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
