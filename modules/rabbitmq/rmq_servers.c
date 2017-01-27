/*
 * Copyright (C) 2017 OpenSIPS Project
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
 * History:
 * ---------
 *  2017-01-24  created (razvanc)
 */

#include "../../mem/shm_mem.h"
#include "../../sr_module.h"
#include "../../db/db_id.h"
#include "../../lib/list.h"
#include "../../mod_fix.h"
#include "../../dprint.h"
#include "../../ut.h"

#include "rmq_servers.h"

static LIST_HEAD(rmq_servers);

enum rmq_func_param_type { RMQT_SERVER, RMQT_PVAR };
struct rmq_func_param {
	enum rmq_func_param_type type;
	void *value;
};


/* function used to get a rmq_server based on a cid */
struct rmq_server *rmq_get_server(str *cid)
{
	struct list_head *it;
	struct rmq_server *srv;

	list_for_each(it, &rmq_servers) {
		srv = container_of(it, struct rmq_server, list);
		if (srv->cid.len == cid->len && memcmp(srv->cid.s, cid->s, cid->len) == 0)
			return srv;
	}
	return NULL;
}

struct rmq_server *rmq_resolve_server(struct sip_msg *msg, char *param)
{
	struct rmq_func_param *p = (struct rmq_func_param *)param;
	str cid;

	if (p->type == RMQT_SERVER)
		return p->value;

	if (fixup_get_svalue(msg, (gparam_p)param, &cid) < 0) {
		LM_ERR("cannot get the connection id!\n");
		return NULL;
	}
	return rmq_get_server(&cid);
}

/*
 * function used to reconnect a RabbitMQ server
 */
int rmq_reconnect(struct rmq_server *srv)
{
	switch (srv->state) {
	case RMQS_NONE:
		break;
	default:
		break;
	}
	return -1;
}

#define IS_WS(_c) ((_c) == ' ' || (_c) == '\t' || (_c) == '\r' || (_c) == '\n')

/*
 * function used to add a RabbitMQ server
 */
int rmq_server_add(modparam_t type, void * val)
{
	struct rmq_server *srv;
	str s;
	str cid;
	str uri = {0, 0};
	char uri_pending = 0;
	struct db_id *id;

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
		LM_ERR("cannot find connection id start: %.*s\n", s.len, s.s);
		return -1;
	}
	cid.s = s.s + 1;
	for (s.s++, s.len--; s.len > 0; s.s++, s.len--)
		if (*s.s == ']')
			break;
	if (s.len <= 0 || *s.s != ']') {
		LM_ERR("cannot find connection id end: %.*s\n", s.len, s.s);
		return -1;
	}
	cid.len = s.s - cid.s;

	/* check if the server was already defined */
	if (rmq_get_server(&cid)) {
		LM_ERR("Connection ID %.*s already defined! Please use different "
				"names for different connections!\n", cid.len, cid.s);
		return -1;
	}

	/* server not found - parse this one */
	for (s.s++, s.len--; s.len > 0; s.s++, s.len--) {
		if (IS_WS(*s.s))
			continue;
		if (s.len > 4 && strncasecmp(s.s, "uri", 3) == 0) {
			/* skip spaces before = */
			for (s.len -= 3, s.s += 3; s.len > 0; s.s++, s.len--)
				if (!IS_WS(*s.s))
					break;
			if (s.len <= 0 || *s.s != '=') {
				LM_ERR("cannot find uri equal: %.*s\n", s.len, s.s);
				return -1;
			}
			s.s++;
			s.len--;

			/* remember where the uri starts */
			uri = s;
			uri_pending = 1;
		} else {
			/* we eneded up in a place that has ';' - if we haven't found
			 * the end of the uri, this is also part of the uri. otherwise it
			 * is an error and we shall report it */
			if (!uri_pending) {
				LM_ERR("Unknown parameter: %.*s\n", s.len, s.s);
				return -1;
			}
		}
		/* search for the next ';' */
		for (; s.len > 0; s.s++, s.len--)
			if (*s.s == ';')
				break;
	}
	/* if we don't have an uri, we forfeit */
	if (!uri.s) {
		LM_ERR("cannot find an uri!");
		return -1;
	}
	/* if still pending, remove the last ';' */
	trim_spaces_lr(uri);
	if (uri_pending && uri.s[uri.len - 1] == ';')
		uri.len--;
	trim_spaces_lr(uri);

	id = new_db_id(&uri);
	if (!id) {
		LM_ERR("invalid url specified\n");
		return -1;
	}

	/* check schema type */
	if (strcmp(id->scheme, "amqp") != 0) {
		LM_ERR("invalid URL scheme '%s' currently only amqp is accepted!\n",
				id->scheme);
		goto free;
	}
	/* TODO: handle amqps */

	if ((srv = pkg_malloc(sizeof *srv)) == NULL) {
		LM_ERR("cannot alloc memory for rabbitmq url\n");
		goto free;
	}
	srv->state = RMQS_NONE;
	srv->id = id;
	srv->cid = cid;

	list_add(&srv->list, &rmq_servers);
	LM_DBG("new AMQP uri=%.*s with cid=%.*s\n",
			srv->id->url.len, srv->id->url.s, srv->cid.len, srv->cid.s);

	/* parse the url */
	return 0;
free:
	free_db_id(id);
	return -1;
}
#undef IS_WS

/*
 * fixup function for rmq_server
 */
int fixup_rmq_server(void **param)
{
	str tmp;
	struct rmq_func_param *p;
	tmp.s = (char *)*param;
	tmp.len = strlen(tmp.s);
	trim_spaces_lr(tmp);
	if (tmp.len <= 0) {
		LM_ERR("invalid connection id!\n");
		return E_CFG;
	}
	p = pkg_malloc(sizeof(*p));
	if (!p) {
		LM_ERR("out of pkg memory!\n");
		return E_OUT_OF_MEM;
	}

	if (tmp.s[0] == PV_MARKER) {
		if (fixup_pvar(param) < 0) {
			LM_ERR("cannot parse cid\n");
			return E_UNSPEC;
		}
		p->value = *param;
		p->type = RMQT_PVAR;
	} else {
		p->value = rmq_get_server(&tmp);
		if (!p->value) {
			LM_ERR("unknown connection id=%.*s\n",
					tmp.len, tmp.s);
			return E_CFG;
		}
		p->type = RMQT_SERVER;
	}
	*param = p;
	return 0;
}

/*
 * function to connect all rmq servers
 */
void rmq_connect_servers(void)
{
	struct list_head *it;
	struct rmq_server *srv;

	list_for_each(it, &rmq_servers) {
		srv = container_of(it, struct rmq_server, list);
		if (rmq_reconnect(srv) < 0)
			LM_ERR("cannot connect to RabbitMQ server %.*s\n",
					srv->id->url.len, srv->id->url.s);
	}
	
}
