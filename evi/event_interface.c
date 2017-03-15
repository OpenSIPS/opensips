/*
 * Copyright (C) 2011 OpenSIPS Solutions
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
 *  2011-05-xx  created (razvancrainea)
 */

#include "event_interface.h"
#include "evi_modules.h"
#include "../mem/shm_mem.h"
#include "../mi/mi.h"
#include "../pvar.h"
#include "../timer.h"
#include "../ut.h"


int events_no = 0;
int max_alloc_events = 10;
static int events_rec_level = MAX_REC_LEV;

/* holds all exported events */
evi_event_t *events = NULL;

event_id_t evi_publish_event(str event_name)
{
	int idx;

	if (event_name.len > MAX_EVENT_NAME) {
		LM_ERR("event name too long [%d>%d]\n", event_name.len, MAX_EVENT_NAME);
		return EVI_ERROR;
	}

	idx = evi_get_id(&event_name);
	if (idx != EVI_ERROR) {
		LM_WARN("Event \"%.*s\" was previously published\n",
				event_name.len, event_name.s);
		return idx;
	}

	/* check if the event was already registered */
	if (!events) {
		/* first event */
		events = shm_malloc(max_alloc_events * sizeof(evi_event_t));
		if (!events) {
			LM_ERR("no more shm memory to hold %d events\n", max_alloc_events);
			return EVI_ERROR;
		}
	} else if (events_no == max_alloc_events) {
		max_alloc_events *= 2;
		events = shm_realloc(events, max_alloc_events * sizeof(evi_event_t));
		if (!events) {
			LM_ERR("no more shm memory to hold %d events\n", max_alloc_events);
			return EVI_ERROR;
		}
	}

	events[events_no].lock = lock_alloc();
	if (!events[events_no].lock) {
		LM_ERR("Failed to allocate subscribers lock\n");
		return EVI_ERROR;
	}
	events[events_no].lock = lock_init(events[events_no].lock);
	if (!events[events_no].lock) {
		LM_ERR("Failed to create subscribers lock\n");
		return EVI_ERROR;
	}

	events[events_no].id = events_no;
	events[events_no].name.s = event_name.s;
	events[events_no].name.len = event_name.len;
	events[events_no].subscribers = NULL;
	LM_INFO("Registered event <%.*s(%d)>\n", event_name.len, event_name.s, events_no);

	return events_no++;
}

int evi_raise_event(event_id_t id, evi_params_t* params)
{
	int status;
	struct sip_msg* req= NULL;
	struct usr_avp *event_avps = 0;
	struct usr_avp **bak_avps = 0;

	/*
	 * because these might be nested, a different message has
	 * to be generated each time
	 */
	req = (struct sip_msg*)pkg_malloc(sizeof(struct sip_msg));
	if(req == NULL)
	{
		LM_ERR("No more memory\n");
		return -1;
	}
	memset(req, 0, sizeof(struct sip_msg));

	req->first_line.type = SIP_REQUEST;
	req->first_line.u.request.method.s= "DUMMY";
	req->first_line.u.request.method.len= 5;
	req->first_line.u.request.uri.s= "sip:user@domain.com";
	req->first_line.u.request.uri.len= 19;
	req->rcv.src_ip.af = AF_INET;
	req->rcv.dst_ip.af = AF_INET;


	bak_avps = set_avp_list(&event_avps);

	status = evi_raise_event_msg(req, id, params);

	/* clean whatever extra structures were added by script functions */
	free_sip_msg(req);
	pkg_free(req);

	/* remove all avps added */
	destroy_avp_list(&event_avps);
	set_avp_list(bak_avps);

	return status;
}

/* XXX: this function should release its parameters before exiting */
int evi_raise_event_msg(struct sip_msg *msg, event_id_t id, evi_params_t* params)
{
	evi_subs_p subs, prev;
	long now;
	int flags, pflags = 0;
	int ret = 0;

	if (id < 0 || id >= events_no) {
		LM_ERR("invalid event %d\n", id);
		goto free;
	}

	if (events_rec_level == 0) {
		LM_ERR("Too many nested events %d\n", MAX_REC_LEV);
		goto free;
	}
	events_rec_level--;
	if (params)
		pflags = params->flags;

	lock_get(events[id].lock);
	now = time(0);
	subs = events[id].subscribers;
	prev = NULL;
	while (subs) {
		if (!subs->reply_sock) {
			LM_ERR("unknown destination\n");
			continue;
		}
		/* check expire */
		if (!(subs->reply_sock->flags & EVI_PENDING) &&
				subs->reply_sock->flags & EVI_EXPIRE &&
				subs->reply_sock->subscription_time +
				subs->reply_sock->expire < now) {
			if (subs->trans_mod && subs->trans_mod->free)
				subs->trans_mod->free(subs->reply_sock);
			else
				shm_free(subs->reply_sock);
			if (!prev) {
				events[id].subscribers = subs->next;
				shm_free(subs);
				subs = events[id].subscribers;
			} else {
				prev->next = subs->next;
				shm_free(subs);
				subs = prev->next;
			}
			continue;
		}

		if (!subs->trans_mod) {
			LM_ERR("unknown transfer protocol\n");
			goto next;
		}

		LM_DBG("found subscriber %.*s\n",
				subs->reply_sock->address.len, subs->reply_sock->address.s);
		if (!subs->trans_mod->raise) {
			LM_ERR("\"%.*s\" protocol cannot raise events\n",
					subs->trans_mod->proto.len, subs->trans_mod->proto.s);
			goto next;
		}
		/* we use this var to make sure nested calls don't reset the flag */
		flags = subs->reply_sock->flags;
		subs->reply_sock->flags |= EVI_PENDING;
		/* make sure nested events don't deadlock */
		lock_release(events[id].lock);

		ret += (subs->trans_mod->raise)(msg, &events[id].name,
					subs->reply_sock, params);

		lock_get(events[id].lock);
		subs->reply_sock->flags = flags;
next:
		prev = subs;
		subs = subs->next;
	}
	lock_release(events[id].lock);

	events_rec_level++;
	if (params)
		params->flags = pflags;
free:
	/* done sending events - free parameters */
	if (params) {
		/* make sure no one is messing with our flags */
		if (params->flags & EVI_FREE_LIST)
			evi_free_params(params);
	}
	return ret;

}

int evi_probe_event(event_id_t id)
{
	if (id < 0 || id >= events_no) {
		LM_ERR("invalid event %d\n", id);
		return -1;
	}

	/* check for subscribers */
	if (!events[id].subscribers)
		return 0;

	/* returns the number of transport module loaded */
	return get_trans_mod_no();
}


/* returns the id of an event */
event_id_t evi_get_id(str *name)
{
	int i;
	for (i = 0; i < events_no; i++)
		if (events[i].name.len == name->len &&
				!memcmp(events[i].name.s, name->s, name->len))
			return i;
	return EVI_ERROR;
}


/* returns an event id */
evi_event_p evi_get_event(str *name)
{
	event_id_t id = evi_get_id(name);
	return id == EVI_ERROR ? NULL : &events[id];
}

/*
 * Subscribes an event
 * Returns:
 *  1 - success
 *  0 - internal error
 * -1 - param error
 */
int evi_event_subscribe(str event_name,
		str sock_str, unsigned expire, unsigned unsubscribe)
{
	evi_subs_t *subscriber = NULL;
	evi_event_p event;
	evi_export_t *trans_mod = NULL;
	evi_reply_sock *sock;

	event = evi_get_event(&event_name);
	if (!event) {
		LM_ERR("invalid event name <%.*s>\n",
				event_name.len, event_name.s);
		goto bad_param;
	}

	/* transport module name */
	trans_mod = get_trans_mod(&sock_str);
	if (!trans_mod) {
		LM_ERR("couldn't find a protocol to support %.*s\n",
				sock_str.len, sock_str.s);
		goto bad_param;
	}
	sock_str.s += trans_mod->proto.len + 1;
	sock_str.len -= (trans_mod->proto.len + 1);

	/* parse reply socket */
	sock = trans_mod->parse(sock_str);
	if (!sock)
		goto bad_param;
	/* reset unrequired flags */
	if (!expire && !unsubscribe)
		sock->flags &= ~EVI_EXPIRE;

	/* tries to match other socket */
	if (trans_mod->match) {
		lock_get(event->lock);
		for (subscriber = event->subscribers; subscriber;
				subscriber = subscriber->next) {
			if (subscriber->trans_mod != trans_mod)
				continue;
			if (trans_mod->match(sock, subscriber->reply_sock)) {
				/* update subscription time */
				subscriber->reply_sock->subscription_time = time(0);
				/* update expire if required */
				if (EVI_EXPIRE & sock->flags) {
					subscriber->reply_sock->expire = expire;
					subscriber->reply_sock->flags = sock->flags;
				}
				if (trans_mod->free)
					trans_mod->free(sock);
				else
					shm_free(sock);
				break;
			}
		}
		lock_release(event->lock);
	}

	/* if no socket matches - create a new one */
	if (!subscriber) {
		subscriber = shm_malloc(sizeof(evi_subs_t));
		if (!subscriber) {
			LM_ERR("no more shm memory\n");
			if (trans_mod && sock) {
				/* if the module has it's own free function */
				if (trans_mod->free)
					trans_mod->free(sock);
				else
					shm_free(sock);
			}
			return 0;
		}

		sock->subscription_time = time(0);
		subscriber->trans_mod = trans_mod;
		subscriber->reply_sock = sock;

		if (EVI_EXPIRE & sock->flags)
			subscriber->reply_sock->expire = expire;
		subscriber->reply_sock->flags |= trans_mod->flags;

		/* guard subscribers list */
		lock_get(event->lock);
		subscriber->next = event->subscribers;
		event->subscribers = subscriber;
		lock_release(event->lock);
		LM_DBG("added new subscriber for event %d\n", event->id);
	}

	return 1;
bad_param:
	return -1;
}

int evi_raise_script_event(struct sip_msg *msg, event_id_t id, void * _a, void * _v)
{
	pv_spec_p vals = (pv_spec_p)_v;
	pv_spec_p attrs = (pv_spec_p)_a;
	struct usr_avp *v_avp = NULL;
	struct usr_avp *a_avp = NULL;
	int err = evi_probe_event(id);
	int_str val, attr;
	str *at;
	evi_params_p params = NULL;

	if (err < 0)
		return err;
	else if (!err)
		return 1;

	if (!vals)
		goto raise;
	if (!(params = evi_get_params())) {
		LM_ERR("cannot create parameters list\n");
		goto raise;
	}

	/* handle parameters */
	while ((v_avp = search_first_avp(vals->pvp.pvn.u.isname.type,
					vals->pvp.pvn.u.isname.name.n, &val, v_avp))) {
		at = NULL;
		/* check attribute */
		if (attrs) {
			err = -1;
			a_avp = search_first_avp(attrs->pvp.pvn.u.isname.type,
					attrs->pvp.pvn.u.isname.name.n, &attr, a_avp);
			if (!a_avp) {
				LM_ERR("missing attribute\n");
				goto error;
			}
			if (!(a_avp->flags & AVP_VAL_STR)) {
				LM_ERR("invalid attribute name - must be string\n");
				goto error;
			}
			at = &attr.s;
		}

		if (v_avp->flags & AVP_VAL_STR)
			err = evi_param_add_str(params, at, &val.s);
		else
			err = evi_param_add_int(params, at, &val.n);
		if (err) {
			LM_ERR("error while adding parameter\n");
			goto error;
		}
	}

	/* check if there were too many attribute names */
	if (attrs && a_avp && search_first_avp(attrs->pvp.pvn.u.isname.type,
				attrs->pvp.pvn.u.isname.name.n, &attr, a_avp)) {
		/* only signal error - continue */
		LM_ERR("too many attribute names\n");
	}

raise:
	err = evi_raise_event_msg(msg, id, params);
	return err ? err : 1;
error:
	evi_free_params(params);
	return -1;
}

struct mi_root * mi_event_subscribe(struct mi_root *root, void *param )
{
	struct mi_node *node;
	int ret;
	unsigned int expire = 0;
	str event_name, transport_sock;

	/* event name */
	node = root->node.kids;
	if (!node || !node->value.len || !node->value.s) {
		LM_ERR("no parameters received\n");
		goto missing_param;
	}
	event_name = node->value;

	/* socket */
	node = node->next;
	if (!node || !node->value.len || !node->value.s) {
		LM_ERR("no transport type\n");
		goto missing_param;
	}
	transport_sock = node->value;

	/* check expire */
	node = node->next;
	if (node) {
		/* expiration period is set */
		if (str2int(&node->value, &expire) < 0) {
			LM_ERR("invalid expire value %.*s", node->value.len, node->value.s);
			goto bad_param;
		}
	} else
		expire = DEFAULT_EXPIRE;

	ret = evi_event_subscribe(event_name, transport_sock, expire, 1);
	if (ret < 0)
		goto bad_param;
	return ret ? init_mi_tree(200, MI_SSTR(MI_OK)) : 0;

missing_param:
	return init_mi_tree( 400, MI_SSTR(MI_MISSING_PARM));

bad_param:
	return init_mi_tree( 400, MI_SSTR(MI_BAD_PARM));
}



/* used to list all the registered events */
struct mi_root * mi_events_list(struct mi_root *cmd_tree, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *node=NULL, *rpl=NULL;
	unsigned i;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==0)
		return 0;
	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;

	for (i = 0; i < events_no; i++) {
		node = add_mi_node_child(rpl, 0, "Event", 5,
				events[i].name.s, events[i].name.len);
		if(node == NULL)
			goto error;

		if (!addf_mi_attr(node, 0, "id", 2, "%d", events[i].id))
			goto error;

		if ((i + 1) % 50 == 0) {
			flush_mi_tree(rpl_tree);
		}
	}
	return rpl_tree;
error:
	free_mi_tree(rpl_tree);
	return 0;
}

static int evi_print_subscriber(struct mi_node *rpl, evi_subs_p subs)
{
	evi_reply_sock *sock;
	struct mi_node *node;
	str socket;

	if (!subs || !subs->trans_mod || !subs->trans_mod->print) {
		LM_ERR("subscriber does not have a print method exported\n");
		return -1;
	}

	node = add_mi_node_child(rpl, 0, "Subscriber", 10, 0, 0);
	if(node == NULL)
		return -1;

	sock = subs->reply_sock;
	if (!sock) {
		LM_DBG("no socket specified\n");
		if (!add_mi_attr(node, 0, "protocol", 8,
				subs->trans_mod->proto.s, subs->trans_mod->proto.len))
			return -1;
		return 0;
	}

	socket = subs->trans_mod->print(sock);
	LM_DBG("print subscriber socket <%.*s> %d\n",
			socket.len, socket.s, socket.len);
	if (!addf_mi_attr(node, MI_DUP_VALUE, "socket", 6, "%.*s:%.*s",
			subs->trans_mod->proto.len, subs->trans_mod->proto.s,
			socket.len, socket.s))
		return -1;

	if (sock->flags & EVI_EXPIRE) {
		if (!addf_mi_attr(node, 0, "expire", 6, "%d", sock->expire))
			return -1;
	} else {
		if (!add_mi_attr(node, 0, "expire", 6, "never", 5))
			return -1;
	}
	/* XXX - does subscription time make sense? */

	return 0;
}

struct evi_mi_param {
	struct mi_node * node;
	struct mi_root * root;
	int nr;
};


static int evi_print_event(struct evi_mi_param *param,
								evi_event_t *ev, evi_subs_p subs)
{
	struct mi_node *node=NULL;
	struct mi_node *rpl = param->node;

	/* add event only if there are subscribers */
	if (!subs && !ev->subscribers)
		return 0;

	node = add_mi_node_child(rpl, MI_IS_ARRAY, "Event", 5,
		ev->name.s, ev->name.len);
	if(node == NULL)
		goto error;

	if (!addf_mi_attr(node, 0, "id", 2, "%d", ev->id))
		goto error;

	if (subs) {
		if (evi_print_subscriber(node, subs) < 0) {
			LM_ERR("cannot print subscriber info\n");
			goto error;
		}
	} else {
		for (subs = ev->subscribers; subs; subs = subs->next) {
			if (evi_print_subscriber(node, subs) < 0) {
				LM_ERR("cannot print subscriber info\n");
				goto error;
			}
			if (++param->nr % 50 == 0)
				flush_mi_tree(param->root);
		}
	}
	return 0;

error:
	return -1;
}

static evi_subs_p evi_get_subscriber(evi_event_p event, str sock_str)
{
	evi_export_t * trans_mod;
	evi_subs_p subscriber = NULL;
	evi_reply_sock * sock;

	/* transport module name */
	trans_mod = get_trans_mod(&sock_str);
	if (!trans_mod) {
		LM_DBG("couldn't find a protocol to support %.*s\n",
				sock_str.len, sock_str.s);
		return NULL;
	}
	sock_str.s += trans_mod->proto.len + 1;
	sock_str.len -= (trans_mod->proto.len + 1);

	/* parse reply socket */
	sock = trans_mod->parse(sock_str);
	if (!sock)
		return NULL;

	/* tries to match other socket */
	if (trans_mod->match) {
		lock_get(event->lock);
		for (subscriber = event->subscribers; subscriber;
				subscriber = subscriber->next) {
			if (subscriber->trans_mod != trans_mod)
				continue;
			if (trans_mod->match(sock, subscriber->reply_sock)) {
				if (trans_mod->free)
					trans_mod->free(sock);
				else
					shm_free(sock);
				break;
			}
		}
		lock_release(event->lock);
	}
	return subscriber;
}


/* used to list all subscribers */
struct mi_root * mi_subscribers_list(struct mi_root *cmd_tree, void *param)
{
	struct mi_root *rpl_tree, *err=NULL;
	struct mi_node *node=NULL, *rpl=NULL;
	struct evi_mi_param prm;
	evi_subs_p subs = NULL;
	evi_event_p event;
	unsigned i;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==0)
		return 0;

	memset(&prm, 0, sizeof(struct evi_mi_param));

	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;
	node = cmd_tree->node.kids;
	prm.node = rpl;
	prm.root = rpl_tree;
	/* dump all info */
	if (!node) {
		for (i = 0; i < events_no; i++) {
			if (evi_print_event(&prm, &events[i], NULL) < 0) {
				LM_ERR("cannot print event %.*s info\n",
						events[i].name.len, events[i].name.s);
				goto error;
			}
		}
		return rpl_tree;
	}
	/* get the event name */
	event = evi_get_event(&node->value);
	if (!event) {
		err = init_mi_tree(404, MI_SSTR("Event not published"));
		goto error;
	}
	node = node->next;
	/* if a subscriber was specified */
	if (node) {
		if (node->next) {
			err = init_mi_tree(400, MI_SSTR(MI_MISSING_PARM));
			goto error;
		}
		/* search for subscriber */
		subs = evi_get_subscriber(event, node->value);
		if (!subs) {
			err = init_mi_tree(404, MI_SSTR("Subscriber does not exist"));
			goto error;
		}
	}

	if (evi_print_event(&prm, event, subs) < 0) {
		LM_ERR("cannot print event %.*s info\n", event->name.len, event->name.s);
		goto error;
	}

	return rpl_tree;

error:
	free_mi_tree(rpl_tree);
	return err;
}
