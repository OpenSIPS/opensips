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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

/* holds all exported events */
evi_event_t *events = NULL;

event_id_t evi_publish_event(str event_name)
{
	int idx;

	if (event_name.len > MAX_EVENT_NAME) {
		LM_ERR("event name too long [%d>%d]\n", event_name.len, MAX_EVENT_NAME);
		return EVI_ERROR;
	}

	for (idx = 0; idx < events_no; idx++) {
		if (events[idx].name.len == event_name.len &&
				!memcmp(events[idx].name.s, event_name.s, event_name.len)) {
			LM_WARN("Event \"%.*s\" was previously published\n",
					event_name.len, event_name.s);
			return idx;
		}
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
		events = shm_realloc(events, max_alloc_events);
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
	LM_DBG("Registered event <%.*s(%d)>\n", event_name.len, event_name.s, events_no);

	return events_no++;
}

int evi_raise_event(event_id_t id, evi_params_t* params)
{
	evi_subs_p subs, prev;
	long now;
	int ret = 0;

	if (id < 0 || id >= events_no) {
		LM_ERR("invalid event %d\n", id);
		return -1;
	}

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
		if (subs->reply_sock->flags & EVI_EXPIRE &&
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

		ret += (subs->trans_mod->raise)(&events[id].name,
					subs->reply_sock, params);
next:
		prev = subs;
		subs = subs->next;
	}
	lock_release(events[id].lock);

	/* done sending events - free parameters */
	if (params)
		evi_free_params(params);
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

int evi_raise_script_event(event_id_t id, void * _a, void * _v)
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
	err = evi_raise_event(id, params);
	return err ? err : 1;
error:
	evi_free_params(params);
	return -1;
}
