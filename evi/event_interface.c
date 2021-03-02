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
#include "../ipc.h"


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
	req = get_dummy_sip_msg();
	if(req == NULL)
	{
		LM_ERR("No more memory\n");
		return -1;
	}

	bak_avps = set_avp_list(&event_avps);

	status = evi_raise_event_msg(req, id, params);

	/* clean whatever extra structures were added by script functions */
	release_dummy_sip_msg(req);

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


static mi_response_t *mi_event_subscribe(const mi_params_t *params, unsigned int expire)
{
	int ret;
	str event_name, transport_sock;

	if (get_mi_string_param(params, "event", &event_name.s,
		&event_name.len) < 0 || !event_name.s || !event_name.len)
		return init_mi_param_error();

	if (get_mi_string_param(params, "socket", &transport_sock.s,
		&transport_sock.len) < 0 || !transport_sock.s || !transport_sock.len)
		return init_mi_param_error();

	ret = evi_event_subscribe(event_name, transport_sock, expire, 1);
	if (ret < 0)
		return init_mi_error(400, MI_SSTR("Bad parameter value"));

	return ret ? init_mi_result_ok() : 0;
}

mi_response_t *w_mi_event_subscribe(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	return mi_event_subscribe(params, DEFAULT_EXPIRE);
}

mi_response_t *w_mi_event_subscribe_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int expire;

	if (get_mi_int_param(params, "expire", &expire) < 0)
		return init_mi_param_error();

	if (expire < 0)
		return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
			MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
			MI_SSTR("Negative expire value"));

	return mi_event_subscribe(params, expire);
}


/* used to list all the registered events */
mi_response_t *mi_events_list(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *events_arr, *event_item;
	unsigned i;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	events_arr = add_mi_array(resp_obj, MI_SSTR("Events"));
	if (!events_arr) {
		free_mi_response(resp);
		return 0;
	}

	for (i = 0; i < events_no; i++) {
		event_item = add_mi_object(events_arr, NULL, 0);
		if (!event_item)
			goto error;

		if (add_mi_string(event_item, MI_SSTR("name"),
			events[i].name.s, events[i].name.len) < 0)
			goto error;

		if (add_mi_number(event_item, MI_SSTR("id"), events[i].id) < 0)
			goto error;
	}

	return resp;

error:
	free_mi_response(resp);
	return 0;
}

static int evi_print_subscriber(mi_item_t *subs_obj, evi_subs_p subs)
{
	evi_reply_sock *sock;
	str socket;

	if (!subs || !subs->trans_mod || !subs->trans_mod->print) {
		LM_ERR("subscriber does not have a print method exported\n");
		return -1;
	}

	sock = subs->reply_sock;
	if (!sock) {
		LM_DBG("no socket specified\n");
		if (add_mi_string(subs_obj, MI_SSTR("protocol"),
			subs->trans_mod->proto.s, subs->trans_mod->proto.len) < 0)
			return -1;
		return 0;
	}

	socket = subs->trans_mod->print(sock);
	LM_DBG("print subscriber socket <%.*s> %d\n",
			socket.len, socket.s, socket.len);
	if (add_mi_string_fmt(subs_obj, MI_SSTR("socket"), "%.*s:%.*s",
			subs->trans_mod->proto.len, subs->trans_mod->proto.s,
			socket.len, socket.s) < 0)
		return -1;

	if (sock->flags & EVI_EXPIRE) {
		if (add_mi_number(subs_obj, MI_SSTR("expire"), sock->expire) < 0)
			return -1;
	} else {
		if (add_mi_string(subs_obj, MI_SSTR("expire"), MI_SSTR("never")) < 0)
			return -1;
	}
	/* XXX - does subscription time make sense? */

	return 0;
}

static int evi_print_event(mi_item_t *ev_obj, evi_event_t *ev, evi_subs_p subs)
{
	mi_item_t *subs_arr, *subs_item;

	/* add event only if there are subscribers */
	if (!subs && !ev->subscribers)
		return 0;

	if (add_mi_string(ev_obj, MI_SSTR("name"), ev->name.s, ev->name.len) < 0)
		goto error;

	if (add_mi_number(ev_obj, MI_SSTR("id"), ev->id) < 0)
		goto error;

	if (subs) {
		subs_item = add_mi_object(ev_obj, MI_SSTR("Subscriber"));
		if (!subs_item)
			goto error;

		if (evi_print_subscriber(subs_item, subs) < 0) {
			LM_ERR("cannot print subscriber info\n");
			goto error;
		}
	} else {
		subs_arr = add_mi_array(ev_obj, MI_SSTR("Subscribers"));
		if (!subs_arr)
			goto error;

		for (subs = ev->subscribers; subs; subs = subs->next) {
			subs_item = add_mi_object(subs_arr, NULL, 0);
			if (!subs_item)
				goto error;

			if (evi_print_subscriber(subs_item, subs) < 0) {
				LM_ERR("cannot print subscriber info\n");
				goto error;
			}
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

static mi_response_t *mi_subscribers_list(evi_event_p event, evi_subs_p subs)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *event_obj;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	event_obj = add_mi_object(resp_obj, MI_SSTR("Event"));
	if (!event_obj)
		goto error;

	if (evi_print_event(event_obj, event, subs) < 0) {
		LM_ERR("cannot print event %.*s info\n",
			event->name.len, event->name.s);
		goto error;
	}

	return resp;

error:
	free_mi_response(resp);
	return NULL;
}

/* used to list all subscribers */
mi_response_t *w_mi_subscribers_list(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *events_arr, *event_item;
	int i;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	events_arr = add_mi_array(resp_obj, MI_SSTR("Events"));
	if (!events_arr)
		goto error;

	for (i = 0; i < events_no; i++) {
		if (!events[i].subscribers)
			continue;

		event_item = add_mi_object(events_arr, NULL, 0);
		if (!event_item)
			goto error;

		if (evi_print_event(event_item, &events[i], NULL) < 0) {
			LM_ERR("cannot print event %.*s info\n",
				events[i].name.len, events[i].name.s);
			goto error;
		}
	}

	return resp;

error:
	free_mi_response(resp);
	return 0;
}

mi_response_t *w_mi_subscribers_list_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str event_s;
	evi_event_p event;

	if (get_mi_string_param(params, "event", &event_s.s, &event_s.len) < 0)
		return init_mi_param_error();

	event = evi_get_event(&event_s);
	if (!event)
		return init_mi_error(404, MI_SSTR("Event not published"));

	return mi_subscribers_list(event, NULL);
}

mi_response_t *w_mi_subscribers_list_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str event_s;
	str subs_s;
	evi_event_p event;
	evi_subs_p subs;

	if (get_mi_string_param(params, "event", &event_s.s, &event_s.len) < 0)
		return init_mi_param_error();

	event = evi_get_event(&event_s);
	if (!event)
		return init_mi_error(404, MI_SSTR("Event not published"));

	if (get_mi_string_param(params, "socket", &subs_s.s, &subs_s.len) < 0)
		return init_mi_param_error();

	subs = evi_get_subscriber(event, subs_s);
	if (!subs)
		return init_mi_error(404, MI_SSTR("Subscriber does not exist"));

	return mi_subscribers_list(event, subs);
}

evi_params_p mi_raise_event_json_params(str *params)
{
	int err;
	cJSON *param;
	cJSON *jparams;
	str name, jstring;
	evi_params_p eparams = NULL;
	char *tmp = pkg_malloc(params->len + 1);
	if (!tmp) {
		LM_ERR("could not create temporary buffer!\n");
		return NULL;
	}
	memcpy(tmp, params->s, params->len);
	tmp[params->len] = 0;
	jparams = cJSON_Parse(tmp);
	pkg_free(tmp);
	if (!jparams) {
		LM_DBG("could not parse json '%.*s'\n", params->len, params->s);
		return NULL;
	} else
		LM_DBG("treating params as json '%.*s'\n", params->len, params->s);

	if (!(jparams->type &cJSON_Object)) {
		LM_ERR("params json is not an object\n");
		return NULL;
	}
	/* parse params as json */
	if (!(eparams = evi_get_params())) {
		LM_ERR("cannot create parameters list\n");
		goto error;
	}
	for (param = jparams->child; param; param = param->next) {
		name.s = param->string;
		name.len = strlen(name.s);
		switch (param->type) {
			case cJSON_Number:
				err = evi_param_add_int(eparams, &name, &param->valueint);
				break;
			case cJSON_String:
				jstring.s = param->valuestring;
				jstring.len = strlen(jstring.s);
				err = evi_param_add_str(eparams, &name, &jstring);
				break;
			default:
				jstring.s = cJSON_PrintUnformatted(param);
				jstring.len = strlen(jstring.s);
				err = evi_param_add_str(eparams, &name, &jstring);
				cJSON_PurgeString(jstring.s);
				break;
		}
		if (err) {
			LM_ERR("could not add parameter %s\n", name.s);
			goto error_free;
		}
	}
	cJSON_Delete(jparams);
	return eparams;
error_free:
	evi_free_params(eparams);
error:
	cJSON_Delete(jparams);
	return NULL;
}

evi_params_p mi_raise_event_array_params(mi_item_t *array, int no)
{
	int i;
	str param;
	evi_params_p eparams = NULL;

	LM_DBG("treating params as array\n");

	/* parse params as json */
	if (!(eparams = evi_get_params())) {
		LM_ERR("cannot create parameters list\n");
		return NULL;
	}

	for (i = 0; i < no; i++) {
		if (get_mi_arr_param_string(array, i, &param.s, &param.len) < 0) {
			LM_ERR("cannot fetch array element %d\n", i);
			goto error;
		}
		if (evi_param_add_str(eparams, NULL, &param)) {
			LM_ERR("cannot add new params %d\n", i);
			goto error;
		}
	}

	return eparams;
error:
	evi_free_params(eparams);
	return NULL;
}

struct mi_raise_event_dispatch {
	event_id_t id;
	evi_params_p params;
};

void mi_raise_event_rpc(int sender, void *param)
{
	struct mi_raise_event_dispatch *p = (struct mi_raise_event_dispatch *)param;
	if (evi_raise_event(p->id, p->params))
		LM_ERR("cannot raise event RPC\n");
	evi_free_shm_params(p->params);
	shm_free(p);
}

mi_response_t *w_mi_raise_event(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int no;
	str event_s;
	str tparams;
	event_id_t id;
	mi_item_t *values;
	evi_params_p eparams = NULL, sparams;
	struct mi_raise_event_dispatch *djob;

	if (get_mi_string_param(params, "event", &event_s.s, &event_s.len) < 0)
		return init_mi_param_error();

	id = evi_get_id(&event_s);
	if (id == EVI_ERROR)
		return init_mi_error(404, MI_SSTR("Event not registered"));

	/* check if there are any subscribers */
	if (!evi_probe_event(id))
		return init_mi_error(480, MI_SSTR("Temporarily Unavailable"));

	/* check to see if we have an array params, or key-value one */
	switch (try_get_mi_array_param(params, "params", &values, &no)) {
		case -1:
		case -3:
			/* no params used */
			break;
		case -2:
			/* not an array - most likely it's a string */
			if (get_mi_string_param(params, "params", &tparams.s, &tparams.len) < 0)
				return init_mi_error(400, MI_SSTR("No Params"));
			eparams = mi_raise_event_json_params(&tparams);
			if (!eparams)
				return init_mi_error(400, MI_SSTR("Bad Params"));
			break;
		case 0:
			/* this is an array - push it like this */
			eparams = mi_raise_event_array_params(values, no);
			if (!eparams)
				return init_mi_error(400, MI_SSTR("Bad Params"));
			break;
	}

	if (eparams) {
		sparams = evi_dup_shm_params(eparams);
		evi_free_params(eparams);
		eparams = NULL;
		if (!sparams) {
			LM_ERR("could not duplicate evi params!\n");
			goto error;
		}
		eparams = sparams;
	}

	djob = shm_malloc(sizeof (*djob));
	if (!djob) {
		LM_ERR("could not allocate new job!\n");
		goto error;
	}
	djob->id = id;
	djob->params = eparams;

	if (ipc_dispatch_rpc(mi_raise_event_rpc, djob) < 0) {
		LM_ERR("could not dispatch raise event job!\n");
		goto error;
	}

	return init_mi_result_ok();
error:
	if (eparams)
		evi_free_shm_params(eparams);
	return init_mi_error(500, MI_SSTR("Cannot Raise Event"));
}
