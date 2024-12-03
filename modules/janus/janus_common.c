/*
 * Janus Module
 *
 * Copyright (C) 2024 OpenSIPS Project
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
 * History:
 * --------
 * 2024-12-03 initial release (vlad)
 */



#include <ctype.h>

#include "../../dprint.h"
#include "../../ut.h"
#include "../../net/trans_trace.h"
#include "../../net/tcp_common.h"

#include "../../timer.h"
#include "../../ipc.h"

#include "janus_common.h"
#include "janus_ws.h"
#include "janus_proc.h"
#include "ws_common_defs.h"

#include "../../lib/cJSON.h"

/* SHM pointer */
unsigned int *janus_mgr_process_no;

struct list_head *janus_sockets;
struct list_head *fs_sockets;
rw_lock_t *sockets_lock;

struct list_head *janus_sockets_down;
rw_lock_t *sockets_down_lock;

int janus_cmd_timeout = 5000;       /* ms */
int janus_cmd_polling_itv = 1000;   /* us */

static str janus_notify_event_name = str_init("E_JANUS_EVENT");
static event_id_t janus_notify_event = EVI_ERROR;

void janus_brief_parse_msg(struct janus_req *r)
{
	cJSON *obj=NULL;
	char *parse_end;

	obj = cJSON_ParseWithOpts(r->buf,(const char **)&parse_end,0);
	if (obj == NULL) {
		LM_ERR("NO parse :( \n");
	} else {
		r->complete=1;
		r->body = obj;
	}
}

int janus_register_event(void) 
{
	janus_notify_event = evi_publish_event(janus_notify_event_name);
	if (janus_notify_event == EVI_ERROR) {
		LM_ERR("cannot register JANUS event \n");
		return -1;
	}

	return 1;
}

int janus_raise_event(janus_connection *conn, cJSON *request)
{
	evi_params_p eparams = NULL;
	str janus_id_param = str_init("janus_id");
	str janus_url_param = str_init("janus_url");
	str janus_body_param = str_init("janus_body");
	char *full_json;
	str full_json_s;

	if (!evi_probe_event(janus_notify_event)) {
		LM_DBG("nothing to do - nobody is listening!\n");
		return 1;
	}

	if (!(eparams = evi_get_params())) {
		LM_ERR("cannot create parameters list\n");
		return -1;
	}

	if (evi_param_add_str(eparams,&janus_id_param,&conn->janus_id) < 0) {
		LM_ERR("cannot add janus_id param\n");
		goto err_free_params;
	}

	if (evi_param_add_str(eparams,&janus_url_param,&conn->full_url) < 0) {
		LM_ERR("cannot add janus_id param\n");
		goto err_free_params;
	}

	full_json = cJSON_Print(request);
	cJSON_Minify(full_json);
	full_json_s.s = full_json;
	full_json_s.len = strlen(full_json);

	if (evi_param_add_str(eparams,&janus_body_param,&full_json_s) < 0) {
		LM_ERR("cannot add janus_body param\n");
		goto err_free;
	}

	if (evi_raise_event(janus_notify_event, eparams) < 0) {
		LM_ERR("Failed to raise janus event \n");
		goto err_free;
	}

	pkg_free(full_json);
	return 1;

err_free:
	pkg_free(full_json);
err_free_params:
	evi_free_params(eparams);
	return -1;
}

int handle_janus_json_request(janus_connection *conn, cJSON *request)
{
	cJSON *aux;
	str reply_status,s_transaction_id;
	uint64_t transaction_id;
	janus_ipc_reply *reply;
	char *full_json;

	aux = cJSON_GetObjectItem(request, "janus");
	if (aux == NULL || aux->type != cJSON_String ||
	(reply_status.s = aux->valuestring) == NULL) {
		LM_ERR("Unexpected JANUS reply received \n");
		return -1;
	}

	if (memcmp(reply_status.s,"ack",3) == 0) {
		LM_DBG("Janus sent us an ack - wait some more, don't do anything \n");
		return 1;
	}

	if (memcmp(reply_status.s,"success",7) != 0 && memcmp(reply_status.s,"event",5) != 0) {
		LM_ERR("non-succesful JANUS reply received \n");
		if (janus_raise_event(conn,request) < 0) {
			LM_ERR("Failed to raise janus event \n");
		}
		/* we don't disconnect, just unexpected janus reply */
		return 1;
	}

	aux = cJSON_GetObjectItem(request, "transaction");
	if (aux == NULL || aux->type != cJSON_String ||
	(reply_status.s = aux->valuestring) == NULL) {
		if (janus_raise_event(conn,request) < 0) {
			LM_ERR("Failed to raise janus event \n");
		}
		return 1;
	}

	s_transaction_id.s = aux->valuestring;
	s_transaction_id.len = strlen(s_transaction_id.s);

	if (str2int64(&s_transaction_id,&transaction_id) != 0) {
		LM_ERR("Unexpected JANUS transaction type \n");
		return -1;
	}


	reply = shm_malloc(sizeof *reply);
	if (reply == NULL) {
		LM_ERR("oom\n");
		/* we're out of mem, let the requestor timeout, don't disconnect janus */
		return 1;
	}

	full_json = cJSON_Print(request);
	cJSON_Minify(full_json);

	reply->text.s = shm_strdup(full_json);
	if (reply->text.s == NULL) {
		/* we're out of mem, let the requestor timeout, don't disconnect janus */
		return 1;
	}

	reply->text.len = strlen(reply->text.s);
	reply->janus_transaction_id = transaction_id;

	pkg_free(full_json);

	lock_start_write(conn->lists_lk);
	list_add_tail(&reply->list, &conn->janus_replies);
	lock_stop_write(conn->lists_lk);

	return 0;
}

int populate_janus_handler_id(janus_connection *conn, cJSON *request) 
{
	cJSON *aux,*aux2;
	str reply_status;

	/* struct janus_msg alloc & etc */
	aux = cJSON_GetObjectItem(request, "janus");
	if (aux == NULL || aux->type != cJSON_String ||
	(reply_status.s = aux->valuestring) == NULL) {
		LM_ERR("Unexpected JANUS reply received - %s\n",cJSON_Print(request));
		return -1;
	}

	if (memcmp(reply_status.s,"success",7) != 0) {
		LM_ERR("non-succesful JANUS reply received - %s\n",cJSON_Print(request));
		return -1;
	}

	aux = cJSON_GetObjectItem(request, "data");
	if (aux == NULL || aux->type != cJSON_Object) {
		LM_ERR("Unexpected JANUS reply received, no data in %s\n",cJSON_Print(request));
		return -1;
	}

	aux2 = cJSON_GetObjectItem(aux, "id");
	if (aux2 == NULL || aux2->type != cJSON_Number) {
		LM_ERR("Unexpected JANUS reply received, id is not number %s\n",cJSON_Print(request));
		return -1;
	}

	conn->janus_handler_id = aux2->valuedouble;
	LM_DBG("init handler id %f on %.*s \n",conn->janus_handler_id,
			conn->full_url.len,conn->full_url.s);


	return 1;
}

void janus_free_connection(janus_connection *sock)
{
	struct list_head *_, *__;
	janus_ipc_reply *reply = NULL;

	list_for_each_safe(_, __, &sock->janus_replies) {
		reply = list_entry(_, janus_ipc_reply, list);
		shm_free(reply->text.s);
		shm_free(reply);
	}

	shm_free(sock->janus_id.s);
	shm_free(sock->full_url.s);

	lock_destroy_rw(sock->lists_lk);
	shm_free(sock);
}

janus_connection* janus_add_connection(const str* janus_id, const str* url)
{
	janus_connection* conn;

	if (!janus_id || !janus_id->s || !janus_id->len) {
		LM_ERR("Janus ID cannot be NULL/Empty\n");
		return NULL;
	}

	if (!url || !url->s || !url->len) {
		LM_ERR("Janus URL cannot be NULL/Empty\n");
		return NULL;
	}

	conn = shm_malloc(sizeof *conn);
	if (!conn) {
		LM_ERR("No more shared mem \n");
		return NULL;
	}

	memset(conn, 0, sizeof *conn);

	INIT_LIST_HEAD(&conn->janus_replies);
	INIT_LIST_HEAD(&conn->reconnect_list);

	if (shm_nt_str_dup(&conn->full_url,url) != 0) {
		LM_ERR("No more shared mem\n");
		goto err_free;
	}

	if (parse_janus_url(conn->full_url.s,
	conn->full_url.s+conn->full_url.len,
	&conn->parsed_url) == NULL) {
		LM_ERR("Invalid Janus URL\n");
		goto err_free;
	}

	if (shm_nt_str_dup(&conn->janus_id,janus_id) != 0) {
		LM_ERR("No more shared mem\n");
		goto err_free;
	}

	conn->lists_lk = lock_init_rw();
	if (!conn->lists_lk) {
		LM_ERR("No more shared mem\n");
		goto err_free;
	}


	conn->fd = -1;
	conn->janus_transaction_id = 1;

	LM_DBG("new JANUS sock [%.*s]: [%.*s]\n",
	       conn->janus_id.len,conn->janus_id.s,
	       conn->full_url.len,conn->full_url.s);

	/* we just add it here, if we ever want to make the connection list dynamic, we need locking here */
	list_add(&conn->list, janus_sockets);
	list_add(&conn->reconnect_list, janus_sockets_down);

	return conn;

err_free:
	janus_free_connection(conn);
	return NULL;
}


janus_connection* get_janus_connection_by_id(const str* janus_id) 
{
	struct list_head *_;
	janus_connection *sock = NULL;

	list_for_each(_, janus_sockets) {
		sock = list_entry(_, janus_connection, list);
		if (str_strcmp(janus_id, &sock->janus_id) == 0)
			break;

		sock = NULL;
	}

	return sock;
}
