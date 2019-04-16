/*
 * Copyright (C) 2019 OpenSIPS Project
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
 */

#include "../../dprint.h"
#include "../../evi/evi_modules.h"
#include "../../ipc.h"

#include "rmq_event.h"

static str evi_body_param_name = str_init("body");

int rmq_evi_init(struct rmq_connection *conn)
{
	conn->evi_id = evi_publish_event(conn->event_name);
	if (conn->evi_id == EVI_ERROR) {
		LM_ERR("failed to register RabbitMQ event\n");
		return -1;
	}

	conn->evi_params = shm_malloc(sizeof *conn->evi_params);
	if (!conn->evi_params) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(conn->evi_params, 0, sizeof *conn->evi_params);

	conn->evi_body_param = evi_param_create(conn->evi_params,
		&evi_body_param_name);
	if (!conn->evi_body_param) {
		LM_ERR("cannot create event's 'body' parameter\n");
		return -1;
	}

	return 0;
}

void rmq_raise_event(int sender, void *_rmq_event)
{
	struct rmq_ipc_event *rmq_event = (struct rmq_ipc_event *)_rmq_event;

	if (evi_param_set_str(rmq_event->conn->evi_body_param,
		&rmq_event->msg_body) < 0) {
		LM_ERR("failed to set event 'body'\n");
		return;
	}

	if (evi_raise_event(rmq_event->conn->evi_id, rmq_event->conn->evi_params) < 0)
		LM_ERR("failed to raise RabbitMQ event\n");

	shm_free(rmq_event->msg_body.s);
	shm_free(rmq_event);
}

int rmq_ipc_dispatch_event(struct rmq_connection *conn, str *msg_body)
{
	struct rmq_ipc_event *rmq_event;

	rmq_event = shm_malloc(sizeof *rmq_event);
	if (!rmq_event) {
		LM_ERR("oom!\n");
		return -1;
	}

	rmq_event->conn = conn;

	if (shm_str_dup(&rmq_event->msg_body, msg_body)) {
		LM_ERR("oom!\n");
		shm_free(rmq_event);
		return -1;
	}

	return ipc_dispatch_rpc(rmq_raise_event, rmq_event);
}
