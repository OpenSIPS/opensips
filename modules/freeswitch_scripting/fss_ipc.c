/*
 * Inter-process communication primitives
 *
 * Copyright (C) 2017 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include "../../dprint.h"
#include "../../evi/evi_modules.h"
#include "../freeswitch/fs_ipc.h"

#include "fss_ipc.h"

ipc_handler_type ipc_hdl_rcv_event;

static event_id_t evi_fs_event_id = EVI_ERROR;
static str evi_fs_event_name = str_init("E_FREESWITCH");

static evi_params_p fs_event_params;

static evi_param_p fs_event_name_param;
static str         fs_event_name = str_init("name");
static evi_param_p fs_event_sender_param;
static str         fs_event_sender = str_init("sender");
static evi_param_p fs_event_body_param;
static str         fs_event_body = str_init("body");

int fss_ipc_init(void)
{
	ipc_hdl_rcv_event = ipc_register_handler(fss_raise_freeswitch_event,
	                                         "Receive FS event");
	if (ipc_bad_handler_type(ipc_hdl_rcv_event)) {
		LM_ERR("failed to register 'Receive FS event' IPC handler\n");
		return -1;
	}

	return 0;
}

int fss_evi_init(void)
{
	evi_fs_event_id = evi_publish_event(evi_fs_event_name);
	if (evi_fs_event_id == EVI_ERROR) {
		LM_ERR("failed to register FS event\n");
		return -1;
	}

	fs_event_params = pkg_malloc(sizeof *fs_event_params);
	if (!fs_event_params) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(fs_event_params, 0, sizeof *fs_event_params);

	fs_event_name_param = evi_param_create(fs_event_params, &fs_event_name);
	if (!fs_event_name_param) {
		LM_ERR("cannot create event name\n");
		return -1;
	}

	fs_event_sender_param = evi_param_create(fs_event_params,&fs_event_sender);
	if (!fs_event_sender_param) {
		LM_ERR("cannot create event sender\n");
		return -1;
	}

	fs_event_body_param = evi_param_create(fs_event_params, &fs_event_body);
	if (!fs_event_body_param) {
		LM_ERR("cannot create event body\n");
		return -1;
	}

	return 0;
}

void fss_raise_freeswitch_event(int sender, void *_esl_event)
{
	fs_ipc_esl_event *esl_event = (fs_ipc_esl_event *)_esl_event;
	str body = {esl_event->body, strlen(esl_event->body)};

	if (evi_param_set_str(fs_event_name_param, &esl_event->name) < 0) {
		LM_ERR("failed to set event name\n");
		return;
	}

	if (evi_param_set_str(fs_event_sender_param, &esl_event->sock->host) < 0) {
		LM_ERR("failed to set event sender\n");
		return;
	}

	if (evi_param_set_str(fs_event_body_param, &body) < 0) {
		LM_ERR("failed to set event body\n");
		return;
	}

	if (evi_raise_event(evi_fs_event_id, fs_event_params) < 0)
		LM_ERR("failed to raise FS event\n");

	shm_free(esl_event->body);
	shm_free(esl_event->name.s);
	shm_free(esl_event);
}
