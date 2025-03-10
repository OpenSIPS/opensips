/*
 * Copyright (C) 2024 OpenSIPS Solutions
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

#include "server.h"
#include "h2_evi.h"

#include "../../dprint.h"
#include "../../ut.h"

static event_id_t h2ev_req_id = EVI_ERROR; /* E_HTTP2_REQUEST */
static evi_params_p h2ev_req_params;

static evi_param_p h2ev_req_param_method;
static evi_param_p h2ev_req_param_path;
static evi_param_p h2ev_req_param_headers;
static evi_param_p h2ev_req_param_data;


int h2_init_evi(void)
{
	/* First publish the events */
	h2ev_req_id = evi_publish_event(str_init(H2EV_REQ_NAME));
	if (h2ev_req_id == EVI_ERROR) {
		LM_ERR("cannot register 'request' event\n");
		return -1;
	}

	h2ev_req_params = pkg_malloc(sizeof *h2ev_req_params);
	if (!h2ev_req_params) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(h2ev_req_params, 0, sizeof *h2ev_req_params);

	h2_response = shm_malloc(sizeof *h2_response);
	if (!h2_response) {
		LM_ERR("oom SHM\n");
		return -1;
	}
	*h2_response = NULL;

	h2ev_req_param_method = evi_param_create(h2ev_req_params, &str_init("method"));
	h2ev_req_param_path = evi_param_create(h2ev_req_params, &str_init("path"));
	h2ev_req_param_headers = evi_param_create(h2ev_req_params, &str_init("headers"));
	h2ev_req_param_data = evi_param_create(h2ev_req_params, &str_init("data"));
	if (!h2ev_req_param_method || !h2ev_req_param_path
	        || !h2ev_req_param_headers || !h2ev_req_param_data) {
		LM_ERR("failed to create EVI params\n");
		return -1;
	}

	return 0;
}


/**
 * The purpose of this dispatched job is for the logic to be ran by a
 * process other than the Diameter peer, since PROC_MODULE workers have NULL
 * @sroutes, causing a crash when attempting to raise a script event
 */
void h2_raise_event_request(const char *method, const char *path,
		const char *headers_json, const str *body)
{
	str st;

	init_str(&st, method);
	if (evi_param_set_str(h2ev_req_param_method, &st) < 0) {
		LM_ERR("failed to set 'method'\n");
		return;
	}

	init_str(&st, path);
	if (evi_param_set_str(h2ev_req_param_path, &st) < 0) {
		LM_ERR("failed to set 'path'\n");
		return;
	}

	init_str(&st, headers_json);
	if (evi_param_set_str(h2ev_req_param_headers, &st) < 0) {
		LM_ERR("failed to set 'headers_json'\n");
		return;
	}

	if (evi_param_set_str(h2ev_req_param_data, body) < 0) {
		LM_ERR("failed to set 'body'\n");
		return;
	}

	if (evi_raise_event(h2ev_req_id, h2ev_req_params) < 0)
		LM_ERR("failed to raise '"H2EV_REQ_NAME"' event\n");
}
