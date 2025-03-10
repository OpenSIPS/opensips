/**
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef DIAMETER_API_H
#define DIAMETER_API_H

/*
 * XXX: most of the functions overlap, so we are currently trying to keep them
 * all together
 */
#include "../../aaa/aaa.h"
#include "../../lib/cJSON.h"

/* structures */
#define diameter_conn aaa_conn

typedef struct {
	cJSON *json;
	int is_error;
	int rc;
} diameter_reply;

/*
	Initialize Diameter protocol implementation

	This function initializes the protocol and returns a pointer to the
	connection variable that represents it.
	The return value is a pointer to a connection variable.
 */
typedef diameter_conn* (diameter_init_f)(str *);

/*
	Search a command in the dictionary

	This function searches a command's code in the dictionary.
	It returns true if found, false otherwise.
 */
typedef int (diameter_find_cmd_f)(diameter_conn*, int code);

/*
	Sends a diameter request and returns a reply handle
 */
typedef int (diameter_send_req_f)(diameter_conn*, int app_id, int code,
		cJSON *req, diameter_reply *reply);

/*
	Callback run for an asynchornous command reply
 */
typedef int (diameter_reply_cb)(diameter_conn *conn, diameter_reply *reply, void *param);

/*
	Sends an asynchornous diameter request and calls the callback in the reply
 */
typedef int (diameter_send_req_async_f)(diameter_conn*, int app_id, int code,
		cJSON *req, diameter_reply_cb *reply_cb, void *reply_param);

/*
	Retrieves a JSON from a reply handle
 */
typedef cJSON *(diameter_get_reply_f)(diameter_reply *rpl);

/*
	Retrieves the status from a reply handle
 */
typedef int (diameter_get_reply_status_f)(diameter_reply *rpl);

/*
	Frees a reply handle
 */
typedef void (diameter_free_reply_f)(diameter_reply *rpl);

typedef struct diameter_api {
	diameter_init_f             *init;
	diameter_find_cmd_f         *find_cmd;
	diameter_send_req_f         *send_request;
	diameter_send_req_async_f   *send_request_async;
	diameter_get_reply_f        *get_reply;
	diameter_get_reply_status_f *get_reply_status;
	diameter_free_reply_f       *free_reply;
} diameter_api;

typedef int (*diameter_bind_f)(diameter_api *api);

static inline int diameter_bind_api(diameter_api *api)
{
	diameter_bind_f bind_f = (diameter_bind_f)find_export("diameter_bind_api", 0);
	if (!bind_f) {
		LM_INFO("could not bind Diameter API\n");
		return -1;
	}
	return bind_f(api);
}

#endif /* DIAMETER_API_H */
