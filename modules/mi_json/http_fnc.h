/*
 * This file is part of Open SIP Server (opensips).
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
 * ---------
 *  2013-03-04  first version (osas)
 */


#ifndef _MI_JSON_HTTP_FNC_H
#define _MI_JSON_HTTP_FNC_H

#define MI_JSON_ASYNC_FAILED   ((void*)-2)
#define MI_JSON_ASYNC_EXPIRED  ((void*)-3)

typedef struct mi_json_async_resp_data_ {
  gen_lock_t* lock;
}mi_json_async_resp_data_t;


int mi_json_init_async_lock(void);
void mi_json_destroy_async_lock(void);

mi_response_t *mi_http_run_mi_cmd(struct mi_cmd *cmd, char *req_method,
                mi_request_t *request, union sockaddr_union *cl_socket,
                struct mi_handler **async_hdl);

void trace_json_request(struct mi_cmd* f, char *req_method,
					union sockaddr_union* cl_socket, mi_item_t *params);

#endif
