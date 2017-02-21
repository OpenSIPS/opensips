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

typedef struct mi_json_html_page_data_ {
  str page;
  str buffer;
}mi_json_page_data_t;

typedef struct mi_json_async_resp_data_ {
  gen_lock_t* lock;
}mi_json_async_resp_data_t;


int mi_json_init_async_lock(void);
void mi_json_destroy_async_lock(void);

struct mi_root* mi_json_run_mi_cmd(struct mi_cmd *f, const str* command,
      const str* params, str *page, str *buffer, struct mi_handler **async_hdl,
	  union sockaddr_union* cl_socket);
int mi_json_build_page(str* page, int max_page_len,
        struct mi_root* tree);
void trace_json_request( struct mi_cmd* f, union sockaddr_union* cl_socket, char* url,
		struct mi_root* mi_req );

#endif
