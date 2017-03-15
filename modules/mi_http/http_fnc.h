/*
 * Copyright (C) 2011 VoIP Embedded Inc.
 *
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
 *  2011-09-20  first version (osas)
 */


#ifndef _MI_HTTP_HTTP_FNC_H
#define _MI_HTTP_HTTP_FNC_H

#define MI_HTTP_ASYNC_FAILED   ((void*)-2)
#define MI_HTTP_ASYNC_EXPIRED  ((void*)-3)

typedef struct http_mi_cmd_ {
	struct mi_cmd* cmds;
	int size;
}http_mi_cmd_t;

typedef struct mi_http_html_page_data_ {
	str page;
	str buffer;
	int mod;
	int cmd;
}mi_http_html_page_data_t;

typedef struct mi_http_async_resp_data_ {
	int mod;
	int cmd;
	gen_lock_t* lock;
	struct mi_root* tree;
}mi_http_async_resp_data_t;


int mi_http_init_async_lock(void);
void mi_http_destroy_async_lock(void);

int mi_http_init_cmds(void);
int mi_http_parse_url(const char* url, int* mod, int* cmd);
struct mi_root* mi_http_run_mi_cmd(int mod, int cmd, const str* arg,
			str *page, str *buffer, struct mi_handler **async_hdl,
			union sockaddr_union* cl_socket, int* is_cmd_traced);
int mi_http_build_page(str* page, int max_page_len,
				int mod, int cmd, struct mi_root* tree);

static str backend = str_init("http");
static union sockaddr_union* sv_socket = NULL;

#endif

