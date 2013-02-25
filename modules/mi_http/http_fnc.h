/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * History:
 * ---------
 *  2011-09-20  first version (osas)
 */


#ifndef _MI_HTTP_HTTP_FNC_H
#define _MI_HTTP_HTTP_FNC_H

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
			str *page, str *buffer, struct mi_handler **async_hdl);
int mi_http_build_page(str* page, int max_page_len,
				int mod, int cmd, struct mi_root* tree);

#endif

