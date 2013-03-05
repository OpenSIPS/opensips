/*
 * $Id$
 *
 * Copyright (C) 2013 VoIP Embedded Inc.
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
 *  2013-03-04  first version (osas)
 */


#ifndef _MI_XMLRPC_HTTP_HTTP_FNC_H
#define _MI_XMLRPC_HTTP_HTTP_FNC_H


typedef struct mi_xmlrpc_http_html_page_data_ {
	str page;
	str buffer;
}mi_xmlrpc_http_page_data_t;

typedef struct mi_xmlrpc_http_async_resp_data_ {
	gen_lock_t* lock;
	struct mi_root* tree;
}mi_xmlrpc_http_async_resp_data_t;


int mi_xmlrpc_http_init_async_lock(void);
void mi_xmlrpc_http_destroy_async_lock(void);

struct mi_root* mi_xmlrpc_http_run_mi_cmd(const str* arg,
			str *page, str *buffer, struct mi_handler **async_hdl);
int mi_xmlrpc_http_build_page(str* page, int max_page_len,
				struct mi_root* tree);

#endif

