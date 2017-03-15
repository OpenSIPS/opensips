/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * History:
 * ---------
 *  2013-03-04  first version (osas)
 */

#ifndef _MI_XMLRPC_HTTP_HTTP_FNC_H
#define _MI_XMLRPC_HTTP_HTTP_FNC_H

 #define MI_XMLRPC_XML_START            "<?xml version=\"1.0\" "        \
       "encoding=\"UTF-8\"?>\r\n<methodResponse>\r\n<params>"  \
       "\r\n<param><value><string>"
#define MI_XMLRPC_XML_STOP             "</string></value></param>"     \
       "\r\n</params>\r\n</methodResponse>\r\n"


#define MI_XMLRPC_XML_START_VER2		"<?xml version=\"1.0\" "	\
	"encoding=\"UTF-8\"?>\r\n<methodResponse>\r\n<params><param>"	\
	"\r\n"
#define MI_XMLRPC_XML_STOP_VER2	"</param></params>\r\n</methodResponse>\r\n"


#define MI_XMLRPC_XML_FAULT_START        "<?xml version=\"1.0\" "        \
       "encoding=\"UTF-8\"?>\r\n<methodResponse>\r\n<fault>"  \
       "<value>\r\n<struct>\r\n"

#define MI_XMLRPC_XML_FAULT_END "</struct>\r\n</value>\r\n</fault>\r\n" \
       "</methodResponse>\r\n"

#define MI_XMLRPC_XML_FAULT_MESSAGE_START "<member>\r\n<name>faultString</name>\r\n" \
       "<value><string>"
#define MI_XMLRPC_XML_FAULT_MESSAGE_END "</string></value>\r\n</member>\r\n"

#define MI_XMLRPC_XML_FAULT_CODE_START "<member>\r\n<name>faultCode</name>\r\n" \
       "<value><int>"
#define MI_XMLRPC_XML_FAULT_CODE_END "</int></value>\r\n</member>\r\n"

#define INIT_XMLRPC_FAULT(code, message) MI_XMLRPC_XML_FAULT_START  \
	MI_XMLRPC_XML_FAULT_CODE_START \
	code \
	MI_XMLRPC_XML_FAULT_CODE_END \
	MI_XMLRPC_XML_FAULT_MESSAGE_START \
	message \
	MI_XMLRPC_XML_FAULT_MESSAGE_END \
	MI_XMLRPC_XML_FAULT_END

#define XMLRPC_FAULT_FORMAT MI_XMLRPC_XML_FAULT_START  \
	MI_XMLRPC_XML_FAULT_CODE_START \
	"%u" \
	MI_XMLRPC_XML_FAULT_CODE_END \
	MI_XMLRPC_XML_FAULT_MESSAGE_START \
	"%.*s" \
	MI_XMLRPC_XML_FAULT_MESSAGE_END \
	MI_XMLRPC_XML_FAULT_END




#define MI_XMLRPC_START_OBJECT   		(1<<0)
#define MI_XMLRPC_END_OBJECT  		(1<<1)
#define MI_XMLRPC_FULL_OBJECT        3

#define MI_XMLRPC_FORMATED_OUTPUT 2
#define MI_XMLRPC_UNFORMATED_OUTPUT 1

#define MI_XMLRPC_ASYNC_FAILED   ((void*)-2)
#define MI_XMLRPC_ASYNC_EXPIRED  ((void*)-3)

typedef struct mi_xmlrpc_http_html_page_data_ {
	str page;
	str buffer;
}mi_xmlrpc_http_page_data_t;

typedef struct mi_xmlrpc_http_async_resp_data_ {
	gen_lock_t* lock;
}mi_xmlrpc_http_async_resp_data_t;


int mi_xmlrpc_http_init_async_lock(void);
void mi_xmlrpc_http_destroy_async_lock(void);

struct mi_root* mi_xmlrpc_http_run_mi_cmd(const str* arg,
			str *page, str *buffer, struct mi_handler **async_hdl,
			union sockaddr_union* cl_socket, int* is_cmd_traced);
int mi_xmlrpc_http_build_page(str* page, int max_page_len,
				struct mi_root* tree);

enum xml_err_enum { ERR_EMPTY=0, ERR_BAD_REQ=1, ERR_NOT_AVAIL=2, ERR_UNEXPECTED,
	ERR_MISS_METCALL, ERR_MISS_METNAME, ERR_MISS_VALUE, ERR_MISS_STRING,
	ERR_EMPTY_STRING, ERR_INTERNAL, ERR_CMD_FAILED, ERR_MAX };

static int xml_errcode;

void trace_xml_request( union sockaddr_union* cl_socket, char* url,
		struct mi_root* mi_req );
#endif

