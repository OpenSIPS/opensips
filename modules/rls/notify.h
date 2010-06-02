/*
 * $Id$
 *
 * rls module - resource list server
 *
 * Copyright (C) 2007 Voice Sistem S.R.L.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2007-09-11  initial version (Anca Vamanu)
 *
 */

#ifndef _RLS_NOTIFY_H
#define _RLS_NOTIFY_H

#include <libxml/parser.h>
#include "../../str.h"
#include "../presence/subscribe.h"

#define BOUNDARY_STRING_LEN    24
#define BUF_REALLOC_SIZE       2048
#define MAX_FORWARD 70

#define REALLOC_BUF\
		do{ \
		size+= BUF_REALLOC_SIZE;\
		buf= (char*)pkg_realloc(buf, size);\
		if(buf== NULL) \
		{	ERR_MEM("constr_multipart_body");} \
		}while(0)

#define APPEND_MULTIPART_BODY() do {\
		add_len = bstr.len+cid.len+ctype.len+body.len +79;\
		if(buf_len+ add_len > size)\
			REALLOC_BUF;\
		buf_len+= sprintf(buf+ buf_len, "--%.*s\r\n", bstr.len, bstr.s);\
		buf_len+= sprintf(buf+ buf_len, "Content-Transfer-Encoding: binary\r\n");\
		buf_len+= sprintf(buf+ buf_len, "Content-ID: <%.*s>\r\n",cid.len, cid.s);\
		buf_len+= sprintf(buf+ buf_len, "Content-Type: %s\r\n\r\n",ctype.s);\
		LM_DBG("last char is %d\n", body.s[body.len-1]);\
		if(body.s[body.len -1] == '\n')\
			body.len--;\
		if(body.s[body.len -1] == '\r')\
			body.len--;\
		buf_len+= sprintf(buf+ buf_len,"%.*s\r\n\r\n", body.len, body.s);\
}while(0)

int send_full_notify(subs_t* subs, xmlNodePtr rl_node, 
		int version, str* rl_uri, unsigned int hash_code);

typedef int (*list_func_t)(char* uri, void* param); 

int process_list_and_exec(xmlNodePtr list, list_func_t f, void* p, int* c);
char* generate_string(int seed, int length);
char* generate_cid(char* uri, int uri_len);
char* get_auth_string(int flag);
int agg_body_sendn_update(str* rl_uri, str boundary_string, str* rlmi_body,
		str* multipart_body, subs_t* subs, unsigned int hash_code);
int rls_send_notify(subs_t* subs,str* body, str* start_cid, str* boundary_string);

#endif
