/*
 * Copyright (C) 2010 VoIP Embedded Inc. <http://www.voipembedded.com/>
 *
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 * 2010-11-09 Initial revision (Ovidiu Sas)
 */

#include "parse_from.h"
#include "parse_to.h"
#include "parse_call_info.h"
#include <stdlib.h>
#include <string.h>
#include "../dprint.h"
#include "msg_parser.h"
#include "../ut.h"
#include "../errinfo.h"
#include "../mem/mem.h"


/*
 * This method is used to parse Call-Info header.
 *
 * params: msg : sip msg
 * returns 0 on success,
 *        -1 on failure.
 */
int parse_call_info_header( struct sip_msg *msg )
{
    struct call_info_body *callinfo_b, *old_callinfo_b=NULL;
    struct to_body *call_info_b;
    struct hdr_field *call_info;
    void **parsed;
    char *tmp, *end, *start;
    unsigned int len;

    if ( !msg->call_info &&
	 (parse_headers(msg, HDR_CALL_INFO_F,0)==-1 || !msg->call_info)) {
	return -1;
    }

    call_info=msg->call_info;

    /* maybe the header is already parsed! */
    if (call_info->parsed)
	return 0;

    parsed = &(call_info->parsed);

    while(*parsed == NULL)
{

    len = call_info->body.len+1;
    start = call_info->body.s;
    end = start + len;
    LM_DBG("parsing the whole body [%.*s]\n", len, call_info->body.s);

    for( tmp=call_info->body.s; tmp<=end; tmp++) {
        if (*tmp == ',' || tmp==end) {
	    LM_DBG("[%.*s]\n",(int)(tmp-start),start);

	    callinfo_b = pkg_malloc(sizeof(struct call_info_body));
	    if (callinfo_b == NULL) {
		LM_ERR("out of pkg_memory\n");
		goto error;
	    }
	    memset(callinfo_b, 0, sizeof(struct call_info_body));

	    /* now parse it!! */
	    call_info_b = &(callinfo_b->call_info_body);
	    parse_to(start, tmp, call_info_b);
	    if (call_info_b->error == PARSE_ERROR) {
		LM_ERR("bad Call-Info header\n");
		pkg_free(call_info_b);
		set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
		    "error parsing Call-Info header");
		set_err_reply(400, "bad header");
		goto error;
	    }

	    /* Save the first parsed body */
	    if (*parsed == NULL)
	    	*parsed = callinfo_b;
	    else
		old_callinfo_b->next = callinfo_b;

	    old_callinfo_b = callinfo_b;

	    start = tmp + 1;
	}
    }
    call_info = call_info->sibling;
    LM_DBG("done ... next call_info [%p]\n", call_info);
    if (call_info == NULL) {
	break;
    }
    parsed = &(call_info->parsed);
}

    return 0;

error:
    return -1;
}

inline static void free_call_info_param_list(struct to_param *param_lst)
{
    struct to_param *foo;
    while(param_lst){
	foo=param_lst->next;
	//LM_DBG(".. free [%p]->[%.*s]\n", param_lst, param_lst->name.len, param_lst->name.s);
	pkg_free(param_lst);
	param_lst=foo;
    }
    return;
}

void free_call_info(struct call_info_body *callinfo_b)
{
    struct call_info_body *foo;
    while(callinfo_b){
	//LM_DBG("freeing callinfo\n");
	foo=callinfo_b;
	callinfo_b=callinfo_b->next;
	if (foo->call_info_body.param_lst)
	    free_call_info_param_list(foo->call_info_body.param_lst);
	//LM_DBG(". free [%p]->[%.*s]\n", foo, foo->call_info_body.body.len, foo->call_info_body.body.s);
	pkg_free(foo);
	//LM_DBG("done freeing callinfo\n");
    }
    return;
}
