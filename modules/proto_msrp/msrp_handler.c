/*
 * Copyright (C) 2022 - OpenSIPS Solutions
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
 *
 */

#include <fnmatch.h>
#include "../../mem/mem.h"
#include "msrp_parser.h"
#include "msrp_signaling.h"
#include "msrp_handler.h"

struct msrp_handler {
	/* 0 - MSRP ; 1 - MSRPS */
	unsigned short secured_filter;
	/* NULL - everything matches; a fmt may be here too */
	str host_filter;
	/* 0 - wild card; or a port value */
	unsigned short port_filter;
	msrp_req_handler_f req_f;
	msrp_rpl_handler_f rpl_f;
	void *param;
	struct msrp_handler *next;
};


static struct msrp_handler *msrp_handlers = NULL;

#define MSRP_DEBUG


void* register_msrp_handler( str *host_filter, int port_filter,
		int secured_filter, msrp_req_handler_f req_f,
		msrp_rpl_handler_f rpl_f, void *param)
{
	struct msrp_handler *hdl, *hdl_it;

	if (req_f==NULL || rpl_f==NULL)
		return NULL;

	hdl = pkg_malloc( sizeof(struct msrp_handler) +
		((host_filter && host_filter->len)?host_filter->len+1:0) );
	if (hdl==NULL) {
		LM_ERR("pkg malloc failed for new req handler filter\n");
		return NULL;
	}

	hdl->secured_filter = (secured_filter==0) ? 0 : 1 ;
	hdl->port_filter = (port_filter<=0) ? 0 : port_filter;
	hdl->req_f = req_f;
	hdl->rpl_f = rpl_f;
	hdl->param = param;
	if (host_filter && host_filter->len) {
		hdl->host_filter.s = (char*)(hdl+1);
		hdl->host_filter.len = host_filter->len;
		memcpy(hdl->host_filter.s, host_filter->s, host_filter->len);
		hdl->host_filter.s[ hdl->host_filter.len ] = 0;
	} else {
		hdl->host_filter.s = NULL;
		hdl->host_filter.len = 0;
	}

	/* link it at the end */
	if (msrp_handlers==NULL) {
		msrp_handlers = hdl;
	} else {
		for( hdl_it=msrp_handlers ; hdl_it->next ; hdl_it=hdl_it->next);
		hdl_it->next = hdl;
	}
	hdl->next = NULL;

	return (void*)hdl;
}


static int _dispatch_req_to_handler( struct msrp_msg *req)
{
	struct msrp_url *url;
	struct msrp_handler *hdl = msrp_handlers;
	char bk;

	/* the To-Path must be already parsed and we need the top URL */
	url = (struct msrp_url*)(req->to_path->parsed);

	/* make HOST part null terminated - we do the usual hack (forcing
	 * a 0 at the end, and restoring it afterwards); this is safe
	 * to do as (1) it is in pkg (so no sharing) and (2) the len+1 is still
	 * in the msg buffer (this is an URL inside the msrp msg */
	bk = url->host.s[url->host.len];
	url->host.s[url->host.len] = 0;
#ifdef MSRP_DEBUG
	LM_DBG("msg is [%d/%s/%d]\n",
			url->secured,  url->host.s, url->port_no);
#endif

	/* now, do the matching */
	for( ; hdl ; hdl=hdl->next) {
#ifdef MSRP_DEBUG
		LM_DBG("checking on filter [%d/%s/%d]\n",
			hdl->secured_filter, hdl->host_filter.s, hdl->port_filter);
#endif
		if ( !(hdl->secured_filter ^ url->secured) &&
		(hdl->port_filter==0 || hdl->port_filter == url->port_no) &&
		fnmatch( hdl->host_filter.s, url->host.s, FNM_CASEFOLD) == 0 ) {
			url->host.s[url->host.len] = bk;
			LM_DBG("matched on filter [%d/%s/%d]\n",
				hdl->secured_filter, hdl->host_filter.s, hdl->port_filter);
			/* run the handler */
			hdl->req_f( req, hdl->param);
			return 0;
		}
	}

	url->host.s[url->host.len] = bk; /* recover the null-termination */

	return -1;
}



int handle_msrp_msg(char* buf, int len, struct msrp_firstline *fl, str *body,
		struct receive_info *rcv_info)
{
	struct msrp_msg* msg;
#ifdef MSRP_DEBUG
	struct hdr_field *hf;
#endif

	msg = pkg_malloc(sizeof(struct msrp_msg));
	if (msg==0) {
		LM_ERR("no pkg mem left for msrp_msg\n");
		goto error;
	}

	memset( msg, 0, sizeof(struct msrp_msg));
	/* fill in msg */
	msg->buf=buf;
	msg->len=len;
	msg->rcv=*rcv_info;
	msg->fl = *fl;
	msg->body = *body;

	if (parse_msrp_msg( buf, len, msg)!=0) {
		LM_ERR("Unable to parse MSRP msg received from [%s:%d]\n",
			ip_addr2a(&(rcv_info->src_ip)), rcv_info->src_port);
		goto parse_error;
	}
	LM_DBG("After parse_msg...\n");

#ifdef MSRP_DEBUG
	LM_DBG("MSRP %s received, Tident [%.*s]\n",
		msg->fl.type==MSRP_REQUEST?"request":"reply",
		msg->fl.ident.len, msg->fl.ident.s);
	if (msg->fl.type==MSRP_REQUEST) {
		LM_DBG("\tMethod [%.*s]\n",
			msg->fl.u.request.method.len,msg->fl.u.request.method.s);
	} else {
		LM_DBG("\tstatus [%.*s], reason [%.*s]\n",
			msg->fl.u.reply.status.len, msg->fl.u.reply.status.s,
			msg->fl.u.reply.reason.len, msg->fl.u.reply.reason.s);
	}
	for( hf=msg->headers; hf ; hf=hf->next )
		LM_DBG("\tHeader [%.*s], body [%.*s]\n",
			hf->name.len, hf->name.s, hf->body.len, hf->body.s) ;
	if (msg->body.s)
		LM_DBG("\tHas body len %d, first 10 are [%.*s]\n", msg->body.len, 10,
			msg->body.s) ;
	else
		LM_DBG("\tHas no body\n");
#endif

	/* MSRP msgs are dispatched to the proper handler 
	 * based on the top To-Path URL */
	msg->to_path->parsed = parse_msrp_path( &msg->to_path->body);
	if (msg->to_path->parsed ==NULL) {
		LM_ERR("Invalid To-Path payload :(\n");
		goto parse_error;  // FIXME a 400 reply ??
	}

	if (msg->fl.type==MSRP_REQUEST) {

		if (_dispatch_req_to_handler( msg )<0) {
			LM_ERR("Message not handled by any handler :(\n");
			goto parse_error;  // FIXME a 4xx reply ??
		}

	} else {

		/* TODO FIXME handle replies here */

	}

	LM_DBG("cleaning up\n");
	free_msrp_msg(msg);
	pkg_free(msg);
	return 0;

parse_error:
	free_msrp_msg(msg);
	pkg_free(msg);
error:
	return -1;
}

