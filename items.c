/**
 * $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2005 Voice Sistem SRL
 * 
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
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
 * 2004-10-20 - added header name specifier (ramona)
 * 2005-06-14 - added avp name specifier (ramona)
 * 2005-06-18 - added color printing support via escape sequesnces
 *              contributed by Ingo Flaschberger (daniel)
 * 2005-06-22 - created this file from modules/xlog/xl_lib.c (daniel)
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#include "dprint.h"
#include "mem/mem.h"
#include "ut.h" 
#include "trim.h" 
#include "dset.h"
#include "usr_avp.h"

#include "parser/parse_from.h"
#include "parser/parse_uri.h"
#include "parser/parse_hname2.h"
#include "parser/parse_content.h"
#include "parser/parse_refer_to.h"
#include "parser/digest/digest.h"

#include "items.h"

static str str_null   = { "<null>", 6 };
static str str_empty  = { "", 0 };
static str str_marker = { ITEM_MARKER_STR, 1 };
static str str_udp    = { "UDP", 3 };
static str str_5060   = { "5060", 4 };

int _it_msg_id = 0;
time_t msg_tm = 0;
int cld_pid = 0;

#define ITEM_FIELD_DELIM ", "
#define ITEM_FIELD_DELIM_LEN (sizeof(ITEM_FIELD_DELIM) - 1)

#define LOCAL_BUF_SIZE	511
static char local_buf[LOCAL_BUF_SIZE+1];

static int xl_get_null(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	res->rs.s = str_null.s;
	res->rs.len = str_null.len;
	res->ri = 0;
	res->flags = XL_VAL_NULL;
	return 0;
}

static int xl_get_empty(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	res->rs.s = str_empty.s;
	res->rs.len = str_empty.len;
	res->ri = 0;
	res->flags = XL_VAL_STR|XL_VAL_INT|XL_VAL_EMPTY;
	return 0;
}

static int xl_get_marker(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	res->rs.s = str_marker.s;
	res->rs.len = str_marker.len;
	res->ri = (int)str_marker.s[0];
	res->flags = XL_VAL_STR|XL_VAL_INT;
	return 0;
}

static int xl_get_udp(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	res->rs.s = str_udp.s;
	res->rs.len = str_udp.len;
	res->ri = PROTO_UDP;
	res->flags = XL_VAL_STR|XL_VAL_INT;
	return 0;
}

static int xl_get_5060(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	res->rs.s = str_5060.s;
	res->rs.len = str_5060.len;
	res->ri = 5060;
	res->flags = XL_VAL_STR|XL_VAL_INT;
	return 0;
}

static int xl_get_pid(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	int l = 0;
	char *ch = NULL;

	if(msg==NULL || res==NULL)
		return -1;

	if(cld_pid == 0)
		cld_pid = (int)getpid();
	ch = int2str(cld_pid, &l);

	res->rs.s = ch;
	res->rs.len = l;

	res->ri = cld_pid;
	res->flags = XL_VAL_STR|XL_VAL_INT|XL_TYPE_INT;
	return 0;
}

extern int return_code;
static int xl_get_return_code(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	int l = 0;
	char *s = NULL;

	if(msg==NULL || res==NULL)
		return -1;

	s = sint2str(return_code, &l);

	res->rs.s = s;
	res->rs.len = l;

	res->ri = return_code;
	res->flags = XL_VAL_STR|XL_VAL_INT|XL_TYPE_INT;
	return 0;
}

static int xl_get_times(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	int l = 0;
	char *ch = NULL;
		
	if(msg==NULL || res==NULL)
		return -1;

	if(_it_msg_id != msg->id || msg_tm==0)
	{
		msg_tm = time(NULL);
		_it_msg_id = msg->id;
	}
	ch = int2str(msg_tm, &l);
	
	res->rs.s = ch;
	res->rs.len = l;

	res->ri = (int)msg_tm;
	res->flags = XL_VAL_STR|XL_VAL_INT|XL_TYPE_INT;
	return 0;
}

static int xl_get_timef(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	char *ch = NULL;
	
	if(msg==NULL || res==NULL)
		return -1;
	if(_it_msg_id != msg->id || msg_tm==0)
	{
		msg_tm = time(NULL);
		_it_msg_id = msg->id;
	}
	
	ch = ctime(&msg_tm);
	
	res->rs.s = ch;
	res->rs.len = strlen(ch)-1;

	res->ri = (int)msg_tm;
	res->flags = XL_VAL_STR|XL_VAL_INT;
	return 0;
}

static int xl_get_msgid(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	int l = 0;
	char *ch = NULL;

	if(msg==NULL || res==NULL)
		return -1;

	ch = int2str(msg->id, &l);
	res->rs.s = ch;
	res->rs.len = l;

	res->ri = (int)msg->id;
	res->flags = XL_VAL_STR|XL_VAL_INT|XL_TYPE_INT;
	return 0;
}

static int xl_get_method(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REQUEST)
	{
		res->rs.s = msg->first_line.u.request.method.s;
		res->rs.len = msg->first_line.u.request.method.len;
		res->ri = (int)msg->first_line.u.request.method_value;
	} else {
		if(msg->cseq==NULL && ((parse_headers(msg, HDR_CSEQ_F, 0)==-1) || 
				(msg->cseq==NULL)))
		{
			LOG(L_ERR, "xl_get_method: ERROR cannot parse CSEQ header\n");
			return xl_get_null(msg, res, param, flags);
		}
		res->rs.s = get_cseq(msg)->method.s;
		res->rs.len = get_cseq(msg)->method.len;
		res->ri = get_cseq(msg)->method_id;
	}
	
	res->flags = XL_VAL_STR|XL_VAL_INT;
	return 0;
}

static int xl_get_status(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)
	{
		res->rs.s = msg->first_line.u.reply.status.s;
		res->rs.len = msg->first_line.u.reply.status.len;		
	}
	else
		return xl_get_null(msg, res, param, flags);
	
	res->ri = (int)msg->first_line.u.reply.statuscode;
	res->flags = XL_VAL_STR|XL_VAL_INT|XL_TYPE_INT;
	return 0;
}

static int xl_get_reason(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)
	{
		res->rs.s = msg->first_line.u.reply.reason.s;
		res->rs.len = msg->first_line.u.reply.reason.len;		
	}
	else
		return xl_get_null(msg, res, param, flags);
	
	res->flags = XL_VAL_STR;
	return 0;
}

static int xl_get_ruri(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)	/* REPLY doesnt have a ruri */
		return xl_get_null(msg, res, param, flags);

	if(msg->parsed_uri_ok==0 /* R-URI not parsed*/ && parse_sip_msg_uri(msg)<0)
	{
		LOG(L_ERR, "xl_get_ruri: ERROR while parsing the R-URI\n");
		return xl_get_null(msg, res, param, flags);
	}
	
	if (msg->new_uri.s!=NULL)
	{
		res->rs.s   = msg->new_uri.s;
		res->rs.len = msg->new_uri.len;
	} else {
		res->rs.s   = msg->first_line.u.request.uri.s;
		res->rs.len = msg->first_line.u.request.uri.len;
	}
	
	res->flags = XL_VAL_STR;
	return 0;
}

static int xl_get_ouri(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)	/* REPLY doesnt have a ruri */
		return xl_get_null(msg, res, param, flags);

	if(msg->parsed_orig_ruri_ok==0
			/* orig R-URI not parsed*/ && parse_orig_ruri(msg)<0)
	{
		LOG(L_ERR, "xl_get_ouri: ERROR while parsing the R-URI\n");
		return xl_get_null(msg, res, param, flags);
	}
	
	res->rs.s   = msg->first_line.u.request.uri.s;
	res->rs.len = msg->first_line.u.request.uri.len;
	
	res->flags = XL_VAL_STR;
	return 0;
}

static int xl_get_xuri_attr(struct sip_msg *msg, xl_value_t *res,
		xl_param_t *param, struct sip_uri *parsed_uri,
		int flags)
{
	if(param->val.len==1) /* username */
	{
		res->rs.s   = parsed_uri->user.s;
		res->rs.len = parsed_uri->user.len;
		res->flags = XL_VAL_STR;
	} else if(param->val.len==2) /* domain */ {
		res->rs.s   = parsed_uri->host.s;
		res->rs.len = parsed_uri->host.len;
		res->flags  = XL_VAL_STR;
	} else if(param->val.len==3) /* port */ {
		if(parsed_uri->port.s==NULL)
			return xl_get_5060(msg, res, param, flags);
		res->rs.s   = parsed_uri->port.s;
		res->rs.len = parsed_uri->port.len;
		res->ri     = (int)parsed_uri->port_no;
		res->flags  = XL_VAL_STR|XL_VAL_INT;
	} else if(param->val.len==4) /* protocol */ {
		if(parsed_uri->transport_val.s==NULL)
			return xl_get_udp(msg, res, param, flags);
		res->rs.s   = parsed_uri->transport_val.s;
		res->rs.len = parsed_uri->transport_val.len;
		res->ri     = (int)parsed_uri->proto;
		res->flags  = XL_VAL_STR|XL_VAL_INT;
	} else {
		LOG(L_ERR, "xl_get_xuri_attr: unknown specifier\n");
		return xl_get_null(msg, res, param, flags);
	}
	
	return 0;
}

static int xl_get_ruri_attr(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)	/* REPLY doesnt have a ruri */
		return xl_get_null(msg, res, param, flags);

	if(msg->parsed_uri_ok==0 /* R-URI not parsed*/ && parse_sip_msg_uri(msg)<0)
	{
		LOG(L_ERR,
			"xl_get_ruri_attr: ERROR while parsing the R-URI\n");
		return xl_get_null(msg, res, param, flags);
	}
	return xl_get_xuri_attr(msg, res, param, &(msg->parsed_uri), flags);
}	

static int xl_get_ouri_attr(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)	/* REPLY doesnt have a ruri */
		return xl_get_null(msg, res, param, flags);

	if(msg->parsed_orig_ruri_ok==0
			/* orig R-URI not parsed*/ && parse_orig_ruri(msg)<0)
	{
		LOG(L_ERR, "xl_get_ouri: ERROR while parsing the R-URI\n");
		return xl_get_null(msg, res, param, flags);
	}
	return xl_get_xuri_attr(msg, res, param, &(msg->parsed_orig_ruri), flags);
}	

	
static int xl_get_contact(struct sip_msg* msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->contact==NULL && parse_headers(msg, HDR_CONTACT_F, 0)==-1) 
	{
		DBG("xl_get_contact: no contact header\n");
		return xl_get_null(msg, res, param, flags);
	}
	
	if(!msg->contact || !msg->contact->body.s || msg->contact->body.len<=0)
    {
		DBG("xl_get_contact: no contact header!\n");
		return xl_get_null(msg, res, param, flags);
	}
	
	res->rs.s = msg->contact->body.s;
	res->rs.len = msg->contact->body.len;

//	res->s = ((struct to_body*)msg->contact->parsed)->uri.s;
//	res->len = ((struct to_body*)msg->contact->parsed)->uri.len;

	res->flags = XL_VAL_STR;
	return 0;
}


static int xl_get_from_attr(struct sip_msg *msg, xl_value_t *res,
		xl_param_t *param,
		int flags)
{
	struct sip_uri uri;
	if(msg==NULL || res==NULL)
		return -1;

	if(parse_from_header(msg)==-1)
	{
		LOG(L_ERR, "xl_get_from_attr: ERROR cannot parse FROM header\n");
		return xl_get_null(msg, res, param, flags);
	}
	
	if(msg->from==NULL || get_from(msg)==NULL)
		return xl_get_null(msg, res, param, flags);

	if(param->val.len==1) /* uri */
	{
		res->rs.s = get_from(msg)->uri.s;
		res->rs.len = get_from(msg)->uri.len; 
		res->flags = XL_VAL_STR;
		return 0;
	}
	
	if(param->val.len==4) /* tag */
	{
		if(get_from(msg)->tag_value.s==NULL||get_from(msg)->tag_value.len<=0)
			return xl_get_null(msg, res, param, flags);
		res->rs.s = get_from(msg)->tag_value.s;
		res->rs.len = get_from(msg)->tag_value.len; 
		res->flags = XL_VAL_STR;
		return 0;
	}

	if(param->val.len==5) /* display name */
	{
		if(get_from(msg)->display.s==NULL||get_from(msg)->display.len<=0)
			return xl_get_empty(msg, res, param, flags);
		res->rs.s = get_from(msg)->display.s;
		res->rs.len = get_from(msg)->display.len; 
		res->flags = XL_VAL_STR;
		return 0;
	}

	memset(&uri, 0, sizeof(struct sip_uri));
	if (parse_uri(get_from(msg)->uri.s, get_from(msg)->uri.len , &uri)<0)
	{
		LOG(L_ERR,"xl_get_from_attr: failed to parse From uri\n");
		return xl_get_null(msg, res, param, flags);
	}
	
	if(param->val.len==2) /* username */ {
		if(uri.user.s==NULL)
			return xl_get_empty(msg, res, param, flags);
		res->rs.s   = uri.user.s;
		res->rs.len = uri.user.len; 
		res->flags = XL_VAL_STR;
	} else if(param->val.len==3) /* domain */ {
		res->rs.s   = uri.host.s;
		res->rs.len = uri.host.len; 
		res->flags = XL_VAL_STR;
	} else {
		LOG(L_ERR, "xl_get_from_attr: unknown specifier\n");
		return xl_get_null(msg, res, param, flags);
	}
	return 0;
}


static int xl_get_to_attr(struct sip_msg *msg, xl_value_t *res,
		xl_param_t *param,
		int flags)
{
	struct sip_uri uri;
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->to==NULL && parse_headers(msg, HDR_TO_F, 0)==-1)
	{
		LOG(L_ERR, "xl_get_to_attr: ERROR cannot parse TO header\n");
		return xl_get_null(msg, res, param, flags);
	}
	if(msg->to==NULL || get_to(msg)==NULL)
		return xl_get_null(msg, res, param, flags);

	if(param->val.len==1) /* uri */
	{
		res->rs.s = get_to(msg)->uri.s;
		res->rs.len = get_to(msg)->uri.len; 
		res->flags = XL_VAL_STR;
		return 0;
	}
	
	if(param->val.len==4) /* tag */
	{
		if (get_to(msg)->tag_value.s==NULL||get_to(msg)->tag_value.len<=0) 
			return xl_get_null(msg, res, param, flags);
		res->rs.s = get_to(msg)->tag_value.s;
		res->rs.len = get_to(msg)->tag_value.len;
		res->flags = XL_VAL_STR;
		return 0;
	}

	if(param->val.len==5) /* display name */
	{
		if(get_to(msg)->display.s==NULL||get_to(msg)->display.len<=0)
			return xl_get_empty(msg, res, param, flags);
		res->rs.s = get_to(msg)->display.s;
		res->rs.len = get_to(msg)->display.len; 
		res->flags = XL_VAL_STR;
		return 0;
	}

	memset(&uri, 0, sizeof(struct sip_uri));
	if (parse_uri(get_to(msg)->uri.s, get_to(msg)->uri.len , &uri)<0)
	{
		LOG(L_ERR,"xl_get_to_attr: failed to parse To uri\n");
		return xl_get_null(msg, res, param, flags);
	}
	
	if(param->val.len==2) /* username */ {
		if(uri.user.s==NULL)
			return xl_get_empty(msg, res, param, flags);
		res->rs.s   = uri.user.s;
		res->rs.len = uri.user.len; 
		res->flags = XL_VAL_STR;
	} else if(param->val.len==3) /* domain */ {
		res->rs.s   = uri.host.s;
		res->rs.len = uri.host.len; 
		res->flags = XL_VAL_STR;
	} else {
		LOG(L_ERR, "xl_get_to_attr: unknown specifier\n");
		return xl_get_null(msg, res, param, flags);
	}
	return 0;
}

static int xl_get_cseq(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	if(msg->cseq==NULL && ((parse_headers(msg, HDR_CSEQ_F, 0)==-1) || 
				(msg->cseq==NULL)) )
	{
		LOG(L_ERR, "xl_get_cseq: ERROR cannot parse CSEQ header\n");
		return xl_get_null(msg, res, param, flags);
	}

	res->rs.s = get_cseq(msg)->number.s;
	res->rs.len = get_cseq(msg)->number.len;

	res->flags = XL_VAL_STR;
	return 0;
}

static int xl_get_msg_buf(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	res->rs.s = msg->buf;
	res->rs.len = msg->len;

	res->flags = XL_VAL_STR;
	return 0;
}

static int xl_get_msg_len(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	int l = 0;
	char *ch = NULL;

	if(msg==NULL || res==NULL)
		return -1;

	ch = int2str(msg->len, &l);
	res->rs.s = ch;
	res->rs.len = l;

	res->ri = (int)msg->len;
	res->flags = XL_VAL_STR|XL_VAL_INT;
	return 0;
}

static int xl_get_flags(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	int l = 0;
	char *ch = NULL;

	if(msg==NULL || res==NULL)
		return -1;

	ch = int2str(msg->flags, &l);
	res->rs.s = ch;
	res->rs.len = l;

	res->ri = (int)msg->flags;
	res->flags = XL_VAL_STR|XL_VAL_INT;
	return 0;
}

static inline char* int_to_8hex(int val)
{
	unsigned short digit;
	int i;
	static char outbuf[9];
	
	outbuf[8] = '\0';
	for(i=0; i<8; i++)
	{
		if(val!=0)
		{
			digit =  val & 0xf;
			outbuf[7-i] = digit >= 10 ? digit + 'a' - 10 : digit + '0';
			val >>= 4;
		}
		else
			outbuf[7-i] = '0';
	}
	return outbuf;
}

static int xl_get_hexflags(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;

	res->rs.s = int_to_8hex(msg->flags);
	res->rs.len = 8;

	res->ri = (int)msg->flags;
	res->flags = XL_VAL_STR|XL_VAL_INT;
	return 0;
}

static int xl_get_callid(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	if(msg->callid==NULL && ((parse_headers(msg, HDR_CALLID_F, 0)==-1) ||
				(msg->callid==NULL)) )
	{
		LOG(L_ERR, "xl_get_callid: ERROR cannot parse Call-Id header\n");
		return xl_get_null(msg, res, param, flags);
	}

	res->rs.s = msg->callid->body.s;
	res->rs.len = msg->callid->body.len;
	trim(&res->rs);

	res->flags = XL_VAL_STR;
	return 0;
}

static int xl_get_srcip(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;

	res->rs.s = ip_addr2a(&msg->rcv.src_ip);
	res->rs.len = strlen(res->rs.s);
   
	res->flags = XL_VAL_STR;
	return 0;
}

static int xl_get_srcport(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	int l = 0;
	char *ch = NULL;

	if(msg==NULL || res==NULL)
		return -1;

	ch = int2str(msg->rcv.src_port, &l);
	res->rs.s = ch;
	res->rs.len = l;
   
	res->ri = (int)msg->rcv.src_port;
	res->flags = XL_VAL_STR|XL_VAL_INT;
	return 0;
}

static int xl_get_rcvip(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	if(msg->rcv.bind_address==NULL 
			|| msg->rcv.bind_address->address_str.s==NULL)
		return xl_get_null(msg, res, param, flags);
	
	res->rs.s   = msg->rcv.bind_address->address_str.s;
	res->rs.len = msg->rcv.bind_address->address_str.len;
	
	res->flags = XL_VAL_STR;
	return 0;
}

static int xl_get_rcvport(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	if(msg->rcv.bind_address==NULL 
			|| msg->rcv.bind_address->port_no_str.s==NULL)
		return xl_get_null(msg, res, param, flags);
	
	res->rs.s   = msg->rcv.bind_address->port_no_str.s;
	res->rs.len = msg->rcv.bind_address->port_no_str.len;
	
	res->ri = (int)msg->rcv.bind_address->port_no;
	res->flags = XL_VAL_STR|XL_VAL_INT;
	return 0;
}

static int xl_get_useragent(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL) 
		return -1;
	if(msg->user_agent==NULL && ((parse_headers(msg, HDR_USERAGENT_F, 0)==-1)
			 || (msg->user_agent==NULL)))
	{
		DBG("xl_get_useragent: User-Agent header not found\n");
		return xl_get_null(msg, res, param, flags);
	}
	
	res->rs.s = msg->user_agent->body.s;
	res->rs.len = msg->user_agent->body.len;
	trim(&res->rs);
	
	res->flags = XL_VAL_STR;
	return 0;
}

static int xl_get_refer_to(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(parse_refer_to_header(msg)==-1)
	{
		LOG(L_ERR,
			"xl_get_refer_to: ERROR cannot parse Refer-To header\n");
		return xl_get_null(msg, res, param, flags);
	}
	
	if(msg->refer_to==NULL || get_refer_to(msg)==NULL)
		return xl_get_null(msg, res, param, flags);

	res->rs.s = get_refer_to(msg)->uri.s;
	res->rs.len = get_refer_to(msg)->uri.len; 
	
	res->flags = XL_VAL_STR;
	return 0;
}


static int xl_get_dset(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
    if(msg==NULL || res==NULL)
	return -1;
    
    res->rs.s = print_dset(msg, &res->rs.len);

    if ((res->rs.s) == NULL) return xl_get_null(msg, res, param, flags);
    
    res->rs.len -= CRLF_LEN;

	res->flags = XL_VAL_STR;
    return 0;
}


static int xl_get_dsturi(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
    if(msg==NULL || res==NULL)
		return -1;
    
    if (msg->dst_uri.s == NULL)
		return xl_get_empty(msg, res, param, flags);

	res->rs.s = msg->dst_uri.s;
    res->rs.len = msg->dst_uri.len;

	res->flags = XL_VAL_STR;
    return 0;
}

static int xl_get_dsturi_attr(struct sip_msg *msg, xl_value_t *res,
		xl_param_t *param,
		int flags)
{
	struct sip_uri uri;
    if(msg==NULL || res==NULL)
		return -1;
    
    if (msg->dst_uri.s == NULL)
		return xl_get_empty(msg, res, param, flags);

	if(parse_uri(msg->dst_uri.s, msg->dst_uri.len, &uri)!=0)
	{
		LOG(L_ERR, "xl_get_dsturi_attr: ERROR cannot parse dst uri\n");
		return xl_get_null(msg, res, param, flags);
	}
	
	if(param->val.len==1) /* domain */
	{
		res->rs.s = uri.host.s;
		res->rs.len = uri.host.len;
		res->flags = XL_VAL_STR;
	} else if(param->val.len==2) /* port */ {
		if(uri.port.s==NULL)
			return xl_get_5060(msg, res, param, flags);
		res->rs.s   = uri.port.s;
		res->rs.len = uri.port.len;
		res->ri     = (int)uri.port_no;
		res->flags  = XL_VAL_STR|XL_VAL_INT;
		return 0;
	} else if(param->val.len==3) /* proto */ {
		if(uri.transport_val.s==NULL)
			return xl_get_udp(msg, res, param, flags);
		res->rs.s   = uri.transport_val.s;
		res->rs.len = uri.transport_val.len;
		res->ri     = (int)uri.proto;
		res->flags  = XL_VAL_STR|XL_VAL_INT;
	} else {
		LOG(L_ERR, "xl_get_dsturi_attr: invalid specifier\n");
		return xl_get_null(msg, res, param, flags);
	}

    return 0;
}

static int xl_get_content_type(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL) 
		return -1;
	if(msg->content_type==NULL
			&& ((parse_headers(msg, HDR_CONTENTTYPE_F, 0)==-1)
			 || (msg->content_type==NULL)))
	{
		DBG("xl_get_content_type: Content-Type header not found\n");
		return xl_get_empty(msg, res, param, flags);
	}
	
	res->rs.s = msg->content_type->body.s;
	res->rs.len = msg->content_type->body.len;
	trim(&res->rs);
	
	res->flags = XL_VAL_STR;
	return 0;
}

static int xl_get_content_length(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	if(msg==NULL || res==NULL) 
		return -1;
	if(msg->content_length==NULL
			&& ((parse_headers(msg, HDR_CONTENTLENGTH_F, 0)==-1)
			 || (msg->content_length==NULL)))
	{
		DBG("xl_get_content_length: Content-Length header not found\n");
		return xl_get_empty(msg, res, param, flags);
	}
	
	res->rs.s = msg->content_length->body.s;
	res->rs.len = msg->content_length->body.len;
	trim(&res->rs);

	res->ri = (int)(long)msg->content_length->parsed;
	res->flags = XL_VAL_STR | XL_VAL_INT;

	return 0;
}

static int xl_get_msg_body(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
    if(msg==NULL || res==NULL)
	return -1;
    
    res->rs.s = get_body( msg );

    if ((res->rs.s) == NULL)
		return xl_get_empty(msg, res, param, flags);
    
	if (!msg->content_length) 
	{
		LOG(L_ERR,"xl_get_msg_body: ERROR no Content-Length header found!\n");
		return xl_get_null(msg, res, param, flags);
	}
	res->rs.len = get_content_length(msg);

	res->flags = XL_VAL_STR;
    return 0;
}

static int xl_get_authattr(struct sip_msg *msg, xl_value_t *res,
		xl_param_t *param,
		int flags)
{
	struct hdr_field *hdr;
	
    if(msg==NULL || res==NULL)
		return -1;
    
	if ((msg->REQ_METHOD == METHOD_ACK) || (msg->REQ_METHOD == METHOD_CANCEL))
		return xl_get_empty(msg, res, param, flags);

	if ((parse_headers(msg, HDR_PROXYAUTH_F|HDR_AUTHORIZATION_F, 0)==-1)
			|| (msg->proxy_auth==0 && msg->authorization==0))
	{
		LOG(L_ERR, "xl_get_authattr: Error while parsing headers\n");
		return -1;
	}

	hdr = (msg->proxy_auth==0)?msg->authorization:msg->proxy_auth;
	
	if(parse_credentials(hdr)!=0)
		return xl_get_empty(msg, res, param, flags);
	
	if(param->val.len==2)
	{
	    res->rs.s   = ((auth_body_t*)(hdr->parsed))->digest.realm.s;
		res->rs.len = ((auth_body_t*)(hdr->parsed))->digest.realm.len;
	} else {
	    res->rs.s   = ((auth_body_t*)(hdr->parsed))->digest.username.user.s;
		res->rs.len = ((auth_body_t*)(hdr->parsed))->digest.username.user.len;
	}
	
	res->flags = XL_VAL_STR;
    return 0;
}

#define COL_BUF 10

#define append_sstring(p, end, str) \
        do{\
                if ((p)+(sizeof(str)-1)<=(end)){\
                        memcpy((p), str, sizeof(str)-1); \
                        (p)+=sizeof(str)-1; \
                }else{ \
                        /* overflow */ \
                        LOG(L_ERR, "append_sstring overflow\n"); \
                        goto error;\
                } \
        } while(0) 


static int xl_get_color(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	static char color[COL_BUF];
	char* p;
	char* end;

	p = color;
	end = p + COL_BUF;
        
	/* excape sequenz */
	append_sstring(p, end, "\033[");
        
	if(param->val.s[0]!='_')
	{
		if (islower(param->val.s[0]))
		{
			/* normal font */
			append_sstring(p, end, "0;");
		} else {
			/* bold font */
			append_sstring(p, end, "1;");
			param->val.s[0] += 32;
		}
	}
         
	/* foreground */
	switch(param->val.s[0])
	{
		case 'x':
			append_sstring(p, end, "39;");
		break;
		case 's':
			append_sstring(p, end, "30;");
		break;
		case 'r':
			append_sstring(p, end, "31;");
		break;
		case 'g':
			append_sstring(p, end, "32;");
		break;
		case 'y':
			append_sstring(p, end, "33;");
		break;
		case 'b':
			append_sstring(p, end, "34;");
		break;
		case 'p':
			append_sstring(p, end, "35;");
		break;
		case 'c':
			append_sstring(p, end, "36;");
		break;
		case 'w':
			append_sstring(p, end, "37;");
		break;
		default:
			LOG(L_ERR, "xl_get_color: exit foreground\n");
			return xl_get_empty(msg, res, param, flags);
	}
         
	/* background */
	switch(param->val.s[1])
	{
		case 'x':
			append_sstring(p, end, "49");
		break;
		case 's':
			append_sstring(p, end, "40");
		break;
		case 'r':
			append_sstring(p, end, "41");
		break;
		case 'g':
			append_sstring(p, end, "42");
		break;
		case 'y':
			append_sstring(p, end, "43");
		break;
		case 'b':
			append_sstring(p, end, "44");
		break;
		case 'p':
			append_sstring(p, end, "45");
		break;
		case 'c':
			append_sstring(p, end, "46");
		break;
		case 'w':
			append_sstring(p, end, "47");
		break;
		default:
			LOG(L_ERR, "xl_get_color: exit background\n");
			return xl_get_empty(msg, res, param, flags);
	}

	/* end */
	append_sstring(p, end, "m");

	res->rs.s = color;
	res->rs.len = p-color;
	res->flags = XL_VAL_STR;
	return 0;

error:
	return -1;
}


static int xl_get_branch(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	str branch;
	qvalue_t q;

	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)
		return xl_get_null(msg, res, param, flags);


	branch.s = get_branch(0, &branch.len, &q, 0, 0, 0, 0);
	if (!branch.s) {
		return xl_get_null(msg, res, param, flags);
	}
	
	res->rs.s = branch.s;
	res->rs.len = branch.len;

	res->flags = XL_VAL_STR;
	return 0;
}

#define Q_PARAM ">;q="
#define Q_PARAM_LEN (sizeof(Q_PARAM) - 1)

static int xl_get_branches(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	str uri;
	qvalue_t q;
	int len, cnt, i;
	unsigned int qlen;
	char *p, *qbuf;

	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)
		return xl_get_null(msg, res, param, flags);
  
	cnt = len = 0;

	while ((uri.s = get_branch(cnt, &uri.len, &q, 0, 0, 0, 0)))
	{
		cnt++;
		len += uri.len;
		if (q != Q_UNSPECIFIED)
		{
			len += 1 + Q_PARAM_LEN + len_q(q);
		}
	}

	if (cnt == 0)
		return xl_get_empty(msg, res, param, flags);   

	len += (cnt - 1) * ITEM_FIELD_DELIM_LEN;

	if (len + 1 > LOCAL_BUF_SIZE)
	{
		LOG(L_ERR, "ERROR:xl_get_branches: local buffer length exceeded\n");
		return xl_get_null(msg, res, param, flags);
	}

	i = 0;
	p = local_buf;

	while ((uri.s = get_branch(i, &uri.len, &q, 0, 0, 0, 0)))
	{
		if (i)
		{
			memcpy(p, ITEM_FIELD_DELIM, ITEM_FIELD_DELIM_LEN);
			p += ITEM_FIELD_DELIM_LEN;
		}

		if (q != Q_UNSPECIFIED)
		{
			*p++ = '<';
		}

		memcpy(p, uri.s, uri.len);
		p += uri.len;
		if (q != Q_UNSPECIFIED)
		{
			memcpy(p, Q_PARAM, Q_PARAM_LEN);
			p += Q_PARAM_LEN;

			qbuf = q2str(q, &qlen);
			memcpy(p, qbuf, qlen);
			p += qlen;
		}
		i++;
	}

	res->rs.s = &(local_buf[0]);
	res->rs.len = len;

	res->flags = XL_VAL_STR;
	return 0;
}

#define ITEM_PRINT_ALL	-2
#define ITEM_PRINT_LAST	-1

static int xl_get_header(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	struct hdr_field *hf, *hf0;
	char *p;
	
	if(msg==NULL || res==NULL)
		return -1;

	if(param==NULL || param->val.len==0)
		return xl_get_null(msg, res, param, flags);
	
	hf0 = NULL;
	p = local_buf;

	/* we need to be sure we have parsed all headers */
	parse_headers(msg, HDR_EOH_F, 0);
	for (hf=msg->headers; hf; hf=hf->next)
	{
		if(param->val.s==NULL)
		{
			if (param->val.len!=hf->type)
				continue;
		} else {
			if (hf->name.len!=param->val.len)
				continue;
			if (strncasecmp(hf->name.s, param->val.s, hf->name.len)!=0)
				continue;
		}
		
		hf0 = hf;
		if(param->ind==ITEM_PRINT_ALL)
		{
			if(p!=local_buf)
			{
				if(p-local_buf+ITEM_FIELD_DELIM_LEN+1>LOCAL_BUF_SIZE)
				{
					LOG(L_ERR,
						"ERROR:xl_get_header: local buffer length exceeded\n");
					return xl_get_null(msg, res, param, flags);
				}
				memcpy(p, ITEM_FIELD_DELIM, ITEM_FIELD_DELIM_LEN);
				p += ITEM_FIELD_DELIM_LEN;
			}
			
			if(p-local_buf+hf0->body.len+1>LOCAL_BUF_SIZE)
			{
				LOG(L_ERR,
					"ERROR:xl_get_header: local buffer length exceeded!\n");
				return xl_get_null(msg, res, param, flags);
			}
			memcpy(p, hf0->body.s, hf0->body.len);
			p += hf0->body.len;
			continue;
		}
		
		if(param->ind==0)
			goto done;
		if(param->ind>0)
			param->ind--;
	}
	
done:
	res->flags = XL_VAL_STR;
	if(param->ind==ITEM_PRINT_ALL)
	{
		*p = 0;
		res->rs.s = local_buf;
		res->rs.len = p - local_buf;
		return 0;
	}
	
	if(hf0==NULL || param->ind>0)
		return xl_get_null(msg, res, param, flags);
	res->rs.s = hf0->body.s;
	res->rs.len = hf0->body.len;
	trim(&res->rs);
	return 0;
}

static int xl_get_avp(struct sip_msg *msg, xl_value_t *res, xl_param_t *param,
		int flags)
{
	unsigned short name_type;
	int_str avp_name;
	int_str avp_value;
	struct usr_avp *avp;
	char *p;
	str s = {0, 0};
	
	if(msg==NULL || res==NULL)
		return -1;

	if(param==NULL || param->val.len==0)
		return xl_get_null(msg, res, param, flags);
	
	if(param->val.s==NULL)
	{
		name_type = 0;
		avp_name.n = param->val.len;
	}
	else
	{
		name_type = AVP_NAME_STR;
		avp_name.s = param->val;
	}
	
	p = local_buf;
	
	if ((avp=search_first_avp(name_type, avp_name, &avp_value))==0)
		return xl_get_null(msg, res, param, flags);

	do {
		/* todo: optimization for last avp !!! */
		if(param->ind==0 || param->ind==ITEM_PRINT_ALL
				|| param->ind==ITEM_PRINT_LAST)
		{
			if(avp->flags & AVP_VAL_STR)
			{
				s.s = avp_value.s.s;
				s.len = avp_value.s.len;
			} else {
				s.s = int2str(avp_value.n, &s.len);
			}
		}
		
		if(param->ind==ITEM_PRINT_ALL)
		{
			if(p!=local_buf)
			{
				if(p-local_buf+ITEM_FIELD_DELIM_LEN+1>LOCAL_BUF_SIZE)
				{
					LOG(L_ERR,
						"ERROR:xl_get_avp: local buffer length exceeded\n");
					return xl_get_null(msg, res, param, flags);
				}
				memcpy(p, ITEM_FIELD_DELIM, ITEM_FIELD_DELIM_LEN);
				p += ITEM_FIELD_DELIM_LEN;
			}
			
			if(p-local_buf+s.len+1>LOCAL_BUF_SIZE)
			{
				LOG(L_ERR,
					"ERROR:xl_get_header: local buffer length exceeded!\n");
				return xl_get_null(msg, res, param, flags);
			}
			memcpy(p, s.s, s.len);
			p += s.len;
			continue;
		}
		
		if(param->ind==0)
			goto done;
		if(param->ind>0)
			param->ind--;
		if(param->ind!=ITEM_PRINT_LAST)
		{
			s.s   = NULL;
			s.len = 0;
		}
	} while ((avp=search_next_avp(avp, &avp_value))!=0);
	
done:
	res->flags = XL_VAL_STR;
	if(param->ind==ITEM_PRINT_ALL)
	{
		*p = 0;
		res->rs.s = local_buf;
		res->rs.len = p - local_buf;
		return 0;
	} else {
		if(avp && !(avp->flags&AVP_VAL_STR))
		{
			res->ri = avp_value.n;
			res->flags |= XL_VAL_INT|XL_TYPE_INT;
		}
	}
	
	if(s.s==NULL || param->ind>0)
		return xl_get_empty(msg, res, param, flags);
	res->rs.s = s.s;
	res->rs.len = s.len;
	return 0;
}

int xl_update_hdrname(xl_spec_p e)
{
	char c;
	struct hdr_field hdr;

	if(e==NULL || e->p.val.s==NULL || e->p.val.len<=0)
		goto error;
	
	/* optimize for known headers -- fake header name */
	c = e->p.val.s[e->p.val.len];
	e->p.val.s[e->p.val.len] = ':';
	e->p.val.len++;
	/* ugly hack for compact header names -- !!fake length!!
	 * -- parse_hname2 expects name buffer length >= 4
	 */
	if (parse_hname2(e->p.val.s,
			e->p.val.s + ((e->p.val.len<4)?4:e->p.val.len),
			&hdr)==0)
	{
		LOG(L_ERR,"xl_parse_name: error parsing header name\n");
		goto error;
	}
	e->p.val.len--;
	e->p.val.s[e->p.val.len] = c;
	if (hdr.type!=HDR_OTHER_T && hdr.type!=HDR_ERROR_T)
	{
		LOG(L_INFO,"INFO:xl_parse_name: using "
			"hdr type (%d) instead of <%.*s>\n",
		hdr.type, e->p.val.len, e->p.val.s);
		e->p.val.len = hdr.type;
		e->p.val.s = NULL;
	}
	
	return 0;
error:
	return -1;
}

char* xl_parse_index(char *s, int *ind)
{
	char *p;
	if(s==NULL || ind==NULL)
		return NULL;

	*ind = 0;
	p = s;
	/* check if we have index */
	if(*p != ITEM_LIBRACKET)
		return p;

	p++;
	if(*p=='-')
	{
		p++;
		if(*p!='1')
		{
			LOG(L_ERR, "xl_parse_index: error"
				" parsing format [%s] -- only -1 is accepted"
				" as a negative index\n", p);
			goto error;
		}
		*ind = ITEM_PRINT_LAST;
		p++;
	} else if (*p=='*') {
		*ind = ITEM_PRINT_ALL;
		p++;
	} else {
		while(*p>='0' && *p<='9')
		{
			*ind = (*ind) * 10 + *p - '0';
			p++;
		}
	}
	if(*p != ITEM_RIBRACKET)
	{
		LOG(L_ERR, "xl_parse_index: error parsing format"
			" [%s] expecting '%c'\n", p, ITEM_RIBRACKET);
		goto error;
	}
	p++;
	return p;

error:
	return NULL;
}

char* xl_parse_name(char *s, xl_spec_p e)
{
	char *p;
	if(s==NULL || e==NULL)
		return NULL;

	p = s;
	e->p.val.s = p;
	while(*p && *p!=ITEM_RNBRACKET && *p!=ITEM_LIBRACKET)
		p++;
	if(p == e->p.val.s)
	{
		LOG(L_ERR, "xl_parse_name: error parsing format - empty name"
			" [%s]\n", e->p.val.s);
		goto error;
	}
	e->p.val.len = p - e->p.val.s;
	
	if(*p==ITEM_RNBRACKET)
		goto done;
	if(*p=='\0')
	{
		LOG(L_ERR, "xl_parse_name: error parsing format - in name"
			" [%s] expecting '%c'\n", e->p.val.s, ITEM_RNBRACKET);
		goto error;
	}
	
	/* check if we have index */
	p = xl_parse_index(p, &(e->p.ind));
	if(p==NULL)
		goto error;
	
	if(*p != ITEM_RNBRACKET)
	{
		LOG(L_ERR, "xl_parse_name: error parsing format"
			" [%s] expecting '%c'!\n", e->p.val.s, ITEM_RNBRACKET);
		goto error;
	}

done:
	DBG("xl_parse_name: name [%.*s] index [%d]\n",
			e->p.val.len, e->p.val.s, e->p.ind);
	return p;

error:
	return NULL;
}

char* xl_parse_vname(char *s, xl_spec_p e, int flags)
{
	char *p;
	char *p0;
	int_str avp_name;
	int avp_type;
	int mode;
	str alias;
	xl_spec_t e0;

	if(s==NULL || e==NULL || *s!=ITEM_MARKER)
	{
		LOG(L_ERR, "xl_parse_vname: error - bad parameters\n");
		return NULL;
	}

	p = s;
#ifdef EXTRA_DEBUG
	DBG("xl_parse_vname: parsing [%s]\n", p);
#endif
	p++;
	e->p.ind = 0;
	if(p[0]=='a' || p[0]=='A')
	{ 
		/* look for avp */
		if(strlen(p)>6 && (p[1]=='v' || p[1]=='V') && (p[2]=='p' || p[2]=='P'))
		{
			/* long name */
			if(p[3]==ITEM_LNBRACKET
					|| ((p[3]=='t' || p[3]=='T') && p[4]==ITEM_LNBRACKET))
			{
				mode = 1;
				if(p[3]==ITEM_LNBRACKET)
					p += 4;
				else
					p += 5;
				
			} else if((p[3]=='g' || p[3]=='G') && p[4]==ITEM_LNBRACKET) {
				mode = 2;
				p += 5;
			} else if((p[3]=='s' || p[3]=='S') && p[4]==ITEM_LNBRACKET) {
				mode = 3;
				p += 5;
			} else if((p[3]=='p' || p[3]=='P') && p[4]==ITEM_LNBRACKET) {
				mode = 4;
				p += 5;
			} else {
				LOG(L_ERR, "xl_parse_vname: error - bad pvar name (1) %s\n", p);
				return NULL;
			}
		} else if(strlen(p)>4 && (p[1]==ITEM_LNBRACKET
					|| p[2]==ITEM_LNBRACKET)) {
			/* short name */
			if(p[1]==ITEM_LNBRACKET
					|| ((p[1]=='t' || p[1]=='T') && p[2]==ITEM_LNBRACKET))
			{
				mode = 1;
				if(p[1]==ITEM_LNBRACKET)
					p += 2;
				else
					p += 3;
			} else if((p[1]=='g' || p[1]=='G') && p[2]==ITEM_LNBRACKET) {
				mode = 2;
				p += 3;
			} else if((p[1]=='s' || p[1]=='S') && p[2]==ITEM_LNBRACKET) {
				mode = 3;
				p += 3;
			} else if((p[1]=='p' || p[1]=='P') && p[2]==ITEM_LNBRACKET) {
				mode = 4;
				p += 3;
			} else {
				LOG(L_ERR, "xl_parse_vname: error - bad pvar name (2) %s\n", p);
				return NULL;
			}
		} else {
			LOG(L_ERR, "xl_parse_vname: error - bad pvar name (3) %s\n", p);
			return NULL;
		}
	} else if (p[0]=='h' || p[0]=='H') {
		/* look for hdr */
		if(strlen(p)>6 && (p[1]=='d' || p[1]=='D') && (p[2]=='r' || p[2]=='R')
				&& p[3]==ITEM_LNBRACKET)
		{
			mode = 10;
			p += 4;
		} else if(strlen(p)>4 && p[1]==ITEM_LNBRACKET) {
			mode = 10;
			p += 2;
		} else {
			LOG(L_ERR, "xl_parse_vname: error - bad pvar name (4) %s\n", p);
			return NULL;
		}
	} else {
		LOG(L_ERR, "xl_parse_vname: error - bad pvar name (5) %s\n", p);
		return NULL;
	}

	if(mode==10)
	{
		/* hdr - we expect a letter or $ */
		if(*p==ITEM_MARKER)
		{ /* pseudo var */
			if(flags&XL_LEVEL2)
			{
				LOG(L_ERR, "xl_parse_xname: error - too many var levels"
					" [%s]!\n", p);
				goto error;
			}
			p = xl_parse_spec(p, &e0, flags|XL_LEVEL2);
			if(p==NULL)
				goto error;
			
			/* dynamic name */
			e->dp.itf = e0.itf;
			memcpy(&(e->p), &(e0.p), sizeof(xl_param_t));
			p = xl_parse_index(p, &(e->dp.ind));
			if(p==NULL)
				goto error;
			e->flags |= XL_DPARAM;
		} else {
			/* name */
			if(((*p < 'A' || *p > 'Z') && (*p < 'a' || *p > 'z')))
			{
				LOG(L_ERR, "xl_parse_vname: error parsing hdr name"
					" [%s]!\n", p);
				goto error;
			}
			p = xl_parse_name(p, e);
			if(p==NULL)
				goto error;
			if(xl_update_hdrname(e)!=0)
				goto error;
		}
		e->itf = xl_get_header;
		e->type = XL_HDR;
		if(e->flags&XL_DPARAM)
			DBG("xl_parse_vname: hdr double reference (%p/%p) (%.*s)"
					" (%d) (%d/%d)\n", e->itf, e->dp.itf,
					(e->p.val.s)?e->p.val.len:0,
					(e->p.val.s)?e->p.val.s:"",
					e->p.val.len, e->p.ind, e->p.ind);
		goto done;
	} else {
		/* avp  - we expect s:, i:, :, letter or $ */
		if(*p==ITEM_MARKER)
		{ /* pseudo var */
			/* backup for avp aliases */
			p0 = p;
			p = xl_parse_spec(p, &e0, flags|XL_LEVEL2);
			if(p==NULL)
				goto error;
			if(e0.type!=XL_NULL && e0.itf!=NULL)
			{
				if(flags&XL_LEVEL2)
				{
					LOG(L_ERR, "xl_parse_vname: error - too many var levels"
						" [%s]!!\n", p);
					goto error;
				}
				/* dynamic name */
				e->dp.itf = e0.itf;
				memcpy(&(e->p), &(e0.p), sizeof(xl_param_t));
				p = xl_parse_index(p, &(e->dp.ind));
				if(p==NULL)
					goto error;
				e->flags |= XL_DPARAM;
			} else {
				p0++;
				alias.s = p0;
				p = strchr(p0, ITEM_RNBRACKET);
				if(p==NULL)
				{
					LOG(L_ERR,
						"ERROR:xl_parse_vname: bad alias name "
						"\"%s\"\n", p0);
					goto error;
				}
				alias.len = p-p0;
				/* look for avp alias */
				if(lookup_avp_galias(&alias, &avp_type,
						&avp_name)==-1)
				{
					LOG(L_ERR,
						"ERROR:xl_parse_vname: unknow avp alias"
						"\"%.*s\"\n", alias.len, alias.s);
					goto error;
				}
				if(avp_type&AVP_NAME_STR)
				{
					e->p.val.s = avp_name.s.s;
					e->p.val.len = avp_name.s.len;
				} else {
					e->p.val.s = NULL;
					e->p.val.len = avp_name.n;
				}
			}
		} else {
			/* name */
			avp_type = 0;
			if(*p==':' || (*p=='s' && *(p+1)==':') || (*p=='S' && *(p+1)==':'))
			{
				if(*p==':')
					p++;
				else
					p+=2;
			} else {
				if((*p=='i' && *(p+1)==':') || (*p=='I' && *(p+1)==':'))
				{
					avp_type = 1;
					p+=2;
				}
			}
			
			p = xl_parse_name(p, e);
			if(p==NULL)
				goto error;
			if(avp_type==1)
			{	/* convert to int */
				p0 = e->p.val.s;
				avp_type = 0;
				while(*p0>='0' && *p0<='9'
						&& p0 < e->p.val.s + e->p.val.len)
				{
					avp_type = avp_type * 10 + *p0 - '0';
					p0++;
				}
				e->p.val.s = NULL;
				e->p.val.len = avp_type;						
			}
		}
		
		e->itf = xl_get_avp;
		e->type = XL_AVP;
		if(e->flags&XL_DPARAM)
			DBG("xl_parse_vname: avp double reference (%p/%p) (%.*s)"
					" (%d) (%d/%d)\n", e->itf, e->dp.itf,
					(e->p.val.s)?e->p.val.len:0,
					(e->p.val.s)?e->p.val.s:"",
					e->p.val.len, e->p.ind, e->p.ind);
		goto done;
	}

done:
	if(*p != ITEM_RNBRACKET)
	{
		LOG(L_ERR, "xl_parse_vname: error parsing format"
			" [%s] expecting '%c'!\n", e->p.val.s, ITEM_RNBRACKET);
		goto error;
	}
	
	if(e->p.ind!=0 && flags&XL_DISABLE_MULTI)
	{
		e->itf = NULL;
		if(flags&XL_THROW_ERROR)
			goto error;
	}
	return p;
	
error:
	return NULL;

}

char* xl_parse_spec(char *s, xl_spec_p e, int flags)
{
	char *p, *p0;
	
	if(s==NULL || e==NULL || *s!=ITEM_MARKER)
	{
		LOG(L_ERR, "xl_parse_item: error - bad parameters\n");
		return NULL;
	}
	memset(e, 0, sizeof(xl_spec_t));
	p = s;
	p++;
	switch(*p)
	{
		case ITEM_MARKER:
			e->itf = xl_get_marker;
			e->type = XL_MARKER;
		break;
		case 'a':
		case 'A':
			if(p[1]=='v' || p[1]=='V' ||  p[1]==ITEM_LNBRACKET
				|| p[1]=='t' || p[1]=='T' ||  p[1]=='g' ||  p[1]=='G'
				|| p[1]=='p' || p[1]=='P' ||  p[1]=='s' ||  p[1]=='S')
			{
				p0 = xl_parse_vname(p-1, e, flags);
				if(p0==NULL)
					goto error;
				p = p0;
				e->type = XL_AVP;
			} else {
				p++;
				switch(*p)
				{
					case 'r':
						e->itf = xl_get_authattr;
						e->p.val.len = 2;
						e->type = XL_AUTH_REALM;
					break;
					case 'u':
						e->itf = xl_get_authattr;
						e->p.val.len = 1;
						e->type = XL_AUTH_USERNAME;
					break;
					default:
						LOG(L_ERR,
							"xl_parse_item: error - bad specifier [%s]\n",p-2);
						goto error;
				}
			}
		break;
		case 'b':
			p++;
			switch(*p)
			{
				case 'r':
					e->itf = xl_get_branch;
					e->type = XL_BRANCH;
				break;
				case 'R':
					e->itf = xl_get_branches;
					e->type = XL_BRANCHES;
				break;
				default:
					e->itf = xl_get_null;
					e->type = XL_NULL;
			}
		break;
		case 'c':
			p++;
			switch(*p)
			{
				case 'i':
					e->itf = xl_get_callid;
					e->type = XL_CALLID;
				break;
				case 'l':
					e->itf = xl_get_content_length;
					e->type = XL_CONTENT_LENGTH;
				break;
				case 's':
					e->itf = xl_get_cseq;
					e->type = XL_CSEQ;
				break;
				case 't':
					e->itf = xl_get_contact;
					e->type = XL_CONTACT;
				break;
				case 'T':
					e->itf = xl_get_content_type;
					e->type = XL_CONTENT_TYPE;
				break;
				default:
					e->itf = xl_get_null;
					e->type = XL_NULL;
			}
		break;
		case 'C':
			p++;
			e->p.val.s = p;
			
			/* foreground */
			switch(*p)
			{
				case 'x':
				case 's': case 'r': case 'g':
				case 'y': case 'b': case 'p':
				case 'c': case 'w': case 'S':
				case 'R': case 'G': case 'Y':
				case 'B': case 'P': case 'C':
				case 'W':
				break;
				default: 
					e->itf = xl_get_empty;
					goto error;
			}
			p++;
                               
			/* background */
			switch(*p)
			{
				case 'x':
				case 's': case 'r': case 'g':
				case 'y': case 'b': case 'p':
				case 'c': case 'w':
				break;   
				default: 
					e->itf = xl_get_empty;
					goto error;
			}
  
			/* end */
			if(flags&XL_DISABLE_COLORS)
			{
				e->itf = NULL;
				e->type = XL_NONE;
				if(flags&XL_THROW_ERROR)
					goto error;
			} else {
				e->p.val.len = 2;
				e->itf = xl_get_color;
				e->type = XL_COLOR;
			}
		break;  
		case 'd':
			p++;
			switch(*p)
			{
				case 'd':
					e->itf = xl_get_dsturi_attr;
					e->p.val.len = 1;
					e->type = XL_DSTURI_DOMAIN;
				break;
				case 'p':
					e->itf = xl_get_dsturi_attr;
					e->p.val.len = 2;
					e->type = XL_DSTURI_PORT;
				break;
				case 'P':
					e->itf = xl_get_dsturi_attr;
					e->p.val.len = 3;
					e->type = XL_DSTURI_PROTOCOL;
				break;
				case 's':
					e->itf = xl_get_dset;
					e->type = XL_DSET;
				break;
				case 'u':
					e->itf = xl_get_dsturi;
					e->type = XL_DSTURI;
				break;
				default:
					e->itf = xl_get_null;
					e->type = XL_NULL;
			}
		break;
		case 'f':
			p++;
			switch(*p)
			{
				case 'd':
					e->itf = xl_get_from_attr;
					e->p.val.len = 3;
					e->type = XL_FROM_DOMAIN;
				break;
				case 'n':
					e->itf = xl_get_from_attr;
					e->p.val.len = 5;
					e->type = XL_FROM_DISPLAYNAME;
				break;
				case 't':
					e->itf = xl_get_from_attr;
					e->p.val.len = 4;
					e->type = XL_FROM_TAG;
				break;
				case 'u':
					e->itf = xl_get_from_attr;
					e->p.val.len = 1;
					e->type = XL_FROM;
				break;
				case 'U':
					e->itf = xl_get_from_attr;
					e->p.val.len = 2;
					e->type = XL_FROM_USERNAME;
				break;
				default:
					e->itf = xl_get_null;
					e->type = XL_NULL;
			}
		break;
		case 'h':
		case 'H':
			if((p[1]==ITEM_LNBRACKET)
				|| ((p[1]=='d' || p[1]=='D')
					&& (p[2]=='r' || p[2]=='R') && p[3]==ITEM_LNBRACKET))
			{
				p0 = xl_parse_vname(p-1, e, flags);
				if(p0==NULL)
					goto error;
				p = p0;
			} else {
				LOG(L_ERR, "xl_parse_item: error - bad specifier [%s]\n", p);
				goto error;
			}
			e->type = XL_HDR;
		break;
		case 'm':
			p++;
			switch(*p)
			{
				case 'b':
					e->itf = xl_get_msg_buf;
					e->type = XL_MSG_BUF;
				break;
				case 'f':
					e->itf = xl_get_flags;
					e->type = XL_FLAGS;
				break;
				case 'F':
					e->itf = xl_get_hexflags;
					e->type = XL_HEXFLAGS;
				break;
				case 'i':
					e->itf = xl_get_msgid;
					e->type = XL_MSGID;
				break;
				case 'l':
					e->itf = xl_get_msg_len;
					e->type = XL_MSG_LEN;
				break;
				default:
					e->itf = xl_get_null;
					e->type = XL_NULL;
			}
		break;
		case 'o':
			p++;
			switch(*p)
			{
				case 'd':
					e->itf = xl_get_ouri_attr;
					e->p.val.len = 2;
					e->type = XL_OURI_DOMAIN;
				break;
				case 'u':
					e->itf = xl_get_ouri;
					e->type = XL_OURI;
				break;
				case 'U':
					e->itf = xl_get_ouri_attr;
					e->p.val.len = 1;
					e->type = XL_OURI_USERNAME;
				break;
				case 'p':
					e->itf = xl_get_ouri_attr;
					e->p.val.len = 3;
					e->type = XL_OURI_PORT;
				break;
				case 'P':
					e->itf = xl_get_ouri_attr;
					e->p.val.len = 4;
					e->type = XL_OURI_PROTOCOL;
				break;
				default:
					e->itf = xl_get_null;
					e->type = XL_NULL;
			}
		break;
		case 'p':
			p++;
			switch(*p)
			{
				case 'p':
					e->itf = xl_get_pid;
					e->type = XL_PID;
				break;
				default:
					e->itf = xl_get_null;
					e->type = XL_NULL;
			}
		break;
		case 'r':
			p++;
			switch(*p)
			{
				case 'b':
					e->itf = xl_get_msg_body;
					e->type = XL_MSG_BODY;
				break;
				case 'c':
					e->itf = xl_get_return_code;
					e->type = XL_RETURN_CODE;
				break;
				case 'd':
					e->itf = xl_get_ruri_attr;
					e->p.val.len = 2;
					e->type = XL_RURI_DOMAIN;
				break;
				case 'm':
					e->itf = xl_get_method;
					e->type = XL_METHOD;
				break;
				case 'p':
					e->itf = xl_get_ruri_attr;
					e->p.val.len = 3;
					e->type = XL_RURI_PORT;
				break;
				case 'P':
					e->itf = xl_get_ruri_attr;
					e->p.val.len = 4;
					e->type = XL_RURI_PROTOCOL;
				break;
				case 'r':
					e->itf = xl_get_reason;
					e->type = XL_REASON;
				break;
				case 's':
					e->itf = xl_get_status;
					e->type = XL_STATUS;
				break;
				case 't':
					e->itf = xl_get_refer_to;
					e->type = XL_REFER_TO;
				break;
				case 'u':
					e->itf = xl_get_ruri;
					e->type = XL_RURI;
				break;
				case 'U':
					e->itf = xl_get_ruri_attr;
					e->p.val.len = 1;
					e->type = XL_RURI_USERNAME;
				break;
				default:
					e->itf = xl_get_null;
					e->type = XL_NULL;
			}
		break;
		case 'R':
			p++;
			switch(*p)
			{
				case 'i':
					e->itf = xl_get_rcvip;
					e->type = XL_RCVIP;
				break;
				case 'p':
					e->itf = xl_get_rcvport;
					e->type = XL_RCVPORT;
				break;
				default:
					e->itf = xl_get_null; 			
					e->type = XL_NULL;
			}
		break;
		case 's':
			p++;
			switch(*p)
			{
				case 'i':
					e->itf = xl_get_srcip;
					e->type = XL_SRCIP;
				break;
				case 'p':
					e->itf = xl_get_srcport;
					e->type = XL_SRCPORT;
				break;
				default:
					e->itf = xl_get_null; 			
					e->type = XL_NULL;
			}
		break;
		case 't':
			p++;
			switch(*p)
			{
				case 'd':
					e->itf = xl_get_to_attr;
					e->p.val.len = 3;
					e->type = XL_TO_DOMAIN;
				break;
				case 'n':
					e->itf = xl_get_to_attr;
					e->p.val.len = 5;
					e->type = XL_TO_DISPLAYNAME;
				break;
				case 't':
					e->itf = xl_get_to_attr;
					e->p.val.len = 4;
					e->type = XL_TO_TAG;
				break;
				case 'u':
					e->itf = xl_get_to_attr;
					e->p.val.len = 1;
					e->type = XL_TO;
				break;
				case 'U':
					e->itf = xl_get_to_attr;
					e->p.val.len = 2;
					e->type = XL_TO_USERNAME;
				break;
				default:
					e->itf = xl_get_null;
					e->type = XL_NULL;
			}
		break;
		case 'T':
			p++;
			switch(*p)
			{
				case 'f':
					e->itf = xl_get_timef;
					e->type = XL_TIMEF;
				break;
				case 's':
					e->itf = xl_get_times;
					e->type = XL_TIMES;
				break;
				default:
					e->itf = xl_get_null;
					e->type = XL_NULL;
			}
		break;
		case 'u':
			p++;
			switch(*p)
			{
				case 'a':
					e->itf = xl_get_useragent;
					e->type = XL_USERAGENT;
				break;
				default:
					e->itf = xl_get_null;
					e->type = XL_NULL;
			}
		break;
		default:
			e->itf = xl_get_null;
			e->type = XL_NULL;
	}
	if(*p != '\0')
		p++;
	return p;
	
error:
	return NULL;
}


/**
 *
 */
int xl_parse_format(char *s, xl_elem_p *el, int flags)
{
	char *p, *p0;
	int n = 0;
	xl_elem_p e, e0;
	
	if(s==NULL || el==NULL)
		return -1;

	DBG("xl_parse_format: parsing [%s]\n", s);
	
	p = s;
	*el = NULL;
	e = e0 = NULL;

	while(*p)
	{
		e0 = e;
		e = pkg_malloc(sizeof(xl_elem_t));
		if(!e)
			goto error;
		memset(e, 0, sizeof(xl_elem_t));
		n++;
		if(*el == NULL)
			*el = e;
		if(e0)
			e0->next = e;
	
		e->text.s = p;
		while(*p && *p!=ITEM_MARKER)
			p++;
		e->text.len = p - e->text.s;
		
		if(*p == '\0')
			break;

		p0 = xl_parse_spec(p, &e->spec, flags);
		
		if(p0==NULL)
			goto error;
		if(*p0 == '\0')
			break;
		p = p0;
	}
	DBG("xl_parse_format: format parsed OK: [%d] items\n", n);

	return 0;

error:
	xl_elem_free_all(*el);
	*el = NULL;
	return -1;
}

int xl_get_spec_name(struct sip_msg* msg, xl_spec_p sp, xl_value_t *value,
		int flags)
{
	if(msg==NULL || sp==NULL || sp->itf==NULL || value==NULL)
		return -1;
	memset(value, 0, sizeof(xl_value_t));
	if(sp->flags&XL_DPARAM) {
		if(sp->dp.itf==NULL)
		{
			LOG(L_ERR, "xl_get_spec_name: error - null sp->dp.itf\n");
			return -1;
		}
		if((*sp->dp.itf)(msg, value, &(sp->p), flags)!=0)
		{
			LOG(L_ERR, "xl_get_spec_name: error - cannot get the value\n");
			return -1;
		}
	} else {
		if(sp->p.val.s!=NULL)
		{
			value->rs = sp->p.val;
			value->flags = XL_VAL_STR;
		} else {
			value->ri = sp->p.val.len;
			value->flags = XL_VAL_INT|XL_TYPE_INT;
		}
	}
	return 0;
}


int xl_get_spec_value(struct sip_msg* msg, xl_spec_p sp, xl_value_t *value,
		int flags)
{
	xl_param_t tp;
	xl_value_t tv;
	if(msg==NULL || sp==NULL || sp->itf==NULL || value==NULL)
		return -1;
	memset(value, 0, sizeof(xl_value_t));
	if(sp->flags&XL_DPARAM) {
		if(sp->dp.itf==NULL)
		{
			LOG(L_ERR, "xl_get_spec_value: error - null sp->dp.itf\n");
			return -1;
		}
		memset(&tv, 0, sizeof(xl_value_t));
		(*sp->dp.itf)(msg, &tv, &(sp->p), flags);
		if(tv.flags&XL_VAL_NULL)
			return xl_get_null(msg, value, &(sp->p), flags);
		memset(&tp, 0, sizeof(xl_param_t));
		if((tv.flags&XL_TYPE_INT) && (tv.flags&XL_VAL_INT))
		{
			tp.val.len = tv.ri;
#ifdef EXTRA_DEBUG
			DBG("xl_get_spec_value: dynamic int name [%d]\n", tv.ri);
#endif
		} else {
			tp.val = tv.rs;
#ifdef EXTRA_DEBUG
			DBG("xl_get_spec_value: dynamic str name [%.*s]\n",
					tv.rs.len, tv.rs.s);
#endif
		}
		tp.ind = sp->dp.ind;
		return (*sp->itf)(msg, value, &tp, flags);
	} else {
		return (*sp->itf)(msg, value, &(sp->p), flags);
	}
}

int xl_print_spec(struct sip_msg* msg, xl_spec_p sp, char *buf, int *len)
{
	xl_value_t tok;
	if(msg==NULL || sp==NULL || buf==NULL || len==NULL)
		return -1;

	if(*len <= 0)
		return -1;
	
	memset(&tok, 0, sizeof(xl_value_t));
	
	/* put the value of the specifier */
	if(xl_get_spec_value(msg, sp, &tok, 0)==0)
	{
		if(tok.rs.len < *len)
			memcpy(buf, tok.rs.s, tok.rs.len);
		else
			goto overflow;
	}
	
	*len = tok.rs.len;
	buf[tok.rs.len] = '\0';
	return 0;
	
overflow:
	LOG(L_ERR,
		"xl_print_spec: buffer overflow -- increase the buffer size...\n");
	return -1;
}


int xl_printf(struct sip_msg* msg, xl_elem_p list, char *buf, int *len)
{
	int n, h;
	xl_value_t tok;
	xl_elem_p it;
	char *cur;
	
	if(msg==NULL || list==NULL || buf==NULL || len==NULL)
		return -1;

	if(*len <= 0)
		return -1;

	*buf = '\0';
	cur = buf;
	
	h = 0;
	n = 0;
	for (it=list; it; it=it->next)
	{
		/* put the text */
		if(it->text.s && it->text.len>0)
		{
			if(n+it->text.len < *len)
			{
				memcpy(cur, it->text.s, it->text.len);
				n += it->text.len;
				cur += it->text.len;
			} else {
				LOG(L_ERR, "xl_printf: no more space for text [%d]\n",it->text.len);
				goto overflow;
			}
		}
		/* put the value of the specifier */
		if(xl_get_spec_value(msg, &(it->spec), &tok, 0)==0)
		{
			if(n+tok.rs.len < *len)
			{
				memcpy(cur, tok.rs.s, tok.rs.len);
				n += tok.rs.len;
				cur += tok.rs.len;
				
				/* check for color entries to reset later */
				if (*it->spec.itf == xl_get_color)
					h = 1;
			} else {
				LOG(L_ERR, "xl_printf: no more space for spec value\n");
				goto overflow;
			}
		}
	}

	/* reset to default after entry */
	if (h == 1)
	{ 
		h = sizeof("\033[0m")-1;
		if (n+h < *len)
		{
			memcpy(cur, "\033[0m", h);
			n += h;
			cur += h;
		} else {
			goto overflow;
			LOG(L_ERR, "xl_printf: no more space for color spec\n");
		}
	}

	goto done;
	
overflow:
	LOG(L_ERR,
		"xl_printf: buffer overflow -- increase the buffer size...\n");
	return -1;

done:
#ifdef EXTRA_DEBUG
	DBG("xl_printf: final buffer length %d\n", n);
#endif
	*cur = '\0';
	*len = n;
	return 0;
}

int xl_elem_free_all(xl_elem_p log)
{
	xl_elem_p t;
	while(log)
	{
		t = log;
		log = log->next;
		pkg_free(t);
	}
	return 0;
}

