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
 *              contributed by Ingo Wolfsberger (daniel)
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
#include "parser/parse_refer_to.h"

#include "items.h"

static str str_null   = { "<null>", 6 };
static str str_empty  = { "", 0 };
static str str_marker = { ITEM_MARKER_STR, 1 };

int msg_id = 0;
time_t msg_tm = 0;
int cld_pid = 0;

#define ITEM_FIELD_DELIM ", "
#define ITEM_FIELD_DELIM_LEN (sizeof(ITEM_FIELD_DELIM) - 1)

#define LOCAL_BUF_SIZE	511
static char local_buf[LOCAL_BUF_SIZE+1];

static int xl_get_null(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	res->s = str_null.s;
	res->len = str_null.len;
	return 0;
}

static int xl_get_empty(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	res->s = str_empty.s;
	res->len = str_empty.len;
	return 0;
}

static int xl_get_marker(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	res->s = str_marker.s;
	res->len = str_marker.len;
	return 0;
}

static int xl_get_pid(struct sip_msg *msg, str *res, str *hp, int hi)
{
	int l = 0;
	char *ch = NULL;

	if(msg==NULL || res==NULL)
		return -1;

	if(cld_pid == 0)
		cld_pid = (int)getpid();
	ch = int2str(cld_pid, &l);

	res->s = ch;
	res->len = l;

	return 0;
}

extern int return_code;
static int xl_get_return_code(struct sip_msg *msg, str *res, str *hp, int hi)
{
	int l = 0;
	char *s = NULL;

	if(msg==NULL || res==NULL)
		return -1;

	s = int2str(return_code, &l);

	res->s = s;
	res->len = l;

	return 0;
}

static int xl_get_times(struct sip_msg *msg, str *res, str *hp, int hi)
{
	int l = 0;
	char *ch = NULL;
		
	if(msg==NULL || res==NULL)
		return -1;

	if(msg_id != msg->id || msg_tm==0)
	{
		msg_tm = time(NULL);
		msg_id = msg->id;
	}
	ch = int2str(msg_tm, &l);
	
	res->s = ch;
	res->len = l;

	return 0;
}
static int xl_get_timef(struct sip_msg *msg, str *res, str *hp, int hi)
{
	char *ch = NULL;
	
	if(msg==NULL || res==NULL)
		return -1;
	if(msg_id != msg->id || msg_tm==0)
	{
		msg_tm = time(NULL);
		msg_id = msg->id;
	}
	
	ch = ctime(&msg_tm);
	
	res->s = ch;
	res->len = strlen(ch)-1;

	return 0;
}

static int xl_get_msgid(struct sip_msg *msg, str *res, str *hp, int hi)
{
	int l = 0;
	char *ch = NULL;

	if(msg==NULL || res==NULL)
		return -1;

	ch = int2str(msg->id, &l);
	res->s = ch;
	res->len = l;

	return 0;
}

static int xl_get_method(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REQUEST)
	{
		res->s = msg->first_line.u.request.method.s;
		res->len = msg->first_line.u.request.method.len;
	}
	else
		return xl_get_null(msg, res, hp, hi);
	
	return 0;
}

static int xl_get_status(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)
	{
		res->s = msg->first_line.u.reply.status.s;
		res->len = msg->first_line.u.reply.status.len;		
	}
	else
		return xl_get_null(msg, res, hp, hi);
	
	return 0;
}

static int xl_get_reason(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)
	{
		res->s = msg->first_line.u.reply.reason.s;
		res->len = msg->first_line.u.reply.reason.len;		
	}
	else
		return xl_get_null(msg, res, hp, hi);
	
	return 0;
}

static int xl_get_ruri(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)	/* REPLY doesnt have a ruri */
		return xl_get_null(msg, res, hp, hi);

	if(msg->parsed_uri_ok==0 /* R-URI not parsed*/ && parse_sip_msg_uri(msg)<0)
	{
		LOG(L_ERR, "xl_get_ruri: ERROR while parsing the R-URI\n");
		return xl_get_null(msg, res, hp, hi);
	}
	
	if (msg->new_uri.s!=NULL)
	{
		res->s   = msg->new_uri.s;
		res->len = msg->new_uri.len;
	} else {
		res->s   = msg->first_line.u.request.uri.s;
		res->len = msg->first_line.u.request.uri.len;
	}
	
	return 0;
}

static int xl_get_ruri_username(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)	/* REPLY doesnt have a ruri */
		return xl_get_null(msg, res, hp, hi);

	if(msg->parsed_uri_ok==0 /* R-URI not parsed*/ && parse_sip_msg_uri(msg)<0)
	{
		LOG(L_ERR,
			"xl_get_ruri_username: ERROR while parsing the R-URI\n");
		return xl_get_null(msg, res, hp, hi);
	}
	
	res->s   = msg->parsed_uri.user.s;
	res->len = msg->parsed_uri.user.len;
	
	return 0;
}

static int xl_get_ruri_domain(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)	/* REPLY doesnt have a ruri */
		return xl_get_null(msg, res, hp, hi);

	if(msg->parsed_uri_ok==0 /* R-URI not parsed*/ && parse_sip_msg_uri(msg)<0)
	{
		LOG(L_ERR,
			"xl_get_ruri_domain: ERROR while parsing the R-URI\n");
		return xl_get_null(msg, res, hp, hi);
	}
	
	res->s   = msg->parsed_uri.host.s;
	res->len = msg->parsed_uri.host.len;
	
	return 0;
}

static int xl_get_contact(struct sip_msg* msg, str* res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->contact==NULL && parse_headers(msg, HDR_CONTACT_F, 0)==-1) 
	{
		DBG("xl_get_contact: no contact header\n");
		return xl_get_null(msg, res, hp, hi);
	}
	
	if(!msg->contact || !msg->contact->body.s || msg->contact->body.len<=0)
    {
		DBG("xl_get_contact: no contact header!\n");
		return xl_get_null(msg, res, hp, hi);
	}
	
	res->s = msg->contact->body.s;
	res->len = msg->contact->body.len;

	
//	res->s = ((struct to_body*)msg->contact->parsed)->uri.s;
//	res->len = ((struct to_body*)msg->contact->parsed)->uri.len;

	return 0;
}


static int xl_get_from(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(parse_from_header(msg)==-1)
	{
		LOG(L_ERR, "xl_get_from: ERROR cannot parse FROM header\n");
		return xl_get_null(msg, res, hp, hi);
	}
	
	if(msg->from==NULL || get_from(msg)==NULL)
		return xl_get_null(msg, res, hp, hi);

	res->s = get_from(msg)->uri.s;
	res->len = get_from(msg)->uri.len; 
	
	return 0;
}

static int xl_get_from_username(struct sip_msg *msg, str *res, str *hp, int hi)
{
	struct sip_uri uri;
	if(msg==NULL || res==NULL)
		return -1;

	if(parse_from_header(msg)==-1)
	{
		LOG(L_ERR,
			"xl_get_from_username: ERROR cannot parse FROM header\n");
		return xl_get_null(msg, res, hp, hi);
	}
	
	if(msg->from==NULL || get_from(msg)==NULL)
		return xl_get_null(msg, res, hp, hi);

	memset(&uri, 0, sizeof(struct sip_uri));
	if (parse_uri(get_from(msg)->uri.s, get_from(msg)->uri.len , &uri)<0)
	{
		LOG(L_ERR,"xl_get_from_username: failed to parse From uri\n");
		return xl_get_null(msg, res, hp, hi);
	}
	
	if(uri.user.s==NULL)
		return xl_get_empty(msg, res, hp, hi);

	res->s   = uri.user.s;
	res->len = uri.user.len; 
	return 0;
}

static int xl_get_from_domain(struct sip_msg *msg, str *res, str *hp, int hi)
{
	struct sip_uri uri;
	if(msg==NULL || res==NULL)
		return -1;

	if(parse_from_header(msg)==-1)
	{
		LOG(L_ERR,
			"xl_get_from_domain: ERROR cannot parse FROM header\n");
		return xl_get_null(msg, res, hp, hi);
	}
	
	if(msg->from==NULL || get_from(msg)==NULL)
		return xl_get_null(msg, res, hp, hi);

	memset(&uri, 0, sizeof(struct sip_uri));
	if (parse_uri(get_from(msg)->uri.s, get_from(msg)->uri.len , &uri)<0)
	{
		LOG(L_ERR,"xl_get_from_domain: failed to parse From uri\n");
		return xl_get_null(msg, res, hp, hi);
	}
	
	res->s   = uri.host.s;
	res->len = uri.host.len; 
	return 0;
}

static int xl_get_from_tag(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(parse_from_header(msg)==-1)
	{
		LOG(L_ERR, "xl_get_from: ERROR cannot parse FROM header\n");
		return xl_get_null(msg, res, hp, hi);
	}
	
	if(msg->from==NULL || get_from(msg)==NULL 
			|| get_from(msg)->tag_value.s==NULL)
		return xl_get_null(msg, res, hp, hi);

	res->s = get_from(msg)->tag_value.s;
	res->len = get_from(msg)->tag_value.len; 

	return 0;
}


static int xl_get_to(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->to==NULL && parse_headers(msg, HDR_TO_F, 0)==-1)
	{
		LOG(L_ERR, "xl_get_to: ERROR cannot parse TO header\n");
		return xl_get_null(msg, res, hp, hi);
	}
	if(msg->to==NULL || get_to(msg)==NULL)
		return xl_get_null(msg, res, hp, hi);

	res->s = get_to(msg)->uri.s;
	res->len = get_to(msg)->uri.len; 
	
	return 0;
}

static int xl_get_to_username(struct sip_msg *msg, str *res, str *hp, int hi)
{
	struct sip_uri uri;
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->to==NULL && parse_headers(msg, HDR_TO_F, 0)==-1)
	{
		LOG(L_ERR, "xl_get_to_username: ERROR cannot parse TO header\n");
		return xl_get_null(msg, res, hp, hi);
	}
	if(msg->to==NULL || get_to(msg)==NULL)
		return xl_get_null(msg, res, hp, hi);

	memset(&uri, 0, sizeof(struct sip_uri));
	if (parse_uri(get_to(msg)->uri.s, get_to(msg)->uri.len , &uri)<0)
	{
		LOG(L_ERR,"xl_get_to_username: failed to parse To uri\n");
		return xl_get_null(msg, res, hp, hi);
	}
	
	if(uri.user.s==NULL)
		return xl_get_empty(msg, res, hp, hi);

	res->s   = uri.user.s;
	res->len = uri.user.len; 
	
	return 0;
}

static int xl_get_to_domain(struct sip_msg *msg, str *res, str *hp, int hi)
{
	struct sip_uri uri;
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->to==NULL && parse_headers(msg, HDR_TO_F, 0)==-1)
	{
		LOG(L_ERR, "xl_get_to_domain: ERROR cannot parse TO header\n");
		return xl_get_null(msg, res, hp, hi);
	}
	if(msg->to==NULL || get_to(msg)==NULL)
		return xl_get_null(msg, res, hp, hi);

	memset(&uri, 0, sizeof(struct sip_uri));
	if (parse_uri(get_to(msg)->uri.s, get_to(msg)->uri.len , &uri)<0)
	{
		LOG(L_ERR,"xl_get_to_domain: failed to parse To uri\n");
		return xl_get_null(msg, res, hp, hi);
	}
	
	res->s   = uri.host.s;
	res->len = uri.host.len; 
	
	return 0;
}

static int xl_get_to_tag(struct sip_msg* msg, str* res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->to==NULL && ((parse_headers(msg, HDR_TO_F, 0)==-1) || 
				(msg->to==NULL)) )
	{
		LOG(L_ERR, "xl_get_to_tag: ERROR cannot parse TO header\n");
		return xl_get_null(msg, res, hp, hi);
	}
	
	if (get_to(msg)->tag_value.len <= 0) 
		return xl_get_null(msg, res, hp, hi);
	
	res->s = get_to(msg)->tag_value.s;
	res->len = get_to(msg)->tag_value.len;

	return 0;
}

static int xl_get_cseq(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	if(msg->cseq==NULL && ((parse_headers(msg, HDR_CSEQ_F, 0)==-1) || 
				(msg->cseq==NULL)) )
	{
		LOG(L_ERR, "xl_get_cseq: ERROR cannot parse CSEQ header\n");
		return xl_get_null(msg, res, hp, hi);
	}

	res->s = get_cseq(msg)->number.s;
	res->len = get_cseq(msg)->number.len;

	return 0;
}

static int xl_get_msg_buf(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	res->s = msg->buf;
	res->len = msg->len;

	return 0;
}

static int xl_get_msg_len(struct sip_msg *msg, str *res, str *hp, int hi)
{
	int l = 0;
	char *ch = NULL;

	if(msg==NULL || res==NULL)
		return -1;

	ch = int2str(msg->len, &l);
	res->s = ch;
	res->len = l;

	return 0;
}

static int xl_get_flags(struct sip_msg *msg, str *res, str *hp, int hi)
{
	int l = 0;
	char *ch = NULL;

	if(msg==NULL || res==NULL)
		return -1;

	ch = int2str(msg->flags, &l);
	res->s = ch;
	res->len = l;

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

static int xl_get_hexflags(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;

	res->s = int_to_8hex(msg->flags);
	res->len = 8;

	return 0;
}

static int xl_get_callid(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	if(msg->callid==NULL && ((parse_headers(msg, HDR_CALLID_F, 0)==-1) ||
				(msg->callid==NULL)) )
	{
		LOG(L_ERR, "xl_get_callid: ERROR cannot parse Call-Id header\n");
		return xl_get_null(msg, res, hp, hi);
	}

	res->s = msg->callid->body.s;
	res->len = msg->callid->body.len;
	trim(res);

	return 0;
}

static int xl_get_srcip(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;

	res->s = ip_addr2a(&msg->rcv.src_ip);
	res->len = strlen(res->s);
   
	return 0;
}

static int xl_get_srcport(struct sip_msg *msg, str *res, str *hp, int hi)
{
	int l = 0;
	char *ch = NULL;

	if(msg==NULL || res==NULL)
		return -1;

	ch = int2str(msg->rcv.src_port, &l);
	res->s = ch;
	res->len = l;
   
	return 0;
}

static int xl_get_rcvip(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	if(msg->rcv.bind_address==NULL 
			|| msg->rcv.bind_address->address_str.s==NULL)
		return xl_get_null(msg, res, hp, hi);
	
	res->s   = msg->rcv.bind_address->address_str.s;
	res->len = msg->rcv.bind_address->address_str.len;
	
	return 0;
}

static int xl_get_rcvport(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;
	
	if(msg->rcv.bind_address==NULL 
			|| msg->rcv.bind_address->port_no_str.s==NULL)
		return xl_get_null(msg, res, hp, hi);
	
	res->s   = msg->rcv.bind_address->port_no_str.s;
	res->len = msg->rcv.bind_address->port_no_str.len;
	
	return 0;
}

static int xl_get_useragent(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL) 
		return -1;
	if(msg->user_agent==NULL && ((parse_headers(msg, HDR_USERAGENT_F, 0)==-1)
			 || (msg->user_agent==NULL)))
	{
		DBG("xl_get_useragent: User-Agent header not found\n");
		return xl_get_null(msg, res, hp, hi);
	}
	
	res->s = msg->user_agent->body.s;
	res->len = msg->user_agent->body.len;
	trim(res);
	
	return 0;
}

static int xl_get_refer_to(struct sip_msg *msg, str *res, str *hp, int hi)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(parse_refer_to_header(msg)==-1)
	{
		LOG(L_ERR,
			"xl_get_refer_to: ERROR cannot parse Refer-To header\n");
		return xl_get_null(msg, res, hp, hi);
	}
	
	if(msg->refer_to==NULL || get_refer_to(msg)==NULL)
		return xl_get_null(msg, res, hp, hi);

	res->s = get_refer_to(msg)->uri.s;
	res->len = get_refer_to(msg)->uri.len; 
	
	return 0;
}


static int xl_get_dset(struct sip_msg *msg, str *res, str *hp, int hi)
{
    if(msg==NULL || res==NULL)
	return -1;
    
    res->s = print_dset(msg, &res->len);

    if ((res->s) == NULL) return xl_get_null(msg, res, hp, hi);
    
    res->len -= CRLF_LEN;

    return 0;
}
static int xl_get_dsturi(struct sip_msg *msg, str *res, str *hp, int hi)
{
    if(msg==NULL || res==NULL)
		return -1;
    
    if (msg->dst_uri.s == NULL) return xl_get_null(msg, res, hp, hi);

	res->s = msg->dst_uri.s;
    res->len = msg->dst_uri.len;

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


static int xl_get_color(struct sip_msg *msg, str *res, str *hp, int hi)
{
	static char color[COL_BUF];
	char* p;
	char* end;

	p = color;
	end = p + COL_BUF;
        
	/* excape sequenz */
	append_sstring(p, end, "\033[");
        
	if(hp->s[0]!='_')
	{
		if (islower(hp->s[0]))
		{
			/* normal font */
			append_sstring(p, end, "0;");
		} else {
			/* bold font */
			append_sstring(p, end, "1;");
			hp->s[0] += 32;
		}
	}
         
	/* foreground */
	switch(hp->s[0])
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
			return xl_get_empty(msg, res, hp, hi);
	}
         
	/* background */
	switch(hp->s[1])
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
			return xl_get_empty(msg, res, hp, hi);
	}

	/* end */
	append_sstring(p, end, "m");

	res->s = color;
	res->len = p-color;
	return 0;

error:
	return -1;
}


static int xl_get_branch(struct sip_msg *msg, str *res, str *hp, int hi)
{
	str branch;
	qvalue_t q;

	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)
		return xl_get_null(msg, res, hp, hi);


	init_branch_iterator();
	branch.s = next_branch(&branch.len, &q, 0, 0, 0);
	if (!branch.s) {
		return xl_get_null(msg, res, hp, hi);
	}
	
	res->s = branch.s;
	res->len = branch.len;

	return 0;
}

#define Q_PARAM ">;q="
#define Q_PARAM_LEN (sizeof(Q_PARAM) - 1)

static int xl_get_branches(struct sip_msg *msg, str *res, str *hp, int hi)
{
	str uri;
	qvalue_t q;
	int len, cnt, i;
	unsigned int qlen;
	char *p, *qbuf;

	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)
		return xl_get_null(msg, res, hp, hi);
  
	cnt = len = 0;

	init_branch_iterator();
	while ((uri.s = next_branch(&uri.len, &q, 0, 0, 0)))
	{
		cnt++;
		len += uri.len;
		if (q != Q_UNSPECIFIED)
		{
			len += 1 + Q_PARAM_LEN + len_q(q);
		}
	}

	if (cnt == 0)
		return xl_get_empty(msg, res, hp, hi);   

	len += (cnt - 1) * ITEM_FIELD_DELIM_LEN;

	if (len + 1 > LOCAL_BUF_SIZE)
	{
		LOG(L_ERR, "ERROR:xl_get_branches: local buffer length exceeded\n");
		return xl_get_null(msg, res, hp, hi);
	}

	i = 0;
	p = local_buf;

	init_branch_iterator();
	while ((uri.s = next_branch(&uri.len, &q, 0, 0, 0)))
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

	res->s = &(local_buf[0]);
	res->len = len;

	return 0;
}

#define ITEM_PRINT_ALL	-2
#define ITEM_PRINT_LAST	-1

static int xl_get_header(struct sip_msg *msg, str *res, str *hp, int hi)
{
	struct hdr_field *hf, *hf0;
	char *p;
	
	if(msg==NULL || res==NULL)
		return -1;

	if(hp==NULL || hp->len==0)
		return xl_get_null(msg, res, hp, hi);
	
	hf0 = NULL;
	p = local_buf;

	/* we need to be sure we have parsed all headers */
	parse_headers(msg, HDR_EOH_F, 0);
	for (hf=msg->headers; hf; hf=hf->next)
	{
		if(hp->s==NULL)
		{
			if (hp->len!=hf->type)
				continue;
		} else {
			if (hf->name.len!=hp->len)
				continue;
			if (strncasecmp(hf->name.s, hp->s, hf->name.len)!=0)
				continue;
		}
		
		hf0 = hf;
		if(hi==ITEM_PRINT_ALL)
		{
			if(p!=local_buf)
			{
				if(p-local_buf+ITEM_FIELD_DELIM_LEN+1>LOCAL_BUF_SIZE)
				{
					LOG(L_ERR,
						"ERROR:xl_get_header: local buffer length exceeded\n");
					return xl_get_null(msg, res, hp, hi);
				}
				memcpy(p, ITEM_FIELD_DELIM, ITEM_FIELD_DELIM_LEN);
				p += ITEM_FIELD_DELIM_LEN;
			}
			
			if(p-local_buf+hf0->body.len+1>LOCAL_BUF_SIZE)
			{
				LOG(L_ERR,
					"ERROR:xl_get_header: local buffer length exceeded!\n");
				return xl_get_null(msg, res, hp, hi);
			}
			memcpy(p, hf0->body.s, hf0->body.len);
			p += hf0->body.len;
			continue;
		}
		
		if(hi==0)
			goto done;
		if(hi>0)
			hi--;
	}
	
done:
	if(hi==ITEM_PRINT_ALL)
	{
		*p = 0;
		res->s = local_buf;
		res->len = p - local_buf;
		return 0;
	}
	
	if(hf0==NULL || hi>0)
		return xl_get_null(msg, res, hp, hi);
	res->s = hf0->body.s;
	res->len = hf0->body.len;
	trim(res);
	return 0;
}

static int xl_get_avp(struct sip_msg *msg, str *res, str *hp, int hi)
{
	unsigned short name_type;
	int_str avp_name;
	int_str avp_value;
	struct usr_avp *avp;
	char *p;
	str s = {0, 0};
	
	if(msg==NULL || res==NULL)
		return -1;

	if(hp==NULL || hp->len==0)
		return xl_get_null(msg, res, hp, hi);
	
	if(hp->s==NULL)
	{
		name_type = 0;
		avp_name.n = hp->len;
	}
	else
	{
		name_type = AVP_NAME_STR;
		avp_name.s = hp;
	}
	
	p = local_buf;
	
	if ((avp=search_first_avp(name_type, avp_name, &avp_value))==0)
		return xl_get_null(msg, res, hp, hi);

	do {
		/* todo: optimization for last avp !!! */
		if(hi==0 || hi==ITEM_PRINT_ALL || hi==ITEM_PRINT_LAST)
		{
			if(avp->flags & AVP_VAL_STR)
			{
				s.s = avp_value.s->s;
				s.len = avp_value.s->len;
			} else {
				s.s = int2str(avp_value.n, &s.len);
			}
		}
		
		if(hi==ITEM_PRINT_ALL)
		{
			if(p!=local_buf)
			{
				if(p-local_buf+ITEM_FIELD_DELIM_LEN+1>LOCAL_BUF_SIZE)
				{
					LOG(L_ERR,
						"ERROR:xl_get_avp: local buffer length exceeded\n");
					return xl_get_null(msg, res, hp, hi);
				}
				memcpy(p, ITEM_FIELD_DELIM, ITEM_FIELD_DELIM_LEN);
				p += ITEM_FIELD_DELIM_LEN;
			}
			
			if(p-local_buf+s.len+1>LOCAL_BUF_SIZE)
			{
				LOG(L_ERR,
					"ERROR:xl_get_header: local buffer length exceeded!\n");
				return xl_get_null(msg, res, hp, hi);
			}
			memcpy(p, s.s, s.len);
			p += s.len;
			continue;
		}
		
		if(hi==0)
			goto done;
		if(hi>0)
			hi--;
		if(hi!=ITEM_PRINT_LAST)
		{
			s.s   = NULL;
			s.len = 0;
		}
	} while ((avp=search_next_avp(avp, &avp_value))!=0);
	
done:
	if(hi==ITEM_PRINT_ALL)
	{
		*p = 0;
		res->s = local_buf;
		res->len = p - local_buf;
		return 0;
	}
	
	if(s.s==NULL || hi>0)
		return xl_get_null(msg, res, hp, hi);
	res->s = s.s;
	res->len = s.len;
	return 0;
}

char* xl_parse_name(char *s, xl_spec_p e, int mode, int flags)
{
	char *p, c;
	struct hdr_field hdr;
	int_str avp_name;
	int avp_type;
	int avp_mode;

	if(s==NULL || e==NULL || *s!='(')
	{
		LOG(L_ERR, "xl_parse_name: error - bad parameters\n");
		return NULL;
	}

	avp_mode = 0;
	p = s;
	p++;
	e->hindex = 0;
	/* we expect a letter, : or $ */
	if(mode==1)
	{
		avp_mode = 1;
		if(*p=='$')
		{ /* alias */
			avp_mode |= 2;
			p++;
		} else {
			if(*p==':' || (*p=='s' && *(p+1)==':') || (*p=='S' && *(p+1)==':'))
			{
				if(*p==':')
					p++;
				else
					p+=2;
			} else {
				if((*p=='i' && *(p+1)==':') || (*p=='I' && *(p+1)==':'))
				{
					avp_mode |= 4;
					p+=2;
				}
			}
		}
	} else {
		if(((*p < 'A' || *p > 'Z') && (*p < 'a' || *p > 'z')))
		{
			LOG(L_ERR, "xl_parse_name: error parsing format"
				" [%s]!\n", p);
			goto error;
		}
	}
	
	e->hparam.s = p;
	while(*p && *p!=')' && *p!='[')
		p++;
	if(*p == '\0')
	{
		LOG(L_ERR, "xl_parse_name: error parsing format"
			" [%s] expecting ')'\n", e->hparam.s);
		goto error;
	}
	e->hparam.len = p - e->hparam.s;
	/* check if we have index */
	if(*p == '[')
	{
		p++;
		if(*p=='-')
		{
			p++;
			if(*p!='1')
			{
				LOG(L_ERR, "xl_parse_name: error"
					" parsing format [%s] -- only -1 is accepted"
					" as a negative index\n", e->hparam.s);
				goto error;
			}
			e->hindex = ITEM_PRINT_LAST;
			p++;
		} else if (*p=='*') {
			e->hindex = ITEM_PRINT_ALL;
			p++;
		} else {
			while(*p>='0' && *p<='9')
			{
				e->hindex = e->hindex * 10 + *p - '0';
				p++;
			}
		}
		if(*p != ']')
		{
			LOG(L_ERR, "xl_parse_name: error parsing format"
				" [%s] expecting ']'\n", e->hparam.s);
			goto error;
		}
		p++;
	}
	if(*p != ')')
	{
		LOG(L_ERR, "xl_parse_name: error parsing format"
			" [%s] expecting ')'!\n", e->hparam.s);
		goto error;
	}
		
	DBG("xl_parse_name: name [%.*s] index [%d]\n",
			e->hparam.len, e->hparam.s, e->hindex);
	if(avp_mode==0)
	{
		/* optimize for known headers -- fake header name */
		c = e->hparam.s[e->hparam.len];
		e->hparam.s[e->hparam.len] = ':';
		e->hparam.len++;
		/* ugly hack for compact header names -- !!fake length!!
		 * -- parse_hname2 expects name buffer length >= 4
		 */
		if (parse_hname2(e->hparam.s,
				e->hparam.s + ((e->hparam.len<4)?4:e->hparam.len),
				&hdr)==0)
		{
			LOG(L_ERR,"xl_parse_name: error parsing header name\n");
			goto error;
		}
		e->hparam.len--;
		e->hparam.s[e->hparam.len] = c;
		if (hdr.type!=HDR_OTHER_T && hdr.type!=HDR_ERROR_T)
		{
			LOG(L_INFO,"INFO:xl_parse_name: using "
				"hdr type (%d) instead of <%.*s>\n",
			hdr.type, e->hparam.len, e->hparam.s);
			e->hparam.len = hdr.type;
			e->hparam.s = NULL;
		}
		e->itf = xl_get_header;
	} else {
		if(avp_mode&2)
		{
			if(lookup_avp_galias(&e->hparam, &avp_type,
					&avp_name)==-1)
			{
				LOG(L_ERR,
					"ERROR:xl_parse_name: unknow avp alias"
					"\"%.*s\"\n", e->hparam.len, e->hparam.s);
				goto error;
			}
			if(avp_type&AVP_NAME_STR)
			{
				e->hparam.s = avp_name.s->s;
				e->hparam.len = avp_name.s->len;
			} else {
				e->hparam.s = NULL;
				e->hparam.len = avp_name.n;
			}
		} else {
			if(avp_mode&4)
			{
				p = e->hparam.s;
				avp_type = 0;
				while(*p>='0' && *p<='9'
						&& p < e->hparam.s + e->hparam.len)
				{
					avp_type = avp_type * 10 + *p - '0';
					p++;
				}
				e->hparam.s = NULL;
				e->hparam.len = avp_type;						
			}
		}
		e->itf = xl_get_avp;
	}
	if(e->hindex!=0 && flags&XL_DISABLE_MULTI)
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
	p = s;
	p++;
	switch(*p)
	{
		case ITEM_MARKER:
			e->itf = xl_get_marker;
		break;
		case 'a':
		case 'A':
			if((p[1]=='v' || p[1]=='V')
					&& (p[2]=='p' || p[2]=='P') && p[3]=='(')
			{
				p+=3;
				p0 = xl_parse_name(p, e, 1, flags);
				if(p0==NULL)
					goto error;
				p = p0;
			} else {
				LOG(L_ERR, "xl_parse_item: error - bad specifier [%s]\n", p);
				goto error;
			}
		break;
		case 'b':
			p++;
			switch(*p)
			{
				case 'r':
					e->itf = xl_get_branch;
				break;
				case 'R':
					e->itf = xl_get_branches;
				break;
				default:
					e->itf = xl_get_null;
			}
		break;
		case 'c':
			p++;
			switch(*p)
			{
				case 'i':
					e->itf = xl_get_callid;
				break;
				case 's':
					e->itf = xl_get_cseq;
				break;
				case 't':
					e->itf = xl_get_contact;
				break;
				default:
					e->itf = xl_get_null;
			}
		break;
		case 'C':
			p++;
			e->hparam.s = p;
			
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
				if(flags&XL_THROW_ERROR)
					goto error;
			} else {
				e->hparam.len = 2;
				e->itf = xl_get_color;
			}
		break;  
		case 'd':
			p++;
			switch(*p)
			{
				case 's':
					e->itf = xl_get_dset;
				break;
				case 'u':
					e->itf = xl_get_dsturi;
				break;
				default:
					e->itf = xl_get_null;
			}
		break;
		case 'f':
			p++;
			switch(*p)
			{
				case 'd':
					e->itf = xl_get_from_domain;
				break;
				case 't':
					e->itf = xl_get_from_tag;
				break;
				case 'u':
					e->itf = xl_get_from;
				break;
				case 'U':
					e->itf = xl_get_from_username;
				break;
				default:
					e->itf = xl_get_null;
			}
		break;
		case 'h':
		case 'H':
			if((p[1]=='d' || p[1]=='D')
					&& (p[2]=='r' || p[2]=='R') && p[3]=='(')
			{
				p+=3;
				p0 = xl_parse_name(p, e, 0, flags);
				if(p0==NULL)
					goto error;
				p = p0;
			} else {
				LOG(L_ERR, "xl_parse_item: error - bad specifier [%s]\n", p);
				goto error;
			}
		break;
		case 'm':
			p++;
			switch(*p)
			{
				case 'b':
					e->itf = xl_get_msg_buf;
				break;
				case 'f':
					e->itf = xl_get_flags;
				break;
				case 'F':
					e->itf = xl_get_hexflags;
				break;
				case 'i':
					e->itf = xl_get_msgid;
				break;
				case 'l':
					e->itf = xl_get_msg_len;
				break;
				default:
					e->itf = xl_get_null;
			}
			break;
		case 'p':
			p++;
			switch(*p)
			{
				case 'p':
					e->itf = xl_get_pid;
				break;
				default:
					e->itf = xl_get_null;
			}
		break;
		case 'r':
			p++;
			switch(*p)
			{
				case 'c':
					e->itf = xl_get_return_code;
				break;
				case 'd':
					e->itf = xl_get_ruri_domain;
				break;
				case 'm':
					e->itf = xl_get_method;
				break;
				case 'r':
					e->itf = xl_get_reason;
				break;
				case 's':
					e->itf = xl_get_status;
				break;
				case 't':
					e->itf = xl_get_refer_to;
				case 'u':
					e->itf = xl_get_ruri;
				break;
				case 'U':
					e->itf = xl_get_ruri_username;
				break;
				default:
					e->itf = xl_get_null;
			}
		break;
		case 'R':
			p++;
			switch(*p)
			{
				case 'i':
					e->itf = xl_get_rcvip;
				break;
				case 'p':
					e->itf = xl_get_rcvport;
				break;
				default:
				e->itf = xl_get_null; 			
			}
		break;
		case 's':
			p++;
			switch(*p)
			{
				case 'i':
					e->itf = xl_get_srcip;
				break;
				case 'p':
					e->itf = xl_get_srcport;
				break;
				default:
				e->itf = xl_get_null; 			
			}
		break;
		case 't':
			p++;
			switch(*p)
			{
				case 'd':
					e->itf = xl_get_to_domain;
				break;
				case 't':
					e->itf = xl_get_to_tag;
				break;
				case 'u':
					e->itf = xl_get_to;
				break;
				case 'U':
					e->itf = xl_get_to_username;
				break;
				default:
					e->itf = xl_get_null;
			}
		break;
		case 'T':
			p++;
			switch(*p)
			{
				case 'f':
					e->itf = xl_get_timef;
				break;
				case 's':
					e->itf = xl_get_times;
				break;
				default:
					e->itf = xl_get_null;
			}
		break;
		case 'u':
			p++;
			switch(*p)
			{
				case 'a':
					e->itf = xl_get_useragent;
				break;
				default:
					e->itf = xl_get_null;
			}
		break;
		case '{':
		break;
		default:
			e->itf = xl_get_null;
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

int xl_get_spec_value(struct sip_msg* msg, xl_spec_p sp, str *value)
{
	if(msg==NULL || sp==NULL || sp->itf==NULL || value==NULL)
		return -1;

	return (*sp->itf)(msg, value, &(sp->hparam), sp->hindex);
}

int xl_print_spec(struct sip_msg* msg, xl_spec_p sp, char *buf, int *len)
{
	str tok;
	if(msg==NULL || sp==NULL || buf==NULL || len==NULL)
		return -1;

	if(*len <= 0)
		return -1;
	
	memset(&tok, 0, sizeof(str));
	
	/* put the value of the specifier */
	if(sp->itf 
			&& !((*sp->itf)(msg, &tok, &(sp->hparam), sp->hindex)))
	{
		if(tok.len < *len)
			memcpy(buf, tok.s, tok.len);
		else
			goto overflow;
	}
	
	*len = tok.len;
	buf[tok.len] = '\0';
	return 0;
	
overflow:
	LOG(L_ERR,
		"xl_printf: buffer overflow -- increase the buffer size...\n");
	return -1;
}


int xl_printf(struct sip_msg* msg, xl_elem_p list, char *buf, int *len)
{
	int n, h;
	str tok;
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
			}
			else
				goto overflow;
		}
		/* put the value of the specifier */
		if(it->spec.itf 
				&& !((*it->spec.itf)(msg, &tok, &(it->spec.hparam),
						it->spec.hindex)))
		{
			if(n+tok.len < *len)
			{
				memcpy(cur, tok.s, tok.len);
				n += tok.len;
				cur += tok.len;
				
				/* check for color entries to reset later */
				if (*it->spec.itf == xl_get_color)
					h = 1;
			}
			else
				goto overflow;
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
			}
	}

	goto done;
	
overflow:
	LOG(L_ERR,
		"xl_printf: buffer overflow -- increase the buffer size...\n");
	return -1;

done:
	DBG("xl_printf: final buffer length %d\n", n);
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

