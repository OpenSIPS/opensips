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


/* here we have MSRP "parsing"-specific functions
 */

#include <ctype.h>

#include "../../ut.h"
#include "msrp_parser.h"

#define _READ4(_p) \
	((*((unsigned char *)(_p) + 0) + \
	 (*((unsigned char *)(_p) + 1) << 8) + \
	 (*((unsigned char *)(_p) + 2) << 16) + \
	 (*((unsigned char *)(_p) + 3) << 24)) | 0x20202020)

#define MSRP_DEBUG


static int _parse_msrp_method( str *method_s, int *method_id)
{
	if (method_s==NULL || method_id==NULL || method_s->s==NULL)
		return -1;

	if (method_s->len<4) {
		/* too short to be a know method */
		goto other;
	}

	switch ( _READ4(method_s->s) ) {
	case 0x64636573 :  /*SEND*/
		if (method_s->len==4) {
			*method_id = MSRP_METHOD_SEND;
			return 0;
		}
		break;
	case 0x68747561 :  /*AUTH*/
		if (method_s->len==4) {
			*method_id = MSRP_METHOD_AUTH;
			return 0;
		}
		break;
	case 0x6f706572 :  /*REPO*/
		if (method_s->len==6 && method_s->s[4]=='R' && method_s->s[5]=='T') {
			*method_id = MSRP_METHOD_REPORT;
			return 0;
		}
		break;
	}

other:
	*method_id = MSRP_METHOD_OTHER;
	return 0;
}


int parse_msrp_msg( char* buf, int len, struct msrp_msg *msg)
{
	struct hdr_field *hf = NULL;
	char *p, *end;
	str mth;

#define link_hdr(_hook, _hdr) \
	do{ \
		if (msg->_hook) { \
			LM_ERR("duplicated hdr _hdr found\n"); \
			goto error; \
		} \
		msg->_hook=_hdr;\
	}while(0)

	/* complete the parsing of the first line */

	if (msg->fl.u.request.method.len >= 3 + 1 + 1 &&
	isdigit(msg->fl.u.request.method.s[0]) &&
	isdigit(msg->fl.u.request.method.s[1]) &&
	isdigit(msg->fl.u.request.method.s[2]) &&
	msg->fl.u.request.method.s[3]==' ') {
		/* it looks like a reply */
		msg->fl.type = MSRP_REPLY;
		mth =  msg->fl.u.request.method;
		msg->fl.u.reply.status.s = mth.s;
		msg->fl.u.reply.status.len = 3;
		msg->fl.u.reply.reason.s = mth.s + 4;
		msg->fl.u.reply.reason.len = mth.len - 4;
		/* this converstion is risk free as the we already tested
		 * for a valid number above */
		str2int( &msg->fl.u.reply.status,
			(unsigned int*)&msg->fl.u.reply.status_no );
	} else {
		/* let's hope it is a request, check for spaces at least */
		if (q_memchr( msg->fl.u.request.method.s, ' ',
		msg->fl.u.request.method.len)!=NULL) {
			/* ups, spaces in the method name */
			goto error;
		}
		msg->fl.type = MSRP_REQUEST;
		_parse_msrp_method( & msg->fl.u.request.method,
			& msg->fl.u.request.method_id);
	}

	/* parse the headers */
	p = msg->fl.eol+1;
	end = msg->body.s ?
		msg->body.s /* the headers end where the body start (we do not chare
					 * of extra CRLF between the hdr and body */
		:
		(buf+len-7-msg->fl.ident.len-1-CRLF_LEN); /* the headers end right
					 * before the EOM, so we go go backward
					 * EOM = "-------" transact-id continuation-flag CRLF*/

	while( p<end ){

		hf = pkg_malloc(sizeof(struct hdr_field));
		if ( hf==NULL ) {
			LM_ERR("pkg memory allocation failed\n");
			goto error;
		}
		memset( hf, 0, sizeof(struct hdr_field));
		hf->type=HDR_ERROR_T;
		p = get_hdr_field( p, end, hf);

		switch (hf->type){
			case HDR_ERROR_T:
				LM_INFO("bad header field\n");
				goto  err_free_hf;
			case HDR_EOH_T:
				pkg_free(hf);
				hf = NULL;
				/* done, EOH */
				goto done;
			case HDR_TO_PATH_T:
				link_hdr( to_path, hf);
				break;
			case HDR_FROM_PATH_T:
				link_hdr( from_path, hf);
				break;
			case HDR_MESSAGE_ID_T:
				link_hdr( message_id, hf);
				break;
			case HDR_BYTE_RANGE_T:
				link_hdr( byte_range, hf);
				break;
			case HDR_FAILURE_REPORT_T:
				link_hdr( failure_report, hf);
				break;
			case HDR_SUCCESS_REPORT_T:
				link_hdr( success_report, hf);
				break;
			case HDR_STATUS_T:
				link_hdr( status, hf);
				break;
			case HDR_USE_PATH_T:
				link_hdr( use_path, hf);
				break;
			case HDR_CONTENTTYPE_T:
				link_hdr( content_type, hf);
				break;
			case HDR_AUTHORIZATION_T:
				link_hdr( authorization, hf);
				break;
			case HDR_OTHER_T:
			default:
				LM_CRIT("unsupported MSRP header type [%.*s]\n",
					hf->name.len, hf->name.s);
				goto err_free_hf;
		}

		/* add the header to the list*/
		if (msg->last_header==0){
			msg->headers=hf;
			msg->last_header=hf;
		}else{
			msg->last_header->next=hf;
			msg->last_header=hf;
		}

	}

done:
	/* some validation on the hdr presence */
	if (msg->from_path==NULL) {
		LM_ERR("MSRP msg has no from-path hdr\n");
		goto error;
	}
	if (msg->to_path==NULL) {
		LM_ERR("MSRP msg has no to-path hdr\n");
		goto error;
	}
	/* TO and FROM (in this order) must be the first ones */
	if (msg->headers->type!=HDR_TO_PATH_T &&
	msg->headers->next->type!=HDR_FROM_PATH_T) {
		LM_ERR("TO and FROM are not the first headers\n");
		goto error;
	}
	if (msg->fl.type == MSRP_REQUEST) {
		if (msg->body.s && msg->content_type==NULL) {
			LM_ERR("MSRP req has no content-type hdr\n");
			goto error;
		}
		if (msg->fl.u.request.method_id != MSRP_METHOD_AUTH &&
			msg->message_id==NULL) {
			LM_ERR("MSRP req has no message-id hdr\n");
			goto error;
		}
	} else {
	}

	return 0;
err_free_hf:
	if (hf) pkg_free(hf);
error:
	return -1;
}


/*
 * Parse a the first MSRP URL from the string
 * Format is "msrp[s]://hostname[:port]/session[?parameters]"
 * Returns:
 *   NULL - if the URL is invalid
 *   pointer where the parsing stopped after the first URL
 * FIXME - support char escaping as %nn format
 */
char* parse_msrp_url(char *start, char *end, struct msrp_url* url)
{
	enum state {
		MURL_SCHEME,      /* Scheme part */
		MURL_SLASH1,      /* First slash */
		MURL_SLASH2,      /* Second slash */
		MURL_HOST,        /* Hostname part */
		MURL_HOST6,       /* Hostname part IPv6 */
		MURL_PORT,        /* Port part */
		MURL_SESSION,     /* Session part */
		MURL_PARAMS       /* Parameters part */
	};
	enum state st;
	unsigned int ipv6_flag = 0;
	char *p;

	if (!start || !url || !end) {
		return NULL;
	}

	memset( url, 0, sizeof(struct msrp_url));

	st = MURL_SCHEME;
	p = start;

	while( p<end ) {
		switch(st) {

		case MURL_SCHEME:
			if ( end-p<4+3/* msrp:// */ )
				goto error;
			if ( _READ4(p)!=0x7072736d /*msrp*/)
				goto error;
			url->whole.s = p;
			p += 4;
			switch(*p) {
			case ':':
				url->secured = 0;
				st = MURL_SLASH1;
				break;
			case 's':
			case 'S':
				if ( *(++p)!=':')
					goto error;
				url->secured = 1;
				st = MURL_SLASH1;
				break;
			}
			break;

		case MURL_SLASH1:
			switch(*p) {
			case '/':
				st = MURL_SLASH2;
				break;
			default:
				goto error;
			}
			break;

		case MURL_SLASH2:
			switch(*p) {
			case '/':
				st = MURL_HOST;
				url->host.s = p+1;
				break;
			default:
				goto error;
			}
			break;

		case MURL_HOST:
			switch(*p) {
			case ':':
				url->host.len = p-url->host.s-ipv6_flag;
				url->port.s = p+1;
				st = MURL_PORT;
				break;
			case '[':
				/* accepted only on the first position */
				if (url->host.s!=p)
					goto error;
				st = MURL_HOST6;
				url->host.s++;
				break;
			case '/':
				url->host.len = p-url->host.s-ipv6_flag;
				url->session.s = p+1;
				st = MURL_SESSION;
				break;
			case ' ':
				url->host.len = p-url->host.s-ipv6_flag;
				goto hdr_end;
			}
			break;

		case MURL_PORT:
			switch(*p) {
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				break;
			case '/':
				url->port.len = p-url->port.s;
				url->session.s = p+1;
				st = MURL_SESSION;
				break;
			case ' ':
				url->port.len = p-url->port.s;
				goto hdr_end;
			default:
				goto error;
			}
			break;

		case MURL_HOST6:
			switch(*p) {
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
			case 'a':
			case 'b':
			case 'c':
			case 'd':
			case 'e':
			case 'f':
			case ':':
				break;
			case ']':
				ipv6_flag = 1;
				st = MURL_HOST;
				break;
			default:
				goto error;
			}
			break;

		case MURL_SESSION:
			switch(*p) {
			case ';':
				url->session.len = p-url->session.s;
				url->params.s = p+1;
				st = MURL_PARAMS;
				break;
			case ' ':
				url->session.len = p-url->session.s;
				goto hdr_end;
			}
			break;

		case MURL_PARAMS:
			switch(*p) {
			case ' ':
				goto hdr_end;
			}
			break;
		}
		p++;
	}

hdr_end:
	switch (st) {

	case MURL_HOST:
		url->host.len = p-url->host.s-ipv6_flag;
		break;

	case MURL_PORT:
		url->port.len = p-url->port.s;
		break;
	
	case MURL_SESSION:
		url->session.len = p-url->session.s;
		break;

	case MURL_PARAMS:
		url->params.len = p-url->params.s;
		break;

	default:
		LM_ERR("URL ending in bad %d state\n",st);
		goto error;
	}
	url->whole.len = p - url->whole.s;

	if (url->port.s && str2int( &url->port, (unsigned int*)&url->port_no)!=0){
		LM_ERR("bad port number [%.*s]\n",url->port.len, url->port.s);
		goto error;
	}

#ifdef MSRP_DEBUG
	LM_DBG("URL [%.*s] schema %s\n", url->whole.len, url->whole.s,
		url->secured?"MSRPS":"MSRP");
	LM_DBG("\tHost [%.*s]\n",url->host.len, url->host.s);
	if (url->port.len)
		LM_DBG("\tPort [%.*s] %d\n",url->port.len, url->port.s, url->port_no);
	if (url->session.len)
		LM_DBG("\tSession [%.*s]\n",url->session.len, url->session.s);
	if (url->params.len)
		LM_DBG("\tParams [%.*s]\n",url->params.len, url->params.s);
#endif

	return p;

error:
	LM_ERR("URL parsing failed in %d, pos %d, in [%.*s]\n",
		st,(int)(p-start), (int)(end-start), start);
	return NULL;
}


void free_msrp_path(struct msrp_url *list)
{
	struct msrp_url *url;

	while(list) {
		url = list;
		list = list->next;
		pkg_free(url);
	}
}


/* parses a path of multiple MSRL URLs
 * Returns an pkg allocated list of URLs or NULL on error
 */
struct msrp_url* parse_msrp_path(str *path)
{
	struct msrp_url *url, *it, *list=NULL;
	char *p, *end;

	if (path==NULL || path->s==NULL || path->len==0)
		return NULL;

	p = path->s;
	end = path->s + path->len;

	do {

		url = pkg_malloc( sizeof(struct msrp_url) );
		if (url==NULL) {
			LM_ERR("failed to pkg allocate a new url struct\n");
			goto error;
		}

		p = parse_msrp_url( p, end, url);
		if (p==NULL) {
			LM_ERR("failed parsing URL inside path\n");
			goto error;
		}

		/* add it to the list, at the end */
		if (list==NULL) {
			list = url;
		} else {
			for( it=list ; it->next ; it=it->next);
			it->next = url;
		}

		/* if still something here, it needs to be a space separtor
		 * between URLs. Still we may accept multiple spaces ;) */
		if (p<end)
			while( *p==' ' ) p++;

	} while(p<end);

	return list;

error:
	if (url)
		pkg_free(url);
	free_msrp_path(list);
	return NULL;
}


void free_msrp_msg( struct msrp_msg *msg)
{
	if (msg->headers)
		free_hdr_field_lst(msg->headers);

	if (msg->to_path && msg->to_path->parsed)
		free_msrp_path( (struct msrp_url *)msg->to_path->parsed );

	if (msg->from_path && msg->from_path->parsed)
		free_msrp_path( (struct msrp_url *)msg->from_path->parsed );
}
