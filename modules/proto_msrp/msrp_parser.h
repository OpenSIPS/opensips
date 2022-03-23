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


/* here we have "network layer"-specific functions that are
 * shared both by msrp "plain" and "tls"
 */

#ifndef _PROTO_MSRP_MSRP_PARSER_H_
#define _PROTO_MSRP_MSRP_PARSER_H_

#include "../../str.h"
#include "../../ip_addr.h"
#include "../../parser/hf.h"
#include "../../ut.h"

enum msrp_msg_type { MSRP_UNKNOWN=0, MSRP_REQUEST=1, MSRP_REPLY=2};

enum msrp_method {
	MSRP_METHOD_UNDEF=0,
	MSRP_METHOD_SEND,
	MSRP_METHOD_REPORT,
	MSRP_METHOD_AUTH,
	MSRP_METHOD_OTHER
};


struct msrp_firstline {
	enum msrp_msg_type type;
	str ident;
	union {
		struct {
			str method;
			int method_id;
		} request;
		struct {
			str status;
			str reason;
			unsigned short status_no;
		} reply;
	}u;
	/* pointer to the last char of this line (including the CFLF) */
	char *eol;
};

struct msrp_msg {
	struct msrp_firstline fl;

	struct hdr_field* headers;     /* All the parsed headers*/
	struct hdr_field* last_header; /* Pointer to the last header*/

	struct hdr_field* to_path;
	struct hdr_field* from_path;
	struct hdr_field* message_id;
	struct hdr_field* byte_range;
	struct hdr_field* failure_report;
	struct hdr_field* success_report;
	struct hdr_field* status;
	struct hdr_field* use_path;
	struct hdr_field* content_type;
	struct hdr_field* authorization;

	str body;

	struct receive_info rcv; /* source & dest ip, ports, proto a.s.o */

	char* buf;        /* unmodified, original (as received) buffer */
	unsigned int len; /* message len (orig) */
};


struct msrp_url {
	str whole;
	unsigned short secured;
	unsigned short port_no;
	str host;
	str port;
	str session;
	str params;
	struct msrp_url *next;
};


int parse_msrp_msg( char* buf, int len, struct msrp_msg *msg);

void free_msrp_msg( struct msrp_msg *msg);


#define _READ4(_p) \
	((*((unsigned char *)(_p) + 0) + \
	 (*((unsigned char *)(_p) + 1) << 8) + \
	 (*((unsigned char *)(_p) + 2) << 16) + \
	 (*((unsigned char *)(_p) + 3) << 24)) | 0x20202020)

/*
 * Parse a the first MSRP URL from the string
 * Format is "msrp[s]://hostname[:port]/session[?parameters]"
 * Returns:
 *   NULL - if the URL is invalid
 *   pointer where the parsing stopped after the first URL
 * FIXME - support char escaping as %nn format
 */
static inline char* parse_msrp_url(char *start, char *end, struct msrp_url* url)
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


static inline void free_msrp_path(struct msrp_url *list)
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
static inline struct msrp_url* parse_msrp_path(str *path)
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

#endif
