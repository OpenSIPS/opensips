/*
 * Janus Module
 *
 * Copyright (C) 2024 OpenSIPS Project
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * --------
 * 2024-12-03 initial release (vlad)
 */

#include <ctype.h>

#include "../../ut.h"
#include "janus_parser.h"

char * parse_janus_url(char *start,char *end,struct janus_url *url)
{
	enum state {
		JURL_SCHEME,      /* Scheme part */
		JURL_SLASH1,      /* First slash */
		JURL_SLASH2,      /* Second slash */
		JURL_HOST,        /* Hostname part */
		JURL_HOST6,       /* Hostname part IPv6 */
		JURL_PORT,        /* Port part */
		JURL_RESOURCE,    /* Resource part */
	};
	enum state st;
	unsigned int ipv6_flag = 0;
	char *p;

	if (!start || !url || !end) {
		return NULL;
	}

	memset( url, 0, sizeof(struct janus_url));

	st = JURL_SCHEME;
	p = start;

	while( p<end ) {
		switch(st) {

		case JURL_SCHEME:
			if ( end-p<10 /* janusws:// */ )
				goto error;
			url->whole.s = p;
			if (memcmp(p,"janusws",7) == 0) {
				url->proto = PROTO_JANUSWS;
				p+=7;
			} else if (memcmp(p,"januswss",7) == 0) {
				url->proto = PROTO_JANUSWSS;
				p+=8;
			}
			LM_DBG("At %c \n",*p);
			st = JURL_SLASH1;
			break;

		case JURL_SLASH1:
			switch(*p) {
			case '/':
				st = JURL_SLASH2;
				break;
			default:
				goto error;
			}
			break;

		case JURL_SLASH2:
			switch(*p) {
			case '/':
				st = JURL_HOST;
				url->host.s = p+1;
				break;
			default:
				goto error;
			}
			break;

		case JURL_HOST:
			switch(*p) {
			case ':':
				url->host.len = p-url->host.s-ipv6_flag;
				url->port.s = p+1;
				st = JURL_PORT;
				break;
			case '[':
				/* accepted only on the first position */
				if (url->host.s!=p)
					goto error;
				st = JURL_HOST6;
				url->host.s++;
				break;
			case '/':
				url->host.len = p-url->host.s-ipv6_flag;
				/* resource should include / */
				url->resource.s = p;
				st = JURL_RESOURCE;
				break;
			case ' ':
				url->host.len = p-url->host.s-ipv6_flag;
				goto hdr_end;
			}
			break;

		case JURL_PORT:
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
				/* resource should include / */
				url->resource.s = p;
				st = JURL_RESOURCE;
				break;
			case ' ':
				url->port.len = p-url->port.s;
				goto hdr_end;
			default:
				goto error;
			}
			break;

		case JURL_HOST6:
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
				st = JURL_HOST;
				break;
			default:
				goto error;
			}
			break;

		case JURL_RESOURCE:
			switch(*p) {
			case ' ':
				url->resource.len = p-url->resource.s;
				goto hdr_end;
			}
			break;
		}
		p++;
	}

hdr_end:
	switch (st) {

	case JURL_HOST:
		url->host.len = p-url->host.s-ipv6_flag;
		break;

	case JURL_PORT:
		url->port.len = p-url->port.s;
		break;

	case JURL_RESOURCE:
		url->resource.len = p-url->resource.s;
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

	LM_DBG("URL [%.*s] proto %d\n", url->whole.len, url->whole.s,
		url->proto);
	LM_DBG("\tHost [%.*s]\n",url->host.len, url->host.s);
	if (url->port.len)
		LM_DBG("\tPort [%.*s] %d\n",url->port.len, url->port.s, url->port_no);
	if (url->resource.len)
		LM_DBG("\tResource [%.*s]\n",url->resource.len, url->resource.s);

	return p;

error:
	LM_ERR("URL parsing failed in %d, pos %d, in [%.*s]\n",
		st,(int)(p-start), (int)(end-start), start);
	return NULL;
}
