/*
 * presence module - presence server implementation
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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
 *  2006-08-15  initial version (Anca Vamanu)
 */


#ifndef UTILS_FUNC_H
#define UTILS_FUNC_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../str.h"
#include "../../socket_info.h"
#include "../../parser/msg_parser.h"

#define BAD_EVENT_CODE 489

static inline int uandd_to_uri(str user,  str domain, str *out)
{
	int size;

	if(out==0)
		return -1;

	size = user.len + domain.len+7;

	out->s = (char*)pkg_malloc(size);
	if(out->s == NULL)
	{
		LM_ERR("no more memory\n");
		return -1;
	}
	strcpy(out->s,"sip:");
	out->len = 4;
	if( user.len != 0)
	{
		memcpy(out->s+out->len, user.s, user.len);
		out->len += user.len;
		out->s[out->len++] = '@';
	}

	memcpy(out->s + out->len, domain.s, domain.len);
	out->len += domain.len;
	out->s[out->len] = '\0';

	return 0;
}

/* Build an contact URI with port and transport parameter
 */
static inline int get_local_contact(struct socket_info *sock, str* contact)
{
	static char buf[MAX_URI_SIZE];
	char *p;

	p = buf;

	/* write "sip:ip" */
	memcpy( p, "sip:", 4);
	p += 4;

	/* if advertised address is set for this interface, use this one */
	if (sock->adv_name_str.s) {
		memcpy( p, sock->adv_name_str.s, sock->adv_name_str.len);
		p += sock->adv_name_str.len;
	}
	else {
		memcpy( p, sock->address_str.s, sock->address_str.len);
		p += sock->address_str.len;
	}
	if ( (p-buf) < 6/*:nnnnn*/)
		goto overflow;

	/* write ":port" if port defined */
	if (sock->adv_name_str.s) {
		if(sock->adv_port_str.s) {
			*(p++) = ':';
			memcpy( p, sock->adv_port_str.s, sock->adv_port_str.len);
			p += sock->adv_port_str.len;
		}
	} else
	if (sock->port_no_str.len) {
		*(p++) = ':';
		memcpy( p, sock->port_no_str.s, sock->port_no_str.len);
		p += sock->port_no_str.len;
	}

	if (sock->proto!=PROTO_UDP) {
		if ( (p-buf) < 15/*;transport=xxxx*/)
			goto overflow;
		memcpy( p, ";transport=", 11);
		p += 11;
		p = proto2str(sock->proto, p);
	}

	/* success */
	contact->s = buf;
	contact->len = (int)(p-buf);
	return 0;
overflow:
	LM_ERR("local contact gets too long, exceeding %d\n",MAX_URI_SIZE);
	return -1;
}

int a_to_i (char *s,int len);

void to64frombits(unsigned char *out, const unsigned char *in, int inlen);

int send_error_reply(struct sip_msg* msg, int reply_code, str reply_str);

#endif

