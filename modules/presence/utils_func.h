/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
#include "../../parser/msg_parser.h"

#define LCONTACT_BUF_SIZE 1024
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

static inline int get_local_contact(struct sip_msg* msg, str* contact)
{
	str ip;
	char* proto =0;
	int len;
	static char buf[LCONTACT_BUF_SIZE];

	contact->s = buf;
	contact->len= 0;
	memset(buf, 0, LCONTACT_BUF_SIZE);

	switch (msg->rcv.proto)
	{
		case PROTO_NONE:
		case PROTO_UDP:
			proto= 0; break;
		case PROTO_TCP:
			proto= "tcp"; break;
		case PROTO_TLS:
			proto= "tls"; break;
		default:
			LM_ERR("wrong proto\n");
			return -1;
	}

	ip = msg->rcv.bind_address->address_str;
	if(strncasecmp(ip.s, "sip:", 4)!=0)
	{
		strncpy(contact->s, "sip:", 4);
		contact->len+= 4;
	}
	strncpy(contact->s+contact->len, ip.s, ip.len);
	contact->len += ip.len;
	if(contact->len> LCONTACT_BUF_SIZE - 21)
	{
		LM_ERR("buffer overflow\n");
		return -1;
	}

	len= sprintf(contact->s+contact->len, ":%d", msg->rcv.dst_port);
	if(len< 0)
	{
		LM_ERR("unsuccessful sprintf\n");
		return -1;
	}
	contact->len+= len;
	if(proto)
	{
		sprintf(contact->s+ contact->len, ";transport=%s", proto);
		contact->len += 14;
	}

	return 0;
}

//str* int_to_str(long int n);

int a_to_i (char *s,int len);

void to64frombits(unsigned char *out, const unsigned char *in, int inlen);

int send_error_reply(struct sip_msg* msg, int reply_code, str reply_str);

#endif

