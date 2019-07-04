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
#include "../../socket_info.h"
#include "../../str.h"
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


/* Like memcpy, but return pointer to the end of copied buffer */
#define memcopy(dest, source, size) (memcpy(dest, source, size) + (size))


/* Build a contact URI using the provided username and the socket's ip:port:protocol */
static inline int get_local_contact(struct socket_info *sock, str *username, str *contact)
{
	static char buf[MAX_URI_SIZE];
	char *ptr = buf;
	str no_username = {0, 0}, ip, port;
	int length, port_no;

	if (!username)
		username = &no_username;

	ip      = (sock->adv_name_str.len > 0) ? sock->adv_name_str : sock->address_str;  // use advertised address if set
	port    = (sock->adv_port_str.len > 0) ? sock->adv_port_str : sock->port_no_str;  // use advertised port if set
	port_no = (sock->adv_port_str.len > 0) ? sock->adv_port     : sock->port_no;      // use advertised port if set

	length = username->len + ip.len + port.len + 21;  // +21 = +4 for 'sip:', +15 for ';transport=xxxx' and +2 for separators ('@', ':')

	if (length > MAX_URI_SIZE) {
		LM_ERR("local contact too long, exceeding %d bytes\n", MAX_URI_SIZE);
		return -1;
	}

	ptr = memcopy(ptr, "sip:", 4);

	if (username->len > 0) {
		ptr = memcopy(ptr, username->s, username->len);
		*ptr++ = '@';
	}

	ptr = memcopy(ptr, ip.s, ip.len);

	if (port.len > 0 && port_no != protos[sock->proto].default_port) {
		*ptr++ = ':';
		ptr = memcopy(ptr, port.s, port.len);
	}

	if (sock->proto != PROTO_UDP) {
		ptr = memcopy(ptr, ";transport=", 11);
		ptr = proto2str(sock->proto, ptr);
	}

	contact->s = buf;
	contact->len = (int)(ptr - buf);

	return 0;
}

int a_to_i (char *s,int len);

void to64frombits(unsigned char *out, const unsigned char *in, int inlen);

int send_error_reply(struct sip_msg* msg, int reply_code, str reply_str);

#endif

