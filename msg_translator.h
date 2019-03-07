/*
 * Copyright (C) 2001-2003 FhG Fokus
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
 * 2003-03-06  totags in outgoing replies bookmarked to enable
 *             ACK/200 tag matching
 * 2003-10-08  receive_test function-alized (jiri)
 */

/*!
 * \file
 * \brief Create and translate SIP messages/ message contents
 * - \ref ViaSpecialParams
 */


#ifndef  _MSG_TRANSLATOR_H
#define _MSG_TRANSLATOR_H

#define MY_HF_SEP ": "
#define MY_HF_SEP_LEN 2

#define BRANCH_SEPARATOR '.'
#define WARNING "Warning: 392 "
#define WARNING_LEN (sizeof(WARNING)-1)
#define WARNING_PHRASE " \"Noisy feedback tells: "
#define WARNING_PHRASE_LEN (sizeof(WARNING_PHRASE)-1)

#define MSG_TRANS_SHM_FLAG    (1<<0)
#define MSG_TRANS_NOVIA_FLAG  (1<<1)

#define OSS_BOUNDARY "OSS-unique-boundary-42"

//#define MAX_CONTENT_LEN_BUF INT2STR_MAX_LEN /* see ut.h/int2str() */

#include "parser/msg_parser.h"
#include "ip_addr.h"
#include "socket_info.h"
#include "context.h"
#include "globals.h"

/*! \brief point to some remarkable positions in a SIP message */
struct bookmark {
	str to_tag_val;
};

/*! \brief used by via_builder() */
struct hostport {
	str* host;
	str* port;
};


#define set_hostport(hp, msg) \
	do { \
		if (!(msg)) \
			(hp)->host = NULL; \
		else { \
			if (((struct sip_msg *)(msg))->set_global_address.s) \
				(hp)->host = &(((struct sip_msg *)(msg))->set_global_address); \
			else \
				(hp)->host = &default_global_address; \
		} \
		if (!(msg)) \
			(hp)->port = NULL; \
		else { \
			if (((struct sip_msg *)(msg))->set_global_port.s) \
				(hp)->port = &(((struct sip_msg *)(msg))->set_global_port); \
			else \
				(hp)->port = &default_global_port; \
		} \
	} while (0)

static inline str *get_adv_host(struct socket_info *send_sock)
{
	if(send_sock->adv_name_str.len)
		return &(send_sock->adv_name_str);
	else if (default_global_address.s)
		return &default_global_address;
	else
		return &(send_sock->address_str);
}

static inline str *get_adv_port(struct socket_info *send_sock)
{
	if(send_sock->adv_port_str.len)
		return &(send_sock->adv_port_str);
	else if (default_global_port.s)
		return &default_global_port;
	else
		return &(send_sock->port_no_str);
}

static inline str *_get_adv_host(struct socket_info *send_sock,
                                 struct sip_msg *msg)
{
	if (send_sock->adv_name_str.len)
		return &send_sock->adv_name_str;
	else if (msg->set_global_address.s)
		return &msg->set_global_address;
	else if (default_global_address.s)
		return &default_global_address;
	else
		return &send_sock->address_str;
}

static inline str *_get_adv_port(struct socket_info *send_sock,
                                 struct sip_msg *msg)
{
	if (send_sock->adv_port_str.len)
		return &send_sock->adv_port_str;
	else if (msg->set_global_port.s)
		return &msg->set_global_port;
	else if (default_global_port.s)
		return &default_global_port;
	else
		return &send_sock->port_no_str;
}

char * build_req_buf_from_sip_req (	struct sip_msg* msg,
				unsigned int *returned_len, struct socket_info* send_sock,
				int proto, str *via_params, unsigned int flags);

char * build_res_buf_from_sip_res(	struct sip_msg* msg,
				unsigned int *returned_len, struct socket_info *sock,int flags);


char * build_res_buf_from_sip_req( unsigned int code,
				str *text,
				str *new_tag,
				struct sip_msg* msg,
				unsigned int *returned_len,
				struct bookmark *bmark);

char* via_builder( unsigned int *len,
	struct socket_info* send_sock,
	str *branch, str* extra_params, int proto, struct hostport *hp );


int branch_builder( unsigned int hash_index,
	/* only either parameter useful */
	unsigned int label, char * char_v,
	int branch,
	/* output value: string and actual length */
	char *branch_str, int *len );

char *contact_builder(struct socket_info* send_sock, int *ct_len);

/* check if IP address in Via != source IP address of signaling */
int received_test( struct sip_msg *msg );

char *construct_uri(str *protocol,str *username,str *domain,str *port,
		str *params,int *len);

void process_lumps( struct sip_msg* msg, struct lump* lumps, char* new_buf,
		unsigned int* new_buf_offs, unsigned int* orig_offs,
		struct socket_info* send_sock, int max_offset);

int is_del_via1_lump(struct sip_msg* msg);

char* received_builder(struct sip_msg *msg, unsigned int *received_len);

char* rport_builder(struct sip_msg *msg, unsigned int *rport_len);

#endif
