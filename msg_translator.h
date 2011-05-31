/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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


//#define MAX_CONTENT_LEN_BUF INT2STR_MAX_LEN /* see ut.h/int2str() */

#include "parser/msg_parser.h"
#include "ip_addr.h"

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
	do{ \
		if ((msg) && ((struct sip_msg*)(msg))->set_global_address.len) \
			(hp)->host=&(((struct sip_msg*)(msg))->set_global_address); \
		else \
			(hp)->host=&default_global_address; \
		if ((msg) && ((struct sip_msg*)(msg))->set_global_port.len) \
			(hp)->port=&(((struct sip_msg*)(msg))->set_global_port); \
		else \
			(hp)->port=&default_global_port; \
	}while(0)

char * build_req_buf_from_sip_req (	struct sip_msg* msg,
				unsigned int *returned_len, struct socket_info* send_sock,
				int proto, unsigned int flags);

char * build_res_buf_from_sip_res(	struct sip_msg* msg,
				unsigned int *returned_len);


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

/* check if IP address in Via != source IP address of signaling */
int received_test( struct sip_msg *msg );

char *construct_uri(str *protocol,str *username,str *domain,str *port,
		str *params,int *len);
int lumps_len(struct sip_msg* msg, struct lump* lumps,
		struct socket_info* send_sock);
void process_lumps(	struct sip_msg* msg, struct lump* lumps, char* new_buf,
		unsigned int* new_buf_offs, unsigned int* orig_offs, struct socket_info* send_sock);
#endif
