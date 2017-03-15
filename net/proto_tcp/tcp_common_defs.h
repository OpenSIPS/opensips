/*
 * Copyright (C) 2015 - OpenSIPS Foundation
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
 *
 * History:
 * -------
 *  2015-02-16  split from proto_tcp.c (razvanc)
 */

#ifndef _NET_tcp_common_defs_h
#define _NET_tcp_common_defs_h

/*!< the max number of chunks that a child accepts until the message
 * is read completely - anything above will lead to the connection being
 * closed - considered an attack */
#define TCP_CHILD_MAX_MSG_CHUNK  4

#define TCP_BUF_SIZE 65535			/*!< TCP buffer size */


enum tcp_req_errors {	TCP_REQ_INIT, TCP_REQ_OK, TCP_READ_ERROR,
		TCP_REQ_OVERRUN, TCP_REQ_BAD_LEN };
enum tcp_req_states {	H_SKIP_EMPTY, H_SKIP, H_LF, H_LFCR,  H_BODY, H_STARTWS,
		H_CONT_LEN1, H_CONT_LEN2, H_CONT_LEN3, H_CONT_LEN4, H_CONT_LEN5,
		H_CONT_LEN6, H_CONT_LEN7, H_CONT_LEN8, H_CONT_LEN9, H_CONT_LEN10,
		H_CONT_LEN11, H_CONT_LEN12, H_CONT_LEN13, H_L_COLON,
		H_CONT_LEN_BODY, H_CONT_LEN_BODY_PARSE , H_PING_CRLFCRLF,
		H_SKIP_EMPTY_CR_FOUND, H_SKIP_EMPTY_CRLF_FOUND,
		H_SKIP_EMPTY_CRLFCR_FOUND
	};


struct tcp_req{
	/* sockaddr ? */
	char buf[TCP_BUF_SIZE+1];		/*!< bytes read so far (+0-terminator)*/
	char* start;					/*!< where the message starts, after all the empty lines are skipped*/
	char* pos;						/*!< current position in buf */
	char* parsed;					/*!< last parsed position */
	char* body;						/*!< body position */
	unsigned int   content_len;
	unsigned short has_content_len;	/*!< 1 if content_length was parsed ok*/
	unsigned short complete;		/*!< 1 if one req has been fully read, 0 otherwise*/
	unsigned int   bytes_to_go;		/*!< how many bytes we have still to read from the body*/
	enum tcp_req_errors error;
	enum tcp_req_states state;
};

#define init_tcp_req( r, _size) \
	do{ \
		(r)->parsed=(r)->start=(r)->buf; \
		(r)->pos=(r)->buf + (_size); \
		(r)->error=TCP_REQ_OK;\
		(r)->state=H_SKIP_EMPTY; \
		(r)->body=0; \
		(r)->complete=(r)->content_len=(r)->has_content_len=0; \
		(r)->bytes_to_go=0; \
	}while(0)

#endif


