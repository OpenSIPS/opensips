/**
 * Copyright (C) 2009 Voice Sistem SRL
 * Copyright (C) 2016 OpenSIPS Solutions
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
 */


#ifndef _PARSE_SIPBODY
#define _PARSE_SIPBODY

#include "../mem/mem.h"

struct body_part;

typedef void (*free_parsed_part_function)(void *, osips_free_f);
typedef void* (*clone_parsed_part_function)(struct body_part*,
		struct body_part*, struct sip_msg *, struct sip_msg* , osips_malloc_f);
typedef int (*dump_part_function)(void *, struct sip_msg *, str *buf);


#define SIP_BODY_PART_FLAG_NEW      (1<<0)
#define SIP_BODY_PART_FLAG_DELETED  (1<<1)

struct body_part{

	/* MIME content type as a recognized/parsed value 
	 * This is present only for recevied parts (not for the new parts) !*/
	int mime;

	/* MIME content type as a string value
	 *  If received part, it points inside the msg buf
	 *  If new part, it holds the mime string, but in the same mem chunk
	 *    as the whole part -> no need for free on it */
	str mime_s;

	/* bitmask with multi purpose flags
	 * like new part, deleted part, etc */
	unsigned int flags;

	/* body of the current part
	 *  If received part, it points inside the msg buf
	 *  If new part, it may hold the new body part (if no dump function) ,
	 *    but in the same mem chunk as the whole part -> no need 
	 *    for free on it */
	str body;

	/* the SIP headers of the part
	 *  If received part, ot points inside the msg buf (it may be empty 
	 *     it is a single part body!)
	 *  If a new part, it may hold additional SIP header (other then
	 *     Content-Type)  but in the same mem chunk as the whole part
	 *     -> no need for free on it */
	str headers;

	/* whatever information might be received from parsing the part
	 * This may be present for received and new parts too! */
	void * parsed;
	free_parsed_part_function free_parsed_f;
	clone_parsed_part_function clone_parsed_f;

	/* function to regenerate the whole body part (no headers) */
	dump_part_function dump_f;
	/* holder for the output of the dump function */
	str dump;

	struct body_part * next;
};

#define is_body_part_received(_part) \
	(((_part)->flags&(SIP_BODY_PART_FLAG_NEW|SIP_BODY_PART_FLAG_DELETED))==0)
#define is_body_part_deleted(_part) \
	(((_part)->flags&SIP_BODY_PART_FLAG_DELETED)!=0)


#define SIP_BODY_FLAG_NEW       (1<<0)
#define SIP_BODY_FLAG_SHM       (1<<1)
#define SIP_BODY_RCV_MULTIPART  (1<<2)

struct sip_msg_body {
	/* original number of parts in the SIP body */
	unsigned char part_count;

	/* updated number of parts (after inserts/deletes of parts)
	 * in the SIP parts */
	unsigned char updated_part_count;

	/* multi purpose flags */
	unsigned char flags;

	/* entire body (as received) */
	str body;

	/* the parts separator in the SIP body */
	str boundary;

	/* list of body parts ; note: as we have all the time at least 
	 * one part, the first part is included in this structure */
	struct body_part first;
};


/*
 * If the body of the message is multipart get all the parts,
 * otherwise get a sip_msg_body cotaining one element of the initial body.
 * Should be used if someone thinks that the message could be multipart
 * and needs to be interpreted.
 *
 */

int parse_sip_body(struct sip_msg * msg);

void free_sip_body(struct sip_msg_body *);

struct body_part* add_body_part(struct sip_msg *msg, str *mime_s,
	str *hdrs, str *body);

int delete_body_part(struct sip_msg *msg, struct body_part *part);

int should_update_sip_body(struct sip_msg *msg);

int clone_sip_msg_body(struct sip_msg *src_msg, struct sip_msg *dst_msg,
	struct sip_msg_body **p_dst, int shared);

#endif

