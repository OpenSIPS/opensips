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

typedef void (*free_parsed_part_function)(void *);
typedef unsigned int (*dump_part_function)(void *, struct sip_msg *,
		char *buf);

struct body_part{

	/* MIME content type */
	int mime;

	/* multi purpose flags */
	unsigned int flags;

	/* body of the current part */
	str body;

	/* the whole part ( body + headers) */
	str all_data;

	/* whatever information might be received from parsing the part */
	void * parsed;
	free_parsed_part_function free_parsed_f;

	/* function to regenerate the whole body part (no headers) */
	dump_part_function dump_f;

	struct body_part * next;
};


struct sip_msg_body {
	/* original number of parts in the SIP body */
	unsigned char part_count;

	/* updated number of parts (after inserts/deletes of parts)
	 * in the SIP parts */
	unsigned char updated_part_count;

	/* multi purpose flags */
	unsigned char flags;

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

struct sip_msg_body *parse_sip_body(struct sip_msg * msg);

void free_sip_body(struct sip_msg_body *);

#endif

