/**
 * Copyright (C) 2009 Voice Sistem SRL
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


#ifndef _PARSE_MULITPART
#define _PARSE_MULITPART
struct part{

    /* MIME content type */
    int content_type;

    /* body of the current part */
    str body;

    /* the whole part ( body + headers) */
    str all_data;

    /* whatever information might be received from parsing the part */
    void * parsed_data;

    struct part * next;
};

struct multi_body {
    int from_multi_part;
    str boundary;

    int part_count;
    struct part * first;
};


/*
 * If the body of the message is multipart get all the parts,
 * otherwise get a multi_body cotaining one element of the initial body.
 * Should be used if someone thinks that the message could be multipart
 * and needs to be interpreted.
 *
 */

struct multi_body * get_all_bodies(struct sip_msg * msg);

void free_multi_body(struct multi_body *);

#endif

