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
 *
 * - utility for generating to-tags
 *   in SER, to-tags consist of two parts: a fixed part
 *   which is bound to server instance and variable part
 *   which is bound to request -- that helps to recognize,
 *   who generated the to-tag in loops through the same
 *   server -- in such cases, fixed part is constant, but
 *   the variable part varies because it depends on
 *   the via header
 *
 * History:
 * --------
 *  2003-02-18  changed TOTAG_LEN into TOTAG_VALUE_LEN, to solve
 *               redefinition conflict with tm/t_msgbuilder.h (andrei)
 */

/*!
 * \file
 * \brief Tag handling functions
 */


#ifndef _TAGS_H
#define _TAGS_H

#include "parser/msg_parser.h"
#include "globals.h"
#include "crc.h"
#include "str.h"
#include "socket_info.h"

#define TOTAG_VALUE_LEN (CRC16_LEN+1+MD5_LEN)

/*! \brief
 * Generate variable part of to-tag for a request;
 * it will have length of MD5_LEN, sufficiently
 * long buffer must be passed to the function */
static inline void calc_tag_suffix( struct sip_msg *msg, char *tag_suffix)
{
	int ss_nr;
	str suffix_source[3];

	ss_nr=2;
	if (msg->via1==0) return; /* no via, bad message */
	suffix_source[0]=msg->via1->host;
	suffix_source[1]=msg->via1->port_str;
	if (msg->via1->branch)
		suffix_source[ss_nr++]=msg->via1->branch->value;
	MD5StringArray( tag_suffix, suffix_source, ss_nr );
}

inline static void init_tags( char *tag, char **suffix,
		char *signature, char separator )
{
	str src[3];
	const struct socket_info* si;

	si=get_first_socket();
	src[0].s=signature; src[0].len=strlen(signature);
	/* if we are not listening on anything we shouldn't be here */
	src[1].s=si?si->address_str.s:"";
	src[1].len=si?si->address_str.len:0;
	src[2].s=si?si->port_no_str.s:"";
	src[2].len=si?si->port_no_str.len:0;

	crcitt_string_array( tag, src, 3);

	tag[CRC16_LEN]=separator;
	*suffix=tag+CRC16_LEN+1;
}


#endif
