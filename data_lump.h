/*
 * adding/removing headers or any other data chunk from a message
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2003-01-29  s/int/enum ... more convenient for gdb (jiri)
 *  2003-03-31  added subst lumps -- they expand in ip addr, port a.s.o (andrei)
 *  2003-04-01  added opt (condition) lumps (andrei)
 *  2003-04-02  added more subst lumps: SUBST_{SND,RCV}_ALL
 *              => ip:port;transport=proto (andrei)
 *
 */

/*!
 * \file data_lump.h
 * \brief adding/removing headers or any other data chunk from a message
 */


#ifndef data_lump_h
#define data_lump_h

#include "lump_struct.h"
#include "parser/msg_parser.h"
#include "parser/hf.h"

extern int init_lump_flags;


#define set_init_lump_flags(_flags) \
	do{\
		init_lump_flags = _flags;\
	}while(0)

#define reset_init_lump_flags() \
	do{\
		init_lump_flags = 0;\
	}while(0)


/*! \brief adds a header to the end
 * WARNING: currently broken! 
 *   - lumps_len() needs to properly handle LUMP_ADD along the main chain of
 *     lumps before we can use this
 */
struct lump* append_new_lump(struct lump** list, char* new_hdr,
		unsigned int len, enum _hdr_types_t type);

/*! \brief inserts a header to the beginning
 * WARNING: currently broken! 
 *   - lumps_len() needs to properly handle LUMP_ADD along the main chain of
 *     lumps before we can use this
 */
struct lump* insert_new_lump(struct lump** list, char* new_hdr,
		unsigned int len, enum _hdr_types_t type);
/*! \brief inserts a header to the beginning - after */
struct lump* insert_new_lump_after(struct lump* after,
		char* new_hdr, unsigned int len, enum _hdr_types_t type);
/*! \brief inserts a header to the beginning - before */
struct lump* insert_new_lump_before(struct lump* before, char* new_hdr,
		unsigned int len,enum _hdr_types_t type);

/*! \brief substitutions (replace with ip address, port etc) - after */
struct lump* insert_subst_lump_after(struct lump* after, enum lump_subst subst,
		enum _hdr_types_t type);
/*! \brief substitutions (replace with ip address, port etc)  - before */
struct lump* insert_subst_lump_before(struct lump* before,
		enum lump_subst subst, enum _hdr_types_t type);

/*! \brief conditional lumps - insert*/
struct lump* insert_cond_lump_after(struct lump* after, enum lump_conditions c,
		enum _hdr_types_t type);
/*! \brief conditional lumps - before */
struct lump* insert_cond_lump_before(struct lump* after,enum lump_conditions c,
		enum _hdr_types_t type);

/*! \brief skip lumps - after*/
struct lump* insert_skip_lump_after( struct lump* after);
/*! \brief skip lumps - before*/
struct lump* insert_skip_lump_before( struct lump* before);

/*! \brief removes an already existing header */
struct lump* del_lump(struct sip_msg* msg, unsigned int offset,
	unsigned int len, enum _hdr_types_t type);
/*! \brief set an anchor */
struct lump* anchor_lump(struct sip_msg* msg, unsigned int offset,
	enum _hdr_types_t type);


/*! \brief duplicates a lump list in pkg-mem */
struct lump* dup_lump_list( struct lump *l );


/*! \brief remove all flagged lumps from the list */
void del_flaged_lumps( struct lump** lump_list, enum lump_flag flags );
/*! \brief remove all unflagged lumps from the list */
void del_notflaged_lumps( struct lump** lump_list, enum lump_flag not_flags);

#endif
