/*
 * $Id$
 *
 * adding/removing headers or any other data chunk from a message
 *
 * Copyright (C) 2001-2003 Fhg Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/* History:
 * --------
 *  2003-01-29  s/int/enum ... more convenient for gdb (jiri)
 *  2003-03-31  added subst lumps -- they expand in ip addr, port a.s.o (andrei)
 *  2003-04-01  added opt (condition) lumps (andrei)
 *  2003-04-02  added more subst lumps: SUBST_{SND,RCV}_ALL  
 *              => ip:port;transport=proto (andrei)
 *  2003-10-20  splitted from data_lump.h (andrei)
 *
 */


#ifndef lump_struct_h
#define lump_struct_h



enum lump_op { LUMP_NOP=0, LUMP_DEL, LUMP_ADD, LUMP_ADD_SUBST, LUMP_ADD_OPT };
enum lump_subst{ SUBST_NOP=0,                     /* do nothing */
				 SUBST_RCV_IP,    SUBST_SND_IP,   /* add ip address */
				 SUBST_RCV_PORT,  SUBST_SND_PORT, /* add port no */
				 SUBST_RCV_PROTO, SUBST_SND_PROTO,/* add protocol(udp,tcp,tls)*/
				 SUBST_RCV_ALL,   SUBST_SND_ALL   /*  ip:port;transport=proto */
				};
				/* Where:
				   SND = sending, e.g the src ip of the outgoing message
				   RCV = received e.g the dst ip of the original incoming msg,
				    or the ip of the ser socket on which the msg was received
				   For SUBST_{RCV,SND}_ALL, :port is added only if port!=5060
				    and transport=proto only if proto!=udp
					*/

enum lump_conditions {	COND_FALSE,         /* always false */
						COND_TRUE,          /* always true */
						COND_IF_DIFF_REALMS,/* true if RCV realm != SND realm */
						COND_IF_DIFF_AF,    /* true if RCV af != SND af */
						COND_IF_DIFF_PROTO, /* true if RCV proto != SND proto */
						COND_IF_DIFF_PORT,  /* true if RCV port != SND port */
						COND_IF_DIFF_IP,    /* true if RCV ip != SND ip */
						COND_IF_RAND        /* 50-50 random prob.of being true*/
						};
						/* Where: 
						   REALM= ip_addr:port:proto
						   af   = address family (ipv4 or ipv6)
						   proto = protocol (tcp, udp, tls)
						*/

enum lump_flag { LUMPFLAG_NONE=0, LUMPFLAG_DUPED=1, LUMPFLAG_SHMEM=2 };


struct lump{
	int type; /* VIA, OTHER, UNSPEC(=0), ... */
	enum lump_op op;   /* DEL, ADD, NOP, UNSPEC(=0) */
	
	union{
		int offset; /* used for DEL, MODIFY */
		enum lump_subst subst; /*what to subst: ip addr, port, proto*/
		enum lump_conditions cond; /* condition for LUMP_ADD_OPT */
		char * value; /* used for ADD */
	}u;
	int len; /* length of this header field */
	
	
	struct lump* before; /* list of headers to be inserted in front of the
								current one */
	struct lump* after; /* list of headers to be inserted immediately after
							  the current one */
	
	struct lump* next;

	enum lump_flag flags; /* additional hints for use from TM's shmem */
};


/*
 * hdrs must be kept sorted after their offset (DEL, NOP, UNSPEC)
 * and/or their position (ADD). E.g.:
 *  - to delete header Z insert it in to the list according to its offset 
 *   and with op=DELETE
 * - if you want to add a new header X after a  header Y, insert Y in the list
 *   with op NOP and after it X (op ADD).
 * - if you want X before Y, insert X in Y's before list.
 * - if you want X to be the first header just put it first in hdr_lst.
 *  -if you want to replace Y with X, insert Y with op=DELETE and then X with
 *  op=ADD.
 * before and after must contain only ADD ops!
 * 
 * Difference between "after" & "next" when ADDing:
 * "after" forces the new header immediately after the current one while
 * "next" means another header can be inserted between them.
 * 
 */

/* frees the content of a lump struct */
void free_lump(struct lump* l);
/*frees an entire lump list, recursively */
void free_lump_list(struct lump* lump_list);

#endif
