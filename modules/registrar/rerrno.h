/*
 * $Id$
 *
 * Registrar errno
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


#ifndef RERRNO_H
#define RERRNO_H


typedef enum rerr {
	R_FINE = 0,   /* Everything went OK */
	R_UL_DEL_R,   /* Usrloc record delete failed */
	R_UL_GET_R,   /* Usrloc record get failed */
	R_UL_NEW_R,   /* Usrloc new record failed */
	R_INV_CSEQ,   /* Invalid CSeq value */
	R_UL_INS_C,   /* Usrloc insert contact failed */
	R_UL_INS_R,   /* Usrloc insert record failed */
	R_UL_DEL_C,   /* Usrloc contact delete failed */
	R_UL_UPD_C,   /* Usrloc contact update failed */
	R_TO_USER,    /* No username part in To URI */
	R_AOR_LEN,    /* Address Of Record too long */
	R_AOR_PARSE,  /* Error while parsing Address Of Record */
	R_INV_EXP,    /* Invalid expires parameter in contact */
	R_INV_Q,      /* Invalid q parameter in contact */
	R_PARSE,      /* Error while parsing message */
	R_TO_MISS,    /* Missing To header field */
	R_CID_MISS,   /* Missing Call-ID header field */
	R_CS_MISS,    /* Missing CSeq header field */
	R_PARSE_EXP,  /* Error while parsing Expires */
	R_PARSE_CONT, /* Error while parsing Contact */
	R_STAR_EXP,   /* star and expires != 0 */
	R_STAR_CONT,  /* star and more contacts */
	R_OOO,        /* Out-Of-Order request */
	R_RETRANS,    /* Request is retransmission */
	R_UNESCAPE    /* Error while unescaping username */
} rerr_t;


extern rerr_t rerrno;


#endif /* RERRNO_H */
