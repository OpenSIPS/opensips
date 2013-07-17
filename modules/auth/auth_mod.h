/*
 * $Id$
 *
 * Digest Authentication Module
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
 * 2003-04-28 rpid contributed by Juha Heinanen added (janakj)
 */

#ifndef AUTH_MOD_H
#define AUTH_MOD_H

#include "../../str.h"
#include "../../parser/msg_parser.h"    /* struct sip_msg */
#include "../signaling/signaling.h"
#include "../../lock_ops.h"

#define MAX_NONCE_INDEX     256000
#define NBUF_LEN            (MAX_NONCE_INDEX>>3)

/*
 * Module parameters variables
 */
extern str secret;            /* secret phrase used to generate nonce */
extern unsigned int nonce_expire;      /* nonce expire interval */
extern str rpid_prefix;       /* Remote-Party-ID prefix */
extern str rpid_suffix;       /* Remote-Party-ID suffix */
extern str realm_prefix;      /* strip off auto-generated realm */

/** SIGNALING binds */
extern struct sig_binds sigb;

/* nonce index */
extern gen_lock_t* nonce_lock;
extern char* nonce_buf;
extern int* sec_monit;
extern int* second;
extern int* next_index;
extern int disable_nonce_check;

#endif /* AUTH_MOD_H */
