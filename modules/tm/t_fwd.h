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
 * History:
 * --------
 *  2003-02-18  added proto to various function prototypes (andrei)
 */


#ifndef _T_FWD_H
#define _T_FWD_H

#include "../../proxy.h"
#include "../../str.h"

typedef int (*taddblind_f)( /*struct cell *t */ );

void e2e_cancel( struct sip_msg *cancel_msg, struct cell *t_cancel,
		struct cell *t_invite );

int e2e_cancel_branch( struct sip_msg *cancel_msg, struct cell *t_cancel,
		struct cell *t_invite, int branch );

int add_blind_uac( );

int t_replicate(struct sip_msg *p_msg, str *dst, int flags);

int t_forward_nonack( struct cell *t, struct sip_msg* p_msg,
		struct proxy_l * p);

int t_forward_ack( struct sip_msg* p_msg );

void t_on_branch( unsigned int go_to );

unsigned int get_on_branch();

typedef int (*tgetbranch_f)(void);
int get_branch_index(void);

#endif


