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

#define TM_INJECT_SRC_MSG     (1<<0)
#define TM_INJECT_SRC_EVENT   (1<<1)
#define TM_INJECT_FLAG_CANCEL (1<<2)

typedef int (*taddblind_f)( /*struct cell *t */ );

int add_blind_uac( );

int t_replicate(struct sip_msg *p_msg, str *dst, int flags);

int t_forward_nonack( struct cell *t, struct sip_msg* p_msg,
		struct proxy_l * p, int reset_bcounter, int locked);

int add_phony_uac( struct cell *t);

int t_add_reason(struct sip_msg *msg, str *reason);

int t_set_reason(struct sip_msg *msg, str *reason);

int t_forward_ack( struct sip_msg* p_msg );

void t_on_branch( unsigned int go_to );

unsigned int get_on_branch();

typedef int (*tgetbranch_f)(void);
int get_branch_index(void);

extern int w_t_wait_for_new_branches(struct sip_msg* msg);

extern int w_t_inject_branches(struct sip_msg* msg, void *source,
                               void *extra_flags);
int t_inject_ul_event_branch(void);
int t_inject_branch( struct cell *t, struct sip_msg *msg, int flags);

void get_cancel_reason(struct sip_msg *msg, int flags, str *reason);

#endif


