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
 *  2003-03-31  200 for INVITE/UAS resent even for UDP (jiri)
 *  2004-11-15  t_write_xxx can print whatever avp/hdr
 */



#ifndef _TM_T_FIFO_H_
#define _TM_T_FIFO_H_

#include "../../parser/msg_parser.h"
#include "../../sr_module.h"

extern int tm_unix_tx_timeout;

int fixup_t_write(void** param);
int fixup_free_t_write(void **param);

int parse_tw_append( modparam_t type, void* val);

int init_twrite_lines();

int init_twrite_sock(void);

struct tw_info;

int t_write_req(struct sip_msg* msg, struct tw_info* info, str* vm_fifo);

int t_write_unix(struct sip_msg* msg, struct tw_info* info, str* socket);

#endif
