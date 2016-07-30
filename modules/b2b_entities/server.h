/*
 * back-to-back entities module
 *
 * Copyright (C) 2009 Free Software Fundation
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
 *  2009-08-03  initial version (Anca Vamanu)
 */

#ifndef _B2B_SERVER_H_
#define _B2B_SERVER_H_

#include "../../parser/msg_parser.h"
#include "dlg.h"

str* server_new(struct sip_msg*, str* local_contact, b2b_notify_t, str*);

dlg_t* b2b_server_build_dlg(b2b_dlg_t* dlg);

void b2b_server_tm_cback( struct cell *t, int type, struct tmcb_params *ps);

#endif
