/*
 * back-to-back entities modules
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

#ifndef _B2B_CLIENT_H_
#define _B2B_CLIENT_H_

#include "../../str.h"
#include "../../parser/msg_parser.h"
#include "dlg.h"
#include "b2b_entities.h"
#include "b2be_load.h"

str* client_new(client_info_t* ci, b2b_notify_t b2b_cback,
		b2b_add_dlginfo_t add_dlginfo, str *mod_name, str* param);

void b2b_client_tm_cback( struct cell *t, int type, struct tmcb_params *ps);

dlg_t* b2b_client_build_dlg(b2b_dlg_t* dlg, dlg_leg_t* leg);

#endif
