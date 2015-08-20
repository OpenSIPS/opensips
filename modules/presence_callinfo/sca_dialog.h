/*
 * Add "call-info" event to presence module
 *
 * Copyright (C) 2013 OpenSIPS Solutions
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
 *  2010-07-13  added support for SCA Broadsoft with dialog module (bogdan)
 */


#ifndef _H_PRESENCE_CALL_INFO_SCA_DIALOG
#define _H_PRESENCE_CALL_INFO_SCA_DIALOG

#include "../../str.h"
#include "../../locking.h"
#include "../../parser/msg_parser.h"


int init_dialog_support(void);

int sca_set_line(struct sip_msg *msg, str *line, int calling);


#endif
