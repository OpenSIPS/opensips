/*
 * signaling module - interface for sending sip messages
 *
 * Copyright (C) 2008 Voice Sistem S.R.L.
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
 *  2008-11-5  initial version (Anca Vamanu)
 */

#ifndef _SIG_H_
#define _SIG_H_

#include "../../sr_module.h"
#include "../../parser/msg_parser.h"

typedef int (*sig_send_reply_f)(struct sip_msg *msg, int code, str *reason,
		str *tag);
typedef int (*sig_gen_totag_f)(struct sip_msg *msg, str *tag);

struct sig_binds {
	sig_send_reply_f reply;
	sig_gen_totag_f  gen_totag;
	};

int load_sig( struct sig_binds *sigb);
typedef int (*load_sig_f) ( struct sig_binds *sigb);

static inline int load_sig_api( struct sig_binds *sigb)
{
	load_sig_f load_sig;

	/* import the SL auto-loading function */
	if ( !(load_sig=(load_sig_f)find_export("load_sig", 0))) {
		LM_ERR("can't import load_sig\n");
		return -1;
	}
	/* let the auto-loading function load all TM stuff */
	if (load_sig( sigb )==-1)
		return -1;

	return 0;
}

#endif
