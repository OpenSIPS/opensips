/*
 * Copyright (C) 2007 Voice Sistem SRL
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
 */


#ifndef _SL_API_H_
#define _SL_API_H_

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../str.h"

typedef int (*sl_send_reply_f)(struct sip_msg *msg, int code, str *reason);
typedef int (*sl_send_reply_dlg_f)(struct sip_msg *msg, int code, str *reason,
		str *tag);
typedef int (*sl_get_totag_f)(struct sip_msg *msg, str *totag);

struct sl_binds {
	sl_send_reply_f     reply;
	sl_send_reply_dlg_f reply_dlg;
	sl_get_totag_f      get_totag;
};

typedef int(*load_sl_f)(struct sl_binds *slb);

int load_sl(struct sl_binds *slb);


static inline int load_sl_api( struct sl_binds *slb )
{
	load_sl_f load_sl;

	/* import the SL auto-loading function */
	if ( !(load_sl=(load_sl_f)find_export("load_sl", 0, 0))) {
		LM_ERR("can't import load_sl\n");
		return -1;
	}
	/* let the auto-loading function load all TM stuff */
	if (load_sl( slb )==-1)
		return -1;

	return 0;
}


#endif
