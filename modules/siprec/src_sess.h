/*
 * Copyright (C) 2017 OpenSIPS Project
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * History:
 * ---------
 *  2017-06-20  created (razvanc)
 */

#ifndef _SIPREC_SESS_H_
#define _SIPREC_SESS_H_

#include "srs_node.h"
#include "srs_body.h"
#include "../dialog/dlg_load.h"
#include "../tm//tm_load.h"

struct src_sess {
	//gen_lock_t lock;
	str *b2b_key;

	str media_ip;
	struct srs_sdp sdp;
	struct srs_set *set;
	struct dlg_cell *dlg;
};

struct src_sess *src_get_session(struct dlg_cell *dlg);
struct src_sess *src_create_session(struct dlg_cell *dlg,
		struct srs_set *set, str media);

extern struct tm_binds srec_tm;
extern struct dlg_binds srec_dlg;

#endif /* _SIPREC_SESS_H_ */
