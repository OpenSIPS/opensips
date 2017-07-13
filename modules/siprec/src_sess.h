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
#include "../../ut.h"

#define SRC_MAX_PARTICIPANTS 2


struct src_part {
	str aor;
	siprec_uuid uuid;
	struct list_head streams;
};

struct src_sess {

	/* media */
	time_t ts;
	int version;
	int streams_no;
	str media_ip;
	struct srs_set *set;

	/* siprec */
	siprec_uuid uuid;
	/* XXX: for now we only have two participants, but we can expand more in
	 * the future */
	int participants_no;
	struct src_part participants[SRC_MAX_PARTICIPANTS];

	/* internal */
	str b2b_key;
	struct dlg_cell *dlg;
	//gen_lock_t lock;
};

struct src_sess *src_get_session(struct dlg_cell *dlg);
struct src_sess *src_create_session(struct dlg_cell *dlg,
		struct srs_set *set, str media);
int src_add_participant(struct src_sess *sess, str *aor);

extern struct tm_binds srec_tm;
extern struct dlg_binds srec_dlg;

#endif /* _SIPREC_SESS_H_ */
