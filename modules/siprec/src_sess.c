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

#include "src_sess.h"

struct tm_binds srec_tm;
struct dlg_binds srec_dlg;
static str srec_dlg_name = str_init("siprecX_ctx");

struct src_sess *src_get_session(struct dlg_cell *dlg)
{
	str val;
	if (srec_dlg.fetch_dlg_value(dlg, &srec_dlg_name, &val, 0) < 0)
		return NULL;
	if (val.len != sizeof(struct src_sess *)) {
		LM_BUG("invalid value in dlg ctx: %d (!= %ld)\n",
				val.len, sizeof(struct src_sess *));
		return NULL;
	}
	return (struct src_sess *)val.s;
}

struct src_sess *src_create_session(struct dlg_cell *dlg,
		struct srs_set *set, str media)
{
	str val;
	struct src_sess *ss = shm_malloc(sizeof *ss + media.len);
	if (!ss) {
		LM_ERR("not enough memory for creating siprec session!\n");
		return NULL;
	}
	memset(ss, 0, sizeof *ss);
	ss->media_ip.s = (char *)(ss + 1);

	memcpy(ss->media_ip.s, media.s, media.len);
	ss->media_ip.len = media.len;

	if (srs_init_sdp_body(&ss->sdp) < 0) {
		LM_ERR("cannot initialize SDP body!\n");
		shm_free(ss);
		return NULL;
	}

	//lock_init(&ss->lock);
	ss->set = set;
	ss->dlg = dlg; /* TODO: ref the dialog */

	val.len = sizeof *ss;
	val.s = (char *)ss;
	if (srec_dlg.store_dlg_value(dlg, &srec_dlg_name, &val) < 0) {
		LM_ERR("cannot store siprec ctx in dialog!\n");
		return NULL;
	}

	return ss;
}

