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
#include "srs_body.h"

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
	struct src_sess *ss = shm_malloc(sizeof *ss + media.len);
	if (!ss) {
		LM_ERR("not enough memory for creating siprec session!\n");
		return NULL;
	}
	memset(ss, 0, sizeof *ss);
	ss->media_ip.s = (char *)(ss + 1);

	memcpy(ss->media_ip.s, media.s, media.len);
	ss->media_ip.len = media.len;
	siprec_build_uuid(ss->uuid);
	ss->participants_no = 0;
	ss->ts = time(NULL);

	//lock_init(&ss->lock);
	ss->set = set;
	ss->dlg = dlg; /* TODO: ref the dialog */

	/* don't need this right now
	val.len = sizeof *ss;
	val.s = (char *)ss;
	if (srec_dlg.store_dlg_value(dlg, &srec_dlg_name, &val) < 0) {
		LM_ERR("cannot store siprec ctx in dialog!\n");
		return NULL;
	}
	*/

	return ss;
}

void src_free_participant(struct src_part *part)
{
	struct srs_sdp_stream *stream;
	struct list_head *it, *tmp;

	list_for_each_safe(it, tmp, &part->streams) {
		stream = list_entry(it, struct srs_sdp_stream, list);
		srs_free_stream(stream);
	}
	if (part->aor.s)
		shm_free(part->aor.s);
}

void src_free_session(struct src_sess *sess)
{
	int p;

	for (p = 0; p < sess->participants_no; p++)
		src_free_participant(&sess->participants[p]);
	shm_free(sess->b2b_key.s);
	shm_free(sess);
}

int src_add_participant(struct src_sess *sess, str *aor)
{
	struct src_part *part;
	if (sess->participants_no >= SRC_MAX_PARTICIPANTS) {
		LM_ERR("no more space for new participants (have %d)!\n",
				sess->participants_no);
		return -1;
	}
	part = &sess->participants[sess->participants_no];
	INIT_LIST_HEAD(&part->streams);
	siprec_build_uuid(part->uuid);

	part->aor.s = shm_malloc(aor->len);
	if (!part->aor.s) {
		LM_ERR("out of shared memory!\n");
		return -1;
	}

	part->aor.len = aor->len;
	memcpy(part->aor.s, aor->s, aor->len);
	sess->participants_no++;

	return 1;
}
