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

#include "srs_body.h"
#include "../dialog/dlg_load.h"
#include "../tm//tm_load.h"
#include "../../ut.h"

#define SRC_MAX_PARTICIPANTS 2
/* Uncomment this to enable SIPREC debugging
#define SIPREC_DEBUG_REF
 */

#ifdef SIPREC_DEBUG_REF
#define SIPREC_DEBUG(_s, _msg) \
	LM_DBG("session=%p ref=%d %s (%s:%d)\n", (_s), (_s)->ref, \
			_msg, __func__, __LINE__)
#else
#define SIPREC_DEBUG(_s, _msg)
#endif

struct src_part {
	str aor;
	str name;
	siprec_uuid uuid;
	struct list_head streams;
};

struct src_sess {

	/* media */
	time_t ts;
	int version;
	int streams_no;
	str rtpproxy;
	str srs_uri;
	str group;

	/* siprec */
	siprec_uuid uuid;
	/* XXX: for now we only have two participants,
	 * but we can expand more in the future */
	int participants_no;
	struct src_part participants[SRC_MAX_PARTICIPANTS];

	/* internal */
	int ref;
	int started;
	str b2b_key;
	gen_lock_t lock;
	struct dlg_cell *dlg;
};

void src_unref_session(void *p);
struct src_sess *src_create_session(str *srs, str *rtp, str *group);
void src_free_session(struct src_sess *sess);
int src_add_participant(struct src_sess *sess, str *aor, str *name);

extern struct tm_binds srec_tm;
extern struct dlg_binds srec_dlg;

#define SIPREC_LOCK(_s) lock_get(&(_s)->lock)
#define SIPREC_UNLOCK(_s) lock_release(&(_s)->lock)

#define SIPREC_REF_UNSAFE(_s) \
	do { \
		SIPREC_DEBUG(_s, "ref"); \
		(_s)->ref++; \
	} while(0)

#define SIPREC_REF(_s) \
	do { \
		SIPREC_LOCK(_s); \
		SIPREC_REF_UNSAFE(_s); \
		SIPREC_UNLOCK(_s); \
	} while(0)

#define SIPREC_UNREF_COUNT_UNSAFE(_s, _c) \
	do { \
		SIPREC_DEBUG(_s, "unref"); \
		(_s)->ref -= (_c); \
		if ((_s)->ref == 0) { \
			LM_DBG("destroying session=%p\n", _s); \
			SIPREC_UNLOCK(_s); \
			src_free_session(_s); \
		} else { \
			if ((_s)->ref < 0) \
				LM_BUG("invalid ref for session=%p ref=%d (%s:%d)\n", \
						(_s), (_s)->ref, __func__, __LINE__); \
		} \
	} while(0)

#define SIPREC_UNREF_COUNT(_s, _c) \
	do { \
		SIPREC_LOCK(_s); \
		SIPREC_UNREF_COUNT_UNSAFE(_s, _c); \
		SIPREC_UNLOCK(_s); \
	} while(0)

#define SIPREC_UNREF_UNSAFE(_s) SIPREC_UNREF_COUNT_UNSAFE(_s, 1)
#define SIPREC_UNREF(_s) SIPREC_UNREF_COUNT(_s, 1)

#endif /* _SIPREC_SESS_H_ */
