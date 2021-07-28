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

#include "siprec_body.h"
#include "../dialog/dlg_load.h"
#include "../tm//tm_load.h"
#include "../../ut.h"

#define SIPREC_SESSION_VERSION 0
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

struct srec_dlg;

struct srs_node {
	str uri;
	struct list_head list;
};

struct src_part {
	str aor;
	str name;
	str xml_val;
	time_t ts;
	siprec_uuid uuid;
	struct list_head streams;
};

#define SIPREC_STARTED	(1<<0)
#define SIPREC_DLG_CBS	(1<<1)
#define SIPREC_ONGOING	(1<<2)

#define SIPREC_SRS(_s) (list_entry((_s)->srs.next, struct srs_node, list)->uri)

struct src_sess {

	/* media */
	time_t ts;
	int version;
	int streams_no;
	str rtpproxy;
	str media_ip;
	str headers;

	/* SRS */
	struct list_head srs;
	str group;
	struct socket_info *socket; /* socket used towards SRS */

	/* siprec */
	siprec_uuid uuid;
	/* XXX: for now we only have two participants,
	 * but we can expand more in the future */
	int participants_no;
	struct src_part participants[SRC_MAX_PARTICIPANTS];

	/* internal */
	int ref;
	unsigned flags;
	gen_lock_t lock;
	struct dlg_cell *dlg;

	/* b2b */
	str b2b_key;
	str b2b_fromtag;
	str b2b_totag;
	str b2b_callid;
};

void src_unref_session(void *p);
struct src_sess *src_new_session(str *srs, str *rtp, str *m_ip, str *group,
		str *hdrs, struct socket_info *si);
void src_free_session(struct src_sess *sess);
int src_add_participant(struct src_sess *sess, str *aor, str *name, str *xml_val,
		siprec_uuid *uuid, time_t *start);

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

#define SIPREC_UNREF(_s) \
	do { \
		SIPREC_LOCK(_s); \
		SIPREC_DEBUG(_s, "unref"); \
		(_s)->ref--; \
		if ((_s)->ref == 0) { \
			LM_DBG("destroying session=%p\n", _s); \
			SIPREC_UNLOCK(_s); \
			src_free_session(_s); \
		} else { \
			if ((_s)->ref < 0) \
				LM_BUG("invalid ref for session=%p ref=%d (%s:%d)\n", \
						(_s), (_s)->ref, __func__, __LINE__); \
			SIPREC_UNLOCK(_s); \
		} \
	} while(0)

#define SIPREC_UNREF_UNSAFE(_s) \
	do { \
		SIPREC_DEBUG(_s, "unref"); \
		(_s)->ref--; \
		if ((_s)->ref == 0) { \
			LM_DBG("destroying session=%p\n", _s); \
			src_free_session(_s); \
		} else { \
			if ((_s)->ref < 0) \
				LM_BUG("invalid ref for session=%p ref=%d (%s:%d)\n", \
						(_s), (_s)->ref, __func__, __LINE__); \
		} \
	} while(0)

void srec_loaded_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *params);
void srec_dlg_write_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *params);

#endif /* _SIPREC_SESS_H_ */
