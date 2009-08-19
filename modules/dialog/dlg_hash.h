/*
 * $Id$
 *
 * Copyright (C) 2006 Voice System SRL
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 * 2006-04-14  initial version (bogdan)
 * 2006-11-28  Added num_100s and num_200s to dlg_cell, to aid in adding 
 *             statistics tracking of the number of early, and active dialogs.
 *             (Jeffrey Magder - SOMA Networks)
 * 2007-03-06  syncronized state machine added for dialog state. New tranzition
 *             design based on events; removed num_1xx and num_2xx (bogdan)
 * 2007-07-06  added flags, cseq, contact, route_set and bind_addr 
 *             to struct dlg_cell in order to store these information into db
 *             (ancuta)
 * 2008-04-17  added new dialog flag to avoid state tranzitions from DELETED to
 *             CONFIRMED_NA due delayed "200 OK" (bogdan)
 */


#ifndef _DIALOG_DLG_HASH_H_
#define _DIALOG_DLG_HASH_H_

#include "../../locking.h"
#include "../../mi/mi.h"
#include "dlg_timer.h"
#include "dlg_cb.h"
#include "dlg_vals.h"


#define DLG_STATE_UNCONFIRMED  1
#define DLG_STATE_EARLY        2
#define DLG_STATE_CONFIRMED_NA 3
#define DLG_STATE_CONFIRMED    4
#define DLG_STATE_DELETED      5

#define DLG_EVENT_TDEL         1
#define DLG_EVENT_RPL1xx       2
#define DLG_EVENT_RPL2xx       3
#define DLG_EVENT_RPL3xx       4
#define DLG_EVENT_REQPRACK     5
#define DLG_EVENT_REQACK       6
#define DLG_EVENT_REQBYE       7
#define DLG_EVENT_REQ          8

#define DLG_FLAG_NEW           (1<<0)
#define DLG_FLAG_CHANGED       (1<<1)
#define DLG_FLAG_HASBYE        (1<<2)
#define DLG_FLAG_BYEONTIMEOUT  (1<<3)
#define DLG_FLAG_ISINIT        (1<<4)

#define DLG_CALLER_LEG         0
#define DLG_FIRST_CALLEE_LEG   1

#define DLG_DIR_NONE           0
#define DLG_DIR_DOWNSTREAM     1
#define DLG_DIR_UPSTREAM       2


struct dlg_leg {
	int id;
	str tag;
	str cseq;
	str route_set;
	str contact;
	struct socket_info *bind_addr;
};


#define DLG_LEGS_USED      0
#define DLG_LEGS_ALLOCED   1
struct dlg_cell
{
	volatile int         ref;
	struct dlg_cell      *next;
	struct dlg_cell      *prev;
	unsigned int         h_id;
	unsigned int         h_entry;
	unsigned int         state;
	unsigned int         lifetime;
	unsigned int         start_ts;    /* start time  (absolute UNIX ts)*/
	unsigned int         flags;
	unsigned int         from_rr_nb;
	unsigned int         user_flags;
	struct dlg_tl        tl;
	str                  callid;
	str                  from_uri;
	str                  to_uri;
	struct dlg_leg       *legs;
	unsigned short       legs_no[2];
	struct dlg_head_cbl  cbs;
	struct dlg_profile_link *profile_links;
	struct dlg_val          *vals;
};


struct dlg_entry
{
	struct dlg_cell    *first;
	struct dlg_cell    *last;
	unsigned int        next_id;
	unsigned int       lock_idx;
};



struct dlg_table
{
	unsigned int       size;
	struct dlg_entry   *entries;
	unsigned int       locks_no;
	gen_lock_set_t     *locks;
};


extern struct dlg_table *d_table;
extern struct dlg_cell  *current_dlg_pointer;


#define set_current_dialog(_dlg) \
		current_dlg_pointer = _dlg

struct dlg_cell *get_current_dialog();

#define dlg_lock(_table, _entry) \
		lock_set_get( (_table)->locks, (_entry)->lock_idx);
#define dlg_unlock(_table, _entry) \
		lock_set_release( (_table)->locks, (_entry)->lock_idx);

#define dlg_leg_print_info(_dlg, _leg, _field) \
	((_dlg)->legs_no[DLG_LEGS_USED]>_leg)?(_dlg)->legs[_leg]._field.len:4, \
	((_dlg)->legs_no[DLG_LEGS_USED]>_leg)?(_dlg)->legs[_leg]._field.s:"NULL"


inline void unlink_unsafe_dlg(struct dlg_entry *d_entry, struct dlg_cell *dlg);
inline void destroy_dlg(struct dlg_cell *dlg);

#define ref_dlg_unsafe(_dlg,_cnt)     \
	do { \
		(_dlg)->ref += (_cnt); \
		LM_DBG("ref dlg %p with %d -> %d\n", \
			(_dlg),(_cnt),(_dlg)->ref); \
	}while(0)

#define unref_dlg_unsafe(_dlg,_cnt,_d_entry)   \
	do { \
		(_dlg)->ref -= (_cnt); \
		LM_DBG("unref dlg %p with %d -> %d\n",\
			(_dlg),(_cnt),(_dlg)->ref);\
		if ((_dlg)->ref<0) {\
			LM_CRIT("bogus ref %d with cnt %d for dlg %p [%u:%u] "\
				"with clid '%.*s' and tags '%.*s' '%.*s'\n",\
				(_dlg)->ref, _cnt, _dlg,\
				(_dlg)->h_entry, (_dlg)->h_id,\
				(_dlg)->callid.len, (_dlg)->callid.s,\
				dlg_leg_print_info(_dlg, DLG_CALLER_LEG, tag), \
				dlg_leg_print_info(_dlg, DLG_FIRST_CALLEE_LEG, tag)); \
		}\
		if ((_dlg)->ref<=0) { \
			unlink_unsafe_dlg( _d_entry, _dlg);\
			LM_DBG("ref <=0 for dialog %p\n",_dlg);\
			destroy_dlg(_dlg);\
		}\
	}while(0)


int dialog_cleanup( struct sip_msg *msg, void *param );

int init_dlg_table(unsigned int size);

void destroy_dlg_table();

struct dlg_cell* build_new_dlg(str *callid, str *from_uri,
		str *to_uri, str *from_tag);

int dlg_set_leg_info(struct dlg_cell *dlg, str* tag, str *rr, str *contact,
		str *cseq, unsigned int leg);

int dlg_update_cseq(struct dlg_cell *dlg, unsigned int leg, str *cseq);

struct dlg_cell* lookup_dlg( unsigned int h_entry, unsigned int h_id);

struct dlg_cell* get_dlg(str *callid, str *ftag, str *ttag, unsigned int *dir);

void link_dlg(struct dlg_cell *dlg, int n);

void unref_dlg(struct dlg_cell *dlg, unsigned int cnt);

void ref_dlg(struct dlg_cell *dlg, unsigned int cnt);

void next_state_dlg(struct dlg_cell *dlg, int event,
		int *old_state, int *new_state, int *unref);

struct mi_root * mi_print_dlgs(struct mi_root *cmd, void *param );
struct mi_root * mi_print_dlgs_ctx(struct mi_root *cmd, void *param );

static inline int match_dialog(struct dlg_cell *dlg, str *callid,
							   str *ftag, str *ttag, unsigned int *dir) {
	str *tag;
	unsigned int i;

	/* first check dialog callid */
	if (dlg->callid.len!=callid->len || 
	strncmp(dlg->callid.s, callid->s, callid->len)!=0 )
		/* callid not matching */
		return 0;

	/* check the dialog from tag */
	if (dlg->legs[DLG_CALLER_LEG].tag.len == ftag->len &&
	strncmp(dlg->legs[DLG_CALLER_LEG].tag.s, ftag->s, ftag->len)==0 ) {
		/* from tag = from tag matching */
		*dir = DLG_DIR_DOWNSTREAM;
		tag = ttag;
	} else if (dlg->legs[DLG_CALLER_LEG].tag.len == ttag->len &&
	strncmp(dlg->legs[DLG_CALLER_LEG].tag.s, ttag->s, ttag->len)==0 ) {
		/* from tag = to tag matching */
		*dir = DLG_DIR_UPSTREAM;
		tag = ftag;
	} else {
		/* dialog from tag does not match */
		return 0;
	}

	/* check the dialog to tag - interate through all the stored to tags */
	if (dlg->legs_no[DLG_LEGS_USED] > DLG_FIRST_CALLEE_LEG) {
		for ( i=DLG_FIRST_CALLEE_LEG ; i<dlg->legs_no[DLG_LEGS_USED] ; i++)
			if (dlg->legs[i].tag.len == tag->len &&
			strncmp(dlg->legs[i].tag.s, tag->s, tag->len)==0 )
				return 0;
		/* no matching */
		return -1;
	}

	/* no to tag -> consider it a match*/
	return 0;

/*
	if (dlg->tag[DLG_CALLEE_LEG].len == 0) {
		if (*dir==DLG_DIR_DOWNSTREAM) {
			if (dlg->callid.len == callid->len &&
			dlg->tag[DLG_CALLER_LEG].len == ftag->len &&
			strncmp(dlg->callid.s, callid->s, callid->len)==0 &&
			strncmp(dlg->tag[DLG_CALLER_LEG].s, ftag->s, ftag->len)==0) {
				return 1;
			}
		} else if (*dir==DLG_DIR_UPSTREAM) {
			if (dlg->callid.len == callid->len &&
			dlg->tag[DLG_CALLER_LEG].len == ttag->len &&
			strncmp(dlg->callid.s, callid->s, callid->len)==0 &&
			strncmp(dlg->tag[DLG_CALLER_LEG].s, ttag->s, ttag->len)==0) {
				return 1;
			}
		} else {
			if (dlg->callid.len != callid->len)
				return 0;

			if (dlg->tag[DLG_CALLER_LEG].len == ttag->len &&
			strncmp(dlg->tag[DLG_CALLER_LEG].s, ttag->s, ttag->len)==0 &&
			strncmp(dlg->callid.s, callid->s, callid->len)==0) {
				*dir = DLG_DIR_UPSTREAM;
				return 1;
			} else if (dlg->tag[DLG_CALLER_LEG].len == ftag->len &&
			strncmp(dlg->tag[DLG_CALLER_LEG].s, ftag->s, ftag->len)==0 &&
			strncmp(dlg->callid.s, callid->s, callid->len)==0) {
				*dir = DLG_DIR_DOWNSTREAM;
				return 1;
			}
		}
	} else {
		if (*dir==DLG_DIR_DOWNSTREAM) {
			if (dlg->callid.len == callid->len &&
				dlg->tag[DLG_CALLER_LEG].len == ftag->len &&
				dlg->tag[DLG_CALLEE_LEG].len == ttag->len &&
				strncmp(dlg->callid.s, callid->s, callid->len)==0 &&
				strncmp(dlg->tag[DLG_CALLER_LEG].s, ftag->s, ftag->len)==0 &&
				strncmp(dlg->tag[DLG_CALLEE_LEG].s, ttag->s, ttag->len)==0) {
				return 1;
			}
		} else if (*dir==DLG_DIR_UPSTREAM) {
			if (dlg->callid.len == callid->len &&
				dlg->tag[DLG_CALLEE_LEG].len == ftag->len &&
				dlg->tag[DLG_CALLER_LEG].len == ttag->len &&
				strncmp(dlg->callid.s, callid->s, callid->len)==0 &&
				strncmp(dlg->tag[DLG_CALLEE_LEG].s, ftag->s, ftag->len)==0 &&
				strncmp(dlg->tag[DLG_CALLER_LEG].s, ttag->s, ttag->len)==0) {
				return 1;
			}
		} else {
			if (dlg->callid.len != callid->len)
				return 0;

			if (dlg->tag[DLG_CALLEE_LEG].len == ftag->len &&
				dlg->tag[DLG_CALLER_LEG].len == ttag->len &&
				strncmp(dlg->tag[DLG_CALLEE_LEG].s, ftag->s, ftag->len)==0 &&
				strncmp(dlg->tag[DLG_CALLER_LEG].s, ttag->s, ttag->len)==0 &&
				strncmp(dlg->callid.s, callid->s, callid->len)==0) {

				*dir = DLG_DIR_UPSTREAM;
				return 1;
			} else if (dlg->tag[DLG_CALLER_LEG].len == ftag->len &&
				dlg->tag[DLG_CALLEE_LEG].len == ttag->len &&
				strncmp(dlg->tag[DLG_CALLER_LEG].s, ftag->s, ftag->len)==0 &&
				strncmp(dlg->tag[DLG_CALLEE_LEG].s, ttag->s, ttag->len)==0 &&
				strncmp(dlg->callid.s, callid->s, callid->len)==0) {

				*dir = DLG_DIR_DOWNSTREAM;
				return 1;
			}
		}
	}
*/
}

static inline int match_downstream_dialog(struct dlg_cell *dlg, 
													str *callid, str *ftag)
{
	if (dlg->callid.len!=callid->len ||
		dlg->legs[DLG_CALLER_LEG].tag.len!=ftag->len  ||
		strncmp(dlg->callid.s,callid->s,callid->len)!=0 ||
		strncmp(dlg->legs[DLG_CALLER_LEG].tag.s,ftag->s,ftag->len)!=0)
		return 0;
	return 1;
}


int mi_print_dlg(struct mi_node *rpl, struct dlg_cell *dlg, int with_context);

#endif
