/*
 * Copyright (C) 2009-2014 OpenSIPS Solutions
 * Copyright (C) 2006-2009 Voice System SRL
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
 * 2009-09-09  support for early dialogs added; proper handling of cseq
 *             while PRACK is used (bogdan)
 */


#ifndef _DIALOG_DLG_HASH_H_
#define _DIALOG_DLG_HASH_H_

#include "../../locking.h"
#include "../../context.h"
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

#define DLG_FLAG_NEW			(1<<0)
#define DLG_FLAG_CHANGED		(1<<1)
#define DLG_FLAG_HASBYE			(1<<2)
#define DLG_FLAG_BYEONTIMEOUT		(1<<3)
#define DLG_FLAG_ISINIT			(1<<4)
#define DLG_FLAG_PING_CALLER		(1<<5)
#define DLG_FLAG_PING_CALLEE		(1<<6)
#define DLG_FLAG_TOPHIDING		(1<<7)
#define DLG_FLAG_VP_CHANGED		(1<<8)
#define DLG_FLAG_DB_DELETED		(1<<9)
#define DLG_FLAG_CSEQ_ENFORCE		(1<<10)
#define DLG_FLAG_REINVITE_PING_CALLER	(1<<11)
#define DLG_FLAG_REINVITE_PING_CALLEE	(1<<12)

#define DLG_CALLER_LEG         0
#define DLG_FIRST_CALLEE_LEG   1

#define DLG_DIR_NONE           0
#define DLG_DIR_DOWNSTREAM     1
#define DLG_DIR_UPSTREAM       2


struct dlg_leg {
	int id;
	str tag;
	str r_cseq;		/* last cseq received targeting this leg */
	str prev_cseq;	/* prev cseq received targeting this leg */
	str inv_cseq;	/* last cseq of invite received from this leg */
	str from_uri;	/* FROM URI for this leg, in case of FROM URI mangling*/
	str to_uri;		/* TO URI for this leg, in case of TO URI mangling */
	str route_set;
	str contact;
	str th_sent_contact;	/* topology hiding advertised contact towards this leg - full header */
	str route_uris[64];
	str sdp;		/* latest SDP provided by this leg ( full body ), after all OpenSIPS changes */
	int nr_uris;
	unsigned int last_gen_cseq; /* FIXME - think this can be atomic_t to avoid locking */
	unsigned int last_inv_gen_cseq; /* used when translating ACKs */
	char reply_received;
	char reinvite_confirmed;
	struct socket_info *bind_addr;
};


#define DLG_LEGS_USED      0
#define DLG_LEGS_ALLOCED   1
#define DLG_LEG_200OK      2

/* ALL module flags to be listed here - we have to centralize here :
- in order to make it easier for future modules to use the flags  
- sometimes, dialog internal behavior changes, depending on whether a certain module is loaded or not ( eg. topology_hiding ) */
#define SST_DIALOG_FLAG   (1 << 0)
#define TOPOH_ONGOING     (1 << 1)
#define TOPOH_KEEP_USER   (1 << 2)
#define TOPOH_HIDE_CALLID (1 << 3)
#define TOPOH_DID_IN_USER (1 << 4)

struct dlg_cell
{
	volatile int         ref;
	struct dlg_cell      *next;
	struct dlg_cell      *prev;
	unsigned int         h_id;
	unsigned int         h_entry;
	unsigned int         state;
	unsigned int         lifetime;
	unsigned short       lifetime_dirty; /* 1 if lifetime timer should
	                                      * be updated */
	unsigned short       locked_by;   /* holds the ID of the process locking
	                                   * the dialog (if the case) while
	                                   * calling a callback */
	unsigned int         start_ts;    /* start time  (absolute UNIX ts)*/
	unsigned int         flags;
	unsigned int         from_rr_nb;
	unsigned int         user_flags;
	unsigned int         mod_flags;
	unsigned int         initial_t_hash_index;
	unsigned int         initial_t_label;
	struct dlg_tl        tl;
	struct dlg_ping_list *pl;
	struct dlg_ping_list *reinvite_pl;
	str                  terminate_reason;
	str                  callid;
	str                  from_uri;
	str                  to_uri;
	struct dlg_leg       *legs;
	unsigned char        legs_no[4];
	struct dlg_head_cbl  cbs;
	struct dlg_profile_link *profile_links;
	struct dlg_val       *vals;
};


struct dlg_entry
{
	struct dlg_cell    *first;
	struct dlg_cell    *last;
	unsigned int        next_id;
	unsigned int        cnt;
	unsigned int        lock_idx;
};



struct dlg_table
{
	unsigned int       size;
	struct dlg_entry   *entries;
	unsigned int       locks_no;
	gen_lock_set_t     *locks;
};


extern struct dlg_table *d_table;
extern int ctx_dlg_idx;

#define callee_idx(_dlg) \
	(((_dlg)->legs_no[DLG_LEG_200OK]==0)? \
		DLG_FIRST_CALLEE_LEG : (_dlg)->legs_no[DLG_LEG_200OK])

#define ctx_dialog_get() \
	((struct dlg_cell*)context_get_ptr(CONTEXT_GLOBAL,current_processing_ctx,ctx_dlg_idx) )

#define ctx_dialog_set(_dlg) \
	context_put_ptr(CONTEXT_GLOBAL,current_processing_ctx, ctx_dlg_idx, _dlg)

struct dlg_cell *get_current_dialog();

#define dlg_hash(_callid) core_hash(_callid, 0, d_table->size)

#define dlg_lock(_table, _entry) \
		lock_set_get( (_table)->locks, (_entry)->lock_idx);
#define dlg_unlock(_table, _entry) \
		lock_set_release( (_table)->locks, (_entry)->lock_idx);

#define dlg_leg_print_info(_dlg, _leg, _field) \
	((_dlg)->legs_no[DLG_LEGS_USED]>_leg)?(_dlg)->legs[_leg]._field.len:4, \
	((_dlg)->legs_no[DLG_LEGS_USED]>_leg)?(_dlg)->legs[_leg]._field.s:"NULL"

#define dlg_lock_dlg(_dlg) \
	dlg_lock( d_table, &(d_table->entries[_dlg->h_entry]))

#define dlg_unlock_dlg(_dlg) \
	dlg_unlock( d_table, &(d_table->entries[_dlg->h_entry]))

static inline str* dlg_leg_from_uri(struct dlg_cell *dlg,int leg_no)
{
	/* no mangling possible on caller leg */
	if (leg_no == DLG_CALLER_LEG)
		return &dlg->from_uri;

	/* if we saved mangled from URI at leg creation, return that */
	if (dlg->legs[leg_no].from_uri.s && dlg->legs[leg_no].from_uri.len)
		return &dlg->legs[leg_no].from_uri;

	/* if there was no mangling for this leg, return original from URI */
	return &dlg->from_uri;
}

static inline str* dlg_leg_to_uri(struct dlg_cell *dlg,int leg_no)
{
	/* no mangling possible on caller leg */
	if (leg_no == DLG_CALLER_LEG)
		return &dlg->to_uri;

	/* if we saved mangled to URI at leg creation, return that */
	if (dlg->legs[leg_no].to_uri.s && dlg->legs[leg_no].to_uri.len)
		return &dlg->legs[leg_no].to_uri;

	/* if there was no mangling for this leg, return original to URI */
	return &dlg->to_uri;
}

void unlink_unsafe_dlg(struct dlg_entry *d_entry, struct dlg_cell *dlg);
void destroy_dlg(struct dlg_cell *dlg);

#define ref_dlg_unsafe(_dlg,_cnt)     \
	do { \
		(_dlg)->ref += (_cnt); \
		LM_DBG("ref dlg %p with %d -> %d\n", \
			(_dlg),(_cnt),(_dlg)->ref); \
	}while(0)

#define unref_dlg_unsafe(_dlg,_cnt,_d_entry)   \
	do { \
		(_dlg)->ref -= (_cnt); \
		LM_DBG("unref dlg %p with %d -> %d in entry %p\n",\
			(_dlg),(_cnt),(_dlg)->ref,(_d_entry));\
		if ((_dlg)->ref<0) {\
			LM_CRIT("bogus ref %d with cnt %d for dlg %p [%u:%u] "\
				"with clid '%.*s' and tags '%.*s' '%.*s'\n",\
				(_dlg)->ref, _cnt, _dlg,\
				(_dlg)->h_entry, (_dlg)->h_id,\
				(_dlg)->callid.len, (_dlg)->callid.s,\
				dlg_leg_print_info(_dlg, DLG_CALLER_LEG, tag), \
				dlg_leg_print_info(_dlg, callee_idx(_dlg), tag)); \
		}\
		if ((_dlg)->ref<=0) { \
			unlink_unsafe_dlg( _d_entry, _dlg);\
			LM_DBG("ref <=0 for dialog %p\n",_dlg);\
			destroy_dlg(_dlg);\
		}\
	}while(0)

/*
 * @input - str
 * @return - integer flag bitmask
 */
#define parse_create_dlg_flags(input) \
	({ \
		char *___p; \
		int ___flags = 0; \
		for (___p=(input).s; ___p < (input).s + (input).len; ___p++) \
		{ \
			switch (*___p) \
			{ \
				case 'P': \
					___flags |= DLG_FLAG_PING_CALLER; \
					LM_DBG("will ping caller\n"); \
					break; \
				case 'p': \
					___flags |= DLG_FLAG_PING_CALLEE; \
					LM_DBG("will ping callee\n"); \
					break; \
				case 'B': \
					___flags |= DLG_FLAG_BYEONTIMEOUT; \
					LM_DBG("bye on timeout activated\n"); \
					break; \
				case 'R': \
					___flags |= DLG_FLAG_REINVITE_PING_CALLER; \
					LM_DBG("re-invite ping caller activated\n"); \
					break; \
				case 'r': \
					___flags |= DLG_FLAG_REINVITE_PING_CALLEE; \
					LM_DBG("re-invite ping callee activated\n"); \
					break; \
				default: \
					LM_DBG("unknown create_dialog flag : [%c] ." \
						   "Skipping\n", *___p); \
			} \
		} \
		___flags; \
	})

int dialog_cleanup( struct sip_msg *msg, void *param );

int init_dlg_table(unsigned int size);

void destroy_dlg_table();

struct dlg_cell* build_new_dlg(str *callid, str *from_uri,
		str *to_uri, str *from_tag);

int dlg_add_leg_info(struct dlg_cell *dlg, str* tag, str *rr,
		str *contact,str *cseq, struct socket_info *sock,
		str *mangled_from,str *mangled_to,str *sdp);

int dlg_update_cseq(struct dlg_cell *dlg, unsigned int leg, str *cseq,
						int field_type);

int dlg_update_routing(struct dlg_cell *dlg, unsigned int leg,str *rr, str *contact);

struct dlg_cell* lookup_dlg( unsigned int h_entry, unsigned int h_id);

struct dlg_cell* get_dlg(str *callid, str *ftag, str *ttag,
		unsigned int *dir, unsigned int *dst_leg);

struct dlg_cell* get_dlg_by_val(str *attr, str *val);

struct dlg_cell* get_dlg_by_callid( str *callid);

void link_dlg(struct dlg_cell *dlg, int n);

void unref_dlg(struct dlg_cell *dlg, unsigned int cnt);

void ref_dlg(struct dlg_cell *dlg, unsigned int cnt);

void next_state_dlg(struct dlg_cell *dlg, int event, int dir, int *old_state,
		int *new_state, int *unref, int last_dst_leg, char is_replicated);

struct mi_root * mi_print_dlgs(struct mi_root *cmd, void *param );
struct mi_root * mi_print_dlgs_ctx(struct mi_root *cmd, void *param );

static inline void unref_dlg_destroy_safe(struct dlg_cell *dlg, unsigned int cnt)
{
	if (d_table)
		unref_dlg(dlg, cnt);
}

static inline int match_dialog(struct dlg_cell *dlg, str *callid,
			str *ftag, str *ttag, unsigned int *dir, unsigned int *dst_leg) {
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
		*dst_leg = 0; /* destination is the caller */
		tag = ftag;
	} else {
		/* dialog from tag does not match */
		return 0;
	}

	/* check the dialog to tag - interate through all the stored to-tags */
	if (dlg->legs_no[DLG_LEGS_USED] > DLG_FIRST_CALLEE_LEG) {
		for ( i=DLG_FIRST_CALLEE_LEG ; i<dlg->legs_no[DLG_LEGS_USED] ; i++) {
			if (dlg->legs[i].tag.len == tag->len &&
			strncmp(dlg->legs[i].tag.s, tag->s, tag->len)==0 ) {
				if (*dst_leg==-1) *dst_leg = i; /* destination is callee */
				return 1;
			}
		}
		/* no matching */
		return 0;
	}

	/* no to tag in dialog */
	return (tag->len==0)?1:0;

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

int mi_print_dlg(struct mi_node *rpl, struct dlg_cell *dlg, int with_context);

static inline void init_dlg_term_reason(struct dlg_cell *dlg,char *reason,int reason_len)
{
	if (!dlg->terminate_reason.s) {
		dlg->terminate_reason.s = shm_malloc(reason_len);
		if (dlg->terminate_reason.s) {
			dlg->terminate_reason.len = reason_len;
			memcpy(dlg->terminate_reason.s,reason,
					reason_len);
			LM_DBG("Setting DLG term reason to [%.*s] \n",
					dlg->terminate_reason.len,dlg->terminate_reason.s);
		} else
			LM_ERR("Failed to initialize the terminate reason \n");
	}
}

int state_changed_event_init(void);
void state_changed_event_destroy(void);

#endif
