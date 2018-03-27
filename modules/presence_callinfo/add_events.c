/*
 * Add "call-info" event to presence module
 *
 * Copyright (C) 2010 Ovidiu Sas
 * Copyright (C) 2013 OpenSIPS Solutions
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
 *  2010-03-11  initial version (osas)
 *  2010-07-13  added support for SCA Broadsoft with dialog module (bogdan)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../timer.h"
#include "../../ut.h"
#include "../../parser/parse_call_info.h"
#include "../presence/event_list.h"
#include "presence_callinfo.h"
#include "sca_hash.h"
#include "add_events.h"


extern int call_info_timeout_notification;
extern int line_seize_timeout_notification;


static str extra_hdrs[] = {
	str_init("Call-Info"),
	{NULL,0},
};

static pres_ev_t *callinfo_event = NULL;
static pres_ev_t *seize_event = NULL;

static str dummy_ci_hdr1 = str_init("Call-Info: <");
static str dummy_ci_hdr2 = str_init(">;appearance-index=*;appearance-state=idle\r\n");



/*
 * event specific publish handling - check if body format is ok
 */
static int callinfo_hdr_checker(struct sip_msg* msg, int* sent_reply)
{
	if (parse_headers(msg,HDR_EOH_F, 0) == -1) {
		LM_ERR("parsing headers\n");
		return -1;
	}

	if (!msg->call_info) {
		LM_ERR("No 'Call-Info' header\n");
		return -1;
	}
	if (0 != parse_call_info_header(msg)) {
		LM_ERR("Unable to parse Call-Info\n");
		return -1;
	}

	return 1;
}


/*
 * event specific extra headers builder - for empty notifications
 */
str* build_callinfo_dummy_header(str* pres_uri, str* extra_hdrs)
{
	if (extra_hdrs->s == NULL)
	{
		extra_hdrs->s = (char*)pkg_malloc( dummy_ci_hdr1.len +
			pres_uri->len + dummy_ci_hdr2.len);
		if (extra_hdrs->s == NULL)
		{
			LM_ERR("oom: no dummy header\n");
			return NULL;
		}
		memcpy(extra_hdrs->s, dummy_ci_hdr1.s, dummy_ci_hdr1.len);
		extra_hdrs->len = dummy_ci_hdr1.len;
		memcpy(extra_hdrs->s+extra_hdrs->len, pres_uri->s, pres_uri->len);
		extra_hdrs->len += pres_uri->len;
		memcpy(extra_hdrs->s+extra_hdrs->len, dummy_ci_hdr2.s, dummy_ci_hdr2.len);
		extra_hdrs->len += dummy_ci_hdr2.len;
	}
	return NULL;
}



/* assumes the Call-INFO hdr is parsed ! */
unsigned int get_appearance_index(struct sip_msg *msg)
{
	struct to_param *top;
	unsigned int idx;

	top = get_call_info(msg)->call_info_body.param_lst;
	for ( ; top ; top=top->next) {
		if ( (top->name.len==CI_hdr_AI_param_len) &&
		(memcmp(CI_hdr_AI_param_s,top->name.s,CI_hdr_AI_param_len)==0) ) {
			/* found */
			if ( str2int( &top->value, &idx)<0 ) {
				LM_ERR("appearance-index <%.*s> param is not numerical\n",
					top->value.len, top->value.s);
				return 0;
			}
			return idx;
		}
	}

	LM_ERR("Call-INFO hdr <%.*s> does not contain 'appearance-index' parameter\n",
		msg->call_info->body.len,msg->call_info->body.s);
	return 0;
}


/*
 * Line must be locked, returned unlocked !
 */
int terminate_line_sieze(struct sca_line *sca)
{
	/* do we have a valid seize on the line ? */
	if (sca->seize_state==0 || sca->seize_expires<get_ticks() )
		return 0;

	sca->seize_state = 0;
	sca->seize_expires = 0;

	unlock_sca_line(sca);

	return pres.terminate_watchers( &sca->line, seize_event);
}


/* Function to be called under lock - extracts and saved in local buffers
 * the sca info that is needed for by "do_callinfo_publish" (as we need to
 * call this function without locking).
 * You need to take care and free the "user" string (only that one) !!!
 */
int extract_publish_data_from_line(struct sca_line *sca, str *user, str *host, str *etag, int *new)
{
	char *buf;

	buf = (char*)pkg_malloc( sca->user.len + sca->domain.len + MD5_LEN );
	if (buf==NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}

	user->s = buf ;
	user->len = sca->user.len;
	memcpy( user->s, sca->user.s, user->len);
	buf += user->len;

	host->s = buf ;
	host->len = sca->domain.len;
	memcpy( host->s, sca->domain.s, host->len);
	buf += host->len;

	etag->s = buf;
	etag->len = MD5_LEN;
	if (sca->etag.len==0) {
		MD5StringArray( sca->etag.s, &sca->line, 1);
		sca->etag.len = MD5_LEN;
		*new = 1;
	} else {
		*new = 0;
	}
	memcpy( etag->s, sca->etag.s, etag->len);

	return 0;
}


/* send the pusblish for the line - expects to get the line locked,
 * returnes the line unlocked */
int do_callinfo_publish(struct sca_line *sca)
{
	str user, host, etag, ci_hdr;
	presentity_t presentity;
	int new_etag;

	/* generate the new call-info line */
	ci_hdr.s = sca_print_line_status( sca, &ci_hdr.len );
	if (ci_hdr.s==NULL ||
	extract_publish_data_from_line(sca, &user, &host, &etag, &new_etag)<0){
		unlock_sca_line(sca);
		LM_ERR("failed to extract Call-INFO data for publishing\n");
	} else {
		unlock_sca_line(sca);
		/* do publish for callinfo */
		memset(&presentity, 0, sizeof(presentity_t));
		presentity.domain = host;
		presentity.user   = user;
		if (new_etag)
			presentity.new_etag   = etag;
		else
			presentity.old_etag   = etag;
		presentity.event  = callinfo_event;
		presentity.expires = callinfo_event->default_expires;
		presentity.received_time= (int)time(NULL);
		presentity.extra_hdrs = &ci_hdr;
		presentity.etag_new = new_etag;
		if ( pres.update_presentity( &presentity )<0 )
			LM_ERR("failed to update presentity\n");
		/* release memory from "extract_publish_data_from_line" */
		pkg_free(user.s);
	}

	/* release memory from "sca_print_line_status" */
	if (ci_hdr.s) pkg_free(ci_hdr.s);

	return 0;
}



/*
 * event specific SUBSCRIBE handling - check if body format is ok
 */
int lineseize_subs_handl(struct sip_msg* msg, struct subscription *subs, int *reply_code, str *reply_reason)
{
	str *line;
	struct sca_line *sca;
	unsigned int idx;
	int is_initial;
	int new_state;

	/* search for the Call-INFO hdr */
	if ( parse_call_info_header( msg )!=0 ) {
		LM_ERR("missing or bogus Call-Info header in SUBSCRIBE lineseize\n");
		*reply_code = 400;
		reply_reason->s = "Bad request";
		reply_reason->len = sizeof("Bad request")-1;
		return -1;
	}
	is_initial = (subs->to_tag.len==0)?1:0;

	idx = get_appearance_index(msg);
	if (idx==0) {
		LM_ERR("failed to extract index from Call-Info hdr\n");
		*reply_code = 400;
		reply_reason->s = "Bad request";
		reply_reason->len = sizeof("Bad request")-1;
		return -1;
	}

	/* get the name of the line -> the subscribed presentity */
	line = &subs->pres_uri;

	/* search for the line in the SCA hash */
	LM_DBG("searching for SCA <%.*s>, initial=%d\n",
		line->len,line->s,is_initial);
	if (subs->expires==0) {
		/* if un-subscribe, search without auto create */
		sca = get_sca_line(line, 0);
	} else {
		/* search with auto create (only if initial) */
		sca = get_sca_line(line, is_initial );
	}

	if (sca==NULL) {
		LM_DBG("SCA not found, expires=%d\n",subs->expires);
		if (subs->expires==0) {
			/* an unsubscribe from an inexisting list,
			   let presence deal with it, we do not really care */
			return 0;
		} else {
			/* for sure this is an internal error, default reply of
			   presence dore */
			return -1;
		}
	}

	LM_DBG("SCA found (%p), seizing (%d,%d), subs expires %d\n",
		sca, sca->seize_state,sca->seize_expires, subs->expires);

	new_state = 0;

	/* SCA found, careful now, it is locked !! */
	if (!is_initial) {

		/* sequential FIXME - some double check here? */
		if (subs->expires==0) {
			/* terminate the subscription */
			LM_DBG("seizing terminated by un-subscribe\n");
			sca->seize_state = 0;
			sca->seize_expires = 0;
			new_state = SCA_STATE_IDLE;
		} else {
			LM_DBG("seizing changed by re-subscribe\n");
			sca->seize_expires = get_ticks() + subs->expires;
		}

	} else {

		/* new SUBSCRIBE */
		if (sca->seize_state!=0) {
			/* already in seizing from a different subscrine */
			if (sca->seize_expires < get_ticks()) {
				/* old seizing still valid -> reject it */
				*reply_code = 480;
				reply_reason->s = "Temporarily Unavailable";
				reply_reason->len = sizeof("Temporarily Unavailable")-1;
				unlock_sca_line(sca);
				return -1;
			}
		}
		/* FIXME - check the seized idx is not already in a call */
		/* do the seizing */
		sca->seize_state = idx;
		sca->seize_expires = get_ticks() + subs->expires;

		new_state = SCA_STATE_SEIZED;

	}


	if (!new_state) {
		unlock_sca_line(sca);
		return 0;
	}

	/* push new state for the index and do the publishing */
	/* STILL LOCKED HERE !! */

	/* everything ok, change the state of the line and notify */
	set_sca_index_state( sca, idx, new_state);

	/* do publish for callinfo */
	do_callinfo_publish( sca );

	return 0;
}


/*
 * event specific extra headers builder - for empty notifications
 */
str* build_lineseize_notify_hdrs(str* pres_uri, str* extra_hdrs)
{
	struct sca_line *sca;
	unsigned int idx;
	int l;
	char *p;
	char *q;

	if (extra_hdrs->s!= NULL)
		return NULL;

	/* search for the SCA */
	sca = get_sca_line(pres_uri, 0);
	if (sca==NULL) {
		LM_CRIT("BUG? notify to line-seize but SCA (%.*s) not found\n",
			pres_uri->len, pres_uri->s);
		return NULL;
	}
	/* watch it!!!! SCA is locked now */
	idx = sca->seize_state;
	unlock_sca_line(sca);

	if (idx==0)
		return NULL;

	/* build the header */
	extra_hdrs->s = (char*)pkg_malloc( CI_hdr_name_len + 1 /*<*/
		+ pres_uri->len + 2 /*>;*/ + CI_hdr_AI_param_len + 1 /*=*/
		+ 5 /*idx*/ + 2 /*CRLF*/);
	if (extra_hdrs->s == NULL) {
		LM_ERR("no more pkg mem for the Call-Info hdr in Notify\n");
		return NULL;
	}
	p = extra_hdrs->s;
	memcpy( p, CI_hdr_name_s "<", CI_hdr_name_len+1);
	p += CI_hdr_name_len + 1;
	memcpy( p, pres_uri->s, pres_uri->len);
	p += pres_uri->len;
	memcpy( p, ">;" CI_hdr_AI_param_s "=", 3+CI_hdr_AI_param_len);
	p += 3 + CI_hdr_AI_param_len;
	q = int2str( (unsigned long)idx, &l );
	LM_DBG("index is <%.*s>\n",l,q);
	memcpy( p , q, l);
	p += l;
	memcpy( p, CRLF, CRLF_LEN);
	p += CRLF_LEN;

	extra_hdrs->len = p - extra_hdrs->s;
	LM_DBG("hdr is <%.*s>\n",extra_hdrs->len,extra_hdrs->s);

	return NULL;
}


int callinfo_add_events(void)
{
	pres_ev_t event;
	event_t ev;

	/* constructing call-info event */
	memset(&event, 0, sizeof(pres_ev_t));
	event.name.s = "call-info";
	event.name.len = 9;

	event.extra_hdrs = extra_hdrs;

	event.etag_not_new = 1;

	event.default_expires= 3600;
	event.mandatory_timeout_notification = call_info_timeout_notification;
	event.type = PUBL_TYPE;
	event.evs_publ_handl = callinfo_hdr_checker;

	/* register the dummy Call-Info header builder */
	event.build_empty_pres_info = build_callinfo_dummy_header;

	if (pres.add_event(&event) < 0) {
		LM_ERR("failed to add event \"call-info\"\n");
		return -1;
	}

	/* now search it back as we need the internal event structure */
	ev.parsed = EVENT_CALL_INFO;
	ev.text = event.name;
	callinfo_event = pres.search_event( &ev );
	if (callinfo_event==NULL) {
		LM_CRIT("BUG: failed to get back the registered CALL INFO event!\n");
		return -1;
	}


	/* constructing line-seize-info event */
	memset(&event, 0, sizeof(pres_ev_t));
	event.name.s = "line-seize";
	event.name.len = 10;

	event.default_expires= 15;
	event.mandatory_timeout_notification = line_seize_timeout_notification;
	event.type = PUBL_TYPE;
	if (no_dialog_support) {
		/* with no dialog, just check the Call-Info hdrs */
		event.evs_publ_handl = callinfo_hdr_checker;
	} else {
		/* with dialog, handle the subscribes */
		event.evs_subs_handl = lineseize_subs_handl;
		/* register the Call-Info builder for NOTIFIES */
		event.build_empty_pres_info = build_lineseize_notify_hdrs;
	}

	if (pres.add_event(&event) < 0) {
		LM_ERR("failed to add event \"line-seize\"\n");
		return -1;
	}

	/* now search it back as we need the internal event structure */
	ev.parsed = EVENT_LINE_SEIZE;
	ev.text = event.name;
	seize_event = pres.search_event( &ev );
	if (seize_event==NULL) {
		LM_CRIT("BUG: failed to get back the registered CALL INFO event!\n");
		return -1;
	}

	return 0;
}

