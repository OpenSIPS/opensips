/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 * 2006-04-14  initial version (bogdan)
 * 2007-03-06  syncronized state machine added for dialog state. New tranzition
 *             design based on events; removed num_1xx and num_2xx (bogdan)
 */


#ifndef _DIALOG_DLG_HANDLERS_H_
#define _DIALOG_DLG_HANDLERS_H_

#include "../../parser/msg_parser.h"
#include "../../parser/parse_from.h"
#include "../../trim.h"
#include "../../str.h"
#include "../../pvar.h"
#include "../../ut.h"
#include "../tm/t_hooks.h"
#include "dlg_timer.h"

#define MAX_DLG_RR_PARAM_NAME 32

/* values for the sequential match mode */
#define SEQ_MATCH_STRICT_ID  0
#define SEQ_MATCH_FALLBACK   1
#define SEQ_MATCH_NO_ID      2

#define RR_DLG_PARAM_SIZE  (2*2*sizeof(int)+3+MAX_DLG_RR_PARAM_NAME)
#define DLG_SEPARATOR      '.'

struct _dlg_cseq{
	struct dlg_cell *dlg;
	str cseq;
};

typedef struct _dlg_cseq dlg_cseq_wrapper;

typedef int (*create_dlg_f)(struct sip_msg *req,int flags);

typedef void (*set_mod_flag_f)(struct dlg_cell *dlg, unsigned int flags);
typedef int (*is_mod_flag_set_f)(struct dlg_cell *dlg, unsigned int flags);

typedef void (*ref_dlg_f)(struct dlg_cell *dlg, unsigned int cnt);
typedef void (*unref_dlg_f)(struct dlg_cell *dlg, unsigned int cnt);

typedef str* (*get_rr_param_f)(void);

extern int ctx_timeout_idx;

#define ctx_timeout_get() \
	context_get_int(CONTEXT_GLOBAL,current_processing_ctx,ctx_timeout_idx)

#define ctx_timeout_set(_timeout) \
	context_put_int(CONTEXT_GLOBAL,current_processing_ctx, ctx_timeout_idx, _timeout)

/* IMPORTANT - as the default value for INT in context is 0, we shift the
   last leg idx with +1 to avoid having idx 0; this shifting is hidden by the
   get /  set functions, so transparent for the usage */
extern int ctx_lastdstleg_idx;

#define ctx_lastdstleg_get() \
	(context_get_int(CONTEXT_GLOBAL,current_processing_ctx,ctx_lastdstleg_idx)-1)

#define ctx_lastdstleg_set(_lastleg) \
	context_put_int(CONTEXT_GLOBAL,current_processing_ctx, ctx_lastdstleg_idx, _lastleg+1)

void init_dlg_handlers(int default_timeout);

void destroy_dlg_handlers();

int dlg_create_dialog(struct cell* t, struct sip_msg *req,unsigned int flags);

void dlg_onreq(struct cell* t, int type, struct tmcb_params *param);

void dlg_onroute(struct sip_msg* req, str *rr_param, void *param);

void dlg_ontimeout( struct dlg_tl *tl);

typedef int (*validate_dialog_f) (struct sip_msg* req, struct dlg_cell *dlg);
int dlg_validate_dialog( struct sip_msg* req, struct dlg_cell *dlg);

typedef int (*fix_route_dialog_f) (struct sip_msg *req,struct dlg_cell *dlg);
int fix_route_dialog(struct sip_msg *req,struct dlg_cell *dlg);

int terminate_dlg(unsigned int h_entry, unsigned int h_id,str *reason);
typedef int (*terminate_dlg_f)(unsigned int h_entry, unsigned int h_id,str *reason);

void unreference_dialog(void *dialog);

static inline int parse_dlg_rr_param(char *p, char *end,
								unsigned int *h_entry, unsigned int *h_id)
{
	char *s;

	for ( s=p ; p<end && *p!=DLG_SEPARATOR ; p++ );
	if (*p!=DLG_SEPARATOR) {
		LM_ERR("malformed rr param '%.*s'\n", (int)(long)(end-s), s);
		return -1;
	}

	if ( reverse_hex2int( s, p-s, h_entry)<0 ) {
		LM_ERR("invalid hash entry '%.*s'\n", (int)(long)(p-s), s);
		return -1;
	}

	if ( reverse_hex2int( p+1, end-(p+1), h_id)<0 ) {
		LM_ERR("invalid hash id '%.*s'\n", (int)(long)(end-(p+1)), p+1 );
		return -1;
	}

	return 0;
}

static inline int pre_match_parse( struct sip_msg *req, str *callid,
														str *ftag, str *ttag)
{
	if (parse_headers(req,HDR_CALLID_F|HDR_TO_F|HDR_FROM_F,0)<0 || !req->callid ||
	!req->to || !req->from) {
		LM_ERR("bad request or missing CALLID/TO hdr :-/\n");
		return -1;
	}

	if (get_to(req)->tag_value.len==0) {
		/* out of dialog request with preloaded Route headers; ignore. */
		return -1;
	}

	if (parse_from_header(req)<0 || get_from(req)->tag_value.len==0) {
		LM_ERR("failed to get From header(%.*s) (hdr=%p,parsed=%p,tag_len=%d) "
			"callid=<%.*s>\n",req->from->body.len, req->from->body.s,
			req->from, req->from?req->from->parsed:NULL,
			req->from?(req->from->parsed?get_from(req)->tag_value.len:0):0,
			req->callid->body.len, req->callid->body.s);
		return -1;
	}

	/* callid */
	*callid = req->callid->body;
	trim(callid);
	/* to tag */
	*ttag = get_to(req)->tag_value;
	/* from tag */
	*ftag = get_from(req)->tag_value;
	return 0;
}

int test_and_set_dlg_flag(struct dlg_cell *dlg, unsigned long index,
		unsigned long value);
#endif
