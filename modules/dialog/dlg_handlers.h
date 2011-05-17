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
 * 2007-03-06  syncronized state machine added for dialog state. New tranzition
 *             design based on events; removed num_1xx and num_2xx (bogdan)
 */


#ifndef _DIALOG_DLG_HANDLERS_H_
#define _DIALOG_DLG_HANDLERS_H_

#include "../../parser/msg_parser.h"
#include "../../str.h"
#include "../../pvar.h"
#include "../tm/t_hooks.h"
#include "dlg_timer.h"

#define MAX_DLG_RR_PARAM_NAME 32

/* values for the sequential match mode */
#define SEQ_MATCH_STRICT_ID  0
#define SEQ_MATCH_FALLBACK   1
#define SEQ_MATCH_NO_ID      2

struct _dlg_cseq{
	struct dlg_cell *dlg;
	str cseq;
};

typedef struct _dlg_cseq dlg_cseq_wrapper;

typedef int (*create_dlg_f)(struct sip_msg *req);

void init_dlg_handlers(char *rr_param, int dlg_flag,
		pv_spec_t *timeout_avp, int default_timeout,
		int seq_match_mode);

void destroy_dlg_handlers();

int dlg_create_dialog(struct cell* t, struct sip_msg *req,unsigned int flags);

void dlg_onreq(struct cell* t, int type, struct tmcb_params *param);

void dlg_onroute(struct sip_msg* req, str *rr_param, void *param);

void dlg_ontimeout( struct dlg_tl *tl);

int dlg_validate_dialog( struct sip_msg* req, struct dlg_cell *dlg);

int fix_route_dialog(struct sip_msg *req,struct dlg_cell *dlg);

int terminate_dlg(unsigned int h_entry, unsigned int h_id);
typedef int (*terminate_dlg_f)(unsigned int h_entry, unsigned int h_id);

#endif
