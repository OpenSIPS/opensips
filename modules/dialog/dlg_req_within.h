/*
 * Copyright (C) 2008-2020 OpenSIPS Solutions
 * Copyright (C) 2007 Voice System SRL
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
*/


#ifndef DLG_REQUEST_WITHIN_H
#define DLG_REQUEST_WITHIN_H

#include "../../statistics.h"
#include "../../str.h"
#include "../../context.h"
#include "../../mi/mi.h"
#include "../tm/tm_load.h"
#include "dlg_hash.h"

#define MAX_FWD			"70"
#define MAX_SIZE		256
#define RCV_BYE_REPLY	1

#define MI_DIALOG_NOT_FOUND 		"Requested Dialog not found"
#define MI_DIALOG_BACKUP_ERR		"Node is backup for requested dialog"
#define MI_DLG_OPERATION_ERR		"Operation failed"

#define DLG_PING_SUCCESS  0
#define DLG_PING_PENDING  1
#define DLG_PING_FAIL     2

extern struct tm_binds d_tmb;

typedef void (dlg_request_callback)(struct cell *t,int type,
					struct tmcb_params* ps);
typedef void (dlg_release_func)(void *param);

static inline int push_new_processing_context( struct dlg_cell *dlg,
								context_p *old_ctx, context_p **new_ctx,
								struct sip_msg **fake_msg)
{
	static context_p my_ctx = NULL;

	*old_ctx = current_processing_ctx;
	if (my_ctx==NULL) {
		my_ctx = context_alloc(CONTEXT_GLOBAL);
		if (my_ctx==NULL) {
			LM_ERR("failed to alloc new ctx in pkg\n");
			return -1;
		}
	}
	if (current_processing_ctx==my_ctx) {
		LM_CRIT("BUG - nested setting of my_ctx\n");
		return -1;
	}

	if (fake_msg) {
		*fake_msg = get_dummy_sip_msg();
		if (*fake_msg == NULL) {
			LM_ERR("cannot create new dummy sip request\n");
			return -1;
		}
	}

	/* reset the new to-be-used CTX */
	memset( my_ctx, 0, context_size(CONTEXT_GLOBAL) );

	/* set the new CTX as current one */
	current_processing_ctx = my_ctx;

	/* store the value from the newly created context */
	*new_ctx = &my_ctx;

	/* set this dialog in the ctx */
	ctx_dialog_set(dlg);
	/* ref it, and it will be unreffed in context destroy */
	ref_dlg(dlg, 1);

	return 0;
}

#define CONTACT_STR_START "Contact: <"
#define CONTACT_STR_START_LEN (sizeof(CONTACT_STR_START)-1)

#define CONTACT_STR_END ">\r\n"
#define CONTACT_STR_END_LEN (sizeof(CONTACT_STR_END)-1)

#define CONTENT_TYPE_STR_START "Content-Type: "
#define CONTENT_TYPE_STR_START_LEN (sizeof(CONTENT_TYPE_STR_START)-1)

#define CONTENT_TYPE_STR_END "\r\n"
#define CONTENT_TYPE_STR_END_LEN (sizeof(CONTENT_TYPE_STR_END)-1)

static inline int dlg_get_leg_hdrs(struct dlg_cell *dlg,
		int sleg, int dleg, str *ct, str *hdrs, str *out)
{
	char *p;
	if (dlg->legs[dleg].adv_contact.len)
		out->len =  dlg->legs[dleg].adv_contact.len;
	else
		out->len = CONTACT_STR_START_LEN +
			dlg->legs[sleg].contact.len +
			CONTACT_STR_END_LEN;
	if (ct && ct->len)
		out->len += CONTENT_TYPE_STR_START_LEN + ct->len + CONTENT_TYPE_STR_END_LEN;
	if (hdrs && hdrs->len)
		out->len += hdrs->len;
	out->s = pkg_malloc(out->len);
	if (!out->s) {
		LM_ERR("No more pkg for extra headers \n");
		return 0;
	}

	p = out->s;
	if (dlg->legs[dleg].adv_contact.len) {
		memcpy(p,dlg->legs[dleg].adv_contact.s,
				dlg->legs[dleg].adv_contact.len);

		p+= dlg->legs[dleg].adv_contact.len;
	} else {
		memcpy(p,CONTACT_STR_START,CONTACT_STR_START_LEN);
		p += CONTACT_STR_START_LEN;
		memcpy(p,dlg->legs[sleg].contact.s,
				dlg->legs[sleg].contact.len);

		p += dlg->legs[sleg].contact.len;
		memcpy(p,CONTACT_STR_END,CONTACT_STR_END_LEN);
		p += CONTACT_STR_END_LEN;
	}
	if (ct && ct->len) {
		memcpy(p,CONTENT_TYPE_STR_START, CONTENT_TYPE_STR_START_LEN);
		p += CONTENT_TYPE_STR_START_LEN;
		memcpy(p, ct->s, ct->len);
		p += ct->len;
		memcpy(p,CONTENT_TYPE_STR_END, CONTENT_TYPE_STR_END_LEN);
		p += CONTENT_TYPE_STR_END_LEN;
	}

	if (hdrs && hdrs->len) {
		memcpy(p, hdrs->s, hdrs->len);
		p += hdrs->len;
	}

	return 1;
}
#undef CONTACT_STR_START
#undef CONTACT_STR_START_LEN
#undef CONTACT_STR_END
#undef CONTACT_STR_END_LEN
#undef CONTENT_TYPE_STR_START
#undef CONTENT_TYPE_STR_START_LEN
#undef CONTENT_TYPE_STR_END
#undef CONTENT_TYPE_STR_END_LEN


int dlg_end_dlg(struct dlg_cell *dlg, str *extra_hdrs, int send_byes);

mi_response_t *mi_terminate_dlg_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_terminate_dlg_2(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_send_sequential_dlg(const mi_params_t *params,
								struct mi_handler *async_hdl);

int send_leg_msg(struct dlg_cell *dlg,str *method,int src_leg,int dst_leg,
		str *hdrs,str *body,dlg_request_callback func,void *param,
		dlg_release_func release,char *reply_marker);
int dlg_handle_seq_reply(struct dlg_cell *dlg, struct sip_msg* rpl,
		int statuscode, int leg, int is_reinvite_rpl);
#endif
