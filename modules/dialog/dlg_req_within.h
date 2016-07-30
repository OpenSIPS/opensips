/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 * 2007-07-10  initial version (ancuta)
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
#define MI_DIALOG_NOT_FOUND_LEN 	(sizeof(MI_DIALOG_NOT_FOUND)-1)
#define MI_DLG_OPERATION_ERR		"Operation failed"
#define MI_DLG_OPERATION_ERR_LEN	(sizeof(MI_DLG_OPERATION_ERR)-1)

extern struct tm_binds d_tmb;
extern int dlg_enable_stats;
extern stat_var * active_dlgs;

typedef void (dlg_request_callback)(struct cell *t,int type,
					struct tmcb_params* ps);
typedef void (dlg_release_func)(void *param);

static inline int push_new_processing_context( struct dlg_cell *dlg,
								context_p *old_ctx, context_p **new_ctx,
								struct sip_msg **fake_msg)
{
	static context_p my_ctx = NULL;
	static struct sip_msg *my_msg = NULL;

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
		if (my_msg==NULL) {
			my_msg = (struct sip_msg*)pkg_malloc(sizeof(struct sip_msg));
			if (my_msg==NULL) {
				LM_ERR("No more pkg memory for a a fake msg\n");
				return -1;
			}
		} else {
			free_sip_msg(my_msg);
		}
		memset(my_msg, 0, sizeof(struct sip_msg));
		my_msg->first_line.type = SIP_REQUEST;
		my_msg->first_line.u.request.method.s= "DUMMY";
		my_msg->first_line.u.request.method.len= 5;
		my_msg->first_line.u.request.uri.s= "sip:user@domain.com";
		my_msg->first_line.u.request.uri.len= 19;
		my_msg->rcv.src_ip.af = AF_INET;
		my_msg->rcv.dst_ip.af = AF_INET;
		*fake_msg = my_msg;
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


int dlg_end_dlg(struct dlg_cell *dlg, str *extra_hdrs);

struct mi_root * mi_terminate_dlg(struct mi_root *cmd_tree, void *param );

int send_leg_msg(struct dlg_cell *dlg,str *method,int src_leg,int dst_leg,
		str *hdrs,str *body,dlg_request_callback func,void *param,
		dlg_release_func release,char *reply_marker);
#endif
