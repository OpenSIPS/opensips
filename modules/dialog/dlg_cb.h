/*
 * $Id$
 *
 * Copyright (C) 2006 Voice Sistem SRLs
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
 * 2006-04-11  initial version (bogdan)
 * 2008-04-04  added direction reporting in dlg callbacks (bogdan)
 * 2008-04-14  added new type of callback to be triggered when dialogs are
 *              loaded from DB (bogdan)
 * 2008-04-17  added new type of callback to be triggered right before the
 *              dialog is destroyed (deleted from memory) (bogdan)
 */

#ifndef _DIALOG_DLG_CB_H_
#define _DIALOG_DLG_CB_H_

#include "../../parser/msg_parser.h"

struct dlg_cell;

struct dlg_cb_params {
	struct sip_msg* msg;       /* sip msg related to the callback event */
	unsigned int direction;    /* direction of the sip msg */
	void *dlg_data;            /* generic paramter, specific to callback */
	void **param;              /* parameter passed at callback registration*/
};

/* callback function prototype */
typedef void (dialog_cb) (struct dlg_cell* dlg, int type,
		struct dlg_cb_params * params);
/* function to free the callback param */
typedef void (param_free_cb) (void *param);
/* register callback function prototype */
typedef int (*register_dlgcb_f)(struct dlg_cell* dlg, int cb_types,
		dialog_cb f, void *param, param_free_cb ff);


#define DLGCB_LOADED          (1<<0)
#define DLGCB_CREATED         (1<<1)
#define DLGCB_FAILED          (1<<2)
#define DLGCB_CONFIRMED       (1<<3)
#define DLGCB_REQ_WITHIN      (1<<4)
#define DLGCB_TERMINATED      (1<<5)
#define DLGCB_EXPIRED         (1<<6)
#define DLGCB_EARLY           (1<<7)
#define DLGCB_RESPONSE_FWDED  (1<<8)
#define DLGCB_RESPONSE_WITHIN (1<<9)
#define DLGCB_MI_CONTEXT      (1<<10)
#define DLGCB_DESTROY         (1<<11)
#define DLGCB_SAVED           (1<<12)

struct dlg_callback {
	int types;
	dialog_cb* callback;
	void *param;
	param_free_cb* callback_param_free;
	struct dlg_callback* next;
};


struct dlg_head_cbl {
	struct dlg_callback *first;
	int types;
};


void destroy_dlg_callbacks(unsigned int type);

void destroy_dlg_callbacks_list(struct dlg_callback *cb);

void mark_dlg_loaded_callbacks_run(void);

int register_dlgcb( struct dlg_cell* dlg, int types, dialog_cb f, void *param, param_free_cb ff);

void run_create_callbacks(struct dlg_cell *dlg, struct sip_msg *msg);

void run_dlg_callbacks( int type , struct dlg_cell *dlg, struct sip_msg *msg,
		unsigned int dir, void *dlg_data);

void run_load_callbacks( void );

void run_load_callback_per_dlg(struct dlg_cell *dlg);

#endif
