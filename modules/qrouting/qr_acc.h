/*
 * Copyright (C) 2014 OpenSIPS Foundation
 * Copyright (C) 2020 OpenSIPS Solutions
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
 */

#ifndef __QR_ACC_H__
#define __QR_ACC_H__

#include <time.h>

#include "../tm/tm_load.h"
#include "../dialog/dlg_load.h"
#include "qr_stats.h"
#include "../drouting/dr_api.h"

#define QR_TM_180_RCVD (1<<0)

extern struct tm_binds tmb;
extern struct dlg_binds dlgcb;
extern struct dr_binds drb;

typedef struct qr_trans_prop {
	qr_gw_t *gw;
	gen_lock_t *prop_lock;
	struct timespec invite;
	char state;
} qr_trans_prop_t;

typedef struct qr_dialog_prop {
	qr_gw_t *gw;
	struct timespec time_200OK;
} qr_dialog_prop_t;

void update_gw_stats(qr_gw_t *);
void update_grp_stats(qr_grp_t );
void qr_acc(void *param);
void qr_check_reply_tmcb(struct cell*, int ,struct tmcb_params*);
void show_stats(qr_gw_t *gw);

#endif
