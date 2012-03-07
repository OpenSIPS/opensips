/*
 * $Id: dlg_tophiding.h $
 *
 * dialog module - basic support for dialog tracking
 *
 * Copyright (C) 2011 Free Software Fundation
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
 *  2011-05-02  initial version (Anca Vamanu)
 */

#ifndef _DIALOG_DLG_TH_H_
#define _DIALOG_DLG_TH_H_

#include "dlg_hash.h"

int w_topology_hiding(struct sip_msg *req);
int dlg_th_onroute(struct dlg_cell *dlg, struct sip_msg *req, int dir);
int dlg_th_onreply(struct dlg_cell *dlg, struct sip_msg *rpl, int init_req, int dir);

#endif
