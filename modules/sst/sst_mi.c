/*
 * Copyright (C) 2008 SOMA Networks, Inc.
 * Written By Ovidiu Sas (osas)
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 * USA
 *
 * History:
 * --------
 * 2008-04-11 initial version (osas)
 */

#include "../../ut.h"
#include "../../mi/mi.h"
#include "../dialog/dlg_load.h"
#include "sst_handlers.h"

/**
 * The dialog mi helper function.
 */
void sst_dialog_mi_context_CB(struct dlg_cell* did, int type, struct dlg_cb_params * params)
{
	sst_info_t* sst_info = (sst_info_t*)*(params->param);
	mi_item_t *context_item = (mi_item_t *)(params->dlg_data);
	mi_item_t *sst_item;

	sst_item = add_mi_object(context_item, MI_SSTR("sst"));
	if (!sst_item)
		return;

	if (add_mi_number(sst_item, MI_SSTR("requester_flags"),
		sst_info->requester) < 0)

	if (add_mi_number(sst_item, MI_SSTR("supported_flags"),
		sst_info->supported) < 0)

	if (add_mi_number(sst_item, MI_SSTR("interval"),
		sst_info->interval) < 0)

	return;
}

