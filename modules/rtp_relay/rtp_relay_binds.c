/*
 * Copyright (C) 2021 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "rtp_relay_load.h"

int rtp_relay_load(struct rtp_relay_binds *binds)
{
	binds->get_ctx = rtp_relay_get_context;
	binds->get_ctx_dlg = rtp_relay_get_context_dlg;
	binds->copy_offer = rtp_relay_copy_offer;
	binds->copy_answer = rtp_relay_copy_answer;
	binds->copy_delete = rtp_relay_copy_delete;
	return 1;
}
