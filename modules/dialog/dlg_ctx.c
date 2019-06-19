/*
 * Copyright (C) 2019 OpenSIPS Solutions
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
 */

#include "dlg_ctx.h"

int dlg_ctx_register_int(context_destroy_f f)
{
	return context_register_int(CONTEXT_DIALOG, f);
}

int dlg_ctx_register_str(context_destroy_f f)
{
	return context_register_str(CONTEXT_DIALOG, f);
}

int dlg_ctx_register_ptr(context_destroy_f f)
{
	return context_register_ptr(CONTEXT_DIALOG, f);
}

void dlg_ctx_put_int(struct dlg_cell *dlg, int pos, int data)
{
	context_put_int(CONTEXT_DIALOG, context_of(dlg), pos, data);
}

void dlg_ctx_put_str(struct dlg_cell *dlg, int pos, str *data)
{
	context_put_str(CONTEXT_DIALOG, context_of(dlg), pos, data);
}

void dlg_ctx_put_ptr(struct dlg_cell *dlg, int pos, void *data)
{
	context_put_ptr(CONTEXT_DIALOG, context_of(dlg), pos, data);
}

int dlg_ctx_get_int(struct dlg_cell *dlg, int pos)
{
	return context_get_int(CONTEXT_DIALOG, context_of(dlg), pos);
}

str *dlg_ctx_get_str(struct dlg_cell *dlg, int pos)
{
	return context_get_str(CONTEXT_DIALOG, context_of(dlg), pos);
}

void *dlg_ctx_get_ptr(struct dlg_cell *dlg, int pos)
{
	return context_get_ptr(CONTEXT_DIALOG, context_of(dlg), pos);
}
