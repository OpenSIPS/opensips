/*
 * Copyright (C) 2001-2003 FhG Fokus
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
 *
 * History:
 * -------
 * 2003-06-24: file created (bogdan)
 */

#ifndef _CPL_LOADER_H
#define _CPL_LOADER_H
#include "../../mi/mi.h"

mi_response_t *mi_cpl_load(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_cpl_remove(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_cpl_get(const mi_params_t *params,
								struct mi_handler *async_hdl);

#endif





