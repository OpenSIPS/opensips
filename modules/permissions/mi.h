/*
 * Header file for permissions MI functions
 *
 * Copyright (C) 2006 Juha Heinanen
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


#ifndef _PERMISSIONS_MI_H_
#define _PERMISSIONS_MI_H_


#include "../../mi/mi.h"


#define MI_ADDRESS_RELOAD "address_reload"
#define MI_ADDRESS_DUMP "address_dump"

#define MI_SUBNET_DUMP "subnet_dump"

#define MI_ALLOW_URI "allow_uri"

mi_response_t *mi_address_reload(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_address_reload_1(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_address_dump(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_address_dump_1(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_subnet_dump(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_subnet_dump_1(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_allow_uri(const mi_params_t *params,
								struct mi_handler *async_hdl);

#endif
