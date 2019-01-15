/*
 * pua_mi module - MI pua module
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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

#ifndef _PUA_MI
#define _PUA_MI

mi_response_t *mi_pua_publish_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_pua_publish_2(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_pua_publish_3(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_pua_publish_4(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_pua_publish_5(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_pua_publish_6(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_pua_publish_7(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_pua_publish_8(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_pua_subscribe(const mi_params_t *params,
								struct mi_handler *async_hdl);

int mi_publ_rpl_cback(ua_pres_t* hentity, struct sip_msg* reply);

#endif
