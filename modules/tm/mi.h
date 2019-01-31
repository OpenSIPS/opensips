/*
 * Header file for TM MI functions
 *
 * Copyright (C) 2006 Voice Sistem SRL
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
 *  2006-12-04  created (bogdan)
 */


#ifndef _TM_MI_H_
#define _TM_MI_H_

#include "../../mi/mi.h"

#define MI_TM_UAC      "t_uac_dlg"
#define MI_TM_CANCEL   "t_uac_cancel"
#define MI_TM_HASH     "t_hash"
#define MI_TM_REPLY    "t_reply"

mi_response_t *mi_tm_uac_dlg_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_tm_uac_dlg_2(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_tm_uac_dlg_3(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_tm_uac_dlg_4(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_tm_uac_dlg_5(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_tm_uac_dlg_6(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_tm_uac_dlg_7(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_tm_uac_dlg_8(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_tm_cancel(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_tm_hash(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_tm_reply_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_tm_reply_2(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_tm_reply_3(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_tm_reply_4(const mi_params_t *params,
								struct mi_handler *async_hdl);

#endif
