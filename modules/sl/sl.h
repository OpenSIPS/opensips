/*
 * sl module
 *
 * Copyright (C) 2006 Voice Sistem
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
 *  2006-02-06  original version (bogdan)
 */

#ifndef _SL_H_
#define _SL_H_

#include "../../statistics.h"

/* module parameter */
extern int sl_enable_stats;

/* statistic variables */
extern stat_var *tx_1xx_rpls;
extern stat_var *tx_2xx_rpls;
extern stat_var *tx_3xx_rpls;
extern stat_var *tx_4xx_rpls;
extern stat_var *tx_5xx_rpls;
extern stat_var *tx_6xx_rpls;
extern stat_var *sent_rpls;
extern stat_var *sent_err_rpls;
extern stat_var *rcv_acks;


#endif
