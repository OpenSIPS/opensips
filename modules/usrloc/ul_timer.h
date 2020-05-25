/*
 * Copyright (C) 2001-2003 FhG Fokus
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __UL_TIMER_H__
#define __UL_TIMER_H__

#include "../../timer.h"

#include "ucontact.h"

extern int timer_interval;
extern int ct_refresh_timer;

int ul_init_timers(void);
void start_refresh_timer(ucontact_t *ct);
void stop_refresh_timer(ucontact_t *ct);

timer_function trigger_ct_refreshes;

#endif /* __UL_TIMER_H__ */
