/*
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

#ifndef __UL_EVI_H__
#define __UL_EVI_H__

#include "urecord.h"

/* AoR event IDs */
extern event_id_t ei_ins_id;
extern event_id_t ei_del_id;

/* Contact event IDs */
extern event_id_t ei_c_ins_id;
extern event_id_t ei_c_del_id;
extern event_id_t ei_c_update_id;
extern event_id_t ei_c_latency_update_id;

int ul_event_init(void);
void ul_raise_event(event_id_t _e, struct urecord *_r);
void ul_raise_contact_event(event_id_t _e, struct ucontact *_c);

#endif /* __UL_EVI_H__ */
