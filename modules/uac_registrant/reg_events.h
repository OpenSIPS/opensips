/*
 * Copyright (C) 2025 OpenSIPS Project
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
 * Foundation Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#ifndef _UAC_REGISTRANT_EVENTS_H_
#define _UAC_REGISTRANT_EVENTS_H_

#include "reg_records.h"

int init_registrant_events(void); 
void raise_registering_event(reg_record_t *rec);
void raise_authenticating_event(reg_record_t *rec);
void raise_registered_event(reg_record_t *rec);
void raise_register_timeout_event(reg_record_t *rec);
void raise_internal_error_event(reg_record_t *rec);
void raise_wrong_credentials_event(reg_record_t *rec);
void raise_registrar_error_event(reg_record_t *rec);
void raise_unregistering_event(reg_record_t *rec);
void raise_authenticating_unregister_event(reg_record_t *rec);

#endif
