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
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 *
 */

#ifndef _B2BL_ENT_STORAGE_H
#define _B2BL_ENT_STORAGE_H

#include "../b2b_entities/b2be_load.h"

#define REPL_TUPLE_NO_INFO 0
#define REPL_TUPLE_NEW 1
#define REPL_TUPLE_UPDATE 2
#define STORAGE_ONLY_VALS 3

#define TUPLE_NO_REPL 0
#define TUPLE_REPL_SENT 1
#define TUPLE_REPL_RECV 2

void entity_event_trigger(enum b2b_entity_type etype, str *entity_key,
	str *b2bl_key, enum b2b_event_type event_type, bin_packet_t *storage,
	int backend);

void entity_event_received(enum b2b_entity_type etype, str *entity_key,
	str *b2bl_key, enum b2b_event_type event_type, bin_packet_t *storage,
	int backend);

#endif