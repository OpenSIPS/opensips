/*
 * Copyright (C) 2010 Sippy Software, Inc., http://www.sippysoft.com
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
 */

#ifndef _NATHELPER_CALLBACKS_H
#define _NATHELPER_CALLBACKS_H

#include "../../parser/msg_parser.h"
#include "../../msg_callbacks.h"

void rtpproxy_pre_fwd(struct sip_msg *, cb_type_t, void *, void *);
void rtpproxy_pre_fwd_free(struct sip_msg *, cb_type_t, void *, void *);

#endif
