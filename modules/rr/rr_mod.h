/*
 * Record-Route & Route module interface
 *
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
 * History:
 * ---------
 * 2003-03-15 License added (janakj)
 */

/*!
 * \file
 * \brief Route & Record-Route module interface
 * \ingroup rr
 */

#ifndef RR_MOD_H
#define RR_MOD_H

#ifdef ENABLE_USER_CHECK
#include "../../str.h"
extern str i_user;
#endif

extern int append_fromtag;
extern int enable_double_rr;
extern int add_username;
extern int enable_socket_mismatch_warning;

#endif /* RR_MOD_H */
