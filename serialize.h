/*
 * sequential forking implementation
 *
 * Copyright (C) 2005 Juha Heinanen
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
 * -------
 *  2005-11-29 splitted from lcr module (bogdan)
 */

/*!
 * \file serialize.h
 * \brief Sequential forking implementation
 */


#ifndef _CORE_SERIALIZE_H_
#define _CORE_SERIALIZE_H_

#include "parser/msg_parser.h"


int init_serialization();


/*! \brief converts the destination set (for parallel forking) into AVPS used
 * for serial forking.
 */
int serialize_branches(struct sip_msg *msg, int clean_before, int keep_order);


/*! \brief gets the next branches for serial forking
 */
int next_branches( struct sip_msg *msg );

#endif
