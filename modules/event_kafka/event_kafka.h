/*
 * Copyright (C) 2011 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 */

#ifndef _EV_KAFKA_H_
#define _EV_KAFKA_H_

/* transport protocols name */
#define KAFKA_NAME	"kafka"
#define KAFKA_STR	{ KAFKA_NAME, sizeof(KAFKA_NAME) - 1}
/* module flag */
#define KAFKA_FLAG	(1 << 21)

#define PROP_KEY_NAME "key"
#define PROP_KEY_NAME_LEN (sizeof(PROP_KEY_NAME) - 1)
#define PROP_KEY_VAL "callid"
#define PROP_KEY_VAL_LEN (sizeof(PROP_KEY_VAL) - 1)

#endif
