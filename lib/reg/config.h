/*
 * Contact info packing functions
 *
 * Copyright (C) 2016-2017 OpenSIPS Solutions
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

#ifndef __LIB_REG_CONFIG__
#define __LIB_REG_CONFIG__

/* if DB support is used, this values must not exceed the
 * storage capacity of the DB columns! See db/schema/entities.xml */
#define CONTACT_MAX_SIZE       255
#define RECEIVED_MAX_SIZE      255
#define USERNAME_MAX_SIZE      64
#define DOMAIN_MAX_SIZE        64
#define CALLID_MAX_SIZE        255
#define UA_MAX_SIZE            255

#define MAX_AOR_LEN            256

#define PATH_MODE_STRICT	2
#define PATH_MODE_LAZY		1
#define PATH_MODE_OFF		0

/* save() flags which correspond to a char flag */
#define REG_SAVE_MEMORY_FLAG           (1<<0)
#define REG_SAVE_NOREPLY_FLAG          (1<<1)
#define REG_SAVE_SOCKET_FLAG           (1<<2)
#define REG_SAVE_PATH_STRICT_FLAG      (1<<3)
#define REG_SAVE_PATH_LAZY_FLAG        (1<<4)
#define REG_SAVE_PATH_OFF_FLAG         (1<<5)
#define REG_SAVE_PATH_RECEIVED_FLAG    (1<<6)
#define REG_SAVE_FORCE_REG_FLAG        (1<<7)
#define REG_SAVE_PATH_FLAG   (REG_SAVE_PATH_STRICT_FLAG|\
			REG_SAVE_PATH_LAZY_FLAG|REG_SAVE_PATH_OFF_FLAG)
#define REG_SAVE_REQ_CT_ONLY_FLAG      (1<<8)

/* save() flags which are internally set, based on the SIP request */
#define REG_SAVE__PN_ON_FLAG           (1<<9)

#endif /* __LIB_REG_CONFIG__ */
