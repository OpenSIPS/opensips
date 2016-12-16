/*
 * mid-registrar contact storing
 *
 * This module is intended to be used as a middle layer SIP component in
 * environments where a large proportion of SIP UAs (e.g. mobile devices)
 * register at high enough frequencies that they actually degrade the
 * performance of their registrars.
 *
 * Copyright (C) 2016 OpenSIPS Solutions
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
 *  2016-10-24 initial version (liviu)
 */

#ifndef __MID_REG_SAVE_
#define __MID_REG_SAVE_

#include "../../parser/msg_parser.h"

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

#define CONTACT_MAX_SIZE       255
#define RECEIVED_MAX_SIZE      255
#define USERNAME_MAX_SIZE      64
#define DOMAIN_MAX_SIZE        64
#define CALLID_MAX_SIZE        255
#define UA_MAX_SIZE            255

#define MAX_CONTACT_BUFFER 1024

#define E_INFO "P-Registrar-Error: "
#define E_INFO_LEN (sizeof(E_INFO) - 1)

#define CONTACT_BEGIN "Contact: "
#define CONTACT_BEGIN_LEN (sizeof(CONTACT_BEGIN) - 1)

#define Q_PARAM ";q="
#define Q_PARAM_LEN (sizeof(Q_PARAM) - 1)

#define EXPIRES_PARAM ";expires="
#define EXPIRES_PARAM_LEN (sizeof(EXPIRES_PARAM) - 1)

#define SIP_PROTO "sip:"
#define SIP_PROTO_SIZE (sizeof(SIP_PROTO) - 1)

#define SIP_INSTANCE ";+sip.instance="
#define SIP_INSTANCE_SIZE (sizeof(SIP_INSTANCE) - 1)

#define CONTACT_SEP ", "
#define CONTACT_SEP_LEN (sizeof(CONTACT_SEP) - 1)

int mid_reg_save(struct sip_msg *msg, char *dom, char *flags_gp,
                          char *to_uri_gp, char *expires_gp);

#endif /* __MID_REG_SAVE_ */
