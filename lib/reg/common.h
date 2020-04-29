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

#ifndef __LIB_REG_COMMON_H__
#define __LIB_REG_COMMON_H__

#include "../../modules/tm/tm_load.h"
#include "../../modules/usrloc/usrloc.h"

#include "config.h"
#include "rerrno.h"
#include "sip_msg.h"
#include "ci.h"
#include "lookup.h"
#include "pn.h"

extern int reg_use_domain;
extern int tcp_persistent_flag;
extern char *tcp_persistent_flag_s;
extern int default_expires;
extern int min_expires;
extern int max_expires;
extern str gruu_secret;
extern str default_gruu_secret;

extern int attr_avp_name;

extern str realm_prefix;
extern str rcv_param;

extern usrloc_api_t ul;
extern struct tm_binds tmb;

/* common registrar init code */
int reg_init_globals(void);

#endif /* __LIB_REG_COMMON_H__ */
