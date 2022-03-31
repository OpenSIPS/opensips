/*
 * Copyright (C) 2022 - OpenSIPS Solutions
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
 *
 */

#ifndef _MSRP_RELAY_AUTH_H_
#define _MSRP_RELAY_AUTH_H_

#include "../../parser/digest/digest.h"
#include "../../lib/digest_auth/digest_auth.h"
#include "../../parser/digest/digest_parser.h"
#include "../../lib/digest_auth/dauth_calc.h"
#include "../../lib/digest_auth/dauth_nonce.h"

#define DEFAULT_NONCE_EXPIRE 30
#define DEFAULT_AUTH_EXPIRES 1800

#define REASON_OK_STR "OK"

int init_digest_auth(void);
int init_digest_auth_child(void);
void destroy_digest_auth(void);
int handle_msrp_auth_req(struct msrp_msg *req, struct msrp_url *my_url);

extern pv_spec_t user_spec;
extern pv_spec_t realm_spec;
extern pv_spec_t passwd_spec;

extern int auth_calc_ha1;
extern unsigned int nonce_expire;
extern unsigned int auth_expires;
extern unsigned int auth_min_expires;
extern unsigned int auth_max_expires;

extern str default_auth_realm;

#endif  /* _MSRP_RELAY_AUTH_H_ */