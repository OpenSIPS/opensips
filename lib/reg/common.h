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
#include "save_flags.h"
#include "lookup.h"
#include "path.h"
#include "pn.h"

extern int reg_use_domain;
extern int tcp_persistent_flag;
extern char *tcp_persistent_flag_s;
extern int default_expires;
extern int min_expires;
extern int max_expires;

extern str realm_prefix;
extern str rcv_param;

extern usrloc_api_t ul;
extern struct tm_binds tmb;

/* common registrar modparams */
extern int expires_max_deviation;
extern int max_contacts;
extern int max_username_len;
extern int max_domain_len;
extern int max_aor_len;
extern int max_contact_len;

#define reg_modparams \
	{"max_contacts",          INT_PARAM, &max_contacts}, \
	{"max_username_len",      INT_PARAM, &max_username_len}, \
	{"max_domain_len",        INT_PARAM, &max_domain_len}, \
	{"max_aor_len",           INT_PARAM, &max_aor_len}, \
	{"max_contact_len",       INT_PARAM, &max_contact_len}, \
	{"expires_max_deviation", INT_PARAM, &expires_max_deviation}

/* common registrar init code */
int reg_init_globals(void);

static inline time_t randomize_expires(unsigned int expires_ts)
{
	time_t ret;

	if (!expires_max_deviation)
		return expires_ts;

	int expires_dur = expires_ts - get_act_time();
	int expires_adj = rand() % (expires_max_deviation * 2 + 1)
						- expires_max_deviation;

	expires_dur += expires_adj;
	if (expires_dur < min_expires)
		expires_dur = min_expires;

	if (max_expires && expires_dur > max_expires)
		expires_dur = max_expires;

	ret = expires_dur + get_act_time();
	LM_DBG("randomized expiry ts from %u to %lu (adj: %d/%d, "
	       "max_deviation: %d)\n", expires_ts, ret, expires_adj,
	       (int)ret - (int)expires_ts, expires_max_deviation);

	return ret;
}

#endif /* __LIB_REG_COMMON_H__ */
