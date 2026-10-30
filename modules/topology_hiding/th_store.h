/*
 * Copyright (C) 2026 OpenSIPS Solutions
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
 */

#ifndef _TH_STORE_H
#define _TH_STORE_H

#include <stdint.h>

#include "../../str.h"
#include "../../parser/msg_parser.h"

/* '_' is outside the word64/word32 alphabets, so no inline thinfo value
 * can ever start with it */
#define TH_KEY_MARKER '_'
#define TH_KEY_LEN 16
#define TH_KEY_WIRE_LEN (1 + TH_KEY_LEN)

#define TH_STORE_DECIDE -1

extern str th_state_url;
extern int th_state_ttl;
extern int th_state_ttl_short;

int th_store_init(int stored_encoding);
int th_store_child_init(void);
void th_store_destroy(void);

int th_store_is_key(const str *val);
int th_store_wanted(struct sip_msg *msg, struct sip_msg *req, int store);

char *th_store_ct_suffix(struct sip_msg *msg, str *rr_set, uint16_t flags,
		const str *param_name, const str *pw, struct sip_msg *ttl_src,
		int *suffix_len);

int th_store_fetch(const str *wire);
int th_store_unpack(str *routes, str *contact, str *flags, str *sock);
void th_store_consumed(struct sip_msg *msg, const str *wire);

#endif
