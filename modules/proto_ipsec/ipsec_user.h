/*
 * Copyright (C) 2024 - OpenSIPS Solutions
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

#ifndef _IPSEC_USER_H_
#define _IPSEC_USER_H_

#include "../../str.h"
#include "../../ip_addr.h"
#include "../../lib/list.h"
#include "ipsec.h"

struct ipsec_user {
	str impu;
	str impi;
	gen_lock_t lock;
	int ref;
	struct ip_addr ip;
	struct list_head sas;
	struct list_head list;
	char _buf[0];
};

int ipsec_map_init(void);
void ipsec_map_destroy(void);
struct ipsec_user *ipsec_get_user(struct ip_addr *ip, str *impi, str *impu);
struct ipsec_user *ipsec_find_user(struct ip_addr *ip, str *impi, str *impu);
struct ipsec_user *ipsec_remove_user(struct ip_addr *ip);
void ipsec_release_user(struct ipsec_user *user);
struct ipsec_ctx *ipsec_get_ctx_user(struct ipsec_user *user, struct receive_info *ri);

#endif /* _IPSEC_USER_H_ */
