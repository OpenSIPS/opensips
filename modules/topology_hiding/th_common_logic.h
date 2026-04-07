/*
 *
 * Copyright (C) 2026 Genesys Cloud Services, Inc.
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
 */

#ifndef _TOPOH_COMMON_LOGIC_H
#define _TOPOH_COMMON_LOGIC_H

#include "../../str.h"
#include "../../data_lump.h"
#include "../../mem/shm_mem.h"
#include "../../parser/contact/parse_contact.h"

struct th_params {
	str ct_caller_user;
	str ct_callee_user;
};

#define RECORD_ROUTE "Record-Route: "
#define RECORD_ROUTE_LEN (sizeof(RECORD_ROUTE)-1)

struct th_ct_params {
    str param_name;
    struct th_ct_params *next;
};

int topo_delete_route_uris(struct sip_msg *msg, int delete_count);
int topo_delete_record_route_uris(struct sip_msg *msg, int delete_count);
int topo_delete_record_routes(struct sip_msg *req);
int topo_delete_vias(struct sip_msg *req);
struct lump* delete_existing_contact(struct sip_msg *msg, int del_hdr);
struct lump* restore_vias_from_req(struct sip_msg *req,struct sip_msg *rpl);

static inline int topo_ct_param_len(str *name, str *val, int should_quote)
{
	int len = 1 /* ; */ + name->len;
	if (val->len) {
		if (should_quote && should_quote_contact_param_value(val))
			len += 2; /* quotes */
		len += 1 /* = */ + val->len;
	}

	return len;
}

static inline char *topo_ct_param_copy(char *buf, str *name, str *val, int should_quote) {
	*buf++ = ';';
	memcpy(buf, name->s, name->len);
	buf += name->len;
	if (val->len) {
		*buf++ = '=';
		if (should_quote)
			should_quote = should_quote_contact_param_value(val);
		if (should_quote)
			*buf++ = '"';
		memcpy(buf, val->s, val->len);
		buf += val->len;
		if (should_quote)
			*buf++ = '"';
	}
	return buf;
}

static void shm_free_wrap(void *param) {
	if (param)
		shm_free(param);
}

#endif