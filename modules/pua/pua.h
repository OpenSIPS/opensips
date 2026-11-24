/*
 * pua module - presence user agent module
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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
 */

#ifndef PUA_PUBLISH_H
#define PUA_PUBLISH_H

#include "../../str.h"
#include "hash.h"
#include "../../db/db.h"

#define INSERT_TYPE      1<<1
#define UPDATE_TYPE      1<<2
/*
 * Set this bit in publ_info_t.flag when a bodyless refresh may be the
 * caller's first PUBLISH for this resource. For example, after a restart
 * usrloc may know a contact from cluster sync while PUA has no matching
 * publication to refresh.
 *
 * If the event requires a body for an initial PUBLISH, send_publish()
 * logs the missing body at DBG and returns ERR_PUBLISH_NO_BODY before
 * sending a SIP request. The caller can then retry with INSERT_TYPE and
 * a body. An existing publication follows the usual refresh path.
 *
 * This bit applies to one publish attempt. For a withdrawal (expires == 0)
 * with no matching publication, PUA already returns ERR_PUBLISH_NO_RECORD
 * at DBG regardless of this bit. The caller handles that result separately.
 */
#define PUBL_SILENT_ERR  1<<3

#define REQ_OTHER  0
#define REQ_ME     1

extern str default_domain;
extern struct tm_binds tmb;
extern htable_t* HashT;
extern int HASH_SIZE;
extern int min_expires;
extern int pua_ul_publish;
extern int default_expires;
extern db_con_t *pua_db;
extern db_func_t pua_dbf;
extern str db_table;

int db_restore(ua_pres_t *pres);

#endif /* PUA_PUBLISH_H */
