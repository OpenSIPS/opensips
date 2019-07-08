/*
 * presence - presence server implementation
 *
 * Copyright (C) 2006 Voice Sistem SRL
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
 * History:
 * ---------
 *  2006-10-09  first version (Anca Vamanu)
 */

#ifndef PRESENCE_MOD_H
#define PRESENCE_MOD_H

#include "../../parser/msg_parser.h"
#include "../tm/tm_load.h"
#include "../signaling/signaling.h"
#include "../../db/db.h"
#include "../../parser/parse_from.h"
#include "event_list.h"
#include "hash.h"

/* TM bind */
extern struct tm_binds tmb;
extern struct sig_binds sigb;

/* DB module bind */
extern db_func_t pa_dbf;
extern db_con_t* pa_db;

/* PRESENCE database */
extern str db_url;
extern str presentity_table;
extern str active_watchers_table;
extern str watchers_table;

extern int counter;
extern int pid;
extern char *to_tag_pref;
extern int expires_offset;
extern str contact_user;
extern int max_expires_publish;
extern int max_expires_subscribe;
extern int fallback2db;
extern int sphere_enable;
extern int shtable_size;
extern shtable_t subs_htable;
extern int mix_dialog_presence;
extern int notify_offline_body;
extern int end_sub_on_timeout;

extern int phtable_size;
extern phtable_t* pres_htable;

extern long waiting_subs_time;

int update_watchers_status(str pres_uri, pres_ev_t* ev, str* rules_doc);

int terminate_watchers(str *pres_uri, pres_ev_t* ev);

extern str bla_presentity_spec_param;
extern pv_spec_t bla_presentity_spec;
extern int fix_remote_target;

#endif /* PA_MOD_H */
