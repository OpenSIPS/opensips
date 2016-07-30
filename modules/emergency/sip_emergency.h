/*
 * emergency module - basic support for emergency calls
 *
 * Copyright (C) 2014-2015 Robison Tesini & Evandro Villaron
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2014-10-14 initial version (Villaron/Tesini)
 *  2015-03-21 implementing subscriber function (Villaron/Tesini)
 *  2015-04-29 implementing notifier function (Villaron/Tesini)
 *  2015-05-20 change callcell identity
 *  2015-06-08 change from list to hash (Villaron/Tesini)
 *  2015-08-05 code review (Villaron/Tesini)
 *  2015-09-07 final test cases (Villaron/Tesini)
 */


#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mod_fix.h"
#include "../../socket_info.h"
#include "../../route_struct.h"
#include "../../ip_addr.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_pai.h"
#include "../../parser/parse_ppi.h"
#include "../../parser/parse_rpid.h"
#include "../../parser/parse_from.h"
#include "../../regexp.h"
#include "../../data_lump.h"
#include "../../data_lump_rpl.h"
#include "../../ut.h"
#include "../../rw_locking.h"
#include "../../timer.h"
#include "../../db/db.h"
#include "../../db/db_insertq.h"
#include "../../forward.h"
#include "../rr/api.h"

#include "hash.h"

#define CP_STR_CHAR(str_source, char_dest)\
	do{	\
		char_dest = (char *)pkg_malloc( str_source.len + 1);\
		if (!char_dest) {\
			LM_ERR("no more shm\n");\
			goto error;\
		}\
		memcpy(char_dest, str_source.s, str_source.len);\
		char_dest[str_source.len] = 0;\
	} while(0)

int check_geolocation_header(struct sip_msg *msg);
int get_geolocation_header(struct sip_msg *msg, char** locationHeader);
int found_CBN(struct sip_msg *msg, char** cbn);
int get_expires_header(struct sip_msg *msg, char** expires);
int check_event_header(struct sip_msg *msg);
int add_hdr_rpl(struct esct *call_cell,struct sip_msg *msg);
int add_headers(char *esqk, struct sip_msg *msg, str cbn);
int add_hdr_PAI(struct sip_msg *msg, str cbn);
int find_body_pidf(struct sip_msg *msg, char** pidf_body);
int proxy_request(struct sip_msg *msg,char *call_server_hostname);
int new_uri_proxy(struct sip_msg *req_msg, char* new_uri );
int get_ip_socket(struct sip_msg *msg, char** saddr);
int extract_contact_hdrs(struct sip_msg *reply, char **contact_esgwri, char **contact_lro);
int get_subscription_state_header(struct sip_msg *msg, char** subs_state, char** expires);
int get_event_header(struct sip_msg *msg, char** subs_state, char** expires);
int range_result(int result);
