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

#include "sip_emergency.h"

extern db_func_t db_funcs;
extern db_con_t *db_con;

struct emergency_report {
	str callid;
	str ert_srid;
	int ert_resn;
	int ert_npa;
	str esgwri;
	str lro;
	str vpc_host;
	str vpc_name;
	str timestamp;
	str result;
	str disposition;
};

struct esrn_routing {
	str srid;
	int resn;
	int npa;
	str esgwri;

	struct esrn_routing *next;
};

extern struct esrn_routing **db_esrn_esgwri;

struct service_provider {
	str nodeIP;
	str OrganizationName;
	str hostId;
	str nenaId;
	str contact;
	str certUri;
	int attribution;

	struct service_provider *next;
};

extern struct service_provider **db_service_provider;

extern char* mandatory_parm;

#define ACK_TIME 				 3
#define BYE_TIME 				 10

int report(struct emergency_report *report, str db_url, str table_report);
int collect_data(struct node *current, str db_url, str table_report);
int emergency_routing(char *srid, int resn, int npa, char** esgwri, rw_lock_t *ref_lock );
int get_db_routing(str table_name, rw_lock_t *ref_lock );
int get_db_provider(str table_name, rw_lock_t *ref_lock );
struct service_provider* get_provider(struct sip_msg *msg, int attr, rw_lock_t *ref_lock );
