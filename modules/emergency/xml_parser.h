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
#include "../tm/tm_load.h" /*load_tm_api*/

extern char *empty;
#define MAX_TIME_SIZE            80
#define MAX_DISPOSITION_SIZE     20

typedef struct parsed_xml_vpc{
	char* organizationname;
	char* hostname;
	char* nenaid;
	char* contact;
	char* certuri;
}NENA;

typedef struct parsed_xml_ert{
	char* selectiveRoutingID ;
	char* routingESN;
	char* npa;
}ERT;

typedef struct parsed_xml_resp{
	char* result;
	char* esgwri;
	char* esqk;
	char* lro;
	char* callid;
	char* datetimestamp;

	NENA *vpc;
	NENA *destination;
	ERT  *ert;
}PARSED;


struct dialog_set{
	char* call_id;
	char* local_tag;
	char* rem_tag;
	int status;
};

typedef struct esct{
	struct dialog_set *eme_dlg_id;
	NENA *source;
	NENA *vpc;
	char* esgwri;
	char* esgw;
	char* esqk;
	char* callid;
	char* ert_srid;
	int   ert_resn;
	int   ert_npa;
	char* datetimestamp;
	char* lro;
	char* disposition;
	char* result;
	int   timeout;
}ESCT;

typedef struct node {
	ESCT *esct;
	struct node *next;
}NODE;

struct dialog_params{
	char* version;
	char* state;
	char* entity;
};

struct target_info{
	char* dlg_id;
	char* callid;
	char* local_tag;
	char* direction;
};

struct notify_body{
	struct dialog_params* params;
	struct target_info* target;
	char* state;
};


struct dialog_id{
	str callid;
	str local_tag;
	str rem_tag;
	int status;
};

struct sm_subscriber{
	struct dialog_id *dlg_id;
	struct dialog_id *call_dlg_id;
	str loc_uri;
	str rem_uri;
	str contact;
	str event;
	int expires;
	int timeout;
	int version;
	struct sm_subscriber *prev;
	struct sm_subscriber *next;
};

char* copy_str_between_two_pointers(char* str_begin, char* str_end);
char* copy_str_between_two_pointers_simple(char* str_begin, char* str_end);
char* copy_str_between_two_tags(char* tag_begin, char* str_total);
int check_str_between_init_tags( char* str_total);
int check_ectAck_init_tags( char* str_total);
PARSED* parse_xml(char* xml);
char* parse_xml_esct(char* xml);
int isNotBlank(char *str);
unsigned long findOutSize(ESCT* esct);
unsigned long findOutNenaSize(NENA* nena);
char* buildXmlFromModel(ESCT* esct);
struct notify_body* parse_notify(char* xml);
char* check_dialog_init_tags( char* str_total);

