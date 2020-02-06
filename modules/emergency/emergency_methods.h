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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <curl/curl.h>
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mod_fix.h"
#include "../../socket_info.h"
#include "../../route_struct.h"
#include "../../route.c"
#include "../rr/api.h"
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
#include "../../proxy.h"
#include "../dialog/dlg_load.h"

#include "model.h"
#include "notifier_emergency.h"

//str str_source;
//char *char_dest;

#define FREE_BUF(buf)\
	if(buf != empty)\
pkg_free(buf);


#define MAXNUMBERLEN 			 31
#define HTTP_HDR_CONTENT_TYPE    "Content-Type"
#define CONTENT_TYPE_HDR_LEN     12
#define MAX_CONTENT_TYPE_LEN     64
#define CODE_DELIM '-'

#define PATTERN_TEL           	 "tel:([+]*[-0-9]+)"
#define PATTERN_TEL_LEN			 (sizeof(PATTERN_TEL)-1)
#define ACK_TIME 				 3
#define BYE_TIME 				 10

#define	EXPIRES_SUBSCRIBE		300

const char *BLANK_SPACE = " ";

struct code_number {
	str code;
	str description;
	struct code_number *next;
};


/*
   static char err_buff[CURL_ERROR_SIZE];
   static char print_buff[MAX_CONTENT_TYPE_LEN];
   */

size_t write_func(char *ptr, size_t size, size_t nmemb, void *userdata);
size_t header_func(char *ptr, size_t size, size_t nmemb, void *userdata);

/*
 * Module parameters
 */

char *emergency_codes;
char *vsp_organization_name;
char *vsp_hostname;
char *vsp_nena_id;
char *vsp_contact;
char *vsp_cert_uri;

char *source_organization_name;
char *source_hostname;
char *source_nena_id;
char *source_contact;
char *source_cert_uri;
char *vpc_organization_name;
char *vpc_hostname;
char *vpc_nena_id;
char *vpc_contact;
char *vpc_cert_uri;

char *contingency_hostname;
char *call_origin = NULL;
char *call_server_hostname = NULL;
int proxy_role = 0;
int emetable_size = 9;
int substable_size = 9;

struct code_number *codes = NULL;


//struct node **calls_eme = NULL;

struct multi_body *mbody;
struct esct *call_cell;
extern struct lump *l;

int timer_interval=10;
str table_name=str_init("emergency_routing");
str table_report=str_init("emergency_report");
str table_provider=str_init("emergency_service_provider");
static rw_lock_t *ref_lock = NULL;

str callid_invite;

char* inicialized;

/*
 * Function headers
 */
static int is_emergency_call(struct sip_msg *msg);
static int send_request_vpc(struct sip_msg *msg);
static int routing_ack(struct sip_msg *msg);
static int bye(struct sip_msg *msg, int dir);
static int emergency_call(struct sip_msg *msg);
static int failure(struct sip_msg *msg);
static int set_codes(unsigned int type, void *val);
static void libera_esqk(void);
static void free_subs(void);

void routing_timer(unsigned int ticks,void *attr);
int check_myself(struct sip_msg *msg);
int contingency(struct sip_msg *msg, ESCT *call_cell);
int fill_blank_space(void);
int fill_parm_with_BS(char** var);
unsigned long get_xml_size(char* lie, char* formated_time, char* callidHeader, char* cbn, char* call_origin);
char* formatted_xml(struct sip_msg *msg, char* lie, char* callidHeader, char* cbn);
int routing_by_ert( struct sip_msg *msg, ESCT *call_cell, int failure);
int treat_routing(struct sip_msg* msg, struct esct *call_cell, char* callidHeader, str cbn);
int create_call_cell(PARSED *parsed,struct sip_msg* msg, char* callidHeader, str cbn, char* from_tag);
void destroy_codes(struct code_number *codes);


