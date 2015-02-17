/*
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
#include "../../ut.h"
#include "../../rw_locking.h"
#include "../../timer.h"
#include "../../db/db.h"
#include "../../db/db_insertq.h"
#include "../../forward.h"
#include "../../proxy.h"
#include "../dialog/dlg_load.h"
#include "model.h"
#include "post_curl.h"

#define MAXNUMBERLEN 31
#define HTTP_HDR_CONTENT_TYPE	"Content-Type"
#define CONTENT_TYPE_HDR_LEN	 12
#define MAX_CONTENT_TYPE_LEN	 64
#define CODE_DELIM '-'

#define P_ASSERTED_HDR			 "P-Asserted-Identity: <sip:+1"
#define P_ASSERTED_HDR_LEN		 (sizeof(P_ASSERTED_HDR)-1)
#define PAI_SUFFIX				 ";user=phone;CBN="
#define PAI_SUFFIX_LEN		 	 (sizeof(PAI_SUFFIX)-1)
#define PAI_SUFFIX_II			 ";user=phone"
#define PAI_SUFFIX_LEN_II		 (sizeof(PAI_SUFFIX_II)-1) 
#define PATTERN_TEL				 "tel:([+]*[-0-9]+)"
#define PATTERN_TEL_LEN			 (sizeof(PATTERN_TEL)-1)
#define NR_KEYS 				 12
#define ACK_TIME 				 3
#define BYE_TIME 				 10


const char *GEO_LOCATION_ROUTING = "Geolocation-Routing";
const char *GEO_LOCATION = "Geolocation";
const char *GEO_LOCATION_ROUTING_YES = "yes";
const char *CONTENT_TYPE_PIDF = "Content-Type: application/pidf+xml";
const char *PRESENCE_START = "<presence";
const char *PRESENCE_END = "/presence>";
const char *BLANK_SPACE = " ";
const char *LOCATION_TAG_BEGIN = "<location-key>";
const char *LOCATION_TAG_END = "</location-key>";
const char *NEW_LINE = "\n";


struct code_number {
	str code;
	str description;
	struct code_number *next;
};

struct esrn_routing {
	str srid;
	int resn;
	int npa;
	str esgwri;

	struct esrn_routing *next;
};

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


/*
static char err_buff[CURL_ERROR_SIZE];
static char print_buff[MAX_CONTENT_TYPE_LEN];
*/

size_t write_func(char *ptr, size_t size, size_t nmemb, void *userdata);
size_t header_func(char *ptr, size_t size, size_t nmemb, void *userdata);

/*
 * Module parameters
 */

char *empty;
char *emergency_codes;
char *url_vpc;
char *vpc_organization_name;
char *vpc_hostname;
char *vpc_nena_id;
char *vpc_contact;
char *vpc_cert_uri;
char *source_organization_name;
char *source_hostname;
char *source_nena_id;
char *source_contact;
char *source_cert_uri;
char *vsp_organization_name;
char *vsp_hostname;
char *vsp_nena_id;
char *vsp_contact;
char *vsp_cert_uri;
char *contingency_hostname;
char *call_origin = NULL;
char *call_server_hostname = NULL;
int flag_empresa_terceira = 0;
int proxy_hole = 0;

struct esrn_routing *new_list;
struct esrn_routing **db_esrn_domain = NULL;
int	size_new_uri;

struct code_number *codes = NULL;
struct rr_binds rr_api;

struct node *list_call;
struct node **calls_eme = NULL;
struct multi_body *mbody;


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
static int find_body_pidf(struct sip_msg *msg, char** pidf_body);
static int emergency_routing(char *srid, int resn, int npa, char** esgwri);
static int report(struct emergency_report *report );
static int collect_data (struct node *current);
static void found_CBN(struct sip_msg *msg, str* cbn_pt);
static int faixa_result(int result);
static int proxy_request(struct sip_msg *msg);
static int new_uri_proxy(struct sip_msg *req_msg, char* new_uri );

void routing_timer(unsigned int ticks,void *attr);
void free_call_cell(struct node *info_call);

int timer_interval=10;
static db_func_t db_funcs;
static db_con_t *db_con;
static str db_url;

static str table_name=str_init("emergency_routing");
static str id_col=str_init("id");
static str srid_col=str_init("selectiveRoutingID");
static str resn_col=str_init("routingESN");
static str npa_col=str_init("npa");
static str esgwri_col=str_init("esgwri");

static str table_report=str_init("emergency_report");
static str id_rep_col=str_init("id");
static str callid_rep_col=str_init("callid");
static str srid_rep_col=str_init("selectiveRoutingID");
static str resn_rep_col=str_init("routingESN");
static str npa_rep_col=str_init("npa");
static str esgwri_rep_col=str_init("esgwri");
static str lro_rep_col=str_init("lro");
static str vpc_name_rep_col=str_init("VPC_organizationName");
static str vpc_host_rep_col=str_init("VPC_hostname");
static str timestamp_rep_col=str_init("VPC_timestamp");
static str result_rep_col=str_init("result");
static str disposition_rep_col=str_init("disposition");

static rw_lock_t *ref_lock = NULL;

static str cbn;

char *replace_str(char *str, char *orig, char *rep);
int check_myself(struct sip_msg *msg);
int check_geolocation_header(struct sip_msg *msg);
int get_geolocation_header(struct sip_msg *msg, char** locationHeader);
int get_callid_header(struct sip_msg *msg, char** callidHeader);
unsigned long get_xml_size(char* lie, char* formated_time, char* callidHeader, char* cbn);
char* formatted_xml(char* lie,char* formated_time, char* callidHeader, char* cbn);
int preenche_com_espaco_em_branco(void);
int preenche_um_com_espaco_em_branco(char** var);
int same_callid(char* callIdEsct, char* callId);
int add_hdr_PAI(struct sip_msg *msg);

