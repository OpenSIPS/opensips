/*
 * sipcapture module - helper module to capture sip messages
 *
 * Copyright (C) 2011 Alexandr Dubovikov (QSC AG) (alexandr.dubovikov@gmail.com)
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

/*! \file
 * sipcapture module - helper module to capture sip messages
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <signal.h>
#include <sys/wait.h>
#include "../proto_hep/hep.h"
#include "../proto_hep/hep_cb.h"
#include "../../context.h"
#include "../../mod_fix.h"
#include "../../msg_translator.h"
#include "../../action.h"
#include "../../socket_info.h"
#include "../../ipc.h"

/* BPF structure */
#ifdef __OS_linux
#include <linux/filter.h>
#endif

#ifndef __USE_BSD
#define __USE_BSD  /* on linux use bsd version of iphdr (more portable) */
#endif /* __USE_BSD */
#include <netinet/ip.h>
#define __FAVOR_BSD /* on linux use bsd version of udphdr (more portable) */
#include <netinet/udp.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../net/proto_udp/proto_udp.h"
#include "../../ut.h"
#include "../../ip_addr.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"
#include "../../db/db.h"
#include "../../db/db_insertq.h"
#include "../../parser/contact/parse_contact.h"
#include "../../parser/parse_content.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_uri.h"
#include "../../parser/digest/digest.h"
#include "../../parser/parse_pai.h"
#include "../../parser/parse_ppi.h"
#include "../../pvar.h"
#include "../../str.h"
#include "../../resolve.h"
#include "../../receive.h"
#include "../../forward.h"
#include "../../msg_translator.h"

#include "../../lib/cJSON.h"

#ifdef STATISTICS
#include "../../statistics.h"
#endif

/* this value shall be put in proto_reserved2 field of
 * the receive_info structure and help us identify a
 * hep message */
#define HEPBUF_LEN (1<<14)

#define LOWER_DWORD(_c1, _c2, _c3, _c4) (((_c1<<24)|(_c2<<16)|(_c3<<8)|_c4)|0x20202020)
#define LOWER_WORD(_c1, _c2) (((_c1|0x20)<<8) | (_c2|0x20))
#define LOWER_BYTE(_c1) (_c1|0x20)

#define HEP_GET_CONTEXT(_api) \
	(struct hep_context*)context_get_ptr(CONTEXT_GLOBAL, current_processing_ctx, _api.get_hep_ctx_id())


#define HAVE_SHARED_QUERIES (max_async_queries > 1)
#define HAVE_MULTIPLE_ASYNC_INSERT (DB_CAPABILITY(db_funcs, DB_CAP_ASYNC_RAW_QUERY) && HAVE_SHARED_QUERIES)

#define IS_ASYNC_F (actx!=NULL)

#define MAX_QUERY 65535
struct _async_query {
	str last_query_suffix;

	int curr_async_queries;

	int  query_len;
	char query_buf[MAX_QUERY];

	gen_lock_t query_lock;
} *global_async_query;

#define QUERY_BUF(_as_query) _as_query->query_buf
#define QUERY_LEN(_as_query) _as_query->query_len

#define INIT_QUERY_LOCK(_as_query) lock_init(&_as_query->query_lock)
#define GET_QUERY_LOCK(_as_query)  lock_get(&_as_query->query_lock)
#define RELEASE_QUERY_LOCK(_as_query)  lock_release(&_as_query->query_lock)
#define DESTROY_QUERY_LOCK(_as_query)  lock_destroy(&_as_query->query_lock)


#define CURR_QUERIES(_as_query) _as_query->curr_async_queries
#define LAST_SUFFIX(_as_query) _as_query->last_query_suffix

typedef struct _tz_table {
	str prefix; /* table name */
	str suffix; /* time format - strftime  */
} tz_table_t;

struct tz_table_list {
	tz_table_t* table;
	struct _async_query* as_qry;
	struct tz_table_list* next;
};

/* HOMER5 compliant table name */
#define CAPTURE_TABLE_MAX_LEN 256
char table_buf[CAPTURE_TABLE_MAX_LEN];
str  current_table;

/* modparam defined table */
tz_table_t tz_table;
tz_table_t rc_table;

/* list of script used tables - we use this list to hold async queries;
 * when opensips is closed we need to run all queries for all the tables
 * in case max_async_queries is used */
struct tz_table_list* tz_list=NULL;
struct tz_table_list* rc_list=NULL;

/* modparam defined table */
struct tz_table_list tz_global;
/* modparam defined report_capture table */
struct tz_table_list rc_global;

struct _sipcapture_object {
	str method;
	str reply_reason;
	str ruri;
	str ruri_user;
	str ruri_domain;
	str from_user;
	str from_domain;
	str from_tag;
	str to_user;
	str to_domain;
	str to_tag;
	str pid_user;
	str contact_user;
	str auth_user;
	str callid;
	str callid_aleg;
	str via_1;
	str via_1_branch;
	str cseq;
	str diversion;
	str reason;
	str content_type;
	str authorization;
	str user_agent;
	str source_ip;
	int source_port;
	str destination_ip;
	int destination_port;
	str contact_ip;
	int contact_port;
	str originator_ip;
	int originator_port;
	int proto;
	int family;
	int proto_type;
	str rtp_stat;
	str correlation_id;
	int type;
	long long tmstamp;
	str node;
	str msg;
	str custom_field1;
	str custom_field2;
	str custom_field3;
#ifdef STATISTICS
	stat_var *stat;
#endif
};

#define ETHHDR 14 /* sizeof of ethhdr structure */
#define EMPTY_STR(val) val.s=""; val.len=0;
#define TABLE_LEN 256

/*
 * WARNING: if you add/remove keys take care to update
 * VALUES_STR
 */
#define NR_KEYS 44

/* allocate more for HOMERv6 */
#define RTCP_NR_KEYS 17
#define RTCP_H5_NR_KEYS 12

typedef void* sc_async_param_t;
db_key_t db_keys[NR_KEYS];

static int rtp_keys_no = RTCP_NR_KEYS;
db_key_t rtcp_db_keys[RTCP_NR_KEYS];

/* module function prototypes */
static int mod_init(void);
static int child_init(int rank);
static void raw_socket_process(int rank);
static void destroy(void);
static int cfg_validate(void);

static int sip_capture(struct sip_msg *msg, void *table,
                       str *cf1, str *cf2, str *cf3);
static int async_sip_capture(struct sip_msg *msg, async_ctx *actx, void *table,
                             str *cf1, str *cf2, str *cf3);
static int sip_capture_fix_table(void** param);
static int sip_capture_async_fix_table(void** param);
static int fix_hep_value_type(void **param);
static int fix_hep_name(void **param);
static int fix_vendor_id(void **param);
static int w_sip_capture(struct sip_msg *msg, void *table_name,
		async_ctx *actx, str *cf1, str *cf2, str *cf3);


static void set_rtcp_keys(void);

static int w_report_capture_async(struct sip_msg* msg, async_ctx *actx,
                                  str* cor_id, void* table, int* proto_t);
static int w_report_capture(struct sip_msg* msg, str* cor_id, void* table,
                            int* proto_t, async_ctx* actx);

int hep_msg_received(void);
int extract_host_port(void);
int raw_capture_socket(struct ip_addr* ip, str* iface, int port_start, int port_end, int proto);
int raw_capture_rcv_loop(int rsock, int port1, int port2, int ipip);
int sipcapture_db_init(const str* db_url);
void sipcapture_db_close(void);

static mi_response_t *sip_capture_mi(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *sip_capture_mi_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
static int db_sync_store(db_val_t* vals, db_key_t* keys, int num_keys);

typedef int (*append_db_vals_f)(char *buf, int max_len, db_val_t* db_vals);
static inline int append_sc_values(char* buf, int max_len, db_val_t* db_vals);
static inline int append_rc_values(char* buf, int max_len, db_val_t* db_vals);

static int
db_async_store(db_val_t* vals, db_key_t* keys, int num_keys,
	append_db_vals_f append_db_vals, async_ctx *actx,
	struct tz_table_list* t_el);
int resume_async_dbquery(int fd, struct sip_msg *msg, void *_param);

/* setter functions */
static int w_set_hep(struct sip_msg* msg, void *id, str *data_s,
                     void *type, void *vid);

/* getter functions */
static int w_get_hep(struct sip_msg* msg, void *_id, void *_type,
                     pv_spec_p data_pv, pv_spec_p vendor_pv);

static int parse_hep_route(char *val);

static int sipcapture_set_ipip_capture(modparam_t type, void * val);
static int sipcapture_set_moni_capture(modparam_t type, void * val);

/* remove chunk functions */
static int w_del_hep(struct sip_msg* msg, void *id);

static int pv_get_hep_net(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_get_hep_version(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

static int
set_generic_hep_chunk(struct hepv3* h3, unsigned chunk_id, str *data);

/* hep relay function */
static int w_hep_relay(struct sip_msg *msg);
static int w_hep_resume_sip(struct sip_msg *msg);



static int pv_parse_hep_net_name(pv_spec_p sp, str *in);

static int parse_hep_index(str *s_index);

static str db_url		= {NULL, 0};
static str table_name		= str_init("sip_capture");
static str rtcp_table_name		= str_init("rtcp_capture");
static str id_column		= str_init("id");
static str date_column		= str_init("date");
static str micro_ts_column 	= str_init("micro_ts");
static str method_column 	= str_init("method");
static str reply_reason_column 	= str_init("reply_reason");
static str ruri_column 		= str_init("ruri");
static str ruri_user_column 	= str_init("ruri_user");
static str from_user_column 	= str_init("from_user");
static str from_tag_column 	= str_init("from_tag");
static str to_user_column 	= str_init("to_user");
static str to_tag_column 	= str_init("to_tag");
static str pid_user_column 	= str_init("pid_user");

	/* FAMILY TYPE */
static str contact_user_column 	= str_init("contact_user");
static str auth_user_column 	= str_init("auth_user");
static str callid_column 	= str_init("callid");
static str callid_aleg_column 	= str_init("callid_aleg");
static str via_1_column 	= str_init("via_1");
static str via_1_branch_column 	= str_init("via_1_branch");
static str cseq_column		= str_init("cseq");
static str diversion_column 	= str_init("diversion_user");
static str reason_column 	= str_init("reason");
static str content_type_column 	= str_init("content_type");
static str authorization_column = str_init("auth");
static str user_agent_column 	= str_init("user_agent");
static str source_ip_column 	= str_init("source_ip");
static str source_port_column 	= str_init("source_port");
static str dest_ip_column	= str_init("destination_ip");
static str dest_port_column 	= str_init("destination_port");
static str contact_ip_column 	= str_init("contact_ip");
static str contact_port_column 	= str_init("contact_port");
static str orig_ip_column 	= str_init("originator_ip");
static str orig_port_column 	= str_init("originator_port");
static str proto_column 	= str_init("proto");
static str family_column 	= str_init("family");
static str rtp_stat_column 	= str_init("rtp_stat");
static str type_column 		= str_init("type");
static str correlation_column 		= str_init("correlation_id");
static str node_column 		= str_init("node");
static str from_domain_column = str_init("from_domain");
static str to_domain_column = str_init("to_domain");
static str ruri_domain_column = str_init("ruri_domain");
static str msg_column 		= str_init("msg");
static str custom_field1	= str_init("custom_field1");
static str custom_field2	= str_init("custom_field2");
static str custom_field3	= str_init("custom_field3");
static str capture_node 	= str_init("homer01");


/* HOMER6 columns for report capture */
static str date_column6 = str_init("tss");
static str micro_ts_column6 = str_init("tsu");
static str correlation_column6 = str_init("transaction_id");
static str extra_correlation_column6 = str_init("correlation_id");
static str source_ip_column6 	= str_init("source_ip");
static str source_port_column6 	= str_init("source_port");
static str dest_ip_column6	= str_init("destination_ip");
static str dest_port_column6 	= str_init("destination_port");
static str capture_ip_column6 = str_init("capture_ip");
static str proto_column6 	= str_init("proto");
static str family_column6 	= str_init("family");
static str type_column6 		= str_init("type");
static str capture_id_column6 		= str_init("capt_id");
static str node_column6 		= str_init("node");
static str event_column6 		= str_init("event");
static str payload_len_column6 		= str_init("payload_len");
static str msg_column6 		= str_init("data");


/*************/


/* hep pvar related */
static str afinet_str    = str_init("AF_INET");
static str afinet6_str   = str_init("AF_INET6");
/* hep capture proto types */
static str hep_net_protos[]={
	/* want same index as in opensips enum */
	{NULL, 0},
	str_init("UDP"),
	str_init("TCP"),
	str_init("TLS"),
	str_init("SCTP"),
	str_init("WS"),
	str_init("WSS"),
	str_init("BIN"),
	str_init("HEP_UDP"),
	str_init("HEP_TCP"),
	{NULL, 0}
};

static str hep_app_protos[]= {
	str_init("reserved"),
	str_init("SIP"),
	str_init("XMPP"),
	str_init("SDP"),
	str_init("RTP"),
	str_init("RTCP"),
	str_init("MGCP"),
	str_init("MEGACO(H.248)"),
	str_init("M2UA(SS7/SIGTRAN)"),
	str_init("M3UA(SS7/SIGTRAN)"),
	str_init("IAX"),
	str_init("H322"),
	str_init("H321"),
	{NULL, 0}
};

#define MAX_PAYLOAD 32767
static char payload_buf[MAX_PAYLOAD];

/* values to be set from script for hep pvar */



#define VALUES_STR "(%ld,%lld,'%.*s','%.*s','%.*s','%.*s','%.*s','%.*s'," \
					"'%.*s','%.*s','%.*s','%.*s','%.*s','%.*s','%.*s','%.*s','%.*s'," \
					"'%.*s','%.*s','%.*s','%.*s','%.*s','%.*s',%d,'%.*s',%d," \
					"'%.*s',%d,'%.*s',%d,%d,%d,'%.*s',%d,'%.*s','%.*s','%.*s'," \
					"'%.*s', '%.*s', '%.*s', '%.*s', '%.*s', '%.*s')"

#define RTCP_VALUES_STR "(%ld, %lld, '%.*s', '%.*s', %d, '%.*s', %d," \
						"%d, %d, %d, '%.*s', '%.*s')"

int  max_async_queries=5;

int raw_sock_desc = -1; /* raw socket used for ip packets */
int capture_on   = 0;
int hep_capture_on   = 0;
int ipip_capture_on   = 0;
int moni_capture_on   = 0;
int moni_port_start = 0;
int moni_port_end   = 0;
int *capture_on_flag = NULL;
int promisc_on = 0;
int bpf_on = 0;

char* hep_route=0;
str hep_route_s;

#define HEP_NO_ROUTE -1
#define HEP_SIP_ROUTE 0
static char* hep_route_name=NULL;
static int hep_route_id=HEP_SIP_ROUTE;

str raw_socket_listen = { 0, 0 };
str raw_interface = { 0, 0 };

struct ifreq ifr; 	/* interface structure */

#ifdef __OS_linux
/* Linux socket filter */
/* tcpdump -s 0 udp and portrange 5060-5090 -dd */
static struct sock_filter BPF_code[] = { { 0x28, 0, 0, 0x0000000c }, { 0x15, 0, 7, 0x000086dd },
        { 0x30, 0, 0, 0x00000014 },   { 0x15, 0, 18, 0x00000011 }, { 0x28, 0, 0, 0x00000036 },
        { 0x35, 0, 1, 0x000013c4 },   { 0x25, 0, 14, 0x000013e2 }, { 0x28, 0, 0, 0x00000038 },
        { 0x35, 11, 13, 0x000013c4 }, { 0x15, 0, 12, 0x00000800 }, { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 10, 0x00000011 },  { 0x28, 0, 0, 0x00000014 },  { 0x45, 8, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },   { 0x48, 0, 0, 0x0000000e },  { 0x35, 0, 1, 0x000013c4 },
        { 0x25, 0, 3, 0x000013e2 },   { 0x48, 0, 0, 0x00000010 },  { 0x35, 0, 2, 0x000013c4 },
        { 0x25, 1, 0, 0x000013e2 },   { 0x6, 0, 0, 0x0000ffff },   { 0x6, 0, 0, 0x00000000 },
};
#endif

db_func_t db_funcs;      	/*!< Database functions */
db_con_t* db_con = 0; 		/*!< database connection */

static db_ps_t sc_ps = NULL;
static query_list_t *sc_ins_list = NULL;


static db_ps_t rc_ps = NULL;
static query_list_t *rc_ins_list = NULL;

proto_hep_api_t hep_api;
load_hep_f load_hep;


static char hepbuf[HEPBUF_LEN];
static str hep_str={hepbuf, 0};

/*! \brief
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"sip_capture", (cmd_function)sip_capture, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, sip_capture_fix_table, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0}, {0, 0, 0}},
	        REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"hep_set", (cmd_function)w_set_hep, {
		{CMD_PARAM_STR, fix_hep_name, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, fix_hep_value_type, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, fix_vendor_id, 0}, {0, 0, 0}},
	        REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"hep_get", (cmd_function)w_get_hep, {
		{CMD_PARAM_STR, fix_hep_name, 0},
		{CMD_PARAM_STR, fix_hep_value_type, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0}, {0, 0, 0}},
	        REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"hep_del", (cmd_function)w_del_hep, {
		{CMD_PARAM_STR, fix_hep_name, 0}, {0, 0, 0}},
	        REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"hep_relay", (cmd_function)w_hep_relay, {{0, 0, 0}},
	        REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"hep_resume_sip", (cmd_function)w_hep_resume_sip, {{0, 0, 0}},
	        REQUEST_ROUTE},
	{"report_capture", (cmd_function)w_report_capture, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, sip_capture_fix_table, 0},
		{CMD_PARAM_INT | CMD_PARAM_OPT, 0, 0}, {0, 0, 0}},
	        REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{0, 0, {{0, 0, 0}}, 0}
};

static acmd_export_t acmds[] = {
	{"sip_capture",    (acmd_function)async_sip_capture, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, sip_capture_async_fix_table, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0}, {0, 0, 0}}},
	{"report_capture", (acmd_function)w_report_capture_async, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, sip_capture_fix_table, 0},
		{CMD_PARAM_INT | CMD_PARAM_OPT, 0, 0}, {0, 0, 0}}},
	{0, 0, {{0, 0, 0}}}
};

static proc_export_t procs[] = {
        {"RAW receiver",  0,  0, raw_socket_process, 1, PROC_FLAG_INITCHILD},
        {0,0,0,0,0,0}
};


/*! \brief
 * Exported parameters
 */
static param_export_t params[] = {
	{"db_url",			STR_PARAM, &db_url.s            },
	{"table_name",       		STR_PARAM, &table_name.s	},
	{"rtcp_table_name",			STR_PARAM, &rtcp_table_name.s	},
	{"id_column",        		STR_PARAM, &id_column.s         },
	{"date_column",        		STR_PARAM, &date_column.s       },
	{"micro_ts_column",     	STR_PARAM, &micro_ts_column.s	},
	{"method_column",      		STR_PARAM, &method_column.s 	},
	{"reply_reason_column",		STR_PARAM, &reply_reason_column.s	},
	{"ruri_column",      		STR_PARAM, &ruri_column.s     	},
	{"ruri_user_column",      	STR_PARAM, &ruri_user_column.s  },
	{"from_user_column",      	STR_PARAM, &from_user_column.s  },
	{"from_tag_column",        	STR_PARAM, &from_tag_column.s   },
	{"to_user_column",     		STR_PARAM, &to_user_column.s	},
	{"to_tag_column",        	STR_PARAM, &to_tag_column.s	},
	{"pid_user_column",   		STR_PARAM, &pid_user_column.s	},
	{"contact_user_column",        	STR_PARAM, &contact_user_column.s	},
	{"auth_user_column",     	STR_PARAM, &auth_user_column.s  },
	{"callid_column",      		STR_PARAM, &callid_column.s},
	{"callid_aleg_column",      	STR_PARAM, &callid_aleg_column.s},
	{"via_1_column",		STR_PARAM, &via_1_column.s      },
	{"via_1_branch_column",        	STR_PARAM, &via_1_branch_column.s },
	{"cseq_column",     		STR_PARAM, &cseq_column.s     },
	{"diversion_column",      	STR_PARAM, &diversion_column.s },
	{"reason_column",		STR_PARAM, &reason_column.s        },
	{"content_type_column",        	STR_PARAM, &content_type_column.s  },
	{"authorization_column",     	STR_PARAM, &authorization_column.s },
	{"user_agent_column",      	STR_PARAM, &user_agent_column.s	},
	{"source_ip_column",		STR_PARAM, &source_ip_column.s  },
	{"source_port_column",		STR_PARAM, &source_port_column.s},
	{"destination_ip_column",	STR_PARAM, &dest_ip_column.s	},
	{"destination_port_column",	STR_PARAM, &dest_port_column.s	},
	{"contact_ip_column",		STR_PARAM, &contact_ip_column.s },
	{"contact_port_column",		STR_PARAM, &contact_port_column.s	},
	{"originator_ip_column",	STR_PARAM, &orig_ip_column.s    },
	{"originator_port_column",	STR_PARAM, &orig_port_column.s  },
	{"proto_column",		STR_PARAM, &proto_column.s },
	{"family_column",		STR_PARAM, &family_column.s },
	{"rtp_stat_column",		STR_PARAM, &rtp_stat_column.s },
	{"type_column",			STR_PARAM, &type_column.s  },
	{"node_column",			STR_PARAM, &node_column.s  },
	{"msg_column",			STR_PARAM, &msg_column.s   },
	{"capture_on",           	INT_PARAM, &capture_on          },
	{"capture_node",     		STR_PARAM, &capture_node.s     	},
        {"raw_sock_children",  		INT_PARAM, &procs[0].no   },
        {"hep_capture_on",  		INT_PARAM, &hep_capture_on   },
    {"max_async_queries",  		INT_PARAM, &max_async_queries   },
	{"raw_socket_listen",     	STR_PARAM, &raw_socket_listen.s   },
	{"raw_ipip_capture_on",		INT_PARAM|USE_FUNC_PARAM,
		(void*)sipcapture_set_ipip_capture   },
	{"raw_moni_capture_on",		INT_PARAM|USE_FUNC_PARAM,
		(void*)sipcapture_set_moni_capture   },
	{"raw_interface",     		STR_PARAM, &raw_interface.s   },
        {"promiscious_on",  		INT_PARAM, &promisc_on   },
        {"raw_moni_bpf_on",  		INT_PARAM, &bpf_on   },
	{"hep_route",		STR_PARAM, &hep_route_name},
	{0, 0, 0}
};

/*! \brief
 * MI commands
 */
static mi_export_t mi_cmds[] = {
	{ "sip_capture", 0, 0, 0, {
		{sip_capture_mi, {0}},
		{sip_capture_mi_1, {"capture_mode", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{EMPTY_MI_EXPORT}
};

#ifdef STATISTICS
stat_var* sipcapture_req;
stat_var* sipcapture_rpl;

stat_export_t sipcapture_stats[] = {
	{"captured_requests" ,  0,  &sipcapture_req  },
	{"captured_replies"  ,  0,  &sipcapture_rpl  },
	{0,0,0}
};
#endif

static module_dependency_t *get_deps_hep(param_export_t *param)
{
	int hep_on = *(int *)param->param_pointer;

	if (hep_on == 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_DEFAULT, "proto_hep", DEP_ABORT);
}



static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_SQLDB, NULL, DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{"hep_capture_on", get_deps_hep},
		{ NULL, NULL },
	},
};

 /**
 * pseudo-variables
 */
static pv_export_t mod_items[] = {
	{{"hep_net", sizeof("hep_net")-1}, 1201, pv_get_hep_net, 0,
		pv_parse_hep_net_name, 0, 0, 0},
	{{"HEPVERSION", sizeof("HEPVERSION")-1}, 1202, pv_get_hep_version, 0,
		0, 0, 0, 0},
	{{0, 0}, 0, 0, 0, 0, 0, 0, 0}
};

/*! \brief module exports */
struct module_exports exports = {
	"sipcapture",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /*!< dlopen flags */
	0,				 /*!< load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /*!< Exported functions */
	acmds,          /*!< Exported async functions */
	params,     /*!< Exported parameters */
#ifdef STATISTICS
	sipcapture_stats,  /*!< exported statistics */
#else
	0,          /*!< exported statistics */
#endif
	mi_cmds,    /*!< exported MI functions */
	mod_items,          /*!< exported pseudo-variables */
	0,                  /*!< exported transformations */
	0,          /*!< extra processes */
	0,          /*!< module pre-initialization function */
	mod_init,   /*!< module initialization function */
	0,          /*!< response function */
	destroy,    /*!< destroy function */
	child_init,  /*!< child initialization function */
	cfg_validate /*!< reload confirm function */
};

static int sipcapture_set_ipip_capture(modparam_t type, void * val)
{
	ipip_capture_on = (int)(long)val;
	if (ipip_capture_on)
		exports.procs = procs;
	return 0;
}

static int sipcapture_set_moni_capture(modparam_t type, void * val)
{
	moni_capture_on = (int)(long)val;
	if (moni_capture_on)
		exports.procs = procs;
	return 0;
}


static int parse_hep_route(char *val)
{
	static const str hep_sip_route = str_init("sip");
	static const str hep_no_route = str_init("none");
	str route_name = {val, strlen(val)};

	if ( route_name.len == hep_no_route.len &&
			strncasecmp(route_name.s, hep_no_route.s, hep_no_route.len ) == 0) {
		hep_route_id = HEP_NO_ROUTE;
	} else if ( route_name.len == hep_sip_route.len &&
			strncasecmp(route_name.s, hep_sip_route.s, hep_sip_route.len ) == 0) {
		hep_route_id = HEP_SIP_ROUTE;
	} else {
		hep_route_id=get_script_route_ID_by_name( route_name.s,
			sroutes->request, RT_NO);
		if ( hep_route_id == -1 ) {
			LM_ERR("route <%s> not defined!\n", route_name.s);
			return -1;
		}
	}

	return 0;
}

void parse_table_str(str* table_s, tz_table_t* tz_table)
{
	if ((tz_table->suffix.s=q_memchr(table_s->s, '%', table_s->len)) == NULL) {
		tz_table->prefix = *table_s;
		tz_table->suffix.len = 0;
	} else {
		tz_table->prefix.s = table_s->s;
		tz_table->prefix.len = tz_table->suffix.s - tz_table->prefix.s;
		tz_table->suffix.len = strlen(tz_table->suffix.s);

		if (tz_table->prefix.len == 0)
			tz_table->prefix.s = NULL;
	}



}



/*! \brief Initialize sipcapture module */
static int mod_init(void) {

	int i;
	struct ip_addr *ip = NULL;

	if (hep_capture_on) {
		load_hep = (load_hep_f)find_export("load_hep", 0);
		if (!load_hep) {
			LM_ERR("Can't bind proto hep!\n");
			return -1;
		}

		if (load_hep(&hep_api)) {
			LM_ERR("can't bind proto hep\n");
			return -1;
		}

		if (hep_api.register_hep_cb(hep_msg_received)) {
			LM_ERR("failed to register hep callback\n");
			return -1;
		}

		if (hep_route_name != NULL) {
			if ( parse_hep_route(hep_route_name) < 0 ) {
				LM_ERR("bad hep route name %s\n", hep_route_name);
				return -1;
			}
		}

		set_rtcp_keys();

		/* db_url is mandatory if sip_capture is used */
		if (((is_script_func_used("sip_capture", -1) ||
				is_script_async_func_used("sip_capture", -1)) ||
				hep_route_id == HEP_NO_ROUTE) ||
			(is_script_func_used("report_capture", -1) ||
				is_script_async_func_used("report_capture", -1))) {
			init_db_url(db_url, 0);
		} else {
			init_db_url(db_url, 1);
		}
	} else {
		if ((is_script_func_used("sip_capture", -1) ||
				is_script_async_func_used("sip_capture", -1))) {
			init_db_url(db_url, 0);
		} else {
			init_db_url(db_url, 1);
		}
	}


	/* init db keys */
	db_keys[0] = &id_column;
	db_keys[1] = &date_column;
	db_keys[2] = &micro_ts_column;
	db_keys[3] = &method_column;
	db_keys[4] = &reply_reason_column;
	db_keys[5] = &ruri_column;
	db_keys[6] = &ruri_user_column;
	db_keys[7] = &from_user_column;
	db_keys[8] = &from_tag_column;
	db_keys[9] = &to_user_column;
	db_keys[10] = &to_tag_column;
	db_keys[11] = &pid_user_column;
	db_keys[12] = &contact_user_column;
	db_keys[13] = &auth_user_column;
	db_keys[14] = &callid_column;
	db_keys[15] = &callid_aleg_column;
	db_keys[16] = &via_1_column;
	db_keys[17] = &via_1_branch_column;
	db_keys[18] = &cseq_column;
	db_keys[19] = &reason_column;
	db_keys[20] = &content_type_column;
	db_keys[21] = &authorization_column;
	db_keys[22] = &user_agent_column;
	db_keys[23] = &source_ip_column;
	db_keys[24] = &source_port_column;
	db_keys[25] = &dest_ip_column;
	db_keys[26] = &dest_port_column;
	db_keys[27] = &contact_ip_column;
	db_keys[28] = &contact_port_column;
	db_keys[29] = &orig_ip_column;
	db_keys[30] = &orig_port_column;
	db_keys[31] = &proto_column;
	db_keys[32] = &family_column;
	db_keys[33] = &rtp_stat_column;
	db_keys[34] = &type_column;
	db_keys[35] = &node_column;
	db_keys[36] = &correlation_column;
	db_keys[37] = &from_domain_column;
	db_keys[38] = &to_domain_column;
	db_keys[39] = &ruri_domain_column;
	db_keys[40] = &msg_column;
	db_keys[41] = &custom_field1;
	db_keys[42] = &custom_field2;
	db_keys[43] = &custom_field3;


#ifdef STATISTICS
	/* register statistics */
	if (register_module_stats(exports.name, sipcapture_stats)!=0)
	{
		LM_ERR("failed to register core statistics\n");
		return -1;
	}
#endif

	table_name.len = strlen(table_name.s);
	rtcp_table_name.len = strlen(rtcp_table_name.s);
	date_column.len = strlen(date_column.s);
	id_column.len = strlen(id_column.s);
	micro_ts_column.len = strlen(micro_ts_column.s);
	method_column.len = strlen(method_column.s);
	reply_reason_column.len = strlen(reply_reason_column.s);
	ruri_column.len = strlen(ruri_column.s);
	ruri_user_column.len = strlen(ruri_user_column.s);
	from_user_column.len = strlen(from_user_column.s);
	from_tag_column.len = strlen(from_tag_column.s);
	to_user_column.len = strlen(to_user_column.s);
	pid_user_column.len = strlen(pid_user_column.s);
	contact_user_column.len = strlen(contact_user_column.s);
	auth_user_column.len = strlen(auth_user_column.s);
	callid_column.len = strlen(callid_column.s);
	via_1_column.len = strlen(via_1_column.s);
	via_1_branch_column.len = strlen(via_1_branch_column.s);
	cseq_column.len = strlen(cseq_column.s);
	diversion_column.len = strlen(diversion_column.s);
	reason_column.len = strlen(reason_column.s);
	content_type_column.len = strlen(content_type_column.s);
	authorization_column.len = strlen(authorization_column.s);
	user_agent_column.len = strlen(user_agent_column.s);
	source_ip_column.len = strlen(source_ip_column.s);
	source_port_column.len = strlen(source_port_column.s);
	dest_ip_column.len = strlen(dest_ip_column.s);
	dest_port_column.len = strlen(dest_port_column.s);
	contact_ip_column.len = strlen(contact_ip_column.s);
	contact_port_column.len = strlen(contact_port_column.s);
	orig_ip_column.len = strlen(orig_ip_column.s);
	orig_port_column.len = strlen(orig_port_column.s);
	proto_column.len = strlen(proto_column.s);
	family_column.len = strlen(family_column.s);
	type_column.len = strlen(type_column.s);
	rtp_stat_column.len = strlen(rtp_stat_column.s);
	node_column.len = strlen(node_column.s);
	msg_column.len = strlen(msg_column.s);
	capture_node.len = strlen(capture_node.s);


	/* extract prefix and suffix from table name */
	parse_table_str(&table_name, &tz_table);
	parse_table_str(&rtcp_table_name, &rc_table);

	if(raw_socket_listen.s)
		raw_socket_listen.len = strlen(raw_socket_listen.s);
	if(raw_interface.s)
		raw_interface.len = strlen(raw_interface.s);

	if (db_url.s && db_url.len) {
		/* Find a database module */
		if (db_bind_mod(&db_url, &db_funcs))
		{
			LM_ERR("unable to bind database module\n");
			return -1;
		}
		if (!DB_CAPABILITY(db_funcs, DB_CAP_INSERT))
		{
			LM_ERR("database modules does not provide all functions needed"
					" by module\n");
			return -1;
		}

		if (DB_CAPABILITY(db_funcs, DB_CAP_ASYNC_RAW_QUERY)) {
			if (!HAVE_SHARED_QUERIES) {
				for (i=0; i < 2; i++) {
					global_async_query = pkg_malloc(sizeof(struct _async_query));
					if (global_async_query == NULL) {
						LM_ERR("no more pkg\n");
						return -1;
					}
					memset(global_async_query, 0, sizeof(struct _async_query));

					if (i==0) {
						tz_global.as_qry = global_async_query;
					} else {
						rc_global.as_qry = global_async_query;
					}
				}
			} else {
				for (i=0; i < 2; i++) {
					global_async_query = shm_malloc(sizeof(struct _async_query));
					if (global_async_query == NULL) {
						LM_ERR("no more shm\n");
						return -1;
					}
					memset(global_async_query, 0, sizeof(struct _async_query));

					LAST_SUFFIX(global_async_query).s = shm_malloc(CAPTURE_TABLE_MAX_LEN);
					if (global_async_query == NULL) {
						LM_ERR("no more shm\n");
						return -1;
					}

					LAST_SUFFIX(global_async_query).len = 0;

					INIT_QUERY_LOCK(global_async_query);
					if( i == 0) {
						tz_global.as_qry = global_async_query;
					} else {
						rc_global.as_qry = global_async_query;
					}
				}
			}

			tz_global.table = &tz_table;
			rc_global.table = &rc_table;
		}

		/*Check the table name*/
		if(!table_name.len) {
			LM_ERR("table_name is not defined or empty\n");
			return -1;
		}
	}

	capture_on_flag = (int*)shm_malloc(sizeof(int));
	if(capture_on_flag==NULL) {
		LM_ERR("no more shm memory left\n");
		return -1;
	}

	*capture_on_flag = capture_on;

	if(ipip_capture_on && moni_capture_on) {
		LM_ERR("only one RAW mode is supported. Please disable ipip_capture_on or moni_capture_on\n");
		return -1;
	}

	/* raw processes for IPIP encapsulation */
	if (ipip_capture_on || moni_capture_on) {

		if(extract_host_port() && (((ip=str2ip(&raw_socket_listen)) == NULL)
					   && ((ip=str2ip6(&raw_socket_listen)) == NULL)
				 ))
		{
			LM_ERR("bad RAW IP: %.*s\n", raw_socket_listen.len, raw_socket_listen.s);
			return -1;
		}

			if(moni_capture_on && !moni_port_start) {
				LM_ERR("Please define port/portrange in 'raw_socket_listen', before \
										activate monitoring capture\n");
				return -1;
				}

		raw_sock_desc = raw_capture_socket(raw_socket_listen.len ? ip : 0, raw_interface.len ? &raw_interface : 0,
										moni_port_start, moni_port_end , ipip_capture_on ? IPPROTO_IPIP : htons(0x0800));

		if(raw_sock_desc < 0) {
			LM_ERR("could not initialize raw udp socket:"
										 " %s (%d)\n", strerror(errno), errno);
					if (errno == EPERM)
						LM_ERR("could not initialize raw socket on startup"
								" due to inadequate permissions, please"
									" restart as root or with CAP_NET_RAW\n");

			return -1;
		}

		if(promisc_on && raw_interface.s && raw_interface.len) {

			 memset(&ifr, 0, sizeof(ifr));
			 memcpy(ifr.ifr_name, raw_interface.s, raw_interface.len);


#ifdef __OS_linux
			 if(ioctl(raw_sock_desc, SIOCGIFFLAGS, &ifr) < 0) {
				LM_ERR("could not get flags from interface [%.*s]:"
										 " %s (%d)\n", raw_interface.len, raw_interface.s, strerror(errno), errno);
				goto error;
			 }

					 ifr.ifr_flags |= IFF_PROMISC;

					 if (ioctl(raw_sock_desc, SIOCSIFFLAGS, &ifr) < 0) {
						LM_ERR("could not set PROMISC flag to interface [%.*s]:"
										 " %s (%d)\n", raw_interface.len, raw_interface.s, strerror(errno), errno);
				goto error;
					 }
#endif

		}
	}

	return 0;
#ifdef __OS_linux
error:
	if(raw_sock_desc) close(raw_sock_desc);
	return -1;
#endif
}


static int cfg_validate(void)
{
	if (hep_capture_on) {
		/* db_url is mandatory if sip_capture is used */
		if (((is_script_func_used("sip_capture", -1) ||
				is_script_async_func_used("sip_capture", -1)) ||
				hep_route_id == HEP_NO_ROUTE) ||
			(is_script_func_used("report_capture", -1) ||
				is_script_async_func_used("report_capture", -1)))
		{
			if (db_funcs.insert==NULL) {
				LM_ERR("sip_capture() found in new script, but the module "
					"did not initalized the DB conn, better restart\n");
				return 0;
			}
		}
	} else {
		if ((is_script_func_used("sip_capture", -1) ||
				is_script_async_func_used("sip_capture", -1)))
		{
			if (db_funcs.insert==NULL) {
				LM_ERR("sip_capture() found in new script, but the module "
					"did not initalized the DB conn, better restart\n");
				return 0;
			}
		}
	}

	return 1;
}


/*
 * returns hep index as an integer from a string
 */
static int parse_hep_index(str *s_index)
{
	int p;
	int index=0;
	int hex_mode=0;
	unsigned int dec_num;

	if (s_index == NULL || s_index->s == NULL || s_index->len == 0) {
		LM_ERR("null index!\n");
		return -1;
	}

	if (!isdigit(s_index->s[0]))
		return 0;

	/* cut the '0x' in the beginning if exists */
	if (s_index->len > 2 && s_index->s[0] == '0' && s_index->s[1] == 'x') {
		s_index->s   += 2;
		s_index->len -= 2;
		hex_mode=1;
	}

	/**/
	while (s_index->s[0] == '0')
		(s_index->s++, s_index->len--);

	/* decimal */
	if (!hex_mode) {
		if (str2int(s_index, &dec_num) < 0) {
			LM_ERR("Chunk identifier begins with a digit "
					"but it's not a valid number!\n");
			return -1;
		}

		return dec_num;
	}

	for (p=0; p < s_index->len; p++) {
		switch (s_index->s[p]) {
			case 'a':
			case 'A':
				index = (index<<4) + 0xA;
				break;
			case 'b':
			case 'B':
				index = (index<<4) + 0xB;
				break;
			case 'c':
			case 'C':
				index = (index<<4) + 0xC;
				break;
			case 'd':
			case 'D':
				index = (index<<4) + 0xD;
				break;
			case 'e':
			case 'E':
				index = (index<<4) + 0xE;
				break;
			case 'f':
			case 'F':
				index = (index<<4) + 0xF;
				break;
			default:
				if (s_index->s[p] >= '0' && s_index->s[p] <= '9') {
					index = (index<<4) + (s_index->s[p] -'0');
					break;
				}

				return -1;
		}
	}

	return index==0?-1:index; /* index can't be 0 */

}


enum hep_state { STATE_NONE=0, SOURCE=1, DEST, PROTO, TIME, AG_ID, PLOAD};

static int parse_hep_name(str *s_name, unsigned *chunk)
{
	#define CHECK_IS_VALID(_str, _pattern)                     \
	do {                                                       \
		if (_str.len < (sizeof(_pattern)-1))                   \
			goto error;                                        \
	} while(0);

	int ret=0;
	int p=0;
	enum hep_state state=STATE_NONE;

	str s;

	if (s_name == NULL || s_name->s == NULL ||
			s_name->len == 0 || chunk == NULL) {
		LM_ERR("bad input!\n");
		return -1;
	}

	str_trim_spaces_lr(*s_name);

	ret=parse_hep_index(s_name);
	if (ret<0) {
		goto error;
	} else if (ret > 0) {
		*chunk=ret;
		return 0;
	} /* else it's a name; continue */

	s = *s_name;
	if (s.len < 4) {
		LM_ERR("bad chunk name <%.*s>!\n", s_name->len, s_name->s);
		return -1;
	}

	switch (LOWER_DWORD(s.s[0], s.s[1], s.s[2], s.s[3])) {
		case LOWER_DWORD('p','r','o','t'):
			state=PROTO;
			break;
		case LOWER_DWORD('s','r','c','_'):
			state=SOURCE;
			break;
		case LOWER_DWORD('d','s','t','_'):
			state=DEST;
			break;
		case LOWER_DWORD('t','i','m','e'):
			state=TIME;
			break;
		case LOWER_DWORD('c','a','p','t'):
			state=AG_ID;
			break;
		case LOWER_DWORD('p','a','y','l'):
			state=PLOAD;
			break;
		default:
			goto error;
	}

	p+=4;

	switch (state) {
		case PROTO:
			/* we need at least 8 bytes protXXXX */
			CHECK_IS_VALID(s, "protXXXX");

			switch LOWER_DWORD(s.s[p], s.s[p+1], s.s[p+2], s.s[p+3]){
			/*proto_family*/
			case LOWER_DWORD('o','_','f','a'):
				p+=4;
				CHECK_IS_VALID(s, "proto_faXXXX");

				if (LOWER_DWORD(s.s[p],s.s[p+1], s.s[p+2], s.s[p+3]) !=
							LOWER_DWORD('m','i','l','y'))
					goto error;

				*chunk=HEP_PROTO_FAMILY;
				break;

			/* protocol id */
			case LOWER_DWORD('o','_','i','d'):
				*chunk=HEP_PROTO_ID;
				break;

			case LOWER_DWORD('o','_','t','y'):
				p+=4;
				CHECK_IS_VALID(s, "proto_tyXX");

				if (LOWER_WORD(s.s[p],s.s[p+1]) != LOWER_WORD('p','e'))
					goto error;
				*chunk=HEP_PROTO_TYPE;
				break;

			default:
				goto error;
			}

			break;
		case SOURCE:
			CHECK_IS_VALID(s, "src_XX");
			switch LOWER_WORD(s.s[p], s.s[p+1]) {
				case LOWER_WORD('i', 'p'):
					*chunk=HEP_IPV4_SRC;
					break;
				case LOWER_WORD('p', 'o'):
					CHECK_IS_VALID(s, "src_poXX");
					p+=2;
					if (LOWER_WORD(s.s[p], s.s[p+1]) != LOWER_WORD('r','t'))
						goto error;

					*chunk=HEP_SRC_PORT;
					break;
				default:
					goto error;
			}

			break;
		case DEST:
			CHECK_IS_VALID(s, "dst_XX");
			switch LOWER_WORD(s.s[p], s.s[p+1]) {
				case LOWER_WORD('i', 'p'):
					*chunk=HEP_IPV4_DST;
					break;
				case LOWER_WORD('p', 'o'):
					CHECK_IS_VALID(s, "dst_poXX");
					p+=2;
					if (LOWER_WORD(s.s[p], s.s[p+1]) != LOWER_WORD('r','t'))
						goto error;

					*chunk=HEP_DST_PORT;
					break;
				default:
					goto error;
			}

			break;
		case TIME:
			CHECK_IS_VALID(s, "timestamp");
			if (s.len == sizeof("timestamp")-1 &&
					!strncasecmp(s.s, "timestamp", s.len)) {
				*chunk = HEP_TIMESTAMP;
				break;
			}

			CHECK_IS_VALID(s, "timestampXXX");
			if (s.len == sizeof("timestamp_us")-1 &&
					!strncasecmp(s.s, "timestamp_us", s.len)) {
				*chunk=HEP_TIMESTAMP_US;
				break;
			}

			goto error;
		case AG_ID:
			CHECK_IS_VALID(s, "captXXXXXXXX");
			if ((LOWER_DWORD(s.s[p], s.s[p+1], s.s[p+2], s.s[p+3])
					!= LOWER_DWORD('a','g','e','n')) || (p+=4,0) ||
				LOWER_DWORD(s.s[p], s.s[p+1], s.s[p+2], s.s[p+3])
					!= LOWER_DWORD('t','_','i','d'))
				goto error;

			*chunk = HEP_AGENT_ID;
			break;
		case PLOAD:
			CHECK_IS_VALID(s, "paylXXX");
			if ((LOWER_WORD(s.s[p], s.s[p+1]) != LOWER_WORD('o', 'a')
						|| s.s[p+2] != 'd'))
				goto error;

			*chunk = HEP_PAYLOAD;
			break;
		default:
			goto error;
	}

	return 0;
error:
	LM_ERR("invalid hepvar name <%.*s>! parsed until <%.*s>!\n",
		s_name->len, s_name->s, s_name->len-p, s_name->s+p);
	return -1;

#undef CHECK_IS_VALID
}


static int pv_parse_hep_net_name(pv_spec_p sp, str* in)
{
	pv_spec_p e;

	unsigned id;

	if (in==NULL || in->s == NULL || in->len == 0) {
		LM_ERR("bad name!\n");
		return -1;
	}

	str_trim_spaces_lr(*in);

	if (in->s[0] != PV_MARKER) {
		if (parse_hep_name(in, &id) < 0) {
			LM_ERR("Invalid hep net name <%.*s>!\n", in->len, in->s);
			return -1;
		}

		sp->pvp.pvn.type = PV_NAME_INTSTR;
		sp->pvp.pvn.u.isname.name.n = id;
		sp->pvp.pvn.u.isname.type = 0;
	} else {
		e = pkg_malloc(sizeof(pv_spec_t));
		if (e==NULL) {
			LM_ERR("no more pkg mem!\n");
			return -1;
		}

		if (pv_parse_spec(in, e)==NULL) {
			LM_ERR("invalid pvar!\n");
			return -1;
		}

		sp->pvp.pvn.u.dname = (void *)e;
		sp->pvp.pvn.type = PV_NAME_PVAR;
	}

	return 0;
}


static int get_hepvar_name(struct sip_msg *msg, pv_param_t *param,
		unsigned int *chunk)
{
	pv_spec_p sp;
	pv_value_t value;

	if (param->pvn.type == PV_NAME_PVAR) {
		sp = param->pvn.u.dname;
		if (pv_get_spec_value(msg, sp, &value) < 0) {
			LM_ERR("failed to get name pv value!\n");
			return -1;
		}

		if (!(value.flags&PV_VAL_STR)) {
			LM_ERR("invalid name!\n");
			return -1;
		}

		if (parse_hep_name(&value.rs, chunk) < 0) {
			LM_ERR("invalid name!\n");
			return -1;
		}
	} else {
		*chunk = param->pvn.u.isname.name.n;
	}

	return 0;
}


static int get_hep_chunk(struct hepv3* h3, unsigned int chunk_id,
		pv_value_t *res)
{
	#define SET_PVAL_INT(__pval__, __ival__)    \
	do {                                                   \
		__pval__->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;\
		__pval__->ri = __ival__;                           \
		__pval__->rs.len +=                                \
			snprintf(__pval__->rs.s + __pval__->rs.len,    \
			HEPBUF_LEN, "%d", __ival__);  \
	} while(0);

	#define SET_PVAL_STR(__pval__, __sval__)    \
	do {                                                   \
		__pval__->flags = PV_VAL_STR;                     \
		__pval__->rs.len +=                                \
			snprintf(__pval__->rs.s + __pval__->rs.len,    \
			HEPBUF_LEN, "%.*s", __sval__.len, __sval__.s); \
	} while(0);


	char addr[INET6_ADDRSTRLEN];

	str addr_str;
	str payload_str;
	hep_str.len = 0;

	res->rs    = hep_str;
	res->flags = PV_VAL_STR;

	switch (chunk_id) {
	/* ip family */
	case HEP_PROTO_FAMILY:
		if (h3->hg.ip_family.chunk.length == 0)
			goto chunk_not_set;

		if (h3->hg.ip_family.data == AF_INET) {
			SET_PVAL_STR(res, afinet_str);
		} else {
			SET_PVAL_STR(res, afinet6_str);
		}

		break;
	/* ip protocol id */
	case HEP_PROTO_ID:
		if (h3->hg.ip_proto.chunk.length == 0)
			goto chunk_not_set;

		if (h3->hg.ip_proto.data<PROTO_UDP || h3->hg.ip_proto.data>PROTO_WS) {
			LM_ALERT("Invalid proto!Probably a new one was added %d\n",
					h3->hg.ip_proto.data);
			return -1;
		}
		SET_PVAL_STR(res, hep_net_protos[h3->hg.ip_proto.data]);

		break;
	/* ipv4/6 source
	 * no difference between ipv4/ipv6 from script level; it only returns
	 * the address it the format that it is */
	case HEP_IPV4_SRC:
	case HEP_IPV6_SRC:
		if (h3->hg.ip_family.data == AF_INET) {
			if (h3->addr.ip4_addr.src_ip4.chunk.length == 0)
				goto chunk_not_set;

			if (inet_ntop(AF_INET, &h3->addr.ip4_addr.src_ip4.data,
						addr, INET_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				return -1;
			}
		} else {
			if (h3->addr.ip6_addr.src_ip6.chunk.length == 0)
				goto chunk_not_set;

			if (inet_ntop(AF_INET6, &h3->addr.ip6_addr.src_ip6.data,
						addr, INET6_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				return -1;
			}
		}

		addr_str.s = addr;
		addr_str.len = strlen(addr);

		SET_PVAL_STR(res, addr_str);

		break;
	/* ipv4/6 dest */
	case HEP_IPV4_DST:
	case HEP_IPV6_DST:
		if (h3->hg.ip_family.data == AF_INET) {
			if (h3->addr.ip4_addr.dst_ip4.chunk.length == 0)
				goto chunk_not_set;

			if (inet_ntop(AF_INET, &h3->addr.ip4_addr.dst_ip4.data,
						addr, INET_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				return -1;
			}
		} else {
			if (h3->addr.ip6_addr.dst_ip6.chunk.length == 0)
				goto chunk_not_set;

			if (inet_ntop(AF_INET6, &h3->addr.ip6_addr.dst_ip6.data,
						addr, INET6_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				return -1;
			}
		}

		addr_str.s = addr;
		addr_str.len = strlen(addr);

		SET_PVAL_STR(res, addr_str);

		break;
	/* ipv6 source */
	/* source port */
	case HEP_SRC_PORT:
		if (h3->hg.src_port.chunk.length == 0)
			goto chunk_not_set;


		SET_PVAL_INT(res, h3->hg.src_port.data);

		break;
	/* destination port */
	case HEP_DST_PORT:
		if (h3->hg.dst_port.chunk.length == 0)
			goto chunk_not_set;

		SET_PVAL_INT(res, h3->hg.dst_port.data);

		break;
	/* timestamp */
	case HEP_TIMESTAMP:
		if (h3->hg.time_sec.chunk.length == 0)
			goto chunk_not_set;

		SET_PVAL_INT( res, h3->hg.time_sec.data );

		break;
	/* timestamp us offset */
	case HEP_TIMESTAMP_US:
		if (h3->hg.time_usec.chunk.length == 0)
			goto chunk_not_set;

		SET_PVAL_INT(res, h3->hg.time_usec.data);

		break;
	/*  proto type (SIP, ...) */
	case HEP_PROTO_TYPE:
		if (h3->hg.proto_t.chunk.length == 0)
			goto chunk_not_set;

		if (h3->hg.proto_t.data >
				(sizeof(hep_app_protos)/sizeof(str))-1) {
			LM_DBG("Not a HEP default defined proto %d\n",
					h3->hg.ip_proto.data);

			SET_PVAL_INT(res, h3->hg.proto_t.data);
		} else {
			SET_PVAL_STR(res, hep_app_protos[h3->hg.proto_t.data]);
		}

		break;
	/* capture agent id */
	case HEP_AGENT_ID:
		if (h3->hg.capt_id.chunk.length == 0)
			goto chunk_not_set;

		SET_PVAL_INT(res, h3->hg.capt_id.data);

		break;
	/* payload */
	case HEP_PAYLOAD:
	case HEP_COMPRESSED_PAYLOAD/* gzipped payload */:
		if (h3->payload_chunk.chunk.length == 0)
			goto chunk_not_set;


		payload_str.s = h3->payload_chunk.data;
		payload_str.len = h3->payload_chunk.chunk.length
							- sizeof(hep_chunk_t);
		SET_PVAL_STR(res, payload_str);

		break;

	}

	return 0;

chunk_not_set:
	LM_DBG("generic chunk <%d> not set!\n", chunk_id);
	return -1;

	#undef SET_PVAL_STR
	#undef SET_PVAL_INT
}

static int del_hep_chunk(struct hepv3* h3, unsigned int chunk_id)
{

	switch (chunk_id) {
	/* ip family */
	case HEP_PROTO_FAMILY:

		h3->hg.ip_family.chunk.length = 0;

		break;
	/* ip protocol id */
	case HEP_PROTO_ID:

		h3->hg.ip_proto.chunk.length = 0;

		break;
	case HEP_IPV4_SRC:
	case HEP_IPV6_SRC:
		if (h3->hg.ip_family.data == AF_INET)
			h3->addr.ip4_addr.src_ip4.chunk.length = 0;
		else
			h3->addr.ip6_addr.src_ip6.chunk.length = 0;

		break;
	/* ipv4/6 dest */
	case HEP_IPV4_DST:
	case HEP_IPV6_DST:
		if (h3->hg.ip_family.data == AF_INET)
			h3->addr.ip4_addr.dst_ip4.chunk.length = 0;
		else
			h3->addr.ip6_addr.dst_ip6.chunk.length = 0;

		break;
	/* ipv6 source */
	/* source port */
	case HEP_SRC_PORT:
		h3->hg.src_port.chunk.length = 0;

		break;
	/* destination port */
	case HEP_DST_PORT:
		h3->hg.dst_port.chunk.length = 0;

		break;
	/* timestamp */
	case HEP_TIMESTAMP:
		h3->hg.time_sec.chunk.length = 0;

		break;
	/* timestamp us offset */
	case HEP_TIMESTAMP_US:
		h3->hg.time_usec.chunk.length = 0;

		break;
	/*  proto type (SIP, ...) */
	case HEP_PROTO_TYPE:
		h3->hg.proto_t.chunk.length = 0;

		break;
	/* capture agent id */
	case HEP_AGENT_ID:
		h3->hg.capt_id.chunk.length = 0;

		break;
	/* payload */
	case HEP_PAYLOAD:
	case HEP_COMPRESSED_PAYLOAD/* gzipped payload */:
		h3->payload_chunk.chunk.length = 0;

		break;
	}

	return 1;
}




static int pv_get_hep_net(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	#define SET_PVAL_INT(__pval__, __ival__)    \
	do {                                                   \
		__pval__->flags = PV_VAL_STR|PV_VAL_INT;           \
		__pval__->ri = __ival__;                           \
		__pval__->rs.len +=                                \
			snprintf(__pval__->rs.s + __pval__->rs.len,    \
			HEPBUF_LEN, "%d", __ival__);  \
	} while(0);

	#define SET_PVAL_STR(__pval__, __sval__)    \
	do {                                                   \
		__pval__->flags = PV_VAL_STR;                     \
		__pval__->rs.len +=                                \
			snprintf(__pval__->rs.s + __pval__->rs.len,    \
			HEPBUF_LEN, "%.*s", __sval__.len, __sval__.s); \
	} while(0);


	char addr[INET6_ADDRSTRLEN];
	unsigned net_info_type;

	struct hep_context *ctx;
	struct receive_info *ri;

	str addr_str;

	if (msg == NULL)
	{
		LM_ERR("invalid message!\n");
		return -1;
	}

	ctx = HEP_GET_CONTEXT(hep_api);
	if (ctx == NULL) {
		LM_ERR("Hep context not there!\n");
		return -1;
	}

	ri = &ctx->ri;

	if (get_hepvar_name(msg, param, &net_info_type) < 0) {
		LM_ERR("failed to get variable index/name!\n");
		return -1;
	}

	if (net_info_type < HEP_PROTO_FAMILY || net_info_type > HEP_DST_PORT) {
		LM_ERR("Invalid hep net var name!\n");
		return -1;
	}


	hep_str.len = 0;
	memset(hep_str.s, 0, HEPBUF_LEN);

	res->rs    = hep_str;
	res->flags = PV_VAL_STR;


	switch (net_info_type) {
	/* ip family */
	case HEP_PROTO_FAMILY:
		if (ri->src_ip.af == AF_INET) {
			SET_PVAL_STR(res, afinet_str);
		} else {
			SET_PVAL_STR(res, afinet6_str);
		}
		break;
	/* ip protocol id */
	case HEP_PROTO_ID:
		if (ri->proto < PROTO_UDP || ri->proto >= PROTO_OTHER) {
			LM_ALERT("Invalid proto!Maybe a new one was added %d\n",
					ri->proto);
			return -1;
		}
		SET_PVAL_STR(res, hep_net_protos[ri->proto]);

		break;
	/* ipv4 source */
	case HEP_IPV4_SRC:
	case HEP_IPV6_SRC:
		if (ri->src_ip.af == AF_INET) {
			if (inet_ntop(AF_INET, &ri->src_ip.u.addr,
					addr, INET_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				return -1;
			}
		} else {
			if (inet_ntop(AF_INET6, &ri->src_ip.u.addr,
					addr, INET6_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				return -1;
			}
		}

		addr_str.s = addr;
		addr_str.len = strlen(addr);

		SET_PVAL_STR(res, addr_str);

		break;
	/* ipv4 dest */
	case HEP_IPV4_DST:
	case HEP_IPV6_DST:
		if (ri->dst_ip.af == AF_INET) {
			if (inet_ntop(AF_INET, &ri->dst_ip.u.addr,
						addr, INET_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				return -1;
			}
		} else {
			if (inet_ntop(AF_INET6, &ri->dst_ip.u.addr,
						addr, INET6_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				return -1;
			}
		}

		addr_str.s = addr;
		addr_str.len = strlen(addr);

		SET_PVAL_STR(res, addr_str);

		break;
	/* source port */
	case HEP_SRC_PORT:
		SET_PVAL_INT(res, ri->src_port);

		break;
	/* destination port */
	case HEP_DST_PORT:
		SET_PVAL_INT(res, ri->dst_port);

		break;
	default:
		break;
	}

	return 0;

	#undef SET_PVAL_STR
	#undef SET_PVAL_INT
}


static int pv_get_hep_version(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct hep_context *ctx;

	ctx = HEP_GET_CONTEXT(hep_api);
	if (ctx == NULL) {
		LM_ERR("Hep context not there!\n");
		return -1;
	}

	res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
	res->ri = ctx->h.version;

	/* can't have bogus version number here since it's been already
	 * checked in proto_hep */
	res->rs = hep_str;
	res->rs.s = int2str(ctx->h.version, &res->rs.len);

	return 0;
}

static int
set_generic_hep_chunk(struct hepv3* h3, unsigned chunk_id, str *data)
{
	#define CHECK_LEN(_str, _len, _fail_fmt, ...)        \
		do {                                                    \
			if (_str->len < _len) {                              \
				LM_ERR("invalid "#_fail_fmt, __VA_ARGS__);      \
				return -1;                                      \
			}                                                   \
		} while(0);

	#define CHECK_PROTO_LEN(_str, _len) CHECK_LEN(_str, _len,   \
			"invalid protocol <%.*s>!\n", _str->len, _str->s);

	#define CHECK_PROTOT_LEN(_str, _len) CHECK_LEN(_str, _len,   \
			"invalid prot_t <%.*s>!\n", _str->len, _str->s);

	#define RETURN_ERROR(_format, ...)                          \
		do {                                                    \
			LM_ERR(_format, __VA_ARGS__);                       \
			return -1;                                          \
		} while (0);

	unsigned int port;
	unsigned int capture_id;


	switch (chunk_id) {
	/* ip family - this can't be set; it will be automatically set
	 * if you change ip addresses */
	case HEP_PROTO_FAMILY:
		h3->hg.ip_family.chunk.length = sizeof(hep_chunk_uint8_t);

		LM_DBG("Proto family can't be set!"
			" It shall be automatically updated when you change addresses!\n");

		return 0;
	/* ip protocol id */
	case HEP_PROTO_ID:
		/** possible values(string)
		 * UDP
		 * TCP
		 * TLS
		 * SCTP
		 * WS
		 */
		h3->hg.ip_proto.chunk.length = sizeof(hep_chunk_uint8_t);

		CHECK_PROTO_LEN(data, 2);

		switch (LOWER_WORD(data->s[0], data->s[1])) {
			case LOWER_WORD('u','d'):
				CHECK_PROTO_LEN(data, 3);
				if (LOWER_BYTE(data->s[2]) != 'p')
					RETURN_ERROR("invalid proto %.*s\n", data->len, data->s);

				h3->hg.ip_proto.data = PROTO_UDP;
				break;
			case LOWER_WORD('t','c'):
				CHECK_PROTO_LEN(data, 3);
				if (LOWER_BYTE(data->s[2]) != 'p')
					RETURN_ERROR("invalid proto %.*s\n", data->len, data->s);

				h3->hg.ip_proto.data = PROTO_TCP;
				break;
			case LOWER_WORD('t','l'):
				if (LOWER_BYTE(data->s[2]) != 's')
					RETURN_ERROR("invalid proto %.*s\n", data->len, data->s);

				h3->hg.ip_proto.data = PROTO_TLS;
				break;
			case LOWER_WORD('s','c'):
				if (LOWER_WORD(data->s[2], data->s[3]) != LOWER_WORD('t', 'p'))
					RETURN_ERROR("invalid proto %.*s\n", data->len, data->s);

				h3->hg.ip_proto.data = PROTO_SCTP;
				break;
			case LOWER_WORD('w','s'):
				h3->hg.ip_proto.data = PROTO_WS;
				break;
			default:
				LM_ERR("invalid protocol <%.*s>!\n", data->len, data->s);
				return -1;
		}
		break;
	/* ipv4 source */
	case HEP_IPV4_SRC:
	case HEP_IPV6_SRC:
		/** possible values(string)
		 * ip address in human readable format
		 */
		if (inet_pton(AF_INET, data->s, &h3->addr.ip4_addr.src_ip4.data) == 0) {
			/* check if it's ipV6*/
			if (inet_pton(AF_INET6, data->s, &h3->addr.ip6_addr.src_ip6.data) == 0) {
				RETURN_ERROR("address <<%.*s>> it's neither IPv4 nor IPv6!\n",
							data->len, data->s);
			} else {
				/* it's IPv6 change ip family*/
				if (h3->hg.ip_family.data == AF_INET) {
					LM_DBG("You changed source address in hep header to IPv6!"
					" You also have to change destination IP in order to work!\n");
					h3->hg.ip_family.data = AF_INET6;
				}
				h3->addr.ip6_addr.src_ip6.chunk.length = sizeof(hep_chunk_ip6_t);

			}
		} else {
			if (h3->hg.ip_family.data == AF_INET6) {
				LM_DBG("You changed source address in hep header to IPv6!"
					" You also have to change destination IP in order to work!\n");
				h3->hg.ip_family.data = AF_INET;
			}
			h3->addr.ip4_addr.src_ip4.chunk.length = sizeof(hep_chunk_ip4_t);
		}

		break;
	/* ipv4 dest */
	case HEP_IPV4_DST:
	case HEP_IPV6_DST:
		/** possible values(string)
		 * ip address in human readable format
		 */
		if (inet_pton(AF_INET, data->s, &h3->addr.ip4_addr.dst_ip4.data) == 0) {
			/* check if it's ipV6*/
			if (inet_pton(AF_INET6, data->s, &h3->addr.ip6_addr.dst_ip6.data) == 0) {
				RETURN_ERROR("address <<%.*s>> it's neither IPv4 nor IPv6!\n",
							data->len, data->s);
			} else {
				/* it's IPv6 change ip family*/
				if (h3->hg.ip_family.data == AF_INET) {
					LM_DBG("You changed source address in hep header to IPv6!"
					" You also have to change destination IP in order to work!\n");
					h3->hg.ip_family.data = AF_INET6;
				}
				h3->addr.ip6_addr.dst_ip6.chunk.length = sizeof(hep_chunk_ip6_t);

			}
		} else {
			if (h3->hg.ip_family.data == AF_INET6) {
				LM_DBG("You changed source address in hep header to IPv6!"
					" You also have to change destination IP in order to work!\n");
				h3->hg.ip_family.data = AF_INET;
			}
			h3->addr.ip4_addr.dst_ip4.chunk.length = sizeof(hep_chunk_ip4_t);
		}

		break;
	/* source port */
	case HEP_SRC_PORT:
		/** possible values(string/int)
		 * valid port
		 */
		if (str2int(data, &port) < 0)
			RETURN_ERROR("invalid port <%.*s>!\n", data->len, data->s);

		if (port > 65535)
			RETURN_ERROR("port not in range <%d>!\n", port);

		h3->hg.src_port.data = port;
		h3->hg.src_port.chunk.length = sizeof(hep_chunk_uint16_t);

		break;
	/* destination port */
	case HEP_DST_PORT:
		/** possible values(string/int)
		 * valid port
		 */
		if (str2int(data, &port) < 0)
			RETURN_ERROR("invalid port <%.*s>!\n", data->len, data->s);

		if (port > 65535)
			RETURN_ERROR("port not in range <%d>!\n", port);

		h3->hg.dst_port.data = port;
		h3->hg.dst_port.chunk.length = sizeof(hep_chunk_uint16_t);

		break;
	case HEP_TIMESTAMP:
	case HEP_TIMESTAMP_US:
		LM_WARN("Timestamp can't be set!\n");
		return 0;
	case HEP_PROTO_TYPE:
		/** possible values(string)
		 * SIP | XMPP | SDP | RTP | RTCP | MGCP | MEGACO
		 * | M2UA | M3UA | IAX | H322 | H321
		 */

		h3->hg.proto_t.chunk.length = sizeof(hep_chunk_uint8_t);

		CHECK_PROTOT_LEN(data, 3);

		switch (LOWER_DWORD(data->s[0], data->s[1], data->s[2],
					((data->len > 3) ? data->s[3] : 0))) {
			case LOWER_DWORD('s','i','p',0):
				h3->hg.proto_t.data = 0x01;
				break;
			case LOWER_DWORD('x','m','p','p'):
				h3->hg.proto_t.data = 0x02;
				break;
			case LOWER_DWORD('s','d','p',0):
				h3->hg.proto_t.data = 0x03;
				break;
			case LOWER_DWORD('r','t','p',0):
				h3->hg.proto_t.data = 0x04;
				break;
			case LOWER_DWORD('r','t','c','p'):
				h3->hg.proto_t.data = 0x05;
				break;
			case LOWER_DWORD('m','g','c','p'):
				h3->hg.proto_t.data = 0x06;
				break;
			case LOWER_DWORD('m','e','g','a'):
				CHECK_PROTOT_LEN(data, 6)
				if ((LOWER_BYTE(data->s[4]) != 'c'
							&& LOWER_BYTE(data->s[5]) != 'o'))
						RETURN_ERROR("invalid prot_t type <%.*s>!\n",
										data->len, data->s);
				h3->hg.proto_t.data = 0x07;
				break;
			case LOWER_DWORD('m','2','u','a'):
				h3->hg.proto_t.data = 0x08;
				break;
			case LOWER_DWORD('m','3','u','a'):
				h3->hg.proto_t.data = 0x09;
				break;
			case LOWER_DWORD('i','a','x',0):
				h3->hg.proto_t.data = 0x0A;
				break;
			case LOWER_DWORD('h','3','2','2'):
				h3->hg.proto_t.data = 0x0B;
				break;
			case LOWER_DWORD('h','3','2','1'):
				h3->hg.proto_t.data = 0x0C;
				break;
			default:
				RETURN_ERROR("invalid prot_t type <%.*s>!\n",
									data->len, data->s);
		}

		break;
	/* capture agent id */
	case HEP_AGENT_ID:
		/* DATA here */
		if (str2int(data, &capture_id) < 0)
			RETURN_ERROR("invalid capture id <%.*s>!\n",
										data->len, data->s);

		h3->hg.capt_id.data = capture_id;
		h3->hg.capt_id.chunk.length = sizeof(hep_chunk_uint32_t);

		break;
	/* payload */
	case HEP_PAYLOAD:
	case HEP_COMPRESSED_PAYLOAD:
		if (data->len>MAX_PAYLOAD) {
			LM_ERR("payload too big! Might be a message from an attacker!\n");
			return -1;
		}

		memcpy(payload_buf, data->s, data->len);
		h3->payload_chunk.data = payload_buf;
		h3->payload_chunk.chunk.length = data->len + sizeof(hep_chunk_t);

		break;
	/* internal correlation id */
	case HEP_CORRELATION_ID:
		LM_WARN("not implemented yet!won't set\n");
		break;
	/* vlan ID */
	}

	return 1;

	#undef CHECK_LEN
	#undef PROTO_LEN
	#undef PROTOT_LEN
	#undef RETURN_ERROR

}



int extract_host_port(void)
{
	if(raw_socket_listen.len) {
		char *p1,*p2;
		p1 = raw_socket_listen.s;

		if( (p1 = strrchr(p1, ':')) != 0 ) {
			 *p1 = '\0';
			 p1++;
			 p2=p1;
			 if((p2 = strrchr(p2, '-')) != 0 ) {
				p2++;
				moni_port_end = atoi(p2);
				p1[strlen(p1)-strlen(p2)-1]='\0';
			 }
			 moni_port_start = atoi(p1);
			 raw_socket_listen.len = strlen(raw_socket_listen.s);
		}
		return 1;
	}
	return 0;
}


static int child_init(int rank)
{
	if (db_url.s)
	  return sipcapture_db_init(&db_url);

	LM_DBG("db_url is empty\n");

	return 0;
}


int sipcapture_db_init(const str* db_url) {


	if(db_funcs.init == 0) {
		LM_CRIT("null dbf\n");
		goto error;
	}

	db_con = db_funcs.init(db_url);
	if (!db_con) {
		LM_ERR("unable to connect database\n");
		return -1;
	}

	if (db_funcs.use_table(db_con, &table_name) < 0) {
		LM_ERR("use_table failed\n");
		return -1;
	}

	return 0;

error:
	return -1;
}

void sipcapture_db_close(void)
{
	if (db_con && db_funcs.close){
		db_funcs.close(db_con);
		db_con=0;
	}

}

static void raw_socket_process(int rank)
{
	if (sipcapture_db_init(&db_url) < 0 ){
			LM_ERR("unable to open database connection\n");
			return;
		}

	raw_capture_rcv_loop(raw_sock_desc, moni_port_start, moni_port_end,
			moni_capture_on ? 0 : 1);

	/* Destroy DB socket */
	sipcapture_db_close();
}

static int do_remaining_queries(str* query_str) {
	if (!db_con) {
		db_con = db_funcs.init(&db_url);
		if (!db_con) {
			LM_ERR("unable to connect database\n");
			return -1;
		}

		if (db_funcs.use_table(db_con, &table_name) < 0) {
			LM_ERR("use_table failed\n");
			return -1;
		}
	}

	if (db_funcs.raw_query(db_con, query_str, NULL)) {
		LM_ERR("failed to insert remaining queries\n");
		return -1;
	}

	return 0;
}


static void destroy(void)
{
	str query_str;

	struct tz_table_list* it=tz_list, *tz_free;

	/* execute the uninserted queries - async only */
	if (DB_CAPABILITY(db_funcs, DB_CAP_ASYNC_RAW_QUERY)) {
		while (it) {
			if (it->as_qry && HAVE_SHARED_QUERIES) {
				if (CURR_QUERIES(it->as_qry)) {
					query_str.s = QUERY_BUF(it->as_qry);
					query_str.len = QUERY_LEN(it->as_qry);
					do_remaining_queries(&query_str);
				}

				shm_free(LAST_SUFFIX(it->as_qry).s);
				DESTROY_QUERY_LOCK(it->as_qry);
				shm_free(it->as_qry);
			}

			tz_free=it;
			it=it->next;
			pkg_free(tz_free);
		}

		it=rc_list;
		while (it) {
			if (it->as_qry && HAVE_SHARED_QUERIES) {
				if (CURR_QUERIES(it->as_qry)) {
					query_str.s = QUERY_BUF(it->as_qry);
					query_str.len = QUERY_LEN(it->as_qry);
					do_remaining_queries(&query_str);
				}

				shm_free(LAST_SUFFIX(it->as_qry).s);
				DESTROY_QUERY_LOCK(it->as_qry);
				shm_free(it->as_qry);
			}

			tz_free=it;
			it=it->next;
			pkg_free(tz_free);
		}

		if (!HAVE_SHARED_QUERIES) {
			if (tz_global.as_qry)
				pkg_free(tz_global.as_qry);
			if (rc_global.as_qry)
				pkg_free(rc_global.as_qry);
		} else {
			/* execute remaining queries for both sip_capture and report_capture */
			if (tz_global.as_qry) {
				if (CURR_QUERIES(tz_global.as_qry)) {
					query_str.s = QUERY_BUF(tz_global.as_qry);
					query_str.len = QUERY_LEN(tz_global.as_qry);
					do_remaining_queries(&query_str);
				}

				shm_free(LAST_SUFFIX(tz_global.as_qry).s);
				DESTROY_QUERY_LOCK(tz_global.as_qry);
				shm_free(tz_global.as_qry);
			}

			if (rc_global.as_qry) {
				if (CURR_QUERIES(rc_global.as_qry)) {
					query_str.s = QUERY_BUF(rc_global.as_qry);
					query_str.len = QUERY_LEN(rc_global.as_qry);
					do_remaining_queries(&query_str);
				}

				shm_free(LAST_SUFFIX(rc_global.as_qry).s);
				DESTROY_QUERY_LOCK(rc_global.as_qry);
				shm_free(rc_global.as_qry);
			}
		}
	}

	/* Destroy DB socket */
	sipcapture_db_close();

	if (capture_on_flag)
		shm_free(capture_on_flag);

	if(raw_sock_desc > 0) {
		 if(promisc_on && raw_interface.len) {
#ifdef __OS_linux
                         ifr.ifr_flags &= ~(IFF_PROMISC);

                         if (ioctl(raw_sock_desc, SIOCSIFFLAGS, &ifr) < 0) {
                                LM_ERR("could not remove PROMISC flag from interface [%.*s]:"
                                         " %s (%d)\n", raw_interface.len, raw_interface.s, strerror(errno), errno);
                         }
#endif
                }
		close(raw_sock_desc);
	}
}

/**
 * HEP message
 */
int hep_msg_received(void)
{
	struct sip_msg msg, *p_msg;

	struct hep_desc *h;
	struct hep_context* ctx;

	if ((ctx=HEP_GET_CONTEXT(hep_api))==NULL) {
		LM_WARN("not a hep message!\n");
		return -1;
	}

	h = &ctx->h;

	if(!hep_capture_on) {
		LM_ERR("HEP is not enabled\n");
		return 0;
	}

	if ( hep_route_id == HEP_NO_ROUTE ) {
		memset(&msg, 0, sizeof(struct sip_msg));

		switch (h->version) {
		case 1:
		case 2:
			msg.buf = h->u.hepv12.payload.s;
			msg.len = h->u.hepv12.payload.len;
			break;
		case 3:
			msg.buf = h->u.hepv3.payload_chunk.data;
			msg.len = h->u.hepv3.payload_chunk.chunk.length - sizeof(struct hep_chunk);
			break;
		default:
			LM_ERR("unknown hep proto [%d]\n", h->version);
			return -1;
		}

		if (parse_msg(msg.buf,msg.len,&msg)!=0) {
			LM_ERR("Unable to parse message in hep payload!"
					"Hep version %d!\n", h->version);
			return -1;
		}

	#if 0
		/* if message not parsed ok this helps with debugging */
		LM_DBG("********************************* SIP MESSAGE ******************\n"
				"%.*s\n"
				"***************************************************************\n",
				(int)msg.len, msg.buf);
	#endif

		/* we basically move the sip_capture() call from the scripts here */
		if (w_sip_capture(&msg, NULL, NULL, NULL, NULL, NULL) < 0) {
			LM_ERR("failed to store the message!\n");
			return -1;
		}

		/* avoid freeing buffer read from HEP structure */
		msg.buf = 0;
		free_sip_msg( &msg );

		/* don't go through the main route */
		return HEP_SCRIPT_SKIP;
	} else if (hep_route_id > HEP_SIP_ROUTE) {

		/* builds a dummy message */
		p_msg = get_dummy_sip_msg();
		if (p_msg == NULL) {
			LM_ERR("cannot create new dummy sip request\n");
			return -1;
		}

		/* set request route type */
		set_route_type( REQUEST_ROUTE );

		/* run given hep route */
		run_top_route( sroutes->request[hep_route_id].a, p_msg);

		/* free possible loaded avps */
		reset_avps();

		release_dummy_sip_msg(p_msg);

		/* requested to go through the main sip route */
		if (ctx->resume_with_sip) {
			return 0;
		} else {
			return HEP_SCRIPT_SKIP;
		}
	}

	return 0;
}


static int fixup_tz_table(void** param,  struct tz_table_list** list)
{
	str table_s;

	tz_table_t* tz_fxup_param;
	struct tz_table_list* list_el,* it;

	tz_fxup_param = pkg_malloc(sizeof(tz_table_t));
	if (tz_fxup_param == NULL) {
		LM_ERR("no more pkg mem!\n");
		return -1;
	}

	table_s = *((str *) *param);
	table_s.len = strlen(table_s.s);

	parse_table_str(&table_s, tz_fxup_param);

	*param = tz_fxup_param;

	/* if not there add this table to the list */
	for ( it=*list; it; it=it->next) {
		if (it->table->prefix.len == tz_fxup_param->prefix.len &&
				it->table->suffix.len == tz_fxup_param->suffix.len &&
				!memcmp(it->table->prefix.s, tz_fxup_param->prefix.s,
					tz_fxup_param->prefix.len) &&
				!memcmp(it->table->suffix.s, tz_fxup_param->suffix.s,
					tz_fxup_param->suffix.len)) {

			/* table already there */
			pkg_free(tz_fxup_param);
			*param = it->table;
			return 1;
		}
	}

	list_el = pkg_malloc(sizeof(struct tz_table_list));
	if (list_el == NULL) {
		LM_ERR("no more pkg mem!\n");
		return -1;
	}

	memset(list_el, 0, sizeof(struct tz_table_list));
	list_el->table = tz_fxup_param;

	if (*list == NULL) {
		*list = list_el;
	} else {
		list_el->next = *list;
		*list = list_el;
	}

	return 0;
}


static int fixup_async_tz_table(void** param,  struct tz_table_list** list)
{
	struct tz_table_list* list_el;
	int rc;

	rc = fixup_tz_table(param, list);
	if (rc < 0)
		return -1;
	if (rc > 0) /* table name already processed */
		return 0;

	list_el = *list;

	/* we store this in shm; need the queries in the end */
	if (HAVE_MULTIPLE_ASYNC_INSERT) {
		list_el->as_qry=shm_malloc(sizeof(struct _async_query));
		if (list_el->as_qry == NULL)
			goto shm_err;

		memset(list_el->as_qry, 0, sizeof(struct _async_query));

		LAST_SUFFIX(list_el->as_qry).s = shm_malloc(CAPTURE_TABLE_MAX_LEN);
		if (LAST_SUFFIX(list_el->as_qry).s == NULL)
			goto shm_err;

		LAST_SUFFIX(list_el->as_qry).len = 0;

		INIT_QUERY_LOCK(list_el->as_qry);
	}

	return 0;

shm_err:
	LM_ERR("no more shared memory!\n");
	return -1;

}

static int sip_capture_fix_table(void** param)
{
	return fixup_tz_table(param, &tz_list);
}

static int sip_capture_async_fix_table(void** param)
{
	return fixup_async_tz_table(param, &tz_list);
}


static int sip_capture_prepare(struct sip_msg* msg)
{
	/* We need parse all headers */
	if (parse_headers(msg, HDR_CALLID_F|HDR_EOH_F, 0) != 0) {
		LM_ERR("cannot parse headers\n");
		return -1;
	}

	return 0;
}

static int sip_capture_store(struct _sipcapture_object *sco,
							async_ctx *actx,
							struct tz_table_list* t_el)
{
	db_val_t db_vals[NR_KEYS];
	int i = 0, ret;

	if(sco==NULL)
	{
		LM_DBG("invalid parameter\n");
		return -1;
	}

	/* To stay compatible with both Postgres and MySQL, we omit auto-increment
	 * columns, rather than setting them to zero
	db_vals[0].type = DB_INT;
	db_vals[0].val.int_val = 0;
	*/

	db_vals[1].type = DB_DATETIME;
	db_vals[1].val.time_val = (sco->tmstamp/1000000);

	db_vals[2].type = DB_BIGINT;
	db_vals[2].val.bigint_val = sco->tmstamp;

	db_vals[3].type = DB_STR;
	db_vals[3].val.str_val = sco->method;

	db_vals[4].type = DB_STR;
	db_vals[4].val.str_val = sco->reply_reason;

	db_vals[5].type = DB_STR;
	db_vals[5].val.str_val = sco->ruri;

	db_vals[6].type = DB_STR;
	db_vals[6].val.str_val = sco->ruri_user;

	db_vals[7].type = DB_STR;
	db_vals[7].val.str_val = sco->from_user;

	db_vals[8].type = DB_STR;
	db_vals[8].val.str_val = sco->from_tag;

	db_vals[9].type = DB_STR;
	db_vals[9].val.str_val = sco->to_user;

	db_vals[10].type = DB_STR;
	db_vals[10].val.str_val = sco->to_tag;

	db_vals[11].type = DB_STR;
	db_vals[11].val.str_val = sco->pid_user;

	db_vals[12].type = DB_STR;
	db_vals[12].val.str_val = sco->contact_user;

	db_vals[13].type = DB_STR;
	db_vals[13].val.str_val = sco->auth_user;

	db_vals[14].type = DB_STR;
	db_vals[14].val.str_val = sco->callid;

	db_vals[15].type = DB_STR;
	db_vals[15].val.str_val = sco->callid_aleg;

	db_vals[16].type = DB_STR;
	db_vals[16].val.str_val = sco->via_1;

	db_vals[17].type = DB_STR;
	db_vals[17].val.str_val = sco->via_1_branch;

	db_vals[18].type = DB_STR;
	db_vals[18].val.str_val = sco->cseq;

	db_vals[19].type = DB_STR;
	db_vals[19].val.str_val = sco->reason;

	db_vals[20].type = DB_STR;
	db_vals[20].val.str_val = sco->content_type;

	db_vals[21].type = DB_STR;
	db_vals[21].val.str_val = sco->authorization;

	db_vals[22].type = DB_STR;
	db_vals[22].val.str_val = sco->user_agent;

	db_vals[23].type = DB_STR;
	db_vals[23].val.str_val = sco->source_ip;

	db_vals[24].type = DB_INT;
	db_vals[24].val.int_val = sco->source_port;

	db_vals[25].type = DB_STR;
	db_vals[25].val.str_val = sco->destination_ip;

	db_vals[26].type = DB_INT;
	db_vals[26].val.int_val = sco->destination_port;

	db_vals[27].type = DB_STR;
	db_vals[27].val.str_val = sco->contact_ip;

	db_vals[28].type = DB_INT;
	db_vals[28].val.int_val = sco->contact_port;

	db_vals[29].type = DB_STR;
	db_vals[29].val.str_val = sco->originator_ip;

	db_vals[30].type = DB_INT;
	db_vals[30].val.int_val = sco->originator_port;

	db_vals[31].type = DB_INT;
	db_vals[31].val.int_val = sco->proto;

	db_vals[32].type = DB_INT;
	db_vals[32].val.int_val = sco->family;

	db_vals[33].type = DB_STR;
	db_vals[33].val.str_val = sco->rtp_stat;

	/* proto type is defined in proto but not stored in homer db :-? */
	//db_vals[34].type = DB_INT;
	//db_vals[34].val.int_val = sco->proto_type;

	db_vals[34].type = DB_INT;
	db_vals[34].val.int_val = sco->type;

	db_vals[35].type = DB_STR;
	db_vals[35].val.str_val = sco->node;

	db_vals[36].type = DB_STR;
	db_vals[36].val.str_val = sco->correlation_id;

	db_vals[37].type = DB_STR;
	db_vals[37].val.str_val = sco->from_domain;

	db_vals[38].type = DB_STR;
	db_vals[38].val.str_val = sco->to_domain;

	db_vals[39].type = DB_STR;
	db_vals[39].val.str_val = sco->ruri_domain;

	db_vals[40].type = DB_BLOB;
	db_vals[40].val.blob_val = sco->msg;

	db_vals[41].type = DB_STR;
	db_vals[41].val.str_val = sco->custom_field1;

	db_vals[42].type = DB_STR;
	db_vals[42].val.str_val = sco->custom_field2;

	db_vals[43].type = DB_STR;
	db_vals[43].val.str_val = sco->custom_field3;

	/* no field can be null */
	for (i = 1; i < NR_KEYS; i++)
		db_vals[i].nul = 0;

	ret=1;

	/* each query has it's own parameters for the prepared statements */
	if (con_set_inslist(&db_funcs,db_con,&sc_ins_list,db_keys+1,NR_KEYS-1) < 0)
	               CON_RESET_INSLIST(db_con);
	CON_PS_REFERENCE(db_con) = &sc_ps;

	if (!actx && db_sync_store(db_vals+1, db_keys+1, NR_KEYS-1) != 1) {
		LM_ERR("failed to insert into database\n");
		return -1;
	} else if (actx) {
		ret = db_async_store(db_vals+1, db_keys+1, NR_KEYS-1, append_sc_values,
				actx, t_el);
	}

	#ifdef STATISTICS
		update_stat(sco->stat, 1);
	#endif

	return ret;
}


static int db_sync_store(db_val_t* vals, db_key_t* keys, int num_keys)
{
	LM_DBG("storing info...\n");

	if (current_table.s && current_table.len) {
		if (db_funcs.use_table(db_con, &current_table) < 0) {
			LM_ERR("use table failed!\n");
			return -1;
		}
	}


	if (db_funcs.insert(db_con, keys, vals, num_keys) < 0) {
		LM_ERR("failed to insert into database\n");
                goto error;
	}

	return 1;
error:
	return -1;
}

static inline int append_sc_values(char* buf, int max_len, db_val_t* db_vals)
{
	int len;

	len = snprintf(buf, max_len, VALUES_STR,
			VAL_TIME(db_vals+1), VAL_BIGINT(db_vals+2),
			VAL_STR(db_vals+3).len, VAL_STR(db_vals+3).s,
			VAL_STR(db_vals+4).len, VAL_STR(db_vals+4).s,
			VAL_STR(db_vals+5).len, VAL_STR(db_vals+5).s,
			VAL_STR(db_vals+6).len, VAL_STR(db_vals+6).s,
			VAL_STR(db_vals+7).len, VAL_STR(db_vals+7).s,
			VAL_STR(db_vals+8).len, VAL_STR(db_vals+8).s,
			VAL_STR(db_vals+9).len, VAL_STR(db_vals+9).s,
			VAL_STR(db_vals+10).len, VAL_STR(db_vals+10).s,
			VAL_STR(db_vals+11).len, VAL_STR(db_vals+11).s,
			VAL_STR(db_vals+12).len, VAL_STR(db_vals+12).s,
			VAL_STR(db_vals+13).len, VAL_STR(db_vals+13).s,
			VAL_STR(db_vals+14).len, VAL_STR(db_vals+14).s,
			VAL_STR(db_vals+15).len, VAL_STR(db_vals+15).s,
			VAL_STR(db_vals+16).len, VAL_STR(db_vals+16).s,
			VAL_STR(db_vals+17).len, VAL_STR(db_vals+17).s,
			VAL_STR(db_vals+18).len, VAL_STR(db_vals+18).s,
			VAL_STR(db_vals+19).len, VAL_STR(db_vals+19).s,
			VAL_STR(db_vals+20).len, VAL_STR(db_vals+20).s,
			VAL_STR(db_vals+21).len, VAL_STR(db_vals+21).s,
			VAL_STR(db_vals+22).len, VAL_STR(db_vals+22).s,
			VAL_STR(db_vals+23).len, VAL_STR(db_vals+23).s,
			VAL_INT(db_vals+24),
			VAL_STR(db_vals+25).len, VAL_STR(db_vals+25).s,
			VAL_INT(db_vals+26),
			VAL_STR(db_vals+27).len, VAL_STR(db_vals+27).s,
			VAL_INT(db_vals+28),
			VAL_STR(db_vals+29).len, VAL_STR(db_vals+29).s,
			VAL_INT(db_vals+30), VAL_INT(db_vals+31), VAL_INT(db_vals+32),
			VAL_STR(db_vals+33).len, VAL_STR(db_vals+33).s,
			VAL_INT(db_vals+34),
			VAL_STR(db_vals+35).len, VAL_STR(db_vals+35).s,
			VAL_STR(db_vals+36).len, VAL_STR(db_vals+36).s,
			VAL_STR(db_vals+37).len, VAL_STR(db_vals+37).s,
			VAL_STR(db_vals+38).len, VAL_STR(db_vals+38).s,
			VAL_STR(db_vals+39).len, VAL_STR(db_vals+39).s,
			VAL_BLOB(db_vals+40).len, VAL_BLOB(db_vals+40).s,
			VAL_STR(db_vals+41).len, VAL_STR(db_vals+41).s,
			VAL_STR(db_vals+42).len, VAL_STR(db_vals+42).s,
			VAL_STR(db_vals+43).len, VAL_STR(db_vals+43).s
				);

	return len;
}

static inline int init_raw_query(char* buf, int max_len, str* table_name,
		db_key_t* keys, int num_keys)
{
	int len, i, ret;
	len = snprintf(buf, max_len, "INSERT INTO %.*s(",
			table_name->len, table_name->s);

	for (i=0; i<num_keys-1; i++) {
		ret = snprintf(buf+len, max_len-len, "%.*s,", keys[i]->len, keys[i]->s);
		if (ret<0)	return ret;
		len += ret;
	}

	ret=snprintf(buf+len, max_len-len, "%.*s) VALUES",
				keys[num_keys-1]->len, keys[num_keys-1]->s);
	if (ret<0)	return ret;
	len += ret;

	return len;
}


static int
db_async_store(db_val_t* vals, db_key_t* keys, int num_keys,
	append_db_vals_f append_db_vals, async_ctx *actx,
	struct tz_table_list* t_el)
{
	int ret;
	int read_fd;
	str query_str;

	struct _async_query *crt_as_query;

	sc_async_param_t as_param;
	if (!DB_CAPABILITY(db_funcs, DB_CAP_ASYNC_RAW_QUERY)) {
		LM_WARN("This database module does not have async queries!"
				"Using sync insert!\n");
		actx->resume_f     = NULL;
		actx->resume_param = NULL;
		async_status  = ASYNC_NO_IO;
		return db_sync_store(vals, keys, num_keys);
	}

	if (HAVE_MULTIPLE_ASYNC_INSERT && t_el == NULL) {
		LM_ERR("can't do multiple insert!\n");
		actx->resume_f     = NULL;
		actx->resume_param = NULL;
		return -1;
	}

	crt_as_query = t_el->as_qry;

	if (HAVE_SHARED_QUERIES)
		GET_QUERY_LOCK(crt_as_query);

	/* use the global async query; we do this only once */
	if (CURR_QUERIES(crt_as_query) == 0) {
		QUERY_LEN(crt_as_query)=init_raw_query(QUERY_BUF(crt_as_query), MAX_QUERY,
				&current_table, keys, num_keys);
	} else {
		QUERY_BUF(crt_as_query)[QUERY_LEN(crt_as_query)++] = ',';
	}

	ret=append_db_vals(QUERY_BUF(crt_as_query)+QUERY_LEN(crt_as_query),
									MAX_QUERY-QUERY_LEN(crt_as_query), vals);
	if (ret < 0)
		goto no_buffer;

	QUERY_LEN(crt_as_query) += ret;

	if ((++CURR_QUERIES(crt_as_query)) == max_async_queries) {
		CURR_QUERIES(crt_as_query) = 0;

		query_str.s   = QUERY_BUF(crt_as_query);
		query_str.len = QUERY_LEN(crt_as_query);
		read_fd = db_funcs.async_raw_query(db_con, &query_str, &as_param);


		if (HAVE_SHARED_QUERIES)
			RELEASE_QUERY_LOCK(crt_as_query);

		if (read_fd < 0) {
			actx->resume_f     = NULL;
			actx->resume_param = NULL;
			return -1;
		}
		actx->resume_f     = resume_async_dbquery;
		actx->resume_param = as_param;
		async_status = read_fd;

		return 1;
	}

	if (HAVE_SHARED_QUERIES)
		RELEASE_QUERY_LOCK(crt_as_query);

	LM_DBG("no query executed!\n");
	async_status = ASYNC_NO_IO;

	return 1;
no_buffer:
	LM_ERR("buffer size exceeded\n");
	return -1;
}


int resume_async_dbquery(int fd, struct sip_msg *msg, void *_param)
{
	int rc;

	rc = db_funcs.async_resume(db_con, fd, NULL, (sc_async_param_t)_param);
	if (async_status == ASYNC_CONTINUE || async_status == ASYNC_CHANGE_FD)
		return rc;

	if (rc != 0) {
		LM_ERR("async query returned error (%d)\n", rc);
		db_funcs.async_free_result(db_con, NULL, (sc_async_param_t)_param);
		return -1;
	}

	LM_DBG("async query executed successfully!\n");
	async_status = ASYNC_DONE;

	db_funcs.async_free_result(db_con, NULL, (sc_async_param_t)_param);
	return 1;
}

static inline int change_table_unsafe(struct tz_table_list* t_el, str* new_table_name)
{
	str query_str;

	/* execute remaining queries for the old table */
	if (CURR_QUERIES(t_el->as_qry)) {
		query_str.s = QUERY_BUF(t_el->as_qry);
		query_str.len = QUERY_LEN(t_el->as_qry);
		if (do_remaining_queries(&query_str) < 0){
			LM_ERR("failed to execute remaining queries "
					"when switching to new table!\n");
		RELEASE_QUERY_LOCK(t_el->as_qry);
			return -1;
		}
		CURR_QUERIES(t_el->as_qry) = 0;

		/* update the suffix */
		LAST_SUFFIX(t_el->as_qry).len = new_table_name->len - t_el->table->prefix.len;
		memcpy(LAST_SUFFIX(t_el->as_qry).s,
				new_table_name->s+t_el->table->prefix.len,
					LAST_SUFFIX(t_el->as_qry).len);
	}

	return 0;
}

static inline int try_change_suffix(struct tz_table_list* t_el, str* new_table)
{
	int ret=0;

	struct _async_query* as_qry=t_el->as_qry;


	GET_QUERY_LOCK(as_qry);

	if (LAST_SUFFIX(as_qry).len) {
		if (memcmp(LAST_SUFFIX(as_qry).s, new_table->s+t_el->table->prefix.len,
					LAST_SUFFIX(as_qry).len)) {
			/* try changing table */
			if (change_table_unsafe(t_el, new_table) < 0) {
				LM_ERR("failed changing tables!\n");
				ret=-1;
				goto out_safe;
			}
		}
	}

out_safe:
	RELEASE_QUERY_LOCK(t_el->as_qry);
	return ret;
}

/*
 * no need to allocate output string buffer
 * */
static inline void build_table_name(tz_table_t* table_format, str* table_s)
{
	time_t rawtime;
	struct tm* gmtm;

	table_s->s = table_buf;
	memcpy(table_s->s, table_format->prefix.s, table_format->prefix.len);
	table_s->len = table_format->prefix.len;

	if (table_format->suffix.len && table_format->suffix.s) {
		time(&rawtime);
		gmtm = gmtime(&rawtime);
		table_s->len += strftime(table_s->s+table_s->len, CAPTURE_TABLE_MAX_LEN-table_s->len,
				table_format->suffix.s, gmtm);
	}
}

static inline struct tz_table_list* search_table(tz_table_t* el, struct tz_table_list* list) {
	struct tz_table_list* it = NULL;

	for (it=list; it; it=it->next)
		if (el->prefix.len && el->prefix.len == it->table->prefix.len &&
				!memcmp(el->prefix.s, it->table->prefix.s, el->prefix.len) &&
			el->suffix.len == it->table->suffix.len &&
				!memcmp(el->suffix.s, it->table->suffix.s, el->suffix.len))
			return it;

	return it;
}



static int sip_capture(struct sip_msg *msg, void *table,
                       str *cf1, str *cf2, str *cf3)
{
	return w_sip_capture(msg, table, NULL, cf1, cf2, cf3);
}

static int async_sip_capture(struct sip_msg *msg, async_ctx *actx, void *table,
                             str *cf1, str *cf2, str *cf3)
{
	return w_sip_capture(msg, table, actx, cf1, cf2, cf3);
}


static int w_sip_capture(struct sip_msg *msg, void *table_name,
                         async_ctx *actx, str *cf1, str *cf2, str *cf3)
{
	struct _sipcapture_object sco;
	struct sip_uri from, to, pai, contact;
	struct hdr_field *hook1 = NULL;
	struct hdr_field *tmphdr[4];
	contact_body_t*  cb=0;
	char src_buf_ip[IP_ADDR_MAX_STR_SIZE+12];
	char dst_buf_ip[IP_ADDR_MAX_STR_SIZE+12];
	char *port_str = NULL, *tmp = NULL;
	struct timeval tvb;
	struct timezone tz;
	char tmp_node[100];

	struct hep_desc *h=NULL;
	struct hep_context* ctx;

	tz_table_t* tzt = (tz_table_t*)table_name;

	struct tz_table_list* t_it=&tz_global;

	generic_chunk_t* it;
	int hep3_correlation_identifier;

	if (tzt == NULL ) {
		tzt = &tz_table;
	}

	/* need list element only if for async */
	if (IS_ASYNC_F && HAVE_MULTIPLE_ASYNC_INSERT)
	{
		if (table_name != NULL) {
		/* find the table in the list */
			if ((t_it=search_table(tzt, tz_list)) == NULL) {
				LM_ERR("Invalid table given!\n");
				return -1;
			}
		}
	}

	build_table_name(tzt, &current_table);
	if (tzt->suffix.s && tzt->suffix.len && IS_ASYNC_F && HAVE_MULTIPLE_ASYNC_INSERT) {
		if (try_change_suffix(t_it, &current_table) < 0)
			return -1;
	}

	gettimeofday( &tvb, &tz );

	if(msg==NULL) {
		LM_DBG("nothing to capture\n");
		return -1;
	}
	memset(&sco, 0, sizeof(struct _sipcapture_object));

	if (hep_capture_on) {
		if ((ctx=HEP_GET_CONTEXT(hep_api))==NULL) {
			LM_WARN("not a hep message!\n");
			return -1;
		}

		h = &ctx->h;
	}


	if(capture_on_flag==NULL || *capture_on_flag==0) {
		LM_DBG("capture off...\n");
		return -1;
	}

	if(sip_capture_prepare(msg)<0) return -1;

		if (h && h->version==3) {
			/*hepv3; struct might have been modified in script */
			sco.tmstamp =
				(unsigned long long)h->u.hepv3.hg.time_sec.data*1000000 +
				h->u.hepv3.hg.time_usec.data;
			snprintf(tmp_node, 100, "%.*s:%i", capture_node.len,
					capture_node.s, h->u.hepv3.hg.capt_id.data);
			sco.node.s = tmp_node;
			sco.node.len = strlen(tmp_node);
		}
		else if(h && h->version==2) {
			sco.tmstamp =
				(unsigned long long)h->u.hepv12.hep_time.tv_sec*1000000+
					h->u.hepv12.hep_time.tv_usec; /* micro ts */
			snprintf(tmp_node, 100, "%.*s:%i", capture_node.len, capture_node.s,
						h->u.hepv12.hep_time.captid);
               sco.node.s = tmp_node;
               sco.node.len = strlen(tmp_node);
        }
        else {
               sco.tmstamp = (unsigned long long)tvb.tv_sec*1000000+tvb.tv_usec; /* micro ts */
               sco.node = capture_node;
        }

	if(msg->first_line.type == SIP_REQUEST) {

		if (parse_sip_msg_uri(msg)<0) return -1;

		sco.method = msg->first_line.u.request.method;
		EMPTY_STR(sco.reply_reason);

		sco.ruri = msg->first_line.u.request.uri;
		sco.ruri_user = msg->parsed_uri.user;
		sco.ruri_domain = msg->parsed_uri.host;
	}
	else if(msg->first_line.type == SIP_REPLY) {
		sco.method = msg->first_line.u.reply.status;
		sco.reply_reason = msg->first_line.u.reply.reason;

		EMPTY_STR(sco.ruri);
		EMPTY_STR(sco.ruri_user);
	}
	else {
		LM_ERR("unknown type [%i]\n", msg->first_line.type);
		EMPTY_STR(sco.method);
		EMPTY_STR(sco.reply_reason);
		EMPTY_STR(sco.ruri);
		EMPTY_STR(sco.ruri_user);
	}

	/* Parse FROM */
        if(msg->from) {

              if (parse_from_header(msg)!=0){
                   LM_ERR("bad or missing" " From: header\n");
                   return -1;
              }

              if (parse_uri(get_from(msg)->uri.s, get_from(msg)->uri.len, &from)<0){
                   LM_ERR("bad from dropping"" packet\n");
                   return -1;
              }

              sco.from_user = from.user;
              sco.from_tag = get_from(msg)->tag_value;
			  sco.from_domain = from.host;
        }
        else {
		EMPTY_STR(sco.from_user);
		EMPTY_STR(sco.from_tag);
        }

        /* Parse TO */
        if(msg->to) {

              if (parse_uri(get_to(msg)->uri.s, get_to(msg)->uri.len, &to)<0){
                    LM_ERR("bad to dropping"" packet\n");
                    return -1;
              }

              sco.to_user = to.user;
              if(get_to(msg)->tag_value.len)
              		sco.to_tag = get_to(msg)->tag_value;
              else { EMPTY_STR(sco.to_tag); }
			  sco.to_domain = to.host;
        }
        else {
        	EMPTY_STR(sco.to_user);
        	EMPTY_STR(sco.to_tag);
        }

	/* Call-id */
	if(msg->callid) sco.callid = msg->callid->body;
	else { EMPTY_STR(sco.callid); }

	/* P-Asserted-Id */
	if(msg->pai && (parse_pai_header(msg) == 0)) {

	     if (parse_uri(get_pai(msg)->uri.s, get_pai(msg)->uri.len, &pai)<0){
             	LM_DBG("bad pai: method:[%.*s] CID: [%.*s]\n", sco.method.len, sco.method.s, sco.callid.len, sco.callid.s);
             }
             else {
	        LM_DBG("PARSE PAI: (%.*s)\n",get_pai(msg)->uri.len, get_pai(msg)->uri.s);
	        sco.pid_user = pai.user;
             }
	}
	else if(msg->ppi && (parse_ppi_header(msg) == 0)) {

	     if (parse_uri(get_ppi(msg)->uri.s, get_ppi(msg)->uri.len, &pai)<0){
             	LM_DBG("bad ppi: method:[%.*s] CID: [%.*s]\n", sco.method.len, sco.method.s, sco.callid.len, sco.callid.s);
             }
             else {
	        sco.pid_user = pai.user;
             }
        }
        else { EMPTY_STR(sco.pid_user); }

	/* Auth headers */
        if(msg->proxy_auth != NULL) hook1 = msg->proxy_auth;
        else if(msg->authorization != NULL) hook1 = msg->authorization;

        if(hook1) {
               if(parse_credentials(hook1) == 0)  sco.auth_user = ((auth_body_t*)(hook1->parsed))->digest.username.user;
               else { EMPTY_STR(sco.auth_user); }
        }
        else { EMPTY_STR(sco.auth_user);}

	if(msg->contact) {

              if (msg->contact->parsed == 0 && parse_contact(msg->contact) == -1) {
                     LM_ERR("while parsing <Contact:> header\n");
                     return -1;
              }

              cb = (contact_body_t*)msg->contact->parsed;

              memset(&contact, 0, sizeof(struct sip_uri));
              if(cb && cb->contacts) {
                  if(parse_uri( cb->contacts->uri.s, cb->contacts->uri.len, &contact)<0){
                        LM_ERR("bad contact dropping packet\n");
                        return -1;
                  }
              }
        }

	/* get header x-cid: */
	/* callid_aleg X-CID */
	if((tmphdr[0] = get_header_by_static_name(msg,"X-CID")) != NULL) {
		sco.callid_aleg = tmphdr[0]->body;
        }
	else { EMPTY_STR(sco.callid_aleg);}

	/* VIA 1 */
	sco.via_1 = msg->h_via1->body;

	/* Via branch */
	if(msg->via1->branch) sco.via_1_branch = msg->via1->branch->value;
	else { EMPTY_STR(sco.via_1_branch); }

	/* CSEQ */
	if(msg->cseq) sco.cseq = msg->cseq->body;
	else { EMPTY_STR(sco.cseq); }

	/* Reason */
	if((tmphdr[1] = get_header_by_static_name(msg,"Reason")) != NULL) {
		sco.reason =  tmphdr[1]->body;
	}
	else { EMPTY_STR(sco.reason); }

	/* Diversion */
	if(msg->diversion) sco.diversion = msg->diversion->body;
	else { EMPTY_STR(sco.diversion);}

	/* Content-type */
	if(msg->content_type) sco.content_type = msg->content_type->body;
	else { EMPTY_STR(sco.content_type);}

	/* User-Agent */
	if(msg->user_agent) sco.user_agent = msg->user_agent->body;
	else { EMPTY_STR(sco.user_agent);}

	/* Contact */
	if(msg->contact && cb) {
		sco.contact_ip = contact.host;
		str2int(&contact.port, (unsigned int*)&sco.contact_port);
	}
	else {
		EMPTY_STR(sco.contact_ip);
		sco.contact_port = 0;
	}

	/* X-OIP */
	if((tmphdr[2] = get_header_by_static_name(msg,"X-OIP")) != NULL) {
		sco.originator_ip = tmphdr[2]->body;
		/* Originator port. Should be parsed from XOIP header as ":" param */
		tmp = strchr(tmphdr[2]->body.s, ':');
	        if (tmp) {
			*tmp = '\0';
	                port_str = tmp + 1;
			sco.originator_port = strtol(port_str, NULL, 10);
		}
		else sco.originator_port = 0;
	}
	else {
		EMPTY_STR(sco.originator_ip);
		sco.originator_port = 0;
	}

	/* X-RTP-Stat */
	if((tmphdr[3] = get_header_by_static_name(msg,"X-RTP-Stat")) != NULL) {
		sco.rtp_stat =  tmphdr[3]->body;
	}
	/* P-RTP-Stat */
	else if((tmphdr[3] = get_header_by_static_name(msg,"P-RTP-Stat")) != NULL) {
		sco.rtp_stat =  tmphdr[3]->body;
	}
	else { EMPTY_STR(sco.rtp_stat); }


	/* PROTO TYPE
	 * FAMILY TYPE */
	if (h && h->version==3) {
		sco.proto = h->u.hepv3.hg.ip_proto.data;
		sco.family = h->u.hepv3.hg.ip_family.data;
		/*SIP, XMPP... */
		sco.proto_type = h->u.hepv3.hg.proto_t.data;

		if (h->u.hepv3.hg.ip_family.data == AF_INET) {
			if (inet_ntop(AF_INET, &h->u.hepv3.addr.ip4_addr.src_ip4.data,
					src_buf_ip, INET_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				return -1;
			}

			if (inet_ntop(AF_INET, &h->u.hepv3.addr.ip4_addr.dst_ip4.data,
					dst_buf_ip, INET_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				return -1;
			}
		} else {
			if (inet_ntop(AF_INET6, &h->u.hepv3.addr.ip6_addr.src_ip6.data,
					src_buf_ip, INET6_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				return -1;
			}

			if (inet_ntop(AF_INET6, &h->u.hepv3.addr.ip6_addr.dst_ip6.data,
					dst_buf_ip, INET6_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				return -1;
			}
		}

		sco.source_ip.s = src_buf_ip;
		sco.source_ip.len = strlen(src_buf_ip);
		sco.source_port = h->u.hepv3.hg.src_port.data;

		sco.destination_ip.s = dst_buf_ip;
		sco.destination_ip.len = strlen(dst_buf_ip);
		sco.destination_port = h->u.hepv3.hg.dst_port.data;
	} else if (h && (h->version == 1 || h->version == 2)) {
		sco.proto = h->u.hepv12.hdr.hp_p;
		sco.family = h->u.hepv12.hdr.hp_f;
		/* default SIP; hepv12 doesn't have proto type */
		sco.proto_type = 0x01;

		if (sco.family == AF_INET) {
			if (inet_ntop(AF_INET,
					&h->u.hepv12.addr.hep_ipheader.hp_src,
					src_buf_ip, INET_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				return -1;
			}

			if (inet_ntop(AF_INET,
					&h->u.hepv12.addr.hep_ipheader.hp_dst,
					dst_buf_ip, INET_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				return -1;
			}
		} else {
			if (inet_ntop(AF_INET6,
					&h->u.hepv12.addr.hep_ip6header.hp6_src,
					src_buf_ip, INET6_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				return -1;
			}

			if (inet_ntop(AF_INET6,
					&h->u.hepv12.addr.hep_ip6header.hp6_dst,
					dst_buf_ip, INET6_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				return -1;
			}
		}

		sco.source_ip.s = src_buf_ip;
		sco.source_ip.len = strlen(src_buf_ip);
		sco.source_port = h->u.hepv12.hdr.hp_sport;

		sco.destination_ip.s = dst_buf_ip;
		sco.destination_ip.len = strlen(dst_buf_ip);
		sco.destination_port = h->u.hepv12.hdr.hp_dport;
	} else {
		sco.proto = msg->rcv.proto;
		sco.family = msg->rcv.src_ip.af;

		/* IP source and destination */

		/*source ip*/
		tmp = ip_addr2a(&msg->rcv.src_ip);
		sco.source_ip.len = strlen(tmp);
		memcpy(src_buf_ip, tmp, sco.source_ip.len);
		sco.source_ip.s = src_buf_ip;
		sco.source_port = msg->rcv.src_port;

		/*destination ip*/
		tmp = ip_addr2a(&msg->rcv.dst_ip);
		sco.destination_ip.len = strlen(tmp);
		memcpy(dst_buf_ip, tmp, sco.destination_ip.len);
		sco.destination_ip.s = dst_buf_ip;
		sco.destination_port = msg->rcv.dst_port;
	}

	/* we change to internal proto id only for version 3; for version
	 * 1/2 we don't change the buffer inside opensips so we don't need
	 * internal protocol id */
	if (h && h->version == 3) {
		if(sco.proto == PROTO_UDP) sco.proto=IPPROTO_UDP;
		else if(sco.proto == PROTO_TCP) sco.proto=IPPROTO_TCP;
		else if(sco.proto == PROTO_TLS) sco.proto=IPPROTO_IDP;
												/* fake protocol */
		else if(sco.proto == PROTO_SCTP) sco.proto=IPPROTO_SCTP;
		else if(sco.proto == PROTO_WS) sco.proto=IPPROTO_ESP;
												/* fake protocol */
		else {
			LM_ERR("unknown protocol [%d]\n",sco.proto);
			sco.proto = PROTO_NONE;
		}
	}


	LM_DBG("src_ip: [%.*s]\n", sco.source_ip.len, sco.source_ip.s);
	LM_DBG("dst_ip: [%.*s]\n", sco.destination_ip.len, sco.destination_ip.s);

	LM_DBG("dst_port: [%d]\n", sco.destination_port);
	LM_DBG("src_port: [%d]\n", sco.source_port);

	/* PROTO */

	/* MESSAGE TYPE */
	sco.type = msg->first_line.type;

	sco.correlation_id.s = "";
	sco.correlation_id.len = 0;

	/* MSG */
	if (h) {
		if (h->version == 3) {
			if ( hep_api.get_homer_version() == HOMER5 ) {
				hep3_correlation_identifier = HEP_CORRELATION_ID;
			} else {
				hep3_correlation_identifier = HEP_EXTRA_CORRELATION;
			}

			for (it=h->u.hepv3.chunk_list; it; it=it->next) {
				if (it->chunk.type_id == hep3_correlation_identifier) {
					sco.correlation_id.s = it->data;
					sco.correlation_id.len = it->chunk.length - sizeof(hep_chunk_t);

					break;
				}
			}

			sco.msg.s = h->u.hepv3.payload_chunk.data;
			sco.msg.len = h->u.hepv3.payload_chunk.chunk.length - sizeof(hep_chunk_t);
		} else {
			sco.msg = h->u.hepv12.payload;
		}
	} else {
		sco.msg.s = msg->buf;
		sco.msg.len = msg->len;
	}
	//EMPTY_STR(sco.msg);

	if (cf1)
		sco.custom_field1 = *cf1;

	if (cf2)
		sco.custom_field2 = *cf2;

	if (cf3)
		sco.custom_field3 = *cf3;

#ifdef STATISTICS
	if(msg->first_line.type==SIP_REPLY) {
		sco.stat = sipcapture_rpl;
	} else {
		sco.stat = sipcapture_req;
	}
#endif

	LM_DBG("DONE\n");
	return sip_capture_store(&sco, actx, t_it);
}

/*
 * resolve data type in chunk
 */
enum hep_chunk_value_type {TYPE_ERROR=0,TYPE_UINT8=1,
					TYPE_UINT16=2, TYPE_UINT32=4, TYPE_INET_ADDR,
					TYPE_INET6_ADDR=16, TYPE_UTF8, TYPE_BLOB};

static int fix_hep_value_type(void **param)
{
	static const str type_uint_s={"uint", sizeof("uint")-1};
	static const str type_utf_string_s=str_init("utf8-string");
	static const str type_octet_string_s=str_init("octet-string");
	static const str type_inet_addr_s=str_init("inet4-addr");
	static const str type_inet6_addr_s=str_init("inet6-addr");
	str *s = (str *)*param;

	int diff;

	diff = s->len - type_uint_s.len; /* also applies to 'str' - same len as 'int'  */

	/* uintX or uintXX */
	if (diff > 0 && diff <=2 &&
			!strncasecmp(s->s, type_uint_s.s, type_uint_s.len)) {
		if (diff == 1) { /* should be int8 */
			if (s->s[s->len-1] == '8') {
				*param = (void*)(long)TYPE_UINT8;
				return 0;
			} else {
				goto error;
			}
		} else {
			if (s->s[s->len-2] == '1' && s->s[s->len-1] =='6') {
				*param = (void*)(long)TYPE_UINT16;
				return 0;
			} else if (s->s[s->len-2] == '3' && s->s[s->len-1] =='2') {
				*param = (void*)(long)TYPE_UINT32;
				return 0;
			} else {
				goto error;
			}
		}
	} else if (s->len==type_utf_string_s.len &&
			!strncasecmp(s->s, type_utf_string_s.s, type_utf_string_s.len)) {
		*param = (void*)(long)TYPE_UTF8;
		return 0;
	} else if (s->len == type_octet_string_s.len &&
			!strncasecmp(s->s, type_octet_string_s.s, type_octet_string_s.len)) {
		*param = (void*)(long)TYPE_BLOB;
		return 0;
	} else if (s->len == type_inet_addr_s.len &&
			!strncasecmp(s->s, type_inet_addr_s.s, type_inet_addr_s.len)) {
		*param = (void*)(long)TYPE_INET_ADDR;
		return 0;
	} else if (s->len == type_inet6_addr_s.len &&
			!strncasecmp(s->s, type_inet6_addr_s.s, type_inet6_addr_s.len)) {
		*param = (void*)(long)TYPE_INET6_ADDR;
		return 0;
	}

error:
	LM_ERR("unrecognized HEP data type: '%.*s'\n", s->len, s->s);
	return -1;
}

static int fix_hep_name(void **param)
{
	unsigned int chunk_id;
	str *in = (str *)*param;

	if (parse_hep_name(in, &chunk_id) < 0) {
		LM_ERR("invalid chunk id: '%.*s'\n", in->len, in->s);
		return -1;
	}

	*param = (void*)(unsigned long)chunk_id;
	return 0;
}

/*
 * get int value from int or hex value in string format
 */
static int fix_hex_int(str *s)
{

	unsigned int retval=0;

	if (!s->len || !s->s)
		goto error;

	if (s->len > 2)
		if ((s->s[0] == '0') && ((s->s[1]|0x20) == 'x')) {
			if (hexstr2int(s->s+2, s->len-2, &retval)!=0)
				goto error;
			else
				return retval;
		}

	if (str2int(s, (unsigned int*)&retval)<0)
		goto error;


	return retval;


error:
	LM_ERR("Invalid value for vendor_id: <%*s>!\n", s->len, s->s);
	return -1;

}

static int fix_vendor_id(void **param)
{
	int vendor_id;

	vendor_id = fix_hex_int((str *)*param);
	if (vendor_id < 0)
		return -1;

	*param = (void*)(long)vendor_id;
	return 0;
}


static int w_set_hep(struct sip_msg* msg, void *id, str *data_s,
                     void *type, void *vid)
{
	int data_len;
	int data_type = TYPE_UTF8;
	int vendor_id = HEP_OPENSIPS_VENDOR_ID;
	unsigned int chunk_id = (unsigned int)(unsigned long)id;

	unsigned int idata;

	struct in_addr addr4;
	struct in6_addr addr6;

	struct hep_desc *h;
	struct hep_context *ctx;

	generic_chunk_t *ch, *it;

	if ((ctx=HEP_GET_CONTEXT(hep_api)) ==  NULL) {
		LM_WARN("not a hep message!\n");
		return -1;
	}

	h = &ctx->h;
	if (h->version < 3) {
		LM_ERR("set chunk only available in HEPv3(EEP)!\n");
		return -1;
	}

	if (type)
		data_type = (int)(long)type;

	if (vid)
		vendor_id = (int)(long)vid;

	if (CHUNK_IS_IN_HEPSTRUCT(chunk_id))
		return set_generic_hep_chunk(&h->u.hepv3, chunk_id, data_s);

	it = NULL;
	for (it=h->u.hepv3.chunk_list; it; it = it->next) {
		if (it->chunk.type_id == chunk_id)
			break;
	}

	if (it == NULL){
		ch = shm_malloc(sizeof(generic_chunk_t));
		if (ch == NULL)
			goto shm_err;

		memset(ch, 0, sizeof(generic_chunk_t));
	} else {
		ch = it;
	}

	if (data_type == TYPE_UTF8 || data_type == TYPE_BLOB) {
		data_len = data_s->len;
	} else if (data_type == TYPE_INET_ADDR) {
		data_len = sizeof(struct in_addr);
		if (inet_pton(AF_INET, data_s->s, &addr4)==0) {
			LM_ERR("not an IPv4 address <<%.*s>>!\n",
					data_s->len, data_s->s);
			return -1;
		}
	} else if (data_type == TYPE_INET6_ADDR) {
		data_len = sizeof(struct in6_addr);
		if (inet_pton(AF_INET6, data_s->s, &addr6)==0) {
			LM_ERR("not an IPv6 address <<%.*s>>!\n",
					data_s->len, data_s->s);
			return -1;
		}
	} else {
		data_len = data_type;
		if (str2int(data_s, &idata) < 0) {
			LM_ERR("Invalid int value for chunk <%*.s>!\n",
										data_s->len, data_s->s);
		}

		/* keep values in big endian */
		if (data_type == TYPE_UINT32)
			idata = htonl(idata);
		else if (data_type == TYPE_UINT16)
			idata = htons(idata);
	}

	/* if new chunk data is same length as the old one no problem there;
	 * else we need to alloc new memory or delete some of the old one  :( */
	if (it && (it->chunk.length - sizeof(hep_chunk_t)) != data_len) {
		ch->data=shm_realloc(ch->data, data_len);
		if (ch->data == NULL)
			goto shm_err;
	} else if (it == NULL) {
		ch->data = shm_malloc(data_len);
		if (ch->data == NULL)
			goto shm_err;
	}

	if (data_type == TYPE_UTF8 || data_type == TYPE_BLOB) {
		memcpy(ch->data, data_s->s, data_len);
	} else if (data_type == TYPE_INET_ADDR) {
		memcpy(ch->data, &addr4, sizeof(struct in_addr));
	} else if (data_type == TYPE_INET6_ADDR) {
		memcpy(ch->data, &addr6, sizeof(struct in6_addr));
	} else {
		memcpy(ch->data, &idata, data_len);
	}

	ch->chunk.vendor_id = vendor_id;
	ch->chunk.type_id = chunk_id;
	ch->chunk.length = sizeof(hep_chunk_t) + data_len;


	/* if it's not a new chunk don't put it in the list */
	if (it == NULL) {
		if (h->u.hepv3.chunk_list == NULL) {
			h->u.hepv3.chunk_list = ch;
		} else {
			for (it=h->u.hepv3.chunk_list; it->next; it=it->next);
			it->next=ch;
		}
	}

	return 1;

shm_err:
	LM_ERR("no more shm!\n");
	return -1;
}

static int w_get_hep(struct sip_msg* msg, void *_id, void *_type,
                     pv_spec_p data_pv, pv_spec_p vendor_pv)
{
	int data_type = (int)(long)_type;

	unsigned int net_data;
	unsigned int chunk_id = (unsigned int)(unsigned long)_id;

	struct hep_desc *h;
	struct hep_context *ctx;

	pv_value_t data_val, vendor_val;
	generic_chunk_t* it;

	if (!data_pv && !vendor_pv) {
		LM_ERR("No output vars provided!\n");
		return -1;
	}

	if ((ctx=HEP_GET_CONTEXT(hep_api)) ==  NULL) {
		LM_WARN("not a hep message!\n");
		return -1;
	}

	h = &ctx->h;
	if (h->version < 3) {
		LM_ERR("get chunk only available in HEPv3(EEP)!\n");
		return -1;
	}

	if (CHUNK_IS_IN_HEPSTRUCT(chunk_id)) {
		/* don't need type for these; we already know it */
		if (data_pv) {
			if (get_hep_chunk(&h->u.hepv3, chunk_id, &data_val) < 0)
				goto set_pv_null;
		}

		if (vendor_pv) {
			vendor_val.ri = 0;
			vendor_val.flags = PV_TYPE_INT;
		}

		goto set_pv_values;
	}

	for (it=h->u.hepv3.chunk_list; it; it=it->next) {
		if (it->chunk.type_id == chunk_id) {
			vendor_val.ri = it->chunk.vendor_id;
			vendor_val.flags = PV_TYPE_INT;

			switch (data_type) {
				/* all int types are in big endian */
				case TYPE_UINT8:
					data_val.ri = ((char*)it->data)[0];
					data_val.flags = PV_TYPE_INT;

					break;
				case TYPE_UINT16:
					net_data = ((unsigned short*)it->data)[0];
					data_val.ri = htons(net_data);
					data_val.flags = PV_TYPE_INT;

					break;
				case TYPE_UINT32:
					net_data = ((unsigned int*)it->data)[0];
					data_val.ri = htonl(net_data);
					data_val.flags = PV_TYPE_INT;

					break;
				case TYPE_INET_ADDR:
					hep_str.len = 0;
					memset(hep_str.s, 0, HEPBUF_LEN);

					if (inet_ntop(AF_INET, it->data,
								hep_str.s, INET_ADDRSTRLEN) == NULL) {
						LM_ERR("Not an IPv4 address!\n");
						return -1;
					}

					hep_str.len = strlen(hep_str.s);

					data_val.rs = hep_str;
					data_val.flags = PV_VAL_STR;

					break;
				case TYPE_INET6_ADDR:
					hep_str.len = 0;
					memset(hep_str.s, 0, HEPBUF_LEN);

					if (inet_ntop(AF_INET6, it->data,
								hep_str.s, INET6_ADDRSTRLEN) == NULL) {
						LM_ERR("Not an IPv4 address!\n");
						return -1;
					}

					hep_str.len = strlen(hep_str.s);

					data_val.rs = hep_str;
					data_val.flags = PV_VAL_STR;

					break;
				case TYPE_UTF8:
				case TYPE_BLOB:
					data_val.rs.s = (char*)it->data;
					data_val.rs.len = it->chunk.length - sizeof(hep_chunk_t);
					data_val.flags = PV_VAL_STR;

					break;
			}
			break;
		}
	}

	if (it == NULL)
		goto set_pv_null;

set_pv_values:
	if (data_pv && pv_set_value(msg, data_pv, 0, &data_val) < 0) {
		LM_ERR("failed to set chunk_data_pv!\n");
		return -1;
	}

	if (vendor_pv && pv_set_value(msg, vendor_pv, 0, &vendor_val) < 0) {
		LM_ERR("failed to set vendor_id_pv!\n");
		return -1;
	}

	return 1;

set_pv_null:
	if (data_pv && pv_set_value(msg, data_pv, 0, NULL) < 0) {
		LM_ERR("failed to set chunk_data_pv!\n");
		return -1;
	}

	if (vendor_pv && pv_set_value(msg, vendor_pv, 0, NULL) < 0) {
		LM_ERR("failed to set vendor_id_pv!\n");
		return -1;
	}

	return -1;
}

static int w_del_hep(struct sip_msg* msg, void *id)
{
	unsigned int chunk_id = (unsigned int)(unsigned long)id;

	struct hep_desc *h;
	struct hep_context *ctx;

	generic_chunk_t* it;
	generic_chunk_t* foo;

	if ((ctx=HEP_GET_CONTEXT(hep_api)) ==  NULL) {
		LM_WARN("not a hep message!\n");
		return -1;
	}

	h = &ctx->h;
	if (h->version < 3) {
		LM_ERR("del chunk only available in HEPv3(EEP)!\n");
		return -1;
	}

	if (CHUNK_IS_IN_HEPSTRUCT(chunk_id))
		return del_hep_chunk(&h->u.hepv3, chunk_id);


	it=h->u.hepv3.chunk_list;

	if (it->chunk.type_id == chunk_id) {
		h->u.hepv3.chunk_list = it->next;
		foo = it;
		goto free_chunk;
	}

	while (it->next) {
		if (it->next->chunk.type_id == chunk_id) {
			foo = it->next;
			it->next = it->next->next;
			goto free_chunk;
		}

		it = it->next;
	}

	return -1;

free_chunk:
	shm_free(foo->data);
	shm_free(foo);

	return 1;
}

static inline void osip_to_net_proto(unsigned char* proto)
{
	if(*proto == PROTO_UDP) *proto=IPPROTO_UDP;
	else if(*proto == PROTO_TCP) *proto=IPPROTO_TCP;
	else if(*proto == PROTO_TLS) *proto=IPPROTO_IDP;
											/* fake protocol */
	else if(*proto == PROTO_SCTP) *proto=IPPROTO_SCTP;
	else if(*proto == PROTO_WS) *proto=IPPROTO_ESP;
                                            /* fake protocol */
	else {
		LM_ERR("unknown protocol [%d]\n", *proto);
		*proto = PROTO_NONE;
	}


}


static void hepv2_to_buf(struct hepv12* h2, char* buf, int *len)
{
	int buflen;
	int payload_len = *len;

	/* instead of copying element by element we just convert
	 * to network order and after convert it back */
	h2->hdr.hp_sport = htons(h2->hdr.hp_sport);
	h2->hdr.hp_dport = htons(h2->hdr.hp_dport);

	memcpy(buf, &h2->hdr, sizeof(struct hep_hdr));
	buflen = sizeof(struct hep_hdr);

	h2->hdr.hp_sport = ntohs(h2->hdr.hp_sport);
	h2->hdr.hp_dport = ntohs(h2->hdr.hp_dport);

	if (h2->hdr.hp_f==AF_INET) {
		memcpy(buf+buflen, &h2->addr.hep_ipheader, sizeof(struct hep_iphdr));
		buflen += sizeof(struct hep_iphdr);
	} else {
		memcpy(buf+buflen, &h2->addr.hep_ip6header, sizeof(struct hep_ip6hdr));
		buflen += sizeof(struct hep_ip6hdr);
	}

	if (h2->hdr.hp_v == 2) {
		memcpy(buf + buflen, &h2->hep_time, sizeof(struct hep_timehdr));
		buflen += sizeof(struct hep_timehdr);
	}


	memcpy(buf + buflen, h2->payload.s, payload_len);


	*len = buflen + payload_len;
}

static void hepv3_to_buf(struct hepv3* h3, char* buf, int *len)
{
	#define CONVERT_HEP_CHUNK(_src_chunk, _dst_chunk)          \
	do {                                                       \
		_dst_chunk.vendor_id = htons(_src_chunk.vendor_id);    \
		_dst_chunk.length    = htons(_src_chunk.length);       \
		_dst_chunk.type_id   = htons(_src_chunk.type_id);      \
	} while(0);


	#define CHUNK_COPY_AND_UPDATE(buf, len, chunk)             \
		do {                                                   \
			memcpy(buf+len, &chunk, sizeof(chunk));            \
			len += sizeof(chunk);                              \
		} while(0);

	int af;
	int buflen=sizeof(hep_ctrl_t);

	unsigned char osip_proto;

	generic_chunk_t* it;

	hep_chunk_t chunk_copy;

	u_int16_t data16;
	u_int32_t data32;

	if (h3->hg.ip_family.chunk.length == 0) {
		LM_WARN("ip family chunk removed! considering default IPv4!\n");
		af = AF_INET;
	} else {
		if (h3->hg.ip_family.data != AF_INET && h3->hg.ip_family.data != AF_INET6) {
			LM_ERR("Unknown family <%d>! Will use IPv4\n", h3->hg.ip_family.data);
			af = AF_INET;
		} else {
			af = h3->hg.ip_family.data;
		}
	}


	if (h3->hg.ip_family.chunk.length) {
		CONVERT_HEP_CHUNK(h3->hg.ip_family.chunk, chunk_copy);
		CHUNK_COPY_AND_UPDATE(buf, buflen, chunk_copy);

		memcpy(buf+buflen, &h3->hg.ip_family.data, sizeof(u_int8_t));
		buflen += sizeof(u_int8_t);
	}

	if (h3->hg.ip_proto.chunk.length) {
		CONVERT_HEP_CHUNK(h3->hg.ip_proto.chunk, chunk_copy);
		CHUNK_COPY_AND_UPDATE(buf, buflen, chunk_copy);

		osip_proto = h3->hg.ip_proto.data;
		osip_to_net_proto(&h3->hg.ip_proto.data);

		memcpy(buf+buflen, &h3->hg.ip_proto.data, sizeof(u_int8_t));
		buflen += sizeof(u_int8_t);

		h3->hg.ip_proto.data = osip_proto;
	}

	if (h3->hg.src_port.chunk.length) {
		CONVERT_HEP_CHUNK(h3->hg.src_port.chunk, chunk_copy);
		CHUNK_COPY_AND_UPDATE(buf, buflen, chunk_copy);

		data16 = htons(h3->hg.src_port.data);
		memcpy(buf+buflen, &data16, sizeof(u_int16_t));
		buflen += sizeof(u_int16_t);
	}

	if (h3->hg.dst_port.chunk.length) {
		CONVERT_HEP_CHUNK(h3->hg.dst_port.chunk, chunk_copy);
		CHUNK_COPY_AND_UPDATE(buf, buflen, chunk_copy);

		data16 = htons(h3->hg.dst_port.data);
		memcpy(buf+buflen, &data16, sizeof(u_int16_t));
		buflen += sizeof(u_int16_t);
	}

	if (h3->hg.time_sec.chunk.length) {
		CONVERT_HEP_CHUNK(h3->hg.time_sec.chunk, chunk_copy);
		CHUNK_COPY_AND_UPDATE(buf, buflen, chunk_copy);

		data32 = htonl(h3->hg.time_sec.data);
		memcpy(buf+buflen, &data32, sizeof(u_int32_t));
		buflen += sizeof(u_int32_t);
	}

	if (h3->hg.time_usec.chunk.length) {
		CONVERT_HEP_CHUNK(h3->hg.time_usec.chunk, chunk_copy);
		CHUNK_COPY_AND_UPDATE(buf, buflen, chunk_copy);

		data32 = htonl(h3->hg.time_usec.data);
		memcpy(buf+buflen, &data32, sizeof(u_int32_t));
		buflen += sizeof(u_int32_t);
	}

	if (h3->hg.proto_t.chunk.length) {
		CONVERT_HEP_CHUNK(h3->hg.proto_t.chunk, chunk_copy);
		CHUNK_COPY_AND_UPDATE(buf, buflen, chunk_copy);

		memcpy(buf+buflen, &h3->hg.proto_t.data, sizeof(u_int8_t));
		buflen += sizeof(u_int8_t);
	}

	if (h3->hg.capt_id.chunk.length) {
		CONVERT_HEP_CHUNK(h3->hg.capt_id.chunk, chunk_copy);
		CHUNK_COPY_AND_UPDATE(buf, buflen, chunk_copy);

		data32 = htonl(h3->hg.capt_id.data);
		memcpy(buf+buflen, &data32, sizeof(u_int32_t));
		buflen += sizeof(u_int32_t);
	}

	if (af == AF_INET) {
		if (h3->addr.ip4_addr.src_ip4.chunk.length) {
			CONVERT_HEP_CHUNK(h3->addr.ip4_addr.src_ip4.chunk, chunk_copy);
			CHUNK_COPY_AND_UPDATE(buf, buflen, chunk_copy);

			memcpy(buf+buflen, &h3->addr.ip4_addr.src_ip4.data,
					sizeof(struct in_addr));
			buflen += sizeof(struct in_addr);
		}

		if (h3->addr.ip4_addr.dst_ip4.chunk.length) {
			CONVERT_HEP_CHUNK(h3->addr.ip4_addr.dst_ip4.chunk, chunk_copy);
			CHUNK_COPY_AND_UPDATE(buf, buflen, chunk_copy);

			memcpy(buf+buflen, &h3->addr.ip4_addr.dst_ip4.data,
					sizeof(struct in_addr));
			buflen += sizeof(struct in_addr);
		}
	} else {
		if (h3->addr.ip6_addr.src_ip6.chunk.length) {
			CONVERT_HEP_CHUNK(h3->addr.ip6_addr.src_ip6.chunk, chunk_copy);
			CHUNK_COPY_AND_UPDATE(buf, buflen, chunk_copy);

			memcpy(buf+buflen, &h3->addr.ip6_addr.src_ip6.data,
					sizeof(struct in6_addr));
			buflen += sizeof(struct in6_addr);
		}

		if (h3->addr.ip6_addr.dst_ip6.chunk.length) {
			CONVERT_HEP_CHUNK(h3->addr.ip6_addr.dst_ip6.chunk, chunk_copy);
			CHUNK_COPY_AND_UPDATE(buf, buflen, chunk_copy);

			memcpy(buf+buflen, &h3->addr.ip6_addr.dst_ip6.data,
					sizeof(struct in6_addr));
			buflen += sizeof(struct in6_addr);
		}
	}

	for (it=h3->chunk_list; it; it=it->next) {
		CONVERT_HEP_CHUNK(it->chunk, chunk_copy);
		CHUNK_COPY_AND_UPDATE(buf, buflen, chunk_copy);


		memcpy(buf+buflen, it->data, it->chunk.length - sizeof(hep_chunk_t));
		buflen += it->chunk.length - sizeof(hep_chunk_t);
	}

	if (h3->payload_chunk.chunk.length) {
		CONVERT_HEP_CHUNK(h3->payload_chunk.chunk, chunk_copy);
		CHUNK_COPY_AND_UPDATE(buf, buflen, chunk_copy);

		memcpy(buf+buflen, h3->payload_chunk.data,
				h3->payload_chunk.chunk.length - sizeof(hep_chunk_t));
		buflen += (h3->payload_chunk.chunk.length - sizeof(hep_chunk_t));
	}

	memcpy(((hep_ctrl_t*)buf)->id, HEP_HEADER_ID, HEP_HEADER_ID_LEN);
	((hep_ctrl_t*)buf)->length = htons(buflen);

	*len = buflen;
}


static int build_hep_buf(str* hep_buf, int* proto)
{

	struct hep_context *ctx;

	ctx = HEP_GET_CONTEXT(hep_api);
	if (ctx == NULL) {
		LM_ERR("Hep context not there!\n");
		return -1;
	}

	if (ctx->h.version == 3) {
		*proto = ctx->h.u.hepv3.hg.ip_proto.data;
		hepv3_to_buf(&ctx->h.u.hepv3, hep_buf->s, &hep_buf->len);
	} else {
		*proto = ctx->h.u.hepv12.hdr.hp_p;
		hepv2_to_buf(&ctx->h.u.hepv12, hep_buf->s, &hep_buf->len);
	}

	return ctx->h.version;
}

static int w_hep_relay(struct sip_msg *msg)
{
	struct proxy_l* proxy;
	struct sip_uri uri;

	struct socket_info* send_sock;

	union sockaddr_union to;

	str* uri_s;
	str  buf_s;

	int hep_version;
	int proto;
	int hep_proto;

	char proto_buf[PROTO_NAME_MAX_SIZE];

	if (msg==NULL) {
		LM_ERR("Invalid sip message!\n");
		return -1;
	}

	uri_s=GET_NEXT_HOP(msg);
	if (parse_uri(uri_s->s, uri_s->len, &uri) < 0) {
		LM_ERR("bad uri <%.*s>!\n", uri_s->len, uri_s->s);
		return -1;
	}



	/* build everything but the sip message because we don't have it yet*/
	buf_s.s = payload_buf;

	/* this way we will know what's the size of the hep payload
	 * in version 1/2 */
	buf_s.len = msg->len;
	if ((hep_version=build_hep_buf(&buf_s, &proto)) < 0) {
		LM_ERR("failed to append hep header!\n");
		return -1;
	}

	if (uri.proto == 0 || uri.proto == PROTO_UDP) {
		hep_proto = PROTO_HEP_UDP;
	} else if (uri.proto == PROTO_TCP) {
		if (hep_version == 1 || hep_version == 2) {
			LM_ERR("TCP not supported for HEPv%d\n", hep_version);
			return -1;
		}
		hep_proto = PROTO_HEP_TCP;
	} else {
		LM_ERR("cannot send hep with proto %s\n",
					proto2str(uri.proto, proto_buf));
		return -1;
	}

	/* get net info */
	proxy = mk_proxy(
		&uri.host,
		uri.port_no?uri.port_no:SIP_PORT, proto, 0 );
	if (proxy == 0) {
		LM_ERR("bad host name in URI <%.*s>\n", uri_s->len, ZSW(uri_s->s));
		return 0;
	}

	hostent2su( &to, &proxy->host, proxy->addr_idx,
				(proxy->port)?proxy->port:SIP_PORT);

	/* FIXME */
	send_sock=get_send_socket(0, &to, hep_proto);
	if (send_sock==0){
		LM_ERR("cannot forward to af %d, proto %d no corresponding"
			"listening socket\n", to.s.sa_family, proxy->proto);
		return -1;
	}

	do {
		if (msg_send(NULL, hep_proto, &to, 0, buf_s.s, buf_s.len, msg)<0){
			LM_ERR("failed to send message!\n");
			continue;
		}

		break;
	} while( get_next_su( proxy, &to, 0)==0 );

	free_proxy(proxy);
	pkg_free(proxy);

	return 1;
}


static int w_hep_resume_sip(struct sip_msg *msg)
{
	struct hep_context* ctx;

	if (current_processing_ctx == NULL ||
			msg == NULL) {
		return -1;
	}

	if ((ctx=HEP_GET_CONTEXT(hep_api))==NULL) {
		LM_WARN("not a hep message!\n");
		return -1;
	}

	if (ctx == NULL) {
		LM_ERR(" no hep context!\n");
		return -1;
	}

	if (ctx->resume_with_sip != 0) {
		LM_ERR("Called this function twice! You should call it"
				"only from the hep route!\n");
		return -1;
	}

	ctx->resume_with_sip = 1;

	/* break hep route execution */
	return 0;
}

#define capture_is_off(_msg) \
	(capture_on_flag==NULL || *capture_on_flag==0)


/*
 * Report Capture logic
 */


/* fixup */
static void set_rtcp_keys(void)
{
	int homerV = hep_api.get_homer_version();

	if ( homerV == HOMER5 ) {
		rtcp_db_keys[0] = &date_column;
		rtcp_db_keys[1] = &micro_ts_column;
		rtcp_db_keys[2] = &correlation_column;
		rtcp_db_keys[3] = &source_ip_column;
		rtcp_db_keys[4] = &source_port_column;
		rtcp_db_keys[5] = &dest_ip_column;
		rtcp_db_keys[6] = &dest_port_column;
		rtcp_db_keys[7] = &proto_column;
		rtcp_db_keys[8] = &family_column;
		rtcp_db_keys[9] = &type_column;
		rtcp_db_keys[10] = &node_column;
		rtcp_db_keys[11] = &msg_column;

		rtp_keys_no = RTCP_H5_NR_KEYS;
	} else if ( homerV == HOMER6 ) {
		/* homer6 column adaptation */
		rtcp_db_keys[0] = &date_column6;
		rtcp_db_keys[1] = &micro_ts_column6;
		rtcp_db_keys[2] = &correlation_column6;
		rtcp_db_keys[3] = &source_ip_column6;
		rtcp_db_keys[4] = &source_port_column6;
		rtcp_db_keys[5] = &dest_ip_column6;
		rtcp_db_keys[6] = &dest_port_column6;
		rtcp_db_keys[7] = &proto_column6;
		rtcp_db_keys[8] = &family_column6;
		rtcp_db_keys[9] = &type_column6;
		rtcp_db_keys[10] = &node_column6;
		rtcp_db_keys[11] = &msg_column6;
		rtcp_db_keys[12] = &payload_len_column6;
		rtcp_db_keys[13] = &extra_correlation_column6;
		rtcp_db_keys[14] = &capture_ip_column6;
		rtcp_db_keys[15] = &capture_id_column6;
		rtcp_db_keys[16] = &event_column6;
		rtp_keys_no = RTCP_NR_KEYS;
	}
}

static inline void build_hepv3_obj(struct hepv3* h3, struct _sipcapture_object* sco) {

	sco->proto = h3->hg.ip_proto.data;
	sco->family = h3->hg.ip_family.data;

	if (h3->hg.ip_family.data == AF_INET) {
		inet_ntop(AF_INET, &(h3->addr.ip4_addr.dst_ip4.data), sco->destination_ip.s, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(h3->addr.ip4_addr.src_ip4.data), sco->source_ip.s, INET_ADDRSTRLEN);
	} else {
		inet_ntop(AF_INET, &(h3->addr.ip6_addr.dst_ip6.data), sco->destination_ip.s, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET, &(h3->addr.ip6_addr.src_ip6.data), sco->source_ip.s, INET6_ADDRSTRLEN);
	}

	sco->source_ip.len = strlen(sco->source_ip.s);
	sco->source_port = h3->hg.src_port.data;

	sco->destination_ip.len = strlen(sco->destination_ip.s);
	sco->destination_port = h3->hg.dst_port.data;

	sco->proto_type = h3->hg.proto_t.data;

	sco->tmstamp = (unsigned long long)h3->hg.time_sec.data*1000000
					+ h3->hg.time_usec.data;

	/* WARN node must be allocated */
	sco->node.len = snprintf(sco->node.s, 100, "%.*s:%i", capture_node.len, capture_node.s, h3->hg.capt_id.data);
}

static inline void build_hepv2_obj(struct hepv12* h2, struct _sipcapture_object* sco) {
	struct timeval tvb;

	sco->proto = h2->hdr.hp_p;
	sco->family = h2->hdr.hp_f;

	if (h2->hdr.hp_f == AF_INET) {
		inet_ntop(AF_INET, &(h2->addr.hep_ipheader.hp_dst), sco->destination_ip.s, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(h2->addr.hep_ipheader.hp_src), sco->source_ip.s, INET_ADDRSTRLEN);
	} else {
		inet_ntop(AF_INET, &(h2->addr.hep_ip6header.hp6_dst), sco->destination_ip.s, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET, &(h2->addr.hep_ip6header.hp6_src), sco->source_ip.s, INET6_ADDRSTRLEN);
	}

	sco->source_ip.len = strlen(sco->source_ip.s);
	sco->source_port = h2->hdr.hp_sport;

	sco->destination_ip.len = strlen(sco->destination_ip.s);
	sco->destination_port = h2->hdr.hp_dport;

	/* only sip in hepv1/2 */
	sco->proto_type = 1;

	if (h2->hdr.hp_v == 2) {
		sco->tmstamp = (unsigned long long)h2->hep_time.tv_sec*1000000
						+ h2->hep_time.tv_usec;

		/* WARN node must be allocated */
		sco->node.len = snprintf(sco->node.s, 100, "%.*s:%i", capture_node.len, capture_node.s, h2->hep_time.captid);
	} else {
		gettimeofday(&tvb, NULL);
		sco->tmstamp = (unsigned long long)tvb.tv_sec * 1000000 + tvb.tv_usec;

		sco->node = capture_node;
	}
}

static inline int append_rc_values(char* buf, int max_len, db_val_t* db_vals)
{
	int len;

	len = snprintf(buf, max_len, RTCP_VALUES_STR,
			VAL_TIME(db_vals+0), VAL_BIGINT(db_vals+1),
			VAL_STR(db_vals+2).len, VAL_STR(db_vals+2).s,
			VAL_STR(db_vals+3).len, VAL_STR(db_vals+3).s,
			VAL_INT(db_vals+4),
			VAL_STR(db_vals+5).len, VAL_STR(db_vals+5).s,
			VAL_INT(db_vals+6), VAL_INT(db_vals+7), VAL_INT(db_vals+8), VAL_INT(db_vals+9),
			VAL_STR(db_vals+10).len, VAL_STR(db_vals+10).s,
			VAL_STR(db_vals+11).len, VAL_STR(db_vals+11).s
		);

	return len;
}


static int report_capture(struct sip_msg* msg, str* table, str* cor_id,
		unsigned int* proto_t, struct tz_table_list* t_el,
		async_ctx *actx)
{
	char node[100], holder;
	char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];

	int homerV = hep_api.get_homer_version();

	struct _sipcapture_object sco;

	struct hep_desc *h;
	struct hep_context *ctx;

	db_val_t db_vals[rtp_keys_no];

	generic_chunk_t* it;
	str addr_str, payload_str;

	char addr[INET6_ADDRSTRLEN];
	cJSON *pld_root, *event;

	if ((ctx=HEP_GET_CONTEXT(hep_api)) == NULL) {
		LM_WARN("not a hep message!\n");
		return -1;
	}

	h= &ctx->h;

	memset(&sco, 0, sizeof(struct _sipcapture_object));

	sco.node.s = node;
	sco.source_ip.s = src_ip;
	sco.destination_ip.s = dst_ip;

	if (h->version == 3) {
		build_hepv3_obj(&h->u.hepv3, &sco);
	} else {
		build_hepv2_obj(&h->u.hepv12, &sco);
	}


	memset(db_vals, 0, sizeof(db_val_t) * rtp_keys_no);

	if ( !(h->version == 3 && homerV == HOMER6) ) {
		db_vals[0].type = DB_DATETIME;
		db_vals[0].val.time_val = (sco.tmstamp/1000000);

		db_vals[1].type = DB_BIGINT;
		db_vals[1].val.bigint_val = sco.tmstamp;
	} else {
		db_vals[0].type = DB_DATETIME;
		db_vals[0].val.time_val = h->u.hepv3.hg.time_sec.data;

		db_vals[1].type = DB_INT;
		db_vals[1].val.bigint_val = h->u.hepv3.hg.time_usec.data;
	}

	db_vals[2].type = DB_STR;
	db_vals[2].val.str_val = *cor_id;

	db_vals[3].type = DB_STR;
	db_vals[3].val.str_val = sco.source_ip;

	db_vals[4].type = DB_INT;
	db_vals[4].val.int_val = sco.source_port;

	db_vals[5].type = DB_STR;
	db_vals[5].val.str_val = sco.destination_ip;

	db_vals[6].type = DB_INT;
	db_vals[6].val.int_val = sco.destination_port;

	db_vals[7].type = DB_INT;
	db_vals[7].val.int_val = sco.proto;

	db_vals[8].type = DB_INT;
	db_vals[8].val.int_val = sco.family;

	db_vals[9].type = DB_INT;
	db_vals[9].val.int_val = proto_t?(*proto_t):sco.proto_type;

	db_vals[10].type = DB_STR;
	if ( !(h->version == 3 && homerV == HOMER6 ) ) {
		db_vals[10].val.str_val = sco.node;
	} else {
		db_vals[10].val.str_val = capture_node;
	}

	db_vals[11].type = DB_STR;


	/* we can have other pyload than sip only for hepv3 */
	if (h->version == 3) {
		if ( h->u.hepv3.payload_chunk.chunk.length ) {
			db_vals[11].val.str_val.s = h->u.hepv3.payload_chunk.data;
			db_vals[11].val.str_val.len = h->u.hepv3.payload_chunk.chunk.length - sizeof(h->u.hepv3.payload_chunk.chunk);
		} else {
			memset( &db_vals[11].val.str_val, 0, sizeof(str) );
		}
	} else {
		db_vals[11].val.str_val.s   = msg->buf;
		db_vals[11].val.str_val.len = msg->len;
	}

	if ( h->version == 3 && homerV == HOMER6 ) {
		db_vals[12].type = DB_INT;
		db_vals[12].val.int_val = db_vals[11].val.str_val.len;

		db_vals[13].type = DB_STR;

		/* search extra correlation header */
		for (it=h->u.hepv3.chunk_list; it; it=it->next) {
			if (it->chunk.type_id == HEP_EXTRA_CORRELATION) {
				db_vals[13].val.str_val.s = it->data;
				db_vals[13].val.str_val.len = it->chunk.length - sizeof(hep_chunk_t);

				break;
			}
		}

		/* not found; set it to empty */
		if ( !it ) {
			db_vals[13].val.str_val.s = "";
		}

		/* get incoming interface ip from receive info */
		if (ctx->ri.dst_ip.af == AF_INET) {
			if (inet_ntop(AF_INET, &ctx->ri.dst_ip.u.addr,
						addr, INET_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				addr_str.s = "";
				addr_str.len = 0;
			} else {
				addr_str.s = addr;
				addr_str.len = strlen(addr);
			}
		} else {
			if (inet_ntop(AF_INET6, &ctx->ri.dst_ip.u.addr,
						addr, INET6_ADDRSTRLEN) == NULL) {
				LM_ERR("failed to convert ipv4 address!\n");
				addr_str.s = "";
				addr_str.len = 0;
			} else {
				addr_str.s = addr;
				addr_str.len = strlen(addr);
			}
		}

		db_vals[14].type = DB_STR;
		db_vals[14].val.str_val = addr_str;

		db_vals[15].type = DB_INT;
		if ( h->u.hepv3.hg.capt_id.chunk.length != 0 ) {
			db_vals[15].val.int_val = h->u.hepv3.hg.capt_id.data;
		} else {
			/* chunk was removed*/
			db_vals[15].val.int_val = 0;
		}

		/* event column; parse the payload as JSON and see if there's any Event key */
		payload_str = db_vals[11].val.str_val;

		/* VERY VERY UGLY HACK; but we should be safe since no one else should
		 * access this memory area while we parse this as JSON */
		holder = payload_str.s[payload_str.len];
		payload_str.s[payload_str.len] = 0;

		pld_root = cJSON_Parse(payload_str.s);

		if ( pld_root ) {
			payload_str.s[payload_str.len] = holder;

			/* now search if we have any Event key */
			event = cJSON_GetObjectItem(pld_root, "Event");
			db_vals[16].type = DB_STR;
			if ( event ) {
				db_vals[16].val.str_val.s = event->valuestring;
				db_vals[16].val.str_val.len = strlen(event->valuestring);
			} else {
				db_vals[16].val.str_val.s = "";
				db_vals[16].val.str_val.len = 0;
			}

			cJSON_Delete( pld_root );
		} else {
			db_vals[16].val.str_val.s = "";
			db_vals[16].val.str_val.len = 0;
		}
	} else if ( homerV == HOMER6 ) {
		/* only warn; continue as usual */
		LM_WARN("using homer6 but hepv2 message received!\n");
	}

	/* each query has it's own parameters for the prepared statements */
	if (con_set_inslist(&db_funcs,db_con,&rc_ins_list,db_keys,NR_KEYS) < 0 )
	               CON_RESET_INSLIST(db_con);
	CON_PS_REFERENCE(db_con) = &rc_ps;

	if (!actx && db_sync_store(db_vals, rtcp_db_keys, rtp_keys_no) != 1) {
		LM_ERR("failed to insert into database\n");
		return -1;
	} else if (actx) {
		return db_async_store(db_vals, rtcp_db_keys, rtp_keys_no,
			append_rc_values, actx, t_el);
	}

	return 1;
}

static int w_report_capture_async(struct sip_msg* msg, async_ctx *actx,
                                  str* cor_id, void* table, int* proto_t)
{
	return w_report_capture(msg, cor_id, table, proto_t, actx);
}


static int w_report_capture(struct sip_msg* msg, str* cor_id, void* table,
                            int* _proto_t, async_ctx* actx)
{
	unsigned int proto_t = (unsigned int)*_proto_t;
	tz_table_t* rct;
	struct tz_table_list* t_el=&rc_global;

	if (table) {
		rct = *(tz_table_t **)table;
	}	else {
		rct = &rc_table;
	}

	if (!cor_id->s || cor_id->len == 0) {
		LM_ERR("empty correlation id!\n");
		return -1;
	}

	if (IS_ASYNC_F && HAVE_MULTIPLE_ASYNC_INSERT) {
		if (table) {
			if ((t_el=search_table(rct, rc_list)) == NULL) {
				LM_ERR("Invalid table given!\n");
				return -1;
			}
		}
	}

	build_table_name(rct, &current_table);
	if (rct->suffix.s && rct->suffix.len && IS_ASYNC_F && HAVE_MULTIPLE_ASYNC_INSERT) {
		if (try_change_suffix(t_el, &current_table) < 0)
			return -1;
	}

	return report_capture(msg, &current_table, cor_id, &proto_t, t_el, actx);
}

/*
 *
 */

/*! \brief
 * MI Sip_capture command
 *
 * MI command format:
 * name: sip_capture
 * attribute: name=none, value=[on|off]
 */
static mi_response_t *sip_capture_mi(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;

	if (capture_on_flag==NULL)
		return init_mi_error(500, MI_SSTR("Internal error"));

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if ( *capture_on_flag ) {
		if (add_mi_string(resp_obj, MI_SSTR("SIP capturing"), MI_SSTR("on")) < 0) {
			free_mi_response(resp);
			return 0;
		}
	} else {
		if (add_mi_string(resp_obj, MI_SSTR("SIP capturing"), MI_SSTR("off")) < 0) {
			free_mi_response(resp);
			return 0;
		}
	}

	return resp;
}

static mi_response_t *sip_capture_mi_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str new_mode;

	if (get_mi_string_param(params, "trace_mode", &new_mode.s, &new_mode.len) < 0)
		return init_mi_param_error();

	if ( (new_mode.s[0] | 0x20) == 'o' &&
			(new_mode.s[1] | 0x20) == 'n' ) {
		*capture_on_flag = 1;
		return init_mi_result_ok();
	} else
	if ( (new_mode.s[0] | 0x20) == 'o' &&
			(new_mode.s[1] | 0x20) == 'f' &&
			(new_mode.s[2] | 0x20) == 'f' ) {
		*capture_on_flag = 0;
		return init_mi_result_ok();
	} else {
		return init_mi_error_extra(500, MI_SSTR("Bad parameter value"),
			MI_SSTR("trace_mode should be 'on' or 'off'"));
	}
}

/* Local raw socket */
int raw_capture_socket(struct ip_addr* ip, str* iface, int port_start, int port_end, int proto)
{

	int sock = -1;
	union sockaddr_union su;

#ifdef __OS_linux
	struct sock_fprog pf;
	char short_ifname[sizeof(int)];
	int ifname_len;
	char* ifname;
#endif
 	//0x0003 - all packets
 	if(proto == IPPROTO_IPIP) {
        	sock = socket(PF_INET, SOCK_RAW, proto);
        }
#ifdef __OS_linux
 	else if(proto == htons(0x800)) {
        	sock = socket(PF_PACKET, SOCK_RAW, proto);
        }
#endif
        else {
                LM_ERR("LSF currently supported only on linux\n");
                goto error;
        }

	if (sock==-1)
		goto error;

#ifdef __OS_linux

	/* set socket options */
	if (iface && iface->s){

		/* workaround for linux bug: arg to setsockopt must have at least
		 * sizeof(int) size or EINVAL would be returned */
		if (iface->len<sizeof(int)){
			memcpy(short_ifname, iface->s, iface->len);
			short_ifname[iface->len]=0; /* make sure it's zero term */
			ifname_len=sizeof(short_ifname);
			ifname=short_ifname;
		}else{
			ifname_len=iface->len;
			ifname=iface->s;
		}
		if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, ifname_len) <0){
				LM_ERR("could not bind to %.*s: %s [%d]\n",
							iface->len, ZSW(iface->s), strerror(errno), errno);
				goto error;
		}
	}

	if(bpf_on) {

		memset(&pf, 0, sizeof(pf));
	        pf.len = sizeof(BPF_code) / sizeof(BPF_code[0]);
        	pf.filter = (struct sock_filter *) BPF_code;

                if(!port_end) port_end = port_start;

        	/* Start PORT */
        	BPF_code[5]  = (struct sock_filter)BPF_JUMP(0x35, port_start, 0, 1);
        	BPF_code[8] = (struct  sock_filter)BPF_JUMP(0x35, port_start, 11, 13);
        	BPF_code[16] = (struct sock_filter)BPF_JUMP(0x35, port_start, 0, 1);
        	BPF_code[19] = (struct sock_filter)BPF_JUMP(0x35, port_start, 0, 2);
        	/* Stop PORT */
        	BPF_code[6]  = (struct sock_filter)BPF_JUMP(0x25, port_end, 0, 14);
        	BPF_code[17] = (struct sock_filter)BPF_JUMP(0x25, port_end, 0, 3);
        	BPF_code[20] = (struct sock_filter)BPF_JUMP(0x25, port_end, 1, 0);

        	/* Attach the filter to the socket */
        	if(setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &pf, sizeof(pf)) < 0 ) {
                        LM_ERR("setsockopt filter: [%s] [%d]\n", strerror(errno), errno);
                }
        }
#endif

        if (ip && proto == IPPROTO_IPIP){
                init_su(&su, ip, 0);
                if (bind(sock, &su.s, sockaddru_len(su))==-1){
                        LM_ERR("bind(%s) failed: %s [%d]\n",
                                ip_addr2a(ip), strerror(errno), errno);
                        goto error;
                }
        }

	return sock;

error:
	if (sock!=-1) close(sock);
	return -1;

}


struct ipc_msg_pack {
	struct receive_info ri;
	str buf;
};

void rpc_msg_received(int sender, void *param)
{
	struct ipc_msg_pack *ipc_pack = (struct ipc_msg_pack *)param;

	receive_msg( ipc_pack->buf.s, ipc_pack->buf.len,
		&ipc_pack->ri, NULL, 0);

	shm_free( ipc_pack );
}

/* Local raw receive loop */
int raw_capture_rcv_loop(int rsock, int port1, int port2, int ipip) {


	static char buf [BUF_SIZE+1];
	union sockaddr_union from;
	union sockaddr_union to;
	int len;
	struct ip *iph;
	struct udphdr *udph;
	char* udph_start;
	unsigned short udp_len;
	int offset = 0;
	char* end;
	unsigned short dst_port;
	unsigned short src_port;
	struct ip_addr dst_ip, src_ip;
	struct ipc_msg_pack *ipc_pack;


	for(;;) {

		len = recvfrom(rsock, buf, BUF_SIZE, 0, 0, 0);

		if (len<0){
			if (len==-1){
				LM_ERR("recvfrom: %s [%d]\n",
						strerror(errno), errno);
				if ((errno==EINTR)||(errno==EWOULDBLOCK))
					continue;
				else goto error;
			}else{
				LM_DBG("recvfrom error: %d\n", len);
				continue;
			}
		}

		end=buf+len;

		offset =  ipip ? sizeof(struct ip) : ETHHDR;

		if (len < (sizeof(struct ip)+sizeof(struct udphdr) + offset)) {
			LM_DBG("received small packet: %d. Ignore it\n",len);
			continue;
		}

		iph = (struct ip*) (buf + offset);

		offset+=iph->ip_hl*4;

		udph_start = buf+offset;

		udph = (struct udphdr*) udph_start;
		offset +=sizeof(struct udphdr);

		if ((buf+offset)>end){
			continue;
		}

		/* cut off the offset */
		len -= offset;

		if (len<MIN_UDP_PACKET){
			LM_DBG("probing packet received from\n");
			continue;
		}

		udp_len=ntohs(udph->uh_ulen);
		if ((udph_start+udp_len)!=end){
			if ((udph_start+udp_len)>end){
				continue;
			}else{
				LM_DBG("udp length too small: %d/%d\n", (int)udp_len, (int)(end-udph_start));
				continue;
			}
		}

		ipc_pack = (struct ipc_msg_pack*)shm_malloc( sizeof(struct ipc_msg_pack) + len );
		if (ipc_pack==NULL) {
			LM_ERR("failed to allocate new ipc_msg_pack, discarding...\n");
			continue;
		}
		memset( ipc_pack, 0, sizeof(struct ipc_msg_pack) + len);

		/* cleaup previous values in dst */
		memset(&dst_ip, 0, sizeof(dst_ip));

		/*FIL IPs*/
		dst_ip.af=AF_INET;
		dst_ip.len=4;
		dst_ip.u.addr32[0]=iph->ip_dst.s_addr;
		/* fill dst_port */
		dst_port=ntohs(udph->uh_dport);
		ip_addr2su(&to, &dst_ip, dst_port);
		/* fill src_port */
		src_port=ntohs(udph->uh_sport);
		src_ip.af=AF_INET;
		src_ip.len=4;
		src_ip.u.addr32[0]=iph->ip_src.s_addr;
		ip_addr2su(&from, &src_ip, src_port);
		su_setport(&from, src_port);

		ipc_pack->ri.src_su=from;
		su2ip_addr(&(ipc_pack->ri.src_ip), &from);
		ipc_pack->ri.src_port=src_port;
			su2ip_addr(&(ipc_pack->ri.dst_ip), &to);
		ipc_pack->ri.dst_port=dst_port;
		ipc_pack->ri.proto=PROTO_UDP;

		LM_DBG("PORT: [%d] and [%d]\n", port1, port2);

		ipc_pack->buf.s = (char*)(ipc_pack+1);
		ipc_pack->buf.len = len;
		memcpy( ipc_pack->buf.s, buf+offset, len);

		if((!port1 && !port2)
		|| (src_port >= port1 && src_port <= port2)
		|| (dst_port >= port1 && dst_port <= port2)
		|| (!port2 && (src_port == port1 || dst_port == port1)))
			ipc_dispatch_rpc( rpc_msg_received, ipc_pack);
	}

	return 0;

error:
	return -1;

}

#undef QUERY_BUF
#undef QUERY_LEN
#undef LAST_SUFFIX
#undef HAVE_MULTIPLE_ASYNC_INSERT
