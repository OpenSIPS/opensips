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

#ifdef STATISTICS
#include "../../statistics.h"
#endif

struct _sipcapture_object {
	str method;
	str reply_reason;
	str ruri;
	str ruri_user;
	str from_user;
	str from_tag;
	str to_user;
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
	str rtp_stat;
	int type;
	long long tmstamp;
	str node;
	str msg;
#ifdef STATISTICS
	stat_var *stat;
#endif
};

#define ETHHDR 14 /* sizeof of ethhdr structure */
#define EMPTY_STR(val) val.s=""; val.len=0;
#define TABLE_LEN 256
#define NR_KEYS 37

typedef void* sc_async_param_t;
db_key_t db_keys[NR_KEYS];

/* module function prototypes */
static int mod_init(void);
static int child_init(int rank);
static void raw_socket_process(int rank);
static void destroy(void);
static int sip_capture(struct sip_msg *msg, char *s1, char *s2);
static int async_sip_capture(struct sip_msg* msg, async_resume_module **resume_f,
		void **resume_param, str* s1, str* s2);
static int w_sip_capture(struct sip_msg *msg,
				async_resume_module **resume_f, void **resume_param);
int hep_msg_received(struct hep_desc *h, struct receive_info *ri);
int extract_host_port(void);
int raw_capture_socket(struct ip_addr* ip, str* iface, int port_start, int port_end, int proto);
int raw_capture_rcv_loop(int rsock, int port1, int port2, int ipip);
int sipcapture_db_init(const str* db_url);
void sipcapture_db_close(void);

static struct mi_root* sip_capture_mi(struct mi_root* cmd, void* param );
static int db_sync_store(db_val_t* db_vals);
static int db_async_store(db_val_t* db_vals,
							async_resume_module **resume_f, void **resume_param);
int resume_async_dbquery(int fd, struct sip_msg *msg, void *_param);

static str db_url		= {NULL, 0};
static str table_name		= str_init("sip_capture");
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
static str authorization_column = str_init("authorization");
static str user_agent_column 	= str_init("user_agent");
static str source_ip_column 	= str_init("source_ip");
static str source_port_column 	= str_init("source_port");
static str dest_ip_column	= str_init("destination_ip");
static str dest_port_column 	= str_init("destination_port");
static str contact_ip_column 	= str_init("contact_ip");
static str contact_port_column 	= str_init("contact_port");
static str orig_ip_column 	= str_init("originator_ip");
static str orig_port_column 	= str_init("originator_port");
static str rtp_stat_column 	= str_init("rtp_stat");
static str proto_column 	= str_init("proto");
static str family_column 	= str_init("family");
static str type_column 		= str_init("type");
static str node_column 		= str_init("node");
static str msg_column 		= str_init("msg");
static str capture_node 	= str_init("homer01");


#define MAX_QUERY 65535
#define VALUES_STR "(%d,%ld,%lld,'%.*s','%.*s','%.*s','%.*s','%.*s','%.*s'," \
					"'%.*s','%.*s','%.*s','%.*s','%.*s','%.*s','%.*s','%.*s','%.*s'," \
					"'%.*s','%.*s','%.*s','%.*s','%.*s','%.*s',%d,'%.*s',%d," \
					"'%.*s',%d,'%.*s',%d,%d,%d,'%.*s',%d,'%.*s','%.*s')"

int  max_async_queries=5;

static int base_query_len;

struct _async_query {
	int curr_async_queries;

	int  query_len;
	char query_buf[65535];

	gen_lock_t query_lock;
} *async_query;

#define query_buf    async_query->query_buf
#define query_len    async_query->query_len
#define query_lock   async_query->query_lock
#define curr_queries async_query->curr_async_queries


int raw_sock_desc = -1; /* raw socket used for ip packets */
unsigned int raw_sock_children = 1;
int capture_on   = 0;
int hep_capture_on   = 0;
int ipip_capture_on   = 0;
int moni_capture_on   = 0;
int moni_port_start = 0;
int moni_port_end   = 0;
int *capture_on_flag = NULL;
int promisc_on = 0;
int bpf_on = 0;

int hep_store_no_script=0;

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

static db_ps_t sipcapture_ps = NULL;
static query_list_t *ins_list = NULL;

struct hep_timehdr* heptime;

proto_hep_api_t hep_api;
load_hep_f load_hep;

/*! \brief
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"sip_capture", (cmd_function)sip_capture, 0, 0, 0,
	        REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{0, 0, 0, 0, 0, 0}
};

static acmd_export_t acmds[] = {

	{"sip_capture", (acmd_function)async_sip_capture, 0, 0},
	{0, 0, 0, 0}
};

static proc_export_t procs[] = {
        {"RAW receiver",  0,  0, raw_socket_process, 1, 0},
        {0,0,0,0,0,0}
};


/*! \brief
 * Exported parameters
 */
static param_export_t params[] = {
	{"db_url",			STR_PARAM, &db_url.s            },
	{"table_name",       		STR_PARAM, &table_name.s	},
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
        {"raw_sock_children",  		INT_PARAM, &raw_sock_children   },
        {"hep_capture_on",  		INT_PARAM, &hep_capture_on   },
    {"max_async_queries",  		INT_PARAM, &max_async_queries   },
	{"raw_socket_listen",     	STR_PARAM, &raw_socket_listen.s   },
        {"raw_ipip_capture_on",  	INT_PARAM, &ipip_capture_on  },
        {"raw_moni_capture_on",  	INT_PARAM, &moni_capture_on  },
	{"raw_interface",     		STR_PARAM, &raw_interface.s   },
        {"promiscious_on",  		INT_PARAM, &promisc_on   },
        {"raw_moni_bpf_on",  		INT_PARAM, &bpf_on   },
	{"hep_store_no_script",		INT_PARAM, &hep_store_no_script},
	{0, 0, 0}
};

/*! \brief
 * MI commands
 */
static mi_export_t mi_cmds[] = {
	{ "sip_capture", 0, sip_capture_mi,   0,  0,  0 },
	{ 0, 0, 0, 0, 0, 0}
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

/*! \brief module exports */
struct module_exports exports = {
	"sipcapture",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /*!< dlopen flags */
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
	0,          /*!< exported pseudo-variables */
	procs,          /*!< extra processes */
	mod_init,   /*!< module initialization function */
	0,          /*!< response function */
	destroy,    /*!< destroy function */
	child_init  /*!< child initialization function */
};


/*! \brief Initialize sipcapture module */
static int mod_init(void) {

	int i;
	struct ip_addr *ip = NULL;

	init_db_url(db_url, 0);

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
	db_keys[36] = &msg_column;


#ifdef STATISTICS
	/* register statistics */
	if (register_module_stats(exports.name, sipcapture_stats)!=0)
	{
		LM_ERR("failed to register core statistics\n");
		return -1;
	}
#endif

	/* check if we need to start extra process */
	procs[0].no = (ipip_capture_on || moni_capture_on) ? raw_sock_children:0;

	db_url.len = strlen(db_url.s);
	table_name.len = strlen(table_name.s);
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

	if(raw_socket_listen.s)
		raw_socket_listen.len = strlen(raw_socket_listen.s);
	if(raw_interface.s)
		raw_interface.len = strlen(raw_interface.s);

	if (hep_capture_on) {
		load_hep = (load_hep_f)find_export("load_hep", 1, 0);
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
	}


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
		async_query = shm_malloc(sizeof(struct _async_query));
		if (async_query == NULL) {
			LM_ERR("no more shm");
			return -1;
		}
		lock_init(&query_lock);

		/* build first part of the async query; no overflow risk */
		query_len = snprintf(query_buf, MAX_QUERY, "INSERT INTO %s(",
															table_name.s);
		for (i = 0; i < NR_KEYS-1; i++)
			query_len += snprintf(query_buf+query_len, MAX_QUERY-query_len,
									"%s,",db_keys[i]->s);
		query_len += snprintf(query_buf+query_len, MAX_QUERY-query_len,
									"%s) VALUES", db_keys[NR_KEYS-1]->s);
		base_query_len = query_len;
	}



	/*Check the table name*/
	if(!table_name.len) {
		LM_ERR("table_name is not defined or empty\n");
		return -1;
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

	if (rank==PROC_MAIN || rank==PROC_TCP_MAIN)
	            return 0; /* do nothing for the main process */

        if (db_url.s)
	          return sipcapture_db_init(&db_url);

        LM_ERR("db_url is empty\n");

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

        heptime = (struct hep_timehdr*)pkg_malloc(sizeof(struct hep_timehdr));
        if(heptime==NULL) {
                LM_ERR("no more pkg memory left\n");
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

        if(heptime) pkg_free(heptime);
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


static void destroy(void)
{
	str query_str;

	/* execute the uninserted queries */
	if (DB_CAPABILITY(db_funcs, DB_CAP_ASYNC_RAW_QUERY)) {
		if (curr_queries) {
			if (!db_con) {
				db_con = db_funcs.init(&db_url);
				if (!db_con) {
					LM_ERR("unable to connect database\n");
					goto destroy_continue;
				}

				if (db_funcs.use_table(db_con, &table_name) < 0) {
					LM_ERR("use_table failed\n");
					goto destroy_continue;
				}
			}

			query_str.s   = query_buf;
			query_str.len = query_len;

			if (db_funcs.raw_query(db_con, &query_str, NULL)) {
				LM_ERR("failed to insert remaining queries\n");
			}
			lock_destroy(&query_lock);
		}

		shm_free(async_query);
	}

	/* Destroy DB socket */
	sipcapture_db_close();

destroy_continue:

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
int hep_msg_received(struct hep_desc *h, struct receive_info *ri)
{

	char ip_family;
	unsigned char proto;
	unsigned short sport, dport;
	struct ip_addr dst_ip, src_ip;

	struct sip_msg msg;

	if(!hep_capture_on) {
		LM_ERR("HEP is not enabled\n");
		return 0;
	}

	switch (h->version) {
		case 1:
		case 2:
			ip_family = h->u.hepv12.hdr.hp_f;
			proto	  = h->u.hepv12.hdr.hp_p;
			dport	  = h->u.hepv12.hdr.hp_dport;
			sport	  = h->u.hepv12.hdr.hp_sport;

			switch (ip_family) {
				case AF_INET:
					dst_ip.af  = src_ip.af  = AF_INET;
					dst_ip.len = src_ip.len = 4;

					memcpy(&dst_ip.u.addr,
								&h->u.hepv12.addr.hep_ipheader.hp_dst, 4);
					memcpy(&src_ip.u.addr,
								&h->u.hepv12.addr.hep_ipheader.hp_src, 4);

					break;

				case AF_INET6:
					dst_ip.af  = src_ip.af  = AF_INET6;
					dst_ip.len = src_ip.len = 16;

					memcpy(&dst_ip.u.addr,
								&h->u.hepv12.addr.hep_ip6header.hp6_dst, 16);
					memcpy(&src_ip.u.addr,
								&h->u.hepv12.addr.hep_ip6header.hp6_src, 16);

					break;

				default:
					LM_ERR("unsupported family [%d]\n", ip_family);
					return -1;
			}

			/* timestamp and capture id */
			if (h->version == 2) {
				heptime->tv_sec  = h->u.hepv12.hep_time.tv_sec;
				heptime->tv_usec = h->u.hepv12.hep_time.tv_usec;
				heptime->captid  = h->u.hepv12.hep_time.captid;
			}

			break;

		case 3:
			ip_family = h->u.hepv3.hg.ip_family.data;
			proto	  = h->u.hepv3.hg.ip_proto.data;
			dport	  = h->u.hepv3.hg.dst_port.data;
			sport     = h->u.hepv3.hg.src_port.data;

			switch (ip_family) {
				case AF_INET:
					dst_ip.af  = src_ip.af  = AF_INET;
					dst_ip.len = src_ip.len = 4;

					memcpy(&dst_ip.u.addr,
								&h->u.hepv3.addr.ip4_addr.dst_ip4.data, 4);
					memcpy(&src_ip.u.addr,
								&h->u.hepv3.addr.ip4_addr.src_ip4.data, 4);

					break;

				case AF_INET6:
					dst_ip.af  = src_ip.af  = AF_INET6;
					dst_ip.len = src_ip.len = 16;

					memcpy(&dst_ip.u.addr,
								&h->u.hepv3.addr.ip6_addr.dst_ip6.data, 16);
					memcpy(&src_ip.u.addr,
								&h->u.hepv3.addr.ip6_addr.src_ip6.data, 16);

					break;

				default:
					LM_ERR("unsupported family [%d]\n", ip_family);
					return -1;
			}

			/* timestamp and capture id */
			heptime->tv_sec  = h->u.hepv3.hg.time_sec.data;
			heptime->tv_usec = h->u.hepv3.hg.time_usec.data;
			heptime->captid  = h->u.hepv3.hg.capt_id.data;

			break;

		default:
			LM_ERR("unknown hep proto [%d]\n", h->version);
			return -1;
	}

	/* PROTO */
	if(proto == IPPROTO_UDP) ri->proto=PROTO_UDP;
	else if(proto == IPPROTO_TCP) ri->proto=PROTO_TCP;
	else if(proto == IPPROTO_IDP) ri->proto=PROTO_TLS;
											/* fake protocol */
	else if(proto == IPPROTO_SCTP) ri->proto=PROTO_SCTP;
	else if(proto == IPPROTO_ESP) ri->proto=PROTO_WS;
                                            /* fake protocol */
	else {
		LM_ERR("unknown protocol [%d]\n",proto);
		ri->proto = PROTO_NONE;
	}

	ri->src_ip = src_ip;
	ri->src_port = ntohs(sport);

	ri->dst_ip = dst_ip;
	ri->dst_port = ntohs(dport);

	if (hep_store_no_script) {
		memset(&msg, 0, sizeof(struct sip_msg));

		switch (h->version) {
		case 1:
		case 2:
			msg.buf = h->u.hepv12.payload;
			msg.len = strlen(msg.buf);
			break;
		case 3:
			msg.buf = h->u.hepv3.payload_chunk.data;
			msg.len = h->u.hepv3.payload_chunk.chunk.length - sizeof(struct hep_chunk);
			break;
		default:
			LM_ERR("unknown hep proto [%d]\n", h->version);
			return -1;
		}

		msg.rcv = *ri;

		if (parse_msg(msg.buf,msg.len,&msg)!=0) {
			LM_ERR("Unable to parse message in hep payload!"
					"Hep version %d!\n", h->version);
			return -1;
		}

		/* if message not parsed ok this helps with debugging */
		LM_DBG("********************************* SIP MESSAGE ******************\n"
				"%.*s\n"
				"***************************************************************\n",
				(int)msg.len, msg.buf);

		/* we basically move the sip_capture() call from the scripts here */
		if (w_sip_capture(&msg, NULL, NULL) < 0) {
			LM_ERR("failed to store the message!\n");
			return -1;
		}

		/* return a special code which will tell hep not to run the script */
		return HEP_SCRIPT_SKIP;
	}

	return 0;
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
							async_resume_module **resume_f, void **resume_param)
{
	db_val_t db_vals[NR_KEYS];
        int i = 0, ret;

	if(sco==NULL)
	{
		LM_DBG("invalid parameter\n");
		return -1;
	}

    db_vals[0].type = DB_INT;
    db_vals[0].val.int_val = 0;

	db_vals[1].type = DB_DATETIME;
	db_vals[1].val.time_val = time(NULL);

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

	db_vals[34].type = DB_INT;
	db_vals[34].val.int_val = sco->type;

	db_vals[35].type = DB_STR;
	db_vals[35].val.str_val = sco->node;

	db_vals[36].type = DB_BLOB;
	db_vals[36].val.blob_val = sco->msg;

	/* no field can be null */
	for (i=0;i<NR_KEYS;i++)
	         db_vals[i].nul = 0;

	ret=1;
	if (!resume_f && db_sync_store(db_vals) != 1) {
		LM_ERR("failed to insert into database\n");
		return -1;
	} else if (resume_f) {
		ret = db_async_store(db_vals, resume_f, resume_param);
	}

	#ifdef STATISTICS
		update_stat(sco->stat, 1);
	#endif

	return ret;
}


static int db_sync_store(db_val_t* db_vals)
{
	LM_DBG("storing info...\n");

	if (con_set_inslist(&db_funcs,db_con,&ins_list,db_keys,NR_KEYS) < 0 )
	               CON_RESET_INSLIST(db_con);
        CON_PS_REFERENCE(db_con) = &sipcapture_ps;

	if (db_funcs.insert(db_con, db_keys, db_vals, NR_KEYS) < 0) {
		LM_ERR("failed to insert into database\n");
                goto error;
	}

	return 1;
error:
	return -1;
}

static int db_async_store(db_val_t* db_vals,
							async_resume_module **resume_f, void **resume_param)
{
	int ret;
	int read_fd;
	str query_str;

	sc_async_param_t as_param;

	if (!DB_CAPABILITY(db_funcs, DB_CAP_ASYNC_RAW_QUERY)) {
		LM_WARN("This database module does not have async queries!"
				"Using sync insert!\n");
		*resume_f     = NULL;
		*resume_param = NULL;
		async_status  = ASYNC_NO_IO;
		return db_sync_store(db_vals);
	}

	lock_get(&query_lock);

	if (curr_queries == 0) {
		query_len = base_query_len;
	} else {
		/* VALUES delimiter*/
		query_buf[query_len++]=',';
	}

	ret = snprintf(query_buf+query_len, MAX_QUERY-query_len, VALUES_STR,
			VAL_INT(db_vals+0), VAL_TIME(db_vals+1), VAL_BIGINT(db_vals+2),
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
			VAL_INT(db_vals+30), VAL_INT(db_vals+31), VAL_INT(db_vals+30),
			VAL_STR(db_vals+33).len, VAL_STR(db_vals+33).s,
			VAL_INT(db_vals+34),
			VAL_STR(db_vals+35).len, VAL_STR(db_vals+35).s,
			VAL_BLOB(db_vals+36).len, VAL_BLOB(db_vals+36).s
				);

	if (ret < 0)
		goto no_buffer;

	query_len += ret;


	if ((++curr_queries) == max_async_queries) {
		curr_queries = 0;

		query_str.s   = query_buf;
		query_str.len = query_len;
		read_fd = db_funcs.async_raw_query(db_con, &query_str, &as_param);

		lock_release(&query_lock);

		if (read_fd < 0) {
			*resume_param = NULL;
			*resume_f     = NULL;
			return -1;
		}


		*resume_param = as_param;
		*resume_f = resume_async_dbquery;
		async_status = read_fd;

		return 1;
	}

	lock_release(&query_lock);

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

	rc = db_funcs.async_raw_resume(db_con, fd, NULL, (sc_async_param_t)_param);
	if (async_status == ASYNC_CONTINUE || async_status == ASYNC_CHANGE_FD)
		return rc;

	if (rc != 0) {
		LM_ERR("async query returned error!\n");
		return -1;
	}

	LM_DBG("Async query executed with success!\n");
	async_status = ASYNC_DONE;

	return 1;
}

static int sip_capture(struct sip_msg *msg, char* s1, char* s2)
{
	return w_sip_capture(msg, NULL, NULL);
}

static int async_sip_capture(struct sip_msg* msg, async_resume_module **resume_f,
		void **resume_param, str* s1, str* s2)
{
	return w_sip_capture(msg, resume_f, resume_param);
}


static int w_sip_capture(struct sip_msg *msg,
				async_resume_module **resume_f, void **resume_param)
{
	struct _sipcapture_object sco;
	struct sip_uri from, to, pai, contact;
	struct hdr_field *hook1 = NULL;
	struct hdr_field *tmphdr[4];
	contact_body_t*  cb=0;
	char buf_ip[IP_ADDR_MAX_STR_SIZE+12];
	char *port_str = NULL, *tmp = NULL;
	struct timeval tvb;
	struct timezone tz;
	char tmp_node[100];

	gettimeofday( &tvb, &tz );

	if(msg==NULL) {
		LM_DBG("nothing to capture\n");
		return -1;
	}
	memset(&sco, 0, sizeof(struct _sipcapture_object));


	if(capture_on_flag==NULL || *capture_on_flag==0) {
		LM_DBG("capture off...\n");
		return -1;
	}

	if(sip_capture_prepare(msg)<0) return -1;

        if(heptime && heptime->tv_sec != 0) {
               sco.tmstamp = (unsigned long long)heptime->tv_sec*1000000+heptime->tv_usec; /* micro ts */
               snprintf(tmp_node, 100, "%.*s:%i", capture_node.len, capture_node.s, heptime->captid);
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


	/* PROTO TYPE */
	sco.proto = msg->rcv.proto;

	/* FAMILY TYPE */
	sco.family = msg->rcv.src_ip.af;

	/* MESSAGE TYPE */
	sco.type = msg->first_line.type;

	/* MSG */
	sco.msg.s = msg->buf;
	sco.msg.len = msg->len;
	//EMPTY_STR(sco.msg);

	/* IP source and destination */

	strcpy(buf_ip, ip_addr2a(&msg->rcv.src_ip));
	sco.source_ip.s = buf_ip;
	sco.source_ip.len = strlen(buf_ip);
        sco.source_port = msg->rcv.src_port;

        /*source ip*/
	sco.destination_ip.s = ip_addr2a(&msg->rcv.dst_ip);
	sco.destination_ip.len = strlen(sco.destination_ip.s);
	sco.destination_port = msg->rcv.dst_port;

        LM_DBG("src_ip: [%.*s]\n", sco.source_ip.len, sco.source_ip.s);
        LM_DBG("dst_ip: [%.*s]\n", sco.destination_ip.len, sco.destination_ip.s);

        LM_DBG("dst_port: [%d]\n", sco.destination_port);
        LM_DBG("src_port: [%d]\n", sco.source_port);

#ifdef STATISTICS
	if(msg->first_line.type==SIP_REPLY) {
		sco.stat = sipcapture_rpl;
	} else {
		sco.stat = sipcapture_req;
	}
#endif
	LM_DBG("DONE\n");
	return sip_capture_store(&sco, resume_f, resume_param);
}

#define capture_is_off(_msg) \
	(capture_on_flag==NULL || *capture_on_flag==0)


/*! \brief
 * MI Sip_capture command
 *
 * MI command format:
 * name: sip_capture
 * attribute: name=none, value=[on|off]
 */
static struct mi_root* sip_capture_mi(struct mi_root* cmd_tree, void* param )
{
	struct mi_node* node;

	struct mi_node *rpl;
	struct mi_root *rpl_tree ;

	node = cmd_tree->node.kids;
	if(node == NULL) {
		rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
		if (rpl_tree == 0)
			return 0;
		rpl = &rpl_tree->node;

		if (*capture_on_flag == 0 ) {
			node = add_mi_node_child(rpl,0,0,0,MI_SSTR("off"));
		} else if (*capture_on_flag == 1) {
			node = add_mi_node_child(rpl,0,0,0,MI_SSTR("on"));
		}
		return rpl_tree ;
	}
	if(capture_on_flag==NULL)
		return init_mi_tree( 500, MI_SSTR(MI_INTERNAL_ERR));

	if ( node->value.len==2 && (node->value.s[0]=='o'
				|| node->value.s[0]=='O') &&
			(node->value.s[1]=='n'|| node->value.s[1]=='N')) {
		*capture_on_flag = 1;
		return init_mi_tree( 200, MI_SSTR(MI_OK));
	} else if ( node->value.len==3 && (node->value.s[0]=='o'
				|| node->value.s[0]=='O')
			&& (node->value.s[1]=='f'|| node->value.s[1]=='F')
			&& (node->value.s[2]=='f'|| node->value.s[2]=='F')) {
		*capture_on_flag = 0;
		return init_mi_tree( 200, MI_SSTR(MI_OK));
	} else {
		return init_mi_tree( 400, MI_SSTR(MI_BAD_PARM));
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

/* Local raw receive loop */
int raw_capture_rcv_loop(int rsock, int port1, int port2, int ipip) {


	static char buf [BUF_SIZE+1];
	union sockaddr_union from;
	union sockaddr_union to;
        struct receive_info ri;
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

		udp_len=ntohs(udph->uh_ulen);
	        if ((udph_start+udp_len)!=end){
        	        if ((udph_start+udp_len)>end){
				continue;
        	        }else{
                	        LM_DBG("udp length too small: %d/%d\n", (int)udp_len, (int)(end-udph_start));
	                        continue;
        	        }
	        }

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

		ri.src_su=from;
                su2ip_addr(&ri.src_ip, &from);
                ri.src_port=src_port;
                su2ip_addr(&ri.dst_ip, &to);
                ri.dst_port=dst_port;
                ri.proto=PROTO_UDP;

		/* cut off the offset */
	        len -= offset;

		if (len<MIN_UDP_PACKET){
                        LM_DBG("probing packet received from\n");
                        continue;
                }

                LM_DBG("PORT: [%d] and [%d]\n", port1, port2);

		if((!port1 && !port2)
		        || (src_port >= port1 && src_port <= port2) || (dst_port >= port1 && dst_port <= port2)
		        || (!port2 && (src_port == port1 || dst_port == port1)))
		                          receive_msg(buf+offset, len, &ri);
	}

	return 0;

error:
	return -1;

}

#undef query_buf
#undef query_len
#undef query_lock
#undef curr_queries
