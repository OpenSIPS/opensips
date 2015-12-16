/*
 * siptrace module - helper module to trace sip messages
 *
 * Copyright (C) 2006-2009 Voice Sistem S.R.L.
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../ip_addr.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"
#include "../../db/db.h"
#include "../../db/db_insertq.h"
#include "../../parser/parse_content.h"
#include "../../parser/parse_from.h"
#include "../../pvar.h"
#include "../tm/tm_load.h"
#include "../dialog/dlg_load.h"
#include "../sl/sl_cb.h"
#include "../../str.h"
#include "../../script_cb.h"
#include "../proto_hep/hep.h"
#include "../proto_hep/hep_cb.h"

#define NR_KEYS 14
#define SIPTRACE_TABLE_VERSION 4

/* trace is completly disabled */
#define trace_is_off() \
	(trace_on_flag==NULL || *trace_on_flag==0)

/* flag-based tracing ise set */
#define flag_trace_is_set(_msg) \
	(((_msg)->flags&trace_flag)!=0)


/* DB structures used for all queries */
db_key_t db_keys[NR_KEYS];
db_val_t db_vals[NR_KEYS];

static db_ps_t siptrace_ps = NULL;
static query_list_t *ins_list = NULL;

struct tm_binds tmb;
struct dlg_binds dlgb;

proto_hep_api_t hep_api;
load_hep_f load_hep;

/* module function prototypes */
static int mod_init(void);
static int child_init(int rank);
static void destroy(void);

static int fixup_trace_dialog(void** param, int param_no);

static int sip_trace(struct sip_msg*);
static int sip_trace_w(struct sip_msg*);
static int trace_dialog(struct sip_msg*);

static int trace_send_duplicate(char *buf, int len);

static void trace_onreq_in(struct cell* t, int type, struct tmcb_params *ps);
static void trace_onreq_out(struct cell* t, int type, struct tmcb_params *ps);
static void trace_onreply_in(struct cell* t, int type, struct tmcb_params *ps);
static void trace_onreply_out(struct cell* t, int type, struct tmcb_params *ps);
static void trace_sl_onreply_out(unsigned int types, struct sip_msg* req,
			struct sl_cb_param *sl_param);
static void trace_sl_ack_in(unsigned int types, struct sip_msg* req,
			struct sl_cb_param *sl_param);
static void trace_msg_out(struct sip_msg* req, str  *buffer,
			struct socket_info* send_sock, int proto, union sockaddr_union *to);
static void trace_msg_out_w(struct sip_msg* req, str  *buffer,
			struct socket_info* send_sock, int proto, union sockaddr_union *to);

static struct mi_root* sip_trace_mi(struct mi_root* cmd, void* param );
static struct mi_root* trace_to_database_mi(struct mi_root* cmd, void* param );

static int trace_send_hep_duplicate(str *body, str *fromproto, str *fromip,
		unsigned short fromport, str *toproto, str *toip, unsigned short toport);
static int pipport2su (str *sproto, str *ip, unsigned short port,
			union sockaddr_union *tmp_su, unsigned int *proto);

static void siptrace_dlg_cancel(struct cell* t, int type, struct tmcb_params *param);

static str db_url             = {NULL, 0};
static str siptrace_table     = str_init("sip_trace");
static str date_column        = str_init("time_stamp");  /* 00 */
static str callid_column      = str_init("callid");      /* 01 */
static str traced_user_column = str_init("traced_user"); /* 02 */
static str msg_column         = str_init("msg");         /* 03 */
static str method_column      = str_init("method");      /* 04 */
static str status_column      = str_init("status");      /* 05 */
static str fromproto_column   = str_init("from_proto");  /* 06 */
static str fromip_column      = str_init("from_ip");     /* 07 */
static str fromport_column    = str_init("from_port");   /* 08 */
static str toproto_column     = str_init("to_proto");    /* 09 */
static str toip_column        = str_init("to_ip");       /* 10 */
static str toport_column      = str_init("to_port");     /* 11 */
static str fromtag_column     = str_init("fromtag");     /* 12 */
static str direction_column   = str_init("direction");   /* 13 */

static str st_flag_val = str_init("_st_XX_flag_43");

static char *trace_flag_str = 0;
int trace_flag = -1;
int trace_on   = 0;
int trace_to_database = 1;
int duplicate_with_hep = 0;

str    dup_uri_str      = {0, 0};
struct sip_uri *dup_uri = 0;

int *trace_on_flag = NULL;
int *trace_to_database_flag = NULL;

static unsigned short traced_user_avp_type = 0;
static int traced_user_avp;
static str traced_user_avp_str = {NULL, 0};

static unsigned short trace_table_avp_type = 0;
static int trace_table_avp;
static str trace_table_avp_str = {NULL, 0};

static str trace_local_proto = {NULL, 0};
static str trace_local_ip = {NULL, 0};
static unsigned short trace_local_port = 0;

static unsigned int enable_ack_trace = 0;

/** database connection */
db_con_t *db_con = NULL;
db_func_t db_funcs;      /* Database functions */


/* sl callback registration */
register_slcb_t register_slcb_f=NULL;

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"sip_trace", (cmd_function)sip_trace_w, 0, 0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"trace_dialog", (cmd_function)trace_dialog, 0, fixup_trace_dialog, 0,
		REQUEST_ROUTE},
	{0, 0, 0, 0, 0, 0}
};


/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"db_url",             STR_PARAM, &db_url.s             },
	{"table",              STR_PARAM, &siptrace_table.s     },
	{"date_column",        STR_PARAM, &date_column.s        },
	{"callid_column",      STR_PARAM, &callid_column.s      },
	{"traced_user_column", STR_PARAM, &traced_user_column.s },
	{"msg_column",         STR_PARAM, &msg_column.s         },
	{"method_column",      STR_PARAM, &method_column.s      },
	{"status_column",      STR_PARAM, &status_column.s      },
	{"fromproto_column",   STR_PARAM, &fromproto_column.s   },
	{"fromip_column",      STR_PARAM, &fromip_column.s      },
	{"fromport_column",    STR_PARAM, &fromport_column.s    },
	{"toproto_column",     STR_PARAM, &toproto_column.s     },
	{"toip_column",        STR_PARAM, &toip_column.s        },
	{"toport_column",      STR_PARAM, &toport_column.s      },
	{"fromtag_column",     STR_PARAM, &fromtag_column.s     },
	{"direction_column",   STR_PARAM, &direction_column.s   },
	{"trace_flag",         STR_PARAM, &trace_flag_str       },
	{"trace_flag",         INT_PARAM, &trace_flag           },
	{"trace_on",           INT_PARAM, &trace_on             },
	{"traced_user_avp",    STR_PARAM, &traced_user_avp_str.s},
	{"trace_table_avp",    STR_PARAM, &trace_table_avp_str.s},
	{"duplicate_uri",      STR_PARAM, &dup_uri_str.s        },
	{"trace_local_ip",     STR_PARAM, &trace_local_ip.s     },
	{"enable_ack_trace",   INT_PARAM, &enable_ack_trace     },
	{"trace_to_database",  INT_PARAM, &trace_to_database 	},
	{"duplicate_with_hep", INT_PARAM, &duplicate_with_hep   },
	{0, 0, 0}
};

static mi_export_t mi_cmds[] = {
	{ "sip_trace", 0, sip_trace_mi,   0,  0,  0 },
	{ "trace_to_database", 0, trace_to_database_mi,   0,  0,  0 },
	{ 0, 0, 0, 0, 0, 0}
};


#ifdef STATISTICS
#include "../../statistics.h"

stat_var* siptrace_req;
stat_var* siptrace_rpl;

static stat_export_t siptrace_stats[] = {
	{"traced_requests" ,  0,  &siptrace_req  },
	{"traced_replies"  ,  0,  &siptrace_rpl  },
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
		{ MOD_TYPE_DEFAULT, "tm", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "sl", DEP_ABORT },
		{ MOD_TYPE_SQLDB, NULL,   DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{"duplicate_with_hep", get_deps_hep},
		{ NULL, NULL },
	},
};

/* module exports */
struct module_exports exports = {
	"siptrace",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /* Exported functions */
	0,          /* Exported async functions */
	params,     /* Exported parameters */
#ifdef STATISTICS
	siptrace_stats,
#else
	0,          /* exported statistics */
#endif
	mi_cmds,    /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* extra processes */
	mod_init,   /* module initialization function */
	0,          /* response function */
	destroy,    /* destroy function */
	child_init  /* child initialization function */
};


static int fixup_trace_dialog(void** param, int param_no)
{
	/* register callback to dialog */
	if (load_dlg_api(&dlgb)!=0) {
		LM_ERR("can't load dialog api\n");
		return -1;
	}

	return 0;
}


static int parse_trace_local_ip(void){
	/* We tokenize the trace_local_ip from proto:ip:port to three fields */

	trace_local_ip.len = strlen(trace_local_ip.s);
	unsigned int port_no;
	char *c = strchr(trace_local_ip.s, ':');
	if (c == NULL) {
		/* Only ip is specified */
		trace_local_port = SIP_PORT;
		trace_local_proto.s = "udp";
		trace_local_proto.len = sizeof("udp") -1;
	}
	else {
		str first_token = {c + 1,
						trace_local_ip.len - (c - trace_local_ip.s) - 1};

		if (str2int(&first_token, &port_no) == 0){

			/* The first token is the port, so no proto */
			if (port_no > 65535 || port_no == 0){
				LM_WARN("trace local_ip: port is out of range (%d). "
						"Will consider it to be %d\n", port_no, SIP_PORT);
				trace_local_port = SIP_PORT;
			}
			else
				trace_local_port = (unsigned short) port_no;

			trace_local_proto.s = "udp";
			trace_local_proto.len = sizeof("udp") - 1;
			trace_local_ip.len = c - trace_local_ip.s;
		}
		else {

			/* The first token is the protocol */
			trace_local_proto.s = trace_local_ip.s;
			trace_local_proto.len = c - trace_local_ip.s;

			if (trace_local_proto.len > 4){
				/* Too many letters for the protocol. Avoiding overflow */
				LM_ERR("trace_local_ip : wrong protocol\n");
				return -1;
			} else if (trace_local_proto.len == 0){
				trace_local_proto.s = "udp";
				trace_local_proto.len = sizeof("udp") - 1;
			}

			char *c2 = strchr(c + 1, ':');

			if (c2 != NULL){

				/* We have a second token */
				str second_token;
				second_token.s = c2 + 1;
				second_token.len = trace_local_ip.len -
									(c2 - trace_local_ip.s) - 1;

				if (str2int(&second_token, &port_no) != 0) {
					trace_local_port = SIP_PORT;
					LM_WARN("trace_local_ip: port is wrongly defined. "
							"Will consider it as %hd\n", trace_local_port);
				}
				else if (port_no > 65535 || port_no == 0){
					LM_WARN("trace local_ip: port is out of range (%d). "
							"Will consider it to be %d\n",
							port_no, SIP_PORT);
					trace_local_port = SIP_PORT;
				}
				else
					trace_local_port = (unsigned short) port_no;
				trace_local_ip.s = c + 1;
				trace_local_ip.len = c2 - c - 1;
			}
			else {
				trace_local_port = SIP_PORT;
				trace_local_ip.len -= c - trace_local_ip.s + 1;
				trace_local_ip.s = c + 1;
			}
		}
	}

	return 0;
}

static int mod_init(void)
{
	pv_spec_t avp_spec;
	int i;

	init_db_url( db_url , 0 /*cannot be null*/);
	siptrace_table.len = strlen(siptrace_table.s);
	date_column.len = strlen(date_column.s);
	callid_column.len = strlen(callid_column.s);
	traced_user_column.len = strlen(traced_user_column.s);
	msg_column.len = strlen(msg_column.s);
	method_column.len = strlen(method_column.s);
	status_column.len = strlen(status_column.s);
	fromproto_column.len = strlen(fromproto_column.s);
	fromip_column.len = strlen(fromip_column.s);
	fromport_column.len = strlen(fromport_column.s);
	toproto_column.len = strlen(toproto_column.s);
	toip_column.len = strlen(toip_column.s);
	toport_column.len = strlen(toport_column.s);
	fromtag_column.len = strlen(fromtag_column.s);
	direction_column.len = strlen(direction_column.s);
	if (traced_user_avp_str.s)
		traced_user_avp_str.len = strlen(traced_user_avp_str.s);
	if (trace_table_avp_str.s)
		trace_table_avp_str.len = strlen(trace_table_avp_str.s);
	if (dup_uri_str.s)
		dup_uri_str.len = strlen(dup_uri_str.s);

	if (trace_local_ip.s)
		parse_trace_local_ip();

	LM_INFO("initializing...\n");

	fix_flag_name(trace_flag_str, trace_flag);

	trace_flag = get_flag_id_by_name(FLAG_TYPE_MSG, trace_flag_str);

	if (flag_idx2mask(&trace_flag)<0)
		return -1;

	trace_to_database_flag = (int*)shm_malloc(sizeof(int));
        if(trace_to_database_flag==NULL) {
                LM_ERR("no more shm memory left\n");
                return -1;
        }

	*trace_to_database_flag = trace_to_database;

	if(trace_to_database_flag!=NULL && *trace_to_database_flag!=0) {
		/* Find a database module */
		if (db_bind_mod(&db_url, &db_funcs))
		{
			LM_ERR("unable to bind database module\n");
			return -1;
		}
		if (trace_to_database_flag && !DB_CAPABILITY(db_funcs, DB_CAP_INSERT))
		{
			LM_ERR("database modules does not provide all functions needed by module\n");
			return -1;
		}

		if ((db_con = db_funcs.init(&db_url)) == 0) {
			LM_CRIT("Cannot connect to DB\n");
			return -1;
		}

		if(db_check_table_version(&db_funcs, db_con,
				&siptrace_table, SIPTRACE_TABLE_VERSION) < 0) {
			LM_ERR("error during table version check.\n");
			return -1;
		}

		db_funcs.close(db_con);
		db_con = 0;
	}

	trace_on_flag = (int*)shm_malloc(sizeof(int));
	if(trace_on_flag==NULL)
	{
		LM_ERR("no more shm memory left\n");
		return -1;
	}

	*trace_on_flag = trace_on;



	/* register callbacks to TM */
	if (load_tm_api(&tmb)!=0)
	{
		LM_ERR("can't load tm api\n");
		return -1;
	}

	if(tmb.register_tmcb( 0, 0, TMCB_REQUEST_IN, trace_onreq_in, 0, 0) <=0)
	{
		LM_ERR("can't register trace_onreq_in\n");
		return -1;
	}

	/* register sl callback */
	register_slcb_f = (register_slcb_t)find_export("register_slcb", 0, 0);
	if(register_slcb_f==NULL)
	{
		LM_ERR("can't load sl api\n");
		return -1;
	}
	if(register_slcb_f(SLCB_REPLY_OUT,trace_sl_onreply_out, NULL)!=0)
	{
		LM_ERR("can't register trace_sl_onreply_out\n");
		return -1;
	}
	if(register_fwdcb(trace_msg_out_w)!=0)
	{
		LM_ERR("can't register trace_sl_ack_out\n");
		return -1;
	}
	if(enable_ack_trace&&register_slcb_f(SLCB_ACK_IN,trace_sl_ack_in,NULL)!=0)
	{
		LM_ERR("can't register trace_sl_ack_in\n");
		return -1;
	}

	if(dup_uri_str.s!=0) {
		dup_uri_str.len = strlen(dup_uri_str.s);
		dup_uri = (struct sip_uri *)pkg_malloc(sizeof(struct sip_uri));
		if(dup_uri==0) {
			LM_ERR("no more pkg memory left\n");
			return -1;
		}
		memset(dup_uri, 0, sizeof(struct sip_uri));
		if(parse_uri(dup_uri_str.s, dup_uri_str.len, dup_uri)<0) {
			LM_ERR("bad dup uri\n");
			return -1;
		}
	}

	if(traced_user_avp_str.s && traced_user_avp_str.len > 0)
	{
		if (pv_parse_spec(&traced_user_avp_str, &avp_spec)==0
				|| avp_spec.type!=PVT_AVP) {
			LM_ERR("malformed or non AVP %.*s AVP definition\n",
				traced_user_avp_str.len, traced_user_avp_str.s);
			return -1;
		}

		if(pv_get_avp_name(0, &avp_spec.pvp, &traced_user_avp,
					&traced_user_avp_type)!=0)
		{
			LM_ERR("[%.*s] - invalid AVP definition\n",
				traced_user_avp_str.len, traced_user_avp_str.s);
			return -1;
		}
	} else {
		traced_user_avp = -1;
		traced_user_avp_type = 0;
	}
	if(trace_table_avp_str.s && trace_table_avp_str.len > 0)
	{
		if (pv_parse_spec(&trace_table_avp_str, &avp_spec)==0
				|| avp_spec.type!=PVT_AVP) {
			LM_ERR("malformed or non AVP %.*s AVP definition\n",
				trace_table_avp_str.len, trace_table_avp_str.s);
			return -1;
		}

		if(pv_get_avp_name(0, &avp_spec.pvp, &trace_table_avp,
					&trace_table_avp_type)!=0)
		{
			LM_ERR("[%.*s] - invalid AVP definition\n"
				, trace_table_avp_str.len, trace_table_avp_str.s);
			return -1;
		}
	} else {
		trace_table_avp = -1;
		trace_table_avp_type = 0;
	}

	if (duplicate_with_hep) {
		load_hep = (load_hep_f)find_export("load_hep", 1, 0);
		if (!load_hep) {
			LM_ERR("Can't bind proto hep!\n");
			return -1;
		}

		if (load_hep(&hep_api)) {
			LM_ERR("can't bind proto hep\n");
			return -1;
		}
	}



	/* init the DB keys for future queries */
	db_keys[0] = &msg_column;
	db_keys[1] = &callid_column;
	db_keys[2] = &method_column;
	db_keys[3] = &status_column;
	db_keys[4] = &fromproto_column;
	db_keys[5] = &fromip_column;
	db_keys[6] = &fromport_column;
	db_keys[7] = &toproto_column;
	db_keys[8] = &toip_column;
	db_keys[9] = &toport_column;
	db_keys[10] = &date_column;
	db_keys[11] = &direction_column;
	db_keys[12] = &fromtag_column;
	db_keys[13] = &traced_user_column;

	/* init DB values info which is constant ( type, null ) */
	db_vals[0].type = DB_BLOB;
	db_vals[1].type = DB_STR;
	db_vals[2].type = DB_STR;
	db_vals[3].type = DB_STR;
	db_vals[4].type = DB_STR;
	db_vals[5].type = DB_STR;
	db_vals[6].type = DB_INT;
	db_vals[7].type = DB_STR;
	db_vals[8].type = DB_STR;
	db_vals[9].type = DB_INT;
	db_vals[10].type = DB_DATETIME;
	db_vals[11].type = DB_STRING;
	db_vals[12].type = DB_STR;
	db_vals[13].type = DB_STR;
	/* no field can be null */
	for (i=0;i<NR_KEYS;i++)
		db_vals[i].nul = 0;

	return 0;
}

static inline int insert_siptrace_flag(struct sip_msg *msg,
		db_key_t *keys,db_val_t *vals)
{
	db_vals[13].val.str_val.s   = "";
	db_vals[13].val.str_val.len = 0;

	LM_DBG("storing info 1...\n");
	if (con_set_inslist(&db_funcs,db_con,&ins_list,keys,NR_KEYS) < 0 )
		CON_RESET_INSLIST(db_con);
	CON_PS_REFERENCE(db_con) = &siptrace_ps;
	if(db_funcs.insert(db_con, keys, vals, NR_KEYS) < 0)
	{
			LM_ERR("error storing trace\n");
		return -1;
	}

	return 0;
}

static inline int insert_siptrace_avp(struct usr_avp *avp,
		int_str *first_val,db_key_t *keys,db_val_t *vals)
{
	int_str        avp_value;

	if (avp == 0)
		return 0;

	if (!is_avp_str_val(avp)) {
		avp_value.s.s=int2str(first_val->n,&avp_value.s.len);
		LM_DBG("int val [%.*s]\n",avp_value.s.len,avp_value.s.s);
	} else {
		avp_value = *first_val;
		LM_DBG("str val [%.*s]\n",avp_value.s.len,avp_value.s.s);
	}
	db_vals[13].val.str_val.s = avp_value.s.s;
	db_vals[13].val.str_val.len = avp_value.s.len;

	LM_DBG("storing info 14...\n");
	CON_PS_REFERENCE(db_con) = &siptrace_ps;
	if (con_set_inslist(&db_funcs,db_con,&ins_list,keys,NR_KEYS) < 0 )
		CON_RESET_INSLIST(db_con);
	if(db_funcs.insert(db_con, keys, vals, NR_KEYS) < 0) {
		LM_ERR("error storing trace\n");
		return -1;
	}

	avp = search_next_avp( avp, &avp_value);
	while(avp!=NULL)
	{
		if (!is_avp_str_val(avp))
			avp_value.s.s=int2str(avp_value.n,&avp_value.s.len);
		db_vals[13].val.str_val.s = avp_value.s.s;
		db_vals[13].val.str_val.len = avp_value.s.len;

		LM_DBG("### - storing info 14 \n");
		CON_PS_REFERENCE(db_con) = &siptrace_ps;
		if (con_set_inslist(&db_funcs,db_con,&ins_list,keys,NR_KEYS) < 0 )
			CON_RESET_INSLIST(db_con);
		if(db_funcs.insert(db_con, keys, vals, NR_KEYS) < 0)
		{
			LM_ERR("error storing trace\n");
			return -1;
		}
		avp = search_next_avp( avp, &avp_value);
	}

	return 0;
}

static inline str* siptrace_get_table(void)
{
	static int_str         avp_value;
	struct usr_avp *avp;

	if(trace_table_avp < 0)
		return &siptrace_table;

	avp=search_first_avp(trace_table_avp_type, trace_table_avp,
			&avp_value, 0);

	if(avp==NULL || !is_avp_str_val(avp) || avp_value.s.len<=0)
		return &siptrace_table;

	return &avp_value.s;
}

static int save_siptrace(struct sip_msg *msg,struct usr_avp *avp,
		int_str *first_val,db_key_t *keys,db_val_t *vals)
{

	if (duplicate_with_hep)
		trace_send_hep_duplicate(&db_vals[0].val.blob_val, &db_vals[4].val.str_val,
				&db_vals[5].val.str_val, db_vals[6].val.int_val, &db_vals[7].val.str_val,
				&db_vals[8].val.str_val, db_vals[9].val.int_val);
	else
		trace_send_duplicate(db_vals[0].val.blob_val.s,
			db_vals[0].val.blob_val.len);


	if(trace_to_database_flag!=NULL && *trace_to_database_flag!=0) {
		LM_DBG("saving siptrace\n");
		db_funcs.use_table(db_con, siptrace_get_table());

		if (flag_trace_is_set(msg) && insert_siptrace_flag(msg,keys,vals) < 0)
			return -1;

		if (avp==NULL)
			return 0;

		if (insert_siptrace_avp(avp,first_val,keys,vals) < 0)
			return -1;
	}

	return 0;
}


static int child_init(int rank)
{

	if(trace_to_database_flag!=NULL && *trace_to_database_flag!=0) {
		db_con = db_funcs.init(&db_url);
		if (!db_con)
		{
			LM_ERR("unable to connect database\n");
			return -1;
		}
	}

	return 0;
}


static void destroy(void)
{
	if(trace_to_database_flag!=NULL && *trace_to_database_flag!=0) {
		if (db_con!=NULL)
			db_funcs.close(db_con);
		if (trace_on_flag)
			shm_free(trace_on_flag);
	}
}


static str* generate_val_name(unsigned char n)
{
	#define SIPTRACE_VAL_NAME "trace_xxx"
	static str v_name = {NULL,0};

	if (v_name.s==NULL) {
		v_name.len = sizeof(SIPTRACE_VAL_NAME)-1;
		v_name.s = pkg_malloc(v_name.len);
		if (v_name.s==NULL) {
			LM_ERR("failed to get pkg mem\n");
			return NULL;
		}
		memcpy(v_name.s, SIPTRACE_VAL_NAME, v_name.len);
	}
	v_name.s[v_name.len-2] = '0' + n/10;
	v_name.s[v_name.len-1] = '0' + n%10;

	return &v_name;
}


static void trace_transaction(struct dlg_cell* dlg, int type,
		struct dlg_cb_params * params)
{
	unsigned char n;
	static int_str avp_value;
	str *name;

	if (params->msg==NULL)
		return;

	/* restore the AVPs from the dialog values */
	n = 0;
	do {
		name = generate_val_name(n);
		if (dlgb.fetch_dlg_value( dlg, name, &avp_value.s, 0)!=0)
			break;
		add_avp( traced_user_avp_type|AVP_VAL_STR, traced_user_avp, avp_value);
		n++;
	}while(1);

	/* set the flag */
	if ( dlgb.fetch_dlg_value( dlg, &st_flag_val, &avp_value.s, 0)==0 )
		params->msg->flags |= trace_flag;
	params->msg->msg_flags |= FL_USE_SIPTRACE;
	/* trace current request */
	sip_trace(params->msg);

	if(tmb.register_tmcb( params->msg, 0, TMCB_REQUEST_BUILT, trace_onreq_out, 0, 0) <=0)
	{
		LM_ERR("can't register trace_onreq_out\n");
		return;
	}

	/* doesn't make sense to register the reply callbacks for ACK or PRACK */
	if (params->msg->REQ_METHOD & (METHOD_ACK | METHOD_PRACK))
		return;

	if(tmb.register_tmcb( params->msg, 0, TMCB_RESPONSE_IN, trace_onreply_in, 0, 0) <=0)
	{
		LM_ERR("can't register trace_onreply_in\n");
		return;
	}

	if(tmb.register_tmcb( params->msg, 0, TMCB_RESPONSE_OUT, trace_onreply_out, 0, 0) <=0)
	{
		LM_ERR("can't register trace_onreply_out\n");
		return;
	}

}


static int trace_dialog(struct sip_msg *msg)
{
	unsigned char n;
	struct dlg_cell* dlg;
	struct usr_avp *avp;
	static int_str avp_value;
	str *name;

	if (!msg) {
		LM_ERR("no msg specified\n");
		return -1;
	}

	if (trace_is_off()) {
		LM_DBG("Trace if off...\n");
		return -1;
	}

	/* any need to do tracing here ? check the triggers */
	avp = traced_user_avp<0 ? NULL : search_first_avp(traced_user_avp_type,
			traced_user_avp, &avp_value, 0);
	if (avp==NULL && (msg->flags&trace_flag)==0) {
		LM_DBG("Nothing to trace here\n");
		return -1;
	}

	if (dlgb.create_dlg(msg,0)<1) {
		LM_ERR("failed to create dialog\n");
		return -1;
	}

	dlg = dlgb.get_dlg();
	if (dlg==NULL) {
		LM_CRIT("BUG: no dialog found after create dialog\n");
		return -1;
	}

	if(dlgb.register_dlgcb(dlg, DLGCB_REQ_WITHIN|DLGCB_TERMINATED,
	trace_transaction,0,0)!=0) {
		LM_ERR("failed to register dialog callback\n");
		return -1;
	}

	/* store in dialog the user avps for tracing ; we will restore
	 them for each transactin from the dialog */
	if(traced_user_avp>=0) {
		n = 0;
		while(avp!=NULL) {
			/* generate a name */
			name = generate_val_name(n);
			if (!is_avp_str_val(avp))
				avp_value.s.s=int2str(avp_value.n,
						&avp_value.s.len);
			/* add the avp value as dialog var */
			dlgb.store_dlg_value( dlg, name, &avp_value.s);
			/* next avp */
			avp = search_next_avp( avp, &avp_value);
			n++;
		}
	}

	/* set the flag to trace the rest of the transaction */
	if (msg->flags&trace_flag) {
		avp_value.s.s = "1";
		avp_value.s.len = 1;
		dlgb.store_dlg_value( dlg, &st_flag_val, &avp_value.s);
	}

	/* trace current request */
	sip_trace(msg);

	/* we also want to catch the incoming cancel */
	if ( tmb.register_tmcb( msg, NULL,TMCB_TRANS_CANCELLED,
				siptrace_dlg_cancel, NULL, NULL)<0 ) {
		LM_ERR("failed to register trans cancelled TMCB\n");
	}

	return 1;
}


static void siptrace_dlg_cancel(struct cell* t, int type, struct tmcb_params *param)
{
	int_str avp_value;
	struct sip_msg *req;
	req = param->req;

	LM_DBG("Tracing incoming cancel due to trace_dialog() \n");

	/* set the flag */
	if ( dlgb.fetch_dlg_value( (struct dlg_cell*)t->dialog_ctx, &st_flag_val, &avp_value.s, 0)==0 )
		req->flags |= trace_flag;
	req->msg_flags |= FL_USE_SIPTRACE;
	/* trace current request */
	sip_trace(req);
}


static inline int siptrace_copy_proto(int proto, char *buf)
{
	if(buf==0)
		return -1;
	if(proto==PROTO_TCP) {
		strcpy(buf, "tcp:");
	} else if(proto==PROTO_TLS) {
		strcpy(buf, "tls:");
	} else if(proto==PROTO_SCTP) {
		strcpy(buf, "sctp:");
	} else {
		strcpy(buf, "udp:");
	}
	return 0;
}

/* siptrace wrapper that verifies if the trace is on */
static int sip_trace_w(struct sip_msg *msg)
{
	if( trace_is_off() ) {
		LM_DBG("trace off...\n");
		return -1;
	}
	return sip_trace(msg);
}

#define set_sock_columns( _col_proto, _col_ip, _col_port, _buff, _ip, _port, _proto) \
	do { \
		char *nbuff = proto2str( _proto, _buff); \
		_col_proto.val.str_val.s = _buff; \
		_col_proto.val.str_val.len = nbuff - _buff; \
		strcpy(nbuff, ip_addr2a(_ip)); \
		_col_ip.val.str_val.s = nbuff; \
		_col_ip.val.str_val.len = strlen(nbuff); \
		_col_port.val.int_val = _port; \
	} while (0)

#define set_columns_to_any( _col_proto, _col_ip, _col_port) \
	do { \
		_col_proto.val.str_val.s = "any"; \
		_col_proto.val.str_val.len = sizeof("any") - 1; \
		_col_ip.val.str_val.s = "255.255.255.255"; \
		_col_ip.val.str_val.len = sizeof("255.255.255.255") - 1; \
		_col_port.val.int_val = 9; \
	} while (0)

#define set_columns_to_trace_local_ip( _col_proto, _col_ip, _col_port) \
	do { \
		db_vals[4].val.str_val = trace_local_proto; \
		db_vals[5].val.str_val = trace_local_ip; \
		db_vals[6].val.int_val = trace_local_port; \
	} while (0)

static int sip_trace(struct sip_msg *msg)
{
	static char toip_buff[IP_ADDR_MAX_STR_SIZE+6];
	static char fromip_buff[IP_ADDR_MAX_STR_SIZE+6];
	int_str         avp_value;
	struct usr_avp *avp;

	if(msg==NULL)
	{
		LM_DBG("no uas request, local transaction\n");
		return -1;
	}

	avp = NULL;
	if(traced_user_avp>=0)
		avp=search_first_avp(traced_user_avp_type, traced_user_avp,
				&avp_value, 0);

	if ( (avp==NULL) && !flag_trace_is_set(msg) )
	{
		LM_DBG("nothing to trace...\n");
		return -1;
	}

	if(parse_from_header(msg)==-1 || msg->from==NULL || get_from(msg)==NULL)
	{
		LM_ERR("cannot parse FROM header\n");
		goto error;
	}

	if(parse_headers(msg, HDR_CALLID_F, 0)!=0 || msg->callid==NULL
			|| msg->callid->body.s==NULL)
	{
		LM_ERR("cannot parse call-id\n");
		goto error;
	}

	LM_DBG("sip_trace called \n");
	db_vals[0].val.blob_val.s = msg->buf;
	db_vals[0].val.blob_val.len = msg->len;

	db_vals[1].val.str_val.s = msg->callid->body.s;
	db_vals[1].val.str_val.len = msg->callid->body.len;

	if(msg->first_line.type==SIP_REQUEST)
	{
		db_vals[2].val.str_val.s = msg->first_line.u.request.method.s;
		db_vals[2].val.str_val.len = msg->first_line.u.request.method.len;
	} else {
		db_vals[2].val.str_val.s = "";
		db_vals[2].val.str_val.len = 0;
	}

	if(msg->first_line.type==SIP_REPLY)
	{
		db_vals[3].val.str_val.s = msg->first_line.u.reply.status.s;
		db_vals[3].val.str_val.len = msg->first_line.u.reply.status.len;
	} else {
		db_vals[3].val.str_val.s = "";
		db_vals[3].val.str_val.len = 0;
	}

	set_sock_columns( db_vals[4], db_vals[5], db_vals[6], fromip_buff,
		&msg->rcv.src_ip, msg->rcv.src_port, msg->rcv.proto);

	set_sock_columns( db_vals[7], db_vals[8], db_vals[9], toip_buff,
		&msg->rcv.dst_ip,  msg->rcv.dst_port, msg->rcv.proto);

	db_vals[10].val.time_val = time(NULL);

	db_vals[11].val.string_val = "in";

	db_vals[12].val.str_val.s = get_from(msg)->tag_value.s;
	db_vals[12].val.str_val.len = get_from(msg)->tag_value.len;

	if (save_siptrace(msg,avp,&avp_value,db_keys,db_vals) < 0) {
		LM_ERR("failed to save siptrace\n");
		goto error;
	}

#ifdef STATISTICS
	if(msg->first_line.type==SIP_REPLY) {
		update_stat(siptrace_rpl, 1);
	} else {
		update_stat(siptrace_req, 1);
	}
#endif
	return 1;
error:
	return -1;
}

static void trace_onreq_in(struct cell* t, int type, struct tmcb_params *ps)
{
	struct sip_msg* msg;
	int_str         avp_value;
	struct usr_avp* avp;

	if(t==NULL || ps==NULL)
	{
		LM_DBG("no uas request, local transaction\n");
		return;
	}

	msg = ps->req;
	if(msg==NULL)
	{
		LM_DBG("no uas request, local transaction\n");
		return;
	}

	if( trace_is_off() )
	{
		LM_DBG("trace off...\n");
		return;
	}

	if (msg->msg_flags & FL_USE_SIPTRACE) {
		return;
	}
	LM_DBG("trace on req in \n");

	avp = NULL;
	if(traced_user_avp>=0)
		avp=search_first_avp(traced_user_avp_type, traced_user_avp,
				&avp_value, 0);

	if( (avp==NULL) && !flag_trace_is_set(msg))
	{
		LM_DBG("nothing to trace...\n");
		return;
	}

	if(parse_from_header(msg)==-1 || msg->from==NULL || get_from(msg)==NULL)
	{
		LM_ERR("cannot parse FROM header\n");
		return;
	}

	if(parse_headers(msg, HDR_CALLID_F, 0)!=0)
	{
		LM_ERR("cannot parse call-id\n");
		return;
	}

	if(tmb.register_tmcb( 0, t, TMCB_REQUEST_BUILT, trace_onreq_out, 0, 0) <=0)
	{
		LM_ERR("can't register trace_onreq_out\n");
		return;
	}

	if(tmb.register_tmcb( 0, t, TMCB_RESPONSE_IN, trace_onreply_in, 0, 0) <=0)
	{
		LM_ERR("can't register trace_onreply_in\n");
		return;
	}

	if(tmb.register_tmcb( 0, t, TMCB_RESPONSE_OUT, trace_onreply_out, 0, 0) <=0)
	{
		LM_ERR("can't register trace_onreply_out\n");
		return;
	}
}

static void trace_onreq_out(struct cell* t, int type, struct tmcb_params *ps)
{
	if(t==NULL || ps==NULL) {
		LM_DBG("no uas request, local transaction\n");
		return;
	}
	if(ps->req==NULL) {
		LM_DBG("no uas msg, local transaction\n");
		return;
	}

	LM_DBG("trace on req out \n");

	if (ps->extra2)
		trace_msg_out( ps->req, (str*)ps->extra1,
			((struct dest_info*)ps->extra2)->send_sock,
			((struct dest_info*)ps->extra2)->proto,
			&((struct dest_info*)ps->extra2)->to);
	else
		trace_msg_out( ps->req, (str*)ps->extra1,
			NULL, PROTO_NONE, NULL);

}

static void trace_msg_out_w(struct sip_msg* msg, str  *sbuf,
			struct socket_info* send_sock, int proto, union sockaddr_union *to)
{
	if( trace_is_off() )
	{
		LM_DBG("trace off...\n");
		return;
	}
	return trace_msg_out(msg, sbuf, send_sock, proto, to);
}

static void trace_msg_out(struct sip_msg* msg, str  *sbuf,
			struct socket_info* send_sock, int proto, union sockaddr_union *to)
{
	static char fromip_buff[IP_ADDR_MAX_STR_SIZE+12];
	static char toip_buff[IP_ADDR_MAX_STR_SIZE+12];
	int_str        avp_value;
	struct usr_avp *avp;
	struct ip_addr to_ip;

	avp = NULL;
	if(traced_user_avp>=0)
		avp=search_first_avp(traced_user_avp_type, traced_user_avp,
				&avp_value, 0);

	if ( (avp==NULL) && !flag_trace_is_set(msg) )
	{
		LM_DBG("trace off...\n");
		return;
	}

	if(parse_from_header(msg)==-1 || msg->from==NULL || get_from(msg)==NULL)
	{
		LM_ERR("cannot parse FROM header\n");
		goto error;
	}

	if(parse_headers(msg, HDR_CALLID_F, 0)!=0)
	{
		LM_ERR("cannot parse call-id\n");
		return;
	}

	LM_DBG("trace msg out \n");

	if(sbuf!=NULL && sbuf->len>0)
	{
		db_vals[0].val.blob_val.s   = sbuf->s;
		db_vals[0].val.blob_val.len = sbuf->len;
	} else {
		db_vals[0].val.blob_val.s   = "No request buffer";
		db_vals[0].val.blob_val.len = sizeof("No request buffer")-1;
	}

	/* check Call-ID header */
	if(msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("cannot find Call-ID header!\n");
		goto error;
	}

	db_vals[1].val.str_val.s = msg->callid->body.s;
	db_vals[1].val.str_val.len = msg->callid->body.len;

	if(sbuf!=NULL && sbuf->len > 7 && !strncasecmp(sbuf->s, "CANCEL ", 7))
	{
		db_vals[2].val.str_val.s = "CANCEL";
		db_vals[2].val.str_val.len = 6;
	} else {
		db_vals[2].val.str_val= REQ_LINE(msg).method;
	}

	db_vals[3].val.str_val.s = "";
	db_vals[3].val.str_val.len = 0;

	memset(&to_ip, 0, sizeof(struct ip_addr));

	if (trace_local_ip.s && trace_local_ip.len > 0){
		set_columns_to_trace_local_ip( db_vals[4], db_vals[5], db_vals[6]);
	}
	else {
		if(send_sock==0 || send_sock->sock_str.s==0)
		{
			set_sock_columns( db_vals[4], db_vals[5], db_vals[6], fromip_buff,
					&msg->rcv.dst_ip, msg->rcv.dst_port, msg->rcv.proto);
		} else {
			char *nbuff = proto2str(send_sock->proto,fromip_buff);
			db_vals[4].val.str_val.s = fromip_buff;
			db_vals[4].val.str_val.len = nbuff - fromip_buff;
			db_vals[5].val.str_val = send_sock->address_str;
			db_vals[6].val.int_val = send_sock->port_no;
		}
	}

	if(to==0)
	{
		set_columns_to_any(db_vals[7], db_vals[8], db_vals[9]);
	} else {
		su2ip_addr(&to_ip, to);
		set_sock_columns( db_vals[7], db_vals[8], db_vals[9], toip_buff,
			&to_ip, (unsigned short)su_getport(to), proto);
	}

	db_vals[10].val.time_val = time(NULL);

	db_vals[11].val.string_val = "out";

	db_vals[12].val.str_val.s = get_from(msg)->tag_value.s;
	db_vals[12].val.str_val.len = get_from(msg)->tag_value.len;

	if (save_siptrace(msg,avp,&avp_value,db_keys,db_vals) < 0) {
		LM_ERR("failed to save siptrace\n");
		goto error;
	}

#ifdef STATISTICS
	update_stat(siptrace_req, 1);
#endif
	return;
error:
	return;
}

static void trace_onreply_in(struct cell* t, int type, struct tmcb_params *ps)
{

	static char fromip_buff[IP_ADDR_MAX_STR_SIZE+12];
	static char toip_buff[IP_ADDR_MAX_STR_SIZE+12];
	struct sip_msg* msg;
	struct sip_msg* req;
	int_str        avp_value;
	struct usr_avp *avp;
	char statusbuf[8];
	int len;

	if(t==NULL || t->uas.request==0 || ps==NULL)
	{
		LM_DBG("no uas request, local transaction\n");
		return;
	}

	req = ps->req;
	msg = ps->rpl;
	if(msg==NULL || req==NULL)
	{
		LM_DBG("no reply\n");
		return;
	}

	LM_DBG("trace onreply in \n");

	avp = NULL;
	if(traced_user_avp>=0)
		avp=search_first_avp(traced_user_avp_type, traced_user_avp,
				&avp_value, 0);

	if(parse_from_header(msg)==-1 || msg->from==NULL || get_from(msg)==NULL)
	{
		LM_ERR("cannot parse FROM header\n");
		goto error;
	}

	if(parse_headers(msg, HDR_CALLID_F, 0)!=0)
	{
		LM_ERR("cannot parse call-id\n");
		return;
	}

	if(msg->len>0) {
		db_vals[0].val.blob_val.s   = msg->buf;
		db_vals[0].val.blob_val.len = msg->len;
	} else {
		db_vals[0].val.blob_val.s   = "No reply buffer";
		db_vals[0].val.blob_val.len = sizeof("No reply buffer")-1;
	}

	/* check Call-ID header */
	if(msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("cannot find Call-ID header!\n");
		goto error;
	}

	db_vals[1].val.str_val.s = msg->callid->body.s;
	db_vals[1].val.str_val.len = msg->callid->body.len;

	db_vals[2].val.str_val.s = t->method.s;
	db_vals[2].val.str_val.len = t->method.len;

	strcpy(statusbuf, int2str(ps->code, &len));
	db_vals[3].val.str_val.s = statusbuf;
	db_vals[3].val.str_val.len = len;

	set_sock_columns( db_vals[4], db_vals[5], db_vals[6], fromip_buff,
		&msg->rcv.src_ip,  msg->rcv.src_port, msg->rcv.proto);

	if(trace_local_ip.s && trace_local_ip.len > 0){
		set_columns_to_trace_local_ip(db_vals[7], db_vals[8], db_vals[9]);
	}
	else {
		set_sock_columns( db_vals[7], db_vals[8], db_vals[9], toip_buff,
			&msg->rcv.dst_ip, msg->rcv.dst_port, msg->rcv.proto);
	}

	db_vals[10].val.time_val = time(NULL);

	db_vals[11].val.string_val = "in";

	db_vals[12].val.str_val.s = get_from(msg)->tag_value.s;
	db_vals[12].val.str_val.len = get_from(msg)->tag_value.len;

	if (save_siptrace(req,avp,&avp_value,db_keys,db_vals) < 0) {
		LM_ERR("failed to save siptrace\n");
		goto error;
	}

#ifdef STATISTICS
	update_stat(siptrace_rpl, 1);
#endif
	return;
error:
	return;
}

static void trace_onreply_out(struct cell* t, int type, struct tmcb_params *ps)
{
	int faked = 0;
	static char fromip_buff[IP_ADDR_MAX_STR_SIZE+12];
	static char toip_buff[IP_ADDR_MAX_STR_SIZE+12];
	struct sip_msg* msg;
	struct sip_msg* req;
	int_str        avp_value;
	struct usr_avp *avp;
	struct ip_addr to_ip;
	int len;
	char statusbuf[8];
	str *sbuf;
	struct dest_info *dst;

	if (t==NULL || t->uas.request==0 || ps==NULL)
	{
		LM_DBG("no uas request, local transaction\n");
		return;
	}

	LM_DBG("trace onreply out \n");

	avp = NULL;
	if(traced_user_avp>=0)
		avp=search_first_avp(traced_user_avp_type, traced_user_avp,
				&avp_value, 0);

	req = ps->req;
	msg = ps->rpl;
	if(msg==NULL || msg==FAKED_REPLY)
	{
		msg = t->uas.request;
		faked = 1;
	}

	if(parse_from_header(msg)==-1 || msg->from==NULL || get_from(msg)==NULL)
	{
		LM_ERR("cannot parse FROM header\n");
		goto error;
	}

	if(parse_headers(msg, HDR_CALLID_F, 0)!=0)
	{
		LM_ERR("cannot parse call-id\n");
		return;
	}

	sbuf = (str*)ps->extra1;
	if(faked==0)
	{
		if(sbuf!=0 && sbuf->len>0) {
			db_vals[0].val.blob_val.s   = sbuf->s;
			db_vals[0].val.blob_val.len = sbuf->len;
		} else if(t->uas.response.buffer.s!=NULL) {
			db_vals[0].val.blob_val.s   = t->uas.response.buffer.s;
			db_vals[0].val.blob_val.len = t->uas.response.buffer.len;
		} else if(msg->len>0) {
			db_vals[0].val.blob_val.s   = msg->buf;
			db_vals[0].val.blob_val.len = msg->len;
		} else {
			db_vals[0].val.blob_val.s   = "No reply buffer";
			db_vals[0].val.blob_val.len = sizeof("No reply buffer")-1;
		}
	} else {
		if(sbuf!=0 && sbuf->len>0) {
			db_vals[0].val.blob_val.s   = sbuf->s;
			db_vals[0].val.blob_val.len = sbuf->len;
		} else if(t->uas.response.buffer.s==NULL) {
			db_vals[0].val.blob_val.s = "No reply buffer";
			db_vals[0].val.blob_val.len = sizeof("No reply buffer")-1;
		} else {
			db_vals[0].val.blob_val.s = t->uas.response.buffer.s;
			db_vals[0].val.blob_val.len = t->uas.response.buffer.len;
		}
	}

	/* check Call-ID header */
	if(msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("cannot find Call-ID header!\n");
		goto error;
	}

	db_vals[1].val.str_val.s = msg->callid->body.s;
	db_vals[1].val.str_val.len = msg->callid->body.len;

	db_vals[2].val.str_val.s = t->method.s;
	db_vals[2].val.str_val.len = t->method.len;


	if(trace_local_ip.s && trace_local_ip.len > 0){
		set_columns_to_trace_local_ip(db_vals[4], db_vals[5], db_vals[6]);
	}
	else {
		set_sock_columns( db_vals[4], db_vals[5], db_vals[6], fromip_buff,
			&msg->rcv.dst_ip, msg->rcv.dst_port, msg->rcv.proto);
	}

	strcpy(statusbuf, int2str(ps->code, &len));
	db_vals[3].val.str_val.s = statusbuf;
	db_vals[3].val.str_val.len = len;

	memset(&to_ip, 0, sizeof(struct ip_addr));
	dst = (struct dest_info*)ps->extra2;
	if(dst==0)
	{
		set_columns_to_any( db_vals[7], db_vals[8], db_vals[9]);
	} else {
		su2ip_addr(&to_ip, &dst->to);
		set_sock_columns( db_vals[7], db_vals[8], db_vals[9], toip_buff,
			&to_ip, (unsigned long)su_getport(&dst->to), dst->proto);
	}

	db_vals[10].val.time_val = time(NULL);

	db_vals[11].val.string_val = "out";

	db_vals[12].val.str_val.s = get_from(msg)->tag_value.s;
	db_vals[12].val.str_val.len = get_from(msg)->tag_value.len;

	if (save_siptrace(req,avp,&avp_value,db_keys,db_vals) < 0) {
		LM_ERR("failed to save siptrace\n");
		goto error;
	}

#ifdef STATISTICS
	update_stat(siptrace_rpl, 1);
#endif
	return;
error:
	return;
}

static void trace_sl_ack_in( unsigned int types, struct sip_msg* req,
									struct sl_cb_param *sl_param)
{
	LM_DBG("storing ack...\n");
	sip_trace_w(req);
}

static void trace_sl_onreply_out( unsigned int types, struct sip_msg* req,
									struct sl_cb_param *sl_param)
{
	static char fromip_buff[IP_ADDR_MAX_STR_SIZE+12];
	static char toip_buff[IP_ADDR_MAX_STR_SIZE+12];
	struct sip_msg* msg;
	int_str        avp_value;
	struct usr_avp *avp;
	struct ip_addr to_ip;
	int len;
	char statusbuf[5];

	if(req==NULL || sl_param==NULL)
	{
		LM_ERR("bad parameters\n");
		goto error;
	}

	if( trace_is_off() )
	{
		LM_DBG("trace off...\n");
		return;
	}

	LM_DBG("trace slonreply out \n");

	avp = NULL;
	if(traced_user_avp >= 0)
		avp=search_first_avp(traced_user_avp_type, traced_user_avp,
				&avp_value, 0);

	if((avp==NULL) && !flag_trace_is_set(req))
	{
		LM_DBG("nothing to trace...\n");
		return;
	}

	msg = req;

	if(parse_from_header(msg)==-1 || msg->from==NULL || get_from(msg)==NULL)
	{
		LM_ERR("cannot parse FROM header\n");
		goto error;
	}

	if(parse_headers(msg, HDR_CALLID_F, 0)!=0)
	{
		LM_ERR("cannot parse call-id\n");
		return;
	}

	db_vals[0].val.blob_val.s   = (sl_param->buffer)?sl_param->buffer->s:"";
	db_vals[0].val.blob_val.len = (sl_param->buffer)?sl_param->buffer->len:0;

	/* check Call-ID header */
	if(msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("cannot find Call-ID header!\n");
		goto error;
	}

	db_vals[1].val.str_val.s = msg->callid->body.s;
	db_vals[1].val.str_val.len = msg->callid->body.len;

	db_vals[2].val.str_val.s = msg->first_line.u.request.method.s;
	db_vals[2].val.str_val.len = msg->first_line.u.request.method.len;

	if(trace_local_ip.s && trace_local_ip.len > 0){
		set_columns_to_trace_local_ip( db_vals[4], db_vals[5], db_vals[6]);
	}
	else {
		set_sock_columns( db_vals[4], db_vals[5], db_vals[6], fromip_buff,
			&msg->rcv.dst_ip, msg->rcv.dst_port, msg->rcv.proto);
	}

	strcpy(statusbuf, int2str(sl_param->code, &len));
	db_vals[3].val.str_val.s = statusbuf;
	db_vals[3].val.str_val.len = len;

	memset(&to_ip, 0, sizeof(struct ip_addr));
	if(sl_param->dst==0)
	{
		set_columns_to_any(db_vals[7], db_vals[8], db_vals[9]);
	} else {
		su2ip_addr(&to_ip, sl_param->dst);
		set_sock_columns( db_vals[7], db_vals[8],db_vals[9], toip_buff, &to_ip,
			(unsigned short)su_getport(sl_param->dst), req->rcv.proto);
	}

	db_vals[10].val.time_val = time(NULL);

	db_vals[11].val.string_val = "out";

	db_vals[12].val.str_val.s = get_from(msg)->tag_value.s;
	db_vals[12].val.str_val.len = get_from(msg)->tag_value.len;

	if (save_siptrace(msg,avp,&avp_value,db_keys,db_vals) < 0) {
		LM_ERR("failed to save siptrace\n");
		goto error;
	}

#ifdef STATISTICS
	update_stat(siptrace_rpl, 1);
#endif
	return;
error:
	return;
}


/**
 * MI command format:
 * name: sip_trace
 * attribute: name=none, value=[on|off]
 */
static struct mi_root* sip_trace_mi(struct mi_root* cmd_tree, void* param )
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

		if (*trace_on_flag == 0 ) {
			node = add_mi_node_child(rpl,0,0,0,MI_SSTR("off"));
		} else if (*trace_on_flag == 1) {
			node = add_mi_node_child(rpl,0,0,0,MI_SSTR("on"));
		}
		return rpl_tree ;
	}
	if(trace_on_flag==NULL)
		return init_mi_tree( 500, MI_SSTR(MI_INTERNAL_ERR));

	if ( node->value.len==2 &&
	(node->value.s[0]=='o'|| node->value.s[0]=='O') &&
	(node->value.s[1]=='n'|| node->value.s[1]=='N'))
	{
		*trace_on_flag = 1;
		return init_mi_tree( 200, MI_SSTR(MI_OK));
	} else if ( node->value.len==3 &&
	(node->value.s[0]=='o'|| node->value.s[0]=='O') &&
	(node->value.s[1]=='f'|| node->value.s[1]=='F') &&
	(node->value.s[2]=='f'|| node->value.s[2]=='F'))
	{
		*trace_on_flag = 0;
		return init_mi_tree( 200, MI_SSTR(MI_OK));
	} else {
		return init_mi_tree( 400, MI_SSTR(MI_BAD_PARM));
	}
}

/**
 * MI command format:
 * name: trace_to_database
 * attribute: name=none, value=[on|off]
 */
static struct mi_root* trace_to_database_mi (struct mi_root* cmd_tree, void* param )
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

		if (*trace_to_database_flag == 0 ) {
			node = add_mi_node_child(rpl,0,0,0,MI_SSTR("off"));
		} else if (*trace_to_database_flag == 1) {
			node = add_mi_node_child(rpl,0,0,0,MI_SSTR("on"));
		}
		return rpl_tree ;
	}
	if(trace_to_database_flag==NULL)
		return init_mi_tree( 500, MI_SSTR(MI_INTERNAL_ERR));

	if ( node->value.len==2 &&
	(node->value.s[0]=='o'|| node->value.s[0]=='O') &&
	(node->value.s[1]=='n'|| node->value.s[1]=='N'))
	{
                if (db_con!=NULL) {
        		*trace_to_database_flag = 1;
	        	return init_mi_tree( 200, MI_SSTR(MI_OK));
                }
                else {
                        return init_mi_tree( 501, MI_SSTR(MI_INTERNAL_ERR));
                }

	} else if ( node->value.len==3 &&
	(node->value.s[0]=='o'|| node->value.s[0]=='O') &&
	(node->value.s[1]=='f'|| node->value.s[1]=='F') &&
	(node->value.s[2]=='f'|| node->value.s[2]=='F'))
	{
		*trace_to_database_flag = 0;
		return init_mi_tree( 200, MI_SSTR(MI_OK));
	} else {
		return init_mi_tree( 400, MI_SSTR(MI_BAD_PARM));
	}
}


static int trace_send_duplicate(char *buf, int len)
{
	union sockaddr_union* to;
	struct socket_info* send_sock;
	struct proxy_l * p;
	int proto;
	int ret;

	if(buf==NULL || len <= 0)
		return -1;

	if(dup_uri_str.s==0 || dup_uri==NULL)
		return 0;

	to=(union sockaddr_union*)pkg_malloc(sizeof(union sockaddr_union));
	if (to==0){
		LM_ERR("out of pkg memory\n");
		return -1;
	}

	/* create a temporary proxy*/
	proto = PROTO_UDP;
	p=mk_proxy(&dup_uri->host, (dup_uri->port_no)?dup_uri->port_no:SIP_PORT,
			proto, 0);
	if (p==0){
		LM_ERR("bad host name in uri\n");
		pkg_free(to);
		return -1;
	}

	hostent2su(to, &p->host, p->addr_idx,
				(p->port)?p->port:SIP_PORT);

	ret = -1;

	do {
		send_sock=get_send_socket(0, to, proto);
		if (send_sock==0){
			LM_ERR("can't forward to af %d, proto %d no corresponding listening socket\n",
					to->s.sa_family,proto);
			continue;
		}

		if (msg_send(send_sock, proto, to, 0, buf, len, NULL)<0){
			LM_ERR("cannot send duplicate message\n");
			continue;
		}
		ret = 0;
		break;
	}while( get_next_su( p, to, 0)==0 );

	free_proxy(p); /* frees only p content, not p itself */
	pkg_free(p);
	pkg_free(to);

	return ret;
}

static int trace_send_hep_duplicate(str *body, str *fromproto, str *fromip,
		unsigned short fromport, str *toproto, str *toip, unsigned short toport)
{
	struct proxy_l * p=NULL /* make gcc happy */;
	int ret;
	union sockaddr_union from_su;
	union sockaddr_union to_su;
	unsigned int proto, osip_proto;
	struct socket_info* send_sock;
	union sockaddr_union* to = NULL;

	int heplen;
	char *hepbuf;

	if(body->s==NULL || body->len <= 0)
		return -1;

	if(dup_uri_str.s==0 || dup_uri==NULL)
		return 0;

	/* Convert proto:ip:port to sockaddress union SRC IP */
	/* proto is going to be converted to netinet proto */
	if (pipport2su(fromproto, fromip, fromport, &from_su, &proto)==-1 ||
	(pipport2su(toproto, toip, toport, &to_su, &proto)==-1))
		goto error;

	/* check if from and to are in the same family*/
	if(from_su.s.sa_family != to_su.s.sa_family) {
		LM_ERR("ERROR: trace_send_hep_duplicate: interworking detected ?\n");
		goto error;
	}


	/* create a temporary proxy*/
	p=mk_proxy(&dup_uri->host, (dup_uri->port_no)?dup_uri->port_no:SIP_PORT,proto, 0);
	if (p==0){
		LM_ERR("bad host name in uri\n");
		return -1;
	}

	to=(union sockaddr_union*)pkg_malloc(sizeof(union sockaddr_union));
	if (to==0){
		LM_ERR("out of pkg memory\n");
		return -1;
	}

	hostent2su(to, &p->host, p->addr_idx, (p->port)?p->port:SIP_PORT);

	if (hep_api.pack_hep(&from_su, to, proto, body->s, body->len,
				&hepbuf, &heplen)) {
		LM_ERR("failed to do hep packing\n");
		return -1;
	}

	switch (proto) {
		case IPPROTO_UDP:
			osip_proto = PROTO_UDP;
			break;

		case IPPROTO_TCP:
			osip_proto = PROTO_TCP;
			break;

		case IPPROTO_IDP:
			osip_proto = PROTO_TLS;
			break;

		case IPPROTO_SCTP:
			osip_proto = PROTO_SCTP;
			break;

		case IPPROTO_ESP:
			osip_proto = PROTO_WS;
			break;

		default:
			LM_ERR("Unknown protocol [%d]\n", proto);
			return -1;
	}

	ret = -1;

	do {
		send_sock=get_send_socket(0, to, osip_proto);
		if (send_sock==0){
			LM_ERR("can't forward to af %d, proto %d no corresponding listening socket\n",
					to->s.sa_family,proto);
			continue;
		}

		if (msg_send(send_sock, PROTO_HEP, to, 0, hepbuf, heplen, NULL)<0){
			LM_ERR("cannot send duplicate message\n");
			continue;
		}
		ret = 0;
		break;
	}while( get_next_su( p, to, 0)==0 );
	free_proxy(p); /* frees only p content, not p itself */
	pkg_free(p);
	pkg_free(to);
	pkg_free(hepbuf);

	return ret;
error:
	if(p)
	{
		free_proxy(p); /* frees only p content, not p itself */
		pkg_free(p);
	}
	if(to) pkg_free(to);
	return -1;
}

/*!
 * \brief Convert a STR [proto:]ip[:port] into socket address.
 * [proto:]ip[:port]
 * \param pipport (udp:127.0.0.1:5060 or tcp:2001:0DB8:AC10:FE01:5060)
 * \param tmp_su target structure
 * \param proto uint protocol type
 * \return success / unsuccess
 */
static int pipport2su (str *sproto, str *ip, unsigned short port,
			union sockaddr_union *tmp_su, unsigned int *proto)
{
	struct ip_addr *ip_a;
	str host_uri;

	/*parse protocol */
	if(strncmp(sproto->s, "udp",3) == 0) *proto = IPPROTO_UDP;
	else if(strncmp(sproto->s, "tcp",3) == 0) *proto = IPPROTO_TCP;
	else if(strncmp(sproto->s, "tls",3) == 0) *proto = IPPROTO_IDP;
												/* fake proto type */
	else if(strncmp(sproto->s, "sctp",4) == 0) *proto = IPPROTO_SCTP;
	else if(strncmp(sproto->s, "any",3) == 0) *proto = IPPROTO_UDP;
	else if(strncmp(sproto->s, "ws",2) == 0) *proto = IPPROTO_ESP;
												/* fake proto type */
	else {
		LM_ERR("bad protocol %.*s\n", sproto->len, sproto->s);
		return -1;
	}

	/*check if ip is not null*/
	if (ip->len == 0) {
		LM_ERR("malformed ip address\n");
		return -1;
	}

	if (port == 0) {
		port = SIP_PORT;
	}
	else{
	/*the address contains a port number*/
		if (port<1024  || port>65536)
		{
			LM_ERR("invalid port number; must be in [1024,65536]\n");
			return -1;
		}
	}
	LM_DBG("proto %d, host %.*s , port %d \n",*proto, ip->len, ip->s, port);

	/* now IPv6 address has no brakets. It should be fixed! */
	host_uri = *ip;
	if (host_uri.s[0] == '[') {
		if(host_uri.s[host_uri.len-1] != ']') {
			LM_ERR("bracket not closed\n");
			return -1;
		}
		host_uri.s++;
		host_uri.len -= 2;
	}

	/* check if it's an ip address */
	if (((ip_a = str2ip(&host_uri)) != 0)
			|| ((ip_a = str2ip6 (&host_uri)) != 0)
	) {
		ip_addr2su(tmp_su, ip_a, ntohs(port));
		return 0;
	}

	LM_ERR("host <%.*s> is not an IP\n",host_uri.len,host_uri.s);
	return -1;
}
