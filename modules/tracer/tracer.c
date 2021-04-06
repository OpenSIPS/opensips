/*
 * tracer module - helper module to trace sip messages
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
#include "../../net/net_tcp.h"
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
#include "../../sl_cb.h"
#include "../../str.h"
#include "../../script_cb.h"
#include "../tm/tm_load.h"
#include "../dialog/dlg_load.h"
#include "../../mod_fix.h"
#include "tracer.h"

/* trace info context position */
int sl_ctx_idx=-1;

/* DB structures used for all queries */
db_key_t db_keys[NR_KEYS];
db_val_t db_vals[NR_KEYS];

static db_ps_t siptrace_ps = NULL;
//static query_list_t *ins_list = NULL;

#define trace_id(_tid) ((tlist_elem_p)(_tid))
#define trace_id_dyn(_tid) ((tlist_dyn_elem_p)(_tid))
#define trace_id_ref(_tid) (trace_id_dyn(_tid)->ref++)
#define trace_id_unref(_tid) \
	do { \
		trace_id_dyn(_tid)->ref--; \
		if (trace_id_dyn(_tid)->ref == 0) { \
			if (trace_id(_tid)->type == TYPE_HEP) \
				tprot.release_trace_dest(trace_id(_tid)->el.hep.hep_id); \
			if (trace_id_dyn(_tid)->filters) \
				free_trace_filters(trace_id_dyn(_tid)->filters); \
			shm_free(_tid); \
		} \
	} while (0)


struct tm_binds tmb;
struct dlg_binds dlgb;

static trace_proto_t tprot;

/* "sip" tracing identifier */
int sip_trace_id;

/* module function prototypes */
static int mod_init(void);
static int child_init(int rank);
static void destroy(void);

static str siptrace_table     = str_init("sip_trace");
static str date_column        = str_init("time_stamp");  /* 00 */
static str callid_column      = str_init("callid");      /* 01 */
static str trace_attrs_column = str_init("trace_attrs"); /* 02 */
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

static int trace_on   = 1;

static int *trace_on_flag = NULL;

static str trace_local_proto = {NULL, 0};
static str trace_local_ip = {NULL, 0};
static unsigned short trace_local_port = 0;

static tlist_elem_p trace_list=NULL;
static tlist_elem_p *dyn_trace_list=NULL;
static gen_lock_t *dyn_trace_lock;

static const char* corr_id_s="correlation_id";
static int corr_vendor = -1;
static int corr_id=-1;



/**
 * TRACER FUNCTIONS
 *
 * **/
static int fixup_tid(void **param);
static int fixup_sflags(void **param);
static int trace_w(struct sip_msg *msg, tlist_elem_p list,
					void *scope_p, str *trace_types_s, str *trace_attrs);
static int sip_trace(struct sip_msg*, trace_info_p);
static int sip_trace_instance(struct sip_msg*, trace_instance_p, int);

static int trace_dialog(struct sip_msg*, trace_info_p);
static int trace_transaction(struct sip_msg* msg, trace_info_p info,
								char dlg_tran);


static void trace_onreq_out(struct cell* t, int type, struct tmcb_params *ps);
static void trace_tm_in(struct cell* t, int type, struct tmcb_params *ps);
static void trace_tm_out(struct cell* t, int type, struct tmcb_params *ps);
static void trace_msg_out(struct sip_msg* req, str  *buffer,
			struct socket_info* send_sock, int proto, union sockaddr_union *to,
			trace_info_p info);
static void siptrace_dlg_cancel(struct cell* t, int type, struct tmcb_params *param);

/*
 * callback used for statelessly forwarded requests; also catches the ACK in
 * stateful transaction
 */
static void trace_slreq_out(struct sip_msg* req, str *buffer,int rpl_code,
				union sockaddr_union *to, struct socket_info *sock, int proto);
static void trace_slreply_out(struct sip_msg* req, str *buffer,int rpl_code,
				union sockaddr_union *dst, struct socket_info *sock, int proto);

#if 0
static void trace_slack_in(struct sip_msg* req, str *buffer,int rpl_code,
				union sockaddr_union *dst, struct socket_info *sock, int proto);
#endif

static mi_response_t *sip_trace_mi(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *sip_trace_mi_tid(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *sip_trace_mi_mode(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *sip_trace_mi_2(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *sip_trace_mi_dyn(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *sip_trace_mi_stop(const mi_params_t *params,
								struct mi_handler *async_hdl);

static int trace_send_duplicate(char *buf, int len, struct sip_uri *uri);
static int send_trace_proto_duplicate(trace_dest dest,
		str* correlation, trace_instance_p info, int conn_id);

static int api_is_id_traced(int id);
static int is_id_traced(int id, trace_instance_p info);


static int pipport2su (str *sproto, str *ip, unsigned short port,
			union sockaddr_union *tmp_su, unsigned int *proto);

static int parse_trace_id(unsigned int type, void *val);

void free_trace_info_pkg(void *param);
void free_trace_info_shm(void *param);
static void free_trace_filters(struct trace_filter *list);


static int init_dyn_tracing(void);
static void destroy_dyn_tracing(void);
static int process_dyn_tracing(struct sip_msg *msg, void *param);


/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"trace", (cmd_function)trace_w, {
		{CMD_PARAM_STR, fixup_tid, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, fixup_sflags, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"trace_id",           STR_PARAM|USE_FUNC_PARAM, parse_trace_id},
	{"date_column",        STR_PARAM, &date_column.s        },
	{"callid_column",      STR_PARAM, &callid_column.s      },
	{"trace_attrs_column", STR_PARAM,&trace_attrs_column.s},
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
	{"trace_on",           INT_PARAM, &trace_on             },
	{"trace_local_ip",     STR_PARAM, &trace_local_ip.s     },
	{0, 0, 0}
};

static mi_export_t mi_cmds[] = {
	{ "trace", 0, MI_NAMED_PARAMS_ONLY, 0, {
		{sip_trace_mi, {0}},
		{sip_trace_mi_tid,  {"id", 0}},
		{sip_trace_mi_mode, {"mode", 0}},
		{sip_trace_mi_2,{"id", "mode", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "trace_start", 0, 0, 0, {
		{sip_trace_mi_dyn,{"id", "uri", 0}},
		{sip_trace_mi_dyn,{"id", "uri", "filter", 0}},
		{sip_trace_mi_dyn,{"id", "uri", "filter", "scope", "type", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "trace_stop", 0, 0, 0, {
		{sip_trace_mi_stop,{"id", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{EMPTY_MI_EXPORT}
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
	tlist_elem_p it;

	for (it=trace_list;it;it=it->next)
		if (it->type==TYPE_HEP)
			return alloc_module_dep(MOD_TYPE_DEFAULT, "proto_hep", DEP_ABORT);
		else if (it->type==TYPE_DB)
			return alloc_module_dep(MOD_TYPE_SQLDB, NULL, DEP_ABORT);

	return NULL;
}


static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{"trace_id", get_deps_hep},
		{ NULL, NULL },
	},
};

/* module exports */
struct module_exports exports = {
	"tracer",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
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
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	destroy,    /* destroy function */
	child_init, /* child initialization function */
	0           /* reload confirm function */
};


static int
get_db_struct(str *url, str *tb_name, st_db_struct_t **st_db)
{
	st_db_struct_t *dbs;
	dbs = pkg_malloc(sizeof(st_db_struct_t));

	if (st_db == NULL) {
		LM_ERR("invalid output parameter!\n");
		return -1;
	}

	if (url == NULL || url->s == NULL || url->len == 0) {
		LM_ERR("invalid URL!\n");
		return -1;
	}

	/* if not set populated with 'tracer_table' in parse_siptrace_id() */
	dbs->table = *tb_name;

	if (db_bind_mod(url, &dbs->funcs)) {
		LM_ERR("unable to bind database module\n");
		return -1;
	}

	if (!DB_CAPABILITY(dbs->funcs, DB_CAP_INSERT)) {
		LM_ERR("database modules does not provide all functions "
			"needed by module\n");
		return -1;
	}

	dbs->url = *url;

	*st_db = dbs;

	return 0;

}

static inline void get_value_and_update(str* token, char delim, str* value)
{
	char* end;

	value->s = token->s;
	if ( !(end=q_memchr(token->s, delim, token->len)) ) {
		value->len = token->len;
		token->len = 0;
	} else {
		value->len = end - token->s;
		token->len = token->len - ((end + 1) - token->s);

		/* might have a negative value if ';' is the last character */
		if ( token->len > 0 )
			token->s = end + 1;
	}

	str_trim_spaces_lr(*value);
}

static int
parse_siptrace_uri(str* token, str* uri, str* param1)
{

	static const char key_value_delim = '=';
	static const char param_delim = ';';
	static const char db_delim = '\\';

	static str uri_str={"uri", sizeof("uri")-1};
	static str tb_name_str={"table", sizeof("table")-1};

	char *end;

	str key, value, aux;

	/* we must be careful because there might be a mysql password containing
	 * our delimiters; so we first parse the key then carefully go through
	 * the value if it's an uri */

	str_trim_spaces_lr(*token);

	while ( token->len > 0 ) {
		if ( !(end=q_memchr(token->s, key_value_delim, token->len)) ) {
			LM_ERR("key delimiter '=' not found in <%.*s>\n", token->len, token->s);
			return -1;
		}

		key.s = token->s;
		key.len = end - token->s;

		str_trim_spaces_lr(key);

		token->len -= ((end + 1) - token->s);
		token->s = end + 1;

		if ( !strncmp(key.s, uri_str.s, uri_str.len) ) {
			if ( !(end=q_memrchr( token->s, db_delim, token->len)) ) {
				/* no '/' so it's not a db url; just do a normal parse  */
				get_value_and_update( token, param_delim, &value);
			} else {
				aux.s = end;
				aux.len = token->len - (end - token->s);

				value.s = token->s;
				/* now search the actual delimiter */
				if ( !(end=q_memchr( aux.s, param_delim, aux.len)) ) {
					value.len = token->len;

					token->len = 0;
				} else {
					value.len = end - token->s;
					token->len = token->len - ((end+1) - token->s);

					if ( token->len > 0 )
						token->s = end + 1;
				}

			}

			*uri = value;
		} else if ( !strncmp(key.s, tb_name_str.s, tb_name_str.len) ) {
			get_value_and_update( token, param_delim, &value);

			*param1 = value;
		} else {
			LM_ERR("Invalid key <%.*s> in trace id!\n", key.len, key.s);
			return -1;
		}
	}

	return 0;
}

static void get_siptrace_type(str *name, str *trace_uri, str *param1,
		unsigned int *hash, enum types *type)
{
	#define IS_HEP_URI(__url__) ((__url__->len > 3/*O_o*/ \
				&& (__url__->s[0]|0x20) == 'h' && (__url__->s[1]|0x20) == 'e' \
					&& (__url__->s[2]|0x20) == 'p'))

	#define IS_SIP_URI(__url__) ((__url__->len > 3/*O_o*/ \
				&& (__url__->s[0]|0x20) == 's' && (__url__->s[1]|0x20) == 'i' \
					&& (__url__->s[2]|0x20) == 'p'))

	#define IS_UDP(__url__) ((__url__.len == 3/*O_o*/ \
				&& (__url__.s[0]|0x20) == 'u' && (__url__.s[1]|0x20) == 'd' \
					&& (__url__.s[2]|0x20) == 'p'))

	#define IS_TCP(__url__) ((__url__.len == 3/*O_o*/ \
				&& (__url__.s[0]|0x20) == 't' && (__url__.s[1]|0x20) == 'c' \
					&& (__url__.s[2]|0x20) == 'p'))


	unsigned int param_hash;
	*hash = core_hash(name, trace_uri, 0);

	if (IS_HEP_URI(trace_uri)) {
		/* jump over 'hep:' prefix and keep the name; will be loaded in mod init */
		*type = TYPE_HEP;
		trace_uri->len -= HEP_PREFIX_LEN;
		trace_uri->s += HEP_PREFIX_LEN;
	} else if (IS_SIP_URI(trace_uri)) {
		*type = TYPE_SIP;
	} else {
		/* need to take the table into account */
		if (param1 && (param1->s == NULL || param1->len == 0))
			param1 = &siptrace_table;

		param_hash = core_hash(trace_uri, param1, 0);
		*hash ^= (param_hash>>3);
		*type = TYPE_DB;
	}


	#undef IS_HEP_URI
	#undef IS_SIP_URI
	#undef IS_TCP
	#undef IS_UDP
}

static inline tlist_elem_p get_siptrace_id(str *name, unsigned int hash, enum types type)
{
	tlist_elem_p el;

	for (el = trace_list; el; el = el->next)
		if (el->type == type && el->uri_hash == hash)
			return el;
	return NULL;
}

static inline tlist_elem_p get_dyn_siptrace_id(str *name, unsigned int hash, enum types type,
		int leave_locked)
{
	tlist_elem_p el;

	lock_get(dyn_trace_lock);

	for (el = *dyn_trace_list; el; el = el->next)
		if (el->type == type && el->uri_hash == hash)
				break;
	if (!leave_locked)
		lock_release(dyn_trace_lock);
	return el;
}

static int parse_siptrace_id(str *suri)
{
	#define PARSE_NAME(__uri, __name)                                   \
		do {                                                            \
			while (__uri->s[0]==' ')                                    \
				(__uri->s++, __uri->len--);                             \
			__name.s = __uri->s;                                        \
			while (__uri->len                                           \
					&& (__uri->s[0] != ']' && __uri->s[0] != ' '))      \
				(__uri->s++, __uri->len--, __name.len++);               \
                                                                        \
			if (*(__uri->s-1) != ']')                                   \
				while (__uri->len && __uri->s[0] != ']')                \
					(__uri->s++, __uri->len--);                         \
			                                                            \
			if (!__uri->len || __uri->s[0] != ']') {                    \
				LM_ERR("bad name [%.*s]!\n", __uri->len, __uri->s);     \
				return -1;                                              \
			}                                                           \
			(__uri->s++, __uri->len--);                                 \
		} while(0);

	unsigned int hash;

	str name={NULL, 0};
	str trace_uri;
	str param1={NULL, 0};
	tlist_elem_p elem;
	enum types uri_type;


	if (suri == NULL) {
		LM_ERR("bad input parameters!\n");
		return  -1;
	}

	/*format: [<proto>]uri; it should never have
	 * less than 5 */
	if (suri->len < 5) {
		LM_ERR("suri too short!\n");
		return -1;
	}

	/* we consider the str trimmed before the function */
	if (suri->s[0] != '[') {
		LM_ERR("bad format for uri {%.*s}\n", suri->len, suri->s);
		return -1;
	} else {
		suri->s++;
		suri->len--;
	}

	PARSE_NAME(suri, name); /*parse '[<name>]'*/

	if (parse_siptrace_uri(suri, &trace_uri, &param1) < 0) {
		LM_ERR("invalid uri <%.*s>\n", suri->len, suri->s);
		return -1;
	}

	get_siptrace_type(&name, &trace_uri, &param1, &hash, &uri_type);

	if (get_siptrace_id(&name, hash, uri_type))
		return 0;

	LM_DBG("allocating %d [%.*s]\n", hash, name.len, name.s);
	elem = pkg_malloc(sizeof(tlist_elem_t));
	if (!elem) {
		LM_ERR("could not allocate elem for %.*s!\n", name.len, name.s);
		return -1;
	}
	memset(elem, 0, sizeof(tlist_elem_t));

	elem->type = uri_type;
	elem->hash = core_hash(&name, NULL, 0);
	elem->uri_hash = hash;
	elem->name = name;

	if (uri_type == TYPE_DB) {
		if (get_db_struct(&trace_uri, &param1, &elem->el.db) < 0) {
			LM_ERR("Invalid parameters extracted!url <%.*s>! table name <%.*s>!\n",
					trace_uri.len, trace_uri.s, param1.len, param1.s);
			return -1;
		}
	} else if (uri_type == TYPE_SIP) {
		if (parse_uri(trace_uri.s, trace_uri.len, &elem->el.uri) < 0) {
			LM_ERR("failed to parse the URI!\n");
			return -1;
		}
	} else {
		elem->el.hep.name = trace_uri;
	}

	add_last(elem, trace_list);

	return 0;
	#undef PARSE_NAME
}


int parse_trace_id(unsigned int type, void *val)
{
	str suri;

	suri.s   = (char*)val;
	suri.len = strlen(suri.s);

	str_trim_spaces_lr(suri);

	if (parse_siptrace_id(&suri) < 0) {
		LM_ERR("failed to parse tracer uri [%.*s]\n", suri.len, suri.s);
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

/*
 * no fancy stuff just bubble sort; the list will be quite small
 */
static void do_sort(tlist_elem_p *list_p)
{
	int done=1;
	tlist_elem_p it, prev, tmp;

	/* 0 or 1 elems already sorted */
	if (*list_p==NULL || (*list_p)->next==NULL)
		return;

	do {
		done=1;
		prev=NULL;
		it=*list_p;
		do {
			if (it->hash > it->next->hash) {
				/* need to modify start of the list */
				if (!prev) {
					tmp=it->next;
					it->next=tmp->next;
					tmp->next=it;
					*list_p=tmp;
				} else {
					tmp=it->next;
					prev->next=tmp;
					it->next=tmp->next;
					tmp->next=it;
				}
				done=0;
			}
			prev=it;
			it=it->next;
		} while (it && it->next);
	} while (!done);
}

static void init_db_cols(void)
{
	#define COL_INIT(_col, _index, _type)                  \
		do {                                               \
			db_keys[_index] = &_col##_column;              \
			db_vals[_index].type = DB_##_type;             \
			db_vals[_index].nul  = 0;                      \
		} while(0);


	COL_INIT(msg, 0, STR);
	COL_INIT(callid, 1, STR);
	COL_INIT(method, 2, STR);
	COL_INIT(status, 3, STR);
	COL_INIT(fromproto, 4, STR);
	COL_INIT(fromip, 5, STR);
	COL_INIT(fromport, 6, INT);
	COL_INIT(toproto, 7, STR);
	COL_INIT(toip, 8, STR);
	COL_INIT(toport, 9, INT);
	COL_INIT(date, 10, DATETIME);
	COL_INIT(direction, 11, STRING);
	COL_INIT(fromtag, 12, STR);
	COL_INIT(trace_attrs, 13, STR);
}

static int mod_init(void)
{
	tlist_elem_p it;

	date_column.len = strlen(date_column.s);
	callid_column.len = strlen(callid_column.s);
	trace_attrs_column.len = strlen(trace_attrs_column.s);
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

	if (trace_local_ip.s)
		parse_trace_local_ip();

	LM_INFO("initializing...\n");

	trace_on_flag = (int*)shm_malloc(sizeof(int));
	if(trace_on_flag==NULL)
	{
		LM_ERR("no more shm memory left\n");
		return -1;
	}

	if (init_dyn_tracing() < 0) {
		LM_ERR("could not initiate dynamic tracing!\n");
		return -1;
	}

	*trace_on_flag = trace_on;

	/* best effort - try to load any tracing protocol, if possible */
	if (trace_prot_bind(TRACE_PROTO, &tprot) != 0)
		LM_DBG("failed to load a tracing protocol API\n");

	/* initialize the trace IDs */
	for (it=trace_list;it;it=it->next) {

		switch (it->type) {

			case TYPE_HEP:

				if (tprot.get_trace_dest_by_name == NULL) {
					LM_ERR("NO tracing protocol specified!\n");
					return -1;
				}

				it->el.hep.hep_id = tprot.get_trace_dest_by_name
					(&it->el.hep.name);
				if (it->el.hep.hep_id == NULL) {
					LM_ERR("hep id not found!\n");
					return -1;
				}
				LM_DBG("hep id {%.*s} loaded successfully!\n",
					it->el.hep.name.len, it->el.hep.name.s);

				break;

			case TYPE_DB:

				if((it->el.db->con=it->el.db->funcs.init(&it->el.db->url))==0){
					LM_CRIT("Cannot connect to DB <%.*s>\n",
						it->el.db->url.len, it->el.db->url.s );
					return -1;
				}

				if (db_check_table_version(&it->el.db->funcs, it->el.db->con,
						&it->el.db->table, TRACER_TABLE_VERSION) < 0) {
					LM_ERR("failed to check table version for <%.*s>\n",
						it->el.db->url.len, it->el.db->url.s );
					return -1;
				}
				it->el.db->funcs.close(it->el.db->con);
				it->el.db->con = 0;

				break;

			case TYPE_SIP:
			case TYPE_END:

				/* nothing to do here*/

				break;
		}

	}

	/* set db_keys/vals info */
	init_db_cols();

	/* this will allow using HEP, SIP and DB that
	 * are declared  under the same name in the same
	 * sip_trace() call */
	for (it=trace_list; it; it=it->next) {
		it->traceable=shm_malloc(sizeof(unsigned char));
		if (it->traceable==NULL) {
			LM_ERR("no more shmem!\n");
			return -1;
		}
		*it->traceable = trace_on;
	}

	/* sort the list */
	do_sort(&trace_list);
	if (trace_list==NULL) {
		LM_WARN("No trace id defined! The module is useless!\n");
	}

	/* this makes sense only if trace protocol is loaded */
	if ( tprot.send_message ) {
		sip_trace_id=register_traced_type(SIP_TRACE_TYPE_STR);
		if (sip_trace_id == -1) {
			LM_ERR("failed to get an id for \"%s\" tracing!\n", SIP_TRACE_TYPE_STR);
			return -1;
		}

		if (register_trace_type == NULL)
			register_trace_type = &register_traced_type;

		if (check_is_traced == NULL)
			check_is_traced = &api_is_id_traced;

		if (get_next_destination == NULL)
			get_next_destination = get_next_trace_dest;

		if (sip_context_trace == NULL)
			sip_context_trace = sip_context_trace_impl;

		/* set the global trace api for other modules/functions if loaded */
		if (tprot.get_trace_dest_by_name && !global_trace_api)
			global_trace_api = &tprot;
	}

	/* load the module dependencies, best effort for now, as the strict
	 * dependency will be checked later in fixup function, according to
	 * the sip_trace() flags */
	if (load_dlg_api(&dlgb) != 0)
		LM_DBG("failed to load the dialog API (dialog module not loaded?)\n");

	load_tm_api(&tmb);

	/* statelessly forwarded request callbacks */
	if (register_slcb(SLCB_REQUEST_OUT, FL_USE_SIPTRACE,
	trace_slreq_out) != 0) {
		LM_ERR("can't register callback for statelessly "
			"forwarded request\n");
		return -1;
	}

	if (register_slcb(SLCB_REPLY_OUT, FL_USE_SIPTRACE,
	trace_slreply_out) != 0) {
		LM_ERR("can't register callback for statelessly "
			"forwarded request\n");
		return -1;
	}

	/* FIXME find a way to pass the flags and the trace_info_p
	 * parameter if there's any*/
	#if 0
	if (register_slcb(SLCB_ACK_IN, 0, trace_slack_in) != 0) {
		LM_ERR("can't register callback for statelessly "
			"forwarded request\n");
		return -1;
	}
	#endif

	/* register the context index for the tracing context
	 * set a free function only if no TM, otherwise
	 * tm/dialog will free the structure */
	sl_ctx_idx=context_register_ptr(CONTEXT_GLOBAL,
			(tmb.t_gett==NULL)?free_trace_info_pkg:0);

	if (register_script_cb(process_dyn_tracing, PRE_SCRIPT_CB|REQ_TYPE_CB, 0)!=0) {
		LM_ERR("could not register request dynamic tracing callback\n");
		return -1;
	}

	return 0;
}

static int child_init(int rank)
{
	tlist_elem_p it;

	for (it=trace_list; it; it=it->next) {
		if (it->type == TYPE_DB) {
			LM_DBG("Initializing trace id [%.*s]\n",
					it->name.len, it->name.s);
			it->el.db->con = it->el.db->funcs.init(&it->el.db->url);
			if (!it->el.db->con) {
				LM_ERR("Unable to connect to database with url [%.*s]\n",
						it->el.db->url.len, it->el.db->url.s);
				return -1;
			}
		}
	}

	return 0;
}


static void destroy(void)
{
	tlist_elem_p el, last=NULL;

	el=trace_list;
	while (el) {
		if (last) {
			shm_free(last->traceable);
			pkg_free(last);
		}

		last=el;
		el=el->next;
	}

	if (last)

	if (trace_on_flag)
		shm_free(trace_on_flag);
	destroy_dyn_tracing();
}



static inline int insert_siptrace(st_db_struct_t *st_db,
		db_key_t *keys,db_val_t *vals, str *trace_attrs)
{
	if (trace_attrs) {
		db_vals[13].val.str_val = *trace_attrs;

		LM_DBG("storing info 14...\n");
	} else {
		db_vals[13].val.str_val.s   = "";
		db_vals[13].val.str_val.len = 0;
	}

	CON_PS_REFERENCE(st_db->con) = &siptrace_ps;
	if (con_set_inslist(&st_db->funcs,st_db->con,
						&st_db->ins_list,keys,NR_KEYS) < 0 )
		CON_RESET_INSLIST(st_db->con);
	if(st_db->funcs.insert(st_db->con, keys, vals, NR_KEYS) < 0) {
		LM_ERR("error storing trace\n");
		return -1;
	}


	return 0;
}


static int save_siptrace(struct sip_msg *msg, db_key_t *keys, db_val_t *vals,
				trace_instance_p info, int conn_id)
{
	unsigned int hash;

	tlist_elem_p it;

	if (!info || !info->trace_list) {
		LM_ERR("invalid trace info!\n");
		return -1;
	}

	/* makes sense only if trace protocol loaded */
	if ( tprot.send_message && !is_id_traced(sip_trace_id, info)) {
		return 1;
	}

	hash = info->trace_list->hash;
	/* check where the hash matches and take the proper action */
	for (it=info->trace_list; it && (it->hash == hash); it=it->next) {
		if (!it->dynamic) {
			if (!(*trace_on_flag) || !it->traceable || !(*it->traceable))
				continue;
		}

		switch (it->type) {
		case TYPE_HEP:
			if (send_trace_proto_duplicate(it->el.hep.hep_id,
					&msg->callid->body, info, conn_id) < 0) {
				LM_ERR("Failed to duplicate with hep to <%.*s:%u>\n",
						it->el.hep.hep_id->ip.len, it->el.hep.hep_id->ip.s,
						it->el.hep.hep_id->port_no);
				continue;
			}

			break;
		case TYPE_SIP:
			if (trace_send_duplicate(db_vals[0].val.str_val.s,
					db_vals[0].val.str_val.len, &it->el.uri) < 0) {
				LM_ERR("Faield to duplicate with sip to <%.*s:%.*s>\n",
						it->el.uri.host.len, it->el.uri.host.s,
						it->el.uri.port.len, it->el.uri.port.s);
				continue;
			}

			break;
		case TYPE_DB:
			it->el.db->funcs.use_table(it->el.db->con,
										&it->el.db->table);

			if (insert_siptrace(it->el.db, keys, vals, info->trace_attrs) < 0) {
				LM_ERR("failed to insert in DB!\n");
				return -1;
			}

			break;
		default:
			LM_ERR("invalid type!\n");
			return -1;
		}
	}

	return 0;
}

static void trace_transaction_dlgcb(struct dlg_cell* dlg, int type,
		struct dlg_cb_params * params)
{
	trace_info_p info = (trace_info_p)*params->param;

	TRACE_FLAG_UNSET(info, TRACE_INFO_TRAN);

	if (trace_transaction(params->msg, info, 1)<0) {
		LM_ERR("trace transaction failed!\n");
		return;
	}

	info->conn_id = params->msg->rcv.proto_reserved1;
	sip_trace(params->msg, info);
}

void free_trace_info_pkg(void *param)
{
	trace_info_p info = (trace_info_p)param;
	trace_instance_p it, next;

	for (it = info->instances; it; it = next) {
		next = it->next;
		if (it->trace_list->dynamic)
			trace_id_unref(it->trace_list);
		pkg_free(it);
	}
	pkg_free(param);
}

void free_trace_info_shm(void *param)
{
	trace_info_p info = (trace_info_p)param;
	trace_instance_p it, next;

	for (it = info->instances; it; it = next) {
		next = it->next;
		if (it->trace_list->dynamic)
			trace_id_unref(it->trace_list);
		shm_free(it);
	}
	shm_free(param);
}

static int trace_transaction(struct sip_msg* msg, trace_info_p info,
								char dlg_tran)
{
	if (msg==NULL)
		return 0;

	/* context for the request message */
	SET_TRACER_CONTEXT(info);

	/* CANCEL forms a separate transaction, so it ok to install the
	 * callback again. */
	if (msg->REQ_METHOD!=METHOD_CANCEL &&
	TRACE_FLAG_ISSET(info, TRACE_INFO_TRAN)) {
		LM_DBG("transaction callbacks already registered!\n");
		return 0;
	}

	/* allows catching statelessly forwarded ACK in stateful transactions
	 * and stateless replies */
	msg->msg_flags |= FL_USE_SIPTRACE;

	if(tmb.register_tmcb( msg, 0, TMCB_MSG_MATCHED_IN, trace_tm_in, info, 0) <=0) {
		LM_ERR("can't register TM MATCH IN callback\n");
		return -1;
	}

	if(tmb.register_tmcb( msg, 0, TMCB_MSG_SENT_OUT, trace_tm_out,
			info, dlg_tran?0:free_trace_info_shm) <=0) {
		LM_ERR("can't register TM SEND OUT callback\n");
		return -1;
	}

	TRACE_FLAG_SET(info, TRACE_INFO_TRAN);
	return 0;
}

static int trace_dialog(struct sip_msg *msg, trace_info_p info)
{
	struct dlg_cell* dlg;

	/* only register if callbacks were not previously registered */
	if (TRACE_FLAG_ISSET(info, TRACE_INFO_DIALOG)) {
		LM_DBG("dialog callbacks already registered!\n");
		return 0;
	}

	if (!dlgb.create_dlg || ! dlgb.get_dlg) {
		LM_ERR("Can't trace dialog!Api not loaded!\n");
		return -1;
	}

	if (dlgb.create_dlg(msg, 0)<1) {
		LM_ERR("faield to create dialog!\n");
		return -1;
	}

	dlg=dlgb.get_dlg();
	if (dlg==NULL) {
		LM_CRIT("BUG: no dialog found after create dialog\n");
		return -1;
	}

	/* dialog callbacks */
	if(dlgb.register_dlgcb(dlg, DLGCB_REQ_WITHIN,
							trace_transaction_dlgcb,info,0)!=0) {
		LM_ERR("failed to register dialog callback\n");
		return -1;
	}

	/* here also free trace info param because we are sure that
	 * this callback is ran only once - when dialog gets for
	 * the first time in DELETED state */
	if(dlgb.register_dlgcb(dlg,DLGCB_TERMINATED,
				trace_transaction_dlgcb,info,free_trace_info_shm)!=0) {
		LM_ERR("failed to register dialog callback\n");
		return -1;
	}

	/* also trace this transaction */
	if (trace_transaction(msg, info, 1) < 0) {
		LM_ERR("failed to trace initial INVITE transaction!\n");
		return -1;
	}

	if ( tmb.register_tmcb( msg, NULL,TMCB_TRANS_CANCELLED,
				siptrace_dlg_cancel, info, NULL)<0 ) {
		LM_ERR("failed to register trans cancelled TMCB\n");
		return -1;
	}

	TRACE_FLAG_SET(info, TRACE_INFO_DIALOG);
	return 0;
}



static void siptrace_dlg_cancel(struct cell* t, int type, struct tmcb_params *param)
{
	struct sip_msg *req;
	trace_info_t info;

	req = param->req;

	LM_DBG("Tracing incoming cancel due to trace_dialog() \n");

	if (trace_transaction(req, *param->param, 1) < 0) {
		LM_ERR("trace transaction failed!\n");
		return;
	}

	info = *(trace_info_p)(*param->param);
	if ( req->rcv.proto != PROTO_UDP ) {
		info.conn_id = req->rcv.proto_reserved1;
	} else {
		info.conn_id = 0;
	}

	/* trace current request */
	sip_trace(req, &info);
}


/*
* the topmost flag shall be kept: if both dialog and transaction
* flags are set, dialog capture shall be done
*/
static int st_parse_flags(str *sflags)
{
	int p;
	int flags=0;

	for (p=0; p<sflags->len; p++) {
		switch(sflags->s[p]) {
			case 'm':
			case 'M':
				if (flags)
					continue;

				flags = TRACE_MESSAGE;
				break;
			case 't':
			case 'T':
				if (flags == TRACE_DIALOG)
					continue;

				flags = TRACE_TRANSACTION;
				break;
			case 'd':
			case 'D':
				flags = TRACE_DIALOG;
				break;
			case ' ':
				continue;
			default:
				LM_ERR("invalid character <%c> in"
						" sip_trace() flags definition", sflags->s[p]);
				return -1;
		}
	}

	return flags;
}

int st_parse_types(str* stypes_p)
{
	str tok, stypes;
	int have_next=1, i, ret=0;
	char* end;
	const struct trace_proto* traced_protos;
	static const char type_delim = '|';

	traced_protos = get_traced_protos();
	stypes = *stypes_p;

	while (have_next) {
		end=q_memchr(stypes.s, type_delim, stypes.len);
		if (end==NULL) {
			have_next = 0;
			tok.len = stypes.len;
		} else {
			tok.len = end - stypes.s;
		}

		tok.s = stypes.s;

		stypes.len -= tok.len + 1/* delimiter */;
		stypes.s = end + 1;

		str_trim_spaces_lr(tok);

		for (i=0; i<get_traced_protos_no(); i++) {
			if (!strncmp(tok.s, traced_protos[i].proto_name,
								strlen(traced_protos[i].proto_name))) {
				ret |= (1<<i);
				break;
			}
		}
		if (i==get_traced_protos_no()) {
			/* the trace type was not found */
			LM_WARN("trace type [%.*s] wasn't defined, ignoring...\n",
				tok.len, tok.s);
		}
	}

	return ret;
}


static tlist_elem_p get_list_start(tlist_elem_p list, str *name)
{
	unsigned int hash;
	tlist_elem_p it;

	if (name==NULL)
		return NULL;

	hash = core_hash(name, NULL, 0);
	for (it=list; it; it=it->next)
		if (hash==it->hash)
			return it;

	return NULL;
}


static int fixup_tid(void **param)
{
	tlist_elem_p tid;

	tid = get_list_start(trace_list, (str*)*param);
	if ( tid == NULL) {
		LM_ERR("Trace id <%.*s> used in sip_trace() function "
			"not defined!\n", ((str*)*param)->len, ((str*)*param)->s);
		return -1;
	}
	*param = (void*)tid;

	return 0;
}

static int fixup_sflags(void **param)
{
	int _flags;

	if ((_flags=st_parse_flags((str*)*param)) < 0) {
		LM_ERR("flag parsing failed!\n");
		return -1;
	}

	if (_flags==TRACE_DIALOG) {
		if (dlgb.create_dlg==NULL) {
			LM_ERR("Dialog tracing explicitly required, but"
				"dialog module not loaded\n");
			return -1;
		}
	}else
	if (_flags==TRACE_TRANSACTION) {
		if (tmb.t_gett==NULL) {
			LM_INFO("Will do stateless transaction aware tracing!\n");
			LM_INFO("tracer will catch internally generated replies"
					" and forwarded requests!\n");
		}
	}

	*param = (void *)((unsigned long)_flags);

	return 0;
}

int trace_has_totag(struct sip_msg* _m)
{
	str tag;

	if (!_m->to && parse_headers(_m, HDR_TO_F,0)==-1) {
		LM_ERR("To parsing failed\n");
		return 0;
	}
	if (!_m->to) {
		LM_ERR("no To\n");
		return 0;
	}
	tag=get_to(_m)->tag_value;
	if (tag.s==0 || tag.len==0) {
		LM_DBG("no totag\n");
		return 0;
	}
	LM_DBG("totag found\n");
	return 1;
}

static int sip_trace_handle(struct sip_msg *msg, tlist_elem_p el,
		int trace_types, int trace_flags, str *trace_attrs)
{
	int extra_len=0;
	trace_info_p info=NULL;
	trace_info_t stack_info;
	trace_instance_t stack_instance;
	trace_instance_p instance=NULL;

	if (trace_attrs != NULL)
		extra_len = sizeof(str) + trace_attrs->len;

	if (trace_flags == TRACE_MESSAGE) {
		/* we don't need to allocate this structure since it will only be
		 * used in this function's context */
		instance = &stack_instance;

		memset(instance, 0, sizeof(trace_instance_t));
		if (extra_len) {
			instance->trace_attrs = trace_attrs;
		}
	} else if (!current_processing_ctx) {
		LM_BUG("sip_trace() failed due to NULL context");
		return -1;

	/* for stateful transactions or dialogs
	 * we need the structure in the shared memory */
	} else if(trace_flags == TRACE_DIALOG ||
	(trace_flags == TRACE_TRANSACTION && tmb.t_gett)) {
		instance=shm_malloc(sizeof(trace_instance_t) + extra_len);
		if (instance==NULL) {
			LM_ERR("no more shm!\n");
			return -1;
		}

		memset(instance, 0, sizeof(*instance) + extra_len);

		if (extra_len) {
			instance->trace_attrs = (str*)(instance+1);
			instance->trace_attrs->s = (char*)(instance->trace_attrs+1);

			memcpy(instance->trace_attrs->s, trace_attrs->s, trace_attrs->len);
			instance->trace_attrs->len = trace_attrs->len;
		}
	} else if (trace_flags == TRACE_TRANSACTION && tmb.t_gett==NULL) {
		/* we need this structure in pkg for stateless replies
		 * and request out callback */
		instance=pkg_malloc(sizeof(trace_instance_t));
		if (instance==NULL) {
			LM_ERR("no more pkg!\n");
			return -1;
		}

		memset(instance, 0, sizeof(trace_instance_t));
		if (extra_len)
			instance->trace_attrs = trace_attrs;
	} else {
		LM_ERR("Unknown trace flags %x\n", trace_flags);
		return -2;
	}

	instance->trace_list=el;
	instance->trace_types = trace_types;

	if (trace_flags != TRACE_MESSAGE) {
		info = GET_TRACER_CONTEXT;
		if (info) {
			instance->next = info->instances;
			info->instances = instance;
		} else {
			if (trace_flags == TRACE_TRANSACTION && tmb.t_gett==NULL) {
				info = pkg_malloc(sizeof(trace_info_t));
				if (!info) {
					LM_INFO("cannot allocate info!\n");
					pkg_free(instance);
					return -1;
				}
			} else {
				info = shm_malloc(sizeof(trace_info_t));
				if (!info) {
					LM_INFO("cannot allocate info!\n");
					shm_free(instance);
					return -1;
				}
			}
			memset(info, 0, sizeof(trace_info_t));
			SET_TRACER_CONTEXT(info);
			info->instances = instance;
		}
		/* this flag here will help catching
		 * stateless replies(sl_send_reply(...))*/
		msg->msg_flags |= FL_USE_SIPTRACE;
	} else {
		info = &stack_info;
		memset(&stack_info, 0, sizeof(stack_info));
		info->instances = instance;
	}

	if (trace_flags==TRACE_DIALOG) {
		if (trace_dialog(msg, info) < 0) {
			LM_ERR("trace dialog failed!\n");
			return -1;
		}
	} else if (trace_flags==TRACE_TRANSACTION) {
		if (trace_transaction(msg, info, 0) < 0) {
			LM_ERR("trace transaction failed!\n");
			return -1;
		}
	}


	/* we're safe; nobody will be in conflict with this conn id
	 * since everybody else will have a local copy of this structure */
	if ( msg->rcv.proto != PROTO_UDP ) {
		info->conn_id = msg->rcv.proto_reserved1;
	} else {
		info->conn_id = 0;
	}

	/* trace the current message only if:
	 *  (a) per-message tracing was requests
	 *  or
	 *  (b) we are not in LOCAL route (UAC trans do not have IN msg) */
	if (trace_flags == TRACE_MESSAGE || route_type != LOCAL_ROUTE) {
		if (sip_trace_instance(msg, instance, info->conn_id) < 0) {
			LM_ERR("sip trace failed!\n");
			return -1;
		}
	}

#ifdef STATISTICS
	if (!TRACE_FLAG_ISSET(info, TRACE_INFO_STAT)) {
		TRACE_FLAG_SET(info, TRACE_INFO_STAT);
		update_stat(siptrace_req, 1);
	}
#endif

	return 1;
}


/* tracer wrapper that verifies if the trace is on */
static int trace_w(struct sip_msg *msg, tlist_elem_p list,
					void *scope_p, str *trace_types_s, str *trace_attrs)
{

	int trace_flags;
	int trace_types=0;

	if(msg==NULL)
	{
		LM_DBG("no uas request, local transaction\n");
		return -1;
	}

	if (scope_p != NULL) {
		trace_flags = (int)((unsigned long)scope_p);
	} else {
		/* we use the topmost flag; if dialogs available trace dialog etc. */
		/* for dialogs check for dialog api and whether it is an initial
		 * INVITE; else we degrade the flag */
		if (dlgb.get_dlg && msg->first_line.type == SIP_REQUEST &&
				msg->REQ_METHOD == METHOD_INVITE ) {
			trace_flags=TRACE_DIALOG;
		} else {
			trace_flags=TRACE_TRANSACTION;
		}
	}

	if (trace_flags == TRACE_DIALOG &&
			dlgb.get_dlg && msg->first_line.type == SIP_REQUEST &&
			msg->REQ_METHOD == METHOD_INVITE && !trace_has_totag(msg)) {
		LM_DBG("tracing dialog!\n");
	} else if (trace_flags == TRACE_DIALOG) {
		LM_DBG("can't trace dialog! Will try to trace transaction\n");
		trace_flags = TRACE_TRANSACTION;
	}

	if (trace_flags == TRACE_TRANSACTION &&
	msg->first_line.type == SIP_REQUEST) {
		LM_DBG("tracing transaction!\n");
	} else if (trace_flags == TRACE_TRANSACTION) {
		LM_DBG("can't trace transaction! Will trace only this message!\n");
		trace_flags = TRACE_MESSAGE;
	}

	/* parse trace types */
	/* this makes sense only if trace protocol is loaded */
	if ( tprot.send_message && trace_types_s != NULL) {
		trace_types = st_parse_types(trace_types_s);
		if (trace_types == 0) {
			LM_DBG("no types to be traced, abording!\n");
			return -1;
		}
	} else {
		/* if no flags defined at least sip type of tracing shall be made
		 * else the function will be useless */
		trace_types = sip_trace_id;
	}
	return sip_trace_handle(msg, list, trace_types, trace_flags, trace_attrs);
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
		_col_proto.val.str_val = trace_local_proto; \
		_col_ip.val.str_val = trace_local_ip; \
		_col_port.val.int_val = trace_local_port; \
	} while (0)



static int sip_trace(struct sip_msg *msg, trace_info_p info)
{
	static char toip_buff[IP_ADDR_MAX_STR_SIZE+6];
	static char fromip_buff[IP_ADDR_MAX_STR_SIZE+6];
	trace_instance_p instance;

	if(parse_from_header(msg)==-1 || msg->from==NULL || get_from(msg)==NULL)
	{
		LM_ERR("cannot parse FROM header\n");
		goto error;
	}

	if(parse_headers(msg, HDR_CALLID_F, 0)!=0)
	{
		LM_ERR("cannot parse call-id\n");
		goto error;
	}

	if(msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("cannot find Call-ID header!\n");
		goto error;
	}

	LM_DBG("sip_trace called \n");
	db_vals[0].val.str_val.s = msg->buf;
	db_vals[0].val.str_val.len = msg->len;

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

	for (instance = info->instances; instance; instance = instance->next) {
		if (save_siptrace(msg, db_keys,db_vals, instance, info->conn_id) < 0) {
			LM_ERR("failed to save tracer\n");
			goto error;
		}
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

static int sip_trace_instance(struct sip_msg* msg,
		trace_instance_p instance, int conn_id)
{
	static char toip_buff[IP_ADDR_MAX_STR_SIZE+6];
	static char fromip_buff[IP_ADDR_MAX_STR_SIZE+6];

	if(parse_from_header(msg)==-1 || msg->from==NULL || get_from(msg)==NULL)
	{
		LM_ERR("cannot parse FROM header\n");
		goto error;
	}

	if(parse_headers(msg, HDR_CALLID_F, 0)!=0)
	{
		LM_ERR("cannot parse call-id\n");
		goto error;
	}

	if(msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("cannot find Call-ID header!\n");
		goto error;
	}

	LM_DBG("sip_trace called \n");
	db_vals[0].val.str_val.s = msg->buf;
	db_vals[0].val.str_val.len = msg->len;

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

	if (save_siptrace(msg, db_keys,db_vals, instance, conn_id) < 0) {
		LM_ERR("failed to save tracer\n");
		goto error;
	}

	return 1;
error:
	return -1;
}

static void trace_onreq_out(struct cell* t, int type, struct tmcb_params *ps)
{
	trace_info_t info;
	struct dest_info* dest;

	if(t==NULL || ps==NULL) {
		LM_DBG("no uas request, local transaction\n");
		return;
	}

	if(ps->req==NULL) {
		LM_DBG("no uas msg, local transaction\n");
		return;
	}

	LM_DBG("trace on req out \n");
	/* we do this little trick in order to have the info on the stack, not
	 * shared to avoid conflicts on conn_id field */
	info = *(trace_info_p)(*ps->param);
	dest = ps->extra2;

	if (current_processing_ctx)
		SET_TRACER_CONTEXT(*ps->param);

	if (dest) {
		if ( dest->proto != PROTO_UDP ) {
			info.conn_id = last_outgoing_tcp_id;
		} else {
			info.conn_id = 0;
		}

		trace_msg_out( ps->req, (str*)ps->extra1,
			dest->send_sock,
			dest->proto,
			&dest->to,
			&info);
	} else {
		info.conn_id = 0;
		trace_msg_out( ps->req, (str*)ps->extra1,
			NULL, PROTO_NONE, NULL, &info);
	}

}

static void trace_slreq_out(struct sip_msg* req, str *buffer,int rpl_code,
				union sockaddr_union *to, struct socket_info *sock, int proto)
{
	trace_info_p info;

	info = GET_TRACER_CONTEXT;

	trace_msg_out(req, buffer, sock, proto, to, info);
}

static void trace_slreply_out(struct sip_msg* req, str *buffer,int rpl_code,
				union sockaddr_union *dst, struct socket_info *sock, int proto)
{
	static char fromip_buff[IP_ADDR_MAX_STR_SIZE+12];
	static char toip_buff[IP_ADDR_MAX_STR_SIZE+12];

	struct ip_addr to_ip;
	int len;
	char statusbuf[INT2STR_MAX_LEN];

	trace_info_p info;
	trace_instance_p instance;

	info = GET_TRACER_CONTEXT;
	if (info == NULL) {
		LM_DBG("no sip_trace() done so far\n");
		return;
	}

	if(parse_from_header(req)==-1 || req->from==NULL || get_from(req)==NULL)
	{
		LM_ERR("cannot parse FROM header\n");
		goto error;
	}

	if(parse_headers(req, HDR_CALLID_F, 0)!=0)
	{
		LM_ERR("cannot parse call-id\n");
		return;
	}

	db_vals[0].val.str_val.s   = (buffer)?buffer->s:"";
	db_vals[0].val.str_val.len = (buffer)?buffer->len:0;

	/* check Call-ID header */
	if(req->callid==NULL || req->callid->body.s==NULL)
	{
		LM_ERR("cannot find Call-ID header!\n");
		goto error;
	}

	db_vals[1].val.str_val.s = req->callid->body.s;
	db_vals[1].val.str_val.len = req->callid->body.len;

	db_vals[2].val.str_val.s = req->first_line.u.request.method.s;
	db_vals[2].val.str_val.len = req->first_line.u.request.method.len;

	if(trace_local_ip.s && trace_local_ip.len > 0){
		set_columns_to_trace_local_ip( db_vals[4], db_vals[5], db_vals[6]);
	} else {
		set_sock_columns( db_vals[4], db_vals[5], db_vals[6], fromip_buff,
		&req->rcv.dst_ip, req->rcv.dst_port, req->rcv.proto);
	}

	char * str_code = int2str(rpl_code, &len);
	statusbuf[INT2STR_MAX_LEN-1]=0;
	strncpy(statusbuf, str_code, len >= INT2STR_MAX_LEN ? INT2STR_MAX_LEN-1 : len);
	db_vals[3].val.str_val.s = statusbuf;
	db_vals[3].val.str_val.len = len;
	memset(&to_ip, 0, sizeof(struct ip_addr));
	if(dst==0)
	{
		set_columns_to_any(db_vals[7], db_vals[8], db_vals[9]);
	} else {
		su2ip_addr(&to_ip, dst);
		set_sock_columns( db_vals[7], db_vals[8],db_vals[9], toip_buff, &to_ip,
		(unsigned short)su_getport(dst), req->rcv.proto);
	}

	db_vals[10].val.time_val = time(NULL);

	db_vals[11].val.string_val = "out";

	db_vals[12].val.str_val.s = get_from(req)->tag_value.s;
	db_vals[12].val.str_val.len = get_from(req)->tag_value.len;

	for (instance = info->instances; instance; instance = instance->next) {
		if (save_siptrace(req,db_keys,db_vals, instance, info->conn_id) < 0) {
			LM_ERR("failed to save siptrace\n");
			goto error;
		}
	}
#ifdef STATISTICS
	update_stat(siptrace_rpl, 1);
#endif
	return;
error:
	return;
}

/* FIXME can't get the trace info here */
#if 0
static void trace_slack_in(struct sip_msg* req, str *buffer,int rpl_code,
				union sockaddr_union *dst, struct socket_info *sock, int proto)
{
	/* FIXME How can we pass the trace info structure here ???? */
	// sip_trace(req, NULL);
}
#endif

static void trace_msg_out(struct sip_msg* msg, str  *sbuf,
		struct socket_info* send_sock, int proto, union sockaddr_union *to,
		trace_info_p info)
{
	static char fromip_buff[IP_ADDR_MAX_STR_SIZE+12];
	static char toip_buff[IP_ADDR_MAX_STR_SIZE+12];
	struct ip_addr to_ip;
	trace_instance_p instance;

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
		db_vals[0].val.str_val.s   = sbuf->s;
		db_vals[0].val.str_val.len = sbuf->len;
	} else {
		db_vals[0].val.str_val.s   = "No request buffer";
		db_vals[0].val.str_val.len = sizeof("No request buffer")-1;
	}

	/* check Call-ID header */
	if(msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("cannot find Call-ID header!\n");
		goto error;
	}

	db_vals[1].val.str_val.s = msg->callid->body.s;
	db_vals[1].val.str_val.len = msg->callid->body.len;

	if(sbuf!=NULL && sbuf->len > 7 && !strncasecmp(sbuf->s, "CANCEL ", 7)){
		db_vals[2].val.str_val.s = "CANCEL";
		db_vals[2].val.str_val.len = 6;
	} else
	if(sbuf!=NULL && sbuf->len > 4 && !strncasecmp(sbuf->s, "ACK ", 4)){
		db_vals[2].val.str_val.s = "ACK";
		db_vals[2].val.str_val.len = 3;
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
			db_vals[6].val.int_val = send_sock->last_local_real_port?
				send_sock->last_local_real_port:send_sock->port_no;
		}
	}

	if(to==0)
	{
		set_columns_to_any(db_vals[7], db_vals[8], db_vals[9]);
	} else {
		su2ip_addr(&to_ip, to);
		set_sock_columns( db_vals[7], db_vals[8], db_vals[9], toip_buff,
			&to_ip,
			(unsigned long)(send_sock->last_remote_real_port?
				send_sock->last_remote_real_port:su_getport(to)),
			proto);
	}

	db_vals[10].val.time_val = time(NULL);

	db_vals[11].val.string_val = "out";

	db_vals[12].val.str_val.s = get_from(msg)->tag_value.s;
	db_vals[12].val.str_val.len = get_from(msg)->tag_value.len;

	for (instance = info->instances; instance; instance = instance->next) {
		if (save_siptrace(msg, db_keys,db_vals, instance, info->conn_id) < 0) {
			LM_ERR("failed to save siptrace\n");
			goto error;
		}
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
	char statusbuf[INT2STR_MAX_LEN];
	int len;
	trace_instance_p instance;
	trace_info_t info;

	if(t==NULL || t->uas.request==0 || ps==NULL)
	{
		LM_DBG("no uas request, local transaction\n");
		return;
	}

	/* context for replies */
	SET_TRACER_CONTEXT((trace_info_p)(*ps->param));

	msg = ps->rpl;

	/* we do this little trick in order to have the info on the stack, not
	 * shared to avoid conflicts on conn_id field */
	info = *(trace_info_p)(*ps->param);
	if ( msg->rcv.proto != PROTO_UDP ) {
		info.conn_id = msg->rcv.proto_reserved1;
	} else {
		info.conn_id = 0;
	}

	LM_DBG("trace onreply in \n");

	if(parse_from_header(msg)==-1 || msg->from==NULL || get_from(msg)==NULL)
	{
		LM_ERR("cannot parse FROM header\n");
		goto error;
	}

	if(parse_headers(msg, HDR_CALLID_F|HDR_CSEQ_F, 0)!=0)
	{
		LM_ERR("cannot parse Call-ID/CSeq\n");
		return;
	}

	if(msg->len>0) {
		db_vals[0].val.str_val.s   = msg->buf;
		db_vals[0].val.str_val.len = msg->len;
	} else {
		db_vals[0].val.str_val.s   = "No reply buffer";
		db_vals[0].val.str_val.len = sizeof("No reply buffer")-1;
	}

	/* check Call-ID header */
	if(msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("cannot find Call-ID header!\n");
		goto error;
	}

	if(msg->cseq==NULL)
	{
		LM_ERR("cannot find CSeq header!\n");
		goto error;
	}

	db_vals[1].val.str_val = msg->callid->body;

	db_vals[2].val.str_val= get_cseq(msg)->method;

	char * str_code = int2str(ps->code, &len);
	statusbuf[INT2STR_MAX_LEN-1]=0;
	strncpy(statusbuf, str_code, len >= INT2STR_MAX_LEN ? INT2STR_MAX_LEN-1 : len);
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

	for (instance = info.instances; instance; instance = instance->next) {
		if (save_siptrace(msg, db_keys,db_vals, instance, info.conn_id) < 0) {
			LM_ERR("failed to save siptrace\n");
			goto error;
		}
	}

#ifdef STATISTICS
	update_stat(siptrace_rpl, 1);
#endif
	return;
error:
	return;
}


static void trace_tm_in(struct cell* t, int type, struct tmcb_params *ps)
{
	LM_DBG("TM in triggered req=%p, rpl=%p\n",ps->req,ps->rpl);
	if (ps->req) {
		/* an incoming request: a retransmission or hop-by-hop ACK */
		sip_trace( ps->req,  (trace_info_p)(*ps->param) );
	} else if (ps->rpl) {
		/* an incoming reply for us or for a CANCEL */
		trace_onreply_in( t, type, ps);
	}
}


static void trace_onreply_out(struct cell* t, int type, struct tmcb_params *ps)
{
	int faked = 0;
	static char fromip_buff[IP_ADDR_MAX_STR_SIZE+12];
	static char toip_buff[IP_ADDR_MAX_STR_SIZE+12];
	trace_instance_p instance;
	struct sip_msg* msg;
	struct ip_addr to_ip;
	int len;
	char statusbuf[8];
	str *sbuf;
	struct dest_info *dst;

	trace_info_t info;

	if (t==NULL || t->uas.request==0 || ps==NULL)
	{
		LM_DBG("no uas request, local transaction\n");
		return;
	}

	LM_DBG("trace onreply out \n");

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

	if(msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("cannot find Call-ID header!\n");
		goto error;
	}

	sbuf = (str*)ps->extra1;
	if(faked==0)
	{
		if(sbuf!=0 && sbuf->len>0) {
			db_vals[0].val.str_val.s   = sbuf->s;
			db_vals[0].val.str_val.len = sbuf->len;
		} else if(t->uas.response.buffer.s!=NULL) {
			db_vals[0].val.str_val.s   = t->uas.response.buffer.s;
			db_vals[0].val.str_val.len = t->uas.response.buffer.len;
		} else if(msg->len>0) {
			db_vals[0].val.str_val.s   = msg->buf;
			db_vals[0].val.str_val.len = msg->len;
		} else {
			db_vals[0].val.str_val.s   = "No reply buffer";
			db_vals[0].val.str_val.len = sizeof("No reply buffer")-1;
		}
	} else {
		if(sbuf!=0 && sbuf->len>0) {
			db_vals[0].val.str_val.s   = sbuf->s;
			db_vals[0].val.str_val.len = sbuf->len;
		} else if(t->uas.response.buffer.s==NULL) {
			db_vals[0].val.str_val.s = "No reply buffer";
			db_vals[0].val.str_val.len = sizeof("No reply buffer")-1;
		} else {
			db_vals[0].val.str_val.s = t->uas.response.buffer.s;
			db_vals[0].val.str_val.len = t->uas.response.buffer.len;
		}
	}

	db_vals[1].val.str_val.s = msg->callid->body.s;
	db_vals[1].val.str_val.len = msg->callid->body.len;

	db_vals[2].val.str_val.s = t->method.s;
	db_vals[2].val.str_val.len = t->method.len;

	strcpy(statusbuf, int2str(ps->code, &len));
	db_vals[3].val.str_val.s = statusbuf;
	db_vals[3].val.str_val.len = len;

	dst = (struct dest_info*)ps->extra2;
	/* we do this little trick in order to have the info on the stack, not
	 * shared to avoid conflicts on conn_id field */
	info = *(trace_info_p)(*ps->param);
	if ( dst == NULL ) {
		info.conn_id = 0;
	} else {
		if ( dst->proto != PROTO_UDP ) {
			info.conn_id = dst->proto_reserved1;
		} else {
			info.conn_id = 0;
		}
	}

	if (trace_local_ip.s && trace_local_ip.len > 0){
		set_columns_to_trace_local_ip( db_vals[4], db_vals[5], db_vals[6]);
	}
	else {
		if(dst==NULL || dst->send_sock==0 || dst->send_sock->sock_str.s==0)
		{
			set_sock_columns( db_vals[4], db_vals[5], db_vals[6], fromip_buff,
					&msg->rcv.dst_ip, msg->rcv.dst_port, msg->rcv.proto);
		} else {
			char *nbuff = proto2str(dst->send_sock->proto,fromip_buff);
			db_vals[4].val.str_val.s = fromip_buff;
			db_vals[4].val.str_val.len = nbuff - fromip_buff;
			db_vals[5].val.str_val = dst->send_sock->address_str;
			db_vals[6].val.int_val = dst->send_sock->last_local_real_port?
				dst->send_sock->last_local_real_port:dst->send_sock->port_no;
		}
	}

	if(dst==0)
	{
		set_columns_to_any( db_vals[7], db_vals[8], db_vals[9]);
	} else {
		memset(&to_ip, 0, sizeof(struct ip_addr));
		su2ip_addr(&to_ip, &dst->to);
		set_sock_columns( db_vals[7], db_vals[8], db_vals[9], toip_buff,
			&to_ip,
			(unsigned long)(dst->send_sock->last_remote_real_port?
				dst->send_sock->last_remote_real_port:su_getport(&dst->to)),
			dst->proto);
	}

	db_vals[10].val.time_val = time(NULL);

	db_vals[11].val.string_val = "out";

	db_vals[12].val.str_val.s = get_from(msg)->tag_value.s;
	db_vals[12].val.str_val.len = get_from(msg)->tag_value.len;

	for (instance = info.instances; instance; instance = instance->next) {
		if (save_siptrace(msg, db_keys,db_vals, instance, info.conn_id) < 0) {
			LM_ERR("failed to save siptrace\n");
			goto error;
		}
	}

#ifdef STATISTICS
	update_stat(siptrace_rpl, 1);
#endif
	return;
error:
	return;
}


static void trace_tm_out(struct cell* t, int type, struct tmcb_params *ps)
{
	LM_DBG("TM out triggered req=%p, rpl=%p\n",ps->req,ps->rpl);
	if (ps->req) {
		/* an outgoing request: request itself, local CANCEL or local ACK */
		trace_onreq_out( t, type, ps);
	} else if (ps->rpl) {
		/* an outpoing reply (local or relaied) */
		trace_onreply_out( t, type, ps);
	}
}

static int mi_tid_dyn_filters(tlist_dyn_elem_p tid_el, mi_item_t *dest_item)
{
	mi_item_t *filters_arr, *obj;
	struct trace_filter *filter;
	char *msg;

	if (!tid_el->filters)
		return 0;

	filters_arr = add_mi_array(dest_item, MI_SSTR("filters"));
	if (!filters_arr) {
		LM_INFO("could not create array!\n");
		return -1;
	}
	for (filter = tid_el->filters; filter; filter = filter->next) {
		switch (filter->type) {
			case TRACE_FILTER_IP:
				msg = "ip";
				break;
			case TRACE_FILTER_CALLER:
				msg = "caller";
				break;
			case TRACE_FILTER_CALLEE:
				msg = "callee";
				break;
			default:
				/* Invalid */
				return -1;
		}
		obj = add_mi_object(filters_arr, NULL, 0);
		if (!obj) {
			LM_ERR("could not create new MI object!\n");
			return -1;
		}
		if (add_mi_string(obj, msg, strlen(msg),
					filter->match.s, filter->match.len) < 0) {
			LM_ERR("could not create new string object!\n");
			return -1;
		}
	}
	return 0;
}

static int mi_tid_info(tlist_elem_p tid_el, mi_item_t *dests_arr)
{
	mi_item_t *dest_item;

	dest_item = add_mi_object(dests_arr, NULL, 0);
	if (!dest_item)
		return -1;

	if (add_mi_string(dest_item, MI_SSTR("name"),
		tid_el->name.s, tid_el->name.len) < 0)
		return -1;

	if (tid_el->type == TYPE_HEP) {
		if (add_mi_string(dest_item, MI_SSTR("type"), MI_SSTR("HEP")) < 0)
			return -1;
		if (add_mi_string_fmt(dest_item, MI_SSTR("uri"), "%.*s:%.*s",
			tid_el->el.hep.hep_id->ip.len, tid_el->el.hep.hep_id->ip.s,
			tid_el->el.hep.hep_id->port.len, tid_el->el.hep.hep_id->port.s) < 0)
			return -1;
	} else if (tid_el->type == TYPE_SIP) {
		if (add_mi_string(dest_item, MI_SSTR("type"), MI_SSTR("SIP")) < 0)
			return -1;
		if (add_mi_string_fmt(dest_item, MI_SSTR("uri"), "%.*s:%.*s",
			tid_el->el.uri.host.len, tid_el->el.uri.host.s,
			tid_el->el.uri.port.len, tid_el->el.uri.port.s) < 0)
			return -1;
	} else if (tid_el->type == TYPE_DB) {
		if (add_mi_string(dest_item, MI_SSTR("type"), MI_SSTR("Database")) < 0)
			return -1;
		if (add_mi_string(dest_item, MI_SSTR("uri"),
			tid_el->el.db->url.s, tid_el->el.db->url.len) < 0)
			return -1;
	}

	if (tid_el->dynamic) {
		if (add_mi_string(dest_item, MI_SSTR("state"), MI_SSTR("dynamic")) < 0)
			return -1;
		/* if dynamic, we might need information about the filters */
		if (mi_tid_dyn_filters(trace_id_dyn(tid_el), dest_item) < 0)
			return -1;
	} else if (tid_el->traceable && *tid_el->traceable) {
		if (add_mi_string(dest_item, MI_SSTR("state"), MI_SSTR("on")) < 0)
			return -1;
	} else {
		if (add_mi_string(dest_item, MI_SSTR("state"), MI_SSTR("off")) < 0)
			return -1;
	}

	return 0;
}

static mi_response_t *sip_trace_mi(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *dests_arr;
	tlist_elem_p it;

	if (trace_on_flag==NULL)
		return init_mi_error(500, MI_SSTR("Internal error"));

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if ( *trace_on_flag ) {
		if (add_mi_string(resp_obj, MI_SSTR("global"), MI_SSTR("on")) < 0) {
			goto error;
		}
	} else {
		if (add_mi_string(resp_obj, MI_SSTR("global"), MI_SSTR("off")) < 0) {
			goto error;
		}
	}

	dests_arr = add_mi_array(resp_obj, MI_SSTR("trace destinations"));
	if (!dests_arr)
		goto error;

	for (it=trace_list;it;it=it->next)
		if (mi_tid_info(it, dests_arr) < 0)
			goto error;

	if (!dyn_trace_list)
		return resp;

	lock_get(dyn_trace_lock);
	for (it=(tlist_elem_p)(*dyn_trace_list); it; it = it->next)
		if (mi_tid_info(it, dests_arr) < 0) {
			lock_release(dyn_trace_lock);
			goto error;
		}
	lock_release(dyn_trace_lock);

	return resp;

error:
	free_mi_response(resp);
	return 0;
}

static mi_response_t *sip_trace_mi_tid(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	tlist_elem_p it;
	unsigned int hash;
	str tid_s;
	mi_response_t *resp = NULL;
	mi_item_t *resp_obj;
	mi_item_t *dests_arr;
	int dynamic = 0;

	if (get_mi_string_param(params, "id", &tid_s.s, &tid_s.len) < 0)
		return init_mi_param_error();

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	it=get_list_start(trace_list, &tid_s);
	if (!it && dyn_trace_list) {
		lock_get(dyn_trace_lock);
		it=get_list_start(*dyn_trace_list, &tid_s);
		if (!it)
			lock_release(dyn_trace_lock);
		else
			dynamic = 1;
	}
	if (!it) {
		free_mi_response(resp);
		return init_mi_error(400, MI_SSTR("Bad trace id value"));
	}

	dests_arr = add_mi_array(resp_obj, MI_SSTR("trace destinations"));
	if (!dests_arr)
		goto error;

	hash=it->hash;
	for (;it&&it->hash==hash;it=it->next)
		if (mi_tid_info(it, dests_arr) < 0)
			goto error;
	if (dynamic)
		lock_release(dyn_trace_lock);

	return resp;

error:
	if (dynamic)
		lock_release(dyn_trace_lock);
	free_mi_response(resp);
	return NULL;
}

static mi_response_t *sip_trace_mi_mode(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str new_mode;

	if (trace_on_flag==NULL)
		return init_mi_error(500, MI_SSTR("Internal error"));

	if (get_mi_string_param(params, "mode", &new_mode.s, &new_mode.len) < 0)
		return init_mi_param_error();

	if ( new_mode.len==2 &&
	(new_mode.s[0]=='o'|| new_mode.s[0]=='O') &&
	(new_mode.s[1]=='n'|| new_mode.s[1]=='N'))
	{
		*trace_on_flag = 1;
		return init_mi_result_ok();
	} else if ( new_mode.len==3 &&
	(new_mode.s[0]=='o'|| new_mode.s[0]=='O') &&
	(new_mode.s[1]=='f'|| new_mode.s[1]=='F') &&
	(new_mode.s[2]=='f'|| new_mode.s[2]=='F'))
	{
		*trace_on_flag = 0;
		return init_mi_result_ok();
	} else
		return init_mi_error_extra(500, MI_SSTR("Bad parameter value"),
			MI_SSTR("trace mode should be 'on' or 'off'"));
}

static int parse_trace_filter(str *filter_s, enum trace_filter_types *type)
{
	if (filter_s->len > 7 && (strncasecmp(filter_s->s, "caller=", 7) == 0)) {
		filter_s->s += 7;
		filter_s->len -= 7;
		*type = TRACE_FILTER_CALLER;
	} else if (filter_s->len > 7 && (strncasecmp(filter_s->s, "callee=", 7) == 0)) {
		*type = TRACE_FILTER_CALLEE;
		filter_s->s += 7;
		filter_s->len -= 7;
	} else if (filter_s->len > 3 && (strncasecmp(filter_s->s, "ip=", 3) == 0)) {
		*type = TRACE_FILTER_IP;
		filter_s->s += 3;
		filter_s->len -= 3;
	} else
		return 0;
	return 1;
}

static void free_trace_filters(struct trace_filter *list)
{
	struct trace_filter *next, *it;

	for (it = list; it; it = next) {
		next = it->next;
		shm_free(it);
	}
}

static struct trace_filter *parse_trace_filters(const mi_params_t *params)
{
	struct trace_filter *filters = NULL, *filter = NULL;
	enum trace_filter_types type;
	int filters_no, i, data_len;
	mi_item_t *fi;
	char *data;
	str sfilter;

	if (try_get_mi_array_param(params, "filter", &fi, &filters_no) < 0)
		return 0;

	/* we have filters! */
	for (i = 0; i < filters_no; i++) {
		if (try_get_mi_arr_param_string(fi, i, &sfilter.s, &sfilter.len) == 0) {
			if (!parse_trace_filter(&sfilter, &type)) {
				LM_WARN("Unknown filter %.*s\n", sfilter.len, sfilter.s);
				goto next;
			}
			switch (type) {
				case TRACE_FILTER_IP:
					data = (char *)str2ip(&sfilter);
					if (data == NULL) {
						LM_ERR("Invalid IP in filter [%.*s]\n",
								sfilter.len, sfilter.s);
						goto next;
					}
					data_len = sizeof(struct ip_addr);
					break;
				default:
					data_len = 0;
					break;
			}

			filter = shm_malloc(sizeof(*filter) + sfilter.len + data_len);
			if (!filter) {
				LM_ERR("could not allocate filters!\n");
				free_trace_filters(filters);
				return NULL;
			}
			memset(filter, 0, sizeof(*filter));
			filter->type = type;
			filter->match.len = sfilter.len;
			filter->match.s = (char *)(filter + 1) + data_len;
			memcpy(filter->match.s, sfilter.s, sfilter.len);
			if (data_len)
				memcpy(filter->data, data, data_len);
			/* link in the filters list */
			filter->next = filters;
			filters = filter;
		} else
			LM_WARN("Bad filter type for index %d\n", i);
next:
		;
	}
	return filters;
}

static mi_response_t *sip_trace_mi_dyn(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	char *p_uri;
	char *p_name;
	unsigned int hash;
	enum types uri_type;
	str name, uri, aux;
	struct trace_filter *filters = NULL;
	tlist_dyn_elem_p elem = NULL;
	hid_list_t* hep_id = NULL;
	int traced_scope = 0, traced_type = 0;

	if (get_mi_string_param(params, "id", &name.s, &name.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "uri", &uri.s, &uri.len) < 0)
		return init_mi_param_error();

	get_siptrace_type(&name, &uri, NULL, &hash, &uri_type);
	if (uri_type == TYPE_DB) {
		LM_WARN("dynamic DB tracing is not yet available!\n");
		return init_mi_error_extra(406, MI_SSTR("DB not acceptable"),
					MI_SSTR("dynamic DB tracing is not yet available"));
	}
	if (get_siptrace_id(&name, hash, uri_type)) {
		LM_INFO("trace %.*s with uri %.*s already exists!\n",
				name.len, name.s, uri.len, uri.s);
		return init_mi_error_extra(500, MI_SSTR("Bad parameter value"),
					MI_SSTR("trace id already used"));
	}
	LM_INFO("allocating %d [%.*s]\n", hash, name.len, name.s);

	if (get_dyn_siptrace_id(&name, hash, uri_type, 1)) {
		lock_release(dyn_trace_lock);
		LM_INFO("dynamic trace %.*s with uri %.*s already exists!\n",
				name.len, name.s, uri.len, uri.s);
		return init_mi_error_extra(500, MI_SSTR("Bad parameter value"),
					MI_SSTR("dynamic trace id already used"));
	}

	if (uri_type == TYPE_HEP) {
		if (tprot.get_trace_dest_by_name == NULL) {
			lock_release(dyn_trace_lock);
			return init_mi_error_extra(500, MI_SSTR("No transport protocol"),
						MI_SSTR("HEP module was not loaded"));
		}
		/* check if we can alocate a hep_id */
		hep_id = tprot.new_trace_dest(&name, &uri);
		if (!hep_id) {
			lock_release(dyn_trace_lock);
			LM_ERR("could not alocate new hep_id\n");
			return init_mi_error_extra(500, MI_SSTR("Bad parameter value"),
						MI_SSTR("error while alocating new hep_id"));
		}
		uri = hep_id->name;
	}
	/* default tracing scope is dialog */
	if (try_get_mi_string_param(params, "scope", &aux.s, &aux.len) < 0 ||
			((traced_scope = st_parse_flags(&aux)) == 0))
		traced_scope = TRACE_DIALOG;

	/* default tracing scope is everything */
	if (try_get_mi_string_param(params, "type", &aux.s, &aux.len) < 0 ||
			((traced_type = st_parse_types(&aux)) == 0))
		traced_type = 0xFFFF;

	filters = parse_trace_filters(params);

	/* first check if the destination exists */
	elem = shm_malloc(sizeof(tlist_dyn_elem_t) + uri.len + name.len);
	if (!elem) {
		LM_ERR("could not allocate dynamic elem!\n");
		goto error;
	}
	memset(elem, 0, sizeof(tlist_dyn_elem_t));
	p_uri = (char *)(elem + 1);
	memcpy(p_uri, uri.s, uri.len);
	p_name = p_uri + uri.len;
	memcpy(p_name, name.s, name.len);

	if (uri_type == TYPE_HEP) {
		elem->elem.el.hep.name.s = p_uri;
		elem->elem.el.hep.name.len = uri.len;
		elem->elem.el.hep.hep_id = hep_id;
	} else if (parse_uri(p_uri, uri.len, &elem->elem.el.uri) < 0) {
		LM_ERR("failed to parse the [%.*s] URI\n", uri.len, p_uri);
		goto error;
	}

	elem->ref = 1;
	elem->scope = traced_scope;
	elem->type = traced_type;
	elem->filters = filters;
	elem->elem.dynamic = 1;
	elem->elem.type = uri_type;
	elem->elem.uri_hash = hash;
	elem->elem.name.s = p_name;
	elem->elem.name.len = name.len;
	elem->elem.hash = core_hash(&elem->elem.name, NULL, 0);

	/* all good now, insert the element */
	elem->elem.next = (*dyn_trace_list);
	*dyn_trace_list = (tlist_elem_p)elem;
	do_sort(dyn_trace_list);
	lock_release(dyn_trace_lock);

	return init_mi_result_ok();
error:
	if (filters)
		free_trace_filters(filters);
	if (hep_id)
		tprot.release_trace_dest(hep_id);
	lock_release(dyn_trace_lock);
	if (elem)
		shm_free(elem);
	return NULL;
}

static mi_response_t *sip_trace_mi_stop(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str tid_s;
	tlist_elem_p it, prev, next;
	unsigned int hash;

	if (!dyn_trace_list)
		return init_mi_error(500, MI_SSTR("Internal Error"));
	if (get_mi_string_param(params, "id", &tid_s.s, &tid_s.len) < 0)
		return init_mi_param_error();

	lock_get(dyn_trace_lock);
	it=get_list_start(*dyn_trace_list, &tid_s);
	if (!it) {
		lock_release(dyn_trace_lock);
		return init_mi_error(400, MI_SSTR("Bad parameter value"));
	}

	hash=it->hash;

	/* search for the previous element */
	for (prev=NULL, it=(*dyn_trace_list); it && it->next; it = it->next) {
		if (it->next->hash == hash)
			break;
		else
			prev = it;
	}
	for (;it&&it->hash==hash;it=next) {
		next = it->next;
		if (prev)
			prev->next = next;
		else
			(*dyn_trace_list) = next;
		trace_id_unref(it);
	}
	lock_release(dyn_trace_lock);

	return init_mi_result_ok();
}

static mi_response_t *sip_trace_mi_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	unsigned int tid_trace_flag=1;
	str tid_s;
	str new_mode;
	tlist_elem_p it;
	unsigned int hash;

	if (get_mi_string_param(params, "id", &tid_s.s, &tid_s.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "mode", &new_mode.s, &new_mode.len) < 0)
		return init_mi_param_error();

	if ( new_mode.len==2 &&
	(new_mode.s[0]=='o'|| new_mode.s[0]=='O') &&
	(new_mode.s[1]=='n'|| new_mode.s[1]=='N'))
	{
		tid_trace_flag=1;
	} else if ( new_mode.len==3 &&
	(new_mode.s[0]=='o'|| new_mode.s[0]=='O') &&
	(new_mode.s[1]=='f'|| new_mode.s[1]=='F') &&
	(new_mode.s[2]=='f'|| new_mode.s[2]=='F'))
	{
		tid_trace_flag=0;
	} else {
		return init_mi_error_extra(500, MI_SSTR("Bad parameter value"),
					MI_SSTR("trace mode should be 'on' or 'off'"));
	}

	it=get_list_start(trace_list, &tid_s);
	if (!it) {
		return init_mi_error(400, MI_SSTR("Bad parameter value"));
	}

	hash=it->hash;

	for (;it&&it->hash==hash;it=it->next)
		*it->traceable=tid_trace_flag;

	return init_mi_result_ok();
}

static int trace_send_duplicate(char *buf, int len, struct sip_uri *uri)
{
	union sockaddr_union* to;
	struct socket_info* send_sock;
	struct proxy_l * p;
	int proto;
	int ret;

	if(buf==NULL || len <= 0)
		return -1;

	if(uri==NULL)
		return 0;

	to=(union sockaddr_union*)pkg_malloc(sizeof(union sockaddr_union));
	if (to==0){
		LM_ERR("out of pkg memory\n");
		return -1;
	}

	/* create a temporary proxy*/
	proto = PROTO_UDP;
	p=mk_proxy(&uri->host, (uri->port_no)?uri->port_no:SIP_PORT,
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


static int send_trace_proto_duplicate(trace_dest dest, str* correlation,
		trace_instance_p info, int conn_id)
{
	union sockaddr_union from_su;
	union sockaddr_union to_su;
	unsigned int proto;
	str *body, *fromproto, *fromip;
	str *toproto, *toip;
	unsigned short fromport, toport;

	unsigned long long trans_correlation_id;
	str conn_id_s;
	static str net_s = str_init("net");

	trace_message trace_msg;

	/* WARNING - db_vals has to be set by functions above */
	body = &db_vals[0].val.str_val;

	fromproto = &db_vals[4].val.str_val;
	fromip = &db_vals[5].val.str_val;
	fromport = db_vals[6].val.int_val;

	toproto = &db_vals[7].val.str_val;
	toip = &db_vals[8].val.str_val;
	toport = db_vals[9].val.int_val;

	if(body->s==NULL || body->len <= 0)
		return -1;

	if (tprot.create_trace_message == NULL || tprot.send_message == NULL) {
		LM_ERR("Trace api functions not implemented!\n");
		return -1;
	}

	if (pipport2su(fromproto, fromip, fromport, &from_su, &proto)==-1 ||
	(pipport2su(toproto, toip, toport, &to_su, &proto)==-1))
		return -1;

	trace_msg = tprot.create_trace_message(&from_su, &to_su, proto, body,
			sip_trace_id, dest);

	if (trace_msg == NULL) {
		LM_ERR("failed to build trace message!\n");
		return -1;
	}

	if (tprot.add_payload_part( trace_msg, "payload", body)<0) {
		LM_ERR("failed to add payload to trace message\n");
		goto error;
	}

	if (conn_id != 0) {
		tcp_get_correlation_id(conn_id, &trans_correlation_id);

		conn_id_s.s =  int2str( trans_correlation_id, &conn_id_s.len);
		if (tprot.add_extra_correlation( trace_msg, &net_s, &conn_id_s)<0) {
			LM_ERR("failed to add 'net' correlation to trace message\n");
			goto error;
		}
	}

	if (correlation) {
		if ( corr_id == -1 && corr_vendor == -1 ) {
			if (tprot.get_data_id(corr_id_s, &corr_vendor, &corr_id) == 0) {
				LM_DBG("no data id!\n");
			}
		}

		if (tprot.add_chunk(trace_msg,
				correlation->s, correlation->len,
					TRACE_TYPE_STR, corr_id, corr_vendor)) {
			LM_ERR("failed to add correlation id to the packet!\n");
			goto error;
		}
	}

	if (tprot.send_message(trace_msg, dest, NULL) < 0) {
		LM_ERR("failed to forward message to destination!\n");
		goto error;
	}

	tprot.free_message(trace_msg);

	return 0;
error:
	tprot.free_message(trace_msg);
	return -1;
#undef SIP_TRACE_MAX
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

	if (port == 0)
		port = SIP_PORT;
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
		ip_addr2su(tmp_su, ip_a, port);
		return 0;
	}

	LM_ERR("host <%.*s> is not an IP\n",host_uri.len,host_uri.s);
	return -1;
}

/**
 *
 * TRACER API IMPLEMENTATION
 *
 */
static struct trace_proto traced_protos[MAX_TRACED_PROTOS];
static int traced_protos_no=0;

trace_dest get_next_trace_dest(trace_dest last_dest, int hash)
{
	int found_last=0;

	tlist_elem_p it;
	trace_info_p info = GET_TRACER_CONTEXT;
	trace_instance_p instance;

	if (info==NULL || info->instances==NULL)
		return NULL;

	if (last_dest == NULL)
		found_last = 1;

	for (instance = info->instances; instance; instance = instance->next) {
		for (it=instance->trace_list; it && it->hash == hash; it=it->next) {
			if (it->type == TYPE_HEP && (!(it->traceable) || *it->traceable)) {
				if (found_last)
					return it->el.hep.hep_id;
				else if (it->el.hep.hep_id == last_dest)
					found_last = 1;
			}
		}
	}

	return NULL;
}


int register_traced_type(char* name)
{
	int id;

	/* if trace proto not loaded return 0 */
	if ( !tprot.send_message ) {
		return 0;
	}

	if (traced_protos_no + 1 == MAX_TRACED_PROTOS) {
		LM_BUG("more than %zu types of tracing!"
				"Increase MAX_TRACE_NAMES value!\n", MAX_TRACED_PROTOS);
		return -1;
	}

	if (!tprot.get_message_id)
		return -1;

	/* proto id will be the same as the packet id */
	if ((id = tprot.get_message_id(name)) == -1) {
		LM_ERR("proto <%s> not registered!\n", name);
		return -1;
	}

	traced_protos[traced_protos_no].proto_id = id;
	traced_protos[traced_protos_no++].proto_name = name;

	return id;
}


static int is_id_traced(int id, trace_instance_p info)
{
	int pos;
	int trace_types;

	if (info==NULL || (trace_types=info->trace_types)==-1)
		return 0;

	LM_DBG("trace=%s dyn=%s\n", (*trace_on_flag?"on":"off"),
		(dyn_trace_list?((*dyn_trace_list)?"on":"off"):"bug"));
	/* quick shortcut to avoid looping if no global is off and no dynamic is present */
	if (!(*trace_on_flag) && (!dyn_trace_list || *dyn_trace_list == NULL))
		return 0;

	/* find the corresponding position for this id */
	for (pos=0; pos < traced_protos_no; pos++)
		if (traced_protos[pos].proto_id == id)
			break;

	if (pos == traced_protos_no) {
		LM_ERR("can't find any proto with id %d\n", id);
		return 0;
	}

	if ((1<<pos) & trace_types)
		return 1;

	return 0;
}


static int api_is_id_traced(int id)
{
	trace_info_p info = GET_TRACER_CONTEXT;
	if (!info)
		return 0;
	trace_instance_p instance = GET_TRACER_CONTEXT->instances;
	while (instance) {
		if (is_id_traced( id, instance))
			return 1;
		instance = instance->next;
	}
	return 0;
}


int sip_context_trace_impl(int id, union sockaddr_union* from_su,
		union sockaddr_union* to_su, str* payload,
		int net_proto, str* correlation_id, struct modify_trace* mod_p)
{
	tlist_elem_p it;
	trace_info_p info = GET_TRACER_CONTEXT;
	trace_instance_p instance;
	int hash;
	trace_message trace_msg;

	if (tprot.send_message == NULL) {
		LM_DBG("trace api not loaded! aborting trace...\n");
		return 0;
	}

	if (info==NULL) {
		LM_DBG("no id to trace! aborting...\n");
		return 0;
	}

	if (info->instances==NULL) {
		LM_DBG("no instances to trace! aborting...\n");
		return 0;
	}

	if (corr_id == -1 && corr_vendor == -1) {
		if (tprot.get_data_id(corr_id_s, &corr_vendor, &corr_id) == 0) {
			LM_DBG("no data id!\n");
		}
	}

	for (instance = info->instances; instance; instance = instance->next) {

		if (is_id_traced(id, instance) == 0) {
			LM_DBG("id %d not traced! aborting...\n", id);
			continue;
		}

		for(it=instance->trace_list; it; it=it->next)
			LM_DBG("name %.*s, hash %d, type %d, traceable %s\n",
					it->name.len,it->name.s,
					it->hash, it->type,
					(it->dynamic?"dynamic":
						(it->traceable && (*it->traceable)?"on":"off")));

		/* iterate through the list of trace URIs but use only those
		 * with the same name (given by same hash) - keep in midn that
		 * the list is hash-ordered, so all trace URIs under the same
		 * name will be grouped */
		hash = instance->trace_list->hash;
		for (it=instance->trace_list; it && (it->hash==hash); it=it->next) {
			if (it->type != TYPE_HEP)
				continue;

			if (!it->dynamic) {
				if (!(*trace_on_flag) || !it->traceable || !(*it->traceable))
					continue;
			}

			trace_msg = tprot.create_trace_message(from_su, to_su,
					net_proto, payload, id, it->el.hep.hep_id);

			if (trace_msg == NULL) {
				LM_ERR("failed to create trace message!\n");
				return -1;
			}

			if (correlation_id && corr_id != -1 && corr_vendor != -1 &&
					tprot.add_chunk(trace_msg,
						correlation_id->s, correlation_id->len,
					TRACE_TYPE_STR, corr_id, corr_vendor)) {
				LM_ERR("failed to add correlation id to the packet!\n");
				goto error;
			}

			/* here the message can be modified */
			if ( mod_p )
				mod_p->mod_f( trace_msg, mod_p->param );

			if (tprot.send_message(trace_msg, it->el.hep.hep_id, NULL) < 0) {
				LM_ERR("failed to send trace message!\n");
				goto error;
			}

			tprot.free_message(trace_msg);
		}
	}

	return 0;
error:
	tprot.free_message(trace_msg);
	return -1;
}

const struct trace_proto* get_traced_protos(void)
{
	return (const struct trace_proto*)traced_protos;
}

int get_traced_protos_no(void)
{
	return traced_protos_no;
}

static int init_dyn_tracing(void)
{
	dyn_trace_lock = lock_alloc();
	if (!dyn_trace_lock) {
		LM_ERR("could not allocate dynamic trace lock!\n");
		return -1;
	}
	if (!lock_init(dyn_trace_lock)) {
		lock_dealloc(dyn_trace_lock);
		LM_ERR("could not allocate dynamic trace lock!\n");
		return -1;
	}
	dyn_trace_list = shm_malloc(sizeof(*dyn_trace_list));
	if (!dyn_trace_list) {
		lock_dealloc(dyn_trace_lock);
		LM_ERR("could not allocate dynamic trace list!\n");
		return -1;
	}
	*dyn_trace_list = 0;
	return 0;
}

static void destroy_dyn_tracing(void)
{
	tlist_elem_t *it, *next;

	if (!dyn_trace_list)
		return;

	lock_get(dyn_trace_lock);
	for (it=*dyn_trace_list; it; it=next) {
		next = it->next;
		trace_id_unref(it);
	}
	lock_release(dyn_trace_lock);

	/* release the lock itself */
	lock_dealloc(dyn_trace_lock);
	shm_free(dyn_trace_list);
}

static inline int dyn_tracing_uri_match(str *match, struct sip_uri *uri)
{
	if (uri->user.len > match->len) /* fail: user too long */
		return 0;
	if (memcmp(uri->user.s, match->s, uri->user.len) != 0) /* fail: different user */
		return 0;
	if (uri->user.len == match->len) /* success: no domain in matching, full match */
		return 1;
	if (match->s[uri->user.len] != '@') /* fail: different user, or domain */
		return 0;
	/* domains should be equal */
	if (match->len - uri->user.len - 1 /* '@' */ != uri->host.len) /* fail: different domains len */
		return 0;
	if (memcmp(uri->host.s, match->s + uri->user.len + 1, uri->host.len) != 0) /* fail: different domains */
		return 0;
	return 1;
}

static int process_dyn_tracing(struct sip_msg *msg, void *param)
{
	int initial_invite = 0;
	tlist_elem_p it;
	tlist_dyn_elem_p el;
	struct trace_filter *filter;
	struct ip_addr *ip;

	/* first thing is to check whether this is an initial request */
	if (msg->REQ_METHOD == METHOD_INVITE) {
		if (parse_to_header(msg) < 0)
			goto end;

		if (get_to(msg)->tag_value.len == 0)
			initial_invite = 1;
	}

	lock_get(dyn_trace_lock);
	for (it=*dyn_trace_list; it; it=it->next) {
		el = trace_id_dyn(it);
		/* check if it's worth tracing */
		if (el->scope == TRACE_DIALOG && !initial_invite)
			goto skip;

		for (filter = el->filters; filter; filter = filter->next) {
			switch (filter->type) {
				case TRACE_FILTER_CALLER:
					if (parse_from_uri(msg) == NULL)
						goto skip;

					if (!dyn_tracing_uri_match(&filter->match, &get_from(msg)->parsed_uri))
						goto skip;
					/* all good, it does match - go to next filter */
					break;

				case TRACE_FILTER_CALLEE:
					if (parse_sip_msg_uri(msg) < 0)
						goto skip;

					if (!dyn_tracing_uri_match(&filter->match, &msg->parsed_uri))
						goto skip;
					/* all good, it does match - go to next filter */
					break;

				case TRACE_FILTER_IP:
					ip = (struct ip_addr *)&filter->data;
					LM_INFO("comparing %s with %s\n",
							ip_addr2a(ip), ip_addr2a(&msg->rcv.src_ip));
					if (!ip_addr_cmp(ip, &msg->rcv.src_ip))
						goto skip;
					break;
			}
		}
		if (sip_trace_handle(msg, it, el->type, el->scope, NULL) == 1)
			trace_id_ref(el);
skip:
		continue;
	}
	lock_release(dyn_trace_lock);

end:
	return SCB_RUN_ALL;
}
