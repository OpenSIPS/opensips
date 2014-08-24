/**
 * $Id$
 *
 * dispatcher module -- stateless load balancing
 *
 * Copyright (C) 2004-2005 FhG Fokus
 * Copyright (C) 2006-2010 Voice Sistem SRL
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
 * History
 * -------
 * 2004-07-31  first version, by daniel
 * 2007-01-11  Added a function to check if a specific gateway is in a group
 *              (carsten - Carsten Bock, BASIS AudioNet GmbH)
 * 2007-02-09  Added active probing of failed destinations and automatic
 *              re-enabling of destinations (carsten)
 * 2007-05-08  Ported the changes to SVN-Trunk and renamed ds_is_domain
 *              to ds_is_from_list.  (carsten)
 * 2007-07-18  Added support for load/reload groups from DB
 *              reload triggered from ds_reload MI_Command (ancuta)
 * 2009-05-18  Added support for weights for the destinations;
 *              added support for custom "attrs" (opaque string) (bogdan)
 * 2013-12-02  Added support state persistency (restart and reload) (bogdan)
 * 2013-12-05  Added a safer reload mechanism based on locking read/writter (bogdan)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "../../sr_module.h"
#include "../../mi/mi.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../route.h"
#include "../../mem/mem.h"
#include "../../mod_fix.h"
#include "../../db/db.h"

#include "dispatch.h"
#include "ds_bl.h"


#define DS_SET_ID_COL		"setid"
#define DS_DEST_URI_COL		"destination"
#define DS_DEST_SOCK_COL	"socket"
#define DS_DEST_STATE_COL	"state"
#define DS_DEST_WEIGHT_COL	"weight"
#define DS_DEST_ATTRS_COL	"attrs"
#define DS_TABLE_NAME 		"dispatcher"

/** parameters */
int  ds_force_dst   = 0;
int  ds_flags       = 0;
int  ds_use_default = 0;
static str dst_avp_param = str_init("$avp(ds_dst_failover)");
static str grp_avp_param = str_init("$avp(ds_grp_failover)");
static str cnt_avp_param = str_init("$avp(ds_cnt_failover)");
static str sock_avp_param = str_init("$avp(ds_sock_failover)");
static str attrs_avp_param = {NULL, 0};
static str pvar_algo_param = str_init("");
str hash_pvar_param = {NULL, 0};

int dst_avp_name;
unsigned short dst_avp_type;
int grp_avp_name;
unsigned short grp_avp_type;
int cnt_avp_name;
unsigned short cnt_avp_type;
int sock_avp_name;
unsigned short sock_avp_type;
int attrs_avp_name;
unsigned short attrs_avp_type;

pv_elem_t * hash_param_model = NULL;

int probing_threshhold = 3; /* number of failed requests, before a destination
							   is taken into probing */
str ds_ping_method = {"OPTIONS",7};
str ds_ping_from   = {"sip:dispatcher@localhost", 24};
static int ds_ping_interval = 0;
int ds_probing_mode = 0;

/*db */
str ds_db_url         = {NULL, 0};
str ds_set_id_col     = str_init(DS_SET_ID_COL);
str ds_dest_uri_col   = str_init(DS_DEST_URI_COL);
str ds_dest_sock_col  = str_init(DS_DEST_SOCK_COL);
str ds_dest_state_col = str_init(DS_DEST_STATE_COL);
str ds_dest_weight_col= str_init(DS_DEST_WEIGHT_COL);
str ds_dest_attrs_col = str_init(DS_DEST_ATTRS_COL);
str ds_table_name     = str_init(DS_TABLE_NAME);

str ds_setid_pvname   = {NULL, 0};
pv_spec_t ds_setid_pv;

static str options_reply_codes_str= {0, 0};
static int* options_reply_codes = NULL;
static int options_codes_no;
static char *probing_sock_s = NULL;
struct socket_info *probing_sock = NULL;

/* event */
static str dispatcher_event = str_init("E_DISPATCHER_STATUS");
event_id_t dispatch_evi_id;


/** module functions */
static int mod_init(void);
static int ds_child_init(int rank);

static int w_ds_select_dst(struct sip_msg*, char*, char*);
static int w_ds_select_dst_limited(struct sip_msg*, char*, char*, char*);
static int w_ds_select_domain(struct sip_msg*, char*, char*);
static int w_ds_select_domain_limited(struct sip_msg*, char*, char*, char*);
static int w_ds_next_dst(struct sip_msg*, char*, char*);
static int w_ds_next_domain(struct sip_msg*, char*, char*);
static int w_ds_mark_dst0(struct sip_msg*, char*, char*);
static int w_ds_mark_dst1(struct sip_msg*, char*, char*);
static int w_ds_count(struct sip_msg*, char*, const char *, char*);

static int w_ds_is_in_list2(struct sip_msg*, char*, char*);
static int w_ds_is_in_list3(struct sip_msg*, char*, char*, char*);
static int w_ds_is_in_list4(struct sip_msg*, char*, char*, char*, char*);


static void destroy(void);

static int in_list_fixup(void** param, int param_no);
static int ds_count_fixup(void** param, int param_no);

static struct mi_root* ds_mi_set(struct mi_root* cmd, void* param);
static struct mi_root* ds_mi_list(struct mi_root* cmd, void* param);
static struct mi_root* ds_mi_reload(struct mi_root* cmd_tree, void* param);
static int mi_child_init(void);

static cmd_export_t cmds[]={
	{"ds_select_dst",    (cmd_function)w_ds_select_dst,    2, fixup_igp_igp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_select_dst",    (cmd_function)w_ds_select_dst_limited,    3, fixup_igp_igp_igp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_select_domain", (cmd_function)w_ds_select_domain, 2, fixup_igp_igp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_select_domain", (cmd_function)w_ds_select_domain_limited, 3, fixup_igp_igp_igp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_next_dst",      (cmd_function)w_ds_next_dst,      0, NULL        , 0,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_next_domain",   (cmd_function)w_ds_next_domain,   0, NULL         , 0,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_mark_dst",      (cmd_function)w_ds_mark_dst0,     0, NULL         , 0,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_mark_dst",      (cmd_function)w_ds_mark_dst1,     1, NULL         , 0,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_is_in_list",    (cmd_function)w_ds_is_in_list2,   2, in_list_fixup, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"ds_is_in_list",    (cmd_function)w_ds_is_in_list3,   3, in_list_fixup, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"ds_is_in_list",    (cmd_function)w_ds_is_in_list4,   4, in_list_fixup, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"ds_count",    (cmd_function)w_ds_count,   3, ds_count_fixup, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{0,0,0,0,0,0}
};


static param_export_t params[]={
	{"db_url",          STR_PARAM, &ds_db_url.s},
	{"table_name",      STR_PARAM, &ds_table_name.s},
	{"setid_col",       STR_PARAM, &ds_set_id_col.s},
	{"destination_col", STR_PARAM, &ds_dest_uri_col.s},
	{"socket_col",      STR_PARAM, &ds_dest_sock_col.s},
	{"state_col",       STR_PARAM, &ds_dest_state_col.s},
	{"weight_col",      STR_PARAM, &ds_dest_weight_col.s},
	{"attrs_col",       STR_PARAM, &ds_dest_attrs_col.s},
	{"force_dst",       INT_PARAM, &ds_force_dst},
	{"flags",           INT_PARAM, &ds_flags},
	{"use_default",     INT_PARAM, &ds_use_default},
	{"dst_avp",         STR_PARAM, &dst_avp_param.s},
	{"grp_avp",         STR_PARAM, &grp_avp_param.s},
	{"cnt_avp",         STR_PARAM, &cnt_avp_param.s},
	{"sock_avp",        STR_PARAM, &sock_avp_param.s},
	{"attrs_avp",       STR_PARAM, &attrs_avp_param.s},
	{"hash_pvar",       STR_PARAM, &hash_pvar_param.s},
	{"setid_pvar",      STR_PARAM, &ds_setid_pvname.s},
	{"pvar_algo_pattern",     STR_PARAM, &pvar_algo_param.s},
	{"ds_probing_threshhold", INT_PARAM, &probing_threshhold},
	{"ds_ping_method",        STR_PARAM, &ds_ping_method.s},
	{"ds_ping_from",          STR_PARAM, &ds_ping_from.s},
	{"ds_ping_interval",      INT_PARAM, &ds_ping_interval},
	{"ds_probing_mode",       INT_PARAM, &ds_probing_mode},
	{"options_reply_codes",   STR_PARAM, &options_reply_codes_str.s},
	{"ds_probing_sock",       STR_PARAM, &probing_sock_s},
	{"ds_define_blacklist",   STR_PARAM|USE_FUNC_PARAM, (void*)set_ds_bl},
	{0,0,0}
};


static mi_export_t mi_cmds[] = {
	{ "ds_set_state",   0, ds_mi_set,     0,                 0,  0            },
	{ "ds_list",        0, ds_mi_list,    MI_NO_INPUT_FLAG,  0,  0            },
	{ "ds_reload",      0, ds_mi_reload,  0,                 0,  mi_child_init},
	{ 0, 0, 0, 0, 0, 0}
};


/** module exports */
struct module_exports exports= {
	"dispatcher",
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,
	params,
	0,          /* exported statistics */
	mi_cmds,    /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* extra processes */
	mod_init,   /* module initialization function */
	(response_function) 0,
	(destroy_function) destroy,
	ds_child_init, /* per-child init function */
};


/**
 * init module function
 */
static int mod_init(void)
{
	pv_spec_t avp_spec;

	LM_DBG("initializing ...\n");

	/* Load stuff from DB */
	init_db_url( ds_db_url , 0 /*cannot be null*/);

	ds_table_name.len = strlen(ds_table_name.s);
	ds_set_id_col.len = strlen(ds_set_id_col.s);
	ds_dest_uri_col.len = strlen(ds_dest_uri_col.s);
	ds_dest_sock_col.len = strlen(ds_dest_sock_col.s);
	ds_dest_state_col.len = strlen(ds_dest_state_col.s);
	ds_dest_weight_col.len = strlen(ds_dest_weight_col.s);
	ds_dest_attrs_col.len = strlen(ds_dest_attrs_col.s);

	/* handle AVPs spec */
	dst_avp_param.len = strlen(dst_avp_param.s);
	if (pv_parse_spec(&dst_avp_param, &avp_spec)==0
	|| avp_spec.type!=PVT_AVP) {
		LM_ERR("malformed or non AVP %.*s AVP definition\n",
			dst_avp_param.len, dst_avp_param.s);
		return -1;
	}
	if(pv_get_avp_name(0, &(avp_spec.pvp), &dst_avp_name,&dst_avp_type)!=0) {
		LM_ERR("[%.*s]- invalid AVP definition\n", dst_avp_param.len,
			dst_avp_param.s);
		return -1;
	}

	grp_avp_param.len=strlen(grp_avp_param.s);
	if (pv_parse_spec(&grp_avp_param, &avp_spec)==0
	|| avp_spec.type!=PVT_AVP) {
		LM_ERR("malformed or non AVP %.*s AVP definition\n",
			grp_avp_param.len, grp_avp_param.s);
		return -1;
	}
	if(pv_get_avp_name(0, &(avp_spec.pvp), &grp_avp_name,&grp_avp_type)!=0) {
		LM_ERR("[%.*s]- invalid AVP definition\n", grp_avp_param.len,
			grp_avp_param.s);
		return -1;
	}

	cnt_avp_param.len=strlen(cnt_avp_param.s);
	if (pv_parse_spec(&cnt_avp_param, &avp_spec)==0
	|| avp_spec.type!=PVT_AVP) {
		LM_ERR("malformed or non AVP %.*s AVP definition\n",
			cnt_avp_param.len, cnt_avp_param.s);
		return -1;
	}
	if(pv_get_avp_name(0, &(avp_spec.pvp), &cnt_avp_name,&cnt_avp_type)!=0) {
		LM_ERR("[%.*s]- invalid AVP definition\n", cnt_avp_param.len,
			cnt_avp_param.s);
		return -1;
	}

	sock_avp_param.len=strlen(sock_avp_param.s);
	if (pv_parse_spec(&sock_avp_param, &avp_spec)==0
	|| avp_spec.type!=PVT_AVP) {
		LM_ERR("malformed or non AVP %.*s AVP definition\n",
			sock_avp_param.len, sock_avp_param.s);
		return -1;
	}
	if(pv_get_avp_name(0, &(avp_spec.pvp), &sock_avp_name,&sock_avp_type)!=0){
		LM_ERR("[%.*s]- invalid AVP definition\n", sock_avp_param.len,
			sock_avp_param.s);
		return -1;
	}

	if (attrs_avp_param.s && (attrs_avp_param.len=strlen(attrs_avp_param.s)) > 0) {
		if (pv_parse_spec(&attrs_avp_param, &avp_spec)==0
		|| avp_spec.type!=PVT_AVP) {
			LM_ERR("malformed or non AVP %.*s AVP definition\n",
					attrs_avp_param.len, attrs_avp_param.s);
			return -1;
		}

		if (pv_get_avp_name(0, &(avp_spec.pvp), &attrs_avp_name,
		&attrs_avp_type)!=0){
			LM_ERR("[%.*s]- invalid AVP definition\n", attrs_avp_param.len,
					attrs_avp_param.s);
			return -1;
		}
	} else {
		attrs_avp_name = -1;
		attrs_avp_type = 0;
	}

	if (hash_pvar_param.s && (hash_pvar_param.len=strlen(hash_pvar_param.s))>0 ) {
		if(pv_parse_format(&hash_pvar_param, &hash_param_model) < 0
				|| hash_param_model==NULL) {
			LM_ERR("malformed PV string: %s\n", hash_pvar_param.s);
			return -1;
		}
	} else {
		hash_param_model = NULL;
	}

	if (ds_setid_pvname.s && (ds_setid_pvname.len=strlen(ds_setid_pvname.s))>0 ) {
		if(pv_parse_spec(&ds_setid_pvname, &ds_setid_pv)==NULL
				|| !pv_is_w(&ds_setid_pv))
		{
			LM_ERR("[%s]- invalid setid_pvname\n", ds_setid_pvname.s);
			return -1;
		}
	}

	pvar_algo_param.len = strlen(pvar_algo_param.s);
	if (pvar_algo_param.len)
		ds_pvar_parse_pattern(pvar_algo_param);

	if (init_ds_bls()!=0) {
		LM_ERR("failed to init DS blacklists\n");
		return E_CFG;
	}

	if (init_ds_data()!=0) {
		LM_ERR("failed to init DS data holder\n");
		return -1;
	}

	/* open DB connection to load provisioning data */
	if (init_ds_db()!= 0) {
		LM_ERR("failed to init database support\n");
		return -1;
	}

	/* do the actula data load */
	if (ds_reload_db()!=0) {
		LM_ERR("failed to load data from DB\n");
		return -1;
	}

	/* close DB connection */
	ds_disconnect_db();

	/* Only, if the Probing-Timer is enabled the TM-API needs to be loaded: */
	if (ds_ping_interval > 0)
	{
		load_tm_f load_tm;
		str host;
		int port,proto;

		if (ds_ping_from.s)
			ds_ping_from.len = strlen(ds_ping_from.s);
		if (ds_ping_method.s)
			ds_ping_method.len = strlen(ds_ping_method.s);
		/* parse the list of reply codes to be counted as success */
		if(options_reply_codes_str.s) {
			options_reply_codes_str.len = strlen(options_reply_codes_str.s);
			if(parse_reply_codes( &options_reply_codes_str, &options_reply_codes,
			&options_codes_no )< 0) {
				LM_ERR("Bad format for options_reply_code parameter"
						" - Need a code list separated by commas\n");
				return -1;
			}
		}
		/* parse and look for the socket to ping from */
		if (probing_sock_s && probing_sock_s[0]!=0 ) {
			if (parse_phostport( probing_sock_s, strlen(probing_sock_s),
			&host.s, &host.len, &port, &proto)!=0 ) {
				LM_ERR("socket description <%s> is not valid\n",
					probing_sock_s);
				return -1;
			}
			probing_sock = grep_sock_info( &host, port, proto);
			if (probing_sock==NULL) {
				LM_ERR("socket <%s> is not local to opensips (we must listen "
					"on it\n", probing_sock_s);
				return -1;
			}
		}
		/* TM-Bindings */
		load_tm=(load_tm_f)find_export("load_tm", 0, 0);
		if (load_tm==NULL) {
			LM_ERR("failed to bind to the TM-Module - required for probing\n");
			return -1;
		}
		/* let the auto-loading function load all TM stuff */
		if (load_tm( &tmb ) == -1) {
			LM_ERR("could not load the TM-functions - disable DS ping\n");
			return -1;
		}
		/* Register the PING-Timer */
		if (register_timer("ds-pinger",ds_check_timer,NULL,ds_ping_interval)<0){
			LM_ERR("failed to register timer for probing!\n");
			return -1;
		}
	}

	/* register timer to flush the state of destination back to DB */
	if (register_timer("ds-flusher",ds_flusher_routine,NULL, 30)<0){
		LM_ERR("failed to register timer for DB flushing!\n");
		return -1;
	}

	dispatch_evi_id = evi_publish_event(dispatcher_event);
	if (dispatch_evi_id == EVI_ERROR)
		LM_ERR("cannot register dispatcher event\n");
	return 0;
}


/*
 * Per process init function
 */
#include "../../pt.h"
static int ds_child_init(int rank)
{
	/* we need DB connection from the timer procs (for the flushing)
	 * and from the main proc (for final flush on shutdown) */
	if ( (process_no==0 || rank==PROC_TIMER) && ds_db_url.s)
		return ds_connect_db();
	return 0;
}


static int mi_child_init(void)
{
	if(ds_db_url.s)
		return ds_connect_db();
	return 0;
}


/**
 * destroy function
 */
static void destroy(void)
{
	LM_DBG("destroying module ...\n");

	/* flush the state of the destinations */
	ds_flusher_routine(0, NULL);

	ds_destroy_data();

	/* destroy blacklists */
	destroy_ds_bls();
}


#define GET_VALUE(param_name,param,i_value,s_value,value_flags) do{ \
	if(fixup_get_isvalue(msg, (gparam_p)(param), &(i_value), &(s_value), &(value_flags))!=0) { \
		LM_ERR("no %s value\n", (param_name)); \
		return -1; \
	} \
}while(0)

#define CHECK_INVALID_PARAM(param) do{ \
	str_trim_spaces_lr(param); \
	if ((param).s[0] == ',' || (param).s[(param).len-1]==',') { \
		LM_ERR("Empty slot in param [%.*s]\n", (param).len, (param).s); \
		return -1; \
	} \
}while(0)

#define PARSE_PARAM(param_name,param,ctl_param) do{ \
	p = q_memrchr( (param).s , ',' , (param).len); \
	_param.s = (p==NULL)?(param).s:p+1; \
	_param.len = (p==NULL)?(param).len:((param).s+(param).len-p-1); \
	(param).len -= _param.len + (p?1:0); \
	if (_param.len<=0) { \
		LM_ERR("empty slot\n"); \
		goto error; \
	} else { \
		str_trim_spaces_lr(_param); \
		if (_param.len<=0) { \
			LM_ERR("empty %s slot after trimming\n", (param_name)); \
			goto error; \
		} \
		if (str2sint(&_param, &(ctl_param))!=0) { \
			LM_ERR("bogus %s slot [%.*s]\n", (param_name), _param.len,_param.s); \
			goto error; \
		} \
	} \
}while(0)

#define DBG_PARSE_PARAM(param_name,param,ctl_param) do{ \
	p = q_memrchr( (param).s , ',' , (param).len); \
	_param.s = (p==NULL)?(param).s:p+1; \
	_param.len = (p==NULL)?(param).len:((param).s+(param).len-p-1); \
	(param).len -= _param.len + (p?1:0); \
	LM_DBG("got %s slot [%p][%d]->[%.*s]\n", (param_name), _param.s,_param.len, _param.len,_param.s); \
	if (_param.len<=0) { \
		LM_ERR("empty slot\n"); \
		goto error; \
	} else { \
		str_trim_spaces_lr(_param); \
		if (_param.len<=0) { \
			LM_ERR("empty %s slot after trimming\n", (param_name)); \
			goto error; \
		} \
		if (str2sint(&_param, &(ctl_param))!=0) { \
			LM_ERR("bogus %s slot [%.*s]\n", (param_name), _param.len,_param.s); \
			goto error; \
		} \
		LM_DBG("found %s    [%p][%d]->[%.*s] => [%d]\n", \
				(param_name), _param.s,_param.len, _param.len,_param.s, (ctl_param)); \
	} \
}while(0)


/**
 *
 */
static int w_ds_select(struct sip_msg* msg, char* set, char* alg, char* max_results, int mode)
{
	unsigned int algo_flags, set_flags, max_flags;
	str s_algo = {NULL, 0};
	str s_set = {NULL, 0};
	str s_max = {NULL, 0};
	str _param;
	char *p;
	int ret;
	int run_prev_ds_select = 0;
	ds_select_ctl_t prev_ds_select_ctl, ds_select_ctl;

	if(msg==NULL)
		return -1;

	ds_select_ctl.mode = mode;
	ds_select_ctl.max_results = 1000;
	ds_select_ctl.reset_AVP = 1;
	ds_select_ctl.set_destination = 1;

	/* Retrieve dispatcher set */
	GET_VALUE("destination set", set, ds_select_ctl.set, s_set, set_flags);

	/* Retrieve dispatcher algorithm */
	GET_VALUE("algorithm", alg, ds_select_ctl.alg, s_algo, algo_flags);

	/* Retrieve dispatcher max results */
	if (max_results) {
		GET_VALUE("max results", max_results, ds_select_ctl.max_results, s_max, max_flags);
		if( !( (set_flags  & GPARAM_INT_VALUE_FLAG)
			&& (algo_flags & GPARAM_INT_VALUE_FLAG)
			&& (max_flags  & GPARAM_INT_VALUE_FLAG) ) ) {
			goto handle_str_params;
		}
	} else {
		if( !( (set_flags  & GPARAM_INT_VALUE_FLAG)
			&& (algo_flags & GPARAM_INT_VALUE_FLAG) ) ) {
			goto handle_str_params;
		}
	}

	return ds_select_dst(msg, &ds_select_ctl);

handle_str_params:
	if (max_results) {
		if(  ( (set_flags  & GPARAM_INT_VALUE_FLAG)
			|| (algo_flags & GPARAM_INT_VALUE_FLAG)
			|| (max_flags  & GPARAM_INT_VALUE_FLAG) ) ) {
			LM_ERR("Mixed param types: set_flags=[%u] algo_flags=[%u] max_flags=[%u]\n",
				set_flags, algo_flags, max_flags);
			return -1;
		}
		if( !( (set_flags  & GPARAM_STR_VALUE_FLAG)
			&& (algo_flags & GPARAM_STR_VALUE_FLAG)
			&& (max_flags  & GPARAM_STR_VALUE_FLAG) ) ) {
			LM_ERR("Not all params are strings: set_flags=[%u] algo_flags=[%u] max_flags=[%u]\n",
				set_flags, algo_flags, max_flags);
			return -1;
		}
	} else {
		if(  ( (set_flags  & GPARAM_INT_VALUE_FLAG)
			|| (algo_flags & GPARAM_INT_VALUE_FLAG) ) ) {
			LM_ERR("Mixed param types: set_flags=[%u] algo_flags=[%u]\n",
				set_flags, algo_flags);
			return -1;
		}
		if( !( (set_flags  & GPARAM_STR_VALUE_FLAG)
			&& (algo_flags & GPARAM_STR_VALUE_FLAG) ) ) {
			LM_ERR("Not all params are strings: set_flags=[%u] algo_flags=[%u]\n",
				set_flags, algo_flags);
			return -1;
		}
	}

	CHECK_INVALID_PARAM(s_set);
	CHECK_INVALID_PARAM(s_algo);
	if (max_results) CHECK_INVALID_PARAM(s_max);

	/* Avoid compiler warning */
	memset(&prev_ds_select_ctl, 0, sizeof(ds_select_ctl_t));

	ds_select_ctl.set_destination = 0;

	/* Parse the params in reverse order.
	 * We need to runt the first entry last to properly populate ds_select_dst AVPs.
	 * On the first ds_select_dst run we need to reset AVPs.
	 * On the last ds_select_dst run we need to set destination.  */
	do {
		PARSE_PARAM("set", s_set,  ds_select_ctl.set);
		PARSE_PARAM("alg", s_algo, ds_select_ctl.alg);
		if (max_results) PARSE_PARAM("max", s_max, ds_select_ctl.max_results);

		if (run_prev_ds_select) {
			LM_DBG("ds_select: %d %d %d %d %d\n",
				prev_ds_select_ctl.set, prev_ds_select_ctl.alg, prev_ds_select_ctl.max_results,
				prev_ds_select_ctl.reset_AVP, prev_ds_select_ctl.set_destination);
			ret = ds_select_dst(msg, &prev_ds_select_ctl);
			if (ret<0) return ret;
			/* stop resetting AVPs. */
			ds_select_ctl.reset_AVP = 0;
		} else {
			/* Enable running ds_select_dst on next loop. */
			run_prev_ds_select = 1;
		}
		prev_ds_select_ctl = ds_select_ctl;
	} while (s_set.len>0 || s_algo.len>0);

	if (max_results && s_max.len>0) {
		LM_ERR("extra max slot(s) [%.*s]\n", s_max.len,s_max.s);
		goto error;
	}

	/* las ds_select_dst run: setting destination. */
	ds_select_ctl.set_destination = 1;
	LM_DBG("ds_select: %d %d %d %d %d\n",
		ds_select_ctl.set, ds_select_ctl.alg, ds_select_ctl.max_results,
		ds_select_ctl.reset_AVP, ds_select_ctl.set_destination);
	return ds_select_dst(msg, &ds_select_ctl);

error:
	return -1;
}

/**
 *
 */
static int w_ds_select_all(struct sip_msg* msg, char* set, char* alg, int mode)
{
	return w_ds_select(msg, set, alg, NULL, mode);
}

/**
 *
 */
static int w_ds_select_limited(struct sip_msg* msg, char* set, char* alg, char* max_results, int mode)
{
	return w_ds_select(msg, set, alg, max_results, mode);
}

/**
 *
 */
static int w_ds_select_dst(struct sip_msg* msg, char* set, char* alg)
{
	return w_ds_select_all(msg, set, alg, 0);
}


/**
 * same wrapper as w_ds_select_dst, but it allows cutting down the result set
 */
static int w_ds_select_dst_limited(struct sip_msg* msg, char* set, char* alg, char* max_results)
{
	return w_ds_select_limited(msg, set, alg, max_results, 0);
}


/**
 *
 */
static int w_ds_select_domain(struct sip_msg* msg, char* set, char* alg)
{
	return w_ds_select_all(msg, set, alg, 1);
}


/**
 * same wrapper as w_ds_select_domain, but it allows cutting down the result set
 */
static int w_ds_select_domain_limited(struct sip_msg* msg, char* set, char* alg, char* max_results)
{
	return w_ds_select_limited(msg, set, alg, max_results, 1);
}


/**
 *
 */
static int w_ds_next_dst(struct sip_msg *msg, char *str1, char *str2)
{
	return ds_next_dst(msg, 0/*set dst uri*/);
}


/**
 *
 */
static int w_ds_next_domain(struct sip_msg *msg, char *str1, char *str2)
{
	return ds_next_dst(msg, 1/*set host port*/);
}


/**
 *
 */
static int w_ds_mark_dst0(struct sip_msg *msg, char *str1, char *str2)
{
	return ds_mark_dst(msg, 0);
}


/**
 *
 */
static int w_ds_mark_dst1(struct sip_msg *msg, char *str1, char *str2)
{
	if(str1 && (str1[0]=='i' || str1[0]=='I' || str1[0]=='0'))
		return ds_mark_dst(msg, 0);
	else if(str1 && (str1[0]=='p' || str1[0]=='P' || str1[0]=='2'))
		return ds_mark_dst(msg, 2);
	else
		return ds_mark_dst(msg, 1);
}


static int in_list_fixup(void** param, int param_no)
{
	if (param_no==1) {
		/* the ip to test */
		return fixup_pvar(param);
	} else if (param_no==2) {
		/* the port to test */
		if (*param==NULL) {
			return 0;
		} else if ( *((char*)*param)==0 ) {
			pkg_free(*param);
			*param = NULL;
			return 0;
		}
		return fixup_pvar(param);
	} else if (param_no==3) {
		/* the group to check in */
		return fixup_uint(param);
	} else if (param_no==4) {
		/*  active only check ? */
		return fixup_uint(param);
	} else {
		LM_CRIT("bug - too many params (%d) in is_in_list()\n",param_no);
		return -1;
	}
}


static int ds_count_fixup(void** param, int param_no)
{
	char *s;
	int i, code = 0;

	if (param_no > 3)
		return 0;

	s = (char *)*param;
	i = strlen(s);

	switch (param_no)
	{
		case 1:
			return fixup_igp(param);
		case 2:

		while (i--)
		{
			switch (s[i])
			{
				/* active */
				case 'a':
				case 'A':
				case '1':
					code |= DS_COUNT_ACTIVE;
					break;

				/* inactive */
				case 'i':
				case 'I':
				case '0':
					code |= DS_COUNT_INACTIVE;
					break;

				/* probing */
				case 'p':
				case 'P':
				case '2':
					code |= DS_COUNT_PROBING;
					break;
			}
		}
		break;

		case 3:
			return fixup_igp(param);
	}

	s[0] = (char)code;
	s[1] = '\0';

	return 0;
}


/************************** MI STUFF ************************/

static struct mi_root* ds_mi_set(struct mi_root* cmd_tree, void* param)
{
	str sp;
	int ret;
	unsigned int group, state;
	struct mi_node* node;

	node = cmd_tree->node.kids;
	if(node == NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);
	sp = node->value;
	if(sp.len<=0 || !sp.s)
	{
		LM_ERR("bad state value\n");
		return init_mi_tree( 500, MI_SSTR("Bad state value") );
	}

	if(sp.s[0]=='0' || sp.s[0]=='I' || sp.s[0]=='i')
		state = 0;
	else if(sp.s[0]=='p' || sp.s[0]=='P' || sp.s[0]=='2')
		state = 2;
	else if(sp.s[0]=='a' || sp.s[0]=='A' || sp.s[0]=='1')
		state = 1;
	else
		return init_mi_tree( 500, MI_SSTR("Bad state value") );

	node = node->next;
	if(node == NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);
	sp = node->value;
	if(sp.s == NULL)
	{
		return init_mi_tree(500, MI_SSTR("group not found"));
	}
	if(str2int(&sp, &group))
	{
		LM_ERR("bad group value\n");
		return init_mi_tree( 500, MI_SSTR("bad group value"));
	}

	node= node->next;
	if(node == NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	sp = node->value;
	if(sp.s == NULL)
	{
		return init_mi_tree(500, MI_SSTR("address not found"));
	}

	if (state==1) {
		/* set active */
		ret = ds_set_state(group, &sp, DS_INACTIVE_DST|DS_PROBING_DST, 0);
	} else if (state==2) {
		/* set probing */
		ret = ds_set_state(group, &sp, DS_PROBING_DST, 1);
		if (ret==0)
			ret = ds_set_state(group, &sp, DS_INACTIVE_DST, 0);
	} else {
		/* set inactive */
		ret = ds_set_state(group, &sp, DS_INACTIVE_DST, 1);
		if (ret == 0)
			ret = ds_set_state(group, &sp, DS_PROBING_DST, 0);
	}

	if(ret!=0)
		return init_mi_tree(404, MI_SSTR("destination not found"));

	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
}


static struct mi_root* ds_mi_list(struct mi_root* cmd_tree, void* param)
{
	struct mi_root* rpl_tree;

	rpl_tree = init_mi_tree(200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==NULL)
		return 0;
	rpl_tree->node.flags |= MI_IS_ARRAY;

	if( ds_print_mi_list(&rpl_tree->node)< 0 )
	{
		LM_ERR("failed to add node\n");
		free_mi_tree(rpl_tree);
		return 0;
	}

	return rpl_tree;
}

#define MI_ERR_RELOAD 			"ERROR Reloading data"
#define MI_ERR_RELOAD_LEN 		(sizeof(MI_ERR_RELOAD)-1)
static struct mi_root* ds_mi_reload(struct mi_root* cmd_tree, void* param)
{
	if (ds_reload_db()<0)
		return init_mi_tree(500, MI_ERR_RELOAD, MI_ERR_RELOAD_LEN);

	return init_mi_tree(200, MI_SSTR(MI_OK_S));
}


static int w_ds_is_in_list2(struct sip_msg *msg, char *ip, char *port)
{
	return ds_is_in_list(msg, (pv_spec_t*)ip, (pv_spec_t*)port, -1, 0);
}


static int w_ds_is_in_list3(struct sip_msg *msg,char *ip,char *port,char *set)
{
	return ds_is_in_list(msg,(pv_spec_t*)ip,(pv_spec_t*)port,(int)(long)set,0);
}


static int w_ds_is_in_list4(struct sip_msg *msg,char *ip,char *port,char *set,
															char *active_only)
{
	return ds_is_in_list(msg,(pv_spec_t*)ip,(pv_spec_t*)port,
		(int)(long)set, (int)(long)active_only);
}


static int w_ds_count(struct sip_msg* msg, char *set, const char *cmp, char *res)
{
	int s = 0;
	gparam_p ret = (gparam_p) res;

	if (fixup_get_ivalue(msg, (gparam_p)set, &s)!=0)
	{
		LM_ERR("No dst set value\n");
		return -1;
	}

	if (ret->type != GPARAM_TYPE_PVS && ret->type != GPARAM_TYPE_PVE)
	{
		LM_ERR("Result must be a pvar!\n");
		return -1;
	}

	return ds_count(msg, s, cmp, ret->v.pvs);
}


int check_options_rplcode(int code)
{
	int i;

	for (i =0; i< options_codes_no; i++)
	{
		if(options_reply_codes[i] == code)
			return 1;
	}

	return 0;
}


