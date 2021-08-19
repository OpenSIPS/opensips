/*
 * Copyright (C) 2005-2009 Voice Sistem SRL
 *
 * This file is part of Open SIP Server (OpenSIPS).
 *
 * DROUTING OpenSIPS-module is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * DROUTING OpenSIPS-module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>


#include "../../evi/evi.h"
#include "../../map.h"
#include "../../ipc.h"

#include "dr_load.h"
#include "prefix_tree.h"
#include "dr_bl.h"
#include "dr_db_def.h"
#include "dr_partitions.h"
#include "dr_clustering.h"
#include "dr_api.h"
#include "dr_api_internal.h"
#include "dr_cb.h"

#include "../../mem/rpm_mem.h"

#define DR_PARAM_USE_WEIGTH         (1<<0)
#define DR_PARAM_RULE_FALLBACK      (1<<1)
#define DR_PARAM_STRICT_LEN         (1<<2)
#define DR_PARAM_ONLY_CHECK         (1<<3)
#define DR_PARAM_USE_QR             (1<<4)
#define DR_PARAM_INTERNAL_TRIGGERED (1<<30)

#define DRD_TABLE_VER 6
#define DRR_TABLE_VER 4
#define DRG_TABLE_VER 2
#define DRC_TABLE_VER 3
#define PART_TABLE_VER 1

#define MAX_LEN_NAME_W_PART 510 /* max len of variable containing
								   avp_spec and partition name */
#define MI_PART_NAME_S "Partition"
#define MI_PART_NAME_LEN (strlen(MI_PART_NAME_S))

#define MI_LAST_UPDATE_S "Date"
#define MI_LAST_UPDATE_LEN (strlen(MI_LAST_UPDATE_S))

#define MI_DEFAULT_PROBING_STATE	1
#define MI_PROBING_DISABLED_S "Gateways probing disabled from script"

/* probing related stuff */
static unsigned int dr_prob_interval = 30;
static str dr_probe_replies = {NULL,0};
struct tm_binds dr_tmb;
str dr_probe_method = str_init("OPTIONS");
str dr_probe_from = str_init("sip:prober@localhost");
static char *dr_probe_sock_s = NULL;
struct socket_info *dr_probe_sock = NULL;
static int* probing_reply_codes = NULL;
static int probing_codes_no = 0;

/* reload controll parametere */
static int no_concurrent_reload = 0;

/*** DB relatede stuff ***/
/* parameters  */
static str db_url = {NULL,0};
static int dr_persistent_state = 1;
/* DRG use domain */
static int use_domain = 1;
int dr_default_grp = -1;
int dr_force_dns = 1;

/* internal AVP used to store serial RURIs */
static str ruri_avp_spec = str_init("$avp(___dr_ruri__)");

/* internal AVP used to store GW IDs */
static str gw_id_avp_spec = str_init("$avp(___dr_gw_id__)");

/* internal AVP used to store GW socket */
static str gw_sock_avp_spec = str_init("$avp(___dr_sock__)");

/* internal AVP used to store GW ATTRs */
static str gw_attrs_avp_spec = str_init("$avp(___dr_gw_att__)");

/* AVP used to store GW Pri Prefix */
static str gw_priprefix_avp_spec = { NULL, 0};

/* AVP used to store RULE IDs */
static str rule_id_avp_spec = {NULL, 0};

/* internal AVP used to store RULE ATTRs */
static str rule_attrs_avp_spec = str_init("$avp(___dr_ru_att__)");

/* AVP used to store RULE prefix */
static str rule_prefix_avp_spec = {NULL, 0};

/* AVP used to store CARRIER ID */
static str carrier_id_avp_spec = {NULL, 0};

/* internal AVP used to store CARRIER ATTRs */
static str carrier_attrs_avp_spec = str_init("$avp(___dr_cr_att__)");

/* AVP used to store PARTITION ID when using wildcard operator instead of
 * partition name */
static str partition_pvar = {NULL, 0};
pv_spec_t partition_spec;


/* restart persistency */
int dr_rpm_enable = 0;
struct head_cache *dr_cache;

/*
 * global pointers for faster parameter passing between functions
 * meaning: current script pvar to dump attrs in (NULL to ignore)
 */
static pv_spec_p rule_attrs_spec;
static pv_spec_p gw_attrs_spec;
static pv_spec_p carrier_attrs_spec;

/*
 * if the attributes are not used at all in the script,
 * do not store them in their internal AVPs at all --liviu
 */
static int populate_rule_attrs;
static int populate_gw_attrs;
static int populate_carrier_attrs;

/* statistic data */
int tree_size = 0;
int inode = 0;
int unode = 0;
static str attrs_empty = str_init("");

/* configuration loader from db specific stuff */
static str db_partitions_table = str_init("dr_partitions"); /* default url */
static str db_partitions_url;
rw_lock_t *reload_lock; /* lock to protect the partitions while reloading */


//static int use_partitions = 0;
int use_partitions = 0; /* by default don't use db for config */
static struct head_config {
	str partition; /* partition name extracted from database */
	str db_url;
	str drd_table; /* drd_table name extracted from database */
	str drr_table; /* drr_table name extracted from database */
	str drc_table; /* drc_table name extracted from database */
	str drg_table; /* drg_table name extracted from database */
	str gw_priprefix_avp_spec; /* extracted from database - it can be NULL */
	str rule_id_avp_spec;      /* extracted from database - it can be NULL */
	str rule_prefix_avp_spec;  /* extracted from database - it can be NULL */
	str carrier_id_avp_spec;   /* extracted from database - it can be NULL */
	str ruri_avp_spec;  /* extracted from database - has default value */
	str gw_id_avp_spec; /* extracted from database - has default value */
	str gw_sock_avp_spec; /* extracted from database - has default value */
	str gw_attrs_avp_spec; /* extracted from database - has default value */
	str rule_attrs_avp_spec; /* extracted from database - has default value */
	str carrier_attrs_avp_spec; /* extracted from database - has default value */
	struct head_config *next;
} *head_start;
int *n_partitions; /* total number of partitions (does not change at runtime) */

struct head_db *head_db_start;

typedef struct param_prob_callback {
	struct head_db * current_partition;
	unsigned int  _id;
}param_prob_callback_t;

typedef struct dr_partition {
	union {
		struct head_db * part;
		gparam_p part_name;
	} v;

	enum dr_partition_type { DR_PTR_PART, DR_GPARAM_PART, DR_NO_PART } type;
} dr_partition_t;

typedef struct dr_part_group {
	dr_partition_t * dr_part;
	dr_group_t * group;
} dr_part_group_t;

typedef struct dr_part_old {
	dr_partition_t *dr_part;
	gparam_p gw_or_cr; /* gateway or carrier */
} dr_part_old_t;

typedef struct dr_part_cr {
	gparam_p part;
	gparam_p cr;
} dr_part_cr_t;

typedef struct dr_part_gw {
	gparam_p part;
	gparam_p gw;
} dr_part_gw_t;

typedef struct dr_dst_ids {
	int gw_id;
	int cr_id;
} dr_dst_ids_t;


static int get_config_from_db();
static int add_head_config();
struct head_cache *get_head_cache(str *part);
struct head_cache *add_head_cache(str *part);
void clean_head_cache(struct head_cache *c);
void init_head_db(struct head_db *new);
static int db_connect_head(struct head_db*); /* populate a db connection */
static char *extra_prefix_chars;


/* reader-writers lock for reloading the data */
static rw_lock_t *ref_lock = NULL;

static int dr_init(void);
static int dr_child_init(int rank);
static int dr_exit(void);

static int fix_flags(void** param);
static int fix_partition(void** param);
static int fix_rule_attr(void** param);
static int fix_gw_attr(void** param);
static int fix_carr_attr(void** param);
static int w_do_routing(struct sip_msg* msg, int *grp, long flags, str *wl,
		pv_spec_t* rule_att, pv_spec_t* gw_att, pv_spec_t* carr_att,
		struct head_db *part);
static int do_routing(struct sip_msg* msg, struct head_db *part, int grp,
		int flags, str* wl);

static int route2_carrier(struct sip_msg* msg, str* ids,
		pv_spec_t* gw_att, pv_spec_t* carr_att, struct head_db *part);

static int route2_gw(struct sip_msg* msg, str* ids, pv_spec_t* gw_attr,
		struct head_db *part);

static int use_next_gw(struct sip_msg* msg,
		pv_spec_t* rule_att, pv_spec_t* gw_att, pv_spec_t* carr_att,
		struct head_db *part);

#define DR_IFG_STRIP_FLAG      (1<<0)
#define DR_IFG_PREFIX_FLAG     (1<<1)
#define DR_IFG_IDS_FLAG        (1<<3)
#define DR_IFG_IGNOREPORT_FLAG (1<<4)
#define DR_IFG_CARRIERID_FLAG  (1<<5)
static int fix_gw_flags(void** param);
static int _is_dr_gw(struct sip_msg* msg, struct head_db *current_partition,
		int flags, int type, struct ip_addr *ip, unsigned int port);
static int is_from_gw(struct sip_msg* msg, int *type, long flags,
		pv_spec_t* gw_att, struct head_db *part);

static int goes_to_gw(struct sip_msg* msg, int *type, long flags,
		pv_spec_t* gw_att, struct head_db *part);

static int dr_is_gw(struct sip_msg* msg, str *uri, int *type, long flags,
		pv_spec_t* gw_att, struct head_db *part);

static int dr_disable(struct sip_msg *req, struct head_db *current_partition);

static int dr_match(struct sip_msg* msg, int *grp, long flags, str *number,
		pv_spec_t* rule_att, struct head_db *part);


mi_response_t *dr_reload_cmd(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *dr_reload_cmd_1(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_dr_gw_status_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_dr_gw_status_2(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_dr_gw_status_3(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_dr_gw_status_4(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_dr_gw_status_5(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_dr_gw_status_6(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_dr_cr_status_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_dr_cr_status_2(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_dr_cr_status_3(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_dr_cr_status_4(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_dr_cr_status_5(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_dr_cr_status_6(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_dr_number_routing_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_dr_number_routing_2(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_dr_number_routing_3(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_dr_number_routing_4(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_dr_reload_status(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_dr_reload_status_1(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_dr_enable_probing(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_dr_enable_probing_1(const mi_params_t *params,
								struct mi_handler *async_hdl);

/*0-> disabled, 1 ->enabled*/
unsigned int *dr_enable_probing_state=0;

/* sorting functions used by dr */
static void no_sort_cb(void *params);
static void weight_based_sort_cb(void *params);
static int weight_based_sort(pgw_list_t *pgwl, int size, unsigned short *idx);
static int sort_rt_dst(rt_info_t *dr_rule, unsigned short dst_idx, unsigned short *idx);
static inline int get_pgwl_params(struct dr_sort_params *dsp,
		pgw_list_t **pgwl, int *size, unsigned short **sorted_dst);


/* event */
static str dr_event = str_init("E_DROUTING_STATUS");
static event_id_t dr_evi_id;


/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"do_routing", (cmd_function)w_do_routing,
		{ {CMD_PARAM_INT|CMD_PARAM_OPT, NULL, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT, fix_flags, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT, NULL, NULL},
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, fix_rule_attr, NULL},
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, fix_gw_attr, NULL},
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, fix_carr_attr, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fix_partition,NULL},
		  {0 , 0, 0}
		},
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|BRANCH_ROUTE
	},
	{"route_to_carrier", (cmd_function)route2_carrier,
		{ {CMD_PARAM_STR, NULL, NULL},
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, fix_gw_attr, NULL},
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, fix_carr_attr, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fix_partition,NULL},
		  {0 , 0, 0}
		},
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|BRANCH_ROUTE
	},
	{"route_to_gw", (cmd_function)route2_gw,
		{ {CMD_PARAM_STR, NULL, NULL},
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, fix_gw_attr, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fix_partition,NULL},
		  {0 , 0, 0}
		},
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|BRANCH_ROUTE
	},
	{"use_next_gw", (cmd_function)use_next_gw,
		{ {CMD_PARAM_VAR|CMD_PARAM_OPT, fix_rule_attr, NULL},
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, fix_gw_attr, NULL},
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, fix_carr_attr, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fix_partition,NULL},
		  {0 , 0, 0}
		},
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|BRANCH_ROUTE
	},
	{"is_from_gw", (cmd_function)is_from_gw,
		{ {CMD_PARAM_INT|CMD_PARAM_OPT, NULL, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT, fix_gw_flags, NULL},
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, fix_gw_attr, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fix_partition,NULL},
		  {0 , 0, 0}
		},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE
	},
	{"goes_to_gw", (cmd_function)goes_to_gw,
		{ {CMD_PARAM_INT|CMD_PARAM_OPT, NULL, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT, fix_gw_flags, NULL},
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, fix_gw_attr, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fix_partition,NULL},
		  {0 , 0, 0}
		},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE
	},
	{"dr_is_gw", (cmd_function)dr_is_gw,
		{ {CMD_PARAM_STR, NULL, NULL},
		  {CMD_PARAM_INT|CMD_PARAM_OPT, NULL, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT, fix_gw_flags, NULL},
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, fix_gw_attr, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fix_partition,NULL},
		  {0 , 0, 0}
		},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|
		LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE
	},
	{"dr_disable", (cmd_function)dr_disable,
		{ {CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fix_partition,NULL},
		  {0 , 0, 0}
		},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE
	},
	{"dr_match", (cmd_function)dr_match,
		{ {CMD_PARAM_INT, NULL, NULL},                    // dr group
		  {CMD_PARAM_STR|CMD_PARAM_OPT, fix_flags, NULL}, // flags
		  {CMD_PARAM_STR, NULL, NULL},                    // str to check
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, fix_rule_attr, NULL}, // rule attr
		  {CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fix_partition,NULL},
		  {0 , 0, 0}
		},
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE
	},
	{"load_dr", (cmd_function)load_dr,
		{ {0 , 0, 0}
		},
		0
	},
	{0,0,{{0,0,0}},0}
};


/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"use_partitions",    INT_PARAM, &use_partitions    },
	{"db_partitions_url",    STR_PARAM, &db_partitions_url.s },
	{"db_partitions_table", STR_PARAM, &db_partitions_table.s },
	{"db_url",           STR_PARAM, &db_url.s         },
	{"drd_table",        STR_PARAM, &drd_table.s      },
	{"drr_table",        STR_PARAM, &drr_table.s      },
	{"drg_table",        STR_PARAM, &drg_table.s      },
	{"drc_table",        STR_PARAM, &drc_table.s      },
	{"use_domain",       INT_PARAM, &use_domain       },
	{"drg_user_col",     STR_PARAM, &drg_user_col.s   },
	{"drg_domain_col",   STR_PARAM, &drg_domain_col.s },
	{"drg_grpid_col",    STR_PARAM, &drg_grpid_col.s  },
	{"ruri_avp",         STR_PARAM, &ruri_avp_spec.s  },
	{"gw_id_avp",        STR_PARAM, &gw_id_avp_spec.s         },
	{"gw_priprefix_avp", STR_PARAM, &gw_priprefix_avp_spec.s  },
	{"gw_sock_avp",      STR_PARAM, &gw_sock_avp_spec.s       },
	{"rule_id_avp",      STR_PARAM, &rule_id_avp_spec.s       },
	{"rule_prefix_avp",  STR_PARAM, &rule_prefix_avp_spec.s   },
	{"carrier_id_avp",   STR_PARAM, &carrier_id_avp_spec.s    },
	{"force_dns",        INT_PARAM, &dr_force_dns             },
	{"default_group",    INT_PARAM, &dr_default_grp           },
	{"define_blacklist", STR_PARAM|USE_FUNC_PARAM, (void*)set_dr_bl },
	{"probing_interval", INT_PARAM, &dr_prob_interval         },
	{"probing_method",   STR_PARAM, &dr_probe_method.s        },
	{"probing_from",     STR_PARAM, &dr_probe_from.s          },
	{"probing_socket",   STR_PARAM, &dr_probe_sock_s          },
	{"probing_reply_codes",STR_PARAM, &dr_probe_replies.s     },
	{"persistent_state", INT_PARAM, &dr_persistent_state      },
	{"no_concurrent_reload",INT_PARAM, &no_concurrent_reload  },
	{"partition_id_pvar", STR_PARAM, &partition_pvar.s        },
	{"cluster_id",        INT_PARAM, &dr_cluster_id           },
	{"cluster_sharing_tag",STR_PARAM, &dr_cluster_shtag       },
	{"enable_restart_persistency",INT_PARAM, &dr_rpm_enable   },
	{"extra_prefix_chars", STR_PARAM, &extra_prefix_chars     },
	{0, 0, 0}
};


/*
 * Exported MI functions
 */
#define HLP1 "Params: none ; Forces drouting module to reload data from DB "\
	"into memory; A return string is returned only in case of error."
#define HLP2 "Params: [ gw_id [ status ]] ; Sets/gets the status of a GW; "\
	"If no gw_id is given, all gws will be listed; if a new status is give, "\
"it will be pushed to the given GW."
#define HLP3 "Params: [ carrier_id [ status ]] ; Sets/gets the status of a " \
	"carrier; If no carrier_id is given, all carrier will be listed; if a " \
"new status is give, it will be pushed to the given carrier."
#define HLP4 "Params: [partition] [group_id] number ; List the gateways a "\
	"number will match when searching through the rules from a specific group. "\
"The partition parameter must be defined only if use_partitions = 1."
#define HLP5 "Params: [partition]; List the time of the last dr_reload"\
	" (load from database) for all partitions if no parameter is supplied, or"\
" for a partition given as parameter. If use_partitions is 0, you should"\
" not specify a partition."
#define HLP6 "Params: [ enable ] ; Enables probing of gateways if parameter "\
	"value greater than 0. Disables probing of gateways if parameter"\
"value is 0. With no parameter, returns current probing status"

static mi_export_t mi_cmds[] = {
	{ "dr_reload", HLP1, 0, 0, {
		{dr_reload_cmd, {0}},
		{dr_reload_cmd_1, {"partition_name", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "dr_gw_status", HLP2, MI_NAMED_PARAMS_ONLY, 0, {
		{mi_dr_gw_status_1, {0}},
		{mi_dr_gw_status_2, {"partition_name", 0}},
		{mi_dr_gw_status_3, {"gw_id", 0}},
		{mi_dr_gw_status_4, {"gw_id", "status", 0}},
		{mi_dr_gw_status_5, {"partition_name", "gw_id", 0}},
		{mi_dr_gw_status_6, {"partition_name", "gw_id", "status", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "dr_carrier_status", HLP3, MI_NAMED_PARAMS_ONLY, 0, {
		{mi_dr_cr_status_1, {0}},
		{mi_dr_cr_status_2, {"partition_name", 0}},
		{mi_dr_cr_status_3, {"carrier_id", 0}},
		{mi_dr_cr_status_4, {"carrier_id", "status", 0}},
		{mi_dr_cr_status_5, {"partition_name", "carrier_id", 0}},
		{mi_dr_cr_status_6, {"partition_name", "carrier_id", "status", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "dr_number_routing", HLP4, MI_NAMED_PARAMS_ONLY, 0, {
		{mi_dr_number_routing_1, {"number", 0}},
		{mi_dr_number_routing_2, {"group_id", "number", 0}},
		{mi_dr_number_routing_3, {"partition_name", "number", 0}},
		{mi_dr_number_routing_4, {"partition_name", "group_id", "number", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "dr_reload_status", HLP5, 0, 0, {
		{mi_dr_reload_status, {0}},
		{mi_dr_reload_status_1, {"partition_name", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "dr_enable_probing", HLP6, 0, 0, {
		{mi_dr_enable_probing, {0}},
		{mi_dr_enable_probing_1, {"status", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static module_dependency_t *get_deps_probing_interval(param_export_t *param)
{
	if (*(int *)param->param_pointer <= 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_DEFAULT, "tm", DEP_ABORT);
}

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_SQLDB, NULL, DEP_ABORT },

		/* if present, qrouting must first load its profiles,
		 * so they can be looked up during DRCB_RLD_INIT_RULE */
		{ MOD_TYPE_DEFAULT, "qrouting", DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "probing_interval", get_deps_probing_interval },
		{ "cluster_id",       get_deps_clusterer},
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"drouting",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,            /* Exported functions */
	0,               /* Exported async functions */
	params,          /* Exported parameters */
	0,               /* exported statistics */
	mi_cmds,         /* exported MI functions */
	0,               /* exported pseudo-variables */
	0,			 	 /* exported transformations */
	0,               /* additional processes */
	0,               /* Module pre-initialization function */
	dr_init,         /* Module initialization function */
	(response_function) 0,
	(destroy_function) dr_exit,
	(child_init_function) dr_child_init, /* per-child init function */
	0                /* reload confirm function */
};


/** Probing Section **/

static int check_options_rplcode(int code)
{
	int i;

	for (i =0; i< probing_codes_no; i++) {
		if(probing_reply_codes[i] == code)
			return 1;
	}

	return 0;
}


static str dr_partition_str = str_init("partition");
static str dr_gwid_str = str_init("gwid");
static str dr_address_str = str_init("address");
static str dr_status_str = str_init("status");
static str dr_inactive_str = str_init("inactive");
static str dr_active_str = str_init("active");
static str dr_disabled_str = str_init("disabled MI");
static str dr_probing_str = str_init("probing");


void dr_raise_event(struct head_db *p, pgw_t *gw)
{
	evi_params_p list;
	str *txt;

	if (dr_evi_id == EVI_ERROR || !evi_probe_event(dr_evi_id))
		return;

	list = evi_get_params();
	if (!list) {
		LM_ERR("cannot create event params\n");
		return;
	}

	if (evi_param_add_str(list, &dr_partition_str, &p->partition) < 0) {
		LM_ERR("cannot add partition\n");
		goto error;
	}

	if (evi_param_add_str(list, &dr_gwid_str, &gw->id) < 0) {
		LM_ERR("cannot add gwid\n");
		goto error;
	}

	if (evi_param_add_str(list, &dr_address_str, &gw->ip_str) < 0) {
		LM_ERR("cannot add address\n");
		goto error;
	}

	if (gw->flags&DR_DST_STAT_DSBL_FLAG) {
		if (gw->flags&DR_DST_STAT_NOEN_FLAG)
			txt = &dr_disabled_str;
		else if (gw->flags&DR_DST_PING_DSBL_FLAG)
			txt = &dr_probing_str;
		else
			txt = &dr_inactive_str;
	} else {
		txt = &dr_active_str;
	}

	if (evi_param_add_str(list, &dr_status_str, txt) < 0) {
		LM_ERR("cannot add state\n");
		goto error;
	}

	if (evi_raise_event(dr_evi_id, list)) {
		LM_ERR("unable to send dr event\n");
	}
	return;

error:
	evi_free_params(list);
}


static void dr_gw_status_changed(struct head_db *p, pgw_t *gw)
{
	/* do Cluster replication*/
	replicate_dr_gw_status_event( p, gw);

	/* raise the event */
	dr_raise_event( p, gw);
}


static int dr_disable(struct sip_msg *req, struct head_db * current_partition)
{
	struct usr_avp *avp;
	int_str id_val;
	pgw_t *gw;

	if (current_partition==NULL) {
		LM_ERR("Partition name is mandatory!\n");
		return -1;
	}

	lock_start_read( current_partition->ref_lock );

	avp = search_first_avp( AVP_VAL_STR, current_partition->gw_id_avp,
		&id_val,0);
	if (avp==NULL) {
		LM_DBG(" no AVP ID ->nothing to disable\n");
		lock_stop_read( current_partition->ref_lock );
		return -1;
	}

	gw = get_gw_by_id(current_partition->rdata->pgw_tree, &id_val.s );
	if (gw!=NULL && (gw->flags&DR_DST_STAT_DSBL_FLAG)==0) {
		LM_DBG("partition : %.*s\n", current_partition->partition.len,
				current_partition->partition.s);
		gw->flags |= DR_DST_STAT_DSBL_FLAG|DR_DST_STAT_DIRT_FLAG;
		dr_gw_status_changed( current_partition, gw);
	}

	lock_stop_read( current_partition->ref_lock );

	return 1;
}


static void dr_probing_callback( struct cell *t, int type,
		struct tmcb_params *ps )
{
	int code = ps->code;
	pgw_t *gw;
	int _id ;
	struct head_db * current_partition;

	if (!ps->param || !*ps->param) {
		LM_CRIT("BUG - reply to a DR probe with no ID (code=%d)\n", ps->code);
		return;
	}

	if( !((param_prob_callback_t*)*ps->param)->current_partition ) {
		LM_CRIT("BUG - no partition supplied to callback function\n");
		return ;
	}

	current_partition=((param_prob_callback_t*)*ps->param)->current_partition;

	lock_start_read( current_partition->ref_lock );

	_id = ((param_prob_callback_t*)*ps->param)->_id;

	gw = get_gw_by_internal_id(current_partition->rdata->pgw_tree, _id);
	if (gw==NULL)
		goto end;

	if ((code == 200) || check_options_rplcode(code)) {
		/* re-enable to DST  (if allowed) */
		if ( (gw->flags&DR_DST_STAT_NOEN_FLAG)!=0 ||  /* permanently disabled */
				(gw->flags&DR_DST_STAT_DSBL_FLAG)==0)         /* not disabled at all */
			goto end;
		gw->flags &= ~DR_DST_STAT_DSBL_FLAG;
		gw->flags |= DR_DST_STAT_DIRT_FLAG;
		dr_gw_status_changed( current_partition, gw);
		goto end;
	}

	if (code>=400 && (gw->flags&DR_DST_STAT_DSBL_FLAG)==0) {
		gw->flags |= DR_DST_STAT_DSBL_FLAG|DR_DST_STAT_DIRT_FLAG;
		dr_gw_status_changed( current_partition, gw);
		goto end;
	}


end:
	lock_stop_read( current_partition->ref_lock );

	return;
}


static void dr_prob_handler(unsigned int ticks, void* param)
{
	static char buff[1000] = {"sip:"};
	/* do probing */
	pgw_t *dst;
	param_prob_callback_t *params;
	dlg_t *dlg;
	str uri;

	void** dest;
	map_iterator_t map_it;

	struct head_db *it = head_db_start;

	if ((*dr_enable_probing_state) == 0 ||
	!dr_cluster_shtag_is_active() )
		return;

	while( it!=NULL ) {
		if (it->rdata==NULL)
			return;

		lock_start_read( it->ref_lock );

		/* go through all destinations */
		for (map_first(it->rdata->pgw_tree, &map_it);
				iterator_is_valid(&map_it); iterator_next(&map_it)) {

			dest = iterator_val(&map_it);
			if (dest==NULL)
				break;

			dst = (pgw_t*)*dest;

			/* dst requires probing ? */
			if ( dst->flags&DR_DST_STAT_NOEN_FLAG
					|| !( (dst->flags&DR_DST_PING_PERM_FLAG)  ||  /*permanent probing*/
						( dst->flags&DR_DST_PING_DSBL_FLAG
						  && dst->flags&DR_DST_STAT_DSBL_FLAG  /*probing on disable*/
						)
						)
			   ) {
				continue;
			}

			memcpy(buff + 4, dst->ip_str.s, dst->ip_str.len);
			uri.s = buff;
			uri.len = dst->ip_str.len + 4;

			/* Execute the Dialog using the "request"-Method of the
			 * TM-Module.*/
			if (dr_tmb.new_auto_dlg_uac(&dr_probe_from, &uri, NULL, NULL,
			     dst->sock?dst->sock:dr_probe_sock, &dlg)!=0) {
				LM_ERR("failed to create new TM dlg\n");
				continue;
			}
			dlg->state = DLG_CONFIRMED;

			params = shm_malloc(sizeof(param_prob_callback_t));
			if( params==0 ) {
				LM_ERR("no more shm memory!\n");
				return;
			}
			params->_id = dst->_id;
			params->current_partition = it;

			if (dr_tmb.t_request_within(&dr_probe_method, NULL, NULL, dlg,
			dr_probing_callback, (void*)params, osips_shm_free)<0) {
				LM_ERR("unable to execute dialog, disabling destination...\n");
				if ( (dst->flags&DR_DST_STAT_DSBL_FLAG)==0 ) {
					dst->flags |= DR_DST_STAT_DSBL_FLAG|DR_DST_STAT_DIRT_FLAG;
					dr_gw_status_changed( it, dst);
				}

				shm_free(params);
			}
			dr_tmb.free_dlg(dlg);

		}

		lock_stop_read( it->ref_lock );
		it = it->next;
	}
}


static void dr_state_flusher(struct head_db* hd)
{
	static db_ps_t cr_ps=NULL, gw_ps=NULL;
	pgw_t *gw;
	pcr_t *cr;
	db_key_t key_cmp;
	db_val_t val_cmp;
	db_key_t key_set;
	db_val_t val_set;

	void** dest;
	map_iterator_t it;

	if(!hd) {
		LM_ERR(" Bug - no head supplied to dr_state_flusher\n");
	}

	/* is data avaialable? */
	if (!hd || !hd->rdata)
		return;

	val_cmp.type = DB_STR;
	val_cmp.nul  = 0;

	val_set.type = DB_INT;
	val_set.nul  = 0;

	/* update the gateways */
	if ((hd->db_funcs).use_table( (*hd->db_con), &(hd->drd_table)) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", hd->drd_table.len, hd->drd_table.s);
		return;
	}
	key_cmp = &gwid_drd_col;
	key_set = &state_drd_col;

	/* iterate the gateways */
	for (map_first(hd->rdata->pgw_tree , &it);
			iterator_is_valid(&it); iterator_next(&it)) {

		dest = iterator_val(&it);
		if (dest==NULL)
			break;

		gw = (pgw_t*)*dest;

		if ( (gw->flags & DR_DST_STAT_DIRT_FLAG)==0 )
			/* nothing to do for this gateway */
			continue;

		/* populate the update */
		val_cmp.val.str_val = gw->id;
		val_set.val.int_val = (gw->flags&DR_DST_STAT_DSBL_FLAG) ? ((gw->flags&DR_DST_STAT_NOEN_FLAG)?1:2) : (0);

		/* update the state of this gateway */
		LM_DBG("updating the state of gw <%.*s> to %d\n",
				gw->id.len, gw->id.s, val_set.val.int_val);

		CON_PS_REFERENCE(*hd->db_con) = gw_ps;
		if ( (hd->db_funcs).update(*hd->db_con,&key_cmp,0,&val_cmp,&key_set,&val_set,1,1)<0 ) {
			LM_ERR("DB update failed\n");
		} else {
			gw->flags &= ~DR_DST_STAT_DIRT_FLAG;
		}
	}

	/* update the carriers */
	if ((hd->db_funcs).use_table( *hd->db_con, &(hd->drc_table)) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", hd->drc_table.len, hd->drc_table.s);
		return;
	}
	key_cmp = &cid_drc_col;
	key_set = &state_drc_col;

	/* iterate the carriers */
	for (map_first(hd->rdata->carriers_tree, &it);
			iterator_is_valid(&it); iterator_next(&it)) {

		dest = iterator_val(&it);
		if (dest==NULL)
			break;

		cr = (pcr_t*)*dest;

		if ( (cr->flags & DR_CR_FLAG_DIRTY)==0 )
			/* nothing to do for this carrier */
			continue;

		/* populate the update */
		val_cmp.val.str_val = cr->id;
		val_set.val.int_val = (cr->flags&DR_CR_FLAG_IS_OFF) ? 1 : 0;

		/* update the state of this carrier */
		LM_DBG("updating the state of cr <%.*s> to %d\n",
				cr->id.len, cr->id.s, val_set.val.int_val);

		CON_PS_REFERENCE(*hd->db_con) = cr_ps;
		if ( (hd->db_funcs).update(*hd->db_con,&key_cmp,0,&val_cmp,&key_set,&val_set,1,1)<0 ) {
			LM_ERR("DB update failed\n");
		} else {
			cr->flags &= ~DR_CR_FLAG_DIRTY;
		}
	}

	return;
}

/* Flushes to DB the state of carriers and gateways (if modified)
 * Locking is done to protect the data consistency */
static void dr_state_timer(unsigned int ticks, void* param)
{
	struct head_db * it;
	it = head_db_start;
	while( it!=NULL ) {
		lock_start_read( it->ref_lock );

		dr_state_flusher(it);

		lock_stop_read( it->ref_lock );
		it = it->next;
	}
}

/*
 * if none is successfully loaded return
 * -1, else return 0
 */

static inline int dr_reload_data_head(struct head_db *hd,
                           str *part_name, int initial)
{
	rt_data_t *new_data;
	rt_data_t *old_data;
	pgw_t *gw, *old_gw;
	pcr_t *cr, *old_cr;
	time_t rawtime;
	struct head_cache *cache = NULL;
	struct dr_prepare_part_params pp;

	void **dest;
	map_iterator_t it;

	if (no_concurrent_reload) {
		lock_get( hd->ref_lock->lock );
		if (hd->ongoing_reload) {
			lock_release( hd->ref_lock->lock );
			LM_WARN("Reload already in progress, discarding this one\n");
			return -2;
		}
		hd->ongoing_reload = 1;
		lock_release( hd->ref_lock->lock );
	}

	if (initial && hd->cache && hd->cache->rdata) {
		LM_INFO("starting drouting with cache data %p->%p!\n", hd->cache, hd->cache->rdata);
		dr_update_head_cache(hd);
		goto success;
	}

	pp.part_name = *part_name;
	run_dr_cbs(DRCB_RLD_PREPARE_PART, &pp);

	LM_INFO("loading drouting data!\n");
	new_data = dr_load_routing_info(hd, dr_persistent_state);
	if ( new_data==0 ) {
		LM_CRIT("failed to load routing info\n");
		goto error;
	}

	lock_start_write( hd->ref_lock );

	/* no more activ readers -> do the swapping */
	old_data = hd->rdata;
	hd->rdata = new_data;
	/* update the time of the last reload for the current partition */
	time(&rawtime);
	hd->time_last_update = rawtime;

	/* update cache head */
	if (hd->cache)
		hd->cache->rdata = new_data;

	lock_stop_write( (hd->ref_lock) );

	/* destroy old data */
	if (old_data) {
		/* copy the state of gw/cr from old data */
		/* interate new gws and search them into old data */
		for (map_first(new_data->pgw_tree, &it);
				iterator_is_valid(&it); iterator_next(&it)) {
			dest = iterator_val(&it);
			if(dest==NULL)
				break;

			gw=(pgw_t *)*dest;

			old_gw = get_gw_by_id( old_data->pgw_tree, &gw->id);
			if (old_gw) {
				gw->flags &= ~DR_DST_STAT_MASK;
				gw->flags |= old_gw->flags&DR_DST_STAT_MASK;
			}
		}
		/* interate new crs and search them into old data */
		for (map_first(new_data->carriers_tree, &it);
				iterator_is_valid(&it); iterator_next(&it)) {
			dest = iterator_val(&it);
			if(dest==NULL)
				break;

			cr=(pcr_t *)*dest;


			old_cr = get_carrier_by_id( old_data->carriers_tree, &cr->id);
			if (old_cr) {
				cr->flags &= ~DR_CR_FLAG_IS_OFF;
				cr->flags |= old_cr->flags&DR_CR_FLAG_IS_OFF;
			}
		}

		/* free old data */
		free_rt_data(old_data, hd->free);
	}

	/* generate new blacklist from the routing info */
	populate_dr_bls(hd->rdata->pgw_tree);

success:
	if (no_concurrent_reload)
		hd->ongoing_reload = 0;
	return 0;

error:
	if (no_concurrent_reload)
		hd->ongoing_reload = 0;
	if (cache)
		clean_head_cache(cache);
	return -1;
}

static inline int dr_reload_data(int initial)
{
	struct head_db *part;
	int ret_val = 0;

	for (part = head_db_start; part; part = part->next)
		if (dr_reload_data_head(part, &part->partition, initial) != 0)
			ret_val = -1;

	/* make the new list the main list used by qrouting */
	lock_start_write(reload_lock);
	run_dr_cbs(DRCB_RLD_FINALIZE, NULL);
	lock_stop_write(reload_lock);

	return ret_val;
}


#define dr_fix_avp_def_w_default( _pv_spec, _avp_id, _default, _name) \
	do { \
		if(_pv_spec.s == NULL) { \
			if(use_partitions) { \
				_pv_spec.len = _default.len + it_head_config->partition.len; \
				_pv_spec.s = shm_malloc((_pv_spec.len)); \
				if (!_pv_spec.s) { \
					LM_ERR("could not allocate pv spec!\n"); \
					continue; \
				} \
				memcpy(_pv_spec.s, _default.s, _default.len - 1); \
				memcpy(_pv_spec.s + _default.len - 1, \
						it_head_config->partition.s, \
						it_head_config->partition.len); \
				_pv_spec.s[_pv_spec.len - 1] = ')'; \
				LM_DBG("name with partition:%.*s\n", _pv_spec.len,  _pv_spec.s); \
			} else \
				shm_str_dup(&_pv_spec, &_default); \
		} \
		dr_fix_avp_definition(_pv_spec, _avp_id, _name); \
	} while (0)

#define dr_fix_avp_definition(_pv_spec, _avp_id, _name) \
	do { \
		if (pv_parse_spec( &_pv_spec, &avp_spec) == 0 \
				|| avp_spec.type != PVT_AVP) { \
			_pv_spec.len = strlen(_pv_spec.s); \
			LM_ERR("malformed or non AVP [%.*s] for %s AVP definition\n",\
					_pv_spec.len, _pv_spec.s, _name); \
			continue; \
		} \
		if (pv_get_avp_name(0, &(avp_spec.pvp), &_avp_id, &dummy) !=0 ) { \
			LM_ERR("[%.*s]- invalid AVP definition for %s AVP\n", \
					_pv_spec.len, _pv_spec.s, _name); \
			continue; \
		} \
	} while(0)

#define add_partition_to_avp_name(_name) \
	do { \
		name_w_part.len = sizeof(_name) + it_head_config->partition.len - 1; \
		memcpy(name_w_part.s, _name, sizeof(_name) - 1); \
		memcpy(name_w_part.s + sizeof(_name) - 1, \
				it_head_config->partition.s, it_head_config->partition.len); \
	} while (0)


static int cleanup_head_config( struct head_config *hd)
{
	if (hd == NULL)
		return 0;

	if (hd->db_url.s)
		shm_free(hd->db_url.s);
	if (hd->drd_table.s && hd->drd_table.s != drd_table.s)
		shm_free(hd->drd_table.s);
	if (hd->drr_table.s && hd->drr_table.s != drr_table.s)
		shm_free(hd->drr_table.s);
	if (hd->drc_table.s && hd->drc_table.s != drc_table.s)
		shm_free(hd->drc_table.s);
	if (hd->drg_table.s && hd->drg_table.s != drg_table.s)
		shm_free(hd->drg_table.s);

	if(hd->gw_priprefix_avp_spec.s)
		shm_free(hd->gw_priprefix_avp_spec.s);
	if(hd->rule_id_avp_spec.s)
		shm_free(hd->rule_id_avp_spec.s);
	if(hd->rule_prefix_avp_spec.s)
		shm_free(hd->rule_prefix_avp_spec.s);
	if(hd->carrier_attrs_avp_spec.s)
		shm_free(hd->carrier_attrs_avp_spec.s);
	if(hd->ruri_avp_spec.s)
		shm_free(hd->ruri_avp_spec.s);
	if(hd->gw_id_avp_spec.s)
		shm_free(hd->gw_id_avp_spec.s);
	if(hd->gw_sock_avp_spec.s)
		shm_free(hd->gw_sock_avp_spec.s);
	if(hd->gw_attrs_avp_spec.s)
		shm_free(hd->gw_attrs_avp_spec.s);
	if(hd->rule_attrs_avp_spec.s)
		shm_free(hd->rule_attrs_avp_spec.s);
	if(hd->carrier_id_avp_spec.s)
		shm_free(hd->carrier_id_avp_spec.s);

	return 0;
}


static void cleanup_head_db(struct head_db *hd)
{
	if (!hd)
		return;

	if (hd->db_con && *(hd->db_con))
		hd->db_funcs.close(*(hd->db_con));
	if( hd->ref_lock )
		lock_destroy_rw( ref_lock );
	if (hd->partition.s)
		shm_free(hd->partition.s);
	if (hd->db_url.s)
		shm_free( hd->db_url.s );
	if (hd->drd_table.s && hd->drd_table.s != drd_table.s)
			shm_free(hd->drd_table.s);
	if (hd->drr_table.s && hd->drr_table.s != drr_table.s)
		shm_free(hd->drr_table.s);
	if( hd->drc_table.s && hd->drc_table.s != drc_table.s)
		shm_free(hd->drc_table.s);
	if( hd->drg_table.s && hd->drg_table.s != drg_table.s)
		shm_free(hd->drg_table.s);
}

static void cleanup_head_db_table(void)
{
	struct head_db * it_head_db = 0;
	struct head_db * last_cleaned = 0;

	it_head_db = head_db_start;
	while (it_head_db) {

		cleanup_head_db(it_head_db);
		last_cleaned = it_head_db;
		it_head_db = it_head_db->next;
		shm_free(last_cleaned);
	}
	head_start = 0;
}

static void cleanup_head_config_table(void)
{
	struct head_config * it_head_config = 0;
	struct head_config * last_cleaned = 0;

	it_head_config = head_start;
	while (it_head_config) {

		cleanup_head_config(it_head_config);
		last_cleaned = it_head_config;
		it_head_config = it_head_config->next;
		shm_free(last_cleaned);
	}
	head_start = 0;
}

#define head_from_extern_param( _dst, _src, _name)\
	do { \
		if ((_src).s && ((_src).len = strlen((_src).s)) != 0) {\
			if (shm_str_dup( &(_dst), &(_src)) != 0) \
				LM_ERR(" Fail duplicating extern param (%s) to head\n", _name);\
		}\
	}while(0)

void init_head_w_extern_params(void) {

	head_from_extern_param( head_start->rule_id_avp_spec,
			rule_id_avp_spec, "rule_id_avp_spec");

	head_from_extern_param( head_start->rule_prefix_avp_spec,
			rule_prefix_avp_spec, "rule_prefix_avp_spec");

	head_from_extern_param( head_start->carrier_id_avp_spec,
			carrier_id_avp_spec, "carrier_id_avp_spec");

	head_from_extern_param( head_start->ruri_avp_spec,
			ruri_avp_spec, "ruri_avp_spec");

	head_from_extern_param( head_start->gw_id_avp_spec,
			gw_id_avp_spec, "gw_id_avp_spec");

	head_from_extern_param( head_start->gw_sock_avp_spec,
			gw_sock_avp_spec, "gw_sock_avp_spec");

	head_from_extern_param( head_start->gw_attrs_avp_spec,
			gw_attrs_avp_spec, "gw_attrs_avp_spec");

	head_from_extern_param( head_start->gw_priprefix_avp_spec,
			gw_priprefix_avp_spec, "gw_priprefix_avp_spec");

	head_from_extern_param( head_start->rule_attrs_avp_spec,
			rule_attrs_avp_spec, "rule_attrs_avp_spec");

	head_from_extern_param( head_start->carrier_attrs_avp_spec,
			carrier_attrs_avp_spec, "carrier_attrs_avp_spec");
}

void clean_head_cache(struct head_cache *c)
{
	struct head_cache_socket *s, *old;
	free_rt_data(c->rdata, rpm_free_func);
	for (s = c->sockets; s; ) {
		old = s;
		s = s->next;
		rpm_free(old);
	}
	rpm_free(c);
}

struct head_cache *add_head_cache(str *part)
{
	struct head_cache *c = rpm_malloc(sizeof(*c) + part->len);
	if (!c) {
		LM_ERR("cannot allocate persistent mem for cache head!\n");
		return NULL;
	}
	c->partition.s = (char *)(c + 1);
	c->partition.len = part->len;
	memcpy(c->partition.s, part->s, part->len);
	c->rdata = 0;
	c->next = dr_cache;
	dr_cache = c;
	rpm_key_set("drouting", dr_cache);

	return c;
}

struct head_cache *get_head_cache(str *part)
{
	struct head_cache *cache_h;

	for (cache_h = dr_cache; cache_h; cache_h = cache_h->next)
		if (cache_h->partition.len == part->len &&
				memcmp(cache_h->partition.s, part->s, part->len) == 0)
			return cache_h;
	return NULL;
}

void fix_cache_sockets(struct head_cache *cache)
{
	struct head_cache_socket *prev, *csock, *free;
	struct socket_info *sock;

	prev = NULL;
	csock = cache->sockets;
	while (csock) {
		sock = grep_internal_sock_info(&csock->host, csock->port, csock->proto);
		if (!sock) {
			LM_ERR("socket <%.*s:%d> (%d) is not local to "
					"OpenSIPS (we must listen on it) -> ignoring socket\n",
					csock->host.len, csock->host.s, csock->port, csock->proto);
			free = csock;
			csock = csock->next;
			if (prev)
				prev->next = csock;
			else
				cache->sockets = csock;

			rpm_free(free);
		} else {
			csock->new_sock = sock;
			prev = csock;
			csock = csock->next;
		}
	}
}

void update_cache_info(void)
{
	struct head_config * it_head_config = 0;
	struct head_cache *cache_h, *prev_h = NULL, *free_h;

	if (!dr_cache)
		return;

	/* now that we know the names of all partitions, cleanup old partitions */
	cache_h = dr_cache;
	while (cache_h) {
		for (it_head_config = head_start; it_head_config != NULL;
				it_head_config = it_head_config->next) {
			if (cache_h->partition.len == it_head_config->partition.len &&
					memcmp(cache_h->partition.s, it_head_config->partition.s,
						it_head_config->partition.len) == 0)
				break;
		}
		if (it_head_config != NULL) {
			prev_h = cache_h;
			cache_h = cache_h->next;
			continue;
		}
		LM_WARN("%.*s partition no longer used - cleaning old data!\n",
				cache_h->partition.len, cache_h->partition.s);


		if (!prev_h) {
			dr_cache = cache_h->next;
			rpm_key_set("drouting", dr_cache);
		} else {
			prev_h->next = cache_h->next;
		}
		free_h = cache_h;
		cache_h = cache_h->next;
		clean_head_cache(free_h);
	}
}

static int dr_init(void)
{
	pv_spec_t avp_spec;
	unsigned short dummy;
	str name_w_part;
	struct head_cache *cache = NULL;
	struct head_config * it_head_config = 0;
	struct head_db *db_part = NULL;
	char name_w_buf[MAX_LEN_NAME_W_PART];
	name_w_part.s = name_w_buf;

	LM_INFO("dynamic routing - initializing\n");
	reload_lock = lock_init_rw();
	if (!reload_lock) {
		LM_ERR("failed to init rw lock for dr_reload\n");
		return -1;
	}

	n_partitions = shm_malloc(sizeof *n_partitions);
	if (!n_partitions) {
		LM_ERR("oom\n");
		return -1;
	}
	*n_partitions = 0;

	drd_table.len = strlen(drd_table.s);
	drg_table.len = strlen(drg_table.s);
	drr_table.len = strlen(drr_table.s);
	drc_table.len = strlen(drc_table.s);

	if (dr_rpm_enable) {
		/* if we are using cache, we need to fetch our dr zone */
		if (rpm_init_mem() < 0) {
			LM_ERR("could not initilize restart persistency memory!\n");
			return -1;
		}
		dr_cache = (struct head_cache *)rpm_key_get("drouting");
		if (!dr_cache)
			LM_INFO("starting drouting with empty cache\n");
		else
			LM_INFO("starting drouting with cache head=%p\n", dr_cache);

		LM_NOTICE("using %ld MB of restart-persistent memory, allocator: %s\n",
		          rpm_mem_size/1024/1024, mm_str(mem_allocator_rpm));
	}

	/* register dr callbacks for sorting */
	if (register_dr_cb(DRCB_SORT_DST, no_sort_cb, (void *)NO_SORT, NULL) < 0) {
		LM_ERR("failed to register no_sort cb\n");
		return -1;
	}

	if (register_dr_cb(DRCB_SORT_DST, weight_based_sort_cb,
				(void *)WEIGHT_BASED_SORT, NULL) < 0) {
		LM_ERR("failed to register weight_based_sort cb\n");
		return -1;
	}

	name_w_part.s = shm_malloc( MAX_LEN_NAME_W_PART /* length of
													   fixed string */);
		if( name_w_part.s == 0 ) {
			LM_ERR(" No more shm memory [drouting:name_w_part.s]\n");
			goto error;
		}

	if( use_partitions == 1 ) { /* loading configurations from db */
		if (get_config_from_db() == -1) {
			LM_ERR("Failed to get configuration from db_config\n");
			return -1;
		}

		if (partition_pvar.s) {
			partition_pvar.len = strlen(partition_pvar.s);
			/* just reusing avp_spec; no need to be an AVP to work */
			if (pv_parse_spec(&partition_pvar, &partition_spec) == 0) {
				LM_ERR("malformed PV string: <<%s>>\n", partition_pvar.s);
				return -1;
			}

			if (partition_spec.setf == NULL) {
				LM_ERR("Partition_id_pvar is not WRITABLE!\n");
				return -1;
			}
		}
	} else {
		init_db_url(db_url, 0);

		add_head_config();

		/* if not empty save to head_config structure */
		if (drd_table.s[0]==0) {
			LM_CRIT("mandatory parameter \"DRD_TABLE\" found empty\n");
			goto error_cfg;
		}
		head_start->drd_table.s = shm_malloc(drd_table.len);
		if (head_start->drd_table.s == 0) {
			LM_ERR(" no more shm memory [drouting:head_start->drd_table.s]\n");
			goto error_cfg;
		}
		memcpy(head_start->drd_table.s, drd_table.s, drd_table.len);
		head_start->drd_table.len = drd_table.len;

		if (drr_table.s[0]==0) {
			LM_CRIT("mandatory parameter \"DRR_TABLE\" found empty\n");
			goto error_cfg;
		}
		head_start->drr_table.s = shm_malloc(drr_table.len);
		if (head_start->drr_table.s == 0) {
			LM_ERR("no more shm memory [drouting:head_start->drr_table.s]\n");
			goto error_cfg;
		}
		memcpy(head_start->drr_table.s, drr_table.s, drr_table.len);
		head_start->drr_table.len = drr_table.len;

		if (drg_table.s[0] == 0) {
			LM_CRIT("mandatory parameter \"DRG_TABLE\" found empty\n");
			goto error_cfg;
		}
		head_start->drg_table.s = shm_malloc(drg_table.len);
		if (head_start->drg_table.s == 0) {
			LM_ERR("no more shm memory [drouting:head_start->drg_table.s]\n");
			goto error_cfg;
		}
		memcpy(head_start->drg_table.s, drg_table.s, drg_table.len);
		head_start->drg_table.len = drg_table.len;

		if (drc_table.s[0] == 0) {
			LM_CRIT("mandatory parameter \"DRC_TABLE\" found empty\n");
			goto error_cfg;
		}
		head_start->drc_table.s = shm_malloc(drc_table.len);
		if (head_start->drc_table.s == 0) {
			LM_ERR("no more shm memory [drouting:head_start->drc_table.s]\n");
			goto error_cfg;
		}
		memcpy(head_start->drc_table.s, drc_table.s, drc_table.len);
		head_start->drc_table.len = drc_table.len;

		head_start->db_url.len = db_url.len;
		head_start->db_url.s = shm_malloc(db_url.len);
		if( head_start->db_url.s == 0 ) {
			LM_ERR("no more shm memory [drouting:head_start->db_url.s]\n");
			goto error_cfg;
		}
		memcpy(head_start->db_url.s, db_url.s, db_url.len );

		init_head_w_extern_params();

		head_start->partition.s = "Default";
		head_start->partition.len = strlen(head_start->partition.s);
	}

	update_cache_info();

	if (init_prefix_tree( extra_prefix_chars )!=0) {
		LM_ERR("failed to initiate the prefix array\n");
		goto error;
	}

	drg_user_col.len = strlen(drg_user_col.s);
	drg_domain_col.len = strlen(drg_domain_col.s);
	drg_grpid_col.len = strlen(drg_grpid_col.s);

	for (it_head_config = head_start; it_head_config != NULL;
			it_head_config = it_head_config->next) {

		db_part = shm_malloc(sizeof(struct head_db));
		if (!db_part) {
			LM_ERR("could not allocate db part!\n");
			goto error_cfg;
		}
		init_head_db(db_part);

		if(shm_str_dup(&db_part->db_url, &it_head_config->db_url) != 0) {
			LM_ERR("shm_str_dup failed for db_url\n");
			goto error_cfg;
		}

		if(shm_str_dup(&db_part->partition, &it_head_config->partition) != 0) {
			LM_ERR("shm_str_dup failed for partition name\n");
			goto error_cfg;
		}

		if (!it_head_config->drd_table.s) {
			db_part->drd_table.s = drd_table.s;
			db_part->drd_table.len = drd_table.len;
		} else if (shm_str_dup(&db_part->drd_table, &it_head_config->drd_table) != 0) {
			LM_ERR("shm_str_dup failed for DRD table\n");
			goto error_cfg;
		}

		if (!it_head_config->drr_table.s) {
			db_part->drr_table.s = drr_table.s;
			db_part->drr_table.len = drr_table.len;
		} else if (shm_str_dup(&db_part->drr_table, &it_head_config->drr_table) != 0) {
			LM_ERR("shm_str_dup failed for DRR table\n");
			goto error_cfg;
		}

		if (!it_head_config->drc_table.s) {
			db_part->drc_table.s = drc_table.s;
			db_part->drc_table.len = drc_table.len;
		} else if (shm_str_dup(&db_part->drc_table, &it_head_config->drc_table) != 0) {
			LM_ERR("shm_str_dup failed for DRC table\n");
			goto error_cfg;
		}

		if (!it_head_config->drg_table.s) {
			db_part->drg_table.s = drg_table.s;
			db_part->drg_table.len = drg_table.len;
		} else if (shm_str_dup(&db_part->drg_table, &it_head_config->drg_table) != 0) {
			LM_ERR("shm_str_dup failed for DRG table\n");
			goto error_cfg;
		}

		/* fix specs for internal AVP (used for fallback) */
		/* partition name is added to AVP name */
		add_partition_to_avp_name("_dr_dst_ids_");
		if ( parse_avp_spec( &name_w_part, &db_part->acc_call_params_avp)!=0 ) {
			LM_ERR("failed to init internal AVP for dst IDs\n");
			goto error_cfg;
		}

		add_partition_to_avp_name("_dr_fb_ruri_");
		if (parse_avp_spec(&name_w_part, &db_part->avpID_store_ruri) != 0) {
			LM_ERR("failed to init internal AVP for ruri\n");
			goto error_cfg;
		}

		add_partition_to_avp_name("_dr_fb_prefix_");
		if (parse_avp_spec(&name_w_part, &db_part->avpID_store_prefix) != 0) {
			LM_ERR("failed to init internal AVP for prefix\n");
			goto error_cfg;
		}

		add_partition_to_avp_name("_dr_fb_index_");
		if (parse_avp_spec(&name_w_part, &db_part->avpID_store_index) != 0) {
			LM_ERR("failed to init internal AVP for index\n");
			goto error_cfg;
		}

		add_partition_to_avp_name("_dr_fb_whitelist_");
		if (parse_avp_spec(&name_w_part, &db_part->avpID_store_whitelist) != 0) {
			LM_ERR("failed to init internal AVP for whitelist\n");
			goto error_cfg;
		}

		add_partition_to_avp_name("_dr_fb_group_");
		if (parse_avp_spec(&name_w_part, &db_part->avpID_store_group) != 0) {
			LM_ERR("failed to init internal AVP for group\n");
			goto error_cfg;
		}

		add_partition_to_avp_name("_dr_fb_flags_");
		if (parse_avp_spec(&name_w_part, &db_part->avpID_store_flags) != 0) {
			LM_ERR("failed to init internal AVP for flags\n");
			goto error_cfg;
		}

		/* fix AVP specs for parameters */
		dr_fix_avp_def_w_default(it_head_config->ruri_avp_spec,
				db_part->ruri_avp, ruri_avp_spec, "RURI");

		dr_fix_avp_def_w_default(it_head_config->gw_id_avp_spec,
				db_part->gw_id_avp, gw_id_avp_spec, "GW ID");

		dr_fix_avp_def_w_default(it_head_config->gw_sock_avp_spec,
				db_part->gw_sock_avp, gw_sock_avp_spec, "GW SOCKET");

		dr_fix_avp_def_w_default(it_head_config->gw_attrs_avp_spec,
				db_part->gw_attrs_avp, gw_attrs_avp_spec, "GW ATTRS");

		dr_fix_avp_def_w_default(it_head_config->rule_attrs_avp_spec,
				db_part->rule_attrs_avp, rule_attrs_avp_spec, "RULE ATTRS");

		dr_fix_avp_def_w_default(it_head_config->carrier_attrs_avp_spec,
				db_part->carrier_attrs_avp, carrier_attrs_avp_spec, "CARRIER ATTRS");

		if (it_head_config->gw_priprefix_avp_spec.s) {
			dr_fix_avp_definition(it_head_config->gw_priprefix_avp_spec,
					db_part->gw_priprefix_avp, "GW PRI PREFIX");
		}

		if (it_head_config->rule_id_avp_spec.s) {
			dr_fix_avp_definition(it_head_config->rule_id_avp_spec,
					db_part->rule_id_avp, "RULE ID");
		}

		if (it_head_config->rule_prefix_avp_spec.s) {
			dr_fix_avp_definition(it_head_config->rule_prefix_avp_spec,
					db_part->rule_prefix_avp, "RULE PREFIX");
		}

		if (it_head_config->carrier_id_avp_spec.s) {
			dr_fix_avp_definition(it_head_config->carrier_id_avp_spec,
					db_part->carrier_id_avp, "CARRIER ID");
		}

		/* create & init lock */
		if ((db_part->ref_lock = lock_init_rw()) == NULL) {
			LM_CRIT("failed to init lock\n");
			goto error_cfg;
		}

		db_part->db_con = pkg_malloc(sizeof(db_con_t *));
		if (!db_part->db_con) {
			LM_ERR("could not allocate db_connection in pkg mem!\n");
			goto error_cfg;
		}

		/* bind to the SQL module */
		if (db_bind_mod( &(db_part->db_url), &( db_part->db_funcs ))) {
			LM_CRIT("cannot bind to database module! "
					"Did you forget to load a database module ? (%.*s)\n",
					db_url.len, db_url.s);
			goto error_cfg;
		}

		if( (*db_part->db_con =
					db_part->db_funcs.init(&db_part->db_url)) == 0) {
			LM_ERR("failed to connect to db url <%.*s>\n",
				db_part->db_url.len, db_part->db_url.s);
			goto error_cfg;
		}

		if (!DB_CAPABILITY( db_part->db_funcs, DB_CAP_QUERY)) {
			LM_CRIT("database modules does not "
				"provide QUERY functions needed by DRouting module\n");
			goto error_cfg;
		}

		if(db_check_table_version(&db_part->db_funcs, *db_part->db_con,
					&db_part->drd_table, DRD_TABLE_VER) < 0) {
			LM_ERR("error during table version check (dr_gateways "
				"table \'%.*s\', for partition \'%.*s\')\n",
				db_part->drd_table.len, db_part->drd_table.s,
				db_part->partition.len, db_part->partition.s);
			goto error_cfg;
		}

		if(db_check_table_version(&db_part->db_funcs, *db_part->db_con,
					&db_part->drr_table, DRR_TABLE_VER) < 0) {
			LM_ERR("error during table version check (dr_rules table \'%.*s\',"
				" for partition \'%.*s\')\n", db_part->drr_table.len,
				db_part->drr_table.s, db_part->partition.len,
				db_part->partition.s);
			goto error_cfg;
		}

		if(db_check_table_version(&db_part->db_funcs, *db_part->db_con,
					&db_part->drg_table, DRG_TABLE_VER) < 0) {
			LM_ERR("error during table version check (dr_groups table \'%.*s\',"
				" for partition \'%.*s\')\n", db_part->drg_table.len,
				db_part->drg_table.s, db_part->partition.len,
				db_part->partition.s);
			goto error_cfg;
		}

		if(db_check_table_version(&db_part->db_funcs, *db_part->db_con,
					&db_part->drc_table, DRC_TABLE_VER) < 0) {
			LM_ERR("error during table version check (dr_carriers "
				"table \'%.*s\', for partition \'%.*s\')\n",
				db_part->drc_table.len, db_part->drc_table.s,
				db_part->partition.len, db_part->partition.s);
			goto error_cfg;
		}

		(db_part->db_funcs).close(*db_part->db_con);
		*db_part->db_con = 0;

		/* all good now - add the partition to the list */
		db_part->next = head_db_start;
		head_db_start = db_part;
		db_part->malloc = shm_malloc_func;
		db_part->free = shm_free_func;

		/* check where we'll be storing data */
		if (dr_rpm_enable) {
			cache = get_head_cache(&db_part->partition);
			if (!cache)
				cache = add_head_cache(&db_part->partition);
			if (!cache) {
				LM_CRIT("could not create cache head - might leak new data!\n");
				LM_WARN("loading data in shared memory!\n");
			} else {
				db_part->cache = cache;
				db_part->malloc = rpm_malloc_func;
				db_part->free = rpm_free_func;
				fix_cache_sockets(cache);
			}
		}
	}
	/* all good now - release the config */
	cleanup_head_config_table();

	if (init_dr_bls(head_db_start)!=0) {
		LM_ERR("failed to init DR blacklists\n");
		goto error;
	}

	dr_enable_probing_state =(unsigned int *) shm_malloc(sizeof(unsigned int));
	if (!dr_enable_probing_state) {
		LM_ERR("no shmem left\n");
		goto error;
	}
	*dr_enable_probing_state = MI_DEFAULT_PROBING_STATE;

	if (dr_prob_interval) {

		str host;
		int port,proto;

		/* load TM API */
		if (load_tm_api(&dr_tmb)!=0) {
			LM_ERR("can't load TM API\n");
			goto error;
		}

		/* parse and look for the socket to ping from */
		if (dr_probe_sock_s && dr_probe_sock_s[0]!=0 ) {
			if (parse_phostport( dr_probe_sock_s, strlen(dr_probe_sock_s),
			&host.s, &host.len, &port, &proto)!=0 ) {
				LM_ERR("socket description <%s> is not valid\n",
					dr_probe_sock_s);
				goto error;
			}
			dr_probe_sock = grep_internal_sock_info( &host, port, proto);
			if (dr_probe_sock==NULL) {
				LM_ERR("socket <%s> is not local to opensips (we must listen "
					"on it\n", dr_probe_sock_s);
				goto error;
			}
		}

		/* probing method */
		dr_probe_method.len = strlen(dr_probe_method.s);
		dr_probe_from.len = strlen(dr_probe_from.s);
		if (dr_probe_replies.s)
			dr_probe_replies.len = strlen(dr_probe_replies.s);

		/* register pinger function */
		if (register_timer( "dr-pinger", dr_prob_handler, NULL,
					dr_prob_interval, TIMER_FLAG_DELAY_ON_DELAY)<0) {
			LM_ERR("failed to register probing handler\n");
			goto error;
		}

		if (dr_probe_replies.s) {
			dr_probe_replies.len = strlen(dr_probe_replies.s);
			if(parse_reply_codes( &dr_probe_replies, &probing_reply_codes,
						&probing_codes_no )< 0) {
				LM_ERR("Bad format for options_reply_code parameter"
						" - Need a code list separated by commas\n");
				goto error;
			}
		}

	}

	if (dr_persistent_state) {
		/* register function to flush changes in state */
		if (register_timer("dr-flush", dr_state_timer, NULL, 30,
		TIMER_FLAG_SKIP_ON_DELAY)<0) {
			LM_ERR("failed to register state flush handler\n");
			goto error;
		}
	}
	LM_DBG("All in place in the init. Will return 0\n");

	dr_evi_id = evi_publish_event(dr_event);
	if (dr_evi_id == EVI_ERROR) {
		LM_ERR("cannot register %.*s event\n", dr_event.len, dr_event.s);
		goto error;
	}

	if (dr_cluster_id>0 && dr_init_cluster()<0) {
		LM_ERR("failed to initialized the clustering support\n");
		goto error;
	}

	return 0;

error_cfg:
	cleanup_head_config_table();
	if (db_part) {
		cleanup_head_db(db_part);
		shm_free(db_part);
	}
error:
	cleanup_head_db_table();
	return -1;
}
#undef add_partition_to_avp_name


static int db_connect_head(struct head_db *x) {

	if( *(x->db_con) ) {
		LM_INFO("db_con already present\n");
		return 1;
	}
	if( x->db_url.s && (*(x->db_con) = x->db_funcs.init(&(x->db_url)))==0 ) {
		LM_ERR("cannot initialize database connection"
				"(partition:%.*s, db_url:%.*s, len:%d)\n", x->partition.len,
				x->partition.s, x->db_url.len, x->db_url.s, x->db_url.len);
		return -1;
	}
	return 0;
}


/* simple wrapper over dr_reload_data to make it compatible with ipc_rpc_f,
 * so triggerable via IPC */
static void rpc_dr_reload_data(int sender_id, void *unused)
{
	dr_reload_data(1);

	dr_cluster_sync();
}


static int dr_child_init(int rank)
{
	struct head_db *db = head_db_start;

	LM_DBG("Child initialization on rank %d \n",rank);

	for (db = head_db_start; db; db = db->next) {
		if (db_connect_head(db) < 0) {
			LM_ERR("failed to create DB connection\n");
			return -1;
		}
	}

	/* if child 1, send a job for itself to run the data loading after
	 * the init sequance is done */
	if ( (rank==1) && ipc_send_rpc( process_no, rpc_dr_reload_data, NULL)<0) {
		LM_CRIT("failed to RPC the data loading\n");
		return -1;
	}

	return 0;
}


static int dr_exit(void)
{
	struct head_db * it = head_db_start, *to_clean;

	while( it!=NULL ) {
		to_clean = it;
		it = it->next;
		if (dr_persistent_state && !to_clean->cache && 
		db_connect_head(to_clean)==0 ) {
			dr_state_flusher(to_clean);

			(to_clean->db_funcs).close(*(to_clean->db_con));
			*(to_clean->db_con) = 0;
			pkg_free(to_clean->db_con);
		}

		/* destroy data */
		if (to_clean->rdata && !to_clean->cache) {
			free_rt_data(to_clean->rdata, to_clean->free);
			to_clean->rdata = 0;
		}

		/* destroy lock */
		if (to_clean->ref_lock) {
			lock_destroy_rw( to_clean->ref_lock );
			to_clean->ref_lock = 0;
		}

		/* free table names stored in head_db */
		if(to_clean->drd_table.s && to_clean->drd_table.s != drd_table.s) {
			shm_free(to_clean->drd_table.s);
		}

		if(to_clean->drr_table.s && to_clean->drr_table.s != drr_table.s) {
			shm_free(to_clean->drr_table.s);
		}

		if(to_clean->drc_table.s && to_clean->drc_table.s != drc_table.s) {
			shm_free(to_clean->drc_table.s);
		}

		if(to_clean->drg_table.s && to_clean->drg_table.s != drg_table.s) {
			shm_free(to_clean->drg_table.s);
		}

		shm_free(to_clean);
	}

	if (dr_enable_probing_state)
		shm_free(dr_enable_probing_state);

	/* destroy blacklists */
	destroy_dr_bls();

	/* destroy all callbacks */
	destroy_dr_cbs();

	return 0;
}

static mi_response_t *mi_dr_get_partition(const mi_params_t *params,
									struct head_db **partition)
{
	str part_name;

	if (!use_partitions)
		return init_mi_error_extra(400,
			MI_SSTR("Invalid parameter: 'partition_name'"),
			MI_SSTR("'partition_name' supported only when 'use_partitions' is set"));

	if (get_mi_string_param(params, "partition_name",
		&part_name.s, &part_name.len) < 0)
		return init_mi_param_error();

	if((*partition = get_partition(&part_name)) == NULL) {
		LM_ERR("Partition not found\n");
		return init_mi_error(404, MI_SSTR("Partition not found"));
	}

	return NULL;
}

mi_response_t *dr_reload_cmd(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	LM_INFO("dr_reload MI command received!\n");

	if (dr_reload_data(0) != 0) {
		LM_CRIT("failed to load routing data\n");
		return init_mi_error(500, MI_SSTR("Failed to reload"));
	}

	if (dr_cluster_id && dr_cluster_sync() < 0)
		return init_mi_error(500, MI_SSTR("Failed to synchronize states from cluster"));

	return init_mi_result_ok();
}

mi_response_t *dr_reload_cmd_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct head_db *part;
	mi_response_t *resp;

	LM_INFO("dr_reload MI command received!\n");

	resp = mi_dr_get_partition(params, &part);
	if (resp)
		return resp;

	if (dr_reload_data_head(part, &part->partition, 0) < 0) {
		LM_CRIT("Failed to load data head\n");
		return init_mi_error(500, MI_SSTR("Failed to reload"));
	}

	/* put the new part in use within qrouting */
	lock_start_write(reload_lock);
	run_dr_cbs(DRCB_RLD_FINALIZE, NULL);
	lock_stop_write(reload_lock);

	if (dr_cluster_id && dr_cluster_sync() < 0)
		return init_mi_error(500, MI_SSTR("Failed to synchronize from cluster"));

	return init_mi_result_ok();
}


static inline int get_group_id(struct sip_uri *uri, struct head_db *
		current_partition)
{
	db_key_t keys_ret[1];
	db_key_t keys_cmp[2];
	db_val_t vals_cmp[2];
	db_res_t* res = 0;
	int n;

	/* user */
	keys_cmp[0] = &drg_user_col;
	vals_cmp[0].type = DB_STR;
	vals_cmp[0].nul  = 0;
	vals_cmp[0].val.str_val = uri->user;
	n = 1;

	if (use_domain) {
		keys_cmp[1] = &drg_domain_col;
		vals_cmp[1].type = DB_STR;
		vals_cmp[1].nul  = 0;
		vals_cmp[1].val.str_val = uri->host;
		n++;
	}

	keys_ret[0] = &drg_grpid_col;
	res = 0;


	if( (current_partition->db_funcs).use_table(*(current_partition->db_con),
				&(current_partition->drg_table))<0 ) {
		LM_ERR("cannot select table \"%.*s\"\n",
				(current_partition->drg_table).len,
				(current_partition->drg_table).s);
		goto error;
	}
	if ( (current_partition->db_funcs).query(*(current_partition->db_con),
				keys_cmp,0,vals_cmp,keys_ret,n,1,0,&res)<0 ) {
		LM_ERR("DB query failed\n");
		goto error;
	}

	if (RES_ROW_N(res) == 0) {
		if (dr_default_grp!=-1) {
			(current_partition->db_funcs).free_result
				(*(current_partition->db_con), res);
			return dr_default_grp;
		}
		LM_ERR("no group for user "
				"\"%.*s\"@\"%.*s\"\n", uri->user.len, uri->user.s,
				uri->host.len, uri->host.s);
		goto error;
	}
	if (res->rows[0].values[0].nul || res->rows[0].values[0].type!=DB_INT) {
		LM_ERR("null or non-integer group_id\n");
		goto error;
	}
	n = res->rows[0].values[0].val.int_val;

	(current_partition->db_funcs).free_result(*(current_partition->db_con), res);
	return n;
error:
	if (res)
		(current_partition->db_funcs).free_result(*(current_partition->db_con)
				, res);
	return -1;
}



static inline str* build_ruri(struct sip_uri *uri, int strip, str *pri,
		str *hostport)
{
	static str uri_str;
	int user_len;
	char *p;

	if (uri->user.len<=strip)
		strip = uri->user.len;
	user_len = uri->user.len - strip + pri->len;

	uri_str.len = 4 /*sip:*/ + user_len;
	if (uri->passwd.s && uri->passwd.len)
		uri_str.len += uri->passwd.len+1;
	if ((uri->passwd.s && uri->passwd.len) || user_len > 0)
		uri_str.len++; /*@*/

	uri_str.len += hostport->len +
		(uri->params.s?(uri->params.len+1):0) +
		(uri->headers.s?(uri->headers.len+1):0);

	if ( (uri_str.s=(char*)pkg_malloc( uri_str.len + 1))==0) {
		LM_ERR("no more pkg mem\n");
		return 0;
	}

	p = uri_str.s;
	*(p++)='s';
	*(p++)='i';
	*(p++)='p';
	*(p++)=':';
	if (pri->len) {
		memcpy(p, pri->s, pri->len);
		p += pri->len;
	}
	memcpy(p, uri->user.s+strip, uri->user.len-strip);
	p += uri->user.len-strip;
	if (uri->passwd.s && uri->passwd.len) {
		*(p++)=':';
		memcpy(p, uri->passwd.s, uri->passwd.len);
		p += uri->passwd.len;
	}
	if ((uri->passwd.s && uri->passwd.len) || user_len > 0)
		*(p++)='@';
	memcpy(p, hostport->s, hostport->len);
	p += hostport->len;
	if (uri->params.s && uri->params.len) {
		*(p++)=';';
		memcpy(p, uri->params.s, uri->params.len);
		p += uri->params.len;
	}
	if (uri->headers.s && uri->headers.len) {
		*(p++)='?';
		memcpy(p, uri->headers.s, uri->headers.len);
		p += uri->headers.len;
	}
	*p = 0;

	if (p-uri_str.s!=uri_str.len) {
		LM_CRIT("difference between allocated(%d)"
				" and written(%d)\n",uri_str.len,(int)(long)(p-uri_str.s));
		return 0;
	}
	return &uri_str;
}


static int w_do_routing(struct sip_msg* msg, int *grp, long flags, str *wl,
				pv_spec_t* rule_att, pv_spec_t* gw_att, pv_spec_t* carr_att,
														struct head_db *part)
{
	rule_attrs_spec = rule_att;
	gw_attrs_spec = gw_att;
	carrier_attrs_spec = carr_att;

	return do_routing( msg, part, grp?*grp:-1, (int)flags, wl);
}


static int use_next_gw(struct sip_msg* msg,
		pv_spec_t* rule_att, pv_spec_t* gw_att, pv_spec_t* carr_att,
		struct head_db *part)
{
	struct head_db * current_partition;
	struct usr_avp *avp, *avp_ru, *avp_sk;
	struct dr_acc_call_params *acp;
	unsigned int flags;
	int grp;
	str *wl_list;
	int_str val;
	pv_value_t pv_val;
	str ruri;
	int ok = 0;
	pgw_t * dst;
	struct socket_info *sock;

	if(part==NULL) {
		LM_ERR("Partition is mandatory for use_next_gw.\n");
		return -1;
	}
	current_partition = part;

	rule_attrs_spec = (pv_spec_p)rule_att;
	gw_attrs_spec = (pv_spec_p)gw_att;
	carrier_attrs_spec = (pv_spec_p)carr_att;

	/*
	 * pop a value from each AVP
	 * (also remove all bogus non-STR top-most values)
	 */
	while(1)
	{
		if (rule_attrs_spec) {
			avp = search_first_avp(0, current_partition->rule_attrs_avp,
				&val, NULL);
			if (avp) {
				pv_val.flags = PV_VAL_STR;
				pv_val.rs = val.s;
				if (pv_set_value(msg, rule_attrs_spec, 0, &pv_val) != 0)
					LM_ERR("failed to set value for rule attrs pvar\n");
			}
		}

		/* remove the old attrs */
		if (gw_attrs_spec) {
			avp = NULL;
			do {
				if (avp) destroy_avp(avp);
				avp = search_first_avp( 0, current_partition->gw_attrs_avp,
					NULL, NULL);
			}while (avp && (avp->flags&AVP_VAL_STR)==0 );
			if (avp) destroy_avp(avp);

			avp = search_first_avp(0, current_partition->gw_attrs_avp, &val,
				NULL);
			if (avp) {
				pv_val.flags = PV_VAL_STR;
				pv_val.rs = val.s;
				if (pv_set_value(msg, gw_attrs_spec, 0, &pv_val) != 0)
					LM_ERR("failed to set value for gateway attrs pvar\n");
			}
		}

		/* remove the old carrier attrs */
		if (carrier_attrs_spec) {
			avp = NULL;
			do {
				if (avp) destroy_avp(avp);
				avp = search_first_avp(0, current_partition->carrier_attrs_avp,
					NULL, NULL);
			}while (avp && (avp->flags&AVP_VAL_STR)==0 );
			if (avp) destroy_avp(avp);

			avp = search_first_avp(0, current_partition->carrier_attrs_avp,
				&val, NULL);
			if (avp) {
				pv_val.flags = PV_VAL_STR;
				pv_val.rs = val.s;
				if (pv_set_value(msg, carrier_attrs_spec, 0, &pv_val) != 0)
					LM_ERR("failed to set value for carrier attrs pvar\n");
			}
		}

		/* remove the old priprefix */
		if (current_partition->gw_priprefix_avp!=-1) {
			avp = NULL;
			do {
				if (avp) destroy_avp(avp);
				avp = search_first_avp( 0, current_partition->gw_priprefix_avp,
					NULL, NULL);
			}while (avp && (avp->flags&AVP_VAL_STR)==0 );
			if (avp) destroy_avp(avp);
		}

		/* remove the old carrier ID */
		if (current_partition->carrier_id_avp!=-1) {
			avp = NULL;
			do {
				if (avp) destroy_avp(avp);
				avp = search_first_avp( 0, current_partition->carrier_id_avp,
					NULL, NULL);
			}while (avp && (avp->flags&AVP_VAL_STR)==0 );
			if (avp) destroy_avp(avp);
		}

		/* remove old gw ID and search next one */
		avp = NULL;
		do {
			if (avp) destroy_avp(avp);
			avp = search_first_avp( 0, current_partition->gw_id_avp,
					NULL, NULL);
		}while (avp && (avp->flags&AVP_VAL_STR)==0 );
		if (!avp) {
			LM_WARN("no GWs found at all -> have you done do_routing "
				"in script ?? \n");
			return -1;
		}
		do {
			if (avp) destroy_avp(avp);
			avp = search_first_avp( 0, current_partition->gw_id_avp,
					NULL, NULL);
		}while (avp && (avp->flags&AVP_VAL_STR)==0 );
		/* any GW found ? */
		if (!avp)
			goto rule_fallback;

		/* search for the first RURI AVP containing a string */
		avp_ru = NULL;
		do {
			if (avp_ru) destroy_avp(avp_ru);
			avp_ru = search_first_avp( 0, current_partition->ruri_avp,
					&val, NULL);
		}while (avp_ru && (avp_ru->flags&AVP_VAL_STR)==0 );

		if (!avp_ru)
			goto rule_fallback;
		ruri = val.s;

		/* search for the first SOCK AVP containing a string */
		avp_sk = NULL;
		do {
			if (avp_sk) destroy_avp(avp_sk);
			avp_sk = search_first_avp( 0, current_partition->gw_sock_avp,
					&val, NULL);
		}while (avp_sk && (avp_sk->flags&AVP_VAL_STR)==0 );
		if (!avp_sk) {
			/* this shuold not happen, it is a bogus state */
			sock = NULL;
		} else {
			if (sscanf( val.s.s, "%p", (void**)&sock ) != 1)
				sock = NULL;
			destroy_avp(avp_sk);
		}

		avp_sk = NULL;
		do {
			if (avp_sk) destroy_avp(avp_sk);
			avp_sk = search_first_avp( 0, current_partition->acc_call_params_avp,
					&val, NULL);
		} while (avp_sk && !(avp_sk->flags & AVP_VAL_STR));

		if (avp_sk) {
			acp = (struct dr_acc_call_params *)val.s.s;
			acp->msg = msg;

			run_dr_cbs(DRCB_ACC_CALL, acp);
			destroy_avp(avp_sk);
		}

		LM_DBG("new RURI set to <%.*s> via socket <%.*s>\n",
				ruri.len, ruri.s,
				sock?sock->name.len:4, sock?sock->name.s:"none");

		/* get value for next gw ID from avp */
		get_avp_val(avp, &val);

		/* we have an ID, so we can check the GW state */
		lock_start_read(current_partition->ref_lock );
		dst = get_gw_by_id(current_partition->rdata->pgw_tree, &val.s);
		if (dst && (dst->flags & DR_DST_STAT_DSBL_FLAG) == 0)
			ok = 1;

		lock_stop_read( current_partition->ref_lock );

		if ( ok )
			break;

		/* search for the next available GW*/
		destroy_avp(avp_ru);
	}

	if (set_ruri( msg, &ruri)==-1) {
		LM_ERR("failed to rewite RURI\n");
		return -1;
	}
	if (sock)
		msg->force_send_socket = sock;

	destroy_avp(avp_ru);

	return 1;

rule_fallback:
	LM_DBG("using rule fallback\n");

	/* check if a "flags" AVP is there and if fallback allowed */
	avp = search_first_avp( 0, current_partition->avpID_store_flags,
			&val, NULL);
	if (avp==NULL || !(val.n & DR_PARAM_RULE_FALLBACK) )
		return -1;

	/* fallback allowed, fetch the rest of data from AVPs */
	flags = val.n | DR_PARAM_INTERNAL_TRIGGERED;

	if (!search_first_avp( 0, current_partition->avpID_store_group,
				&val, NULL)) {
		LM_ERR("Cannot find group AVP during a fallback\n");
		goto fallback_failed;
	}
	grp = val.n;

	if (!search_first_avp( AVP_VAL_STR,
	current_partition->avpID_store_whitelist, &val, NULL)) {
		wl_list = NULL;
	} else {
		wl_list = &val.s;
		wl_list->s[--wl_list->len] = 0;
	}

	if (do_routing( msg, current_partition, grp, flags, wl_list)==1) {
		return 1;
	}

fallback_failed:
	/* prevent any more fallback by removing the flags AVP */
	destroy_avp(avp);
	return -1;
}


#define resize_dr_sort_buffer( _buf, _old_size, _new_size, _error) \
	do { \
		if (_new_size > _old_size) { \
			/* need a larger buffer */ \
			_buf = (unsigned short*)pkg_realloc( _buf, \
				_new_size *sizeof(unsigned short) ); \
			if (_buf==NULL) { \
				LM_ERR("no more pkg mem (needed  %ld)\n", \
					_new_size*sizeof(unsigned short));\
				_old_size = 0; \
				goto _error;\
			}\
			_old_size = _new_size; \
		} \
	}while(0) \

static inline int get_pgwl_params(struct dr_sort_params *dsp,
		pgw_list_t **pgwl, int *size, unsigned short **sorted_dst)
{
	if (dsp->dst_idx == (unsigned short)-1) {
		*pgwl = dsp->dr_rule->pgwl;
		*size = dsp->dr_rule->pgwa_len;
	} else { /* it is a carrier */
		if (dsp->dst_idx >= 0 && dsp->dst_idx < dsp->dr_rule->pgwa_len) {
			if (dsp->dr_rule->pgwl[dsp->dst_idx].is_carrier) {
				*pgwl = dsp->dr_rule->pgwl[dsp->dst_idx].dst.carrier->pgwl;
				*size = dsp->dr_rule->pgwl[dsp->dst_idx].dst.carrier->pgwa_len;
			} else {
				LM_WARN("provided destination for sorting is not a carrier\n");
				return -1;
			}
		} else {
			LM_WARN("no destination with this id (%d)\n", dsp->dst_idx);
			return -1;
		}
	}

	*sorted_dst = dsp->sorted_dst;
	return 0;
}

#define DR_MAX_GWLIST	64

static int sort_rt_dst(rt_info_t *dr_rule, unsigned short dst_idx,
		unsigned short *idx)
{
	struct dr_sort_params dsp;
	pgw_list_t *_;
	int i;
	int size;
	unsigned short *__;
	unsigned char sort_alg;

	memset(&dsp, 0, sizeof dsp);
	dsp.dr_rule = dr_rule;
	dsp.dst_idx = dst_idx;
	dsp.sorted_dst = idx;

	if (get_pgwl_params(&dsp, &_, &size, &__) < 0) {
		LM_ERR("failed to extract params\n");
		return -1;
	}

	/* extract the sorting algorithm */
	if (dst_idx == (unsigned short)-1) /* destination is a gw */
		sort_alg = dr_rule->sort_alg;
	else /* destination is a carrier */
		sort_alg = dr_rule->pgwl[dst_idx].dst.carrier->sort_alg;

	run_dr_sort_cbs(sort_alg, &dsp);
	if (dsp.rc != 0) {
		LM_ERR("failed to sort destinations (%d)\n", dsp.rc);
		return -1;
	}

	LM_DBG("Sorted destination list:\n");
	for (i = 0; i < size; i++)
		LM_DBG("%d\n", idx[i]);

	return 0;
}

/* preserve the order of the destinations */
static void no_sort_cb(void *params)
{
	struct dr_sort_params *dsp = (struct dr_sort_params *)params;
	int i = 0;
	unsigned short *sorted_dst = NULL;
	int size = 0;
	pgw_list_t *pgwl = NULL;
	int rc = 0;

	rc = get_pgwl_params(dsp, &pgwl, &size, &sorted_dst);
	if (rc < 0) {
		LM_ERR("failed to sort\n");
		dsp->rc = -1;
		return;
	}

	for (i = 0; i < size; i++)
		sorted_dst[i] = i;

	dsp->rc = 0; /* everything ok */
}

/* sort based on the weight of the gws */
static void weight_based_sort_cb(void *params)
{
	pgw_list_t *pgwl;
	int size;
	int rc;
	unsigned short *sorted_dst;
	struct dr_sort_params *dsp = (struct dr_sort_params *)params;

	rc = get_pgwl_params(dsp, &pgwl, &size, &sorted_dst);
	if (rc < 0) {
		LM_WARN("failed to sort\n");
		dsp->rc = -1;
		return;
	}

	if (weight_based_sort(pgwl, size, sorted_dst) < 0)
		dsp->rc = -1;
	else
		dsp->rc = 0;
}

/* sort based on the weight of the gws */
static int weight_based_sort(pgw_list_t *pgwl, int size, unsigned short *idx)
{
	static unsigned short *running_sum = NULL;
	static unsigned short sum_buf_size = 0;

	unsigned int i, first, weight_sum, rand_no;

	/* populate the index array */
	for( i=0 ; i<size ; i++ ) idx[i] = i;
	first = 0;

	while (size-first>1) {
		resize_dr_sort_buffer( running_sum, sum_buf_size, size, err);
		/* calculate the running sum */
		for( i=first,weight_sum=0 ; i<size ; i++ ) {
			weight_sum += pgwl[ idx[i] ].weight ;
			running_sum[i] = weight_sum;
			LM_DBG("elem %d, weight=%d, sum=%d\n",i,
					pgwl[ idx[i] ].weight, running_sum[i]);
		}
		if (weight_sum) {
			/* randomly select number */
			rand_no = (unsigned int)(weight_sum*((float)rand()/RAND_MAX));
			LM_DBG("random number is %d\n",rand_no);
			/* select the element */
			for( i=first ; i<size ; i++ )
				if (running_sum[i]>rand_no) break;
			if (i==size) {
				LM_CRIT("bug in weight sort, first=%u, size=%u, rand_no=%u, total weight=%u\n",
					first, size, rand_no, weight_sum);
				for(i=first; i<size;i++)
					LM_CRIT("i %d, idx %u, weight %u, running sum %u\n",
						i, idx[i], pgwl[idx[i]].weight, running_sum[i]);
				/* try to recover here by picking the last gw */
				i = size - 1;
				// return -1;
			}
		} else {
			/* randomly select index */
			//	i = (unsigned int)((size-first)*((float)rand()/RAND_MAX));
			i = first;
		}
		LM_DBG("selecting element %d with weight %d\n",
				idx[i], pgwl[ idx[i] ].weight);
		/* "i" is the selected element : swap it with first position and
		   retake alg without first elem */
		rand_no = idx[i];
		idx[i] = idx[first];
		idx[first] = rand_no;
		first ++;
	}

	return 0;
err:
	return -1;
}


inline static int push_gw_for_usage(struct sip_msg *msg,
         struct head_db *current_partition, struct sip_uri *uri,
         rt_info_t *rt, pgw_list_t *dst, int cr_id, int gw_id, int idx)
{
	static void *qr_data;

	char buf[PTR_STRING_SIZE]; /* a hexa string */
	str *ruri;
	pgw_t *gw = NULL;
	str *c_id = NULL;
	str *c_attrs = NULL;
	int_str val;
	int_str dst_id_acc;
	struct dr_acc_call_params acp;

	if (rt) { /* rule based routing, e.g. do_routing() */
		if (cr_id == -1) { /* it is not a carrier */
			gw = rt->pgwl[gw_id].dst.gw;
		} else { /* destination is a carrier */
			c_id = &rt->pgwl[cr_id].dst.carrier->id;
			c_attrs = &rt->pgwl[cr_id].dst.carrier->attrs;
			gw = rt->pgwl[cr_id].dst.carrier->pgwl[gw_id].dst.gw;
		}

	} else if (dst) {
		/* routing was not done rule-based => don't use qrouting
		     (called from route_2gw or route_2cr) */

		if (dst->is_carrier) {
			gw = dst->dst.carrier->pgwl[gw_id].dst.gw;
			c_id = &dst->dst.carrier->id;
			c_attrs = &dst->dst.carrier->attrs;
		} else {
			gw = dst->dst.gw;
		}

	} else {
		LM_BUG("invalid function call, no rule, no destination\n");
		return -1;
	}

	/* build uri*/
	ruri = build_ruri( uri, gw->strip, &gw->pri, &gw->ip_str);
	if (ruri==0) {
		LM_ERR("failed to build new ruri\n");
		return -1;
	}

	LM_DBG("adding gw [%.*s] as \"%.*s\" in order %d\n",
			gw->id.len, gw->id.s, ruri->len, ruri->s, idx);

	/* first GW to be added ? */
	if (idx==0) {

		/* add to RURI */
		if (set_ruri( msg, ruri)!= 0 ) {
			LM_ERR("failed to set new RURI\n");
			goto error;
		}
		/* set socket to be used */
		if (gw->sock)
			msg->force_send_socket = gw->sock;

		if (rt && rt->sort_alg == QR_BASED_SORT) {
			memset(&acp, 0, sizeof acp);
			acp.rule = (void *)rt->qr_handler;
			acp.cr_id = cr_id;
			acp.gw_id = gw_id;
			acp.msg = msg;

			run_dr_cbs(DRCB_ACC_CALL, &acp); /* qr accounting */
			qr_data = acp.data;
		}
	} else {

		/* add ruri as AVP */
		val.s = *ruri;
		if (add_avp_last( AVP_VAL_STR, current_partition->ruri_avp, val)!=0 ) {
			LM_ERR("failed to insert ruri avp\n");
			goto error;
		}

		/* add GW sock avp */
		val.s.len = 1 + snprintf( buf, PTR_STR_SIZE, "%p", gw->sock );
		val.s.s = buf;
		LM_DBG("setting GW sock [%.*s] as avp\n",val.s.len, val.s.s);
		if (add_avp_last(AVP_VAL_STR, current_partition->gw_sock_avp, val)) {
			LM_ERR("failed to insert sock avp\n");
			goto error;
		}

		if (rt && rt->sort_alg == QR_BASED_SORT) {
			acp.rule = (void *)rt->qr_handler;
			acp.cr_id = cr_id;
			acp.gw_id = gw_id;
			acp.data = qr_data;

			dst_id_acc.s.s = (char *)&acp;
			dst_id_acc.s.len = sizeof acp;
			if (add_avp_last(AVP_VAL_STR,
			        current_partition->acc_call_params_avp, dst_id_acc)) {
				LM_ERR("failed to insert dst_id avp\n");
				goto error;
			}
		}
	}

	/* add GW id avp */
	val.s = gw->id;
	LM_DBG("setting GW id [%.*s] as avp\n",val.s.len, val.s.s);
	if (add_avp_last( AVP_VAL_STR, current_partition->gw_id_avp, val)!=0 ) {
		LM_ERR("failed to insert ids avp\n");
		goto error;
	}

	/* add internal GW attrs avp if requested at least once in the script */
	if (populate_gw_attrs) {
		val.s = gw->attrs.s? gw->attrs : attrs_empty;
		LM_DBG("setting GW attr [%.*s] as avp\n", val.s.len, val.s.s);
		if (add_avp_last(AVP_VAL_STR, current_partition->gw_attrs_avp,
					val)!=0){
			LM_ERR("failed to insert gw attrs avp\n");
			goto error;
		}
	}

	/* add GW priprefix avp */
	if (current_partition->gw_priprefix_avp!=-1) {
		val.s = gw->pri.s? gw->pri : attrs_empty;
		LM_DBG("setting GW priprefix [%.*s] as avp\n",val.s.len,val.s.s);
		if (add_avp_last(AVP_VAL_STR, current_partition->gw_priprefix_avp,
					val)!=0){
			LM_ERR("failed to insert priprefix avp\n");
			goto error;
		}
	}

	if (current_partition->carrier_id_avp!=-1) {
		val.s = (c_id && c_id->s)? *c_id : attrs_empty ;
		LM_DBG("setting CR Id [%.*s] as avp\n",val.s.len,val.s.s);
		if (add_avp_last(AVP_VAL_STR, current_partition->carrier_id_avp,
					val)!=0){
			LM_ERR("failed to insert attrs avp\n");
			goto error;
		}
	}

	/* add internal carrier attrs avp if requested at least once
	 * in the script */
	if (populate_carrier_attrs) {
		val.s = (c_attrs && c_attrs->s)? *c_attrs : attrs_empty;
		LM_DBG("setting CR attr [%.*s] as avp\n", val.s.len, val.s.s);
		if (add_avp_last(AVP_VAL_STR, current_partition->carrier_attrs_avp,
					val)!=0) {
			LM_ERR("failed to insert carrier attrs avp\n");
			goto error;
		}
	}

	pkg_free(ruri->s);
	return 0;
error:
	pkg_free(ruri->s);
	return -1;
}


static inline int is_dst_in_list(void* dst, pgw_list_t *list,
															unsigned short len)
{
	unsigned short i;

	if (list==NULL)
		return 1;
	for( i=0 ; i<len ; i++ ) {
		if (dst==(void*)list[i].dst.gw)
			return 1;
	}
	return 0;
}


struct head_db * get_partition(const str *name)
{
	struct head_db * it = head_db_start;

	while( it!= NULL) {
		if( it->partition.len==name->len && memcmp( it->partition.s, name->s,
					name->len)==0 ) {
			return it;
		}
		it = it->next;
	}

	return NULL; /* partition was not found */
}


static int do_routing(struct sip_msg* msg, struct head_db *part, int grp,
													int flags, str* whitelist)
{
	static unsigned short *dsts_idx = NULL;
	static unsigned short dsts_idx_size = 0;
	static unsigned short *carrier_idx = NULL;
	static unsigned short carrier_idx_size = 0;
	struct to_body  *from;
	struct sip_uri  uri;
	rt_info_t  *rt_info;
	pv_value_t pv_val;
	struct usr_avp *avp_prefix=NULL, *avp_index=NULL;
	pgw_list_t *dst, *cdst;
	pgw_list_t *wl_list;
	unsigned int prefix_len;
	unsigned int rule_idx;
	struct head_db *current_partition=NULL;
	unsigned short wl_len;
	str username;
	int i, j, n, rt_idx;
	int_str val;
	str ruri;
	str next_carrier_attrs = {NULL, 0};
	str next_gw_attrs = {NULL, 0};
	int ret, fret;
	char tmp;
	char *ruri_buf;

	ret = -1;
	ruri_buf = NULL;
	wl_list = NULL;
	rt_info = NULL;

	if (use_partitions && part==NULL) {
		/* WILDCARD partition */
		for (current_partition = head_db_start;
		current_partition; current_partition = current_partition->next) {
			ret=do_routing( msg, current_partition, grp, flags, whitelist);
			if (ret > 0) {
				if (partition_pvar.s) {
					pv_val.rs = current_partition->partition;
					pv_val.flags = PV_VAL_STR;
					if (pv_set_value(msg, &partition_spec, 0, &pv_val) != 0) {
						LM_ERR("cannot print the PV-formatted"
								" partition string\n");
						return -1;
					}
				}
				break;
			}
		}

		/* ret must be less than 0 here if nothing found */
		return ret;
	} else {
		current_partition = part;
	}

	/* allow no GWs if we're only trying to use DR for checking purposes */
	if (current_partition->rdata == 0 || ((flags & DR_PARAM_ONLY_CHECK) == 0
				&& current_partition->rdata->pgw_tree == 0 )) {
		LM_DBG("empty routing table\n");
		goto error1;
	}

	/* do some cleanup first (if without the CHECK_ONLY flag) */
	if ((flags & DR_PARAM_ONLY_CHECK) == 0) {
		destroy_avps( 0, current_partition->ruri_avp, 1);
		destroy_avps( 0, current_partition->gw_id_avp, 1);
		destroy_avps( 0, current_partition->gw_sock_avp, 1);
		destroy_avps( 0, current_partition->rule_attrs_avp, 1);
		destroy_avps( 0, current_partition->gw_attrs_avp, 1);
		destroy_avps( 0, current_partition->carrier_attrs_avp, 1);

		if ((current_partition->carrier_id_avp)!=-1)
			destroy_avps( 0, current_partition->carrier_id_avp, 1);
		if ((current_partition->gw_priprefix_avp)!=-1)
			destroy_avps( 0, current_partition->gw_priprefix_avp, 1);
		if ((current_partition->rule_id_avp)!=-1)
			destroy_avps( 0, current_partition->rule_id_avp, 1);
		if ((current_partition->rule_prefix_avp)!=-1)
			destroy_avps( 0, current_partition->rule_prefix_avp, 1);
	}

	if ( !(flags & DR_PARAM_INTERNAL_TRIGGERED) ) {
		/* not internally triggered, so get data from SIP msg */
		if(grp<0)
		{
			/* get the username from FROM_HDR */
			if (parse_from_header(msg)!=0) {
				LM_ERR("unable to parse from hdr\n");
				goto error1;
			}
			from = (struct to_body*)msg->from->parsed;
			/* parse uri */
			if (parse_uri( from->uri.s, from->uri.len, &uri)!=0) {
				LM_ERR("unable to parse from uri\n");
				goto error1;
			}

			grp = get_group_id( &uri, current_partition);
			if (grp<0) {
				LM_ERR("failed to get group id\n");
				goto error1;
			}
		}

		/* get the number/RURI and make a copy of it */
		ruri = *GET_RURI(msg);
		ruri_buf = (char*)pkg_malloc(ruri.len);
		if (ruri_buf==NULL) {
			LM_ERR("no more pkg mem (needed %d)\n",ruri.len);
			goto error1;
		}
		memcpy(ruri_buf, ruri.s, ruri.len);
		ruri.s = ruri_buf;
		/* parse ruri */
		if (parse_uri( ruri.s, ruri.len, &uri)!=0) {
			LM_ERR("unable to parse RURI\n");
			goto error1;
		}
		username = uri.user;

		/* search all rules on dr tree (start from beginning) */
		rule_idx = 0;

	} else {

		/* resume index on the rule under same prefix */
		avp_index = search_first_avp( 0, current_partition->avpID_store_index,
				&val, 0);
		if (avp_index==NULL) {
			LM_ERR("Cannot find index AVP during a fallback\n");
			goto error1;
		}
		rule_idx = val.n;

		/* prefix to resume with */
		avp_prefix = search_first_avp( AVP_VAL_STR,
				current_partition->avpID_store_prefix, &val, 0);
		if (avp_prefix==NULL) {
			LM_ERR("Cannot find prefix AVP during a fallback\n");
			goto error1;
		}
		username = val.s;
		/* still something to look for ? */
		if (username.len==0) return -1;

		/* original RURI to be used when building RURIs for new attempts */
		if (search_first_avp( AVP_VAL_STR, current_partition->avpID_store_ruri,
		&val, 0)==NULL) {
			LM_ERR("Cannot find ruri AVP during a fallback\n");
			goto error1;
		}
		if (parse_uri( val.s.s, val.s.len, &uri)!=0) {
			LM_ERR("unable to parse RURI from AVP\n");
			goto error1;
		}
		ruri.s = NULL; ruri.len = 0;
	}


	LM_DBG("using dr group %d, rule_idx %d, username %.*s\n",
			grp,rule_idx,username.len,username.s);

	/* ref the data for reading */
	lock_start_read( current_partition->ref_lock );

search_again:

	if (rt_info) {
		/* we are here because of the "search_again", on a
		   sequential retry based on rule FALL BACK */
		/* => force fallback, either on next rule, either on shorter prefix */
		username.len = prefix_len -(rule_idx?0:1);
		LM_DBG("doing internal fallback, prefix_len=%d,rule_idx=%d\n",
				username.len, rule_idx);
		if (username.len==0 && rule_idx==0) {
			/* disable failover as nothing left */
			flags = flags & ~DR_PARAM_RULE_FALLBACK;
			goto error2;
		}
	}

	/* search a prefix */
	rt_info = get_prefix(current_partition->rdata->pt, &username,
			(unsigned int)grp,&prefix_len, &rule_idx);

	if (flags & DR_PARAM_STRICT_LEN) {
		if (rt_info==NULL || prefix_len!=username.len)
			goto error2;
	}

	if (rt_info==0) {
		LM_DBG("no matching for prefix \"%.*s\"\n",
				username.len, username.s);
		/* try prefixless rules */
		rt_info = check_rt(&current_partition->rdata->noprefix,
				(unsigned int)grp);
		if (rt_info==0) {
			LM_DBG("no prefixless matching for "
					"grp %d\n", grp);
			goto error2;
		}
		prefix_len = 0;
		rule_idx = 0;
	}

	if (rt_info->route_idx && (rt_idx=get_script_route_ID_by_name
	(rt_info->route_idx, sroutes->request, RT_NO))!=-1) {
		fret = run_top_route( sroutes->request[rt_idx].a, msg );
		if (fret&ACT_FL_DROP) {
			/* drop the action */
			LM_DBG("script route %s drops routing "
				"by %d\n", sroutes->request[rt_idx].name, fret);
			goto error2;
		}
	}

	/* if only checking the prefix, we are done here */
	if (flags & DR_PARAM_ONLY_CHECK)
		goto no_gws;

	/* do we have anything left to failover to ? */
	if (prefix_len==0 && rule_idx==0)
		/* disable failover as nothing left */
		flags = flags & ~DR_PARAM_RULE_FALLBACK;

	/* START EVALUATING THE DESTINATIONS FROM LIST ! */
	n = 0;

	if (rt_info->pgwl==NULL) {
		LM_INFO("no destination for dr group %d, rule_idx %d, username %.*s\n",
				grp,rule_idx,username.len,username.s);
		if ( flags & DR_PARAM_RULE_FALLBACK )
			goto search_again;
		goto error2;
	}

	/* sort the destination elements in the rule */
	resize_dr_sort_buffer( dsts_idx, dsts_idx_size, rt_info->pgwa_len, error2);
	i = sort_rt_dst(rt_info, -1, dsts_idx);
	if (i!=0) {
		LM_ERR("failed to sort destinations in rule\n");
		goto error2;
	}


	/* evaluate and parse the whitelist of GWs/CARRIERs, if provided and
	   if the first time here */
	if (whitelist && wl_list==NULL) {
		tmp = whitelist->s[whitelist->len];
		whitelist->s[whitelist->len] = 0;
		if (parse_destination_list(current_partition->rdata,
		whitelist->s, &wl_list, &wl_len, 1, NULL)!=0) {
			LM_ERR("invalid format in whitelist-> ignoring...\n");
			wl_list = NULL;
		}
		whitelist->s[whitelist->len] = tmp;
	}

	/* walk the sorted list, skip disabled destinations */
	for ( i=0 ; i<rt_info->pgwa_len ; i++ ) {

		if(dsts_idx[i] == (unsigned short)-1) {
			LM_DBG("All available destinations were inserted\n");
			break;
		}
		dst = &rt_info->pgwl[dsts_idx[i]];

		/* is the destination carrier or gateway ? */
		if (dst->is_carrier) {

			/* is carrier turned off ? */
			if( dst->dst.carrier->flags & DR_CR_FLAG_IS_OFF
					|| !is_dst_in_list( (void*)dst->dst.carrier,
						wl_list, wl_len) )
				continue;

			/* any gws for this carrier ? */
			if( dst->dst.carrier->pgwl==NULL )
				continue;

			/* sort the gws of the carrier */
			resize_dr_sort_buffer( carrier_idx, carrier_idx_size,
				dst->dst.carrier->pgwa_len, skip);
			j = sort_rt_dst(rt_info, dsts_idx[i],
					carrier_idx);
			if (j!=0) {
				LM_ERR("failed to sort gws for carrier <%.*s>, skipping\n",
						dst->dst.carrier->id.len, dst->dst.carrier->id.s);
				continue;
			}

			/* iterate through the list of GWs provided by carrier */
			for ( j=0 ; j<dst->dst.carrier->pgwa_len ; j++ ) {

				if(carrier_idx[j] == (unsigned short)-1) {
					LM_DBG("All available destinations (dst idx %d) were"
					       "inserted\n", carrier_idx[j]);
					break;
				}

				cdst = &dst->dst.carrier->pgwl[carrier_idx[j]];

				/* is gateway disabled ? */
				if (cdst->dst.gw->flags & DR_DST_STAT_DSBL_FLAG ) {
					/*ignore it*/
				} else {
					/* add gateway to usage list */
					if ( push_gw_for_usage(msg, current_partition, &uri, rt_info ,
								NULL, dsts_idx[i], carrier_idx[j], n) ) {
						LM_ERR("failed to use gw <%.*s>, skipping\n",
								cdst->dst.gw->id.len, cdst->dst.gw->id.s);
					} else {
						n++;

						/* only export the top-most carrier/gw
						 * attributes in the script */
						if (n == 1) {
							next_carrier_attrs = dst->dst.carrier->attrs;
							next_gw_attrs = cdst->dst.gw->attrs;
						}

						/* use only first valid GW */
						if (dst->dst.carrier->flags&DR_CR_FLAG_FIRST)
							break;
					}
				}

			}
			skip:
			;

		} else {

			/* is gateway disabled ? */
			if (dst->dst.gw->flags & DR_DST_STAT_DSBL_FLAG
					|| !is_dst_in_list( (void*)dst->dst.gw, wl_list, wl_len) )
				continue;

			/* add gateway to usage list */
			if ( push_gw_for_usage(msg, current_partition, &uri,
						rt_info, NULL, -1, dsts_idx[i], n) ) {
				LM_ERR("failed to use gw <%.*s>, skipping\n",
						dst->dst.gw->id.len, dst->dst.gw->id.s);
			} else {
				n++;
				/* only export the first gw attributes in the script */
				if (n == 1) {
					next_carrier_attrs.s = NULL;
					next_gw_attrs = dst->dst.gw->attrs;
				}
			}

		}

	}

	if( n < 1) {
		if ( flags & DR_PARAM_RULE_FALLBACK )
			goto search_again;
		goto error2;
	}

	pv_val.flags = PV_VAL_STR;

	if (gw_attrs_spec) {
		pv_val.flags = PV_VAL_STR;
		pv_val.rs = !next_gw_attrs.s ? attrs_empty : next_gw_attrs;
		if (pv_set_value(msg, gw_attrs_spec, 0, &pv_val) != 0) {
			LM_ERR("failed to set value for gateway attrs pvar - do_routing\n");
			goto error2;
		}
	}

	if (carrier_attrs_spec) {
		pv_val.flags = PV_VAL_STR;
		pv_val.rs = !next_carrier_attrs.s ? attrs_empty : next_carrier_attrs;
		if (pv_set_value(msg, carrier_attrs_spec, 0, &pv_val)
				!= 0) {
			LM_ERR("failed to set value for carrier attrs pvar - do_routing\n");
			goto error2;
		}
	}

no_gws:
	/* add RULE prefix avp */
	if (current_partition->rule_prefix_avp!=-1) {
		val.s.s = username.s ;
		val.s.len = prefix_len;
		LM_DBG("setting RULE prefix [%.*s] \n",val.s.len,val.s.s);
		if (add_avp( AVP_VAL_STR, current_partition->rule_prefix_avp, val)!=0 ) {
			LM_ERR("failed to insert rule prefix avp\n");
			goto error2;
		}
	}

	/* add internal RULE attrs avp if requested at least once in the script */
	if (populate_rule_attrs) {
		val.s = !rt_info->attrs.s ? attrs_empty : rt_info->attrs;
		LM_DBG("setting RULE attr [%.*s] \n", val.s.len, val.s.s);
		if (add_avp( AVP_VAL_STR, current_partition->rule_attrs_avp, val) != 0) {
			LM_ERR("failed to insert rule attrs avp\n");
			goto error2;
		}

		if (rule_attrs_spec) {
			pv_val.flags = PV_VAL_STR;
			pv_val.rs = val.s;
			if (pv_set_value(msg, rule_attrs_spec, 0,
						&pv_val) != 0) {
				LM_ERR("failed to set value for rule attrs pvar\n");
				goto error2;
			}
		}
	}

	/* add RULE id avp */
	if (current_partition->rule_id_avp!=-1) {
		val.n = (int) rt_info->id;
		LM_DBG("setting RULE id [%d] as avp\n",val.n);
		if (add_avp( 0, current_partition->rule_id_avp, val)!=0 ) {
			LM_ERR("failed to insert rule ids avp\n");
			goto error2;
		}
	}

	/* we are done reading -> unref the data */
	lock_stop_read( current_partition->ref_lock );

	/* prepare/update data for fallback */
	if ( flags & DR_PARAM_RULE_FALLBACK ) {
		if ( !(flags & DR_PARAM_INTERNAL_TRIGGERED) ) {
			/* first time - we need to save some date, to be able to
			 * do the rule fallback later in "next_gw" , but do it only if 
			 * there is place for fallback (more rules or shorter prefix are 
			 * available) */
			if (prefix_len!=0 || rule_idx!=0) {
				LM_DBG("saving rule_idx %d, prefix %.*s\n",rule_idx,
						prefix_len - (rule_idx?0:1), username.s);
				val.n = rule_idx;
				if (add_avp( 0 , current_partition->avpID_store_index, val) ) {
					LM_ERR("failed to insert index avp for fallback\n");
					flags = flags & ~DR_PARAM_RULE_FALLBACK;
				}
				/* if no rules available on current prefix (index is 0), simply
				   reduce the len of the prefix from start, to lookup another
				   prefix in the DR tree */
				val.s.s = username.s ;
				val.s.len = prefix_len - (rule_idx?0:1);
				if (add_avp( AVP_VAL_STR,
				current_partition->avpID_store_prefix, val) ) {
					LM_ERR("failed to insert prefix avp for fallback\n");
					flags = flags & ~DR_PARAM_RULE_FALLBACK;
				}
				/* also store current ruri as we will need it */
				val.s = ruri;
				if (add_avp( AVP_VAL_STR,
				current_partition->avpID_store_ruri, val) ) {
					LM_ERR("failed to insert ruri avp for fallback\n");
					flags = flags & ~DR_PARAM_RULE_FALLBACK;
				}
				/* we need to save a some date, to be able to do the rule
				   fallback later in "next_gw" (prefix/index already added) */
				if (wl_list) {
					val.s = *whitelist ;
					/* we need extra space to place \0 when using */
					val.s.len++;
					if (add_avp( AVP_VAL_STR,
					current_partition->avpID_store_whitelist, val) ) {
						LM_ERR("failed to insert whitelist avp for fallback\n");
						flags = flags & ~DR_PARAM_RULE_FALLBACK;
					}
				}
				val.n = grp ;
				if (add_avp( 0, current_partition->avpID_store_group, val) ) {
					LM_ERR("failed to insert group avp for fallback\n");
					flags = flags & ~DR_PARAM_RULE_FALLBACK;
				}
				val.n = flags ;
				if (add_avp( 0, current_partition->avpID_store_flags, val) ) {
					LM_ERR("failed to insert flags avp for fallback\n");
				}
			}
		} else {
			/* update the fallback coordonats for next resume */
			/* using ugly hack by directly accessing the AVP data in order
			   to perform changes - we want to avoid re-creating the AVP */
			avp_index->data = (void *)(long)rule_idx;
			if (rule_idx==0) {
				void *data;
				/* all rules under current prefix used -> reduce the prefix */
				data = (void*)&avp_prefix->data;
				((str*)data)->len = prefix_len?prefix_len-1:0;
			}
			LM_DBG("updating to %d, prefix %.*s \n",rule_idx,
					prefix_len-(rule_idx?1:0),username.s);
		}
	} else if ( (flags & DR_PARAM_INTERNAL_TRIGGERED) ) {
		/* triggered via failover, but failover dropped at this iteration */
		destroy_avps( 0, current_partition->avpID_store_flags, 1);
	}

	if (wl_list) pkg_free(wl_list);
	if (ruri_buf) pkg_free(ruri_buf);
	return 1;
error2:
	if (wl_list) pkg_free(wl_list);
	/* we are done reading -> unref the data */
	lock_stop_read( current_partition->ref_lock );
error1:
	if (ruri_buf) pkg_free(ruri_buf);
	return ret;
}


static int route2_carrier(struct sip_msg* msg, str* ids,
				pv_spec_t* gw_att, pv_spec_t* carr_att, struct head_db *part)
{
	static unsigned short *carrier_idx;
	static unsigned short carrier_idx_size;
	struct sip_uri  uri;
	pgw_list_t *cdst;
	pgw_list_t dst;
	pcr_t *cr;
	pv_value_t pv_val;
	str ruri, id;
	str next_carrier_attrs = {NULL, 0};
	str next_gw_attrs = {NULL, 0};
	int i, j, n;
	struct head_db * current_partition = 0;
	char *ruri_buf=NULL, *p;

	if(part==NULL) {
		LM_ERR("Partition is mandatory for route_to_carrier.\n");
		return -1;
	}
	current_partition = part;


	if (current_partition->rdata == 0 ||
	current_partition->rdata->pgw_tree == 0) {
		LM_DBG("empty routing table\n");
		return -1;
	}

	gw_attrs_spec = (pv_spec_p) gw_att;
	carrier_attrs_spec = (pv_spec_p) carr_att;

	/* do some cleanup first */
	destroy_avps( 0, current_partition->ruri_avp, 1);
	destroy_avps( 0, current_partition->gw_id_avp, 1);
	destroy_avps( 0, current_partition->gw_sock_avp, 1);
	destroy_avps( 0, current_partition->gw_attrs_avp, 1);
	destroy_avps( 0, current_partition->rule_attrs_avp, 1);
	destroy_avps( 0, current_partition->carrier_attrs_avp, 1);

	if (current_partition->carrier_id_avp!=-1)
		destroy_avps( 0, current_partition->carrier_id_avp, 1);
	if (current_partition->gw_priprefix_avp!=-1)
		destroy_avps( 0, current_partition->gw_priprefix_avp, 1);
	if (current_partition->rule_id_avp!=-1)
		destroy_avps( 0, current_partition->rule_id_avp, 1);
	if (current_partition->rule_prefix_avp!=-1)
		destroy_avps( 0, current_partition->rule_prefix_avp, 1);

	/* get the RURI */
	ruri = *GET_RURI(msg);
	ruri_buf = (char*)pkg_malloc(ruri.len);
	if (ruri_buf==NULL) {
		LM_ERR("no more pkg mem (needed %d)\n",ruri.len);
		return -1;
	}
	memcpy(ruri_buf, ruri.s, ruri.len);
	ruri.s = ruri_buf;

	/* parse ruri */
	if (parse_uri( ruri.s, ruri.len, &uri)!=0) {
		LM_ERR("unable to parse RURI\n");
		goto error_free;
	}

	/* ref the data for reading */
	lock_start_read( current_partition->ref_lock);

	/* how many gws will be added */
	n = 0;

	while (ids->len>0) {

		/* extract a new carrier ID */
		id.s = ids->s;
		p = q_memchr( ids->s, ',', ids->len);
		id.len = (p==NULL)?ids->len:(p-ids->s);

		/* adjust remaing 'ids' buffer */
		ids->len -= id.len + (p?1:0);
		ids->s += id.len + (p?1:0);

		str_trim_spaces_lr( id );
		if (id.len==0) {
			/* empty value */
			continue;
		}

		LM_DBG("found and looking for carrier id <%.*s>,len=%d\n",
			id.len, id.s, id.len);
		cr = get_carrier_by_id(current_partition->rdata->carriers_tree, &id);
		if (cr==NULL) {
			LM_ERR("carrier <%.*s> was not found, skipping...\n", id.len,id.s);
			continue;
		}

		/* is carrier turned off ? */
		if( cr->flags & DR_CR_FLAG_IS_OFF ) {
			LM_DBG("carrier <%.*s> is disabled, skipping..,\n",
				cr->id.len, cr->id.s);
			continue;
		}

		/* any GWs for the carrier? */
		if (cr->pgwl==NULL)
			continue;

		/* sort the gws of the carrier */
		resize_dr_sort_buffer( carrier_idx, carrier_idx_size,
			cr->pgwa_len, skip);

		/* sort the gws of the carrier */
		if(cr->sort_alg == WEIGHT_BASED_SORT) {
			/* just weight based sort permitted, because qr-based
			 * sorting is rule-oriented*/
			j = weight_based_sort( cr->pgwl, cr->pgwa_len,
					carrier_idx);

			if (j!=0) {
				LM_ERR("failed to sort gws for carrier <%.*s>, skipping\n",
						cr->id.len, cr->id.s);
				goto error;
			}
		} else {
			/* No sort */
			for(i = 0; i < cr->pgwa_len; i++) {
				carrier_idx[i] = i;
			}
		}

		/* iterate through the list of GWs provided by carrier */
		for ( j=0 ; j<cr->pgwa_len ; j++ ) {

			cdst = &cr->pgwl[carrier_idx[j]];

			/* is gateway disabled ? */
			if (cdst->dst.gw->flags & DR_DST_STAT_DSBL_FLAG ) {
				/*ignore it*/
			} else {
				/* add gateway to usage list */
				dst.is_carrier = 1;
				dst.dst.carrier = cr;
				if ( push_gw_for_usage(msg, current_partition, &uri,
				NULL, &dst, -1, carrier_idx[j], n ) ) {
					LM_ERR("failed to use gw <%.*s>, skipping\n",
						cdst->dst.gw->id.len, cdst->dst.gw->id.s);
				} else {
					n++;

					/* only export the top-most carrier/gw
					 * attributes in the script */
					if (n == 1) {
						next_carrier_attrs = cr->attrs;
						next_gw_attrs = cdst->dst.gw->attrs;
					}

					/* use only first valid GW */
					if (cr->flags&DR_CR_FLAG_FIRST)
						break;
				}
			}

		}

		skip:
		;

	}

	if( n < 1) {

		LM_DBG("No GW added (not found or found disabled)\n");

	} else {

		pv_val.flags = PV_VAL_STR;

		if (gw_attrs_spec) {
			pv_val.flags = PV_VAL_STR;
			pv_val.rs = !next_gw_attrs.s ? attrs_empty : next_gw_attrs;
			if (pv_set_value(msg, gw_attrs_spec, 0, &pv_val) != 0) {
				LM_ERR("failed to set value for gateway attrs pvar\n");
				goto error;
			}
		}

		if (carrier_attrs_spec) {
			pv_val.flags = PV_VAL_STR;
			pv_val.rs = !next_carrier_attrs.s ? attrs_empty : next_carrier_attrs;
			if (pv_set_value(msg, carrier_attrs_spec, 0, &pv_val) != 0) {
				LM_ERR("failed to set value for carrier attrs pvar\n");
				goto error;
			}
		}

	}

	/* we are done reading -> unref the data */
	lock_stop_read( current_partition->ref_lock );
	if (ruri_buf) pkg_free(ruri_buf);

	return (n==0)?-1:1;
error:
	/* we are done reading -> unref the data */
	lock_stop_read( current_partition->ref_lock );
error_free:
	if (ruri_buf) pkg_free(ruri_buf);
	return -1;
}


static int route2_gw(struct sip_msg* msg, str* ids, pv_spec_t* gw_attr,
														struct head_db *part)
{
	struct sip_uri  uri;
	pgw_t *gw;
	pgw_list_t dst;
	pv_value_t pv_val;
	str ruri, id;
	str next_gw_attrs = {NULL, 0};
	char *p;
	int idx;
	struct head_db * current_partition = 0;
	char *ruri_buf = NULL;

	if(part== NULL) {
		LM_ERR("Partition is mandatory for route_to_gw.\n");
		return -1;
	}
	current_partition = part;

	if (current_partition->rdata == 0 ||
	current_partition->rdata->pgw_tree == 0) {
		LM_DBG("empty routing table\n");
		return -1;
	}

	gw_attrs_spec = (pv_spec_p)gw_attr;

	/* get the RURI */
	ruri = *GET_RURI(msg);
	ruri_buf = (char*)pkg_malloc(ruri.len);
	if (ruri_buf==NULL) {
		LM_ERR("no more pkg mem (needed %d)\n",ruri.len);
		return -1;
	}
	memcpy(ruri_buf, ruri.s, ruri.len);
	ruri.s = ruri_buf;

	/* parse ruri */
	if (parse_uri( ruri.s, ruri.len, &uri)!=0) {
		LM_ERR("unable to parse RURI\n");
		goto error_free;
	}

	/* ref the data for reading */
	lock_start_read( current_partition->ref_lock );

	idx = 0;
	do {
		id.s = ids->s;
		p = q_memchr( ids->s , ',' , ids->len);
		id.len = (p==NULL)?ids->len:(p-ids->s);

		ids->len -= id.len + (p?1:0);
		ids->s += id.len + (p?1:0);

		str_trim_spaces_lr(id);
		if (id.len<=0) {
			LM_ERR("empty slot\n");
			lock_stop_read( current_partition->ref_lock );
			return -1;
		} else {
			LM_DBG("found and looking for gw id <%.*s>,len=%d\n",
				id.len, id.s, id.len);
			gw = get_gw_by_id(current_partition->rdata->pgw_tree, &id);
			dst.is_carrier = 0;
			dst.dst.gw = gw;

			if (gw==NULL) {
				LM_ERR("no GW found with ID <%.*s> -> ignorring\n",
					id.len, id.s);
			} else
			if (gw->flags & DR_DST_STAT_DSBL_FLAG) {
				/* is gateway disabled, skip it */
			} else
			if ( push_gw_for_usage(msg, current_partition, &uri, NULL,
			&dst, -1, -1, idx ) ) {
				LM_ERR("failed to use gw <%.*s>, skipping\n",
						gw->id.len, gw->id.s);
			} else {
				idx++;

				/* only export the top-most gw attributes in the script */
				if (idx == 1)
					next_gw_attrs = gw->attrs;
			}
		}
	} while(ids->len>0);

	/* we are done reading -> unref the data */
	lock_stop_read( current_partition->ref_lock );

	if ( idx==0 ) {
		LM_ERR("no GW added at all\n");
		goto error_free;
	}

	if (gw_attrs_spec) {
		pv_val.flags = PV_VAL_STR;
		pv_val.rs = !next_gw_attrs.s ? attrs_empty : next_gw_attrs;
		if (pv_set_value(msg, gw_attrs_spec, 0, &pv_val) != 0) {
			LM_ERR("failed to set value for gateway attrs pvar\n");
			goto error_free;
		}
	}

	if (ruri_buf) pkg_free(ruri_buf);
	return 1;

error_free:
	if (ruri_buf) pkg_free(ruri_buf);
	return -1;
}


static int fix_flags(void** param)
{
	str *s = (str*)(*param);
	char *p;
	long flags=0;

	if (s) {
		for ( p=s->s ; p<s->s+s->len ; p++ ) {
			switch (*p) {
				case 'W':
					flags |= DR_PARAM_USE_WEIGTH;
					LM_DBG("using weights in GW selection\n");
					break;
				case 'F':
					flags |= DR_PARAM_RULE_FALLBACK;
					LM_DBG("enabling rule fallback\n");
					break;
				case 'L':
					flags |= DR_PARAM_STRICT_LEN;
					LM_DBG("matching prefix with strict len\n");
					break;
				case 'C':
					flags |= DR_PARAM_ONLY_CHECK;
					LM_DBG("only check the prefix\n");
					break;
				default:
					LM_DBG("unknown flag : [%c] . Skipping\n",*p);
			}
		}
		*param = (void*)(long)flags;
	}
	return 0;
}


static int fix_partition(void** param)
{
	str *s = (str*)(*param);
	struct head_db *part;

	if (s==NULL) {
		/* no partition defined */
		if (use_partitions==0) {
			if(head_db_start == NULL) {
				LM_ERR("Bad configuration, missing default partition\n");
				return -1;
			}
			part = head_db_start;
		} else {
			LM_ERR("Partition name is mandatory\n");
			return -1;
		}
	} else {
		/* partition name defined */
		if (s->len==1 && s->s[0]=='*') {
			/* partition wild card */
			part = NULL;
		} else {
			part = get_partition( s );
			if (part==NULL) {
				LM_ERR("partition <%.*s> used, but not defined\n",s->len,s->s);
				return -1;
			}
		}
	}
	*param = (void*)part;

	return 0;
}


static int fix_rule_attr(void** param)
{
	populate_rule_attrs = 1;

	return 0;
}


static int fix_gw_attr(void** param)
{
	populate_gw_attrs = 1;

	return 0;
}


static int fix_carr_attr(void** param)
{
	populate_carrier_attrs = 1;

	return 0;
}


static int fix_gw_flags(void** param)
{
	str *s = (str*)(*param);
	int i;
	long flags=0;

	if (s) {
		for( i=0 ; i < s->len ; i++ ) {
			switch (s->s[i]) {
				case 's': flags |= DR_IFG_STRIP_FLAG; break;
				case 'p': flags |= DR_IFG_PREFIX_FLAG; break;
				case 'i': flags |= DR_IFG_IDS_FLAG; break;
				case 'n': flags |= DR_IFG_IGNOREPORT_FLAG; break;
				case 'c': flags |= DR_IFG_CARRIERID_FLAG; break;
				default: LM_WARN("unsupported flag %c \n",s->s[i]);
			}
		}
		*param = (void*)(long)flags;
	}
	return 0;
}


static int strip_username(struct sip_msg* msg, int strip)
{
	if (rewrite_ruri(msg, NULL, strip, RW_RURI_STRIP) < 0) {
		LM_ERR("error while stripping host\n");
		return -1;
	}

	return 0;
}


static int prefix_username(struct sip_msg* msg, str *pri)
{
	if (rewrite_ruri(msg, pri, 0, RW_RURI_PREFIX) < 0) {
		LM_ERR("error while setting prefix\n");
		return -1;
	}

	return 0;
}


static int gw_matches_ip(pgw_t *pgwa, struct ip_addr *ip, unsigned short port)
{
	unsigned short j;
	for ( j=0 ; j<pgwa->ips_no ; j++)
		if ( (pgwa->ports[j]==0 || port==0 || pgwa->ports[j]==port) &&
				ip_addr_cmp( &pgwa->ips[j], ip) ) return 1;
	return 0;
}


/*
 * Checks if a given IP + PORT is a GW; tests the TYPE too
 * INTERNAL FUNCTION
 */
static int _is_dr_gw(struct sip_msg* msg,
		struct head_db *current_partition,
		int flags, int type, struct ip_addr *ip, unsigned int port)
{
	pgw_t *pgwa = NULL;
	pcr_t *pcr = NULL;
	pv_value_t pv_val;
	int_str val;
	int i;

	void** dest;
	map_iterator_t gw_it, cr_it;

	if(current_partition==NULL || current_partition->rdata==NULL || msg==NULL)
		return -1;

	lock_start_read( current_partition->ref_lock );

	if(current_partition->rdata!=NULL) {
		for (map_first(current_partition->rdata->pgw_tree, &gw_it);
			iterator_is_valid(&gw_it); iterator_next(&gw_it)) {

			dest = iterator_val(&gw_it);
			if (dest==NULL)
				break;

			pgwa = (pgw_t*)*dest;

			if( (type<0 || type==pgwa->type) &&
			gw_matches_ip( pgwa, ip, (flags&DR_IFG_IGNOREPORT_FLAG)?0:port )) {
				/* strip ? */
				if ( (flags&DR_IFG_STRIP_FLAG) && pgwa->strip>0)
					strip_username(msg, pgwa->strip);
				/* prefix ? - set it even if it is "" */
				if ( (flags&DR_IFG_PREFIX_FLAG) && pgwa->pri.s) {
					/* pri prefix ? */
					if (current_partition->gw_priprefix_avp!=-1) {
						val.s = pgwa->pri;
						if (add_avp(AVP_VAL_STR,
						current_partition->gw_priprefix_avp, val)!=0)
							LM_ERR("failed to insert GW pri prefix avp\n");
					}
					prefix_username(msg, &pgwa->pri);
				}

				/* attrs ? */
				if (gw_attrs_spec) {
					pv_val.flags = PV_VAL_STR;
					pv_val.rs = pgwa->attrs.s ? pgwa->attrs : attrs_empty;
					if (pv_set_value(msg, gw_attrs_spec, 0, &pv_val) != 0)
						LM_ERR("failed to set value for GW attrs pvar\n");
				}

				if ( flags & DR_IFG_IDS_FLAG ) {
					val.s = pgwa->id;
					if (add_avp(AVP_VAL_STR,
					current_partition->gw_id_avp, val)!=0)
						LM_ERR("failed to insert GW attrs avp\n");
				}

				if ( flags & DR_IFG_CARRIERID_FLAG ) {
					/* lookup first carrier that contains this gw */
					for (map_first(current_partition->rdata->carriers_tree, &cr_it);
							iterator_is_valid(&cr_it); iterator_next(&cr_it)) {

						dest = iterator_val(&cr_it);
						if (dest==NULL)
							break;

						pcr = (pcr_t*)*dest;

						for (i=0;i<pcr->pgwa_len;i++) {
							if (pcr->pgwl[i].is_carrier == 0 &&
									pcr->pgwl[i].dst.gw == pgwa ) {
								/* found our carrier */
								if (current_partition->carrier_id_avp!=-1) {
									val.s = pcr->id;
									if (add_avp_last(AVP_VAL_STR,
									current_partition->carrier_id_avp,val)!=0){
										LM_ERR("failed to add carrier id "
											"AVP\n");
									}
								}
								goto end;
							}
						}
					}
				}
end:
				lock_stop_read( current_partition->ref_lock );
				return 1;
			}
		}
	}

	lock_stop_read( current_partition->ref_lock );

	return -1;
}


static int is_from_gw(struct sip_msg* msg, int *type, long flags,
									pv_spec_t* gw_att, struct head_db *part)
{
	int ret=-1;
	pv_value_t pv_val;
	struct head_db * it;

	gw_attrs_spec = (pv_spec_p)gw_att;

	if (part==NULL) {
		/* if we got here we have the wildcard operator */
		for (it = head_db_start; it; it = it->next) {
			ret = _is_dr_gw(msg, it, (int)flags, type?*type:-1,
				&msg->rcv.src_ip, msg->rcv.src_port);
			if (ret > 0) {
				if (partition_pvar.s) {
					pv_val.rs = it->partition;
					pv_val.flags = PV_VAL_STR;
					if (pv_set_value(msg, &partition_spec, 0, &pv_val) != 0) {
						LM_ERR("cannot set value for the partition PV\n");
						return -1;
					}
				}
				return ret;
			}
		}
		return ret;
	}

	return _is_dr_gw(msg, part, (int)flags, type?*type:-1,
		&msg->rcv.src_ip, msg->rcv.src_port);
}


/*
 * Extracts the IP & port corresponding to the msg destination
 */
static int _uri_to_ip_port(str *uri, struct ip_addr *ip, int *port)
{
	struct sip_uri puri;
	struct hostent* he;

	memset( &puri, 0, sizeof(struct sip_uri));
	if (parse_uri(uri->s, uri->len, &puri)!=0) {
		LM_ERR("invalid sip uri <%.*s>\n", uri->len, uri->s);
		return -1;
	}

	he = sip_resolvehost(&puri.host, &puri.port_no, &puri.proto,
			(puri.type==SIPS_URI_T), 0);
	if (he==0) {
		LM_DBG("resolve_host(%.*s) failure\n", puri.host.len, puri.host.s);
		return -1;
	}

	/* extract the first ip */
	memset( ip, 0, sizeof(struct ip_addr));
	hostent2ip_addr( ip, he, 0);

	*port = puri.port_no;

	return 0;
}


static int goes_to_gw(struct sip_msg* msg, int *type, long flags,
									pv_spec_t* gw_att, struct head_db *part)
{
	int ret=-1;
	pv_value_t pv_val;
	struct head_db * it;
	struct ip_addr ip;
	int port;

	if (_uri_to_ip_port( GET_NEXT_HOP(msg), &ip, &port)!=0) {
		LM_ERR("failed to extract IP/port from msg destination\n");
		return -1;
	}

	gw_attrs_spec = (pv_spec_p)gw_att;

	if (part==NULL) {
		/* if we got here we have the wildcard operator */
		for (it = head_db_start; it; it = it->next) {
			ret = _is_dr_gw(msg, it, (int)flags, type?*type:-1, &ip, port);
			if (ret > 0) {
				if (partition_pvar.s) {
					pv_val.rs = it->partition;
					pv_val.flags = PV_VAL_STR;
					if (pv_set_value(msg, &partition_spec, 0, &pv_val) != 0) {
						LM_ERR("cannot set value for the partition PV\n");
						return -1;
					}
				}
				return ret;
			}
		}
		return ret;
	}

	return _is_dr_gw(msg, part, (int)flags, type?*type:-1, &ip, port);
}


static int dr_is_gw(struct sip_msg* msg, str *uri, int *type, long flags,
									pv_spec_t* gw_att, struct head_db *part)
{
	int ret=-1;
	pv_value_t pv_val;
	struct head_db * it;
	struct ip_addr ip;
	int port;

	if (_uri_to_ip_port( uri, &ip, &port)!=0) {
		LM_ERR("failed to extract IP/port from uri <%.*s>\n", uri->len,uri->s);
		return -1;
	}

	gw_attrs_spec = (pv_spec_p)gw_att;

	if (part==NULL) {
		/* if we got here we have the wildcard operator */
		for (it = head_db_start; it; it = it->next) {
			ret = _is_dr_gw(msg, it, (int)flags, type?*type:-1, &ip, port);
			if (ret > 0) {
				if (partition_pvar.s) {
					pv_val.rs = it->partition;
					pv_val.flags = PV_VAL_STR;
					if (pv_set_value(msg, &partition_spec, 0, &pv_val) != 0) {
						LM_ERR("cannot set value for the partition PV\n");
						return -1;
					}
				}
				return ret;
			}
		}
		return ret;
	}

	return _is_dr_gw(msg, part, (int)flags, type?*type:-1, &ip, port);
}


static int dr_match(struct sip_msg* msg, int *grp, long flags, str *number,
		pv_spec_t* rule_att, struct head_db *part)
{
	rt_info_t* rule;
	unsigned int matched_len;
	pv_value_t val;
	int_str a_val;

	if (part==NULL || part->rdata == 0)
		return -1;

	lock_start_read( part->ref_lock );

	rule = find_rule_by_prefix_unsafe(part->rdata->pt,
			&part->rdata->noprefix, *number, *grp, &matched_len);
	if (rule == NULL){
		goto failure;
	}

	/* some rule matched */

	/* was it a full prefix matching ? */
	if (flags & DR_PARAM_STRICT_LEN) {
		if (matched_len!=number->len)
			goto failure;
	}

	if (rule_att) {
		val.flags = PV_VAL_STR;
		val.rs = !rule->attrs.s ? attrs_empty : rule->attrs;
		if (pv_set_value(msg, rule_att, 0, &val) != 0) {
			LM_ERR("failed to set value for rule attrs pvar\n");
			goto failure;
		}
	}

	/* add RULE prefix avp */
	if (part->rule_prefix_avp!=-1) {
		a_val.s.s = number->s ;
		a_val.s.len = matched_len;
		LM_DBG("setting RULE prefix [%.*s] \n",a_val.s.len,a_val.s.s);
		if (add_avp( AVP_VAL_STR, part->rule_prefix_avp, a_val)!=0 ) {
			LM_ERR("failed to insert rule prefix avp\n");
			goto failure;
		}
	}

	lock_stop_read( part->ref_lock );

	return 1;

failure:
	lock_stop_read( part->ref_lock );
	return -1;
}



static inline int mi_dr_print_gw_state(pgw_t *gw, mi_item_t *gw_item)
{
	if (gw->flags&DR_DST_STAT_DSBL_FLAG) {
		if (gw->flags&DR_DST_STAT_NOEN_FLAG)
			return add_mi_string(gw_item, MI_SSTR("State"),
					MI_SSTR("Disabled MI"));
		else if (gw->flags&DR_DST_PING_DSBL_FLAG)
			return add_mi_string(gw_item, MI_SSTR("State"),
					MI_SSTR("Probing"));
		else
			return add_mi_string(gw_item, MI_SSTR("State"),
					MI_SSTR("Inactive"));
	} else
		return add_mi_string(gw_item, MI_SSTR("State"),
					MI_SSTR("Active"));
}

static mi_response_t *mi_dr_list_gw(struct head_db *current_partition,
										str *gw_id)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	pgw_t *gw;

	gw = get_gw_by_id(current_partition->rdata->pgw_tree, gw_id);
	if (gw==NULL)
		return init_mi_error( 404, MI_SSTR("GW ID not found"));

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (gw->attrs.s != NULL && gw->attrs.len > 0)
		if (add_mi_string(resp_obj, MI_SSTR("ATTRS"),
			gw->attrs.s,gw->attrs.len) < 0)
			goto error;

	if (mi_dr_print_gw_state(gw, resp_obj) < 0) {
		goto error;
	}

	return resp;
error:
	free_mi_response(resp);
	return 0;
}

static mi_response_t *mi_dr_list_all_gw(struct head_db *current_partition)
{
	pgw_t *gw;
	void** dest;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *gws_arr, *gw_item;
	map_iterator_t it;

	lock_start_read( current_partition->ref_lock );

	if (current_partition->rdata==NULL) {
		lock_stop_read( current_partition->ref_lock );
		return init_mi_error( 404, MI_SSTR("No Data available yet"));
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp) {
		lock_stop_read( current_partition->ref_lock );
		return 0;
	}
	gws_arr = add_mi_array(resp_obj, MI_SSTR("Gateways"));
	if (!gws_arr)
		goto error;

	for (map_first(current_partition->rdata->pgw_tree, &it);
			iterator_is_valid(&it); iterator_next(&it)) {

		dest = iterator_val(&it);
		if (dest==NULL)
			goto error;

		gw = (pgw_t*)*dest;

		gw_item = add_mi_object(gws_arr, NULL, 0);
		if (!gw_item)
			goto error;

		if (add_mi_string(gw_item, MI_SSTR("ID"), gw->id.s, gw->id.len) < 0)
			goto error;
		if (add_mi_string(gw_item, MI_SSTR("IP"), gw->ip_str.s, gw->ip_str.len) < 0)
			goto error;
		if (gw->attrs.s != NULL && gw->attrs.len > 0)
			if (add_mi_string(gw_item, MI_SSTR("ATTRS"),
				gw->attrs.s,gw->attrs.len) < 0)
				goto error;
		if (mi_dr_print_gw_state(gw, gw_item) < 0)
			goto error;
	}

	lock_stop_read( current_partition->ref_lock );

	return resp;

error:
	lock_stop_read( current_partition->ref_lock );
	free_mi_response(resp);
	return 0;
}

static mi_response_t *mi_dr_gw_set_status(struct head_db *current_partition,
										str *gw_id, int stat)
{
	pgw_t *gw;
	int old_flags;

	gw = get_gw_by_id(current_partition->rdata->pgw_tree, gw_id);
	if (gw==NULL)
		return init_mi_error( 404, MI_SSTR("GW ID not found"));

	old_flags = gw->flags;
	if (stat) {
		gw->flags &= ~ (DR_DST_STAT_DSBL_FLAG|DR_DST_STAT_NOEN_FLAG);
	} else {
		gw->flags |= DR_DST_STAT_DSBL_FLAG|DR_DST_STAT_NOEN_FLAG;
	}
	if (old_flags!=gw->flags) {
		gw->flags |= DR_DST_STAT_DIRT_FLAG;
		dr_gw_status_changed( current_partition, gw);
	}

	return init_mi_result_ok();
}

mi_response_t *mi_dr_gw_status_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	if (use_partitions)
		return init_mi_error_extra(400,
			MI_SSTR("Missing parameter: 'partition_name'"),
			MI_SSTR("'partition_name' is required when 'use_partitions' is set"));

	return mi_dr_list_all_gw(head_db_start);
}

mi_response_t *mi_dr_gw_status_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct head_db * current_partition=0;
	mi_response_t *resp;

	resp = mi_dr_get_partition(params, &current_partition);
	if (resp)
		return resp;

	return mi_dr_list_all_gw(current_partition);
}

mi_response_t *mi_dr_gw_status_3(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str id;

	if (use_partitions)
		return init_mi_error_extra(400,
			MI_SSTR("Missing parameter: 'partition_name'"),
			MI_SSTR("'partition_name' is required when 'use_partitions' is set"));

	if (get_mi_string_param(params, "gw_id", &id.s, &id.len) < 0)
		return init_mi_param_error();

	return mi_dr_list_gw(head_db_start, &id);
}

mi_response_t *mi_dr_gw_status_4(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str id;
	int stat;

	if (use_partitions)
		return init_mi_error_extra(400,
			MI_SSTR("Missing parameter: 'partition_name'"),
			MI_SSTR("'partition_name' is required when 'use_partitions' is set"));

	if (get_mi_string_param(params, "gw_id", &id.s, &id.len) < 0)
		return init_mi_param_error();
	if (get_mi_int_param(params, "status", &stat) < 0)
		return init_mi_param_error();

	return mi_dr_gw_set_status(head_db_start, &id, stat);
}

mi_response_t *mi_dr_gw_status_5(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str id;
	struct head_db * current_partition=0;
	mi_response_t *resp;

	resp = mi_dr_get_partition(params, &current_partition);
	if (resp)
		return resp;

	if (get_mi_string_param(params, "gw_id", &id.s, &id.len) < 0)
		return init_mi_param_error();

	return mi_dr_list_gw(current_partition, &id);
}

mi_response_t *mi_dr_gw_status_6(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str id;
	int stat;
	struct head_db * current_partition=0;
	mi_response_t *resp;

	resp = mi_dr_get_partition(params, &current_partition);
	if (resp)
		return resp;

	if (get_mi_string_param(params, "gw_id", &id.s, &id.len) < 0)
		return init_mi_param_error();
	if (get_mi_int_param(params, "status", &stat) < 0)
		return init_mi_param_error();

	return mi_dr_gw_set_status(current_partition, &id, stat);
}


static mi_response_t *mi_dr_list_cr(struct head_db *current_partition,
										str *cr_id)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	pcr_t *cr;

	cr = get_carrier_by_id(current_partition->rdata->carriers_tree, cr_id);
	if (cr==NULL)
		return init_mi_error( 404, MI_SSTR("Carrier ID not found"));

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (cr->attrs.s != NULL && cr->attrs.len > 0)
		if (add_mi_string(resp_obj, MI_SSTR("ATTRS"),
			cr->attrs.s,cr->attrs.len) < 0)
			goto error;

	if (add_mi_string(resp_obj, MI_SSTR("Enabled"),
		MI_SSTR((cr->flags&DR_CR_FLAG_IS_OFF) ? "no " : "yes")) < 0) {
		goto error;
	}

	return resp;
error:
	free_mi_response(resp);
	return 0;
}

static mi_response_t *mi_dr_list_all_cr(struct head_db *current_partition)
{
	pcr_t *cr;
	void** dest;
	map_iterator_t it;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *crs_arr, *cr_item;

	lock_start_read( current_partition->ref_lock );

	if (current_partition->rdata==NULL) {
		lock_stop_read( current_partition->ref_lock );
		return init_mi_error( 404, MI_SSTR("No Data available yet"));
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp) {
		lock_stop_read( current_partition->ref_lock );
		return 0;
	}
	crs_arr = add_mi_array(resp_obj, MI_SSTR("Carriers"));
	if (!crs_arr)
		goto error;

	for (map_first(current_partition->rdata->carriers_tree, &it);
			iterator_is_valid(&it); iterator_next(&it)) {

		dest = iterator_val(&it);
		if (dest==NULL)
			goto error;

		cr = (pcr_t*)*dest;

		cr_item = add_mi_object(crs_arr, 0, 0);
		if (!cr_item)
			goto error;

		if (add_mi_string(cr_item, MI_SSTR("ID"), cr->id.s, cr->id.len) < 0)
			goto error;

		if (cr->attrs.s != NULL && cr->attrs.len > 0)
			if (add_mi_string(cr_item, MI_SSTR("ATTRS"),
				cr->attrs.s,cr->attrs.len) < 0)
				goto error;

		if (add_mi_string(cr_item, MI_SSTR("Enabled"),
			MI_SSTR((cr->flags&DR_CR_FLAG_IS_OFF) ? "no " : "yes")) < 0)
			goto error;
	}

	lock_stop_read( current_partition->ref_lock );

	return resp;

error:
	lock_stop_read( current_partition->ref_lock );
	free_mi_response(resp);
	return 0;
}

static mi_response_t *mi_dr_cr_set_status(struct head_db *current_partition,
										str *cr_id, int stat)
{
	pcr_t *cr;
	int old_flags;

	cr = get_carrier_by_id(current_partition->rdata->carriers_tree, cr_id);
	if (cr==NULL)
		return init_mi_error( 404, MI_SSTR("Carrier ID not found"));

	old_flags = cr->flags;
	if (stat) {
		cr->flags &= ~ (DR_CR_FLAG_IS_OFF);
	} else {
		cr->flags |= DR_CR_FLAG_IS_OFF;
	}
	if (old_flags!=cr->flags) {
		cr->flags |= DR_CR_FLAG_DIRTY;
		replicate_dr_carrier_status_event( current_partition, cr );
	}

	return init_mi_result_ok();
}

mi_response_t *mi_dr_cr_status_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	if (use_partitions)
		return init_mi_error_extra(400,
			MI_SSTR("Missing parameter: 'partition_name'"),
			MI_SSTR("'partition_name' is required when 'use_partitions' is set"));

	return mi_dr_list_all_cr(head_db_start);
}

mi_response_t *mi_dr_cr_status_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct head_db * current_partition=0;
	mi_response_t *resp;

	resp = mi_dr_get_partition(params, &current_partition);
	if (resp)
		return resp;

	return mi_dr_list_all_cr(current_partition);
}

mi_response_t *mi_dr_cr_status_3(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str id;

	if (use_partitions)
		return init_mi_error_extra(400,
			MI_SSTR("Missing parameter: 'partition_name'"),
			MI_SSTR("'partition_name' is required when 'use_partitions' is set"));

	if (get_mi_string_param(params, "carrier_id", &id.s, &id.len) < 0)
		return init_mi_param_error();

	return mi_dr_list_cr(head_db_start, &id);
}

mi_response_t *mi_dr_cr_status_4(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str id;
	int stat;

	if (use_partitions)
		return init_mi_error_extra(400,
			MI_SSTR("Missing parameter: 'partition_name'"),
			MI_SSTR("'partition_name' is required when 'use_partitions' is set"));

	if (get_mi_string_param(params, "carrier_id", &id.s, &id.len) < 0)
		return init_mi_param_error();
	if (get_mi_int_param(params, "status", &stat) < 0)
		return init_mi_param_error();

	return mi_dr_cr_set_status(head_db_start, &id, stat);
}

mi_response_t *mi_dr_cr_status_5(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str id;
	struct head_db * current_partition=0;
	mi_response_t *resp;

	resp = mi_dr_get_partition(params, &current_partition);
	if (resp)
		return resp;

	if (get_mi_string_param(params, "carrier_id", &id.s, &id.len) < 0)
		return init_mi_param_error();

	return mi_dr_list_cr(current_partition, &id);
}

mi_response_t *mi_dr_cr_status_6(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str id;
	int stat;
	struct head_db * current_partition=0;
	mi_response_t *resp;

	resp = mi_dr_get_partition(params, &current_partition);
	if (resp)
		return resp;

	if (get_mi_string_param(params, "carrier_id", &id.s, &id.len) < 0)
		return init_mi_param_error();
	if (get_mi_int_param(params, "status", &stat) < 0)
		return init_mi_param_error();

	return mi_dr_cr_set_status(current_partition, &id, stat);
}

void init_head_db(struct head_db *new)
{
	memset(new, 0, sizeof(struct head_db));
	new->acc_call_params_avp = -1;
	new->avpID_store_ruri = -1;
	new->avpID_store_prefix = -1;
	new->avpID_store_index = -1;
	new->avpID_store_whitelist = -1;
	new->avpID_store_group = -1;
	new->avpID_store_flags = -1;
	new->gw_priprefix_avp = -1;
	new->rule_id_avp = -1;
	new->rule_prefix_avp = -1;
	new->carrier_id_avp = -1;
	new->ruri_avp = -1;
	new->gw_id_avp = -1;
	new->gw_sock_avp = -1;
	new->gw_attrs_avp = -1;
	new->rule_attrs_avp = -1;
	new->carrier_attrs_avp = -1;
}

/* use_partitions: use configurations from database */
int add_head_config(void)
{
	/* expand linked list */
	struct head_config *new;

	new = shm_malloc(sizeof(struct head_config));
	if( new == NULL ) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(new, 0, sizeof(struct head_config));

	new->next = head_start;
	head_start = new;

	(*n_partitions)++;
	return 0;
}

#define init_head_config_value( from_head, external, default_val)\
	if( external.len!=0 ) {\
		shm_str_dup( &(from_head), &(external));\
	} else {\
		from_head = default_val;\
	}\

#define set_head_config_value(head_param, db_param)\
	if(db_param.len > 0) {\
		shm_str_dup(&(head_param), &(db_param));\
	}\


static int populate_head_config(struct head_config *current, str attr, int index) {
	switch(index) {
		case 0:
			if(shm_str_dup( &(current->partition), &attr) < 0) {
				LM_ERR("no more shm memory for partition_name in head_config\n");
			}
			break;
		case 1:
			if( shm_str_dup(&(current->db_url), &attr) < 0) {
				LM_ERR("no more shm memory for db_url in head_config\n");
			}
			break;
		case 2:
			init_head_config_value( current->drd_table, attr, drd_table);
			break;
		case 3:
			init_head_config_value( current->drr_table, attr, drr_table);
			break;
		case 4:
			init_head_config_value( current->drg_table, attr, drg_table);
			break;
		case 5:
			init_head_config_value( current->drc_table, attr, drc_table);
			break;
		case 6:
			set_head_config_value( current->ruri_avp_spec, attr);
			break;
		case 7:
			set_head_config_value( current->gw_id_avp_spec, attr);
			break;
		case 8:
			set_head_config_value( current->gw_priprefix_avp_spec, attr);
			break;
		case 9:
			set_head_config_value( current->gw_sock_avp_spec, attr);
			break;
		case 10:
			set_head_config_value( current->rule_id_avp_spec, attr);
			break;
		case 11:
			set_head_config_value( current->rule_prefix_avp_spec, attr);
			break;
		case 12:
			set_head_config_value( current->carrier_id_avp_spec, attr);
			break;
		default:
			LM_DBG("Column from db_config not_known\n");
			return -1;
	}
	return 0;
}
static int get_config_from_db(void) {

	db_func_t db_funcs;
	db_res_t * query_res;
	db_con_t * db_con = 0;
	/* columns needed from db_confgir_url for query */
	str partition_col = str_init("partition_name");
	str db_url_col = str_init("db_url");
	str drd_col = str_init("drd_table");
	str drr_col = str_init("drr_table");
	str drg_col = str_init("drg_table");
	str drc_col = str_init("drc_table");
	str ruri_avp_col = str_init("ruri_avp");
	str gw_id_avp_col = str_init("gw_id_avp");
	str gw_priprefix_avp_col = str_init("gw_priprefix_avp");
	str gw_sock_avp_col = str_init("gw_sock_avp");
	str rule_id_avp_col = str_init("rule_id_avp");
	str rule_prefix_avp_col = str_init("rule_prefix_avp");
	str carrier_id_avp_col = str_init("carrier_id_avp");
	int n_query_col = 13;
	db_key_t query_cols[] = {&partition_col, &db_url_col, &drd_col, &drr_col,
		&drg_col, &drc_col, &ruri_avp_col, &gw_id_avp_col,
		&gw_priprefix_avp_col, &gw_sock_avp_col,
		&rule_id_avp_col, &rule_prefix_avp_col, &carrier_id_avp_col};
	/* query result processing stuff */
	int nr_rows_db_config = 0 ;
	int nr_cols_db_config = 0 ;
	db_val_t * value;
	db_row_t *rows_db_config = NULL;
	int j;
	int i;
	str ans_col = {NULL, 0};

	init_db_url(db_partitions_url, 0);
	db_partitions_url.len = strlen(db_partitions_url.s);
	db_partitions_table.len = strlen(db_partitions_table.s);

	if(db_bind_mod( &db_partitions_url, &db_funcs) < 0) {
		LM_ERR("Unable to bind to database driver (partition definitions) "
				"<db url = %.*s>\n", db_partitions_url.len,
				db_partitions_url.s);
		goto error;
	}

	if( (db_con = db_funcs.init(&db_partitions_url)) == 0 ) {
		LM_ERR("Cannot init connection to partitions table "
				"<db url = %.*s>\n", db_partitions_url.len,
				db_partitions_url.s);
		goto error;
	}


	if(db_check_table_version(&db_funcs, db_con,
				&db_partitions_table, PART_TABLE_VER) < 0) {
		LM_ERR("error during table version check <partitions table:\'%.*s\'>.\n",
				db_partitions_table.len, db_partitions_table.s);
		return -1;
	}

	if( db_funcs.use_table( db_con, &db_partitions_table) < 0) {
		LM_ERR("Cannot use the partitions table "
				"<table containing partition defs = %.*s ( in db %.*s "
				")>\n", db_partitions_table.len, db_partitions_table.s,
				db_partitions_url.len, db_partitions_url.s);
		goto error;
	}

	/* query for populating head_config structure */
	if( db_funcs.query( db_con, NULL, NULL, NULL, query_cols, 0, n_query_col,
				NULL, &query_res) < 0 ) {
		LM_ERR("Failed to query the table containing the partition definitions "
				"<db url = %.*s , partitions table = %.*s>\n",
				db_partitions_url.len, db_partitions_url.s,
				db_partitions_table.len, db_partitions_table.s);
		goto error;
	}

	nr_rows_db_config = RES_ROW_N(query_res);
	nr_cols_db_config = RES_COL_N(query_res);
	rows_db_config = RES_ROWS(query_res);

	for( i=0; i<nr_rows_db_config; i++) {
		value = ROW_VALUES(rows_db_config+i);
		add_head_config();
		for( j=0; j<nr_cols_db_config; j++) {
			if( VAL_NULL(value+j) ) {
				LM_DBG("Row %d is NULL\n", i);
			} else if( VAL_TYPE(value+j) == DB_STR || VAL_TYPE(value+j) == DB_STRING ) {
				if(VAL_TYPE(value+j) == DB_STR) {
					ans_col = VAL_STR(value+j);
				} else if(VAL_TYPE(value+j) == DB_STRING) {
					ans_col.s = (char*)VAL_STRING(value+j);
					ans_col.len = strlen(ans_col.s);
				}
				if (populate_head_config(head_start, ans_col, j) < 0 )
					LM_ERR("Column from partition table not recognized; will continue\n");

			} else {
				LM_ERR("Result from query is not a string\n");
			}
		}
	}



	db_funcs.free_result(db_con, query_res);
	if( db_con != 0 ) {
		db_funcs.close(db_con);
		db_con = 0;
	}

	return 0;
error:
	if( db_con != 0 ) {
		db_funcs.close(db_con);
		db_con = 0;
	}
	return -1;
}

mi_response_t *mi_dr_number_routing(const mi_params_t *params,
							struct head_db *partition, int grp_id)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *arr_obj, *gw_obj;
	str number;
	rt_info_t *route;
	unsigned int matched_len;
	unsigned int i;
	static const str gw_str = str_init("GATEWAY");
	static const str carrier_str = str_init("CARRIER");
	str chosen_desc;
	str chosen_id;

	if (get_mi_string_param(params, "number", &number.s, &number.len) < 0)
		return init_mi_param_error();

	if (partition->rdata == 0)
		return init_mi_result_ok();

	lock_start_read( partition->ref_lock );

	route = find_rule_by_prefix_unsafe(partition->rdata->pt,
			&partition->rdata->noprefix, number, grp_id, &matched_len);
	if (route == NULL){
		lock_stop_read( partition->ref_lock );
		return init_mi_result_string(MI_SSTR("No match"));
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_string(resp_obj, MI_SSTR("Matched Prefix"),
		number.s, matched_len) < 0)
		goto error;

	arr_obj = add_mi_array(resp_obj, MI_SSTR("GW List"));
	if (!arr_obj)
		goto error;

	for (i = 0; i < route->pgwa_len; ++i){
		if (route->pgwl[i].is_carrier) {
			chosen_desc = carrier_str;
			chosen_id = route->pgwl[i].dst.carrier->id;
		}
		else {
			chosen_desc = gw_str;
			chosen_id = route->pgwl[i].dst.gw->id;
		}
		gw_obj = add_mi_object(arr_obj, NULL, 0);
		if (!gw_obj)
			goto error;

		if (add_mi_string(gw_obj, chosen_desc.s, chosen_desc.len,
			chosen_id.s, chosen_id.len) < 0)
			goto error;
	}

	if (route->attrs.s != NULL && route->attrs.len > 0)
		if (add_mi_string(resp_obj, MI_SSTR("ATTRS"),
			route->attrs.s,route->attrs.len) < 0)
			goto error;

	lock_stop_read( partition->ref_lock );

	return resp;

error:
	lock_stop_read( partition->ref_lock );
	free_mi_response(resp);
	return 0;
}

mi_response_t *mi_dr_number_routing_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	if (use_partitions)
		return init_mi_error_extra(400,
			MI_SSTR("Missing parameter: 'partition_name'"),
			MI_SSTR("'partition_name' is required when 'use_partitions' is set"));

	return mi_dr_number_routing(params, head_db_start, -1);
}

mi_response_t *mi_dr_number_routing_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int grp_id;

	if (use_partitions)
		return init_mi_error_extra(400,
			MI_SSTR("Missing parameter: 'partition_name'"),
			MI_SSTR("'partition_name' is required when 'use_partitions' is set"));

	if (get_mi_int_param(params, "group_id", &grp_id) < 0)
		return init_mi_param_error();

	return mi_dr_number_routing(params, head_db_start, grp_id);
}

mi_response_t *mi_dr_number_routing_3(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct head_db * current_partition=0;
	mi_response_t *resp;

	resp = mi_dr_get_partition(params, &current_partition);
	if (resp)
		return resp;

	return mi_dr_number_routing(params, current_partition, -1);
}

mi_response_t *mi_dr_number_routing_4(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct head_db * current_partition=0;
	int grp_id;
	mi_response_t *resp;

	resp = mi_dr_get_partition(params, &current_partition);
	if (resp)
		return resp;

	if (get_mi_int_param(params, "group_id", &grp_id) < 0)
		return init_mi_param_error();

	return mi_dr_number_routing(params, current_partition, grp_id);
}


static int mi_dr_print_rld_status(mi_item_t *part_item, struct head_db * partition,
							int with_name)
{
	char ch_time[26];

	lock_start_read(partition->ref_lock);

	ctime_r(&partition->time_last_update, ch_time);
	LM_DBG("partition  %.*s was last updated:%s\n",
			partition->partition.len, partition->partition.s,
			ch_time);

	if (with_name && add_mi_string(part_item, MI_SSTR("name"),
		partition->partition.s, partition->partition.len) < 0)
		goto error;

	if (add_mi_string(part_item, MI_SSTR(MI_LAST_UPDATE_S),
		ch_time, strlen(ch_time)-1) < 0)
		goto error;

	lock_stop_read(partition->ref_lock);

	return 0;

error:
	lock_stop_read(partition->ref_lock);
	return -1;
}

mi_response_t *mi_dr_reload_status(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct head_db * partition;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *parts_arr, *part_item;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if(use_partitions){
		/* display for all partitions */
		parts_arr = add_mi_array(resp_obj, MI_SSTR("Partitions"));
		if (!parts_arr)
			goto error;

		for(partition = head_db_start; partition; partition = partition->next) {
			part_item = add_mi_object(parts_arr, NULL, 0);
			if (!part_item)
				goto error;

			if (mi_dr_print_rld_status(part_item, partition, 1) < 0)
				goto error;
		}
	} else  /* just one partition */
		if (mi_dr_print_rld_status(resp_obj, head_db_start, 0) < 0)
			goto error;

	return resp;

error:
	free_mi_response(resp);
	return 0;
}

mi_response_t *mi_dr_enable_probing(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;

	if (dr_enable_probing_state==NULL)
		return init_mi_error(400, MI_SSTR(MI_PROBING_DISABLED_S));

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_number(resp_obj, MI_SSTR("Status"),
		*dr_enable_probing_state)<0) {
		free_mi_response(resp);
		return 0;
	}

	return resp;
}

mi_response_t *mi_dr_enable_probing_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int status;

	if (dr_enable_probing_state==NULL)
		return init_mi_error(400, MI_SSTR(MI_PROBING_DISABLED_S));

	if (get_mi_int_param(params, "status", &status) < 0)
		return init_mi_param_error();

	(*dr_enable_probing_state) = status?1:0;

	return init_mi_result_ok();
}

mi_response_t *mi_dr_reload_status_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct head_db * partition;
	mi_response_t *resp;
	mi_item_t *resp_obj;

	resp = mi_dr_get_partition(params, &partition);
	if (resp)
		return resp;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (mi_dr_print_rld_status(resp_obj, partition, 1) < 0) {
		free_mi_response(resp);
		return 0;
	}

	return resp;
}
