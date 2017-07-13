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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * For any questions about this software and its license, please contact
 * Voice Sistem at following e-mail address:
 *         office@voice-system.ro
 *
 * History:
 * ---------
 *  2005-02-20  first version (cristian)
 *  2005-02-27  ported to 0.9.0 (bogdan)
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>


#include "../../evi/evi.h"
#include "../../map.h"

#include "dr_load.h"
#include "prefix_tree.h"
#include "dr_bl.h"
#include "dr_db_def.h"
#include "dr_partitions.h"
#include "dr_api.h"
#include "dr_api_internal.h"


#define DR_PARAM_USE_WEIGTH         (1<<0)
#define DR_PARAM_RULE_FALLBACK      (1<<1)
#define DR_PARAM_STRICT_LEN         (1<<2)
#define DR_PARAM_ONLY_CHECK         (1<<3)
#define DR_PARAM_INTERNAL_TRIGGERED (1<<30)

#define DRD_TABLE_VER 6
#define DRR_TABLE_VER 3
#define DRG_TABLE_VER 2
#define DRC_TABLE_VER 2
#define PART_TABLE_VER 1

#define MAX_LEN_NAME_W_PART 510 /* max len of variable containing
								   avp_spec and partition name */
#define  MI_NO_PART_S "Too many arguments (use_partitions is 0 so no parameter"\
	" should be supplied to the MI function)"

#define MI_NO_PART_LEN (strlen(MI_NO_PART_S))

#define MI_PART_NAME_S "Partition"
#define MI_PART_NAME_LEN (strlen(MI_PART_NAME_S))

#define MI_LAST_UPDATE_S "Date"
#define MI_LAST_UPDATE_LEN (strlen(MI_LAST_UPDATE_S))

/* probing related stuff */
static unsigned int dr_prob_interval = 30;
static str dr_probe_replies = {NULL,0};
struct tm_binds dr_tmb;
str dr_probe_method = str_init("OPTIONS");
str dr_probe_from = str_init("sip:prober@localhost");
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


//static int use_partitions = 0;
// int use_partitions = 0; /* by default don't use db for config */
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
}* head_start = NULL,* head_end = NULL;

struct head_db * head_db_start = NULL,* head_db_end = NULL;


typedef struct param_prob_callback {
	struct head_db * current_partition;
	unsigned int  _id;
}param_prob_callback_t;


typedef struct dr_partition {
	union {
		struct head_db * part;
		gparam_p part_name;
	} v;

	enum dr_partition_type { DR_PTR_PART, DR_GPARAM_PART, DR_WILDCARD_PART, DR_NO_PART } type;
} dr_partition_t;

typedef struct dr_part_group {
	dr_partition_t * dr_part;
	dr_group_t * group;
} dr_part_group_t;

static dr_part_group_t * default_part; /* for do_routing, used when
										  use_partitions = 0 */

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


static int get_config_from_db();
static int add_head_config();
static int add_head_db();
static int db_load_head(struct head_db*); /* used for populating head_db with
											 db connections and db funcs */
static void trim_char(char**);
static int fixup_dr_disable(void **,int);
//static struct head_db * get_partition(const str *);
static int _is_dr_gw_w_part(struct sip_msg* , char * , char* ,
		int , struct ip_addr* , unsigned int);
static int use_next_gw_w_part( struct sip_msg*, struct head_db *, char *, char *, char *);
static int dr_disable(struct sip_msg *req, char * current_partition);
static int dr_disable_w_part(struct sip_msg *req, struct head_db *current_partition);
static int to_partition(struct sip_msg*, dr_partition_t *,
		struct head_db **);


/* reader-writers lock for reloading the data */
static rw_lock_t *ref_lock = NULL;

static int dr_init(void);
static int dr_child_init(int rank);
static int dr_exit(void);

static int fixup_do_routing(void** param, int param_no);
static int fixup_next_gw(void** param, int param_no);
static int fixup_from_gw(void** param, int param_no);
static int fixup_is_gw(void** param, int param_no);
static int fixup_route2_carrier( void** param, int param_no);
static int fixup_route2_gw( void** param, int param_no);

static int do_routing(struct sip_msg* msg,dr_part_group_t*, int sort, gparam_t* wl);
static int do_routing_0(struct sip_msg* msg);
static int do_routing_1(struct sip_msg* msg, char * , char* id, char* fl, char* wl,
		char* rule_att, char* gw_att, char* carr_att);
static int use_next_gw(struct sip_msg* msg,
		char* rule_or_part, char* rule_or_gw, char* gw_or_carr, char * carr);
static int is_from_gw_0(struct sip_msg* msg);
static int is_from_gw_1(struct sip_msg* msg, char * part);
static int is_from_gw_2(struct sip_msg* msg, char * part, char* str1);
static int is_from_gw_3(struct sip_msg* msg, char *, char*, char* );
static int is_from_gw_4(struct sip_msg*, char*, char*, char*, char*);
static int goes_to_gw_0(struct sip_msg* msg);
static int goes_to_gw_1(struct sip_msg* msg, char * part,  char* f1, char* f2, char* f3);
static int dr_is_gw(struct sip_msg* msg, char * part, char* str1, char* str2, char* str3,
		char* str4);
static int route2_carrier(struct sip_msg* msg, char* cr_str,
		char* gw_att_pv, char* carr_att_pv);
static int route2_gw(struct sip_msg* msg, char* gw, char* gw_att_pv);

static struct mi_root* dr_reload_cmd(struct mi_root *cmd_tree, void *param);
static struct mi_root* mi_dr_gw_status(struct mi_root *cmd, void *param);
static struct mi_root* mi_dr_cr_status(struct mi_root *cmd, void *param);
static struct mi_root* mi_dr_number_routing(struct mi_root *cmd_tree, void *param);
static struct mi_root* mi_dr_reload_status(struct mi_root *cmd_tree, void *param);


/* event */
static str dr_event = str_init("E_DROUTING_STATUS");
static event_id_t dr_evi_id;


/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"do_routing",  (cmd_function)do_routing_0,   0,  0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"do_routing",  (cmd_function)do_routing_1, 1,  fixup_do_routing, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"do_routing",  (cmd_function)do_routing_1, 2,  fixup_do_routing, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"do_routing",  (cmd_function)do_routing_1, 3,  fixup_do_routing, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"do_routing",  (cmd_function)do_routing_1, 4,  fixup_do_routing, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"do_routing",  (cmd_function)do_routing_1, 5,  fixup_do_routing, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"do_routing",  (cmd_function)do_routing_1, 6,  fixup_do_routing, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"do_routing",  (cmd_function)do_routing_1, 7,  fixup_do_routing, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"use_next_gw",  (cmd_function)use_next_gw,   0,  0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"use_next_gw",  (cmd_function)use_next_gw,   1,  fixup_next_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"use_next_gw",  (cmd_function)use_next_gw,   2,  fixup_next_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"use_next_gw",  (cmd_function)use_next_gw,   3,  fixup_next_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"use_next_gw",  (cmd_function)use_next_gw,   4,  fixup_next_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"next_routing",  (cmd_function)use_next_gw,  0,  0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"next_routing",  (cmd_function)use_next_gw,  1,  fixup_next_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"next_routing",  (cmd_function)use_next_gw,  2,  fixup_next_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"next_routing",  (cmd_function)use_next_gw,  3,  fixup_next_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"is_from_gw",  (cmd_function)is_from_gw_0,   0,  0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE},
	{"is_from_gw",  (cmd_function)is_from_gw_1,   1,  fixup_from_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE},
	{"is_from_gw",  (cmd_function)is_from_gw_2,   2,  fixup_from_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE},
	{"is_from_gw",  (cmd_function)is_from_gw_3,   3,  fixup_from_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE},
	{"is_from_gw",  (cmd_function)is_from_gw_4,   4,  fixup_from_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE},
	{"goes_to_gw",  (cmd_function)goes_to_gw_0,   0,  0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"goes_to_gw",  (cmd_function)goes_to_gw_1,   1,  fixup_from_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"goes_to_gw",  (cmd_function)goes_to_gw_1,   2,  fixup_from_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"goes_to_gw",  (cmd_function)goes_to_gw_1,   3,  fixup_from_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"goes_to_gw",  (cmd_function)goes_to_gw_1,   4,  fixup_from_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"dr_is_gw",  (cmd_function)dr_is_gw,         1,  fixup_is_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
			STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"dr_is_gw",  (cmd_function)dr_is_gw,         2,  fixup_is_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
			STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"dr_is_gw",  (cmd_function)dr_is_gw,         3,  fixup_is_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
			STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"dr_is_gw",  (cmd_function)dr_is_gw,         4,  fixup_is_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
			STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"dr_is_gw",  (cmd_function)dr_is_gw,         5,  fixup_is_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
			STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"dr_disable", (cmd_function)dr_disable,      0,  0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE},
	{"dr_disable", (cmd_function)dr_disable,      1,  fixup_dr_disable, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE},
	{"route_to_carrier",(cmd_function)route2_carrier,1,fixup_route2_carrier, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"route_to_carrier",(cmd_function)route2_carrier,2,fixup_route2_carrier, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"route_to_carrier",(cmd_function)route2_carrier,3,fixup_route2_carrier, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"route_to_gw",     (cmd_function)route2_gw,     1,fixup_route2_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"route_to_gw",     (cmd_function)route2_gw,     2,fixup_route2_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"load_dr",  (cmd_function)load_dr,   0, 0, 0, 0},
	{0, 0, 0, 0, 0, 0}
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
	{"probing_reply_codes",STR_PARAM, &dr_probe_replies.s     },
	{"persistent_state", INT_PARAM, &dr_persistent_state      },
	{"no_concurrent_reload",INT_PARAM, &no_concurrent_reload  },
	{"partition_id_pvar", STR_PARAM, &partition_pvar.s},
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
static mi_export_t mi_cmds[] = {
	{ "dr_reload",         HLP1, dr_reload_cmd,    0, 0,  0},
	{ "dr_gw_status",      HLP2, mi_dr_gw_status,  0,                0,  0},
	{ "dr_carrier_status", HLP3, mi_dr_cr_status,  0,                0,  0},
	{ "dr_number_routing", HLP4, mi_dr_number_routing, 0,            0,  0},
	{ "dr_reload_status", HLP5, mi_dr_reload_status,   0,            0,  0},
	{ 0, 0, 0, 0, 0, 0}
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
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "probing_interval", get_deps_probing_interval },
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"drouting",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	&deps,           /* OpenSIPS module dependencies */
	cmds,            /* Exported functions */
	0,               /* Exported async functions */
	params,          /* Exported parameters */
	0,               /* exported statistics */
	mi_cmds,         /* exported MI functions */
	0,               /* exported pseudo-variables */
	0,               /* additional processes */
	dr_init,         /* Module initialization function */
	(response_function) 0,
	(destroy_function) dr_exit,
	(child_init_function) dr_child_init /* per-child init function */
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

static int dr_disable(struct sip_msg *req, char * param_part_name) {
	str part_name;
	struct head_db * current_partition = 0;
	if( param_part_name!=NULL && fixup_get_svalue(req,
				(gparam_p)param_part_name,
				&part_name)==0 ) {
		if( (current_partition = get_partition(&part_name))!= NULL) {
			return dr_disable_w_part(req, current_partition);
		} else {
			LM_ERR("Given partition name <%.*s> was not found\n", part_name.len, part_name.s);
			return -1;
		}
	} else {
		if( use_partitions ) {
			LM_ERR("Partition name is mandatory <%.*s>\n", part_name.len
					,part_name.s);
			return -1;
		} else {
			if( head_db_start==NULL ) {
				LM_ERR(" Error while loading default converation from .cfg"
						" file\n");
				return -1;
			}
			return dr_disable_w_part(req, head_db_start);
		}
	}
	return -1;/* unexpected ending */
}

static str dr_gwid_str = str_init("gwid");
static str dr_address_str = str_init("address");
static str dr_status_str = str_init("status");
static str dr_inactive_str = str_init("inactive");
static str dr_active_str = str_init("active");
static str dr_disabled_str = str_init("disabled MI");
static str dr_probing_str = str_init("probing");

static void dr_raise_event(pgw_t *gw)
{
	evi_params_p list = NULL;
	str *txt;
	if (dr_evi_id == EVI_ERROR || !evi_probe_event(dr_evi_id))
		return;

	list = evi_get_params();
	if (!list) {
		LM_ERR("cannot create event params\n");
		return;
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


static int dr_disable_w_part(struct sip_msg *req, struct head_db *current_partition)
{
	struct usr_avp *avp;
	int_str id_val;
	pgw_t *gw;

	lock_start_read( current_partition->ref_lock );

	avp = search_first_avp( AVP_VAL_STR, current_partition->gw_id_avp, &id_val,0);
	if (avp==NULL) {
		LM_DBG(" no AVP ID ->nothing to disable\n");
		lock_stop_read( current_partition->ref_lock );
		return -1;
	}

	gw = get_gw_by_id( (*current_partition->rdata)->pgw_tree, &id_val.s );
	if (gw!=NULL && (gw->flags&DR_DST_STAT_DSBL_FLAG)==0) {
		LM_INFO(" partition : %.*s\n", current_partition->partition.len,
				current_partition->partition.s);
		gw->flags |= DR_DST_STAT_DSBL_FLAG|DR_DST_STAT_DIRT_FLAG;
		dr_raise_event(gw);
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

	current_partition = ( (param_prob_callback_t*) *ps->param)->current_partition;



	lock_start_read( current_partition->ref_lock );

	_id = ((param_prob_callback_t*)*ps->param)->_id;

	gw = get_gw_by_internal_id( (*(current_partition->rdata))->pgw_tree, _id);
	if (gw==NULL)
		goto end;

	if ((code == 200) || check_options_rplcode(code)) {
		/* re-enable to DST  (if allowed) */
		if ( (gw->flags&DR_DST_STAT_NOEN_FLAG)!=0 ||  /* permanently disabled */
				(gw->flags&DR_DST_STAT_DSBL_FLAG)==0)         /* not disabled at all */
			goto end;
		gw->flags &= ~DR_DST_STAT_DSBL_FLAG;
		gw->flags |= DR_DST_STAT_DIRT_FLAG;
		dr_raise_event(gw);
		goto end;
	}

	if (code>=400 && (gw->flags&DR_DST_STAT_DSBL_FLAG)==0) {
		gw->flags |= DR_DST_STAT_DSBL_FLAG|DR_DST_STAT_DIRT_FLAG;
		dr_raise_event(gw);
		goto end;
	}


end:
	lock_stop_read( current_partition->ref_lock );

	return;
}


static void param_prob_callback_free(void *param) {
	shm_free(param);
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
	while( it!=NULL ) {
		if (it->rdata==NULL || *(it->rdata)==NULL)
			return;

		lock_start_read( it->ref_lock );

		/* go through all destinations */
		for (map_first( (*(it->rdata))->pgw_tree, &map_it);
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
			if (dr_tmb.new_auto_dlg_uac(&dr_probe_from, &uri, dst->sock, &dlg)!=0) {
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
			dr_probing_callback, (void*)params, param_prob_callback_free)<0) {
				LM_ERR("unable to execute dialog, disabling destination...\n");
				if ( (dst->flags&DR_DST_STAT_DSBL_FLAG)==0 ) {
					dst->flags |= DR_DST_STAT_DSBL_FLAG|DR_DST_STAT_DIRT_FLAG;
					dr_raise_event(dst);
				}
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
	if (!hd || !(hd->rdata) || !(*hd->rdata))
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
	for (map_first((*hd->rdata)->pgw_tree , &it);
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
	for (map_first( (*hd->rdata)->carriers_tree, &it);
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

static inline int dr_reload_data_head( struct head_db *hd )
{
	rt_data_t *new_data;
	rt_data_t *old_data;
	pgw_t *gw, *old_gw;
	pcr_t *cr, *old_cr;
	time_t rawtime;

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

	new_data = dr_load_routing_info(hd, dr_persistent_state);
	if ( new_data==0 ) {
		LM_CRIT("failed to load routing info\n");
		goto error;
	}

	lock_start_write( hd->ref_lock );

	/* no more activ readers -> do the swapping */
	old_data = *(hd->rdata);
	*(hd->rdata) = new_data;
	/* update the time of the last reload for the current partition */
	time(&rawtime);
	hd->time_last_update = rawtime;

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
		free_rt_data( old_data, 1 );
	}

	/* generate new blacklist from the routing info */
	populate_dr_bls((*(hd->rdata))->pgw_tree);

	if (no_concurrent_reload)
		hd->ongoing_reload = 0;
	return 0;

error:
	if (no_concurrent_reload)
		hd->ongoing_reload = 0;
	return -1;
}

static inline int dr_reload_data( void ) {
	struct head_db * it_head_db;
	int ret_val = 0;

	for( it_head_db=head_db_start; it_head_db!=NULL;
			it_head_db=it_head_db->next ) {
		if( dr_reload_data_head( it_head_db )!=0 )
			ret_val = -1;
	}
	return ret_val;
}


#define dr_fix_avp_def_w_default( _pv_spec, _avp_id, _default, _p_name, _name)\
	if(_pv_spec.s == NULL) { \
		if(use_partitions) {\
			_pv_spec.len = _default.len + _p_name.len;\
			_pv_spec.s = shm_malloc((_pv_spec.len)*sizeof(char));\
			memcpy(_pv_spec.s, _default.s, _default.len-1);\
			memcpy(_pv_spec.s + _default.len - 1, _p_name.s, _p_name.len);\
			_pv_spec.s[_pv_spec.len-1] = ')';\
			LM_DBG("name with partition:%.*s\n",_pv_spec.len, _pv_spec.s);\
		}\
		else { \
			shm_str_dup(&_pv_spec, &_default);\
		}\
	}\
dr_fix_avp_definition(_pv_spec, _avp_id, _name);

#define dr_fix_avp_definition( _pv_spec, _avp_id, _name) \
	do { \
		if (pv_parse_spec( &_pv_spec, &avp_spec)==0 \
				|| avp_spec.type!=PVT_AVP) { \
			_pv_spec.len = strlen(_pv_spec.s); \
			LM_ERR("malformed or non AVP [%.*s] for %s AVP definition\n",\
					_pv_spec.len, _pv_spec.s, _name); \
			head_db_end->db_url.s = 0;\
			goto skip;\
		} \
		if( pv_get_avp_name(0, &(avp_spec.pvp), &_avp_id, &dummy )!=0) { \
			LM_ERR("[%.*s]- invalid AVP definition for %s AVP\n", \
					_pv_spec.len, _pv_spec.s, _name); \
			head_db_end->db_url.s = 0;\
			goto skip;\
		} \
	} while(0)

#define add_partition_to_avp_name( _spec, _p_name, _name_w_part ) \
	_name_w_part.len = _spec.len + _p_name.len; \
memcpy(_name_w_part.s, _spec.s, _spec.len);\
memcpy(_name_w_part.s + _spec.len, _p_name.s, _p_name.len);

static int cleanup_head_config( struct head_config *hd) {
	LM_DBG("Cleanup started\n");
	if( hd==NULL ) {
		LM_CRIT(" Cleanup head_config failed. Null pointer supplied\n");
		return -1;
	}

	if( hd->db_url.s ) {
		shm_free( hd->db_url.s );
		hd->db_url.s = 0;
	}

	if( hd->drd_table.s && hd->drd_table.s != drd_table.s) {
		shm_free( hd->drd_table.s );
	}
	if( hd->drr_table.s && hd->drr_table.s != drr_table.s) {
		shm_free( hd->drr_table.s );
	}
	if( hd->drc_table.s && hd->drc_table.s != drc_table.s) {
		shm_free( hd->drc_table.s );
	}
	if( hd->drg_table.s && hd->drg_table.s != drg_table.s) {
		shm_free( hd->drg_table.s );
	}

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


static int cleanup_head_db( struct head_db *hd) {
	if(hd) {
		if( hd->db_con &&  *(hd->db_con) ) {
			hd->db_funcs.close(*(hd->db_con));
		}
		if( hd->ref_lock ) {
			lock_destroy_rw( ref_lock );
		}
		if ( hd->rdata ) {
			shm_free(hd->rdata);
			hd->rdata = 0;
		}
		if ( hd->partition.s ) {
			shm_free(hd->partition.s);
			hd->partition.len = 0;
		}
		if( hd->db_url.s ) {
			shm_free( hd->db_url.s );
			hd->db_url.len = 0;
		}
		if( hd->drd_table.s && hd->drd_table.s != drd_table.s) {
			shm_free(hd->drd_table.s);
			hd->drd_table.s = 0;
			hd->drd_table.len = 0;
		}
		if( hd->drr_table.s && hd->drr_table.s != drr_table.s) {
			shm_free(hd->drr_table.s);
			hd->drr_table.s = 0;
			hd->drr_table.len = 0;
		}
		if( hd->drc_table.s && hd->drc_table.s != drc_table.s) {
			shm_free(hd->drc_table.s);
			hd->drc_table.s = 0;
			hd->drc_table.len = 0;
		}
		if( hd->drg_table.s && hd->drg_table.s != drg_table.s) {
			shm_free(hd->drg_table.s);
			hd->drg_table.s = 0;
			hd->drg_table.len = 0;
		}

		hd->avpID_store_ruri = -1;
		hd->avpID_store_prefix = -1;
		hd->avpID_store_index = -1;
		hd->avpID_store_whitelist = -1;
		hd->avpID_store_group = -1;
		hd->avpID_store_flags = -1;
		hd->gw_priprefix_avp = -1;
		hd->rule_id_avp = -1;
		hd->rule_prefix_avp = -1;
		hd->carrier_id_avp = -1;
		hd->ruri_avp = -1;
		hd->gw_id_avp = -1;
		hd->gw_sock_avp = -1;
		hd->gw_attrs_avp = -1;
		hd->rule_attrs_avp = -1;
		hd->carrier_attrs_avp = -1;
	} else {
		LM_CRIT(" No head_db to clean supplied");
		return -1;
	}
	return 0;
}

#define head_from_extern_param( _dst, _src, _name)\
	do { \
		if( (_src).s && ((_src).len=strlen((_src).s))!=0 ) {\
			if( shm_str_dup( &(_dst), &(_src))!=0 ) \
				LM_ERR(" Fail duplicating extern param (%s) to head\n",_name);\
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

static int dr_init(void)
{
	pv_spec_t avp_spec;
	unsigned short dummy;
	str name, name_w_part;
	struct head_config * it_head_config = 0;
	struct head_config * last_cleaned = 0;
	struct head_db * it_head_db = 0, *to_clean = 0;

	head_start = NULL; //empty head list
	head_end = NULL;

	LM_INFO("Dynamic-Routing - initializing\n");

	name_w_part.s = shm_malloc( MAX_LEN_NAME_W_PART /* length of
													   fixed string */);
	if( name_w_part.s == 0 ) {
		LM_ERR(" No more shm memory [drouting:name_w_part.s]\n");
		goto error;
	}

	if( use_partitions == 1 ) { /* loading configurations from db */
		if( get_config_from_db() == -1 ) {
			LM_ERR("Failed to get configuration from db_config\n");
			goto error;
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
		drd_table.len = strlen(drd_table.s);
		if (drd_table.s[0]==0) {
			LM_CRIT("mandatory parameter \"DRD_TABLE\" found empty\n");
			goto error;
		}
		head_start->drd_table.s = shm_malloc( drd_table.len * sizeof(char) );
		if( head_start->drd_table.s == 0 ) {
			LM_ERR(" no more shm memory [drouting:head_start->drd_table.s]\n");
			goto error;
		}
		memcpy( head_start->drd_table.s, drd_table.s, drd_table.len );
		head_start->drd_table.len = drd_table.len;

		drr_table.len = strlen(drr_table.s);
		if (drr_table.s[0]==0) {
			LM_CRIT("mandatory parameter \"DRR_TABLE\" found empty\n");
			goto error;
		}
		head_start->drr_table.s = shm_malloc( drr_table.len * sizeof(char) );
		if( head_start->drr_table.s == 0 ) {
			LM_ERR(" no more shm memory [drouting:head_start->drr_table.s]\n");
			goto error;
		}
		memcpy( head_start->drr_table.s, drr_table.s, drr_table.len);
		head_start->drr_table.len = drr_table.len;

		drg_table.len = strlen(drg_table.s);
		if (drg_table.s[0]==0) {
			LM_CRIT("mandatory parameter \"DRG_TABLE\" found empty\n");
			goto error;
		}
		head_start->drg_table.s = shm_malloc( drg_table.len * sizeof(char) );
		if( head_start->drg_table.s == 0 ) {
			LM_ERR(" no more shm memory [drouting:head_start->drg_table.s]\n");
			goto error;
		}
		memcpy( head_start->drg_table.s, drg_table.s, drg_table.len);
		head_start->drg_table.len = drg_table.len;

		drc_table.len = strlen(drc_table.s);
		if ( drc_table.s[0]==0 ) {
			LM_CRIT("mandatory parameter \"DRC_TABLE\" found empty\n");
			goto error;
		}
		head_start->drc_table.s = shm_malloc( drc_table.len * sizeof(char) );
		if( head_start->drc_table.s == 0 ) {
			LM_ERR(" no more shm memory [drouting:head_start->drc_table.s]\n");
			goto error;
		}
		memcpy( head_start->drc_table.s, drc_table.s, drc_table.len);
		head_start->drc_table.len = drc_table.len;

		head_start->db_url.len = db_url.len;
		head_start->db_url.s = shm_malloc( db_url.len * sizeof(char));
		if( head_start->db_url.s == 0 ) {
			LM_ERR(" no more shm memory [drouting:head_start->db_url.s]\n");
			goto error;
		}
		memcpy( head_start->db_url.s, db_url.s, db_url.len );

		init_head_w_extern_params();

		head_start->partition.s = "Default";
		head_start->partition.len = strlen("Default\0");
	}

	it_head_config = head_start;

	drg_user_col.len = strlen(drg_user_col.s);
	drg_domain_col.len = strlen(drg_domain_col.s);
	drg_grpid_col.len = strlen(drg_grpid_col.s);

	while(it_head_config != NULL) {
		/* check if last head was ok, if not overwrite it */
		if( head_db_start==NULL || (head_db_start!=NULL &&
					head_db_end->db_url.s!=NULL) ) {
			add_head_db();
		}

		if( it_head_config->db_url.s==0 )
			continue;

		if( shm_str_dup( &( head_db_end->db_url ),
					&(it_head_config->db_url))!=0 ) {
			LM_CRIT("shm_str_dup failed for db_url");
			head_db_end->db_url.s = 0;
			goto skip;
		}

		if( shm_str_dup( &( head_db_end->partition ),
					&(it_head_config->partition))!=0 ) {
			LM_CRIT("shm_str_dup failed for db_url");
			head_db_end->db_url.s = 0;
			goto skip;
		}

		if(!it_head_config->drd_table.s) {
			head_db_end->drd_table.s = drd_table.s;
			head_db_end->drd_table.len = drd_table.len;
		}else if( shm_str_dup( &( head_db_end->drd_table ),
					&(it_head_config->drd_table))!=0 ) {
			LM_CRIT("shm_str_dup failed for db_url");
			head_db_end->db_url.s = 0;
			goto skip;
		}

		if(!it_head_config->drr_table.s) {
			head_db_end->drr_table.s = drr_table.s;
			head_db_end->drr_table.len = drr_table.len;
		}else if( shm_str_dup( &( head_db_end->drr_table ),
					&(it_head_config->drr_table))!=0 ) {
			LM_CRIT("shm_str_dup failed for db_url");
			head_db_end->db_url.s = 0;
			goto skip;
		}

		if(!it_head_config->drc_table.s) {
			head_db_end->drc_table.s = drc_table.s;
			head_db_end->drc_table.len = drc_table.len;
		} else if( shm_str_dup( &( head_db_end->drc_table ),
					&(it_head_config->drc_table))!=0 ) {
			LM_CRIT("shm_str_dup failed for db_url");
			head_db_end->db_url.s = 0;
			goto skip;
		}
		if(!it_head_config->drg_table.s) {
			head_db_end->drg_table.s = drg_table.s;
			head_db_end->drg_table.len = drg_table.len;
		} else if( shm_str_dup( &( head_db_end->drg_table ),
					&(it_head_config->drg_table))!=0 ) {
			LM_CRIT("shm_str_dup failed for db_url");
			head_db_end->db_url.s = 0;
			goto skip;
		}


		/* fix specs for internal AVP (used for fallback) */
		/* partition name is added to AVP name */

		name.s = "_dr_fb_ruri_"; name.len=12;
		add_partition_to_avp_name( name, it_head_config->partition,
				name_w_part);

		if ( parse_avp_spec( &name_w_part,
		&(head_db_end->avpID_store_ruri))!=0 ) {
			LM_ERR("failed to init internal AVP for ruri\n");
			head_db_end->db_url.s = 0;
			goto skip;
		}

		name.s = "_dr_fb_prefix_"; name.len=14;
		add_partition_to_avp_name( name, it_head_config->partition,
				name_w_part);
		if ( parse_avp_spec( &name_w_part,
		&(head_db_end->avpID_store_prefix))!=0 ) {
			LM_ERR("failed to init internal AVP for prefix\n");
			head_db_end->db_url.s = 0;
			goto skip;
		}

		name.s = "_dr_fb_index_"; name.len=13;
		add_partition_to_avp_name( name, it_head_config->partition,
				name_w_part);
		if ( parse_avp_spec( &name_w_part,
		&(head_db_end->avpID_store_index))!=0 ) {
			LM_ERR("failed to init internal AVP for index\n");
			head_db_end->db_url.s = 0;
			goto skip;
		}

		name.s = "_dr_fb_whitelist_"; name.len=17;
		add_partition_to_avp_name( name, it_head_config->partition,
				name_w_part);
		if ( parse_avp_spec( &name_w_part,
		&(head_db_end->avpID_store_whitelist))!=0 ) {
			LM_ERR("failed to init internal AVP for whitelist\n");
			head_db_end->db_url.s = 0;
			goto skip;
		}

		name.s = "_dr_fb_group_"; name.len=13;
		add_partition_to_avp_name( name, it_head_config->partition,
				name_w_part);
		if ( parse_avp_spec( &name_w_part,
		&(head_db_end->avpID_store_group))!=0 ) {
			LM_ERR("failed to init internal AVP for group\n");
			head_db_end->db_url.s = 0;
			goto skip;
		}

		name.s = "_dr_fb_flags_"; name.len=13;
		add_partition_to_avp_name( name, it_head_config->partition,
				name_w_part);
		if ( parse_avp_spec( &name_w_part,
		&(head_db_end->avpID_store_flags))!=0 ) {
			LM_ERR("failed to init internal AVP for flags\n");
			head_db_end->db_url.s = 0;
			goto skip;
		}

		/* fix AVP specs for parameters */
		dr_fix_avp_def_w_default( it_head_config->ruri_avp_spec,
				head_db_end->ruri_avp, ruri_avp_spec,
				it_head_config->partition, "RURI");

		dr_fix_avp_def_w_default( it_head_config->gw_id_avp_spec,
				head_db_end->gw_id_avp, gw_id_avp_spec,
				it_head_config->partition, "GW ID");

		dr_fix_avp_def_w_default( it_head_config->gw_sock_avp_spec,
				head_db_end->gw_sock_avp, gw_sock_avp_spec,
				it_head_config->partition, "GW SOCKET");

		dr_fix_avp_def_w_default( it_head_config->gw_attrs_avp_spec,
				head_db_end->gw_attrs_avp, gw_attrs_avp_spec,
				it_head_config->partition, "GW ATTRS");

		dr_fix_avp_def_w_default( it_head_config->rule_attrs_avp_spec,
				head_db_end->rule_attrs_avp, rule_attrs_avp_spec,
				it_head_config->partition, "RULE ATTRS");

		dr_fix_avp_def_w_default( it_head_config->carrier_attrs_avp_spec,
				head_db_end->carrier_attrs_avp, carrier_attrs_avp_spec,
				it_head_config->partition, "CARRIER ATTRS");

		if (it_head_config->gw_priprefix_avp_spec.s ) {
			dr_fix_avp_definition( it_head_config->gw_priprefix_avp_spec,
					head_db_end->gw_priprefix_avp, "GW PRI PREFIX");
		}

		if (it_head_config->rule_id_avp_spec.s) {
			dr_fix_avp_definition( it_head_config->rule_id_avp_spec,
					head_db_end->rule_id_avp, "RULE ID");
		}

		if (it_head_config->rule_prefix_avp_spec.s) {
			dr_fix_avp_definition( it_head_config->rule_prefix_avp_spec,
					head_db_end->rule_prefix_avp, "RULE PREFIX");
		}

		if (it_head_config->carrier_id_avp_spec.s) {
			dr_fix_avp_definition( it_head_config->carrier_id_avp_spec,
					head_db_end->carrier_id_avp, "CARRIER ID");
		}

		/* data pointer in shm */
		head_db_end->rdata = (rt_data_t**)shm_malloc( sizeof(rt_data_t*) );
		if ( head_db_end->rdata==0 ) {
			LM_CRIT("failed to get shm mem for data ptr\n");
			head_db_end->db_url.s = 0;
			goto skip;
		}

		*(head_db_end->rdata) = 0;

		/* create & init lock */
		if ((head_db_end->ref_lock = lock_init_rw()) == NULL) {
			LM_CRIT("failed to init lock\n");
			head_db_end->db_url.s = 0;
			goto skip;
		}

		head_db_end->db_con = pkg_malloc(sizeof(db_con_t **));
		(*(head_db_end->db_con)) = 0;

		/* bind to the SQL module */
		if (db_bind_mod( &(head_db_end->db_url), &( head_db_end->db_funcs ))) {
			LM_CRIT("cannot bind to database module! "
					"Did you forget to load a database module ? (%.*s)\n",
					db_url.len, db_url.s);
			head_db_end->db_url.s = 0;
			goto skip;
		}

		if( (*head_db_end->db_con =
					head_db_end->db_funcs.init(&head_db_end->db_url)) == 0) {
			LM_ERR("Cand't load db ulr %.*s", head_db_end->db_url.len,
					head_db_end->db_url.s);
			return -1;
		}

		if (!DB_CAPABILITY( head_db_end->db_funcs, DB_CAP_QUERY)) {
			LM_CRIT( "database modules does not "
					"provide QUERY functions needed by DRouting module\n");
			head_db_end->db_url.s = 0;
			goto skip;
		}

		if(db_check_table_version(&head_db_end->db_funcs, *head_db_end->db_con,
					&head_db_end->drd_table, DRD_TABLE_VER) < 0) {
			LM_ERR("error during table version check<dr_gateways table \'%.*s\',"
					" for partition \'%.*s\'>\n", head_db_end->drd_table.len,
					head_db_end->drd_table.s, head_db_end->partition.len,
					head_db_end->partition.s);
			return -1;
		}

		if(db_check_table_version(&head_db_end->db_funcs, *head_db_end->db_con,
					&head_db_end->drr_table, DRR_TABLE_VER) < 0) {
			LM_ERR("error during table version check<dr_rules table \'%.*s\',"
					" for partition \'%.*s\'>\n", head_db_end->drr_table.len,
					head_db_end->drr_table.s, head_db_end->partition.len,
					head_db_end->partition.s);
			return -1;
		}

		if(db_check_table_version(&head_db_end->db_funcs, *head_db_end->db_con,
					&head_db_end->drg_table, DRG_TABLE_VER) < 0) {
			LM_ERR("error during table version check<dr_groups table \'%.*s\',"
					" for partition \'%.*s\'>\n", head_db_end->drg_table.len,
					head_db_end->drg_table.s, head_db_end->partition.len,
					head_db_end->partition.s);
			return -1;
		}

		if(db_check_table_version(&head_db_end->db_funcs, *head_db_end->db_con,
					&head_db_end->drc_table, DRC_TABLE_VER) < 0) {
			LM_ERR("error during table version check<dr_carriers table \'%.*s\',"
					" for partition \'%.*s\'>\n", head_db_end->drc_table.len,
					head_db_end->drc_table.s, head_db_end->partition.len,
					head_db_end->partition.s);
			return -1;
		}

		(head_db_end->db_funcs).close(*head_db_end->db_con);
		*head_db_end->db_con = 0;


skip:
		it_head_config = it_head_config->next;
		if(head_db_end->db_url.s == 0) {
			cleanup_head_db(head_db_end);
			memset( head_db_end, 0, sizeof(struct head_db) );
		}
	}

	if( name_w_part.s ) {
		shm_free(name_w_part.s);
		name_w_part.s = 0;
	}

	/* free last head if left uninitialized */
	if( head_db_end!=NULL && head_db_end->db_url.s==NULL ) {
		if( head_db_end==head_db_start ) {
			cleanup_head_db( head_db_start );
			memset( head_db_start, 0, sizeof(struct head_db) );
			if( head_db_start ) {
				shm_free( head_db_start );
			}
			head_db_start=head_db_end = 0;
			return -1; /* no valid head available */
		} else {
			it_head_db = head_db_start;
			while( it_head_db->next!=head_db_end )
				it_head_db = it_head_db->next;
			to_clean = head_db_end;
			head_db_end = it_head_db;
			head_db_end->next = NULL;
			cleanup_head_db( to_clean );
			memset( to_clean, 0, sizeof(struct head_db) );
			if( to_clean ) {
				shm_free( to_clean );
				to_clean = 0;
			}

		}
	}

	if (init_dr_bls(head_db_start)!=0) {
		LM_ERR("failed to init DR blacklists\n");
		return E_CFG;
	}
	it_head_config = head_start;
	while( it_head_config ) {
		cleanup_head_config( it_head_config );
		last_cleaned = it_head_config;
		it_head_config = it_head_config->next;

		memset( last_cleaned, 0 , sizeof( struct head_config ));

		if( last_cleaned ) {
			shm_free( last_cleaned );
			last_cleaned = 0;
		}
	}
	head_start = 0;
	head_end = 0;

	if (dr_prob_interval) {
		/* load TM API */
		if (load_tm_api(&dr_tmb)!=0) {
			LM_ERR("can't load TM API\n");
			return -1;
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
			return -1;
		}

		if (dr_probe_replies.s) {
			dr_probe_replies.len = strlen(dr_probe_replies.s);
			if(parse_reply_codes( &dr_probe_replies, &probing_reply_codes,
						&probing_codes_no )< 0) {
				LM_ERR("Bad format for options_reply_code parameter"
						" - Need a code list separated by commas\n");
				return -1;
			}
		}

	}

	if (dr_persistent_state) {
		/* register function to flush changes in state */
		if (register_timer("dr-flush", dr_state_timer, NULL, 30,
		TIMER_FLAG_SKIP_ON_DELAY)<0) {
			LM_ERR("failed to register state flush handler\n");
			return -1;
		}
	}
	LM_DBG("All in place in the init. Will return 0\n");

	/* init the the default partition for do_routing */
	default_part = pkg_malloc(sizeof(dr_part_group_t));
	if(default_part == NULL) {
		LM_ERR("No more pkg memory!\n");
		goto error;
	}
	memset(default_part, 0, sizeof(dr_part_group_t));
	default_part->dr_part = pkg_malloc(sizeof(dr_partition_t));
	if(default_part->dr_part == NULL) {
		LM_ERR("No more pkg memory!\n");
		goto error;
	}
	memset(default_part->dr_part, 0, sizeof(dr_partition_t));
	default_part->dr_part->type = DR_PTR_PART;
	default_part->dr_part->v.part = head_db_start;

	dr_evi_id = evi_publish_event(dr_event);
	if (dr_evi_id == EVI_ERROR) {
		LM_ERR("cannot register %.*s event\n", dr_event.len, dr_event.s);
		goto error;
	}



	return 0;

error:
	/* clean-up -> only when we used extern_params
	 * from the cfg*/
	if( head_db_end==head_db_start) { /* sanity check: should contain
										 only one head */
		cleanup_head_db( head_db_end );
		if( head_db_end!=0 ) {
			shm_free( head_db_end );
		}
		head_db_end=head_db_start = 0;

		cleanup_head_config( head_end );
		if( head_end!=0 ) {
			shm_free( head_end );
			head_end = 0;
		}


		if (name_w_part.s) {
			shm_free(name_w_part.s);
			name_w_part.s = NULL;
		}
	} else {
		LM_ERR(" Something went wrong: Head list should have only "
				"one head\n");
	}
	return -1;
}


static int db_load_head(struct head_db *x) {

	if( *(x->db_con) ) {
		LM_ERR(" db_con already used\n");
		return -1;
	}
	if( x->db_url.s && (*(x->db_con) = x->db_funcs.init(&(x->db_url)))==0 ) {
		LM_ERR("cannot initialize database connection"
				"(partition:%.*s, db_url:%.*s, len:%d)\n", x->partition.len,
				x->partition.s, x->db_url.len, x->db_url.s, x->db_url.len);
		return -1;
	}
	if( x->db_con && *(x->db_con) &&
			x->db_funcs.use_table( *(x->db_con), &(x->drg_table)) <0 ) {
		LM_ERR("cannot select table (partition:%.*s, drg_table:%.*s\n",
				x->partition.len, x->partition.s, (x->drg_table).len,
				(x->drg_table).s);
		return -1;
	}
	return 0;
}



static int dr_child_init(int rank)
{
	/* We need DB connection from:
	 * 	 - attendant - for shutdown, flushingmstate
	 *   - timer - may trigger routes with dr group
	 *   - workers - execute routes with dr group
	 *   - module's proc - ??? */
	LM_DBG("Child initialization\n");
	if (rank==PROC_TCP_MAIN || rank==PROC_BIN)
		return 0;

	struct head_db *head_db_it = head_db_start;

	while( head_db_it!=NULL ) {
		db_load_head( head_db_it );
		head_db_it = head_db_it->next;

		LM_DBG("Child iterates\n");
	}

	/* child 1 load the routing info */
	if ( (rank==1) && dr_reload_data()!=0 ) {
		LM_CRIT("failed to load routing data\n");
		return -1;
	}
	srand(getpid()+time(0)+rank);
	return 0;
}


static int dr_exit(void)
{
	struct head_db * it = head_db_start, *to_clean;

	while( it!=NULL ) {
		to_clean = it;
		it = it->next;
		if (dr_persistent_state && to_clean->db_con && *(to_clean->db_con))
			dr_state_flusher(to_clean);

		/* close DB connection */
		if (to_clean->db_con && *(to_clean->db_con)) {
			(to_clean->db_funcs).close(*(to_clean->db_con));
			*(to_clean->db_con) = 0;
			pkg_free(to_clean->db_con);
		}

		/* destroy data */
		if ( to_clean->rdata) {
			if (*(to_clean->rdata))
				free_rt_data( *(to_clean->rdata), 1 );
			shm_free( to_clean->rdata );
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

	/* destroy blacklists */
	destroy_dr_bls();

	/* destroy all callbacks */
	destroy_dr_cbs();

	return 0;
}



static struct mi_root* dr_reload_cmd(struct mi_root *cmd_tree, void *param)
{
	int n;
	str * part_name;
	struct head_db * part;
	struct mi_node * node = NULL;

	LM_INFO("dr_reload MI command received!\n");

	if(cmd_tree!=NULL)
		node = cmd_tree->node.kids;

	if(node==NULL || use_partitions==0) {
		/* no parameter supplied
		 * -> load the data for all the partitions */
		if ( (n=dr_reload_data())!=0 ) {
			LM_CRIT("failed to load routing data\n");
			goto error;
		}
	} else {
		part_name = &(node->value);
		if( (part = get_partition(part_name))==NULL) {
			LM_CRIT("Partition not found\n");
			goto error;
		}
		if( dr_reload_data_head(part)<0 ) {
			LM_CRIT("Failed to load data head\n");
			goto error;
		}
	}


	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
error:
	return init_mi_tree( 500, "Failed to reload",16);
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
	char *p;

	if (uri->user.len<=strip) {
		LM_ERR("stripping %d makes "
				"username <%.*s> null\n",strip,uri->user.len,uri->user.s);
		return 0;
	}

	uri_str.len = 4 /*sip:*/ + uri->user.len - strip +pri->len +
		(uri->passwd.s?(uri->passwd.len+1):0) + 1/*@*/ + hostport->len +
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


static inline void pack_part_grp(dr_part_group_t ** part_w_no_grp,
						struct head_db * current_partition, dr_group_t * drg)
{
	static dr_part_group_t  part_grp;
	static dr_partition_t   part;

	memset( &part_grp, 0, sizeof(dr_part_group_t));
	memset( &part, 0, sizeof(dr_partition_t));

	part.type = DR_PTR_PART;
	part.v.part = current_partition;

	part_grp.group = drg;
	part_grp.dr_part = &part;

	*part_w_no_grp = &part_grp;
}

static int do_routing_0(struct sip_msg* msg)
{
	rule_attrs_spec = gw_attrs_spec = carrier_attrs_spec = NULL;
	dr_part_group_t * part_w_no_grp;
	if(use_partitions == 0) {
		if(head_db_start == NULL) {
			LM_ERR("Error while loading configuration\n");
			return -1;
		}
		pack_part_grp(&part_w_no_grp, head_db_start, 0);
		return do_routing(msg, part_w_no_grp, (int)0, NULL);
	} else {
		LM_ERR("Partition name is mandatory");
		return -1;
	}
	return -1;
}


static int do_routing_1(struct sip_msg* msg, char *part_grp, char* grp_flags,
		char* flags_wlst, char* wlst_rule, char* rule_gw,
		char* gw_carr, char* carr)
{
	str res = {0,0};
	dr_part_group_t * dr_part_group;
	int flags=0;
	char *p;
	char * _flags, * wlst, * rule_att, * gw_att, * carr_att;

	if (use_partitions == 0) {
		if(head_db_start == NULL) {
			LM_CRIT("Can't load configuration.\n");
			return -1;
		}
		if(part_grp != NULL) {
			default_part->group = ((dr_part_group_t*)part_grp)->group;
		} else {
			default_part->group = NULL;
		}
		dr_part_group = default_part;
		_flags = grp_flags;
		wlst = flags_wlst;
		rule_att = wlst_rule;
		gw_att = rule_gw;
		carr_att = gw_carr;
	} else {
		dr_part_group = (dr_part_group_t*)part_grp;
		_flags = grp_flags;
		wlst = flags_wlst;
		rule_att = wlst_rule;
		gw_att = rule_gw;
		carr_att = gw_carr;
	}

	if (_flags) {
		if (fixup_get_svalue(msg, (gparam_p)_flags, &res) != 0) {
			LM_ERR("failed to extract flags\n");
			return -1;
		}

		for (p=res.s;p<res.s+res.len;p++)
		{
			switch (*p)
			{
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
	}

	rule_attrs_spec = (pv_spec_p)rule_att;
	gw_attrs_spec = (pv_spec_p)gw_att;
	carrier_attrs_spec = (pv_spec_p)carr_att;

	return do_routing(msg, (dr_part_group_t*)dr_part_group, flags, (gparam_t*)wlst);
}

static int use_next_gw(struct sip_msg* msg, char* rule_or_part,
		char * rule_or_gw, char *gw_carr, char * carr) {
	dr_partition_t * part = 0;
	struct head_db * current_partition = 0;

	if( use_partitions ) { /* first argument is partition name */
		part = (dr_partition_t*)rule_or_part;
		if(part != NULL) {
			if(part->type == DR_PTR_PART) {
				current_partition = part->v.part;
			} else if(part->type == DR_GPARAM_PART) {
				if(to_partition(msg, part, &current_partition) < 0) {
					return -1;
				}
			}
			return use_next_gw_w_part(msg, current_partition, rule_or_gw,
					gw_carr, carr);
		} else {
			LM_ERR("Partition is mandatory for use_next_gw.\n");
			return -1;
		}
	} else { /* setup from .cfg file => default partition */
		if(head_db_start == NULL) {
			LM_ERR(" Error while loading default converation from .cfg"
					" file\n");
			return -1;
		}
		return use_next_gw_w_part(msg, head_db_start, rule_or_part,
				rule_or_gw, gw_carr);
	}
	return 0;
}


static int use_next_gw_w_part(struct sip_msg* msg,
		struct head_db * current_partition,
		char* rule_att, char* gw_att, char* carr_att)
{
	struct usr_avp *avp, *avp_ru, *avp_sk;
	unsigned int flags;
	gparam_t wl_list;
	dr_group_t grp;
	int_str val;
	pv_value_t pv_val;
	str ruri;
	dr_part_group_t * part_grp;
	int ok = 0;
	pgw_t * dst;
	struct socket_info *sock;

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
			avp = search_first_avp(0, current_partition->rule_attrs_avp, &val, NULL);
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
				avp = search_first_avp( 0, current_partition->gw_attrs_avp, NULL, NULL);
			}while (avp && (avp->flags&AVP_VAL_STR)==0 );
			if (avp) destroy_avp(avp);

			avp = search_first_avp(0, current_partition->gw_attrs_avp, &val, NULL);
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
				avp = search_first_avp( 0, current_partition->carrier_attrs_avp, NULL, NULL);
			}while (avp && (avp->flags&AVP_VAL_STR)==0 );
			if (avp) destroy_avp(avp);

			avp = search_first_avp(0, current_partition->carrier_attrs_avp, &val, NULL);
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
				avp = search_first_avp( 0, current_partition->gw_priprefix_avp, NULL, NULL);
			}while (avp && (avp->flags&AVP_VAL_STR)==0 );
			if (avp) destroy_avp(avp);
		}

		/* remove the old carrier ID */
		if (current_partition->carrier_id_avp!=-1) {
			avp = NULL;
			do {
				if (avp) destroy_avp(avp);
				avp = search_first_avp( 0, current_partition->carrier_id_avp, NULL, NULL);
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
			LM_WARN("no GWs found at all -> have you done do_routing in script ?? \n");
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

		LM_DBG("new RURI set to <%.*s> via socket <%.*s>\n",
				ruri.len, ruri.s,
				sock?sock->name.len:4, sock?sock->name.s:"none");

		/* get value for next gw ID from avp */
		get_avp_val(avp, &val);

		/* we have an ID, so we can check the GW state */
		lock_start_read( current_partition->ref_lock );
		dst = get_gw_by_id( (*current_partition->rdata)->pgw_tree, &val.s);
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
	grp.type = 0;
	grp.u.grp_id = val.n;

	if (!search_first_avp( AVP_VAL_STR, current_partition->avpID_store_whitelist,
				&val, NULL)) {
		wl_list.type = 0;
	} else {
		wl_list.type = GPARAM_TYPE_STR;
		wl_list.v.sval = val.s;
		wl_list.v.sval.s[--wl_list.v.sval.len] = 0;
	}

	pack_part_grp(&part_grp, current_partition, &grp);
	if (do_routing( msg, part_grp, flags, wl_list.type?&wl_list:NULL)==1) {
		return 1;
	}

fallback_failed:
	/* prevent any more fallback by removing the flags AVP */
	destroy_avp(avp);
	return -1;
}


#define DR_MAX_GWLIST	64

static int sort_rt_dst(pgw_list_t *pgwl, unsigned short size,
		int weight, unsigned short *idx)
{
	unsigned short running_sum[DR_MAX_GWLIST];
	unsigned int i, first, weight_sum, rand_no;

	/* populate the index array */
	for( i=0 ; i<size ; i++ ) idx[i] = i;
	first = 0;

	if (weight==0)
		return 0;

	while (size-first>1) {
		/* calculate the running sum */
		for( i=first,weight_sum=0 ; i<size ; i++ ) {
			weight_sum += pgwl[ idx[i] ].weight ;
			running_sum[i] = weight_sum;
			LM_DBG("elen %d, weight=%d, sum=%d\n",i,
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
				LM_CRIT("bug in weight sort\n");
				return -1;
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
}


inline static int push_gw_for_usage(struct sip_msg *msg, struct head_db *current_partition,
		struct sip_uri *uri, pgw_t *gw , str *c_id, str *c_attrs, int idx)
{
	char buf[PTR_STRING_SIZE]; /* a hexa string */
	str *ruri;
	int_str val;
	if( current_partition==NULL ) {
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
		if (add_avp_last( AVP_VAL_STR, current_partition->gw_sock_avp, val)!=0 ) {
			LM_ERR("failed to insert sock avp\n");
			goto error;
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


struct head_db * get_partition(const str *name) {
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


static int do_routing(struct sip_msg* msg, dr_part_group_t * part_group,
		int flags, gparam_t* whitelist)
{
	unsigned short dsts_idx[DR_MAX_GWLIST];
	unsigned short carrier_idx[DR_MAX_GWLIST];
	struct to_body  *from;
	struct sip_uri  uri;
	rt_info_t  *rt_info;
	pv_value_t pv_val;
	struct usr_avp *avp, *avp_prefix=NULL, *avp_index=NULL;
	str parsed_whitelist;
	pgw_list_t *dst, *cdst;
	pgw_list_t *wl_list;
	unsigned int prefix_len;
	unsigned int rule_idx;
	struct head_db *current_partition=NULL;
	unsigned short wl_len;
	dr_group_t * drg;
	str username;
	int grp_id;
	int i, j, n;
	int_str val;
	str ruri;
	str next_carrier_attrs = {NULL, 0};
	str next_gw_attrs = {NULL, 0};
	int ret, fret;
	char tmp;
	char *ruri_buf;

	gparam_p tmp_gparam = NULL;

	ret = -1;
	ruri_buf = NULL;
	wl_list = NULL;
	rt_info = NULL;

	if(use_partitions) {
		if(part_group == NULL || part_group->dr_part == NULL ||
		part_group->dr_part->type == DR_NO_PART) {
			LM_ERR("Partition name is mandatory for do_routing\n");
			return -1;
		}

		if(part_group->dr_part->type == DR_GPARAM_PART) {
			if ((fret=to_partition(msg, part_group->dr_part, &current_partition))<0) {
				return -1;
			} else if (fret == 1) {
				tmp_gparam = part_group->dr_part->v.part_name;
				part_group->dr_part->type = DR_WILDCARD_PART;
			}

		} else if(part_group->dr_part->type == DR_PTR_PART) {
			current_partition = part_group->dr_part->v.part;
		}


		if (part_group->dr_part->type == DR_WILDCARD_PART) {
			for (current_partition = head_db_start;
					current_partition; current_partition = current_partition->next) {
				part_group->dr_part->v.part = current_partition;
				part_group->dr_part->type = DR_PTR_PART;

				ret=do_routing( msg, part_group, flags, whitelist);
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

			/* restore to initial state */
			if (tmp_gparam) {
				part_group->dr_part->type = DR_GPARAM_PART;
			} else {
				memset(part_group->dr_part, 0, sizeof(dr_partition_t));
				part_group->dr_part->type = DR_WILDCARD_PART;
			}

			/* ret must be less than 0 here if nothing found */
			return ret;
		}
	} else {
		if(part_group->dr_part->type == DR_PTR_PART) {
			current_partition = part_group->dr_part->v.part;
		} else {
			LM_ERR("Error while loading configuration for do_routing\n");
		}
	}
	drg = part_group->group;


	/* allow no GWs if we're only trying to use DR for checking purposes */
	if ( *(current_partition->rdata)==0 || ((flags & DR_PARAM_ONLY_CHECK) == 0
				&& (*(current_partition->rdata))->pgw_tree==0 )) {
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

		if ((current_partition->gw_priprefix_avp)!=-1)
			destroy_avps( 0, current_partition->gw_priprefix_avp, 1);
		if ((current_partition->rule_id_avp)!=-1)
			destroy_avps( 0, current_partition->rule_id_avp, 1);
		if ((current_partition->rule_prefix_avp)!=-1)
			destroy_avps( 0, current_partition->rule_prefix_avp, 1);
	}

	if ( !(flags & DR_PARAM_INTERNAL_TRIGGERED) ) {
		/* not internally triggered, so get data from SIP msg */
		if(drg==NULL)
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

			grp_id = get_group_id( &uri, current_partition);
			if (grp_id<0) {
				LM_ERR("failed to get group id\n");
				goto error1;
			}
		} else {
			if(drg->type==0)
				grp_id = (int)drg->u.grp_id;
			else if(drg->type==1) {
				grp_id = 0; /* call get avp here */
				if((avp=search_first_avp(0, drg->u.avp_name, &val, 0))==NULL ||
						(avp->flags&AVP_VAL_STR) ) {
					LM_ERR( "failed to get group id from avp\n");
					goto error1;
				}
				grp_id = val.n;
			} else
				grp_id = 0;
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
		grp_id = (int)drg->u.grp_id;
		ruri.s = NULL; ruri.len = 0;
	}


	LM_DBG("using dr group %d, rule_idx %d, username %.*s\n",
			grp_id,rule_idx,username.len,username.s);

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
	rt_info = get_prefix( (*(current_partition->rdata))->pt, &username,
			(unsigned int)grp_id,&prefix_len, &rule_idx);

	if (flags & DR_PARAM_STRICT_LEN) {
		if (rt_info==NULL || prefix_len!=username.len)
			goto error2;
	}

	if (rt_info==0) {
		LM_DBG("no matching for prefix \"%.*s\"\n",
				username.len, username.s);
		/* try prefixless rules */
		rt_info = check_rt( &(*(current_partition->rdata))->noprefix,
				(unsigned int)grp_id);
		if (rt_info==0) {
			LM_DBG("no prefixless matching for "
					"grp %d\n", grp_id);
			goto error2;
		}
		prefix_len = 0;
	}

	if (rt_info->route_idx>0 && rt_info->route_idx<RT_NO) {
		fret = run_top_route( rlist[rt_info->route_idx].a, msg );
		if (fret&ACT_FL_DROP) {
			/* drop the action */
			LM_DBG("script route %s drops routing "
					"by %d\n", rlist[rt_info->route_idx].name, fret);
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
				grp_id,rule_idx,username.len,username.s);
		if ( flags & DR_PARAM_RULE_FALLBACK )
			goto search_again;
		goto error2;
	}

	/* sort the destination elements in the rule */
	i = sort_rt_dst(rt_info->pgwl, rt_info->pgwa_len,
			flags&DR_PARAM_USE_WEIGTH, dsts_idx);
	if (i!=0) {
		LM_ERR("failed to sort destinations in rule\n");
		goto error2;
	}

	/* evaluate and parse the whitelist of GWs/CARRIERs, if provided and
	   if the first time here */
	if (whitelist && wl_list==NULL) {
		if (fixup_get_svalue(msg, whitelist, &parsed_whitelist)!=0) {
			LM_ERR("failed to evaluate whitelist-> ignoring...\n");
		} else {
			tmp = parsed_whitelist.s[parsed_whitelist.len];
			parsed_whitelist.s[parsed_whitelist.len] = 0;
			if (parse_destination_list( *(current_partition->rdata),
						parsed_whitelist.s, &wl_list, &wl_len, 1)!=0) {
				LM_ERR("invalid format in whitelist-> ignoring...\n");
				wl_list = NULL;
			}
			parsed_whitelist.s[parsed_whitelist.len] = tmp;
		}
	}

	/* iterate through the list, skip the disabled destination */
	for ( i=0 ; i<rt_info->pgwa_len ; i++ ) {

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
			j = sort_rt_dst(dst->dst.carrier->pgwl, dst->dst.carrier->pgwa_len,
					dst->dst.carrier->flags&DR_CR_FLAG_WEIGHT, carrier_idx);
			if (j!=0) {
				LM_ERR("failed to sort gws for carrier <%.*s>, skipping\n",
						dst->dst.carrier->id.len, dst->dst.carrier->id.s);
				continue;
			}

			/* iterate through the list of GWs provided by carrier */
			for ( j=0 ; j<dst->dst.carrier->pgwa_len ; j++ ) {

				cdst = &dst->dst.carrier->pgwl[carrier_idx[j]];

				/* is gateway disabled ? */
				if (cdst->dst.gw->flags & DR_DST_STAT_DSBL_FLAG ) {
					/*ignore it*/
				} else {
					/* add gateway to usage list */
					if ( push_gw_for_usage(msg, current_partition,
					&uri, cdst->dst.gw ,
					&dst->dst.carrier->id, &dst->dst.carrier->attrs, n ) ) {
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

		} else {

			/* is gateway disabled ? */
			if (dst->dst.gw->flags & DR_DST_STAT_DSBL_FLAG
					|| !is_dst_in_list( (void*)dst->dst.gw, wl_list, wl_len) )
				continue;

			/* add gateway to usage list */
			if ( push_gw_for_usage(msg, current_partition, &uri,
						dst->dst.gw, NULL, NULL, n) ) {
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
		LM_INFO("All the gateways are disabled\n");
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
				if (add_avp( AVP_VAL_STR, current_partition->avpID_store_prefix,
							val) ) {
					LM_ERR("failed to insert prefix avp for fallback\n");
					flags = flags & ~DR_PARAM_RULE_FALLBACK;
				}
				/* also store current ruri as we will need it */
				val.s = ruri;
				if (add_avp( AVP_VAL_STR, current_partition->avpID_store_ruri, val) ) {
					LM_ERR("failed to insert ruri avp for fallback\n");
					flags = flags & ~DR_PARAM_RULE_FALLBACK;
				}
				/* we need to save a some date, to be able to do the rule
				   fallback later in "next_gw" (prefix/index already added) */
				if (wl_list) {
					val.s = parsed_whitelist ;
					val.s.len++; /* we need extra space to place \0 when using */
					if (add_avp( AVP_VAL_STR,
								current_partition->avpID_store_whitelist, val) ) {
						LM_ERR("failed to insert whitelist avp for fallback\n");
						flags = flags & ~DR_PARAM_RULE_FALLBACK;
					}
				}
				val.n = grp_id ;
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
			   to perform changes - we want to avoid re-creating the AVP -bogdan */
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


static int route2_carrier(struct sip_msg* msg, char* part_carrier,
		char* gw_att_pv, char* carr_att_pv)
{
	unsigned short carrier_idx[DR_MAX_GWLIST];
	struct sip_uri  uri;
	pgw_list_t *cdst;
	pcr_t *cr;
	pv_value_t pv_val;
	str ruri, id;
	str next_carrier_attrs = {NULL, 0};
	str next_gw_attrs = {NULL, 0};
	int j,n;
	dr_part_old_t * part_cr;
	struct head_db * current_partition = 0;
	char *ruri_buf=NULL;

	part_cr = (dr_part_old_t*)part_carrier;
	if(use_partitions) {
		if(part_cr == NULL) {
			LM_ERR("Partition is mandatory for route2_carrier.\n");
			return -1;
		}
		if(part_cr->dr_part->type == DR_PTR_PART) {
			current_partition = part_cr->dr_part->v.part;
		} else if(part_cr->dr_part->type == DR_GPARAM_PART) {
			if(to_partition(msg, part_cr->dr_part, &current_partition) < 0)
				return -1;
		}
	} else {
		current_partition = head_db_start;
	}


	if ( (*current_partition->rdata)==0 || (*current_partition->rdata)->pgw_tree==0 ) {
		LM_DBG("empty routing table\n");
		return -1;
	}

	/* get the carrier ID */
	if (fixup_get_svalue(msg, (gparam_p)part_cr->gw_or_cr, &id) != 0) {
		LM_ERR("failed to get string value for carrier ID\n");
		return -1;
	}

	gw_attrs_spec = (pv_spec_p) gw_att_pv;
	carrier_attrs_spec = (pv_spec_p) carr_att_pv;

	/* do some cleanup first */
	destroy_avps( 0, current_partition->ruri_avp, 1);
	destroy_avps( 0, current_partition->gw_id_avp, 1);
	destroy_avps( 0, current_partition->gw_sock_avp, 1);
	destroy_avps( 0, current_partition->gw_attrs_avp, 1);
	destroy_avps( 0, current_partition->rule_attrs_avp, 1);
	destroy_avps( 0, current_partition->carrier_attrs_avp, 1);

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
	lock_start_read( current_partition->ref_lock );

	cr = get_carrier_by_id( (*current_partition->rdata)->carriers_tree, &id );
	if (cr==NULL) {
		LM_ERR("carrier <%.*s> was not found\n", id.len, id.s );
		goto error;
	}

	/* is carrier turned off ? */
	if( cr->flags & DR_CR_FLAG_IS_OFF ) {
		LM_NOTICE("routing to disabled carrier <%.*s> failed\n",
				cr->id.len, cr->id.s);
		goto error;
	}

	/* any GWs for the carrier? */
	if (cr->pgwl==NULL)
		goto no_gws;

	/* sort the gws of the carrier */
	j = sort_rt_dst( cr->pgwl, cr->pgwa_len, cr->flags&DR_CR_FLAG_WEIGHT,
			carrier_idx);
	if (j!=0) {
		LM_ERR("failed to sort gws for carrier <%.*s>, skipping\n",
				cr->id.len, cr->id.s);
		goto error;
	}

	/* iterate through the list of GWs provided by carrier */
	for ( j=0,n=0 ; j<cr->pgwa_len ; j++ ) {

		cdst = &cr->pgwl[carrier_idx[j]];

		/* is gateway disabled ? */
		if (cdst->dst.gw->flags & DR_DST_STAT_DSBL_FLAG ) {
			/*ignore it*/
		} else {
			/* add gateway to usage list */
			if ( push_gw_for_usage(msg, current_partition, &uri, cdst->dst.gw,
						&cr->id, &cr->attrs, n ) ) {
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

	if( n < 1) {
		LM_ERR("All the gateways are disabled\n");
		goto error;
	}

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

no_gws:

	/* we are done reading -> unref the data */
	lock_stop_read( current_partition->ref_lock );
	if (ruri_buf) pkg_free(ruri_buf);

	return 1;
error:
	/* we are done reading -> unref the data */
	lock_stop_read( current_partition->ref_lock );
error_free:
	if (ruri_buf) pkg_free(ruri_buf);
	return -1;
}


static int route2_gw(struct sip_msg* msg, char* ch_part_gw, char* gw_att_pv)
{
	struct sip_uri  uri;
	pgw_t *gw;
	pv_value_t pv_val;
	str ruri, ids, id;
	str next_gw_attrs = {NULL, 0};
	char *p;
	int idx;
	dr_part_old_t * part_gw = (dr_part_old_t*)ch_part_gw;
	struct head_db * current_partition = 0;
	char *ruri_buf = NULL;

	if( part_gw==NULL ) {
		LM_ERR("No gateway to route to\n");
		return -1;
	}

	if(use_partitions) {
		if(part_gw == NULL) {
			LM_ERR("Partition is mandatory for route2_gw.\n");
			return -1;
		}
		if(part_gw->dr_part->type == DR_PTR_PART) {
			current_partition = part_gw->dr_part->v.part;
		} else if(part_gw->dr_part->type == DR_GPARAM_PART) {
			if(to_partition(msg, part_gw->dr_part, &current_partition) < 0)
				return -1;
		}
	} else {
		if(head_db_start == NULL) {
			LM_ERR("Problem loading configuration for route_to_gw\n");
			return -1;
		}
		current_partition = head_db_start;
	}


	if ( (*current_partition->rdata)==0 || (*current_partition->rdata)->pgw_tree==0 ) {
		LM_DBG("empty routing table\n");
		return -1;
	}

	gw_attrs_spec = (pv_spec_p)gw_att_pv;

	/* get the gw ID */
	if (fixup_get_svalue(msg, (gparam_p)part_gw->gw_or_cr, &ids) != 0) {
		LM_ERR("Invalid pseudo variable!\n");
		return -1;
	}
	str_trim_spaces_lr(ids);
	if (ids.s[0] == ',' || ids.s[ids.len-1] == ',') {
		LM_ERR("Empty slot\n");
		return -1;
	}

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
		id.s = ids.s;
		p = q_memchr( ids.s , ',' , ids.len);
		id.len = (p==NULL)?ids.len:(p-ids.s);

		ids.len -= id.len + (p?1:0);
		ids.s += id.len + (p?1:0);

		str_trim_spaces_lr(id);
		if (id.len<=0) {
			LM_ERR("empty slot\n");
			lock_stop_read( current_partition->ref_lock );
			return -1;
		} else {
			LM_DBG("found and looking for gw id <%.*s>,len=%d\n",id.len, id.s, id.len);
			gw = get_gw_by_id( (*current_partition->rdata)->pgw_tree, &id );
			if (gw==NULL) {
				LM_ERR("no GW found with ID <%.*s> -> ignorring\n", id.len, id.s);
			} else if ( push_gw_for_usage(msg, current_partition, &uri, gw, NULL, NULL, idx ) ) {
				LM_ERR("failed to use gw <%.*s>, skipping\n",
						gw->id.len, gw->id.s);
			} else {
				idx++;

				/* only export the top-most gw attributes in the script */
				if (idx == 1)
					next_gw_attrs = gw->attrs;
			}
		}
	} while(ids.len>0);

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

int fxup_split_param(void ** fst_param, void ** scnd_param) {
	char * ch_it ;
	*scnd_param = 0;

	if(*fst_param == NULL || ((char*)*fst_param)[0] == 0) { /* NULL string */
		return -1;
	}

	for(ch_it=*fst_param; (*ch_it)!=0 && (*ch_it)!=':'; ch_it++);

	if(*ch_it == 0) {
		LM_CRIT("No partition specified. Missing ':'.\n");
		return -1; /* partition name was not specified */
	}
	/* partition name exits */
	*ch_it = 0;
	*scnd_param = ch_it+1; /* the second parameter */

	return 0;
}

int fxup_get_partition(void ** part_name, dr_partition_t ** x) {
	str str_part_name;
	struct head_db* part;

	trim_char((char**)part_name);
	*x = (dr_partition_t*)pkg_malloc( sizeof(dr_partition_t) );
	if(*x == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(*x, 0, sizeof(dr_partition_t));

	if(part_name == 0 || *part_name == 0 || **(char**)part_name == 0) {
		(*x)->type = DR_NO_PART; /* NO partition specified */
		LM_ERR("No partition\n");
		return 0;
	}


	if( fixup_sgp((void**)part_name)!=0 ) {
		LM_CRIT("Failed to get partition name\n");
		return -1;
	}

	if( ((gparam_p)(*part_name))->type==GPARAM_TYPE_STR ) { /* was
															   defined statically */
		str_part_name = (( (gparam_p) (*part_name))->v.sval);
		str_trim_spaces_lr(str_part_name);
		if (str_part_name.len == 1 && str_part_name.s[0] == '*') {
			(*x)->type = DR_WILDCARD_PART;
			return 0;
		}

		if((part = get_partition(&str_part_name)) == NULL) {
			LM_CRIT("Partition <%.*s> was not found.\n", str_part_name.len,
					str_part_name.s);
			return -1; /* partition was not found */
		}
		(*x)->v.part = part;
		(*x)->type = DR_PTR_PART;
	} else { /* defined via avp/pv => will be evaluated at runtime*/
		(*x)->v.part_name = *part_name;
		(*x)->type = DR_GPARAM_PART;
	}
	return 0;
}

/* gets partition name from avp, and searches for that partition */
static int to_partition(struct sip_msg* msg, dr_partition_t *part,
		struct head_db ** current_partition) {
	str part_name;
	if(fixup_get_svalue(msg, part->v.part_name,
				&part_name) < 0) {
		LM_ERR("Failed to parse avp/pve.\n");
		return -1;
	}

	str_trim_spaces_lr(part_name);

	/* check for wildcard operator */
	if ( part_name.len == 1 && part_name.s[0] == '*') {
		return 1;
	}

	if((*current_partition = get_partition(&part_name)) == NULL) {
		LM_ERR("Partition <%.*s> was not found.\n", part_name.len, part_name.s);
		return -1;
	}
	return 0;
}
/* Returns a gparam_p to the containing partition if
 * specified. If partition isn't specified return NULL
 */
gparam_t * fixup_get_partition(void** param) {
	gparam_t *part_name = 0;
	char *ch_it,*s = (char*)*param, *separator;

	if( s==NULL || s[0]==0 ) {
		return NULL;
	}
	if( use_partitions==0 ) /* partition will be omitted */
		return NULL;
	for( ch_it=s; (*ch_it)!=0 && (*ch_it)!=':'; ch_it++);
	separator = ch_it;

	if( (*separator)==':' ) { /* partition was specified */
		part_name = pkg_malloc(sizeof(gparam_t));
		if( part_name==0 ) {
			LM_ERR("No more pkg memory for part_name\n");
		}
		memset( part_name, 0, sizeof(gparam_t));

		while( (*s)==' ' ) s++; /* trim space left-of partition name */
		(*ch_it) = 0;
		ch_it--;
		while( (*ch_it)==' ' && ch_it!=s) {
			(*ch_it) = 0;
			ch_it--;
		}

		if( fixup_sgp( (void**)&s )<0 ) /* get partition name */
			return NULL;

		part_name = (gparam_p)s;
		*param = separator+1; /* go to group */
	}
	return part_name;

}

static int fixup_dr_disable(void ** param, int param_no) {
	if(use_partitions) {
		switch(param_no) {
			case 1:
				trim_char((char**)param);
				return fixup_sgp(param);
		}
	}
	LM_ERR("Too many parameters. (if you don't use partitions)\n");
	return -1;
}

static int fixup_do_routing(void** param, int param_no)
{
	char *s;
	dr_group_t * drg = 0;
	dr_part_group_t * part_param;
	pv_spec_t avp_spec;
	unsigned short dummy;
	char * scnd_param;
	str r;

	s = (char*)*param;

	switch (param_no) {
		/* [partition name':']group ID */
		case 1:
			part_param = pkg_malloc(sizeof(dr_part_group_t));
			if(part_param == NULL) {
				LM_ERR("No more pkg memory.\n");
				return -1;
			}
			memset(part_param, 0, sizeof(dr_part_group_t));
			if(use_partitions == 1) {
				if(fxup_split_param(param, (void **)&scnd_param) < 0) {
					return -1;
				}
				if(fxup_get_partition(param, &(part_param->dr_part)) < 0) {
					return -1;
				}

				if(part_param->dr_part->type == DR_NO_PART) {
					LM_ERR("Partition name is mandatory do_routing");
				}
			} else {
				scnd_param = s;
			}
			s = scnd_param;
			trim_char(&s);
			if ( s==NULL || s[0]==0 ) {
				*param = (void*)part_param;
				return 0;
			}

			drg = pkg_malloc(sizeof(dr_group_t));
			if(drg == NULL) {
				LM_ERR("No more pkg memory.\n");
				return -1;
			}
			memset(drg, 0, sizeof(dr_group_t));

			if (s[0]=='$') {
				/* param is a PV (AVP only supported) */
				r.s = s;
				r.len = strlen(s);
				if (pv_parse_spec( &r, &avp_spec)==0
						|| avp_spec.type!=PVT_AVP) {
					LM_ERR("malformed or non AVP %s AVP definition\n", s);
					return E_CFG;
				}

				if( pv_get_avp_name(0, &(avp_spec.pvp),
							&drg->u.avp_name, &dummy )!=0) {
					LM_ERR("[%s]- invalid AVP definition\n", s);
					return E_CFG;
				}
				drg->type = 1;
				/* do not free the param as the AVP spec may point inside
				   this string*/
			} else {
				while(s && *s) {
					if(*s<'0' || *s>'9') {
						LM_ERR( "bad number\n");
						return E_UNSPEC;
					}
					drg->u.grp_id = (drg->u.grp_id)*10+(*s-'0');
					s++;
				}
			}
			part_param->group = drg;
			*param = (void*)part_param;
			return 0;

			/* string with flags */
		case 2:
			return fixup_sgp(param);

			/* white list of GWs/Carriers */
		case 3:
			return fixup_spve(param);

			/* rule | gateway | carrier attributes output pvars */
		case 4:
			populate_rule_attrs = 1;
			return fixup_pvar(param);
		case 5:
			populate_gw_attrs = 1;
			return fixup_pvar(param);
		case 6:
			populate_carrier_attrs = 1;
			return fixup_pvar(param);
	}
	return -1;
}

static int fixup_next_gw( void** param, int param_no)
{
	dr_partition_t * part;
	if( !use_partitions ) { /* partition not needed */
		switch (param_no) {
			/* rule attrs pvar */
			case 1: /* first param can be partition name */
				populate_rule_attrs = 1;
				return fixup_pvar(param);
				/* gateway attrs pvar */
			case 2:
				populate_gw_attrs = 1;
				return fixup_pvar(param);
				/* carrier attrs pvar */
			case 3:
				populate_carrier_attrs = 1;
				return fixup_pvar(param);
			case 4:
				LM_ERR("Too many arguments for use_next_gw()\n");
				return -1;

		}
	} else { /* parition is mandatory => the first param */
		switch (param_no) {
			case 1:
				part = pkg_malloc(sizeof(dr_partition_t));
				if(part == NULL) {
					LM_CRIT("No more pkg memory!\n");
					return -1;
				}
				memset(part, 0, sizeof(dr_partition_t));
				if(fxup_get_partition(param, &part) < 0)
					return -1;
				if(part->type == DR_NO_PART) {
					LM_ERR("Partition name is mandatory for use_next_gw.\n");
					return -1;
				}
				*param = part;
				return 0;
			case 2: /* first param can be partition name */
				populate_rule_attrs = 1;
				return fixup_pvar(param);
				/* gateway attrs pvar */
			case 3:
				populate_gw_attrs = 1;
				return fixup_pvar(param);
				/* carrier attrs pvar */
			case 4:
				populate_carrier_attrs = 1;
				return fixup_pvar(param);
		}
	}

	return -1;
}


static int fixup_from_gw( void** param, int param_no)
{
	dr_partition_t * part;
	if(use_partitions == 0) {
		switch (param_no) {
			/* GW type*/
			case 1:
				return fixup_sint(param);
				/* GW ops */
			case 2:

				return fixup_spve(param);
				/* ATTRS pseudo-var */
			case 3:
				return fixup_pvar(param);
			case 4:
				LM_ERR("Too many parameters. (if you don't use partitions)\n");
				return -1;
		}
	} else {
		switch (param_no) {
			/* GW type*/
			case 1:
				part = pkg_malloc(sizeof(dr_partition_t));
				if(part == NULL) {
					LM_ERR("No more pkg memory.\n");
					return -1;
				}
				memset(part, 0, sizeof(dr_partition_t));

				if(fxup_get_partition(param, &part) < 0)
					return -1;
				*param = part;

				return 0;
			case 2:
				return fixup_sint(param);

				/* GW ops */
			case 3:
				return fixup_spve(param);

				/* ATTRS pseudo-var */
			case 4:
				return fixup_pvar(param);
		}
	}

	return -1;
}


static int fixup_is_gw( void** param, int param_no)
{
	dr_partition_t * part;
	if(use_partitions == 0) {
		switch (param_no) {
			/* SIP URI pseudo-var */
			case 1:
				return fixup_pvar(param);

				/* GW type*/
			case 2:
				return fixup_sint(param);

				/* GW ops */
			case 3:
				return fixup_spve(param);

				/* ATTRS pseudo-var */
			case 4:
				return fixup_pvar(param);
			case 5:
				LM_ERR("Too many parameters. (if you don't use partitions)\n");
				return -1;
		}
	} else {
		switch (param_no) {
			case 1:
				part = pkg_malloc(sizeof(dr_partition_t));
				if(part == NULL) {
					LM_CRIT("No more pkg memory!");
					return -1;
				}
				memset(part, 0, sizeof(dr_partition_t));

				if(fxup_get_partition(param, &part) < 0)
					return -1;
				*param = part;
				return 0;
				/* SIP URI pseudo-var */
			case 2:
				return fixup_pvar(param);

				/* GW type*/
			case 3:
				return fixup_sint(param);

				/* GW ops */
			case 4:
				return fixup_spve(param);

				/* ATTRS pseudo-var */
			case 5:
				return fixup_pvar(param);
		}

	}
	return -1;
}

static void trim_char(char ** param) {
	char *trailing_sp;
	if(*param!=NULL) {
		while(**param==' ') (*param)++;
		trailing_sp = *param;
		while(*trailing_sp!=0) trailing_sp++;
		trailing_sp--;
		while(*trailing_sp==' ') *trailing_sp = 0, trailing_sp--;
	}
}

static int fixup_route2_carrier( void** param, int param_no)
{
	dr_part_old_t *part_param;
	char * scnd_param;


	int rc;
	switch (param_no) {

		/* carrier name string - it has partition */
		case 1:
			part_param = pkg_malloc(sizeof(dr_part_old_t));
			if(part_param == NULL) {
				LM_ERR("No more pkg memory!");
				return -1;
			}
			memset(part_param, 0, sizeof(dr_part_old_t));
			if(use_partitions == 1) {
				if(fxup_split_param(param, (void**)&scnd_param) < 0) {
					return -1;
				}
				if(fxup_get_partition(param, &(part_param->dr_part)) < 0) {
					return -1;
				}
				if(part_param->dr_part->type == DR_NO_PART) {
					LM_ERR("Partition name is mandatory for route2_carrier\n");
					return -1;
				}
			} else {
				scnd_param = *param; /* only carrier present */
			}
			if(scnd_param == NULL) {
				LM_CRIT("carrier_id mandatory for function route_to_carrier.\n");
				return -1;
			}
			trim_char(&scnd_param);
			if(*scnd_param == 0) { /* carrier_id was formed only from spaces */
				LM_CRIT("carrier_id mandatory for function route_to_carrier.\n");
				return -1;
			}
			rc = fixup_sgp((void**)&scnd_param);
			part_param->gw_or_cr = (gparam_p)scnd_param;
			*param = (void*)part_param;

			return rc;

			/* gateway attrs pvar */
		case 2:
			populate_gw_attrs = 1;
			return fixup_pvar(param);

			/* carrier attrs pvar */
		case 3:
			populate_carrier_attrs = 1;
			return fixup_pvar(param);
	}

	return -1;
}


static int fixup_route2_gw( void** param, int param_no)
{
	int rc;
	char *gw = 0;
	dr_part_old_t * part_param; /* partition and gateway */
	switch (param_no) {
		/* gateway / gateways (csv) */
		case 1:
			part_param = pkg_malloc(sizeof(dr_part_old_t));
			if(part_param == NULL) {
				LM_ERR("No more pkg memory!");
				return -1;
			}
			memset(part_param, 0, sizeof(dr_part_old_t));
			if(use_partitions == 1) {
				if(fxup_split_param(param, (void**)&gw) < 0) {
					return -1;
				}
				if(fxup_get_partition(param, &(part_param->dr_part))<0) {
					return -1;
				}
				if(part_param->dr_part->type == DR_NO_PART) {
					LM_ERR("Partition name is mandatory for route2_gw\n");
				}
			} else {
				gw = *param;
			}

			if(gw == NULL) {
				LM_CRIT("gateway mandatory for function route_to_gw.\n");
				return -1;
			}

			trim_char((char**)&gw);

			if(*gw == 0) {
				LM_CRIT("gateway mandatory for function route_to_gw.\n");
				return -1;
			}

			rc = fixup_sgp((void**)&gw);
			part_param->gw_or_cr = (gparam_p)gw;
			*param = (void*)part_param;

			return rc;

			/* gateway attrs pvar */
		case 2:
			populate_gw_attrs = 1;
			return fixup_pvar(param);
	}

	return -1;
}

static int strip_username(struct sip_msg* msg, int strip)
{
	struct action act;

	act.type = STRIP_T;
	act.elem[0].type = NUMBER_ST;
	act.elem[0].u.number = strip;
	act.next = 0;

	if (do_action(&act, msg) < 0) {
		LM_ERR( "Error in do_action\n");
		return -1;
	}
	return 0;
}


static int prefix_username(struct sip_msg* msg, str *pri)
{
	struct action act;

	act.type = PREFIX_T;
	act.elem[0].type = STR_ST;
	act.elem[0].u.s = *pri;
	act.next = 0;

	if (do_action(&act, msg) < 0) {
		LM_ERR( "Error in do_action\n");
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


#define DR_IFG_STRIP_FLAG      (1<<0)
#define DR_IFG_PREFIX_FLAG     (1<<1)
#define DR_IFG_IDS_FLAG        (1<<3)
#define DR_IFG_IGNOREPORT_FLAG (1<<4)
#define DR_IFG_CARRIERID_FLAG  (1<<5)


static int _is_dr_gw(struct sip_msg* msg, char * part,
		char * flags_pv, int type, struct ip_addr *ip,
		unsigned int port) {

	int ret=-1;
	pv_value_t pv_val;

	struct head_db * it;
	if(use_partitions) {
		if(part == NULL || ((dr_partition_t*)part)->type == DR_NO_PART) {
			LM_ERR("Partition is mandatory!\n");
			return -1;
		}

		if(((dr_partition_t*)part)->type == DR_PTR_PART) {
			return _is_dr_gw_w_part(msg, (char*)((dr_partition_t*)part)->v.part,
					flags_pv, type, ip, port);
		} else if(((dr_partition_t*)part)->type == DR_GPARAM_PART) {
			if((ret=to_partition(msg, (dr_partition_t*)part, &it) < 0)) {
				return -1;
			} else if (ret == 0) {
				return _is_dr_gw_w_part(msg, (char*)it,flags_pv, type, ip, port);
			}
		}

		/* if we got here we have the wildcard operator */
		for (it = head_db_start; it; it = it->next) {
			ret = _is_dr_gw_w_part(msg, (char *)it, flags_pv, type, ip, port);
			if (ret > 0) {
				if (partition_pvar.s) {
					pv_val.rs = it->partition;
					pv_val.flags = PV_VAL_STR;
					if (pv_set_value(msg, &partition_spec, 0, &pv_val) != 0) {
						LM_ERR("cannot print the PV-formatted"
								" partition string\n");
						return -1;
					}
				}
				return ret;
			}
		}

		return ret;


	} else {
		if( head_db_start == NULL ) {
			LM_ERR("Error loading config.");
			return -1;
		}
		return _is_dr_gw_w_part(msg, (char*)head_db_start, flags_pv, (int)type,
				(struct ip_addr *)ip, (unsigned int)port);
	}
	return -1;
}


/*
 * Checks if a given IP + PORT is a GW; tests the TYPE too
 * INTERNAL FUNCTION
 */
static int _is_dr_gw_w_part(struct sip_msg* msg, char * part, char* flags_pv,
		int type, struct ip_addr *ip, unsigned int port)
{
	pgw_t *pgwa = NULL;
	pcr_t *pcr = NULL;
	pv_value_t pv_val;
	int flags = 0;
	str flags_s;
	int_str val;
	int i;
	struct head_db *current_partition = (struct head_db *)part;

	void** dest;
	map_iterator_t gw_it, cr_it;

	if(current_partition == NULL || current_partition->rdata==NULL
			|| *current_partition->rdata==NULL || msg==NULL)
		return -1;


	if (flags_pv && flags_pv[0]) {
		if (fixup_get_svalue( msg, (gparam_p)flags_pv, &flags_s)!=0) {
			LM_ERR("invalid flags parameter");
			return -1;
		}
		for( i=0 ; i < flags_s.len ; i++ ) {
			switch (flags_s.s[i]) {
				case 's': flags |= DR_IFG_STRIP_FLAG; break;
				case 'p': flags |= DR_IFG_PREFIX_FLAG; break;
				case 'i': flags |= DR_IFG_IDS_FLAG; break;
				case 'n': flags |= DR_IFG_IGNOREPORT_FLAG; break;
				case 'c': flags |= DR_IFG_CARRIERID_FLAG; break;
				default: LM_WARN("unsupported flag %c \n",flags_s.s[i]);
			}
		}
	}

	if(current_partition->rdata!=NULL && *current_partition->rdata!=NULL) {
		for (map_first((*current_partition->rdata)->pgw_tree, &gw_it);
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
				/* prefix ? */
				if ( (flags&DR_IFG_PREFIX_FLAG) && pgwa->pri.len>0) {
					/* pri prefix ? */
					if (current_partition->gw_priprefix_avp!=-1) {
						val.s = pgwa->pri.s ? pgwa->pri : attrs_empty ;
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
					for (map_first((*current_partition->rdata)->carriers_tree, &cr_it);
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
				return 1;
			}
			pgwa = pgwa->next;
		}
	}


	return -1;
}


static int is_from_gw_0(struct sip_msg* msg) {
	return _is_dr_gw(msg, NULL, NULL, -1, &msg->rcv.src_ip, msg->rcv.src_port);
}
/*
 * Checks if a given src IP and PORT is a GW; no TYPE, no FLAGS
 */
static int is_from_gw_1(struct sip_msg* msg, char * part)
{
	if(use_partitions) {
		return _is_dr_gw( msg, part, NULL, -1, &msg->rcv.src_ip , msg->rcv.src_port);
	} else {
		return _is_dr_gw(msg, NULL, NULL, (!part? -1:(int)(long)part), &msg->rcv.src_ip,
				msg->rcv.src_port);
	}
}


/*
 * Checks if a given src IP and PORT is a GW; tests the TYPE too, no FLAGS
 */
static int is_from_gw_2(struct sip_msg* msg, char * part, char* type_s)
{
	if(use_partitions) {
		return _is_dr_gw(msg, part, NULL, (!type_s ? -1 : (int)(long)type_s),
				&msg->rcv.src_ip , msg->rcv.src_port);
	} else {
		return _is_dr_gw(msg, NULL, type_s, (!part ? -1: (int)(long)part),
				&msg->rcv.src_ip, msg->rcv.src_port);
	}
}


static int is_from_gw_3(struct sip_msg* msg, char * part,char* type_s,
		char* flags_pv) {
	if(use_partitions) {
		return _is_dr_gw(msg, part, flags_pv, (!type_s ? -1:(int)(long)type_s),
				&msg->rcv.src_ip, msg->rcv.src_port);
	} else {
		gw_attrs_spec = (pv_spec_p)flags_pv;
		return _is_dr_gw(msg, NULL, type_s, (!part ? -1:(int)(long)part),
				&msg->rcv.src_ip, msg->rcv.src_port);
	}
}

/*
 * Checks if a given src IP and PORT is a GW; tests the TYPE too
 */
static int is_from_gw_4(struct sip_msg* msg, char * part,char* type_s, char* flags_pv,
		char* gw_att)
{
	gw_attrs_spec = (pv_spec_p)gw_att;

	if(use_partitions) {
		return _is_dr_gw( msg, part, flags_pv,
				(!type_s ? -1 : (int)(long)type_s), &msg->rcv.src_ip ,
				msg->rcv.src_port);
	} else {
		LM_ERR("Too many parameters\n");
		return -1;
	}
}


/*
 * Checks if a given SIP URI is a GW; tests the TYPE too
 * INTERNAL FUNCTION
 */
static int _is_dr_uri_gw(struct sip_msg* msg, char *part, char* flags_pv, int type, str *uri)
{
	struct sip_uri puri;
	struct hostent* he;
	struct ip_addr ip;

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
	memset(&ip,0,sizeof(struct ip_addr));
	hostent2ip_addr( &ip, he, 0);

	return _is_dr_gw( msg, part, flags_pv, type, &ip , puri.port_no);
}


/*
 * Checks if RURI is a GW ; tests the TYPE too
 */
static int goes_to_gw_1(struct sip_msg* msg, char * part, char* _type, char* flags_pv,
		char* gw_att)
{

	if(use_partitions) {
		gw_attrs_spec = (pv_spec_p)gw_att;
		return _is_dr_uri_gw(msg, part, flags_pv, (!_type ? -1 : (int)(long)_type),
				GET_NEXT_HOP(msg));
	} else {
		gw_attrs_spec = (pv_spec_p)flags_pv;
		return _is_dr_uri_gw(msg, NULL, flags_pv, (!_type ? -1 : (int)(long)_type),
				GET_NEXT_HOP(msg));
	}
}


/*
 * Checks if RURI is a GW; not TYPE check
 */
static int goes_to_gw_0(struct sip_msg* msg)
{
	return goes_to_gw_1(msg, NULL, (char *)-1, NULL, NULL);
}


/*
 * Checks if a variable (containing a SIP URI) is a GW; tests the TYPE too
 */
static int dr_is_gw(struct sip_msg* msg, char * part, char* src_pv, char* type_s,
		char* flags_pv, char* gw_att)
{
	pv_value_t src;

	if(use_partitions) {
		gw_attrs_spec = (pv_spec_p)gw_att;
		if ( pv_get_spec_value(msg, (pv_spec_p)src_pv, &src)!=0 ||
				(src.flags&PV_VAL_STR)==0 || src.rs.len<=0) {
			LM_ERR("failed to get string value for src\n");
			return -1;
		}
		return _is_dr_uri_gw(msg, part, flags_pv, !type_s ? -1:(int)(long)type_s, &src.rs);
	}
	else {
		if ( pv_get_spec_value(msg, (pv_spec_p)part, &src)!=0 ||
				(src.flags&PV_VAL_STR)==0 || src.rs.len<=0) {
			LM_ERR("failed to get string value for src\n");
			return -1;
		}
		gw_attrs_spec = (pv_spec_p)flags_pv;
		return _is_dr_uri_gw(msg, NULL, flags_pv ,!type_s ? -1:(int)(long)type_s
				,&src.rs);
	}
}

static struct mi_root* mi_w_partition(struct mi_node **node, struct head_db **
		current_partition) {
	struct mi_root *rpl_tree;

	if( use_partitions ) {
		if( node!=NULL && (*node)!=NULL ) {
			if( (*current_partition = get_partition(&((*node)->value))) == NULL) {
				LM_ERR("Partition not found\n");
				rpl_tree = init_mi_tree( 404, MI_SSTR("Partition not found\n"));
				return rpl_tree;
			}
			*node = (*node)->next; /* advance to next param */
			return NULL; /* everything is ok */
		} else {
			LM_ERR("Partition name mandatory\n");
			rpl_tree = init_mi_tree(400, MI_SSTR("Partition mandatory\n"));
			return rpl_tree;
		}
	} else {
		*current_partition = head_db_start;
		return NULL; /* everything is ok */
	}
	rpl_tree = init_mi_tree( 400,
			MI_SSTR("Unexpected outcome while parsing param for opensisctl\n"));
	return rpl_tree;
}


static struct mi_root* mi_dr_gw_status(struct mi_root *cmd, void *param)
{

	struct mi_root *rpl_tree;
	struct mi_node *node;
	struct mi_attr *attr;
	unsigned int stat;
	struct head_db * current_partition=0;
	pgw_t *gw;
	str *id;
	int old_flags;

	void** dest;
	map_iterator_t it;

	node = cmd->node.kids;


	if( (rpl_tree = mi_w_partition(&node, &current_partition))!=NULL )
		return rpl_tree; /* something went wrong: bad command format */

	lock_start_read( current_partition->ref_lock );

	if (current_partition->rdata==NULL || *current_partition->rdata==NULL) {
		rpl_tree = init_mi_tree( 404, MI_SSTR("No Data available yet"));
		goto done;
	}

	if (node==NULL) {
		/* no GW specified, list all of them */
		rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
		if (rpl_tree==NULL)
			goto error;
		rpl_tree->node.flags |= MI_IS_ARRAY;

		for (map_first((*current_partition->rdata)->pgw_tree, &it);
				iterator_is_valid(&it); iterator_next(&it)) {

			dest = iterator_val(&it);
			if (dest==NULL)
				return NULL;

			gw = (pgw_t*)*dest;

			node = add_mi_node_child( &rpl_tree->node, MI_DUP_VALUE,
					"ID", 2, gw->id.s, gw->id.len);
			if (node==NULL) goto error;
			attr = add_mi_attr( node, MI_DUP_VALUE, "IP" , 2,
					gw->ip_str.s, gw->ip_str.len);
			if (attr==NULL) goto error;
			if (gw->flags&DR_DST_STAT_DSBL_FLAG) {
				if (gw->flags&DR_DST_STAT_NOEN_FLAG)
					attr = add_mi_attr( node, 0, "State", 5,
							"Disabled MI", 11);
				else if (gw->flags&DR_DST_PING_DSBL_FLAG)
					attr = add_mi_attr( node, 0, "State", 5,
							"Probing", 7);
				else
					attr = add_mi_attr( node, 0, "State", 5,
							"Inactive", 8);
			} else {
				attr = add_mi_attr( node, 0, "State", 5,
						"Active", 6);
			}
			if (attr==NULL) goto error;
		}

		goto done;
	}

	/* GW ID (param 1) */
	id =  &node->value;

	/* search for the Gw */
	gw = get_gw_by_id( (*current_partition->rdata)->pgw_tree, id);
	if (gw==NULL) {
		rpl_tree = init_mi_tree( 404, MI_SSTR("GW ID not found"));
		goto done;
	}

	/* status (param 2) */
	node = node->next;
	if (node == NULL) {

		/* no status provided -> return the internal one */
		rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
		if (rpl_tree==NULL)
			goto error;
		if (gw->flags&DR_DST_STAT_DSBL_FLAG) {
			if (gw->flags&DR_DST_STAT_NOEN_FLAG)
				node = add_mi_node_child( &rpl_tree->node, 0, "State", 5,
						"Disabled MI", 11);
			else if (gw->flags&DR_DST_PING_DSBL_FLAG)
				node = add_mi_node_child( &rpl_tree->node, 0, "State", 5,
						"Probing", 7);
			else
				node = add_mi_node_child( &rpl_tree->node, 0, "State", 5,
						"Inactive", 8);
		} else {
			node = add_mi_node_child( &rpl_tree->node, 0, "State", 5,
					"Active", 6);
		}
		if (node==NULL)
			goto error;

		goto done;

	}

	/* set the status */
	if (node->next) {
		rpl_tree = init_mi_tree( 400,
				MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);
		goto done;
	}
	if (str2int( &node->value, &stat) < 0) {
		rpl_tree = init_mi_tree( 400, MI_SSTR(MI_BAD_PARM_S));
		goto done;
	}
	/* set the disable/enable */
	old_flags = gw->flags;
	if (stat) {
		gw->flags &= ~ (DR_DST_STAT_DSBL_FLAG|DR_DST_STAT_NOEN_FLAG);
	} else {
		gw->flags |= DR_DST_STAT_DSBL_FLAG|DR_DST_STAT_NOEN_FLAG;
	}
	if (old_flags!=gw->flags) {
		gw->flags |= DR_DST_STAT_DIRT_FLAG;
		dr_raise_event(gw);
	}
	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);

done:
	lock_stop_read( current_partition->ref_lock );
	return rpl_tree;
error:
	lock_stop_read( current_partition->ref_lock );
	if(rpl_tree) free_mi_tree(rpl_tree);
	return NULL;
}


static struct mi_root* mi_dr_cr_status(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *node;
	struct mi_attr *attr;
	unsigned int stat;
	struct head_db * current_partition = 0;
	pcr_t *cr;
	str *id;
	int old_flags;

	void** dest;
	map_iterator_t it;

	node = cmd->node.kids;

	if( (rpl_tree = mi_w_partition(&node, &current_partition))
			!=NULL ) {
		return rpl_tree;
	}

	lock_start_read( current_partition->ref_lock );

	if (current_partition->rdata==NULL || *current_partition->rdata==NULL) {
		rpl_tree = init_mi_tree( 404, MI_SSTR("No Data available yet"));
		goto done;
	}

	if (node==NULL) {
		/* no carrier specified, list all of them */
		rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
		if (rpl_tree==NULL)
			goto error;
		rpl_tree->node.flags |= MI_IS_ARRAY;

		for (map_first((*current_partition->rdata)->carriers_tree, &it);
				iterator_is_valid(&it); iterator_next(&it)) {
			dest = iterator_val(&it);
			if (dest==NULL)
				return NULL;

			cr = (pcr_t*)*dest;

			node = add_mi_node_child( &rpl_tree->node, MI_DUP_VALUE,
					"ID", 2, cr->id.s, cr->id.len);
			if (node==NULL) goto error;
			attr = add_mi_attr( node, 0, "Enabled", 7,
					(cr->flags&DR_CR_FLAG_IS_OFF)?"no ":"yes", 3);
			if (attr==NULL) goto error;
		}

		goto done;
	}

	/* GW ID (param 1) */
	id =  &node->value;

	/* search for the Carrier */
	cr = get_carrier_by_id( (*current_partition->rdata)->carriers_tree, id);
	if (cr==NULL) {
		rpl_tree = init_mi_tree( 404, MI_SSTR("Carrier ID not found"));
		goto done;
	}

	/* status (param 2) */
	node = node->next;
	if (node == NULL) {

		/* no status provided -> return the internal one */
		rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
		if (rpl_tree==NULL)
			goto error;
		node = add_mi_node_child( &rpl_tree->node, 0, "Enabled", 7,
				(cr->flags&DR_CR_FLAG_IS_OFF)?"no ":"yes", 3);
		if (node==NULL)
			goto error;

		goto done;

	}

	/* set the status */
	if (node->next) {
		rpl_tree = init_mi_tree( 400,
				MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);
		goto done;
	}
	if (str2int( &node->value, &stat) < 0) {
		rpl_tree = init_mi_tree( 400, MI_SSTR(MI_BAD_PARM_S));
		goto done;
	}
	/* set the disable/enable */
	old_flags = cr->flags;
	if (stat) {
		cr->flags &= ~ (DR_CR_FLAG_IS_OFF);
	} else {
		cr->flags |= DR_CR_FLAG_IS_OFF;
	}
	if (old_flags!=cr->flags)
		cr->flags |= DR_CR_FLAG_DIRTY;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);

done:
	lock_stop_read( current_partition->ref_lock );
	return rpl_tree;
error:
	lock_stop_read( current_partition->ref_lock );
	if(rpl_tree) free_mi_tree(rpl_tree);
	return NULL;
}

int add_head_db(void) {
	struct head_db *new;
	new = ( struct head_db* )shm_malloc(sizeof( struct head_db ) );
	if( new == NULL ) {
		LM_ERR(" no more shm memory(add_head_db)\n");
		return -1;
	}
	memset( new, 0, sizeof( struct head_db ) );
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
	if( head_db_start == NULL) {
		head_db_start = new;
		head_db_end = new;
	} else {
		head_db_end->next = new;
		head_db_end = new;
	}
	return 0;
}

/* use_partitions: use configurations from database */
int add_head_config(void)
{
	/* expand linked list */
	struct head_config *new;

	new = ( struct head_config* )shm_malloc( sizeof( struct head_config ) );
	if( new == NULL ) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(new, 0, sizeof( struct head_config ) );
	/* ->next will be null too */

	if( head_start == NULL) {
		head_start = new;
		head_end = new;
	} else {
		head_end->next = new;
		head_end = new;
	}
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
				if( populate_head_config( head_end, ans_col, j) < 0 )
					LM_ERR("Column from partition table not recognized; will continue");

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

static struct mi_root* mi_dr_number_routing(struct mi_root *cmd_tree, void *param)
{
	struct mi_node *node = cmd_tree->node.kids;
	struct head_db *partition;
	str s;
	int grp_id;
	unsigned int matched_len;
	struct mi_node *prefix_node;
	rt_info_t *route;

	if (node == NULL)
		return init_mi_tree(400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (use_partitions) {
		s = node->value;
		if((partition = get_partition(&s)) == NULL) {
			LM_WARN("Partition <%.*s> was not found.\n", s.len, s.s);
			return init_mi_tree(400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
		}

		node = node->next;
	}
	else partition = head_db_start;

	if (node == NULL)
		return init_mi_tree(400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (node->next == NULL) {
		grp_id = -1;
	} else {
		unsigned int ugrp_id;
		if (str2int(&node->value, &ugrp_id) != 0)
			return init_mi_tree(400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
		grp_id = ugrp_id;
		node = node->next;
	}

	lock_start_read( partition->ref_lock );
	route = find_rule_by_prefix_unsafe((*(partition->rdata))->pt,
			&(*(partition->rdata))->noprefix, node->value, grp_id, &matched_len);
	if (route == NULL){
		lock_stop_read( partition->ref_lock );
		return init_mi_tree(200, MI_OK_S, MI_OK_LEN);
	}

	struct mi_root* rpl_tree = init_mi_tree(200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree == NULL){
		lock_stop_read( partition->ref_lock );
		return 0;
	}

	unsigned int i;
	static const str gw_str = str_init("GATEWAY");
	static const str carrier_str = str_init("CARRIER");
	static const str matched_str = str_init("Matched Prefix");
	str chosen_desc;
	str chosen_id;
	if ((prefix_node = add_mi_node_child(&rpl_tree->node, 0, matched_str.s,
		matched_str.len, node->value.s, matched_len)) == NULL) {
		LM_ERR("failed to add node\n");
		lock_stop_read( partition->ref_lock );
		free_mi_tree(rpl_tree);
		return 0;
	}

	prefix_node->flags |= MI_IS_ARRAY;

	for (i = 0; i < route->pgwa_len; ++i){
		if (route->pgwl[i].is_carrier) {
			chosen_desc = carrier_str;
			chosen_id = route->pgwl[i].dst.carrier->id;
		}
		else {
			chosen_desc = gw_str;
			chosen_id = route->pgwl[i].dst.gw->id;
		}

		if (add_mi_node_child(prefix_node, 0, chosen_desc.s,
					chosen_desc.len, chosen_id.s, chosen_id.len) == NULL) {

			LM_ERR("failed to add node\n");
			lock_stop_read( partition->ref_lock );
			free_mi_tree(rpl_tree);
			return 0;
		}
	}
	lock_stop_read( partition->ref_lock );

	return rpl_tree;
}


static struct mi_root* mi_dr_reload_status(struct mi_root *cmd_tree, void *param) {
	struct mi_node *node = cmd_tree->node.kids;
	struct mi_root *rpl_tree = init_mi_tree(200, MI_OK_S, MI_OK_LEN);
	struct mi_node *ans;
	struct head_db * partition;
	str part_name;
	char * ch_time;

	if(node != NULL) {
		if (use_partitions) {
			part_name = node->value;
			if((partition = get_partition(&part_name)) == NULL) {
				LM_WARN("Partition <%.*s> was not found.\n", part_name.len,
						part_name.s);
				return init_mi_tree(400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
			}
			/* display just for given partition */
			lock_start_read(partition->ref_lock);
			ch_time = ctime(&partition->time_last_update);
			if((ans = add_mi_node_child(&rpl_tree->node, MI_DUP_VALUE,
						MI_PART_NAME_S, MI_PART_NAME_LEN, partition->partition.s,
						partition->partition.len)) == NULL) {
				LM_ERR("failed to add mi_node\n");
				goto error;
			}
			if(add_mi_attr(ans, MI_DUP_VALUE, MI_LAST_UPDATE_S, MI_LAST_UPDATE_LEN,
						ch_time, strlen(ch_time)) == NULL) {
				LM_ERR("failed to add mi_attr\n");
				goto error;
			}
			lock_stop_read(partition->ref_lock);
		} else {
			return init_mi_tree(400, MI_NO_PART_S, MI_NO_PART_LEN);
		}
	}
	else if(use_partitions){
		rpl_tree->node.flags |= MI_IS_ARRAY;

		/* display for all partitions */
		for(partition = head_db_start; partition; partition = partition->next) {
			lock_start_read(partition->ref_lock);
			ch_time = ctime(&partition->time_last_update);
			LM_DBG("partition  %.*s was last updated:%s\n",
					partition->partition.len, partition->partition.s,
					ch_time);
			if((ans = add_mi_node_child(&rpl_tree->node, 0, MI_PART_NAME_S,
						MI_PART_NAME_LEN, partition->partition.s,
						partition->partition.len))  == NULL) {
				LM_ERR("failed to add mi_node\n");
				goto error;
			}
			if(add_mi_attr(ans, MI_DUP_VALUE, MI_LAST_UPDATE_S, MI_LAST_UPDATE_LEN,
						ch_time, strlen(ch_time)) == NULL) {
				LM_ERR("failed to add attr to mi_node\n");
				goto error;
			}
			lock_stop_read(partition->ref_lock);
		}
	}
	else {
		/* just one partition */
		partition = head_db_start;

		lock_start_read(partition->ref_lock);
		ch_time = ctime(&partition->time_last_update);
		if((ans = add_mi_node_child(&rpl_tree->node, 0, MI_LAST_UPDATE_S,
						MI_LAST_UPDATE_LEN, ch_time, strlen(ch_time))) == NULL) {
			LM_ERR("failed to add mi_node\n");
			goto error;
		}
		lock_stop_read(partition->ref_lock);

	}
	return rpl_tree;
error:
	lock_stop_read(partition->ref_lock);
	free_mi_tree(rpl_tree);
	return 0;

}
