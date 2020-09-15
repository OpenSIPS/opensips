/*
 * load balancer module - complex call load balancing
 *
 * Copyright (C) 2009 Voice Sistem SRL
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include "../../sr_module.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../timer.h"
#include "../../ut.h"
#include "../../rw_locking.h"
#include "../../usr_avp.h"
#include "../dialog/dlg_load.h"
#include "../tm/tm_load.h"
#include "../freeswitch/fs_api.h"

#include "lb_parser.h"
#include "lb_db.h"
#include "lb_data.h"
#include "lb_clustering.h"
#include "lb_prober.h"
#include "lb_bl.h"


/* db stuff */
static str db_url = {NULL, 0};
static char *table_name = NULL;

/* dialog stuff */
struct dlg_binds lb_dlg_binds;

struct lb_data **curr_data = NULL;

/* probing related stuff */
static unsigned int lb_prob_interval = 30;
static unsigned int lb_prob_verbose = 0;
static str lb_probe_replies = {NULL,0};
struct tm_binds lb_tmb;
struct fs_binds fs_api;

str lb_probe_method = str_init("OPTIONS");
str lb_probe_from = str_init("sip:prober@localhost");
static int* probing_reply_codes = NULL;
static int probing_codes_no = 0;

int fetch_freeswitch_stats;
int initial_fs_load = 1000;

static int mod_init(void);
static int child_init(int rank);
static void mod_destroy(void);
static int mi_child_init();

/* failover stuff */
static str group_avp_name_s = str_init("__lb_grp");
static str flags_avp_name_s = str_init("__lb_flg");
static str mask_avp_name_s = str_init("__lb_mask");
static str id_avp_name_s = str_init("__lb_id");
static str res_avp_name_s = str_init("__lb_res");
int group_avp_name;
int flags_avp_name;
int mask_avp_name;
int id_avp_name;
int res_avp_name;

static str attrs_empty = str_init("");

mi_response_t *mi_lb_reload(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_lb_resize(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_lb_list(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_lb_status(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_lb_status_1(const mi_params_t *params,
								struct mi_handler *async_hdl);

static int fixup_resources(void** param);
static int fixup_free_resources(void** param);

static int w_lb_start(struct sip_msg *req, int *grp_no,
				struct lb_res_str_list *lb_rl, str *flstr, pv_spec_t *attrs_var);
static int w_lb_next(struct sip_msg *req, pv_spec_t *attrs_var);
static int w_lb_start_or_next(struct sip_msg *req,void *grp,void *rl,void *fl,
				pv_spec_t *attrs_var);
static int w_lb_reset(struct sip_msg *req);
static int w_lb_is_started(struct sip_msg *req);
static int w_lb_disable_dst(struct sip_msg *req);
static int w_lb_is_dst(struct sip_msg *msg,str *ip,int *port,int *group,
					int *active, pv_spec_t *attrs_var);
static int w_lb_count_call(struct sip_msg *req, str *ip_str, int *port, char *grp,
					struct lb_res_str_list *lb_rl, int *dir);


static void lb_prob_handler(unsigned int ticks, void* param);

static void lb_update_max_loads(unsigned int ticks, void *param);

static cmd_export_t cmds[]={
	{"lb_start", (cmd_function)w_lb_start, {
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_STR, fixup_resources, fixup_free_resources},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"load_balance", (cmd_function)w_lb_start_or_next, {
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_STR, fixup_resources, fixup_free_resources},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"lb_start_or_next", (cmd_function)w_lb_start_or_next, {
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_STR, fixup_resources, fixup_free_resources},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"lb_next", (cmd_function)w_lb_next, {
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"lb_reset", (cmd_function)w_lb_reset, {{0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"lb_is_started", (cmd_function)w_lb_is_started, {{0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"lb_disable_dst", (cmd_function)w_lb_disable_dst, {{0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"lb_is_destination",(cmd_function)w_lb_is_dst, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"lb_count_call",    (cmd_function)w_lb_count_call, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_STR, fixup_resources, fixup_free_resources},
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{0,0,{{0,0,0}},0}
};

static param_export_t mod_params[]={
	{ "db_url",                STR_PARAM, &db_url.s                 },
	{ "db_table",              STR_PARAM, &table_name               },
	{ "probing_interval",      INT_PARAM, &lb_prob_interval         },
	{ "probing_verbose",       INT_PARAM, &lb_prob_verbose          },
	{ "probing_method",        STR_PARAM, &lb_probe_method.s        },
	{ "probing_from",          STR_PARAM, &lb_probe_from.s          },
	{ "probing_reply_codes",   STR_PARAM, &lb_probe_replies.s       },
	{ "lb_define_blacklist",   STR_PARAM|USE_FUNC_PARAM, (void*)set_lb_bl},
	{ "cluster_id",            INT_PARAM, &lb_cluster_id            },
	{ "cluster_sharing_tag",   STR_PARAM, &lb_cluster_shtag         },
	{ "fetch_freeswitch_stats",  INT_PARAM, &fetch_freeswitch_stats },
	{ "initial_freeswitch_load", INT_PARAM, &initial_fs_load        },
	{ 0,0,0 }
};


static mi_export_t mi_cmds[] = {
	{ "lb_reload", 0, 0, mi_child_init, {
		{mi_lb_reload, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "lb_resize", 0, 0, 0, {
		{mi_lb_resize, {"destination_id", "res_name", "new_capacity", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "lb_list", 0, 0, 0, {
		{mi_lb_list, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "lb_status", 0, 0, 0, {
		{mi_lb_status, {"destination_id", 0}},
		{mi_lb_status_1, {"destination_id", "new_status", 0}},
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

static module_dependency_t *get_deps_fetch_fs_load(param_export_t *param)
{
	if (*(int *)param->param_pointer <= 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_DEFAULT, "freeswitch", DEP_ABORT);
}

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "dialog", DEP_ABORT },
		{ MOD_TYPE_SQLDB,   NULL,     DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "probing_interval", get_deps_probing_interval },
		{ "fetch_freeswitch_stats", get_deps_fetch_fs_load },
		{ "cluster_id", get_deps_clusterer},
		{ NULL, NULL },
	},
};

struct module_exports exports= {
	"load_balancer",  /* module's name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,            /* exported functions */
	0,               /* exported async functions */
	mod_params,      /* param exports */
	0,               /* exported statistics */
	mi_cmds,         /* exported MI functions */
	0,               /* exported pseudo-variables */
	0,			 	 /* exported transformations */
	0,               /* extra processes */
	0,               /* module pre-initialization function */
	mod_init,        /* module initialization function */
	0,               /* reply processing function */
	mod_destroy,
	child_init,      /* per-child init function */
	0                /* reload confirm function */
};


struct lb_grp_param {
	int grp_no;
	pv_spec_t *grp_pv;
};


static int fixup_resources(void** param)
{
	struct lb_res_str_list *lb_rl;
	str s;

	if (pkg_nt_str_dup(&s, (str*)*param) < 0)
		return E_OUT_OF_MEM;

	lb_rl = parse_resources_list(s.s, 0);
	if (lb_rl==NULL) {
		LM_ERR("invalid parameter %s\n", s.s);
		return E_CFG;
	}

	pkg_free(s.s);

	*param = lb_rl;
	return 0;
}

static int fixup_free_resources(void** param)
{
	pkg_free(*param);
	return 0;
}


static void lb_inherit_state(struct lb_data *old_data,struct lb_data *new_data)
{
	struct lb_dst *old_dst;
	struct lb_dst *new_dst;

	for ( new_dst=new_data->dsts ; new_dst ; new_dst=new_dst->next ) {
		for ( old_dst=old_data->dsts ; old_dst ; old_dst=old_dst->next ) {
			if (new_dst->id==old_dst->id &&
			new_dst->group==old_dst->group &&
			new_dst->uri.len==old_dst->uri.len &&
			strncasecmp(new_dst->uri.s, old_dst->uri.s, old_dst->uri.len)==0) {
				LM_DBG("DST %d/<%.*s> found in old set, copying state\n",
					new_dst->group, new_dst->uri.len,new_dst->uri.s);
				/* first reset the existing flags (only the flags related 
				 * to state!!!) */
				new_dst->flags &=
					~(LB_DST_STAT_DSBL_FLAG|LB_DST_STAT_NOEN_FLAG);
				/* copy the flags from the old node */
				new_dst->flags |= (old_dst->flags &
					(LB_DST_STAT_DSBL_FLAG|LB_DST_STAT_NOEN_FLAG));
				break;
			}
		}
	}
}


static inline int lb_reload_data( void )
{
	struct lb_data *new_data;
	struct lb_data *old_data;

	new_data = load_lb_data();
	if ( new_data==0 ) {
		LM_CRIT("failed to load load-balancing info\n");
		return -1;
	}

	lock_start_write( ref_lock );

	/* no more activ readers -> do the swapping */
	old_data = *curr_data;
	*curr_data = new_data;

	lock_stop_write( ref_lock );

	/* destroy old data */
	if (old_data) {
		/* copy the state of the destinations from the old set
		 * (for the matching ids) */
		lb_inherit_state( old_data, new_data);
		free_lb_data( old_data );
	}

	/* generate new blacklist from the routing info */
	populate_lb_bls((*curr_data)->dsts);

	return 0;
}



static int mod_init(void)
{
	LM_INFO("Load-Balancer module - initializing\n");

	init_db_url( db_url , 0 /*cannot be null*/);

	/* Load dialog API */
	if (load_dlg_api(&lb_dlg_binds) != 0) {
		LM_ERR("Can't load dialog hooks\n");
		return -1;
	}

	if (fetch_freeswitch_stats) {
		if (load_fs_api(&fs_api) == -1) {
			LM_ERR("failed to load the FS API!\n");
			return -1;
		}
	}

	/* data pointer in shm */
	curr_data = (struct lb_data**)shm_malloc( sizeof(struct lb_data*) );
	if (curr_data==0) {
		LM_CRIT("failed to get shm mem for data ptr\n");
		return -1;
	}
	*curr_data = 0;

	/* create & init lock */
	if ((ref_lock = lock_init_rw()) == NULL) {
		LM_CRIT("failed to init lock\n");
		return -1;
	}

	if (init_lb_bls()) {
		LM_ERR("BL INIT failed\n");
		return -1;
	}

	/* init and open DB connection */
	if (init_lb_db(&db_url, table_name)!=0) {
		LM_ERR("failed to initialize the DB support\n");
		return -1;
	}

	/* load data */
	if ( lb_reload_data()!=0 ) {
		LM_CRIT("failed to load load-balancing data\n");
		return -1;
	}

	/* close DB connection */
	lb_close_db();

	/* arm a function for probing */
	if (lb_prob_interval) {
		/* load TM API */
		if (load_tm_api(&lb_tmb)!=0) {
			LM_ERR("can't load TM API\n");
			return -1;
		}

		/* probing method */
		lb_probe_method.len = strlen(lb_probe_method.s);
		lb_probe_from.len = strlen(lb_probe_from.s);
		if (lb_probe_replies.s)
			lb_probe_replies.len = strlen(lb_probe_replies.s);

		/* register pinger function */
		if (register_timer( "lb-pinger", lb_prob_handler , NULL,
		lb_prob_interval, TIMER_FLAG_DELAY_ON_DELAY)<0) {
			LM_ERR("failed to register probing handler\n");
			return -1;
		}

		/* Register the max load recalculation timer */
		if (fetch_freeswitch_stats &&
		    register_timer("lb-update-max-load", lb_update_max_loads, NULL,
		           fs_api.stats_update_interval, TIMER_FLAG_SKIP_ON_DELAY)<0) {
			LM_ERR("failed to register timer for max load recalc!\n");
			return -1;
		}

		if (lb_probe_replies.s) {
			lb_probe_replies.len = strlen(lb_probe_replies.s);
			if(parse_reply_codes( &lb_probe_replies, &probing_reply_codes,
			&probing_codes_no )< 0) {
				LM_ERR("Bad format for options_reply_code parameter"
					" - Need a code list separated by commas\n");
				return -1;
			}
		}
	}

	/* parse avps */
	if (parse_avp_spec(&group_avp_name_s, &group_avp_name)) {
		LM_ERR("cannot parse group avp\n");
		return -1;
	}
	if (parse_avp_spec(&flags_avp_name_s, &flags_avp_name)) {
		LM_ERR("cannot parse flags avp\n");
		return -1;
	}
	if (parse_avp_spec(&mask_avp_name_s, &mask_avp_name)) {
		LM_ERR("cannot parse mask avp\n");
		return -1;
	}
	if (parse_avp_spec(&id_avp_name_s, &id_avp_name)) {
		LM_ERR("cannot parse id avp\n");
		return -1;
	}
	if (parse_avp_spec(&res_avp_name_s, &res_avp_name)) {
		LM_ERR("cannot parse resources avp\n");
		return -1;
	}

	if (lb_init_event() < 0) {
		LM_ERR("cannot init event\n");
		return -1;
	}

	if (lb_cluster_id>0 && lb_init_cluster()<0) {
		LM_ERR("failed to initialized the clustering support\n");
		return -1;
	}

	return 0;
}


static int child_init(int rank)
{
	return 0;
}


static int mi_child_init( void )
{
	/* init DB connection */
	if ( lb_connect_db(&db_url)!=0 ) {
		LM_CRIT("cannot initialize database connection\n");
		return -1;
	}
	return 0;
}


static void mod_destroy(void)
{
	/* destroy data */
	if ( curr_data) {
		if (*curr_data)
			free_lb_data( *curr_data );
		shm_free( curr_data );
		curr_data = 0;
	}

	/* destroy lock */
	if (ref_lock) {
		lock_destroy_rw( ref_lock );
		ref_lock = 0;
	}

	/* destroy blacklist structures */
	destroy_lb_bls();
}


static int w_lb_next(struct sip_msg *req, pv_spec_t *attrs_var)
{
	int ret;
	str attrs_str = {0,0};
	pv_value_t pv_val;

	lock_start_read(ref_lock);

	/* do lb */
	ret = do_lb_next(req, *curr_data, attrs_var ? &attrs_str : NULL);

	lock_stop_read(ref_lock);

	if (attrs_var) {
		pv_val.flags = PV_VAL_STR;
		pv_val.rs = (attrs_str.s && attrs_str.len) ? attrs_str : attrs_empty;
		if (pv_set_value(req, attrs_var, 0, &pv_val) != 0) {
			LM_ERR("failed to set output variable\n");
			return -1;
		}
	}

	if( ret < 0 )
		return ret;
	return 1;
}


static int w_lb_start(struct sip_msg *req, int *grp_no,
				struct lb_res_str_list *lb_rl, str *flstr, pv_spec_t *attrs_var)
{
	int ret;
	int flags=LB_FLAGS_DEFAULT;
	char *f;
	str attrs_str = {0,0};
	pv_value_t pv_val;

	if( flstr ) {
		for( f=flstr->s ; f<flstr->s+flstr->len ; f++ ) {
			switch( *f ) {
				case 'r':
					flags |= LB_FLAGS_RELATIVE;
					LM_DBG("using relative versus absolute estimation\n");
					break;
				case 'n':
					flags |= LB_FLAGS_NEGATIVE;
					LM_DBG("do not skip negative loads\n");
					break;
				case 's':
					flags |= LB_FLAGS_RANDOM;
					LM_DBG("pick a random destination among all selected dsts with equal load\n");
					break;
				default:
					LM_DBG("skipping unknown flag: [%c]\n", *f);
			}
		}
	}

	lock_start_read( ref_lock );

	/* do lb */
	ret = do_lb_start(req, *grp_no, lb_rl, flags, *curr_data,
		attrs_var ? &attrs_str : NULL);

	lock_stop_read( ref_lock );

	if (attrs_var) {
		pv_val.flags = PV_VAL_STR;
		pv_val.rs = (attrs_str.s && attrs_str.len) ? attrs_str : attrs_empty;
		if (pv_set_value(req, attrs_var, 0, &pv_val) != 0) {
			LM_ERR("failed to set output variable\n");
			return -1;
		}
	}

	if (ret<0)
		return ret;
	return 1;
}


static int w_lb_start_or_next(struct sip_msg *req,void *grp,void *rl,void *fl,
	pv_spec_t *attrs_var)
{
	return (do_lb_is_started(req) > 0) ?
		w_lb_next(req, attrs_var) :
		w_lb_start(req, grp, rl, fl, attrs_var)
	;
}


static int w_lb_reset(struct sip_msg *req)
{
	int ret;

	lock_start_read(ref_lock);

	/* do lb */
	ret = do_lb_reset(req, *curr_data);

	lock_stop_read(ref_lock);

	if( ret < 0 )
		return ret;
	return 1;
}


static int w_lb_is_started(struct sip_msg *req)
{
	int ret;

	/* do lb, do not need a lock, since do not use '*curr_data' */
	ret = do_lb_is_started(req);

	if( ret < 0 )
		return ret;
	return 1;
}


static int w_lb_disable_dst(struct sip_msg *req)
{
	int ret;

	lock_start_read(ref_lock);

	/* do lb */
	ret = do_lb_disable_dst(req, *curr_data, lb_prob_verbose);

	lock_stop_read(ref_lock);

	if( ret < 0 )
		return ret;
	return 1;
}


static int w_lb_is_dst(struct sip_msg *msg,str *ip,int *port,int *group,
										int *active, pv_spec_t *attrs_var)
{
	int ret;
	str attrs_str = {0,0};
	pv_value_t pv_val;

	lock_start_read( ref_lock );

	ret = lb_is_dst(*curr_data, msg, ip, *port,
	    group ? *group : -1, active ? *active : 0, attrs_var ? &attrs_str : NULL);

	lock_stop_read( ref_lock );

	if (attrs_var) {
		pv_val.flags = PV_VAL_STR;
		pv_val.rs = (attrs_str.s && attrs_str.len) ? attrs_str : attrs_empty;
		if (pv_set_value(msg, attrs_var, 0, &pv_val) != 0)
			LM_ERR("failed to set output variable\n");
	}

	if (ret<0)
		return ret;
	return 1;
}


static int w_lb_count_call(struct sip_msg *req, str *ip_str, int *port, char *grp,
					struct lb_res_str_list *lb_rl, int *dir)
{
	struct ip_addr *ipa;
	int ret;

	if ( (ipa=str2ip(ip_str))==NULL && (ipa=str2ip6(ip_str))==NULL) {
		LM_ERR("IP val is not IP <%.*s>\n",ip_str->len,ip_str->s);
		return -1;
	}

	lock_start_read( ref_lock );

	ret = lb_count_call( *curr_data, req, ipa, *port, *grp, lb_rl,
			dir ? *dir : 0);

	lock_stop_read( ref_lock );

	if (ret<0)
		return ret;
	return 1;
}



/******************** PROBING Stuff ***********************/


static int check_options_rplcode(int code)
{
	int i;

	for (i =0; i< probing_codes_no; i++) {
		if(probing_reply_codes[i] == code)
			return 1;
	}

	return 0;
}



void set_dst_state_from_rplcode( int id, int code)
{
	struct lb_dst *dst;
	int old_flags;

	lock_start_read( ref_lock );

	for( dst=(*curr_data)->dsts ; dst && dst->id!=id ; dst=dst->next);
	if (dst==NULL) {
		lock_stop_read( ref_lock );
		return;
	}

	if ((code == 200) || check_options_rplcode(code)) {
		/* re-enable to DST  (if allowed) */
		if ( dst->flags&LB_DST_STAT_NOEN_FLAG ) {
			lock_stop_read( ref_lock );
			return;
		}
		old_flags = dst->flags;
		dst->flags &= ~LB_DST_STAT_DSBL_FLAG;
		if (dst->flags != old_flags) {
			lb_status_changed(dst);
			if (lb_prob_verbose)
				LM_INFO("re-enable destination %d <%.*s> after %d reply "
					"on probe\n", dst->id, dst->uri.len, dst->uri.s, code);
		}
		lock_stop_read( ref_lock );
		return;
	}

	if (code>=400) {
		old_flags = dst->flags;
		dst->flags |= LB_DST_STAT_DSBL_FLAG;
		if (dst->flags != old_flags) {
			lb_status_changed(dst);
			if (lb_prob_verbose)
				LM_INFO("disable destination %d <%.*s> after %d reply "
					"on probe\n", dst->id, dst->uri.len, dst->uri.s, code);
		}
	}

	lock_stop_read( ref_lock );
}



static void lb_prob_handler(unsigned int ticks, void* param)
{
	lock_start_read( ref_lock );

	/* do probing */
	lb_do_probing(*curr_data);

	lock_stop_read( ref_lock );
}

static void lb_update_max_loads(unsigned int ticks, void *param)
{
	struct lb_dst *dst;
	int ri, old, psz;

	LM_DBG("updating max loads...\n");

	lock_start_write(ref_lock);
	for (dst = (*curr_data)->dsts; dst; dst = dst->next) {
		if (!dst->fs_sock)
			continue;

		lock_start_read(dst->fs_sock->stats_lk);
		for (ri = 0; ri < dst->rmap_no; ri++) {
			if (dst->rmap[ri].fs_enabled) {
				psz = lb_dlg_binds.get_profile_size(
				            dst->rmap[ri].resource->profile, &dst->profile_id);
				old = dst->rmap[ri].max_load;

				/*
				 * The normal case. OpenSIPS sees, at _most_, the same number
				 * of sessions as FreeSWITCH does. Any differences must be
				 * subtracted from the remote "max sessions" value
				 */
				if (psz < dst->fs_sock->stats.max_sess) {
					dst->rmap[ri].max_load =
					(dst->fs_sock->stats.id_cpu / (float)100) *
						(dst->fs_sock->stats.max_sess -
						 (dst->fs_sock->stats.sess - psz));
				} else {
					dst->rmap[ri].max_load =
					(dst->fs_sock->stats.id_cpu / (float)100) *
						dst->fs_sock->stats.max_sess;
				}
				LM_DBG("load update on FS (%p) %s:%d: "
				       "%d -> %d (%d %d %.3f), prof=%d\n",
				       dst->fs_sock, dst->fs_sock->host.s, dst->fs_sock->port,
				       old, dst->rmap[ri].max_load, dst->fs_sock->stats.sess,
				       dst->fs_sock->stats.max_sess,
				       dst->fs_sock->stats.id_cpu, psz);
			}
		}
		lock_stop_read(dst->fs_sock->stats_lk);
	}
	lock_stop_write(ref_lock);
}

/******************** MI commands ***********************/
mi_response_t *mi_lb_reload(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	LM_INFO("\"lb_reload\" MI command received!\n");

	if ( lb_reload_data()!=0 ) {
		LM_CRIT("failed to load load balancing data\n");
		goto error;
	}

	if (lb_cluster_id && lb_cluster_sync() < 0)
		return init_mi_error(500, MI_SSTR("Failed to synchronize from cluster"));

	return init_mi_result_ok();
error:
	return init_mi_error( 500, MI_SSTR("Failed to reload"));
}

/*! \brief
 * Expects 3 nodes:
 *        destination ID (number)
 *        resource name (string)
 *        size (number)
 */

mi_response_t *mi_lb_resize(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct lb_dst *dst;
	int n, size;
	int id;
	str name;

	if (get_mi_int_param(params, "destination_id", &id) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "res_name", &name.s, &name.len) < 0)
		return init_mi_param_error();
	if (get_mi_int_param(params, "new_capacity", &size) < 0)
		return init_mi_param_error();

	lock_start_read( ref_lock );

	/* get destination */
	for( dst=(*curr_data)->dsts ; dst && dst->id!=id ; dst=dst->next);
	if (dst==NULL) {
		lock_stop_read( ref_lock );
		return init_mi_error( 404, MI_SSTR("Destination ID not found"));
	} else {
		/* get resource */
		for( n=0 ; n<dst->rmap_no ; n++)
			if (dst->rmap[n].resource->name.len == name.len &&
			memcmp( dst->rmap[n].resource->name.s, name.s, name.len)==0)
				break;
		if (n==dst->rmap_no) {
			lock_stop_read( ref_lock );
			return init_mi_error( 404,
				MI_SSTR("Destination has no such resource"));
		} else {
			dst->rmap[n].max_load = size;
		}
	}

	lock_stop_read( ref_lock );

	return init_mi_result_ok();
}


mi_response_t *mi_lb_status(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int id;
	struct lb_dst *dst;
	mi_response_t *resp;
	mi_item_t *resp_obj;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (get_mi_int_param(params, "destination_id", &id) < 0)
		return init_mi_param_error();

	lock_start_read( ref_lock );

	for(dst=(*curr_data)->dsts; dst && dst->id!=id ;dst=dst->next);
	if (dst==NULL) {
		lock_stop_read( ref_lock );
		return init_mi_error(404, MI_SSTR("Destination ID not found"));
	} else {
		if (dst->flags&LB_DST_STAT_DSBL_FLAG) {
			if (add_mi_string(resp_obj, MI_SSTR("enable"), MI_SSTR("no")) < 0)
				goto error;
		} else {
			if (add_mi_string(resp_obj, MI_SSTR("enable"), MI_SSTR("yes")) < 0)
				goto error;
		}

		if (dst->attrs.s && dst->attrs.len &&
			add_mi_string(resp_obj, MI_SSTR("attrs"),
				dst->attrs.s, dst->attrs.len) < 0)
			goto error;
	}

	lock_stop_read( ref_lock );
	return resp;

error:
	lock_stop_read( ref_lock );
	free_mi_response(resp);
	return 0;
}

mi_response_t *mi_lb_status_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int id;
	int stat;
	unsigned int old_flags;
	struct lb_dst *dst;

	if (get_mi_int_param(params, "destination_id", &id) < 0)
		return init_mi_param_error();
	if (get_mi_int_param(params, "new_status", &stat) < 0)
		return init_mi_param_error();

	lock_start_read( ref_lock );

	for( dst=(*curr_data)->dsts ; dst && dst->id!=id ; dst=dst->next);
	if (dst==NULL) {
		lock_stop_read( ref_lock );
		return init_mi_error(404, MI_SSTR("Destination ID not found"));
	} else {
		/* set the disable/enable */
		old_flags = dst->flags;
		if (stat) {
			dst->flags &=
				~ (LB_DST_STAT_DSBL_FLAG|LB_DST_STAT_NOEN_FLAG);
		} else {
			dst->flags |=
				LB_DST_STAT_DSBL_FLAG|LB_DST_STAT_NOEN_FLAG;
		}
		if (old_flags != dst->flags) {
			lb_status_changed(dst);
			if( lb_prob_verbose )
				LM_INFO("manually %s destination %d <%.*s>\n",
					(stat ? "enable" : "disable"),
					dst->id, dst->uri.len, dst->uri.s
				);
		}
	}

	lock_stop_read( ref_lock );
	return init_mi_result_ok();
}


mi_response_t *mi_lb_list(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct lb_dst *dst;
	int i;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *dests_arr, *dest_item, *res_arr, *res_item;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	dests_arr = add_mi_array(resp_obj, MI_SSTR("Destinations"));
	if (!dests_arr)
		goto error;

	lock_start_read( ref_lock );

	/* go through all destination */
	for( dst=(*curr_data)->dsts ; dst ; dst=dst->next) {
		dest_item = add_mi_object(dests_arr, NULL, 0);
		if (!dest_item)
			goto error;

		if (add_mi_string(dest_item, MI_SSTR("uri"), dst->uri.s, dst->uri.len) < 0)
			goto error;

		if (add_mi_number(dest_item, MI_SSTR("id"), dst->id) < 0)
			goto error;

		if (add_mi_number(dest_item, MI_SSTR("group"), dst->group) < 0)
			goto error;

		if (dst->flags&LB_DST_STAT_DSBL_FLAG) {
			if (add_mi_string(dest_item, MI_SSTR("enabled"), MI_SSTR("no")) < 0)
				goto error;
		} else {
			if (add_mi_string(dest_item, MI_SSTR("enabled"), MI_SSTR("yes")) < 0)
				goto error;
		}

		if (dst->flags&LB_DST_STAT_NOEN_FLAG) {
			if (add_mi_string(dest_item, MI_SSTR("auto-reenable"),
				MI_SSTR("off")) < 0)
				goto error;
		} else {
			if (add_mi_string(dest_item, MI_SSTR("auto-reenable"),
				MI_SSTR("on")) < 0)
				goto error;
		}

		res_arr = add_mi_array(dest_item, MI_SSTR("Resources"));
		if (!res_arr)
			goto error;

		/* go through all resources */
		for( i=0 ; i<dst->rmap_no ; i++) {
			res_item = add_mi_object(res_arr, NULL, 0);
			if (!res_item)
				goto error;

			if (add_mi_string(res_item, MI_SSTR("name"),
				dst->rmap[i].resource->name.s,dst->rmap[i].resource->name.len) < 0)
				goto error;

			if (add_mi_number(res_item, MI_SSTR("max"), dst->rmap[i].max_load) < 0)
				goto error;

			if (add_mi_number(res_item, MI_SSTR("load"),
				lb_dlg_binds.get_profile_size
				(dst->rmap[i].resource->profile, &dst->profile_id)) < 0)
				goto error;
		}

		if (dst->attrs.s && dst->attrs.len &&
			add_mi_string(dest_item, MI_SSTR("attrs"),
				dst->attrs.s, dst->attrs.len) < 0)
			goto error;
	}

	lock_stop_read( ref_lock );
	return resp;

error:
	lock_stop_read( ref_lock );
	free_mi_response(resp);
	return 0;
}


int lb_update_from_replication( unsigned int group, str *uri,
										unsigned int flags, int raise_event)
{
	struct lb_dst *dst;

	lock_start_read( ref_lock );

	for( dst=(*curr_data)->dsts; dst; dst=dst->next ) {
		if ( (dst->group == group) &&
		(strncmp(dst->uri.s, uri->s, dst->uri.len) == 0)) {
			if ((dst->flags&LB_DST_STAT_MASK) != flags) {
				/* import the status flags */
				dst->flags = ((~LB_DST_STAT_MASK)&dst->flags)|
					(LB_DST_STAT_MASK&flags);
				if (raise_event)
					/* raise event of status change */
					lb_raise_event(dst);
				lock_stop_read( ref_lock );
				return 0;
			}
		}
	}

	lock_stop_read( ref_lock );

	return -1;
}


