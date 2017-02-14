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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2009-02-01 initial version (bogdan)
 */

#include "../../sr_module.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../timer.h"
#include "../../ut.h"
#include "../../mod_fix.h"
#include "../../rw_locking.h"
#include "../../usr_avp.h"

#include "../dialog/dlg_load.h"
#include "../tm/tm_load.h"
#include "../freeswitch/fs_api.h"

#include "lb_parser.h"
#include "lb_db.h"
#include "lb_data.h"
#include "lb_prober.h"
#include "lb_bl.h"



/* db stuff */
static str db_url = {NULL, 0};
static char *table_name = NULL;

/* dialog stuff */
struct dlg_binds lb_dlg_binds;

/* reader-writers lock for data reloading */
static rw_lock_t *ref_lock = NULL;
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



static struct mi_root* mi_lb_reload(struct mi_root *cmd_tree, void *param);
static struct mi_root* mi_lb_resize(struct mi_root *cmd_tree, void *param);
static struct mi_root* mi_lb_list(struct mi_root *cmd_tree, void *param);
static struct mi_root* mi_lb_status(struct mi_root *cmd_tree, void *param);

static int fixup_resources(void** param, int param_no);
static int fixup_is_dst(void** param, int param_no);
static int fixup_cnt_call(void** param, int param_no);

static int w_lb_start(struct sip_msg *req, char *grp, char *rl, char *fl);
static int w_lb_next(struct sip_msg *req);
static int w_lb_start_or_next(struct sip_msg *req,char *grp,char *rl,char *fl);
static int w_lb_reset(struct sip_msg *req);
static int w_lb_is_started(struct sip_msg *req);
static int w_lb_disable_dst(struct sip_msg *req);
static int w_lb_is_dst2(struct sip_msg *msg, char *ip, char *port);
static int w_lb_is_dst3(struct sip_msg *msg, char *ip, char *port, char *grp);
static int w_lb_is_dst4(struct sip_msg *msg, char *ip, char *port, char *grp,
		char *active);
static int w_lb_count_call(struct sip_msg *req, char *ip, char *port, char *grp,
		char *rl, char *dir);


static void lb_prob_handler(unsigned int ticks, void* param);
static void lb_update_max_loads(unsigned int ticks, void *param);




static cmd_export_t cmds[]={
	{"lb_start",         (cmd_function)w_lb_start,         2, fixup_resources,
		0, REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"lb_start",         (cmd_function)w_lb_start,         3, fixup_resources,
		0, REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"load_balance",    (cmd_function)w_lb_start_or_next,  2, fixup_resources,
		0, REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"load_balance",    (cmd_function)w_lb_start_or_next,  3, fixup_resources,
		0, REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"lb_start_or_next",(cmd_function)w_lb_start_or_next,  2, fixup_resources,
		0, REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"lb_start_or_next",(cmd_function)w_lb_start_or_next,  3, fixup_resources,
		0, REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"lb_next",          (cmd_function)w_lb_next,          0,               0,
		0, REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"lb_reset",         (cmd_function)w_lb_reset,         0,               0,
		0, REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"lb_is_started",    (cmd_function)w_lb_is_started,    0,               0,
		0, REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"lb_disable_dst",   (cmd_function)w_lb_disable_dst,   0,               0,
		0, REQUEST_ROUTE|FAILURE_ROUTE},
	{"lb_is_destination",(cmd_function)w_lb_is_dst2,       2,    fixup_is_dst,
		0, REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"lb_is_destination",(cmd_function)w_lb_is_dst3,       3,    fixup_is_dst,
		0, REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"lb_is_destination",(cmd_function)w_lb_is_dst4,       4,    fixup_is_dst,
		0, REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"lb_count_call",    (cmd_function)w_lb_count_call,    4,  fixup_cnt_call,
		0, REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"lb_count_call",    (cmd_function)w_lb_count_call,    5,  fixup_cnt_call,
		0, REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{0,0,0,0,0,0}
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
	{ "fetch_freeswitch_stats", INT_PARAM, &fetch_freeswitch_stats},
	{ "initial_freeswitch_load", INT_PARAM, &initial_fs_load},
	{ 0,0,0 }
};


static mi_export_t mi_cmds[] = {
	{ "lb_reload",   0, mi_lb_reload,   MI_NO_INPUT_FLAG,   0,  mi_child_init},
	{ "lb_resize",   0, mi_lb_resize,   0,                  0,  0},
	{ "lb_list",     0, mi_lb_list,     MI_NO_INPUT_FLAG,   0,  0},
	{ "lb_status",   0, mi_lb_status,   0,                  0,  0},
	{ 0, 0, 0, 0, 0, 0}
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
		{ "probing_interval",      get_deps_probing_interval },
		{ "fetch_freeswitch_stats", get_deps_fetch_fs_load },
		{ NULL, NULL },
	},
};

struct module_exports exports= {
	"load_balancer",  /* module's name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	&deps,           /* OpenSIPS module dependencies */
	cmds,            /* exported functions */
	0,               /* exported async functions */
	mod_params,      /* param exports */
	0,               /* exported statistics */
	mi_cmds,         /* exported MI functions */
	0,               /* exported pseudo-variables */
	0,               /* extra processes */
	mod_init,        /* module initialization function */
	0,               /* reply processing function */
	mod_destroy,
	child_init       /* per-child init function */
};


struct lb_grp_param {
	int grp_no;
	pv_spec_t *grp_pv;
};


static int fixup_resources(void** param, int param_no)
{
	struct lb_res_str_list *lb_rl;
	struct lb_grp_param *lbgp;
	struct lb_res_parse *lbp;
	pv_elem_t *model=NULL;
	str s;

	if (param_no==1) {

		lbgp = (struct lb_grp_param *)pkg_malloc(sizeof(struct lb_grp_param));
		if (lbgp==NULL) {
			LM_ERR("no more pkg mem\n");
			return E_OUT_OF_MEM;
		}
		/* try first as number */
		s.s = (char*)*param;
		s.len = strlen(s.s);
		if (str2int(&s, (unsigned int*)&lbgp->grp_no)==0) {
			lbgp->grp_pv = NULL;
			pkg_free(*param);
		} else {
			lbgp->grp_pv = (pv_spec_t*)pkg_malloc(sizeof(pv_spec_t));
			if (lbgp->grp_pv==NULL) {
				LM_ERR("no pkg memory left\n");
				return E_OUT_OF_MEM;
			}
			if (pv_parse_spec(&s, lbgp->grp_pv)==0 ||
			lbgp->grp_pv->type==PVT_NULL) {
				LM_ERR("%s is not integer nor PV !\n", (char*)*param);
				return E_UNSPEC;
			}
		}
		*param=(void *)(unsigned long)lbgp;
		return 0;

	} else if (param_no==2) {

		/* parameter is string (semi-colon separated list)
		 * of needed resources */
		lbp = (struct lb_res_parse *)pkg_malloc(sizeof(struct lb_res_parse));
		if (!lbp) {
			LM_ERR("no more pkg mem\n");
			return E_OUT_OF_MEM;
		}
		s.s = (char*)*param;
		s.len = strlen(s.s);

		if(pv_parse_format(&s ,&model) || model==NULL) {
			LM_ERR("wrong format [%s] in resource list!\n", s.s);
			return E_CFG;
		}
		/* check if there is any pv in string */
		if (!model->spec.getf && !model->next)
			lbp->type = RES_TEXT;
		else
			lbp->type = RES_ELEM;

		if (lbp->type & RES_TEXT) {
			lb_rl = parse_resources_list( (char *)(*param), 0);
			if (lb_rl==NULL) {
				LM_ERR("invalid parameter %s\n",(char *)(*param));
				return E_CFG;
			}
			pkg_free(*param);
			lbp->param = (void*)(unsigned long)lb_rl;
		} else {
			lbp->param = (void*)(unsigned long)model;
		}
		*param = (void *)(unsigned long)lbp;
		return 0;

	} else if (param_no==3) {
		/* string with flags */
		return fixup_sgp(param);

	}

	LM_CRIT("error - wrong params count (%d)\n",param_no);
	return -1;
}


static int fixup_is_dst(void** param, int param_no)
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
		return fixup_igp(param);
	} else if (param_no==3) {
		/* the group to check in */
		return fixup_igp(param);
	} else if (param_no==4) {
		/*  active only check ? */
		return fixup_uint(param);
	} else {
		LM_CRIT("bug - too many params (%d) in lb_is_dst()\n",param_no);
		return -1;
	}
}


static int fixup_cnt_call(void** param, int param_no)
{
	if (param_no==1)
		/* IP */
		return fixup_is_dst(param, 1);
	if (param_no==2)
		/* port */
		return fixup_is_dst(param, 2);
	if (param_no==3)
		/* group id */
		return fixup_resources(param, 1);
	if (param_no==4)
		/* resources */
		return fixup_resources(param, 2);
	if (param_no==5)
		/* count or un-count */
		return fixup_uint(param);

	LM_CRIT("error - wrong params count (%d)\n",param_no);
	return -1;
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
		                   FS_HEARTBEAT_ITV, TIMER_FLAG_SKIP_ON_DELAY)<0) {
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


static int w_lb_next(struct sip_msg *req)
{
	int ret;

	lock_start_read(ref_lock);

	/* do lb */
	ret = do_lb_next(req, *curr_data);

	lock_stop_read(ref_lock);

	if( ret < 0 )
		return ret;
	return 1;
}


static int w_lb_start(struct sip_msg *req, char *grp, char *rl, char *fl)
{
	int ret;

	int grp_no;
	struct lb_grp_param *lbgp = (struct lb_grp_param *)grp;
	pv_value_t val;

	struct lb_res_str_list *lb_rl;
	struct lb_res_parse *lbp;
	pv_elem_t *model;
	str dest;

	str flstr = {0,0};
	int flags=LB_FLAGS_DEFAULT;
	char *f;

	if (lbgp->grp_pv) {
		if (pv_get_spec_value( req, (pv_spec_p)lbgp->grp_pv, &val)!=0) {
			LM_ERR("failed to get PV value\n");
			return -1;
		}
		if ( (val.flags&PV_VAL_INT)==0 ) {
			LM_ERR("PV vals is not integer\n");
			return -1;
		}
		grp_no = val.ri;
	} else {
		grp_no = lbgp->grp_no;
	}

	lbp = (struct lb_res_parse *)rl;
	if (lbp->type & RES_ELEM) {
		model = (pv_elem_p)lbp->param;
		if (pv_printf_s(req, model, &dest) || dest.len <= 0) {
			LM_ERR("cannot create resource string\n");
			return -1;
		}
		lb_rl = parse_resources_list(dest.s, 0);
		if (!lb_rl) {
			LM_ERR("cannot create resource list\n");
			return -1;
		}
	} else
		lb_rl = (struct lb_res_str_list *)lbp->param;

	if( fl ) {
		if( fixup_get_svalue(req, (gparam_p)fl, &flstr) != 0 ) {
			LM_ERR("failed to extract flags\n");
			return -1;
		}
		for( f=flstr.s ; f<flstr.s+flstr.len ; f++ ) {
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
	ret = do_lb_start(req, grp_no, lb_rl, flags, *curr_data);

	lock_stop_read( ref_lock );

	if (lbp->type & RES_ELEM)
		pkg_free(lb_rl);

	if (ret<0)
		return ret;
	return 1;
}


static int w_lb_start_or_next(struct sip_msg *req,char *grp,char *rl,char *fl)
{
	return (do_lb_is_started(req) > 0) ?
		w_lb_next(req) :
		w_lb_start(req, grp, rl, fl)
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


static int w_lb_is_dst2(struct sip_msg *msg, char *ip, char *port)
{
	int ret;

	lock_start_read( ref_lock );

	ret = lb_is_dst(*curr_data, msg, (pv_spec_t*)ip, (gparam_t*)port, -1, 0);

	lock_stop_read( ref_lock );

	if (ret<0)
		return ret;
	return 1;
}


static int w_lb_is_dst3(struct sip_msg *msg,char *ip,char *port,char *grp)
{
	return w_lb_is_dst4(msg, ip, port, grp, 0);
}


static int w_lb_is_dst4(struct sip_msg *msg,char *ip,char *port,char *grp,
															char *active)
{
	int ret, group;

	if (fixup_get_ivalue(msg, (gparam_p)grp, &group) != 0) {
		LM_ERR("Invalid lb group pseudo variable!\n");
		return -1;
	}

	lock_start_read( ref_lock );

	ret = lb_is_dst(*curr_data, msg, (pv_spec_t*)ip, (gparam_t*)port,
	                group, (int)(long)active);

	lock_stop_read( ref_lock );

	if (ret<0)
		return ret;
	return 1;
}


static int w_lb_count_call(struct sip_msg *req, char *ip, char *port, char *grp,
			char *rl, char *dir)
{
	struct lb_grp_param *lbgp = (struct lb_grp_param *)grp;
	struct lb_res_str_list *lb_rl;
	struct lb_res_parse *lbp;
	struct ip_addr *ipa;
	pv_value_t val;
	pv_elem_t *model;
	int grp_no;
	int port_no;
	str dest;
	int ret;

	/* get the ip address */
	if (pv_get_spec_value( req, (pv_spec_t*)ip, &val)!=0) {
		LM_ERR("failed to get IP value from PV\n");
		return -1;
	}
	if ( (val.flags&PV_VAL_STR)==0 ) {
		LM_ERR("IP PV val is not string\n");
		return -1;
	}
	if ( (ipa=str2ip( &val.rs ))==NULL ) {
		LM_ERR("IP val is not IP <%.*s>\n",val.rs.len,val.rs.s);
		return -1;
	}

	/* get the port */
	if (port) {
		if (fixup_get_ivalue( req, (gparam_p)port, &port_no)!=0) {
			LM_ERR("failed to get PORT value from PV\n");
			return -1;
		}
	} else {
		port_no = 0;
	}

	/* get the group */
	if (lbgp->grp_pv) {
		if (pv_get_spec_value( req, (pv_spec_p)lbgp->grp_pv, &val)!=0) {
			LM_ERR("failed to get PV value\n");
			return -1;
		}
		if ( (val.flags&PV_VAL_INT)==0 ) {
			LM_ERR("PV vals is not integer\n");
			return -1;
		}
		grp_no = val.ri;
	} else {
		grp_no = lbgp->grp_no;
	}

	/* get the resources list */
	lbp = (struct lb_res_parse *)rl;
	if (lbp->type & RES_ELEM) {
		model = (pv_elem_p)lbp->param;
		if (pv_printf_s(req, model, &dest) || dest.len <= 0) {
			LM_ERR("cannot create resource string\n");
			return -1;
		}
		lb_rl = parse_resources_list(dest.s, 0);
		if (!lb_rl) {
			LM_ERR("cannot create resource list\n");
			return -1;
		}
	} else
		lb_rl = (struct lb_res_str_list *)lbp->param;

	lock_start_read( ref_lock );

	ret = lb_count_call( *curr_data, req, ipa, port_no, grp_no, lb_rl,
			(unsigned int)(long)dir);

	lock_stop_read( ref_lock );

	if (lbp->type & RES_ELEM)
		pkg_free(lb_rl);

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
			lb_raise_event(dst);
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
			lb_raise_event(dst);
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

		lock_start_read(dst->fs_sock->hb_data_lk);
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
				if (psz < dst->fs_sock->hb_data.max_sess) {
					dst->rmap[ri].max_load =
					(dst->fs_sock->hb_data.id_cpu / (float)100) *
						(dst->fs_sock->hb_data.max_sess -
						 (dst->fs_sock->hb_data.sess - psz));
				} else {
					dst->rmap[ri].max_load =
					(dst->fs_sock->hb_data.id_cpu / (float)100) *
						dst->fs_sock->hb_data.max_sess;
				}
				LM_DBG("load update on FS (%p) %s:%d: "
				       "%d -> %d (%d %d %.3f), prof=%d\n",
				       dst->fs_sock, dst->fs_sock->host.s, dst->fs_sock->port,
				       old, dst->rmap[ri].max_load, dst->fs_sock->hb_data.sess,
				       dst->fs_sock->hb_data.max_sess,
				       dst->fs_sock->hb_data.id_cpu, psz);
			}
		}
		lock_stop_read(dst->fs_sock->hb_data_lk);
	}
	lock_stop_write(ref_lock);
}

/******************** MI commands ***********************/

static struct mi_root* mi_lb_reload(struct mi_root *cmd_tree, void *param)
{
	LM_INFO("\"lb_reload\" MI command received!\n");

	if ( lb_reload_data()!=0 ) {
		LM_CRIT("failed to load load balancing data\n");
		goto error;
	}

	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
error:
	return init_mi_tree( 500, "Failed to reload",16);
}

/*! \brief
 * Expects 3 nodes:
 *        destination ID (number)
 *        resource name (string)
 *        size (number)
 */

static struct mi_root* mi_lb_resize(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct lb_dst *dst;
	struct mi_node *node;
	unsigned int  id, size;
	str *name;
	int n;

	for( n=0,node = cmd->node.kids; n<3 && node ; n++,node=node->next );
	if (n!=3 || node!=0)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	node = cmd->node.kids;

	/* id (param 1) */
	if (str2int( &node->value, &id) < 0)
		goto bad_syntax;

	/* resource (param 2) */
	node = node->next;
	name = &node->value;

	/* id (param 3) */
	node = node->next;
	if (str2int( &node->value, &size) < 0)
		goto bad_syntax;

	lock_start_read( ref_lock );

	/* get destination */
	for( dst=(*curr_data)->dsts ; dst && dst->id!=id ; dst=dst->next);
	if (dst==NULL) {
		rpl_tree = init_mi_tree( 404, MI_SSTR("Destination ID not found"));
	} else {
		/* get resource */
		for( n=0 ; n<dst->rmap_no ; n++)
			if (dst->rmap[n].resource->name.len == name->len &&
			memcmp( dst->rmap[n].resource->name.s, name->s, name->len)==0)
				break;
		if (n==dst->rmap_no) {
			rpl_tree = init_mi_tree( 404,
				MI_SSTR("Destination has no such resource"));
		} else {
			dst->rmap[n].max_load = size;
			rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK_S));
		}
	}

	lock_stop_read( ref_lock );

	return rpl_tree;
bad_syntax:
	return init_mi_tree( 400, MI_SSTR(MI_BAD_PARM_S));

}


/*! \brief
 * Expects 2 nodes:
 *        destination ID (number)
 *        status (number)
 */

static struct mi_root* mi_lb_status(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct lb_dst *dst;
	struct mi_node *node;
	unsigned int  id, stat;
	unsigned int old_flags;

	node = cmd->node.kids;
	if (node==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	/* id (param 1) */
	if (str2int( &node->value, &id) < 0)
		return init_mi_tree( 400, MI_SSTR(MI_BAD_PARM_S));

	lock_start_read( ref_lock );

	/* status (param 2) */
	node = node->next;
	if (node == NULL) {
		/* return the status -> find the destination */
		for(dst=(*curr_data)->dsts; dst && dst->id!=id ;dst=dst->next);
		if (dst==NULL) {
			rpl_tree = init_mi_tree( 404,
				MI_SSTR("Destination ID not found"));
		} else {
			rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
			if (rpl_tree!=NULL) {
				if (dst->flags&LB_DST_STAT_DSBL_FLAG) {
					node = add_mi_node_child( &rpl_tree->node, 0, "enable", 6,
							"no", 2);
				} else {
					node = add_mi_node_child( &rpl_tree->node, 0, "enable", 6,
							"yes", 3);
				}
				if (node==NULL) {free_mi_tree(rpl_tree); rpl_tree=NULL;}
			}
		}
	} else {
		/* set the status */
		if (node->next) {
			rpl_tree = init_mi_tree( 400,
				MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);
		} else if (str2int( &node->value, &stat) < 0) {
			rpl_tree = init_mi_tree( 400, MI_SSTR(MI_BAD_PARM_S));
		} else {
			/* find the destination */
			for( dst=(*curr_data)->dsts ; dst && dst->id!=id ; dst=dst->next);
			if (dst==NULL) {
				rpl_tree =  init_mi_tree( 404,
					MI_SSTR("Destination ID not found"));
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
					lb_raise_event(dst);
					if( lb_prob_verbose )
						LM_INFO("manually %s destination %d <%.*s>\n",
							(stat ? "enable" : "disable"),
							dst->id, dst->uri.len, dst->uri.s
						);
				}
				lock_stop_read( ref_lock );
				return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
			}
		}
	}

	lock_stop_read( ref_lock );

	return rpl_tree;
}




static struct mi_root* mi_lb_list(struct mi_root *cmd_tree, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *dst_node;
	struct mi_node *node, *node1;
	struct mi_attr *attr;
	struct lb_dst *dst;
	char *p;
	int len;
	int i;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==NULL)
		return NULL;
	rpl_tree->node.flags |= MI_IS_ARRAY;

	lock_start_read( ref_lock );

	/* go through all destination */
	for( dst=(*curr_data)->dsts ; dst ; dst=dst->next) {
		/* add a destination node */
		dst_node = add_mi_node_child( &rpl_tree->node, 0, "Destination", 11,
					dst->uri.s, dst->uri.len);
		if (dst_node==0)
			goto error;

		/* add some attributes to the destination node */
		p= int2str((unsigned long)dst->id, &len);
		attr = add_mi_attr( dst_node, MI_DUP_VALUE, "id", 2, p, len);
		if (attr==0)
			goto error;

		p= int2str((unsigned long)dst->group, &len);
		attr = add_mi_attr( dst_node, MI_DUP_VALUE, "group", 5, p, len);
		if (attr==0)
			goto error;

		if (dst->flags&LB_DST_STAT_DSBL_FLAG) {
			attr = add_mi_attr( dst_node, 0, "enabled", 7, "no", 2);
		} else {
			attr = add_mi_attr( dst_node, 0, "enabled", 7, "yes", 3);
		}
		if (attr==0)
			goto error;

		if (dst->flags&LB_DST_STAT_NOEN_FLAG) {
			attr = add_mi_attr( dst_node, 0, "auto-reenable", 13, "off", 3);
		} else {
			attr = add_mi_attr( dst_node, 0, "auto-reenable", 13, "on", 2);
		}
		if (attr==0)
			goto error;

		node = add_mi_node_child( dst_node, MI_IS_ARRAY, "Resources", 9, NULL, 0);
		if (node==0)
			goto error;

		/* go through all resources */
		for( i=0 ; i<dst->rmap_no ; i++) {
		/* add a resource node */
			node1 = add_mi_node_child( node, 0, "Resource", 8,
				dst->rmap[i].resource->name.s,dst->rmap[i].resource->name.len);
			if (node1==0)
				goto error;

			/* add some attributes to the destination node */
			p= int2str((unsigned long)dst->rmap[i].max_load, &len);
			attr = add_mi_attr( node1, MI_DUP_VALUE, "max", 3, p, len);
			if (attr==0)
				goto error;

			p= int2str((unsigned long)lb_dlg_binds.get_profile_size
				(dst->rmap[i].resource->profile, &dst->profile_id), &len);
			attr = add_mi_attr( node1, MI_DUP_VALUE, "load", 4, p, len);
			if (attr==0)
				goto error;
		}
	}

	lock_stop_read( ref_lock );
	return rpl_tree;
error:
	lock_stop_read( ref_lock );
	free_mi_tree(rpl_tree);
	return 0;
}
