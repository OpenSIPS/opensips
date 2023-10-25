/*
 * call center module - call queuing and distribution
 *
 * Copyright (C) 2014-2020 OpenSIPS Solutions
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
 */

#include "../../sr_module.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../timer.h"
#include "../../ut.h"
#include "../../locking.h"
#include "../../flags.h"
#include "../../parser/parse_from.h"
#include "../../parser/sdp/sdp.h"
#include "../b2b_logic/b2b_load.h"
#include "cc_data.h"
#include "cc_queue.h"
#include "cc_db.h"



/* db stuff */
static str db_url = {NULL, 0};
static str acc_db_url = {NULL, 0};;
static str rt_db_url = {NULL, 0};;

/* internal data (agents, flows) */
static struct cc_data *data=NULL;
static str b2b_scenario = str_init("call center");
static str b2b_scenario_agent = str_init("call center agent");

/* b2b logic API */
b2bl_api_t b2b_api;

static call_state cc_call_state = CC_CALL_NONE;


static int mod_init(void);
static void mod_destroy(void);
static int child_init( int rank );
static int mi_child_init();

static mi_response_t *mi_cc_reload(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_cc_list_flows(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_cc_list_queue(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_agent_login(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_cc_list_agents(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_cc_list_calls(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_reset_stats(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_dispatch_call_to_agent(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_internal_call_dispatching(const mi_params_t *params,
								struct mi_handler *async_hdl);

static int w_handle_call(struct sip_msg *msg, str *flow_name, str *param,
		str *media_s);
static int w_agent_login(struct sip_msg *req, str *agent_s, int *state);

static int pv_get_cc_state( struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

static void cc_timer_agents(unsigned int ticks, void* param);
static void cc_timer_calls(unsigned int ticks, void* param);
static void cc_timer_cleanup(unsigned int ticks, void* param);

unsigned long stg_awt(unsigned short foo);
unsigned long stg_load(unsigned short foo);
unsigned long stg_free_agents(unsigned short foo);

stat_var *stg_incalls = 0;
stat_var *stg_dist_incalls = 0;
stat_var *stg_answ_incalls = 0;
stat_var *stg_answ_inchats = 0;
stat_var *stg_aban_incalls = 0;
stat_var *stg_onhold_calls = 0;
stat_var *stg_onhold_chats = 0;

/* a default of 30 secs wrapup time for agents */
unsigned int wrapup_time = 30;

/* the name of the URI param to report the queue position */
str queue_pos_param = {NULL,0};
/* by default reject new calls if there are no agents logged */
static int reject_on_no_agents = 1;
/* default policy for distributing the MSRP/CHAT sessions to agents */
int msrp_dispatch_policy = CC_MSRP_POLICY_LB;
static char *msrp_dispatch_policy_str = NULL;
/* if calls should be dispatched by internals of the module */
static int internal_call_dispatching_param = 1;
int *internal_call_dispatching = NULL;


static cmd_export_t cmds[]={
	{"cc_handle_call", (cmd_function)w_handle_call,
		{{CMD_PARAM_STR, 0,0},
		 {CMD_PARAM_STR|CMD_PARAM_OPT, 0,0},
		 {CMD_PARAM_STR|CMD_PARAM_OPT, 0,0},
		 {0,0,0}},
		REQUEST_ROUTE},
	{"cc_agent_login", (cmd_function)w_agent_login,
		{{CMD_PARAM_STR, 0,0},
		 {CMD_PARAM_INT, 0,0},
		 {0,0,0}},
		REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

static param_export_t mod_params[]={
	{ "db_url",               STR_PARAM, &db_url.s             },
	{ "acc_db_url",           STR_PARAM, &acc_db_url.s         },
	{ "rt_db_url",            STR_PARAM, &rt_db_url.s          },
	{ "wrapup_time",          INT_PARAM, &wrapup_time          },
	{ "reject_on_no_agents",  INT_PARAM, &reject_on_no_agents  },
	{ "chat_dispatch_policy", STR_PARAM, &msrp_dispatch_policy_str },
	{ "queue_pos_param",      STR_PARAM, &queue_pos_param.s    },
	{ "internal_call_dispatching",INT_PARAM, &internal_call_dispatching_param},
	{ "cc_agents_table",      STR_PARAM, &cc_agent_table_name.s  },
	{ "cca_agentid_column",   STR_PARAM, &cca_agentid_column.s   },
	{ "cca_location_column",  STR_PARAM, &cca_location_column.s  },
	{ "cca_msrp_location_column",    STR_PARAM, &cca_msrp_location_column.s  },
	{ "cca_msrp_max_sessions_column",STR_PARAM, &cca_msrp_max_sessions_column.s  },
	{ "cca_skills_column",    STR_PARAM, &cca_skills_column.s    },
	{ "cca_logstate_column",  STR_PARAM, &cca_logstate_column.s  },
	{ "cca_wrapupend_column", STR_PARAM, &cca_wrapupend_column.s },
	{ "cca_wrapuptime_column",STR_PARAM, &cca_wrapuptime_column.s},

	{ "cc_flows_table",       STR_PARAM, &cc_flow_table_name.s             },
	{ "ccf_flowid_column",    STR_PARAM, &ccf_flowid_column.s              },
	{ "ccf_priority_column",  STR_PARAM, &ccf_priority_column.s            },
	{ "ccf_skill_column",     STR_PARAM, &ccf_skill_column.s               },
	{ "ccf_cid_column",       STR_PARAM, &ccf_cid_column.s                 },
	{ "ccf_max_wrapup_column",STR_PARAM, &ccf_max_wrapup_column.s          },
	{ "ccf_dissuading_hangup_column",
							  STR_PARAM, &ccf_dissuading_hangup_column.s   },
	{ "ccf_dissuading_onhold_th_column",
							  STR_PARAM, &ccf_dissuading_onhold_th_column.s},
	{ "ccf_dissuading_ewt_th_column",
							  STR_PARAM, &ccf_dissuading_ewt_th_column.s   },
	{ "ccf_dissuading_qsize_th_column",
							  STR_PARAM, &ccf_dissuading_qsize_th_column.s },
	{ "ccf_m_welcome_column", STR_PARAM, &ccf_m_welcome_column.s           },
	{ "ccf_m_queue_column",   STR_PARAM, &ccf_m_queue_column.s             },
	{ "ccf_m_dissuading_column",
							  STR_PARAM, &ccf_m_dissuading_column.s        },
	{ "ccf_m_flow_id_column", STR_PARAM, &ccf_m_flow_id_column.s           },
	{ 0,0,0 }
};

static mi_export_t mi_cmds[] = {
	{"cc_reload", 0, 0, mi_child_init, {
		{mi_cc_reload, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{"cc_agent_login", 0, 0, 0, {
		{mi_agent_login, {"agent_id", "state", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{"cc_list_queue", 0, 0, 0, {
		{mi_cc_list_queue, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{"cc_list_flows", 0, 0, 0, {
		{mi_cc_list_flows, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{"cc_list_agents", 0, 0, 0, {
		{mi_cc_list_agents, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{"cc_list_calls", 0, 0, 0, {
		{mi_cc_list_calls, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{"cc_reset_stats", 0, 0, 0, {
		{mi_reset_stats, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{"cc_dispatch_call_to_agent", 0, 0, 0, {
		{mi_dispatch_call_to_agent, {"call_id", "agent_id", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{"cc_internal_call_dispatching", 0, 0, 0, {
		{mi_internal_call_dispatching, {0}},
		{mi_internal_call_dispatching, {"dispatching", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static stat_export_t mod_stats[] = {
	{"ccg_incalls",             0,             &stg_incalls                  },
	{"ccg_awt",                 STAT_IS_FUNC,  (stat_var**)stg_awt           },
	{"ccg_load",                STAT_IS_FUNC,  (stat_var**)stg_load          },
	{"ccg_distributed_incalls", 0,             &stg_dist_incalls             },
	{"ccg_answered_incalls" ,   0,             &stg_answ_incalls             },
	{"ccg_answered_inchats" ,   0,             &stg_answ_inchats             },
	{"ccg_abandonned_incalls" , 0,             &stg_aban_incalls             },
	{"ccg_onhold_calls",        STAT_NO_RESET, &stg_onhold_calls             },
	{"ccg_onhold_chats",        STAT_NO_RESET, &stg_onhold_chats             },
	{"ccg_free_agents",         STAT_IS_FUNC,  (stat_var**)stg_free_agents   },
	{0,0,0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "b2b_logic", DEP_ABORT },
		{ MOD_TYPE_SQLDB,   NULL,        DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

static pv_export_t mod_pvars[] = {
	{ {"cc_state",  sizeof("cc_state")-1},     1000, pv_get_cc_state,
		0,                 0, 0, 0, 0 },
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

struct module_exports exports= {
	"call_center",   /* module's name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,            /* exported functions */
	0,               /* exported async functions */
	mod_params,      /* param exports */
	mod_stats,       /* exported statistics */
	mi_cmds,         /* exported MI functions */
	mod_pvars,       /* exported pseudo-variables */
	0,				 /* exported transformations */
	0,               /* extra processes */
	0,               /* module pre-initialization function */
	mod_init,        /* module initialization function */
	0,               /* reply processing function */
	mod_destroy,
	child_init,      /* per-child init function */
	0                /* reload confirm function */
};



unsigned long stg_awt(unsigned short foo)
{
	return data->avt_waittime;
}


unsigned long stg_load(unsigned short foo)
{
	unsigned int free_ag;
	unsigned int load;
	struct cc_agent *agent;

	lock_get( data->lock );

	if (data->loggedin_agents==0) {
		lock_release( data->lock );
		return 0;
	}

	free_ag = 0;
	for (agent = data->agents[CC_AG_ONLINE] ; agent ; agent=agent->next) {
		if (agent->state==CC_AGENT_FREE) free_ag++;
	}

	load = 100*( get_stat_val(stg_onhold_calls) + data->loggedin_agents - free_ag ) / data->loggedin_agents;

	lock_release( data->lock );

	return load;
}


unsigned long stg_free_agents(unsigned short foo)
{
	struct cc_agent *agent;
	unsigned int free = 0;

	lock_get( data->lock );

	for (agent = data->agents[CC_AG_ONLINE] ; agent ; agent=agent->next) {
		if (agent->state==CC_AGENT_FREE) free++;
	}

	lock_release( data->lock );

	return free;
}

unsigned long cc_flow_free_agents( void *flow)
{
	struct cc_agent *agent;
	unsigned int free = 0;
	unsigned int i;

	lock_get( data->lock );

	for (agent = data->agents[CC_AG_ONLINE] ; agent ; agent=agent->next) {
		if (agent->state==CC_AGENT_FREE) {
			/* iterate all skills of the agent */
			for( i=0 ; i<agent->no_skills ; i++) {
				if (agent->skills[i]==((struct cc_flow*)flow)->skill)
					free++;
			}
		}
	}

	lock_release( data->lock );

	return free;
}


static int mod_init(void)
{
	LM_INFO("Call Center module - initializing\n");

	init_db_url( db_url , 0 /*cannot be null*/);
	init_db_url( acc_db_url , 0 /*cannot be null*/);
	if (rt_db_url.s==NULL)
		rt_db_url = db_url;
	init_db_url( rt_db_url , 0 /*cannot be null*/);

	cc_agent_table_name.len = strlen(cc_agent_table_name.s);
	cca_agentid_column.len = strlen(cca_agentid_column.s);
	cca_location_column.len = strlen(cca_location_column.s);
	cca_skills_column.len = strlen(cca_skills_column.s);
	cca_logstate_column.len = strlen(cca_logstate_column.s);
	cca_wrapupend_column.len = strlen(cca_wrapupend_column.s);
	cca_wrapuptime_column.len = strlen(cca_wrapuptime_column.s);

	cc_flow_table_name.len = strlen(cc_flow_table_name.s);
	ccf_flowid_column.len = strlen(ccf_flowid_column.s);
	ccf_priority_column.len = strlen(ccf_priority_column.s);
	ccf_skill_column.len = strlen(ccf_skill_column.s);
	ccf_cid_column.len = strlen(ccf_cid_column.s);
	ccf_max_wrapup_column.len = strlen(ccf_max_wrapup_column.s);
	ccf_dissuading_hangup_column.len = strlen(ccf_dissuading_hangup_column.s);
	ccf_dissuading_onhold_th_column.len =
		strlen(ccf_dissuading_onhold_th_column.s);
	ccf_dissuading_ewt_th_column.len = strlen(ccf_dissuading_ewt_th_column.s);
	ccf_dissuading_qsize_th_column.len =
		strlen(ccf_dissuading_qsize_th_column.s);
	ccf_m_welcome_column.len = strlen(ccf_m_welcome_column.s);
	ccf_m_queue_column.len = strlen(ccf_m_queue_column.s);
	ccf_m_dissuading_column.len = strlen(ccf_m_dissuading_column.s);
	ccf_m_flow_id_column.len = strlen(ccf_m_flow_id_column.s);

	if (queue_pos_param.s)
		queue_pos_param.len = strlen(queue_pos_param.s);

	if (msrp_dispatch_policy_str) {
		if (!strcasecmp(msrp_dispatch_policy_str, "balancing")) {
			msrp_dispatch_policy = CC_MSRP_POLICY_LB;
		} else if (!strcasecmp(msrp_dispatch_policy_str, "full-load")) {
			msrp_dispatch_policy = CC_MSRP_POLICY_FULL_AGENT;
		}
	}

	internal_call_dispatching = (int*)shm_malloc(sizeof(int));
	if (internal_call_dispatching==NULL) {
		LM_ERR("Can't allocate shm holder for internal_call_dispatching\n");
		return -1;
	}
	*internal_call_dispatching =  (internal_call_dispatching_param==0) ? 0 : 1;

	/* Load B2BUA API */
	if (load_b2b_logic_api( &b2b_api) != 0) {
		LM_ERR("Can't load B2B-UA hooks, missing 'b2b_logic' module ?\n");
		return -1;
	}

	if (register_timer( "cc_agents", cc_timer_agents, NULL, 1,
	TIMER_FLAG_DELAY_ON_DELAY)<0) {
		LM_ERR("failed to register agents timer function\n");
		return -1;
	}

	if (register_timer( "cc_calls", cc_timer_calls, NULL, 1,
	TIMER_FLAG_DELAY_ON_DELAY)<0) {
		LM_ERR("failed to register calls timer function\n");
		return -1;
	}

	if (register_timer( "cc_cleanup", cc_timer_cleanup, NULL, 5,
	TIMER_FLAG_DELAY_ON_DELAY)<0) {
		LM_ERR("failed to register cleaup timer function\n");
		return -1;
	}

	/* main CC data */
	data = init_cc_data();
	if (data==0) {
		LM_CRIT("failed to get shm mem for data\n");
		return -1;
	}

	/* init and open DB connection for provisioning data */
	if (init_cc_db( &db_url )!=0) {
		LM_ERR("failed to initialize the DB support\n");
		return -1;
	}
	/* init DB connection (no connect) for ACC/CDR data */
	if (init_cc_acc_db( &acc_db_url )!=0) {
		LM_ERR("failed to initialize the acc DB support\n");
		return -1;
	}
	/* init and open DB connection for runtime data */
	if (init_cc_rt_db( &rt_db_url )!=0) {
		LM_ERR("failed to initialize the realtime DB support\n");
		return -1;
	}

	/* load data */
	if ( cc_load_db_data( data )!=0 ) {
		LM_CRIT("failed to load callcenter data\n");
		return -1;
	}
	clean_cc_old_data(data);

	/* restore calls */
	if ( cc_db_restore_calls( data )!=0 ) {
		LM_CRIT("failed to load callcenter data\n");
		return -1;
	}

	/* close DB connections here, to reopen in the worker processes */
	cc_close_db();
	cc_close_rt_db();

	return 0;
}


static int child_init( int rank )
{
	/* init DB connection */
	if ( rank<1 )
		return 0;
	if ( cc_connect_db(&db_url)!=0 ) {
		LM_CRIT("cannot initialize database connection\n");
		return -1;
	}
	if ( cc_connect_acc_db(&acc_db_url)!=0 ) {
		LM_CRIT("cannot initialize acc database connection\n");
		return -1;
	}
	if ( cc_connect_rt_db(&rt_db_url)!=0 ) {
		LM_CRIT("cannot initialize rt database connection\n");
		return -1;
	}
	return 0;
}


static int mi_child_init( void )
{
	/* init DB connection */
	if ( cc_connect_db(&db_url)!=0 ) {
		LM_CRIT("cannot initialize database connection\n");
		return -1;
	}
	if ( cc_connect_acc_db(&acc_db_url)!=0 ) {
		LM_CRIT("cannot initialize acc database connection\n");
		return -1;
	}
	if ( cc_connect_rt_db(&rt_db_url)!=0 ) {
		LM_CRIT("cannot initialize rt database connection\n");
		return -1;
	}
	return 0;
}


static void mod_destroy(void)
{
	/* destroy data */
	free_cc_data( data );
}


static inline void update_awt( unsigned int duration )
{
	data->avt_waittime_no ++;
	data->avt_waittime = 
		( ((float)duration + (data->avt_waittime * (float)(data->avt_waittime_no-1))) ) /
		(float)data->avt_waittime_no;
}


static inline int get_wrapup_time(struct cc_agent *ag, struct cc_flow *fl)
{
	int x;

	x = (ag && ag->wrapup_time!=0) ? ag->wrapup_time : wrapup_time;
	if (fl && fl->max_wrapup && fl->max_wrapup<x)
		return fl->max_wrapup;
	return x;
}


static void terminate_call(struct cc_call *call, b2bl_dlg_stat_t* stat,
		call_state prev_state)
{
	str un, fid, aid;
	int type;

	if(prev_state == CC_CALL_ENDED) {
		LM_CRIT("BUG - terminate state \n");
		return;
	}
	
	LM_DBG("terminating call %p (stat=%p)\n",call,stat);

	lock_get( data->lock );

	prepare_cdr( call, &un, &fid , &aid);

	if (prev_state==CC_CALL_TOAGENT || prev_state==CC_CALL_PRE_TOAGENT) {
		/* free the agent */
		if (stat && stat->call_time && prev_state==CC_CALL_TOAGENT) {
			if (call->media==CC_MEDIA_RTP) {
				call->agent->state = CC_AGENT_WRAPUP;
				call->agent->wrapup_end_time = get_ticks()
					+ get_wrapup_time(call->agent, call->flow);
			} else /*MSRP*/ {
				call->agent->state = CC_AGENT_INCHAT ;
				call->agent->wrapup_end_time =
					( (call->agent->wrapup_end_time<get_ticks()) ?
						get_ticks():call->agent->wrapup_end_time )
					+ get_wrapup_time(call->agent, call->flow);
			}
			call->flow->processed_calls ++;
			call->flow->avg_call_duration =
				( ((float)stat->call_time + 
				((float)call->flow->avg_call_duration *
				(call->flow->processed_calls-1)) ) ) /
				call->flow->processed_calls ;
			/* update awt for established calls */
			update_awt( stat->start_time - call->recv_time );
			update_cc_flow_awt(call->flow, stat->start_time - call->recv_time);
			update_cc_agent_att(call->agent, stat->call_time);
		} else {
			call->agent->state = (call->media==CC_MEDIA_RTP) ?
				CC_AGENT_FREE :
				( (call->agent->ongoing_sessions[CC_MEDIA_MSRP]==1) ?
					CC_AGENT_FREE : CC_AGENT_INCHAT) ;
			/* update awt for failed calls */
			update_awt( get_ticks() - call->recv_time );
			update_cc_flow_awt( call->flow, get_ticks() - call->recv_time );
		}
		/* update end time for agent's wrapup */
		cc_db_update_agent_wrapup_end(call->agent);
		agent_raise_event( call->agent, NULL);
		call->agent->ongoing_sessions[call->media]--;
		call->agent->ref_cnt--;
		call->agent = NULL;
	} else {
		/* update awt for failed calls */
		update_awt( get_ticks() - call->recv_time );
		update_cc_flow_awt( call->flow, get_ticks() - call->recv_time );
	}

	/* remove the call from queue (if there) */
	if ( is_call_in_queue(data, call) ) {
		cc_queue_rmv_call( data, call);
		call->ref_cnt--;
	}

	call->flow->ongoing_calls--;

	lock_release( data->lock );

	if (call->setup_time==-1)
		call->setup_time = stat ? stat->setup_time : 0;

	/* generate CDR */
	type = (stat==NULL) ? -1 : ((prev_state==CC_CALL_TOAGENT && stat->call_time)? 0 : 1);
	cc_write_cdr( &un, &fid, &aid, type, call->recv_time,
		((type==0)? stat->start_time : get_ticks()) - call->recv_time ,
		(type==0)?stat->call_time:0 , call->setup_time, call->no_rejections,
		call->fst_flags, call->id, call->media);

	cc_db_delete_call(call);
}


int set_call_leg( struct sip_msg *msg, struct cc_call *call, str *new_leg);

#define MAX_OUT_BUF_LEN 1024
static char out_buf[MAX_OUT_BUF_LEN];
#define OUT_BUF_LEN(_a)  (_a<MAX_OUT_BUF_LEN?_a:MAX_OUT_BUF_LEN)

void handle_agent_reject(struct cc_call* call, int from_customer, int pickup_time)
{
	str un, fid, aid;
	str out;

	//update_stat( stg_aban_incalls, 1); /*abandon from agent */
	update_stat( call->agent->st_aban_incalls, 1);
	call->no_rejections++;

	/* put call back into queue */ 
	call->state = CC_CALL_QUEUED;
	call->setup_time = -1;

	lock_get( data->lock );

	/* prepare CDR */
	prepare_cdr( call, &un, &fid , &aid);

	if (call->media==CC_MEDIA_RTP) {
		call->agent->state = CC_AGENT_WRAPUP;
		call->agent->wrapup_end_time = get_ticks()
			+ get_wrapup_time(call->agent, call->flow);
	} else /*MSRP*/ {
		call->agent->state = CC_AGENT_INCHAT ;
		call->agent->wrapup_end_time =
			( (call->agent->wrapup_end_time<get_ticks()) ?
				get_ticks():call->agent->wrapup_end_time )
			+ get_wrapup_time(call->agent, call->flow);
	}

	/* update end time for agent's wrapup */
	cc_db_update_agent_wrapup_end(call->agent);
	agent_raise_event( call->agent, NULL);
	call->agent->ongoing_sessions[call->media]--;
	call->agent->ref_cnt--;
	call->agent = NULL;

	cc_queue_push_call( data, call, 1/*top*/);

	if(from_customer || call->prev_state != CC_CALL_QUEUED) {
		out.len = OUT_BUF_LEN(call->flow->recordings[AUDIO_QUEUE].len);
		out.s = out_buf;
		memcpy( out.s, call->flow->recordings[AUDIO_QUEUE].s, out.len);
	}

	lock_release( data->lock );

	cc_call_state = call->state;
	if(from_customer || call->prev_state != CC_CALL_QUEUED) {
		/* send call to queue */
		if (set_call_leg( NULL, call, &out)< 0 ) {
			LM_ERR("failed to set new destination for call\n");
		}
		LM_DBG("onhold++: agent rejected [%p]\n", call);
		if(from_customer)
		{
			update_stat( stg_onhold_calls, 1);
			update_stat( call->flow->st_onhold_calls, 1);
			if (call->media==CC_MEDIA_MSRP) {
				update_stat( stg_onhold_chats, 1);
				update_stat( call->flow->st_onhold_chats, 1);
			}
		}
	}
	cc_call_state = CC_CALL_NONE;
	/* write CDR */
	cc_write_cdr( &un, &fid, &aid, -2, call->recv_time,
		get_ticks() - call->recv_time, 0 , pickup_time, call->no_rejections-1,
		call->fst_flags, call->id, call->media);
	cc_db_update_call(call);
}

int b2bl_callback_agent(b2bl_cb_params_t *params, unsigned int event)
{
	struct cc_call *call = (struct cc_call*)params->param;
	int cnt;
	b2bl_dlg_stat_t* stat = params->stat;

	LM_DBG(" call (%p) has BYE for event %d, \n", call, event);

	lock_set_get( data->call_locks, call->lock_idx );
	
	if (event == B2B_DESTROY_CB) {
		LM_DBG("A delete in b2blogic, call->state=%d, %p\n", call->state, call);
		cnt = --call->ref_cnt;
		lock_set_release( data->call_locks, call->lock_idx );
		if (cnt==0)
			free_cc_call( data, call);
		return 0;
	}

	if(call->ign_cback) {
		lock_set_release( data->call_locks, call->lock_idx );
		return 2;
	}
	
	if (event == B2B_BYE_CB && params->entity == 0) {
		/* BYE from agent */
		if (call->state==CC_CALL_PRE_TOAGENT) {
			handle_agent_reject(call, 0, stat->setup_time);
		}
		lock_set_release( data->call_locks, call->lock_idx );
		/* route the BYE according to scenario */
		return 1;
	}

	/*
	 * if negative reply from agent - deny call
	 */
	if(event == B2B_REJECT_CB && params->entity == 0) {
		if(call->state == CC_CALL_PRE_TOAGENT) {
			handle_agent_reject(call, 0, 0);
		}
		lock_set_release( data->call_locks, call->lock_idx );
		return 1;
	}

	/* right-side leg of call sent BYE -> get next state */

	if(call->state != CC_CALL_PRE_TOAGENT) {
		LM_CRIT("State not PRE_TOAGENT\n");
	}

	call->state = CC_CALL_TOAGENT;

	if (stat) call->setup_time = stat->setup_time;

	/* call no longer on wait */
	LM_DBG("** onhold-- Bridging [%p]\n", call);
	update_stat( stg_onhold_calls, -1);
	update_stat( call->flow->st_onhold_calls, -1);
	if (call->media==CC_MEDIA_MSRP) {
		update_stat( stg_onhold_chats, -1);
		update_stat( call->flow->st_onhold_chats, -1);
	}

	LM_DBG("Bridge two calls [%p] - [%p]\n", call, call->agent);
	cc_call_state = call->state;
	cnt = --call->ref_cnt;
	if(b2b_api.bridge_2calls(&call->b2bua_id, &call->b2bua_agent_id) < 0)
	{
		LM_ERR("Failed to bridge the agent with the customer\n");
		lock_set_release( data->call_locks, call->lock_idx );
		b2b_api.terminate_call(&call->b2bua_id);
		cc_call_state = CC_CALL_NONE;
		return -1;
	}
	cc_call_state = CC_CALL_NONE;
	/* if the agent was connected to the costumer */	
	lock_set_release( data->call_locks, call->lock_idx );
	
	return 0;
}

int b2bl_callback_customer(b2bl_cb_params_t *params, unsigned int event)
{
	struct cc_call *call = (struct cc_call*)params->param;
	str leg = {NULL,0};
	call_state cs;
	int cnt;
	b2bl_dlg_stat_t* stat = params->stat;

	LM_DBG(" call (%p) has event %d, \n", call, event);

	lock_set_get( data->call_locks, call->lock_idx );
	cs = call->state;
	cc_call_state = call->state;

	if (event==B2B_DESTROY_CB) {
		LM_DBG("A delete in b2blogic, call->state=%d, %p\n", call->state, call);
		call->state = CC_CALL_ENDED;
		lock_set_release( data->call_locks, call->lock_idx );
		if( cs != CC_CALL_ENDED) {
			/* call terminated due to some error -> cleanup here */
			terminate_call( call, NULL, cs);
			if (cs < CC_CALL_TOAGENT) {
				LM_DBG("** onhold-- Destroy [%p]\n", call);
				update_stat( stg_onhold_calls, -1);
				update_stat( call->flow->st_onhold_calls, -1);
				if (call->media==CC_MEDIA_MSRP) {
					update_stat( stg_onhold_chats, -1);
					update_stat( call->flow->st_onhold_chats, -1);
				}
			}
			if (cs == CC_CALL_TOAGENT) {
				/* call no longer on wait */
				//update_stat( stg_aban_incalls, 1); /*abandon from agent */
				//update_stat( call->agent->st_aban_incalls, 1);
			}
		}
		lock_set_get( data->call_locks, call->lock_idx );
		cnt = --call->ref_cnt;
		lock_set_release( data->call_locks, call->lock_idx );
		if (cnt==0)
			free_cc_call( data, call);
		else
			LM_DBG("!!! Call ref not 0 - do not delete %p\n", call);
		cc_call_state = CC_CALL_NONE;
		return 0;
	}

	if(call->ign_cback) {
		lock_set_release( data->call_locks, call->lock_idx );
		cc_call_state = CC_CALL_NONE;
		return 2;
	}

	if ( event==B2B_BYE_CB ) {
		if (cs==CC_CALL_TOAGENT && stat->call_time) {
			/* an established call was terminated */
			update_stat( stg_answ_incalls, 1);
			update_stat( call->flow->st_answ_incalls, 1);
			call->fst_flags |= FSTAT_ANSW;
			update_stat( call->agent->st_answ_incalls, 1);
			if (call->media==CC_MEDIA_MSRP) {
				update_stat( stg_answ_inchats, 1);
				update_stat( call->flow->st_answ_inchats, 1);
				update_stat( call->agent->st_answ_inchats, 1);
			}
		}
	}
	
	if (event==B2B_BYE_CB && params->entity==0) {
		LM_DBG("BYE from the customer\n");
		if(call->state==CC_CALL_PRE_TOAGENT) {
			/* terminate the call to the agent */
			b2b_api.terminate_call(&call->b2bua_agent_id);
		}
		/* external caller terminated the call */
		call->state = CC_CALL_ENDED;
		cc_call_state = CC_CALL_ENDED;
		lock_set_release( data->call_locks, call->lock_idx );
		if (cs<CC_CALL_TOAGENT) {
			/* call terminated while onwait */
			LM_DBG("** onhold-- BYE from customer [%p]\n", call);
			update_stat( stg_onhold_calls, -1);
			update_stat( call->flow->st_onhold_calls, -1);
			if (call->media==CC_MEDIA_MSRP) {
				update_stat( stg_onhold_chats, -1);
				update_stat( call->flow->st_onhold_chats, -1);
			}
		}
		/* Abandon: client was not sent to agent yet, or call still ringing
		 * on agent side
		 */
		if (cs<CC_CALL_TOAGENT || stat->call_time==0) {
 			/*abandon from customer */
			update_stat( stg_aban_incalls, 1);
			update_stat( call->flow->st_aban_incalls, 1);
			call->fst_flags |= FSTAT_ABAN;
		}
		terminate_call(call, stat, cs);

		/* route the BYE according to scenario */
		cc_call_state = CC_CALL_NONE;
		return 2;
	}
	/* if reInvite to the customer failed - end the call */
	if(event == B2B_REJECT_CB && params->entity==0) {
		lock_set_release( data->call_locks, call->lock_idx );
		cc_call_state = CC_CALL_NONE;
		return 1;
	}

	if(event == B2B_REJECT_CB && params->entity>0) {
		if(call->state == CC_CALL_TOAGENT) {
			handle_agent_reject(call, 1, stat->setup_time);
			lock_set_release( data->call_locks, call->lock_idx );
			cc_call_state = CC_CALL_NONE;
			return 0;
		}
		lock_set_release( data->call_locks, call->lock_idx );
		cc_call_state = CC_CALL_NONE;
		return 1;
	}

	/* we are not interested in B2B_RE_INVITE_CB and B2B_CONFIRMED_CB
	 * events, just in the BYEs from media/agent side */
	if (event!=B2B_BYE_CB) {
		lock_set_release( data->call_locks, call->lock_idx );
		cc_call_state = CC_CALL_NONE;
		return 0;
	}

	/* right-side leg of call sent BYE */
	if (stat->call_time==0 && call->state == CC_CALL_TOAGENT) {
		LM_INFO("*** AGENT answered and closed immediately %.*s\n",
			call->agent->media[call->media].location.len,
			call->agent->media[call->media].location.s);
		handle_agent_reject(call, 1, stat->setup_time);
		lock_set_release( data->call_locks, call->lock_idx );
		cc_call_state = CC_CALL_NONE;
		return 0;
	}

	/* get next state */
	lock_get( data->lock );

	cc_call_state = CC_CALL_NONE;
	if (cc_call_state_machine( data, call, &leg )!=0) {
		LM_ERR("failed to get next call destination \n");
		lock_release( data->lock );
		lock_set_release( data->call_locks, call->lock_idx );
		/* force BYE to be sent in both parts */
		return -1;
	}
	cc_call_state = call->state;

	lock_release( data->lock );

	LM_DBG("new destination for call(%p) is %.*s (state=%d)\n",
		call, leg.len, leg.s, call->state);

	if (call->state == CC_CALL_ENDED) {
		lock_set_release( data->call_locks, call->lock_idx );
		terminate_call( call, stat, cs);
		cc_call_state = CC_CALL_NONE;
		return 2;
	} else if (call->state == CC_CALL_TOAGENT) {
		/* call no longer on wait */
		LM_DBG("** onhold-- Direct to agent [%p]\n", call);
		update_stat( stg_onhold_calls, -1);
		update_stat( call->flow->st_onhold_calls, -1);
		if (call->media==CC_MEDIA_MSRP) {
			update_stat( stg_onhold_chats, -1);
			update_stat( call->flow->st_onhold_chats, -1);
		}
	}

	/* send call to selected destination */
	if (set_call_leg( NULL, call, &leg)< 0) {
		LM_ERR("failed to set new destination for call\n");
		lock_set_release( data->call_locks, call->lock_idx );
		pkg_free(leg.s);
		cc_call_state = CC_CALL_NONE;
		return -1;
	}
	cc_call_state = CC_CALL_NONE;
	lock_set_release( data->call_locks, call->lock_idx );

	if(cc_db_update_call(call) < 0)
	{
		LM_ERR("Failed to update call in database\n");
	}

	pkg_free(leg.s);
	return 0;
}


int set_call_leg( struct sip_msg *msg, struct cc_call *call, str *new_leg)
{
	str* id;
	b2bl_init_params_t b2b_params;
	str proxy = {0,0};

	LM_DBG("call %p moving to %.*s , state %d\n", call,
		new_leg->len, new_leg->s, call->state);

	if(call->state==CC_CALL_PRE_TOAGENT) {
		call->ref_cnt++;

		memset(&b2b_params, 0, sizeof b2b_params);
		b2b_params.e1_type = B2B_CLIENT;
		b2b_params.e1_to = call->agent->media[call->media].location;
		b2b_params.e1_from_dname = call->caller_dn;
		b2b_params.e2_type = B2B_CLIENT;
		b2b_params.e2_to = *new_leg;

		id = b2b_api.init(NULL, &b2b_scenario_agent, &b2b_params, b2bl_callback_agent,
				(void*)call, B2B_DESTROY_CB|B2B_REJECT_CB|B2B_BYE_CB, NULL);

		if (id==NULL || id->len==0 || id->s==NULL) {
			LM_ERR("failed to connect agent to media server "
					"(empty ID received)\n");
			return -2;
		}
		call->b2bua_agent_id.len = id->len;
		call->b2bua_agent_id.s = (char*)shm_malloc(id->len);
		if(call->b2bua_agent_id.s == NULL) {
			LM_ERR("No more memory\n");
			return -2;
		}
		memcpy(call->b2bua_agent_id.s, id->s, id->len);
	}
	else if (call->b2bua_id.len==0) {
		/* b2b instance not initialized yet =>
		 * create new b2bua instance */
		call->ref_cnt++;

		memset(&b2b_params, 0, sizeof b2b_params);
		b2b_params.e1_type = B2B_SERVER;
		b2b_params.e2_type = B2B_CLIENT;
		b2b_params.e2_to = *new_leg;

		id = b2b_api.init(msg, &b2b_scenario, &b2b_params, b2bl_callback_customer,
				(void*)call, B2B_DESTROY_CB|B2B_REJECT_CB|B2B_BYE_CB, NULL /* custom_hdrs */ );
		if (id==NULL || id->len==0 || id->s==NULL) {
			LM_ERR("failed to init new b2bua call (empty ID received)\n");
			return -2;
		}
		
		call->b2bua_id.s = (char*)shm_malloc(id->len);
		if (call->b2bua_id.s==NULL) {
			LM_ERR("failed to allocate b2bua ID\n");
			return -1;
		}
		memcpy( call->b2bua_id.s, id->s, id->len);
		/* this must be the last, as we use it as marker for checking
         * if b2b entity is initialized */
		call->b2bua_id.len = id->len;
	} else {
		/* call already ongoing */
		if(b2b_api.bridge( &call->b2bua_id, new_leg, &proxy,
			&call->caller_dn, 0) < 0) {
			LM_ERR("bridging failed\n");
			b2b_api.terminate_call(&call->b2bua_id);
			return -1;
		}
	}
	/* remember last time when the call started */
	call->last_start = get_ticks();
	//b2b_api.set_state(&call->b2bua_id, call->state);
	return 0;
}


static inline str* build_displayname(str *prefix, struct to_body *fh)
{
	static char buf[65];
	static str dn;
	unsigned int l=64;
	unsigned int n;
	char *p;
	str *s;

	dn.s = p = buf;

	*(p++) = '"';
	l --;

	n = prefix->len;
	if (n>=l) n = l;
	
	memcpy( p, prefix->s , n);
	p += n;
	l -= n;

	if (l<=0)
		goto done;

	*(p++) = ' ';
	l --;

	if (l<=0)
		goto done;

	if (fh->display.len) {
		s = &fh->display;
		if(s->s[0]=='"') {
			s->s++;
			s->len-=2;
		}
	}
	else
		s = &fh->parsed_uri.user;

	n = s->len;
	if (n>l) n = l;
	memcpy( p, s->s , n);
	p += n;
	l -= n;

done:
	*(p++) = '"';
	dn.len = p-buf;
	return &dn;
}


static int w_handle_call(struct sip_msg *msg, str *flow_name, str *param,
		str *media_s)
{
	struct cc_flow *flow;
	struct cc_call *call;
	str leg = {NULL,0};
	str *dn;
	int dec;
	unsigned int media;
	int ret = -1;

	call = NULL;
	dec = 0;

	/* parse FROM URI */
	if (parse_from_uri(msg)==NULL) {
		LM_ERR("failed to parse from hdr\n");
		return -2;
	}

	lock_get( data->lock );

	/* get the flow ID */
	flow = get_flow_by_name(data, flow_name);
	if (flow==NULL) {
		LM_ERR("flow <%.*s> does not exists\n", flow_name->len, flow_name->s);
		ret = -3;
		goto error;
	}
	LM_DBG("using call flow %p\n", flow);

	if (flow->logged_agents==0 /* no logged agents */
	&& reject_on_no_agents /*reject calls if no agents logged*/) {
		LM_NOTICE("flow <%.*s> closed\n",flow->id.len,flow->id.s);
		ret = -4;
		goto error;
	}

	update_stat(stg_incalls, 1);
	update_stat(flow->st_incalls, 1);

	if (flow->cid.len) {
		dn = build_displayname(&flow->cid, get_from(msg));
	} else if (get_from(msg)->display.len) {
		dn = &get_from(msg)->display;
	} else {
		dn = &get_from(msg)->parsed_uri.user;
	}
	LM_DBG("cid=<%.*s>\n",dn->len,dn->s);

	/* detect the media type */
	if (media_s==NULL || media_s->s==NULL || media_s->len==0) {
		struct sdp_info *sdp;
		if ( (sdp=parse_sdp(msg))==NULL ) {
			LM_ERR("failed to parse the SDP body\n");
			ret = -6;
			goto error;
		}
		/* TODO - right now we look only at the first session / stream */
		if (sdp->sessions==NULL || sdp->sessions->streams==NULL) {
			LM_ERR("no session/stream in the SDP\n");
			ret = -6;
			goto error;
		}
		media_s = &sdp->sessions->streams->transport;
	}
	str _rtp = str_init("RTP");
	str _msrp = str_init("MSRP");
	if (str_strstr( media_s, &_rtp))
		media = CC_MEDIA_RTP;
	else
	if (str_strstr( media_s, &_msrp))
		media = CC_MEDIA_MSRP;
	else {
		LM_ERR("media [%.*s] is neither RTP, nor MSRP\n",
			media_s->len, media_s->s);
		ret = -7;
		goto error;
	}

	call = new_cc_call(data, flow, dn, &get_from(msg)->parsed_uri.user, param);
	if (call==NULL) {
		LM_ERR("failed to create new call\n");
		ret = -5;
		goto error;
	}
	call->fst_flags |= FSTAT_INCALL;
	call->media = media;

	/* get estimated wait time */
	if (flow->logged_agents)
		call->eta = (unsigned int) (( flow->avg_call_duration *
			(float)get_stat_val(flow->st_queued_calls) ) /
			(float)flow->logged_agents);
	else
		call->eta = INT_MAX;

	LM_DBG("avg_call_duration=%.2f queued_calls=%lu loggedin_agents=%u\n",
		flow->avg_call_duration, get_stat_val(flow->st_queued_calls),
		flow->logged_agents);

	LM_DBG("ETA for new call(%p) is %d\n", call, call->eta);

	/* one more call to process */
	flow->ongoing_calls++;

	/* there is no need to lock the call here as it is not 
	 * yet sharead at all - just we have a ref to it */
	
	/* get the first state */
	if (cc_call_state_machine( data, call, &leg )!=0) {
		LM_ERR("failed to get first call destination \n");
		ret = -5;
		goto error;
	}
	cc_call_state = call->state;

	lock_release( data->lock );
	LM_DBG("new destination for call(%p) is %.*s (state=%d)\n",
		call, leg.len, leg.s, call->state);

	/* call still waits for agent ? */
	if (call->state!=CC_CALL_TOAGENT) {
		LM_DBG("** onhold++ Not to agent [%p]\n", call);
		update_stat( stg_onhold_calls, +1);
		update_stat( flow->st_onhold_calls, +1);
		if (call->media==CC_MEDIA_MSRP) {
			update_stat( stg_onhold_chats, +1);
			update_stat( flow->st_onhold_chats, +1);
		}
		dec = 1;
	}

	/* send call to selected destination */
	if (set_call_leg( msg, call, &leg)< 0 ) {
		LM_ERR("failed to set new destination for call\n");
		if (dec) { 
			LM_DBG("** onhold-- Error [%p]\n", call);
			update_stat( stg_onhold_calls, -1);
			update_stat( flow->st_onhold_calls, -1);
			if (call->media==CC_MEDIA_MSRP) {
				update_stat( stg_onhold_chats, -1);
				update_stat( call->flow->st_onhold_chats, -1);
			}
		}
		pkg_free(leg.s);
		goto error1;
	}

	pkg_free(leg.s);

	if(cc_db_insert_call(call) < 0) {
		LM_ERR("Failed to insert call record in db\n");
	}

	cc_call_state = CC_CALL_NONE;
	return 1;
error:
	lock_release( data->lock );
error1:
	if (call) {
		if (call->state==CC_CALL_QUEUED)
				cc_queue_rmv_call( data, call);
		free_cc_call( data, call);
		flow->ongoing_calls--;
	}
	cc_call_state = CC_CALL_NONE;
	return ret;
}


static int w_agent_login(struct sip_msg *req, str *agent_s, int *state)
{
	struct cc_agent *agent, *prev_agent;

	/* block access to data */
	lock_get( data->lock );

	/* name of the agent */
	agent = get_agent_by_name( data, agent_s, &prev_agent);
	if (agent==NULL) {
		lock_release( data->lock );
		LM_DBG("agent <%.*s> not found\n",agent_s->len,agent_s->s);
		return -3;
	}

	if (agent->logged_in != *state) {

		if(*state) {
			if ( agent->state==CC_AGENT_WRAPUP &&
			get_ticks() > agent->wrapup_end_time )
				agent->state = CC_AGENT_FREE;

			if ( agent->state==CC_AGENT_INCHAT &&
			get_ticks() > agent->wrapup_end_time &&
			agent->ongoing_sessions[CC_MEDIA_MSRP]==0 )
				agent->state = CC_AGENT_FREE;

			if(data->agents[CC_AG_ONLINE] == NULL)
				data->last_online_agent = agent;
		}

		/* agent event is triggered here */
		agent_switch_login(data, agent, prev_agent);

		if(*state) {
			data->loggedin_agents++;
			log_agent_to_flows( data, agent, 1);
		} else {
			data->loggedin_agents--;
			log_agent_to_flows(data, agent, 0);
		}
	}

	/* release access to data */
	lock_release( data->lock );

	return 1;
}


static void cc_timer_agents(unsigned int ticks, void* param)
{
	struct cc_agent *agent, *prev_agent;
	struct cc_call  *call;
	str out;
	str dest;

	if (data==NULL || data->agents[CC_AG_ONLINE]==NULL)
		return;


	lock_get( data->lock );

	/* iterate all agents to get update state and evaluate their
	 * availability */
	agent = data->agents[CC_AG_ONLINE];
	prev_agent = data->agents[CC_AG_ONLINE];

	do {

		//LM_DBG("%.*s , state=%d, wrapup_end_time=%u, ticks=%u, "
		//		"wrapup=%u\n", agent->id.len, agent->id.s, agent->state,
		//		agent->wrapup_end_time, ticks, wrapup_time);
		/* for agents in WRAPUP time, check if expired */
		if (
		(agent->state==CC_AGENT_WRAPUP && ticks>agent->wrapup_end_time)
		  ||
		(agent->state==CC_AGENT_INCHAT && ticks>agent->wrapup_end_time
			&& agent->ongoing_sessions[CC_MEDIA_MSRP]==0)
		) {
			agent->state = CC_AGENT_FREE;
			agent_raise_event( agent, NULL);
			/* move it to the end of the list*/
			move_cc_agent_to_end( data, agent, prev_agent);
			/* re-iterate */
			agent = prev_agent;
		}

		/* next agent */
		prev_agent = agent;
		agent = agent->next;
	}while(agent);


	if (*internal_call_dispatching==0) {
		lock_release( data->lock );
		return;
	}


	/* assign calls/chats to the agents */
	do {

		/* iterate and find one call/chat for each agent */
		agent = data->agents[CC_AG_ONLINE];
		prev_agent =  data->agents[CC_AG_ONLINE];
		call = NULL;

		do {

			if (data->queue.calls_no==0)
				break;

			/* for free agents -> check for calls */
			if (agent->state==CC_AGENT_FREE &&
			agent->media[CC_MEDIA_RTP].sessions/*0 or 1 here*/) {
				call = cc_queue_pop_call_for_agent( data, agent, CC_MEDIA_RTP);
				if (call) {
					/* found a call for the agent */
					break;
				}
			}

			/* can the agent take chats? */
			if ( can_agent_take_chats(agent) ){
				call = cc_queue_pop_call_for_agent( data, agent,CC_MEDIA_MSRP);
				if (call) {
					if (msrp_dispatch_policy == CC_MSRP_POLICY_LB)
						move_cc_agent_to_end( data, agent, prev_agent);
					/* found a chat for the agent */
					break;
				}
			}

			/* next agent */
			prev_agent = agent;
			agent = agent->next;

		}while(agent);

		lock_release( data->lock );

		/* no locking here */

		if (call) {

			lock_set_get( data->call_locks, call->lock_idx );
			call->ref_cnt--;

			/* is the call state still valid? (as queued) */
			if(call->state != CC_CALL_QUEUED) {
				if (call->state==CC_CALL_ENDED && call->ref_cnt==0) {
					lock_set_release( data->call_locks, call->lock_idx );
					free_cc_call( data, call);
				} else {
					lock_set_release( data->call_locks, call->lock_idx );
				}
				continue;
			}
			LM_DBG("Call %p ref= %d, state= %d\n", call,
					call->ref_cnt, call->state);

			lock_get( data->lock );

			if(!call->flow->recordings[AUDIO_FLOW_ID].len)
				dest = agent->media[call->media].location;
			else
				dest = call->flow->recordings[AUDIO_FLOW_ID];

			/* make a copy for destination to agent */
			out.len = OUT_BUF_LEN(dest.len);
			out.s = out_buf;
			memcpy( out.s, dest.s, out.len);
			
			call->prev_state = call->state;
			if(!call->flow->recordings[AUDIO_FLOW_ID].len) {
				call->state = CC_CALL_TOAGENT;
				/* call no longer on wait */
				LM_DBG("** onhold-- Took out of the queue [%p]\n", call);
				update_stat( stg_onhold_calls, -1);
				update_stat( call->flow->st_onhold_calls, -1);
				if (call->media==CC_MEDIA_MSRP) {
					update_stat( stg_onhold_chats, -1);
					update_stat( call->flow->st_onhold_chats, -1);
				}
			}else{
				call->state = CC_CALL_PRE_TOAGENT;
			}

			/* mark agent as used */
			agent->state = (call->media==CC_MEDIA_RTP) ?
				CC_AGENT_INCALL : CC_AGENT_INCHAT;
			call->agent = agent;
			call->agent->ref_cnt++;
			agent->ongoing_sessions[call->media]++;
			agent_raise_event( agent, call);
			update_stat( stg_dist_incalls, 1);
			update_stat( call->flow->st_dist_incalls, 1);
			call->fst_flags |= FSTAT_DIST;
			update_stat( call->agent->st_dist_incalls, +1);

			/* unlock data */
			lock_release( data->lock );

			/* send call to selected agent */
			cc_call_state = call->state;
			if (set_call_leg( NULL, call, &out)< 0 ) {
				LM_ERR("failed to set new destination for call\n");
			}
			cc_call_state = CC_CALL_NONE;
			lock_set_release( data->call_locks, call->lock_idx );

			if(cc_db_update_call(call) < 0)
			{
				LM_ERR("Failed to update call in database\n");
			}
		}

	} while (call);
}


static void cc_timer_calls(unsigned int ticks, void* param)
{
	struct cc_call  *call;
	str out;

	if (data==NULL || data->queue.calls_no==0)
		return;

	/* iterate all queued calls to check for how long they were waiting */

	do {

		call = NULL;
		lock_get( data->lock );

		for ( call=data->queue.first ; call ; call=call->lower_in_queue) {
			if (call->flow->diss_onhold_th &&
			(ticks - call->last_start > call->flow->diss_onhold_th) &&
			call->flow->recordings[AUDIO_DISSUADING].len ) {
				LM_DBG("call %p in queue for %d(%d) sec -> dissuading msg\n",
					call,ticks-call->last_start,call->flow->diss_onhold_th);
				/* remove from queue */
				cc_queue_rmv_call( data, call);
				break;
			}
		}

		lock_release( data->lock );

		/* no locking here */

		if (call) {

			lock_set_get( data->call_locks, call->lock_idx );
			call->ref_cnt--;

			/* is the call state still valid? (as queued) */
			if(call->state != CC_CALL_QUEUED) {
				if (call->state==CC_CALL_ENDED && call->ref_cnt==0) {
					lock_set_release( data->call_locks, call->lock_idx );
					free_cc_call( data, call);
				} else {
					lock_set_release( data->call_locks, call->lock_idx );
				}
				continue;
			}
			
			lock_get( data->lock );

			/* make a copy for destination to dissuading */
			out.len = OUT_BUF_LEN(call->flow->recordings[AUDIO_DISSUADING].len);
			if (out.len==0) {
				cc_queue_push_call( data, call, 1/*top*/);

				/* unlock data */
				lock_release( data->lock );
			} else {
				out.s = out_buf;
				memcpy( out.s, call->flow->recordings[AUDIO_DISSUADING].s,
					out.len);

				call->state = call->flow->diss_hangup ?
					CC_CALL_DISSUADING2 : CC_CALL_DISSUADING1;

				/* unlock data */
				lock_release( data->lock );

				cc_call_state = call->state;
				/* send call to selected destination */
				if (set_call_leg( NULL, call, &out)<-0 ) {
					LM_ERR("failed to set new destination for call\n");
				}
				cc_call_state = CC_CALL_NONE;
			}
			lock_set_release( data->call_locks, call->lock_idx );
		}

	} while(call);

	return;
}


static void cc_timer_cleanup(unsigned int ticks, void* param)
{
	if (data->old_flows==NULL && data->old_agents==NULL)
		return;

	/* block access to data */
	lock_get( data->lock );

	clean_cc_unref_data(data);
	
	/* done with data */
	lock_release( data->lock );
}


/******************** MI commands ***********************/

static mi_response_t *mi_cc_reload(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int ret;

	LM_INFO("\"cc_reload\" MI command received!\n");

	/* block access to data */
	lock_get( data->lock );

	/* do the update */
	ret = cc_load_db_data( data );
	if (ret<0) {
		LM_CRIT("failed to load CC data\n");
	}

	clean_cc_old_data(data);

	/* release the readers */
	lock_release( data->lock );

	if (ret==0)
		return init_mi_result_ok();
	else
		return init_mi_error(500, MI_SSTR("Failed to reload"));
}

static mi_response_t *mi_cc_list_flows(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct cc_flow *flow;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *flows_arr, *flow_item;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	flows_arr = add_mi_array(resp_obj, MI_SSTR("Flows"));
	if (!flows_arr) {
		free_mi_response(resp);
		return 0;
	}

	/* block access to data */
	lock_get( data->lock );

	for( flow=data->flows; flow ; flow=flow->next ) {
		flow_item = add_mi_object(flows_arr, NULL, 0);
		if (!flow_item)
			goto error;

		if (add_mi_string(flow_item, MI_SSTR("id"),
			flow->id.s, flow->id.len) < 0)
			goto error;

		if (add_mi_number(flow_item, MI_SSTR("Avg Call Duration"),
			flow->avg_call_duration) < 0)
			goto error;

		if (add_mi_number(flow_item, MI_SSTR("Processed Calls"),
			flow->processed_calls) < 0)
			goto error;

		if (add_mi_number(flow_item, MI_SSTR("Logged Agents"),
			flow->logged_agents) < 0)
			goto error;

		if (add_mi_number(flow_item, MI_SSTR("Ongoing Calls"),
			flow->ongoing_calls) < 0)
			goto error;

		if (add_mi_number(flow_item, MI_SSTR("Ref Calls"),
			flow->ref_cnt) < 0)
			goto error;
	}

	lock_release( data->lock );

	return resp;

error:
	lock_release( data->lock );
	free_mi_response(resp);
	return 0;
}

static mi_response_t *mi_cc_list_agents(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *agents_arr, *agent_item;
	struct cc_agent *agent;
	int i;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	agents_arr = add_mi_array(resp_obj, MI_SSTR("Agents"));
	if (!agents_arr) {
		free_mi_response(resp);
		return 0;
	}

	/* block access to data */
	lock_get( data->lock );

	for(i=0; i< 2; i++)
		for( agent=data->agents[i] ; agent ; agent=agent->next ) {
			agent_item = add_mi_object(agents_arr, NULL, 0);
			if (!agent_item)
				goto error;

			if (add_mi_string(agent_item, MI_SSTR("id"),
				agent->id.s, agent->id.len) < 0)
				goto error;

			if (add_mi_number(agent_item, MI_SSTR("Ref"),
				agent->ref_cnt) < 0)
				goto error;

			if(!agent->logged_in) {
				if (add_mi_string(agent_item, MI_SSTR("Loged in"),
					MI_SSTR("NO")) < 0)
					goto error;
			} else {
				if (add_mi_string(agent_item, MI_SSTR("Loged in"),
					MI_SSTR("YES")) < 0)
					goto error;

				switch ( agent->state ) {
				case CC_AGENT_FREE:
					if (add_mi_string(agent_item, MI_SSTR("State"),
					MI_SSTR("free")) < 0)
						goto error;
					break;
				case CC_AGENT_WRAPUP:
					if (add_mi_string(agent_item, MI_SSTR("State"),
					MI_SSTR("wrapup")) < 0)
						goto error;
					if (add_mi_number(agent_item, MI_SSTR("Wrapup-ends"),
					agent->wrapup_end_time-get_ticks() ) < 0)
						goto error;
					break;
				case CC_AGENT_INCALL:
					if (add_mi_string(agent_item, MI_SSTR("State"),
					MI_SSTR("incall")) < 0)
						goto error;
					break;
				case CC_AGENT_INCHAT:
					if (add_mi_string(agent_item, MI_SSTR("State"),
					MI_SSTR("inchat")) < 0)
						goto error;
					if (add_mi_number(agent_item, MI_SSTR("Ongoing chats"),
					agent->ongoing_sessions[CC_MEDIA_MSRP]) < 0)
						goto error;
					if (add_mi_number(agent_item, MI_SSTR("Free chats"),
					agent->media[CC_MEDIA_MSRP].sessions -
					agent->ongoing_sessions[CC_MEDIA_MSRP]) < 0)
						goto error;
					if (agent->wrapup_end_time>get_ticks())
						if (add_mi_number(agent_item, MI_SSTR("Wrapup-ends"),
						agent->wrapup_end_time-get_ticks() ) < 0)
							goto error;
					break;
				default:
					if (add_mi_number(agent_item, MI_SSTR("State"),
					agent->state) < 0)
						goto error;
				}
			}
		}

	lock_release( data->lock );

	return resp;

error:
	lock_release( data->lock );
	free_mi_response(resp);
	return 0;
}

static mi_response_t *mi_cc_list_calls(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct cc_call *call;
	struct cc_agent *agent;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *calls_arr, *call_item;
	str *state;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	calls_arr = add_mi_array(resp_obj, MI_SSTR("Calls"));
	if (!calls_arr) {
		free_mi_response(resp);
		return 0;
	}

	/* block access to data */
	lock_get( data->lock );

	for( call=data->list.first ; call ; call=call->next_list ) {
		call_item = add_mi_object(calls_arr, NULL, 0);
		if (!call_item)
			goto error;

		if (add_mi_string(call_item, MI_SSTR("id"),
			call->b2bua_id.s, call->b2bua_id.len) < 0)
			goto error;

		if (add_mi_number(call_item, MI_SSTR("Ref"),
			call->ref_cnt) < 0)
			goto error;

		if(call->ign_cback) {
			if (add_mi_string(call_item, MI_SSTR("State"),
				MI_SSTR("ignored")) < 0)
				goto error;
		} else {
			state = call_state_str(call->state);
			if (add_mi_string(call_item, MI_SSTR("State"),
				state->s, state->len) < 0)
				goto error;
		}

		LM_DBG("call->recv_time= %d, ticks= %d\n", call->recv_time, get_ticks());
		if(call->state != CC_CALL_ENDED)
		{
			if (add_mi_number(call_item, MI_SSTR("Call Time"),
				(unsigned long)(call->recv_time?(get_ticks() - call->recv_time):0)) < 0)
				goto error;

			if(call->flow) {
				if (add_mi_string(call_item, MI_SSTR("Flow"),
					call->flow->id.s, call->flow->id.len) < 0)
					goto error;
			}
		}
		if(call->agent) {
				agent = call->agent;
				if (add_mi_string(call_item, MI_SSTR("Agent"),
					agent->id.s, agent->id.len) < 0)
					goto error;
		}

	}

	lock_release( data->lock );

	return resp;

error:
	lock_release( data->lock );
	free_mi_response(resp);
	return 0;
}


/* FORMAT :  agent_id  log_state */
static mi_response_t *mi_agent_login(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct cc_agent *agent;
	int logged_in;
	struct cc_agent* prev_agent= 0;
	str agent_id;

	if (get_mi_string_param(params, "agent_id", &agent_id.s, &agent_id.len) < 0)
		return init_mi_param_error();

	if (get_mi_int_param(params, "state", &logged_in) < 0)
		return init_mi_param_error();
	logged_in = logged_in ? 1 : 0;

	/* block access to data */
	lock_get( data->lock );

	/* name of the agent */
	agent = get_agent_by_name( data, &agent_id, &prev_agent);
	if (agent==NULL) {
		lock_release( data->lock );
		return init_mi_error( 404, MI_SSTR("Agent not found"));
	}

	if (agent->logged_in != logged_in) {

		if(logged_in && (agent->state==CC_AGENT_WRAPUP) &&
			(get_ticks() > agent->wrapup_end_time))
			agent->state = CC_AGENT_FREE;

		if(logged_in && data->agents[CC_AG_ONLINE] == NULL)
			data->last_online_agent = agent;

		/* agent event is triggered here */
		agent_switch_login(data, agent, prev_agent);

		if(logged_in) {
			data->loggedin_agents++;
			log_agent_to_flows( data, agent, 1);
		} else {
			data->loggedin_agents--;
			log_agent_to_flows(data, agent, 0);
		}
	}

	/* release the readers */
	lock_release( data->lock );

	return init_mi_result_ok();
}


static mi_response_t *mi_reset_stats(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct cc_flow *flow;
	struct cc_agent *agent;
	int i;

	/* reset global stats */
	reset_stat( stg_incalls) ;
	data->avt_waittime_no = 0;
	data->avt_waittime = 0;
	reset_stat( stg_dist_incalls );
	reset_stat( stg_answ_incalls );
	reset_stat( stg_answ_inchats );
	reset_stat( stg_aban_incalls );

	/* block access to data */
	lock_get( data->lock );

	/* reset flow stats */
	for ( flow = data->flows ; flow ; flow = flow->next ) {
		reset_stat( flow->st_incalls );
		reset_stat( flow->st_dist_incalls );
		reset_stat( flow->st_answ_incalls );
		reset_stat( flow->st_answ_inchats );
		reset_stat( flow->st_aban_incalls );
		flow->avg_call_duration = 0;
		flow->processed_calls = 0;
		flow->avg_waittime = 0;
		flow->avg_waittime_no = 0;
	}

	/* reset agent stats */
	for(i = 0; i< 2; i++) {
		for ( agent = data->agents[i] ; agent ; agent = agent->next ) {
			reset_stat( agent->st_dist_incalls );
			reset_stat( agent->st_answ_incalls );
			reset_stat( agent->st_answ_inchats );
			reset_stat( agent->st_aban_incalls );
			agent->avg_talktime = 0;
			agent->avg_talktime_no = 0;
		}
	}

	/* release the readers */
	lock_release( data->lock );

	return init_mi_result_ok();
}


static mi_response_t *mi_cc_list_queue(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *calls_arr, *call_item;
	struct cc_call *call;
	unsigned int n, now;
	str *s;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	calls_arr = add_mi_array(resp_obj, MI_SSTR("Calls"));
	if (!calls_arr) {
		free_mi_response(resp);
		return 0;
	}

	n = 0;
	now = get_ticks();

	/* block access to data */
	lock_get( data->lock );

	for ( call=data->queue.first ; call ; call=call->lower_in_queue, n++) {
		call_item = add_mi_object(calls_arr, NULL, 0);
		if (!call_item)
			goto error;

		if (add_mi_number(call_item, MI_SSTR("index"), n) < 0)
			goto error;

		if (add_mi_string(call_item, MI_SSTR("id"),
			call->b2bua_id.s, call->b2bua_id.len) < 0)
			goto error;

		if (call->media==CC_MEDIA_RTP) {
			if (add_mi_string(call_item, MI_SSTR("Media"), MI_SSTR("RTP"))<0)
				goto error;
		} else
		if (call->media==CC_MEDIA_MSRP) {
			if (add_mi_string(call_item, MI_SSTR("Media"), MI_SSTR("MSRP"))<0)
				goto error;
		} else {
			if (add_mi_string(call_item, MI_SSTR("Media"), MI_SSTR("--"))<0)
				goto error;
		}

		if (add_mi_string(call_item, MI_SSTR("Caller username"),
			call->caller_un.s, call->caller_un.len) < 0)
			goto error;

		if (add_mi_string(call_item, MI_SSTR("Caller display name"),
			call->caller_dn.s, call->caller_dn.len) < 0)
			goto error;

		if (add_mi_number(call_item, MI_SSTR("Waiting for"),
			now-call->last_start) < 0)
			goto error;

		if (add_mi_number(call_item, MI_SSTR("ETW"), call->eta) < 0)
			goto error;

		/* flow data */
		if (add_mi_string(call_item, MI_SSTR("Flow"),
			call->flow->id.s, call->flow->id.len) < 0)
			goto error;

		if (add_mi_number(call_item, MI_SSTR("Priority"), call->flow->priority) < 0)
			goto error;

		s = get_skill_by_id(data,call->flow->skill);
		if (s && add_mi_string(call_item, MI_SSTR("Skill"),
			s->s, s->len) < 0)
			goto error;
	}

	/* release the readers */
	lock_release( data->lock );

	return resp;
error:
	lock_release( data->lock );
	free_mi_response(resp);
	return NULL;
}


static int pv_get_cc_state( struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if (cc_call_state == CC_CALL_NONE)
		return pv_get_null( msg, param, res);

	res->rs = *call_state_str(cc_call_state);
	res->flags = PV_VAL_STR;
	return 0;
}


static mi_response_t *mi_internal_call_dispatching(const mi_params_t *params,
		struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	int dispatch_val;
	int ret;

	ret = try_get_mi_int_param(params, "dispatching", &dispatch_val);
	if (ret<0 && ret!=-1/*MI_PARAM_ERR_MISSING*/)
		return init_mi_param_error();

	if (ret==0) {
		/* set the value */
		*internal_call_dispatching = (dispatch_val==0)? 0 : 1;
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_number(resp_obj, MI_SSTR("dispatching"),
	*internal_call_dispatching ) < 0)
		return 0;

	return resp;
}


static mi_response_t *mi_dispatch_call_to_agent(const mi_params_t *params,
		struct mi_handler *async_hdl)
{
	struct cc_agent *agent, *prev_agent;
	struct cc_call *call;
	str agent_id, call_id;
	str dest, out;
	int i;

	if (*internal_call_dispatching!=0)
		return init_mi_error( 403, MI_SSTR("Internal dispatching is enabled"));

	if (get_mi_string_param(params, "call_id", &call_id.s, &call_id.len) < 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, "agent_id", &agent_id.s, &agent_id.len)<0)
		return init_mi_param_error();

	/* block access to data */
	lock_get( data->lock );

	/* get the agent */
	agent = get_agent_by_name( data, &agent_id, &prev_agent);
	if (agent==NULL) {
		lock_release( data->lock );
		return init_mi_error( 404, MI_SSTR("Agent not found"));
	}

	if (!agent->logged_in) {
		lock_release( data->lock );
		return init_mi_error( 404, MI_SSTR("Agent not logged in"));
	}
	LM_DBG("found logged-in agent %p(%.*s) in state %d\n",
		agent, agent->id.len, agent->id.s, agent->state);

	/* search for the call in the queue */
	for (call=data->queue.first ; call ; call=call->lower_in_queue) {
		/* match the call id */
		if ( call->b2bua_id.len && call->b2bua_id.len==call_id.len &&
		strncmp(call->b2bua_id.s, call_id.s, call_id.len)==0 )
			break;
	}
	if (call==NULL) {
		lock_release( data->lock );
		return init_mi_error( 404, MI_SSTR("Call not found"));
	}
	LM_DBG("found call %p(%.*s), media %d in state %d \n",
		call, call->b2bua_id.len, call->b2bua_id.s,
		call->media, call->state);

	/* check the compatibility of the call and agent */
	for(i=0 ; i<agent->no_skills ; i++) {
		if (call->flow->skill==agent->skills[i]) {
			LM_DBG("found matching skill %d\n",
				call->flow->skill);
			break;
		}
	}
	if(i==agent->no_skills) {
		lock_release( data->lock );
		return init_mi_error( 488, MI_SSTR("Agent has no skill for the call"));
	}
	/* check media and agent state */
	if (call->media==CC_MEDIA_RTP) {
		/* we need a FREE agent with calling */
		if (agent->state!=CC_AGENT_FREE ||
		agent->media[CC_MEDIA_RTP].sessions==0) {
			lock_release( data->lock );
			return init_mi_error( 488,
				MI_SSTR("Agent is not free/audio enabled"));
		}
	} else
	if (call->media==CC_MEDIA_MSRP) {
		/* we need an agent with available chatting */
		if ( !can_agent_take_chats(agent) ) {
			lock_release( data->lock );
			return init_mi_error( 488,
				MI_SSTR("Agent is not free/chat enabled"));
		}
	} else {
		lock_release( data->lock );
		return init_mi_error( 488,
			MI_SSTR("Unsupported media in call"));
	}

	/* we have the call and agent, fully compatible
	 * and with available sessions => marry them :) */

	/* remove the call from queue */
	cc_queue_rmv_call( data, call);
	lock_release( data->lock );


	/* no locking here */

	lock_set_get( data->call_locks, call->lock_idx );
	call->ref_cnt--;

	/* is the call state still valid? (as queued) */
	if(call->state != CC_CALL_QUEUED) {
		if (call->state==CC_CALL_ENDED && call->ref_cnt==0) {
			lock_set_release( data->call_locks, call->lock_idx );
			free_cc_call( data, call);
		} else {
			lock_set_release( data->call_locks, call->lock_idx );
		}
		return init_mi_error( 404, MI_SSTR("Call not in queue any more"));
	}
	LM_DBG("Call %p ref= %d, state= %d\n", call,
		call->ref_cnt, call->state);

	lock_get( data->lock );

	if(!call->flow->recordings[AUDIO_FLOW_ID].len)
		dest = agent->media[call->media].location;
	else
		dest = call->flow->recordings[AUDIO_FLOW_ID];

	/* make a copy for destination to agent */
	out.len = OUT_BUF_LEN(dest.len);
	out.s = out_buf;
	memcpy( out.s, dest.s, out.len);

	call->prev_state = call->state;
	if(!call->flow->recordings[AUDIO_FLOW_ID].len) {
		call->state = CC_CALL_TOAGENT;
		/* call no longer on wait */
		LM_DBG("** onhold-- Took out of the queue [%p]\n", call);
		update_stat( stg_onhold_calls, -1);
		update_stat( call->flow->st_onhold_calls, -1);
		if (call->media==CC_MEDIA_MSRP) {
			update_stat( stg_onhold_chats, -1);
			update_stat( call->flow->st_onhold_chats, -1);
		}
	}else{
		call->state = CC_CALL_PRE_TOAGENT;
	}

	/* mark agent as used */
	agent->state = call->media==CC_MEDIA_RTP ?
		CC_AGENT_INCALL : CC_AGENT_INCHAT;
	call->agent = agent;
	call->agent->ref_cnt++;
	agent->ongoing_sessions[call->media]++;
	agent_raise_event( agent, call);
	update_stat( stg_dist_incalls, 1);
	update_stat( call->flow->st_dist_incalls, 1);
	call->fst_flags |= FSTAT_DIST;
	update_stat( call->agent->st_dist_incalls, +1);

	/* unlock data */
	lock_release( data->lock );

	/* send call to selected agent */
	cc_call_state = call->state;
	if (set_call_leg( NULL, call, &out)< 0 ) {
		LM_ERR("failed to set new destination for call\n");
	}
	cc_call_state = CC_CALL_NONE;
	lock_set_release( data->call_locks, call->lock_idx );

	if(cc_db_update_call(call) < 0) {
		LM_ERR("Failed to update call in database\n");
	}

	return init_mi_result_ok();
}

