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


static int mod_init(void);
static void mod_destroy(void);
static int child_init( int rank );
static int mi_child_init();

static mi_response_t *mi_cc_reload(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_cc_load_flow(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_cc_load_agent(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_cc_reload_flow(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_cc_reload_agent(const mi_params_t *params,
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
static mi_response_t *mi_cc_get_agent(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_cc_get_flow(const mi_params_t *params,
								struct mi_handler *async_hdl);

static int w_handle_call(struct sip_msg *msg, str *flow_name, str *param);
static int w_agent_login(struct sip_msg *req, str *agent_s, int *state);

static void cc_timer_agents(unsigned int ticks, void* param);
static void cc_timer_calls(unsigned int ticks, void* param);
static void cc_timer_cleanup(unsigned int ticks, void* param);

unsigned long stg_awt(unsigned short foo);
unsigned long stg_load(unsigned short foo);
unsigned long stg_free_agents(unsigned short foo);

stat_var *stg_incalls = 0;
stat_var *stg_dist_incalls = 0;
stat_var *stg_answ_incalls = 0;
stat_var *stg_aban_incalls = 0;
stat_var *stg_onhold_calls = 0;

/* a default of 30 secs wrapup time for agents */
unsigned int wrapup_time = 30;

/* the name of the URI param to report the queue position */
str queue_pos_param = {NULL,0};
/* by default reject new calls if there are no agents logged */
static int reject_on_no_agents = 1;
/* by default load all flow and agent to memory on start */
static int dynamic_load = 0;

static cmd_export_t cmds[]={
	{"cc_handle_call", (cmd_function)w_handle_call,
		{{CMD_PARAM_STR, 0,0},
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
    { "dynamic_load",         INT_PARAM, &dynamic_load         },
	{ "queue_pos_param",      STR_PARAM, &queue_pos_param.s    },
	{ "cc_agents_table",      STR_PARAM, &cc_agent_table_name.s  },
	{ "cca_agentid_column",   STR_PARAM, &cca_agentid_column.s   },
	{ "cca_location_column",  STR_PARAM, &cca_location_column.s  },
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
    { "cc_skills_table",      STR_PARAM, &cc_skill_table_name.s  },
	{ "ccs_agentid_column",   STR_PARAM, &ccs_agentid_column.s   },
	{ "ccs_skill_column",     STR_PARAM, &ccs_skill_column.s  },
	{ 0,0,0 }
};

static mi_export_t mi_cmds[] = {
	{"cc_reload", 0, 0, mi_child_init, {
		{mi_cc_reload, {0}},
		{EMPTY_MI_RECIPE}}
	},
    {"cc_load_flow", 0, 0, 0, {
		{mi_cc_load_flow, {"flow_id", 0}},
		{EMPTY_MI_RECIPE}}
	},
    {"cc_load_agent", 0, 0, 0, {
		{mi_cc_load_agent, {"agent_id", 0}},
		{EMPTY_MI_RECIPE}}
	},
    {"cc_reload_flow", 0, 0, 0, {
		{mi_cc_reload_flow, {"flow_id", 0}},
		{EMPTY_MI_RECIPE}}
	},
    {"cc_reload_agent", 0, 0, 0, {
		{mi_cc_reload_agent, {"agent_id", 0}},
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
    {"cc_get_flow", 0, 0, 0, {
		{mi_cc_get_flow, {"flow_id", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{"cc_get_agent", 0, 0, 0, {
		{mi_cc_get_agent, {"agent_id", 0}},
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
	{"ccg_abandonned_incalls" , 0,             &stg_aban_incalls             },
	{"ccg_onhold_calls",        STAT_NO_RESET, &stg_onhold_calls             },
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
	0,               /* exported pseudo-variables */
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
    map_iterator_t it;
    void** it_val;

	lock_get( data->lock );

	if (data->logedin_agents==0) {
		lock_release( data->lock );
		return 0;
	}

	free_ag = 0;
    // iterate all agents
    for (map_first(data->agents, &it); iterator_is_valid(&it); iterator_next(&it)) {
        it_val = iterator_val(&it);
        
        if (!it_val) {
            continue;
        }
        
        agent = (struct cc_agent*)*it_val;
        
		if (agent->state==CC_AGENT_FREE) free_ag++;
	}

	load = 100*( get_stat_val(stg_onhold_calls) + data->logedin_agents - free_ag ) / data->logedin_agents;

	lock_release( data->lock );

	return load;
}


unsigned long stg_free_agents(unsigned short foo)
{
	struct cc_agent *agent;
	unsigned int free = 0;
    map_iterator_t it;
    void** it_val;

	lock_get( data->lock );

	for (map_first(data->agents, &it); iterator_is_valid(&it); iterator_next(&it)) {
        it_val = iterator_val(&it);
        
        if (!it_val) {
            continue;
        }
        
        agent = (struct cc_agent*)*it_val;
        
		if (agent->state==CC_AGENT_FREE) free++;
	}

	lock_release( data->lock );

	return free;
}

unsigned long cc_flow_free_agents( void *flow)
{
    struct cc_rel *rel;
	unsigned int free = ((struct cc_flow*)flow)->agents->avl_count;

	lock_get( data->lock );

	for (rel = ((struct cc_flow*)flow)->online_agents; rel; rel=rel->next) {
        free--;
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
    if (!dynamic_load) {
        if ( cc_load_db_data( data, NULL )!=0 ) {
            LM_CRIT("failed to load callcenter data\n");
            return -1;
        }
    }

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
    struct cc_agent *agent;
    struct cc_flow *flow;

	if(prev_state == CC_CALL_ENDED) {
		LM_CRIT("BUG - terminate state \n");
		return;
	}
	
	LM_DBG("terminating call %p (stat=%p)\n",call,stat);

	lock_get( data->lock );

	prepare_cdr( call, &un, &fid , &aid);
    
    agent = get_agent_by_name(data, &(call->agent));
    flow = get_flow_by_name(data, &(call->flow));
    
    if (!agent) {
        LM_DBG("agent %.*s of call %p does not exists, it may be deleted\n", call->agent.len, call->agent.s, call);
    }
    if (!flow) {
        if (cc_load_db_data(data, &(call->flow)) < 0) {
            LM_CRIT("failed to dynamic load flow data from call handler\n");
        }
        flow = get_flow_by_name(data, &(call->flow));
        if (!flow) LM_ERR("flow %.*s does not exists in db, it may be permanently deleted\n", call->flow.len, call->flow.s);
    }

	if (prev_state==CC_CALL_TOAGENT || prev_state==CC_CALL_PRE_TOAGENT) {
		/* free the agent */
		if (stat && stat->call_time && prev_state==CC_CALL_TOAGENT) {
            
            if (agent) {
                agent->state = CC_AGENT_WRAPUP;
                agent->wrapup_end_time = get_ticks()
                    + (flow ? get_wrapup_time(agent, flow) : 0);
            }
            
            if (flow) {
                flow->processed_calls ++;
                flow->avg_call_duration =
                    ( ((float)stat->call_time + 
                    ((float)flow->avg_call_duration *
                    (flow->processed_calls-1)) ) ) /
                    flow->processed_calls ;
            }
			
			/* update awt for established calls */
			update_awt( stat->start_time - call->recv_time );
			if (flow) update_cc_flow_awt(flow, stat->start_time - call->recv_time);
			if (agent) update_cc_agent_att(agent, stat->call_time);
		} else {
			if (agent) agent->state = CC_AGENT_FREE;
			/* update awt for failed calls */
			update_awt( get_ticks() - call->recv_time );
			if (flow) update_cc_flow_awt( flow, get_ticks() - call->recv_time );
		}
		/* update end time for agent's wrapup */
		if (agent) {
            cc_db_update_agent_wrapup_end(agent);
            agent_raise_event( agent, NULL);
        }
        free_cc_call_agent(data, call);
	} else {
		/* update awt for failed calls */
		update_awt( get_ticks() - call->recv_time );
		if (flow) update_cc_flow_awt( flow, get_ticks() - call->recv_time );
	}

	/* remove the call from queue (if there) */
	if ( is_call_in_queue(data, call) ) {
		cc_queue_rmv_call( data, call);
		call->ref_cnt--;
	}

	if (flow) flow->ongoing_calls--;

	lock_release( data->lock );

	if (call->setup_time==-1)
		call->setup_time = stat ? stat->setup_time : 0;

	/* generate CDR */
	type = (stat==NULL) ? -1 : ((prev_state==CC_CALL_TOAGENT && stat->call_time)? 0 : 1);
	cc_write_cdr( &un, &fid, &aid, type, call->recv_time,
		((type==0)? stat->start_time : get_ticks()) - call->recv_time ,
		(type==0)?stat->call_time:0 , call->setup_time, call->no_rejections, call->fst_flags,
		call->id);

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
    struct cc_agent *agent;
    struct cc_flow *flow;
    
    agent = get_agent_by_name(data, &(call->agent));
    flow = get_flow_by_name(data, &(call->flow));

	//update_stat( stg_aban_incalls, 1); /*abandon from agent */
	call->no_rejections++;

	/* put call back into queue */ 
	call->state = CC_CALL_QUEUED;
	call->setup_time = -1;

	lock_get( data->lock );
    
    // dynamic load flow again if they do not exist
    // these operations must be after data->lock acquired
    // dynamic load agent is not neccessary here as it is just update statistics
    if (!agent) {
        LM_DBG("agent %.*s does not exists, it may be deleted\n", call->agent.len, call->agent.s);
    }
    if (!flow && dynamic_load) {
        if (cc_load_db_data(data, &(call->flow)) < 0) {
            LM_CRIT("failed to dynamic load flow data from call handler\n");
        }
        flow = get_flow_by_name(data, &(call->flow));
        if (!flow) LM_ERR("flow %.*s does not exists in db, it may be permanently deleted\n", call->flow.len, call->flow.s);
    }
    
    if (agent) update_stat( agent->st_aban_incalls, 1);

	/* prepare CDR */
	prepare_cdr( call, &un, &fid , &aid);

    if (agent) {
        agent->state = CC_AGENT_WRAPUP;
        agent->wrapup_end_time = get_ticks() +
				+ (flow ? get_wrapup_time(agent, flow) : 0);
        /* update end time for agent's wrapup */
        cc_db_update_agent_wrapup_end(agent);
        agent_raise_event( agent, NULL);
    }
	free_cc_call_agent(data, call);

	cc_queue_push_call( data, call, 1/*top*/);

	if(from_customer || call->prev_state != CC_CALL_QUEUED) {
        if (flow) {
            out.len = OUT_BUF_LEN(flow->recordings[AUDIO_QUEUE].len);
            out.s = out_buf;
            memcpy( out.s, flow->recordings[AUDIO_QUEUE].s, out.len);
        }
        else {
            LM_ERR("flow %.*s was removed while it's call is processing, so call will be terminated\n", call->flow.len, call->flow.s);
        }
	}

	lock_release( data->lock );

	if(from_customer || call->prev_state != CC_CALL_QUEUED) {
		/* send call to queue */
		if (set_call_leg( NULL, call, &out)< 0 ) {
			LM_ERR("failed to set new destination for call\n");
		}
		LM_DBG("onhold++: agent rejected [%p]\n", call);
		if(from_customer)
		{
			update_stat( stg_onhold_calls, 1);
			if (flow) update_stat( flow->st_onhold_calls, 1);
		}
	}
	/* write CDR */
	cc_write_cdr( &un, &fid, &aid, -2, call->recv_time,
		get_ticks() - call->recv_time, 0 , pickup_time, call->no_rejections-1,
		call->fst_flags, call->id);
	cc_db_update_call(call);
}

int b2bl_callback_agent(b2bl_cb_params_t *params, unsigned int event)
{
	struct cc_call *call = (struct cc_call*)params->param;
	int cnt;
	b2bl_dlg_stat_t* stat = params->stat;
    struct cc_flow *flow;

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
    flow = get_flow_by_name(data, &(call->flow));
    if (flow) update_stat( flow->st_onhold_calls, -1);

	LM_DBG("Bridge two calls [%p] - [%.*s]\n", call, call->agent.len, call->agent.s);
	cnt = --call->ref_cnt;
	if(b2b_api.bridge_2calls(&call->b2bua_id, &call->b2bua_agent_id) < 0)
	{
		LM_ERR("Failed to bridge the agent with the customer\n");
		lock_set_release( data->call_locks, call->lock_idx );
		b2b_api.terminate_call(&call->b2bua_id);
		return -1;
	}
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
    struct cc_agent *agent;
    struct cc_flow *flow;

	LM_DBG(" call (%p) has event %d, \n", call, event);

	lock_set_get( data->call_locks, call->lock_idx );
	cs = call->state;
    
    flow = get_flow_by_name(data, &(call->flow));

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
                if (flow) update_stat( flow->st_onhold_calls, -1);
			}
			if (cs == CC_CALL_TOAGENT) {
				/* call no longer on wait */
				//update_stat( stg_aban_incalls, 1); /*abandon from agent */
				//if (agent) update_stat( call->agent->st_aban_incalls, 1);
			}
		}
		lock_set_get( data->call_locks, call->lock_idx );
		cnt = --call->ref_cnt;
		lock_set_release( data->call_locks, call->lock_idx );
		if (cnt==0)
			free_cc_call( data, call);
		else
			LM_DBG("!!! Call ref not 0 - do not delete %p\n", call);
		return 0;
	}

	if(call->ign_cback) {
		lock_set_release( data->call_locks, call->lock_idx );
		return 2;
	}

	if ( event==B2B_BYE_CB ) {
		if (cs==CC_CALL_TOAGENT && stat->call_time) {
			/* an established call was terminated */
			update_stat( stg_answ_incalls, 1);
            if (flow) update_stat( flow->st_answ_incalls, 1);
			call->fst_flags |= FSTAT_ANSW;
            
            agent = get_agent_by_name(data, &(call->agent));
            if (agent) update_stat( agent->st_answ_incalls, 1);
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
		lock_set_release( data->call_locks, call->lock_idx );
        
        if (cs<CC_CALL_TOAGENT) {
			/* call terminated while onwait */
			LM_DBG("** onhold-- BYE from customer [%p]\n", call);
			update_stat( stg_onhold_calls, -1);
            
            if (flow) update_stat( flow->st_onhold_calls, -1);
		}
		/* Abandon: client was not sent to agent yet, or call still ringing
		 * on agent side
		 */
		if (cs<CC_CALL_TOAGENT || stat->call_time==0) {
 			/*abandon from customer */
			update_stat( stg_aban_incalls, 1);
			if (flow) update_stat( flow->st_aban_incalls, 1);
			call->fst_flags |= FSTAT_ABAN;
		}
		terminate_call(call, stat, cs);

		/* route the BYE according to scenario */
		return 2;
	}
	/* if reInvite to the customer failed - end the call */
	if(event == B2B_REJECT_CB && params->entity==0) {
		lock_set_release( data->call_locks, call->lock_idx );
		return 1;
	}

	if(event == B2B_REJECT_CB && params->entity>0) {
		if(call->state == CC_CALL_TOAGENT) {
			handle_agent_reject(call, 1, stat->setup_time);
			lock_set_release( data->call_locks, call->lock_idx );
			return 0;
		}
		lock_set_release( data->call_locks, call->lock_idx );
		return 1;
	}

	/* we are not interested in B2B_RE_INVITE_CB and B2B_CONFIRMED_CB
	 * events, just in the BYEs from media/agent side */
	if (event!=B2B_BYE_CB) {
		lock_set_release( data->call_locks, call->lock_idx );
		return 0;
	}

	/* right-side leg of call sent BYE */
	if (stat->call_time==0 && call->state == CC_CALL_TOAGENT) {
		LM_INFO("*** AGENT answered and closed immediately %.*s\n",
			call->agent.len, call->agent.s);
		handle_agent_reject(call, 1, stat->setup_time);
		lock_set_release( data->call_locks, call->lock_idx );
		return 0;
	}

	/* get next state */
	lock_get( data->lock );

	if (cc_call_state_machine( data, call, &leg )!=0) {
		LM_ERR("failed to get next call destination \n");
		lock_release( data->lock );
		lock_set_release( data->call_locks, call->lock_idx );
		/* force BYE to be sent in both parts */
		return -1;
	}

	lock_release( data->lock );

	LM_DBG("new destination for call(%p) is %.*s (state=%d)\n",
		call, leg.len, leg.s, call->state);

	if (call->state == CC_CALL_ENDED) {
		lock_set_release( data->call_locks, call->lock_idx );
		terminate_call( call, stat, cs);
		return 2;
	} else if (call->state == CC_CALL_TOAGENT) {
		/* call no longer on wait */
		LM_DBG("** onhold-- Direct to agent [%p]\n", call);
		update_stat( stg_onhold_calls, -1);
        if (flow) update_stat( flow->st_onhold_calls, -1);
	}

	/* send call to selected destination */
	if (set_call_leg( NULL, call, &leg)< 0) {
		LM_ERR("failed to set new destination for call\n");
		lock_set_release( data->call_locks, call->lock_idx );
		pkg_free(leg.s);
		return -1;
	}
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
    struct cc_agent* agent;

	LM_DBG("call %p moving to %.*s , state %d\n", call,
		new_leg->len, new_leg->s, call->state);

	if(call->state==CC_CALL_PRE_TOAGENT) {
		agent = get_agent_by_name(data, &(call->agent));
        if (!agent) {
            LM_ERR("agent %.*s does not exists, it may be deleted\n", call->agent.len, call->agent.s);
            return -2;
        }
        
        call->ref_cnt++;

		memset(&b2b_params, 0, sizeof b2b_params);
		b2b_params.e1_type = B2B_CLIENT;
		b2b_params.e1_to = agent->location;
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


static int w_handle_call(struct sip_msg *msg, str *flow_name, str *param)
{
	struct cc_flow *flow;
	struct cc_call *call;
	str leg = {NULL,0};
	str *dn;
	int dec;
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
        if (dynamic_load) {
            if (cc_load_db_data(data, flow_name) < 0) {
                LM_CRIT("failed to dynamic load flow data from call handler\n");
            }
            
            flow = get_flow_by_name(data, flow_name);
        }
        
        if (flow == NULL) {
            LM_ERR("flow <%.*s> does not exists\n", flow_name->len, flow_name->s);
            ret = -3;
            goto error;
        }
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

	call = new_cc_call(data, flow, dn, &get_from(msg)->parsed_uri.user, param);
	if (call==NULL) {
		LM_ERR("failed to create new call\n");
		ret = -5;
		goto error;
	}
	call->fst_flags |= FSTAT_INCALL;

	/* get estimated wait time */
	if (flow->logged_agents)
		call->eta = (unsigned int) (( flow->avg_call_duration *
			(float)get_stat_val(flow->st_queued_calls) ) /
			(float)flow->logged_agents);
	else
		call->eta = INT_MAX;

	LM_DBG("avg_call_duration=%.2f queued_calls=%lu logedin_agents=%u\n",
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

	lock_release( data->lock );
	LM_DBG("new destination for call(%p) is %.*s (state=%d)\n",
		call, leg.len, leg.s, call->state);

	/* call still waits for agent ? */
	if (call->state!=CC_CALL_TOAGENT) {
		LM_DBG("** onhold++ Not to agent [%p]\n", call);
		update_stat( stg_onhold_calls, +1);
		update_stat( flow->st_onhold_calls, +1);
		dec = 1;
	}

	/* send call to selected destination */
	if (set_call_leg( msg, call, &leg)< 0 ) {
		LM_ERR("failed to set new destination for call\n");
		if (dec) { 
			LM_DBG("** onhold-- Error [%p]\n", call);
			update_stat( stg_onhold_calls, -1);
			update_stat( flow->st_onhold_calls, -1);
		}
		pkg_free(leg.s);
		goto error1;
	}

	pkg_free(leg.s);

	if(cc_db_insert_call(call) < 0) {
		LM_ERR("Failed to insert call record in db\n");
	}

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
	return ret;
}


static int w_agent_login(struct sip_msg *req, str *agent_s, int *state)
{
	struct cc_agent *agent;

	/* block access to data */
	lock_get( data->lock );

	/* name of the agent */
	agent = get_agent_by_name( data, agent_s);
	if (agent==NULL) {
		lock_release( data->lock );
		LM_DBG("agent <%.*s> not found\n",agent_s->len,agent_s->s);
		return -3;
	}

	if (agent->loged_in != *state) {

		if(*state && (agent->state==CC_AGENT_WRAPUP) &&
			(get_ticks() > agent->wrapup_end_time))
			agent->state = CC_AGENT_FREE;

		//if(*state && data->agents[CC_AG_ONLINE] == NULL)
		//	data->last_online_agent = agent;

		/* agent event is triggered here */
		agent_switch_login(data, agent);

		if(*state) {
			data->logedin_agents++;
			log_agent_to_flows( data, agent, 1);
		} else {
			data->logedin_agents--;
			log_agent_to_flows(data, agent, 0);
		}
	}

	/* release access to data */
	lock_release( data->lock );

	return 1;
}


static void cc_timer_agents(unsigned int ticks, void* param)
{
	struct cc_agent *agent;
	struct cc_call  *call;
	str out;
	str dest;
    map_iterator_t it;
    void** it_val;
    struct cc_flow *flow;
    

	if (data==NULL)
		return;

    call = NULL;
    
	do {

		lock_get( data->lock );
        
		call = NULL;

		// iterate all agents
        for (map_first(data->agents, &it); iterator_is_valid(&it); iterator_next(&it)) {
            it_val = iterator_val(&it);
            
            if (!it_val) {
                continue;
            }
            
            agent = (struct cc_agent*)*it_val;

            //LM_DBG("%.*s , state=%d, wrapup_end_time=%u, ticks=%u, "
            //		"wrapup=%u\n", agent->id.len, agent->id.s, agent->state,
            //		agent->wrapup_end_time, ticks, wrapup_time);
            // for agents in WRAPUP time, check if expired
            if ( (agent->state==CC_AGENT_WRAPUP) &&
                    (ticks > agent->wrapup_end_time )) {
                agent->state = CC_AGENT_FREE;
                agent_raise_event( agent, NULL);
            }

            // for free agents -> check for calls
            if ( (data->queue.calls_no!=0) && (agent->state==CC_AGENT_FREE) ) {
                call = cc_queue_pop_call_for_agent( data, agent);
                if (call) {
                    // found a call for the agent
                    break;
                }
            }
        }
        
        if (call) {
            flow = get_flow_by_name(data, &(call->flow));
                
            if (!flow && dynamic_load) {
                if (cc_load_db_data(data, &(call->flow)) < 0) {
                    LM_CRIT("failed to dynamic load flow data from call handler\n");
                }
                
                flow = get_flow_by_name(data, &(call->flow));
                if (!flow) LM_ERR("flow %.*s does not exists in db, it may be permanently deleted\n", call->flow.len, call->flow.s);
            }
        }

        lock_release( data->lock );

		// no locking here

		if (call) {

			lock_set_get( data->call_locks, call->lock_idx );
			call->ref_cnt--;

			// is the call state still valid? (as queued)
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

			if(!flow || !flow->recordings[AUDIO_FLOW_ID].len)
				dest = agent->location;
			else
				dest = flow->recordings[AUDIO_FLOW_ID];

			// make a copy for destination to agent
			out.len = OUT_BUF_LEN(dest.len);
			out.s = out_buf;
			memcpy( out.s, dest.s, out.len);
			
			call->prev_state = call->state;
			if(!flow || !flow->recordings[AUDIO_FLOW_ID].len) {
				call->state = CC_CALL_TOAGENT;
				// call no longer on wait
				LM_DBG("** onhold-- Took out of the queue [%p]\n", call);
				update_stat( stg_onhold_calls, -1);
				if (flow) update_stat( flow->st_onhold_calls, -1);
			}else{
				call->state = CC_CALL_PRE_TOAGENT;
			}

			// mark agent as used
			agent->state = CC_AGENT_INCALL;
            cc_set_call_agent(data, call, agent);
			agent_raise_event( agent, call);
			update_stat( stg_dist_incalls, 1);
			if (flow) update_stat( flow->st_dist_incalls, 1);
			call->fst_flags |= FSTAT_DIST;
			update_stat( agent->st_dist_incalls, +1);

			// unlock data
			lock_release( data->lock );

			// send call to selected agent
			if (set_call_leg( NULL, call, &out)< 0 ) {
				LM_ERR("failed to set new destination for call\n");
			}
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
	struct cc_call  *call = NULL;
	str out;
    map_iterator_t it;
    struct cc_flow *flow;

	if (data==NULL || data->queue.calls_no==0)
		return;

	/* iterate all queued calls to check for how long they were waiting */

	for (map_first(data->agents, &it); iterator_is_valid(&it); iterator_next(&it)) {

		call = NULL;
		lock_get( data->lock );

		for ( call=data->queue.first ; call ; call=call->lower_in_queue) {
            flow = get_flow_by_name(data, &(call->flow));
            
            if (!flow && dynamic_load) {
                if (cc_load_db_data(data, &(call->flow)) < 0) {
                    LM_CRIT("failed to dynamic load flow data from call handler\n");
                }
                
                flow = get_flow_by_name(data, &(call->flow));
            }
            
            if (flow) {
                if (flow->diss_onhold_th &&
                (ticks - call->last_start > flow->diss_onhold_th) &&
                flow->recordings[AUDIO_DISSUADING].len ) {
                    LM_DBG("call %p in queue for %d(%d) sec -> dissuading msg\n",
                        call,ticks-call->last_start, flow->diss_onhold_th);
                    /* remove from queue */
                    cc_queue_rmv_call( data, call);
                    break;
                }
            }
            else {
                LM_ERR("flow %.*s does not exists in db, it may be permanently deleted\n", call->flow.len, call->flow.s);
                continue;
                // consider clean the call here, otherwise, the expired B2B entities will delete this call automatically
                // and give a grace time for this flow to be loaded again.
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
			if (flow) out.len = OUT_BUF_LEN(flow->recordings[AUDIO_DISSUADING].len);
			if (out.len==0) {
				cc_queue_push_call( data, call, 1/*top*/);

				/* unlock data */
				lock_release( data->lock );
			} else {
				out.s = out_buf;
				memcpy( out.s, flow->recordings[AUDIO_DISSUADING].s,
					out.len);

				call->state = flow->diss_hangup ?
					CC_CALL_DISSUADING2 : CC_CALL_DISSUADING1;

				/* unlock data */
				lock_release( data->lock );

				/* send call to selected destination */
				if (set_call_leg( NULL, call, &out)<-0 ) {
					LM_ERR("failed to set new destination for call\n");
				}
			}
			lock_set_release( data->call_locks, call->lock_idx );
		}

	} while(call);

	return;
}


static void cc_timer_cleanup(unsigned int ticks, void* param)
{
	/* block access to data */
	//lock_get( data->lock );

	//clean_cc_unref_data(data);
	
	/* done with data */
	//lock_release( data->lock );
}


/******************** MI commands ***********************/

static mi_response_t *mi_cc_reload(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int ret = 0;

	LM_INFO("\"cc_reload\" MI command received!\n");

	/* block access to data */
	lock_get( data->lock );

    if (!dynamic_load) {
        ret = cc_load_db_data( data, NULL );
        if (ret<0) {
            LM_CRIT("failed to load CC data\n");
        }
    }
    else {
        clean_cc_data(data);
    }

	/* release the readers */
	lock_release( data->lock );

	if (ret==0)
		return init_mi_result_ok();
	else
		return init_mi_error(500, MI_SSTR("Failed to reload"));
}

static mi_response_t *mi_cc_load_flow(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int ret;
    str flow_id;

	LM_INFO("\"cc_load_flow\" MI command received!\n");

	if (get_mi_string_param(params, "flow_id", &flow_id.s, &flow_id.len) < 0) {
        return init_mi_param_error();
    }
    
    /* block access to data */
	lock_get( data->lock );
    
    ret = cc_load_db_data(data, &flow_id);
    if (ret<0) {
        LM_CRIT("failed to load flow data\n");
    }

	/* release the readers */
	lock_release( data->lock );

	if (ret==0)
		return init_mi_result_ok();
	else
		return init_mi_error(500, MI_SSTR("Failed to reload"));
}

static mi_response_t *mi_cc_reload_flow(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int ret = 0;
    str flow_id;
    struct cc_flow *flow;

	LM_INFO("\"cc_reload_flow\" MI command received!\n");

	if (get_mi_string_param(params, "flow_id", &flow_id.s, &flow_id.len) < 0) {
        return init_mi_param_error();
    }
    
    flow = get_flow_by_name(data, &flow_id);
    if (flow) {
        /* block access to data */
        lock_get( data->lock );
        
        ret = cc_load_db_data(data, &flow_id);
        if (ret<0) {
            LM_CRIT("failed to load flow data\n");
        }

        /* release the readers */
        lock_release( data->lock );
    }

	if (ret==0)
		return init_mi_result_ok();
	else
		return init_mi_error(500, MI_SSTR("Failed to reload"));
}

static mi_response_t *mi_cc_load_agent(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int ret;
    str agent_id;
    struct cc_agent *agent;

	LM_INFO("\"cc_load_agent\" MI command received!\n");

	/* do the update */
    if (get_mi_string_param(params, "agent_id", &agent_id.s, &agent_id.len) < 0) {
        return init_mi_param_error();
    }

	agent = get_agent_by_name( data, &agent_id);
    //logout agent from flow first
    if (agent) {
        unlink_agent_from_flows(data, agent);
    }
    
    /* block access to data */
	lock_get( data->lock );
    
    ret = cc_load_db_agent_data(data, &agent_id);
    if (ret<0) {
        LM_CRIT("failed to load agent data\n");
    }

	/* release the readers */
	lock_release( data->lock );

	if (ret==0)
		return init_mi_result_ok();
	else
		return init_mi_error(500, MI_SSTR("Failed to reload"));
}

static mi_response_t *mi_cc_reload_agent(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int ret = 0;
    str agent_id;
    struct cc_agent *agent;

	LM_INFO("\"cc_reload_agent\" MI command received!\n");

	/* do the update */
    if (get_mi_string_param(params, "agent_id", &agent_id.s, &agent_id.len) < 0) {
        return init_mi_param_error();
    }

	agent = get_agent_by_name( data, &agent_id);
    if (agent) {
        unlink_agent_from_flows(data, agent);
        
        /* block access to data */
        lock_get( data->lock );
        
        ret = cc_load_db_agent_data(data, &agent_id);
        if (ret<0) {
            LM_CRIT("failed to load agent data\n");
        }

        /* release the readers */
        lock_release( data->lock );
    }

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
	mi_item_t *flows_arr, *flow_item, *flows_agents_arr;
    map_iterator_t it, it2;
    void** it_val;
    str *it_key;

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
    
    for (map_first(data->flows, &it); iterator_is_valid(&it); iterator_next(&it)) {
        it_val = iterator_val(&it);
        
        if (!it_val) {
            continue;
        }
        
        flow = (struct cc_flow*)*it_val;
        
        flow_item = add_mi_object(flows_arr, NULL, 0);
		if (!flow_item)
			goto error;

		if (add_mi_string(flow_item, MI_SSTR("id"),
			flow->id.s, flow->id.len) < 0)
			goto error;
        
        flows_agents_arr = add_mi_array(flow_item, MI_SSTR("Agents"));
        if (!flows_agents_arr) {
            goto error;
        }
        
        for (map_first(flow->agents, &it2); iterator_is_valid(&it2); iterator_next(&it2)) {
            it_key = iterator_key(&it2);
            
            if (!it_key) {
                continue;
            }
            
            if (add_mi_string(flows_agents_arr, NULL, 0, it_key->s, it_key->len) < 0)
                goto error;
        }

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
	mi_item_t *agents_arr, *agent_item, *agent_flows_arr;
	struct cc_agent *agent;
	str state;
	static str s_free={"free", 4};
	static str s_wrapup={"wrapup", 6};
	static str s_incall={"incall", 6};
    map_iterator_t it;
    void **it_val;
    struct cc_rel *rel;

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

	for (map_first(data->agents, &it); iterator_is_valid(&it); iterator_next(&it)) {
        it_val = iterator_val(&it);
        
        if (!it_val) {
            continue;
        }
        
        agent = (struct cc_agent*)*it_val;
        
        agent_item = add_mi_object(agents_arr, NULL, 0);
        if (!agent_item)
            goto error;

        if (add_mi_string(agent_item, MI_SSTR("id"),
            agent->id.s, agent->id.len) < 0)
            goto error;
        
        agent_flows_arr = add_mi_array(agent_item, MI_SSTR("Flows"));
        if (!agent_flows_arr) {
            goto error;
        }
        for(rel=agent->flows; rel; rel=rel->next) {
            LM_DBG("Agent flow rel %.*s", rel->id.len, rel->id.s);
            if (add_mi_string(agent_flows_arr, NULL, 0, rel->id.s, rel->id.len) < 0)
                goto error;
        }

        if(!agent->loged_in) {
            if (add_mi_string(agent_item, MI_SSTR("Loged in"),
                MI_SSTR("NO")) < 0)
                goto error;
        } else {
            if (add_mi_string(agent_item, MI_SSTR("Loged in"),
                MI_SSTR("YES")) < 0)
                goto error;

            switch ( agent->state ) {
                case CC_AGENT_FREE:   state = s_free;   break;
                case CC_AGENT_WRAPUP: state = s_wrapup; break;
                case CC_AGENT_INCALL: state = s_incall; break;
                default: state.s =0;  state.len = 0;
            }
            if (add_mi_string(agent_item, MI_SSTR("State"),
                state.s, state.len) < 0)
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

static mi_response_t *mi_cc_list_calls(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct cc_call *call;
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

			if(call->flow.s) {
				if (add_mi_string(call_item, MI_SSTR("Flow"),
					call->flow.s, call->flow.len) < 0)
					goto error;
			}
		}
		if(call->agent.s) {
            if (add_mi_string(call_item, MI_SSTR("Agent"),
                call->agent.s, call->agent.len) < 0)
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
	int loged_in;
	str agent_id;

	if (get_mi_string_param(params, "agent_id", &agent_id.s, &agent_id.len) < 0)
		return init_mi_param_error();

	if (get_mi_int_param(params, "state", &loged_in) < 0)
		return init_mi_param_error();

	/* block access to data */
	lock_get( data->lock );
    
    if (dynamic_load) {
        // save agent logstate to database
        cc_db_update_agent_logstate(&agent_id, loged_in);
    }

	/* name of the agent */
	agent = get_agent_by_name( data, &agent_id);
	if (agent==NULL) {
		lock_release( data->lock );
        if (!dynamic_load) {
            return init_mi_error( 404, MI_SSTR("Agent not found"));
        }
        else {
            return init_mi_result_ok();
        }
	}

	if (agent->loged_in != loged_in) {
		if(loged_in && (agent->state==CC_AGENT_WRAPUP) &&
			(get_ticks() > agent->wrapup_end_time))
			agent->state = CC_AGENT_FREE;

		/* agent event is triggered here */
		agent_switch_login(data, agent);

		if(loged_in) {
			data->logedin_agents++;
			log_agent_to_flows( data, agent, 1);
		} else {
			data->logedin_agents--;
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
    map_iterator_t it;
    void **it_val;

	/* reset global stats */
	reset_stat( stg_incalls) ;
	data->avt_waittime_no = 0;
	data->avt_waittime = 0;
	reset_stat( stg_dist_incalls );
	reset_stat( stg_answ_incalls );
	reset_stat( stg_aban_incalls );

	/* block access to data */
	lock_get( data->lock );

	/* reset flow stats */
    for (map_first(data->flows, &it); iterator_is_valid(&it); iterator_next(&it)) {
        it_val = iterator_val(&it);
        
        if (!it_val) {
            continue;
        }
        
        flow = (struct cc_flow*)*it_val;
	
        if (!flow) {
            continue;
        }
    
		reset_stat( flow->st_incalls );
		reset_stat( flow->st_dist_incalls );
		reset_stat( flow->st_answ_incalls );
		reset_stat( flow->st_aban_incalls );
		reset_stat( flow->st_onhold_calls );
		flow->avg_call_duration = 0;
		flow->processed_calls = 0;
		flow->avg_waittime = 0;
		flow->avg_waittime_no = 0;
	}

	/* reset agent stats */
	for (map_first(data->agents, &it); iterator_is_valid(&it); iterator_next(&it)) {
        it_val = iterator_val(&it);
        
        if (!it_val) {
            continue;
        }
        
        agent = (struct cc_agent*)*it_val;
        
        reset_stat( agent->st_dist_incalls );
        reset_stat( agent->st_answ_incalls );
        reset_stat( agent->st_aban_incalls );
        agent->avg_talktime = 0;
        agent->avg_talktime_no = 0;
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

		if (add_mi_number(call_item, MI_SSTR("Waiting for"),
			now-call->last_start) < 0)
			goto error;

		if (add_mi_number(call_item, MI_SSTR("ETW"), call->eta) < 0)
			goto error;

		/* flow data */
        if (add_mi_string(call_item, MI_SSTR("Flow"),
            call->flow.s, call->flow.len) < 0)
            goto error;

        if (add_mi_number(call_item, MI_SSTR("Priority"), call->priority) < 0)
            goto error;

		/*s = get_skill_by_id(data,call->flow->skill);
		if (s && add_mi_string(call_item, MI_SSTR("Skill"),
			s->s, s->len) < 0)
			goto error;*/
	}

	/* release the readers */
	lock_release( data->lock );

	return resp;
error:
	lock_release( data->lock );
	free_mi_response(resp);
	return NULL;
}

static mi_response_t *mi_cc_get_flow(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct cc_flow *flow;
	mi_response_t *resp;
	mi_item_t *resp_obj, *flows_arr, *flow_item, *agent_item, *flows_agents_arr;
    str flow_id, state;
    struct cc_agent *agent;
    static str s_free={"free", 4};
	static str s_wrapup={"wrapup", 6};
	static str s_incall={"incall", 6};
    map_iterator_t it;
    str *it_key;
    

	if (get_mi_string_param(params, "flow_id", &flow_id.s, &flow_id.len) < 0)
		return init_mi_param_error();

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;
    
    flows_arr = add_mi_array(resp_obj, MI_SSTR("Flows"));
	if (!flows_arr) {
		free_mi_response(resp);
		return 0;
	}
    
    flow_item = add_mi_object(flows_arr, NULL, 0);
    if (!flow_item)
        goto error;
    
    /* block access to data */
	lock_get( data->lock );
        
    flow = get_flow_by_name(data, &flow_id);

    if (flow) {
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
        
        flows_agents_arr = add_mi_array(flow_item, MI_SSTR("Agents"));
        if (!flows_agents_arr) {
            goto error;
        }
        
        for (map_first(flow->agents, &it); iterator_is_valid(&it); iterator_next(&it)) {
            it_key = iterator_key(&it);
            
            if (!it_key) {
                continue;
            }
            
            agent = get_agent_by_name(data, it_key);
            
            agent_item = add_mi_object(flows_agents_arr, NULL, 0);
            if (!agent_item)
                goto error;
            
            if (add_mi_string(agent_item,  MI_SSTR("id"), it_key->s, it_key->len) < 0)
                goto error;
            
            if (agent) {
                if(!agent->loged_in) {
                    if (add_mi_string(agent_item, MI_SSTR("Loged in"),
                        MI_SSTR("NO")) < 0)
                        goto error;
                } else {
                    if (add_mi_string(agent_item, MI_SSTR("Loged in"),
                        MI_SSTR("YES")) < 0)
                        goto error;

                    switch ( agent->state ) {
                        case CC_AGENT_FREE:   state = s_free;   break;
                        case CC_AGENT_WRAPUP: state = s_wrapup; break;
                        case CC_AGENT_INCALL: state = s_incall; break;
                        default: state.s =0;  state.len = 0;
                    }
                    if (add_mi_string(agent_item, MI_SSTR("State"),
                        state.s, state.len) < 0)
                        goto error;
                }
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

static mi_response_t *mi_cc_get_agent(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj, *agent_item, *agents_arr;
	struct cc_agent *agent;
	str state;
	static str s_free={"free", 4};
	static str s_wrapup={"wrapup", 6};
	static str s_incall={"incall", 6};
    str agent_id;

	if (get_mi_string_param(params, "agent_id", &agent_id.s, &agent_id.len) < 0)
		return init_mi_param_error();

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;
    
    agents_arr = add_mi_array(resp_obj, MI_SSTR("Agents"));
	if (!agents_arr) {
		free_mi_response(resp);
		return 0;
	}
    
    agent_item = add_mi_object(agents_arr, NULL, 0);
    if (!agent_item)
        goto error;
    
    /* block access to data */
	lock_get( data->lock );
    
    agent = get_agent_by_name(data, &agent_id);
    
    if (agent) {
        if (add_mi_string(agent_item, MI_SSTR("id"),
            agent->id.s, agent->id.len) < 0)
            goto error;

        if(!agent->loged_in) {
            if (add_mi_string(agent_item, MI_SSTR("Loged in"),
                MI_SSTR("NO")) < 0)
                goto error;
        } else {
            if (add_mi_string(agent_item, MI_SSTR("Loged in"),
                MI_SSTR("YES")) < 0)
                goto error;

            switch ( agent->state ) {
                case CC_AGENT_FREE:   state = s_free;   break;
                case CC_AGENT_WRAPUP: state = s_wrapup; break;
                case CC_AGENT_INCALL: state = s_incall; break;
                default: state.s =0;  state.len = 0;
            }
            if (add_mi_string(agent_item, MI_SSTR("State"),
                state.s, state.len) < 0)
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
