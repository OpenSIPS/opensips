/*
 * call center module - call queuing and distribution
 *
 * Copyright (C) 2014 OpenSIPS Solutions
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
 *  2014-03-17 initial version (bogdan)
 */

#include "../../sr_module.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../timer.h"
#include "../../ut.h"
#include "../../mod_fix.h"
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

/* internal data (agents, flows) */
static struct cc_data *data=NULL;
static str b2b_scenario = {"call center", 0};

/* b2b logic API */
b2bl_api_t b2b_api;


static int mod_init(void);
static void mod_destroy(void);
static int child_init( int rank );
static int mi_child_init();

static struct mi_root* mi_cc_reload(struct mi_root *cmd_tree, void *param);
static struct mi_root* mi_cc_list_flows(struct mi_root *cmd_tree, void *param);
static struct mi_root* mi_cc_list_queue(struct mi_root *cmd_tree, void *param);
static struct mi_root* mi_agent_login(struct mi_root *cmd_tree, void *param);
static struct mi_root* mi_cc_list_agents(struct mi_root *cmd_tree, void *param);
static struct mi_root* mi_cc_list_calls(struct mi_root *cmd_tree, void *param);
static struct mi_root* mi_reset_stats(struct mi_root *cmd_tree, void *param);

static int w_handle_call(struct sip_msg *req, char *id);
static int w_agent_login(struct sip_msg *req, char *agent, char *state);

static void cc_timer_agents(unsigned int ticks, void* param);
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



static cmd_export_t cmds[]={
	{"cc_handle_call",           (cmd_function)w_handle_call,         1,
		fixup_sgp_null, 0, REQUEST_ROUTE},
	{"cc_agent_login",           (cmd_function)w_agent_login,         2,
		fixup_sgp_sgp, 0, REQUEST_ROUTE},
	{0,0,0,0,0,0}
	};


static param_export_t mod_params[]={
	{ "db_url",               STR_PARAM, &db_url.s             },
	{ "acc_db_url",           STR_PARAM, &acc_db_url.s         },
	{ "b2b_scenario",         STR_PARAM, &b2b_scenario.s       },
	{ "wrapup_time",          INT_PARAM, &wrapup_time          },
	{ "queue_pos_param",      STR_PARAM, &queue_pos_param.s    },
	{ 0,0,0 }
};


static mi_export_t mi_cmds[] = {
	{ "cc_reload",      "", mi_cc_reload,    MI_NO_INPUT_FLAG,0,mi_child_init},
	{ "cc_agent_login", "", mi_agent_login,                  0, 0, 0},
	{ "cc_list_queue",  "", mi_cc_list_queue, MI_NO_INPUT_FLAG, 0, 0},
	{ "cc_list_flows",  "", mi_cc_list_flows, MI_NO_INPUT_FLAG, 0, 0},
	{ "cc_list_agents", "", mi_cc_list_agents,MI_NO_INPUT_FLAG, 0, 0},
	{ "cc_list_calls",  "", mi_cc_list_calls, MI_NO_INPUT_FLAG, 0, 0},
	{ "cc_reset_stats", "", mi_reset_stats,   MI_NO_INPUT_FLAG, 0, 0},
	{ 0, 0, 0, 0, 0, 0}
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
	&deps,           /* OpenSIPS module dependencies */
	cmds,            /* exported functions */
	0,               /* exported async functions */
	mod_params,      /* param exports */
	mod_stats,       /* exported statistics */
	mi_cmds,         /* exported MI functions */
	0,               /* exported pseudo-variables */
	0,               /* extra processes */
	mod_init,        /* module initialization function */
	0,               /* reply processing function */
	mod_destroy,
	child_init       /* per-child init function */
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

	if (data->logedin_agents==0) {
		lock_release( data->lock );
		return 0;
	}

	free_ag = 0;
	for (agent = data->agents[CC_AG_ONLINE] ; agent ; agent=agent->next) {
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
	b2b_scenario.len = strlen(b2b_scenario.s);
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

	/* init and open DB connection */
	if (init_cc_db( &db_url )!=0) {
		LM_ERR("failed to initialize the DB support\n");
		return -1;
	}
	if (init_cc_acc_db( &acc_db_url )!=0) {
		LM_ERR("failed to initialize the acc DB support\n");
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

	/* close DB connection */
	cc_close_db();

	return 0;
}


static int child_init( int rank )
{
	/* init DB connection */
	if ( rank<PROC_MAIN)
		return 0;
	if ( cc_connect_db(&db_url)!=0 ) {
		LM_CRIT("cannot initialize database connection\n");
		return -1;
	}
	if ( cc_connect_acc_db(&acc_db_url)!=0 ) {
		LM_CRIT("cannot initialize acc database connection\n");
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

	if (prev_state==CC_CALL_TOAGENT) {
		/* free the agent */
		if (stat && stat->call_time && prev_state==CC_CALL_TOAGENT) {
			call->agent->state = CC_AGENT_WRAPUP;
			call->agent->last_call_end = get_ticks();
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
			call->agent->state = CC_AGENT_FREE;
			/* update awt for failed calls */
			update_awt( get_ticks() - call->recv_time );
			update_cc_flow_awt( call->flow, get_ticks() - call->recv_time );
		}
		/* update last_call_end for agent */
		cc_db_update_agent_end_call(call->agent);
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

	if (call->setup_time==-1 && stat)
		call->setup_time = stat->setup_time;

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

	//update_stat( stg_aban_incalls, 1); /*abandon from agent */
	update_stat( call->agent->st_aban_incalls, 1);
	call->no_rejections++;

	/* put call back into queue */ 
	call->state = CC_CALL_QUEUED;
	call->setup_time = -1;

	lock_get( data->lock );

	/* prepare CDR */
	prepare_cdr( call, &un, &fid , &aid);

	call->agent->state = CC_AGENT_WRAPUP;
	call->agent->last_call_end = get_ticks();
	/* update last call_end for agent */
	cc_db_update_agent_end_call(call->agent);
	call->agent->ref_cnt--;
	call->agent = NULL;

	cc_queue_push_call( data, call, 1/*top*/);

	if(from_customer || call->prev_state != CC_CALL_QUEUED) {
		out.len = OUT_BUF_LEN(call->flow->recordings[AUDIO_QUEUE].len);
		out.s = out_buf;
		memcpy( out.s, call->flow->recordings[AUDIO_QUEUE].s, out.len);
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
			update_stat( call->flow->st_onhold_calls, 1);
		}
	}
	/* write CDR */
	cc_write_cdr( &un, &fid, &aid, -2, call->recv_time,
		get_ticks() - call->recv_time, 0 , pickup_time, call->no_rejections-1,
		call->fst_flags, call->id);
	cc_db_update_call(call);
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
			update_stat( call->flow->st_answ_incalls, 1);
			call->fst_flags |= FSTAT_ANSW;
			update_stat( call->agent->st_answ_incalls, 1);
		}
	}
	
	if (event==B2B_BYE_CB && params->entity==0) {
		LM_DBG("BYE from the customer\n");
		/* external caller terminated the call */
		call->state = CC_CALL_ENDED;
		lock_set_release( data->call_locks, call->lock_idx );
		if (cs<CC_CALL_TOAGENT) {
			/* call terminated while onwait */
			LM_DBG("** onhold-- BYE from customer [%p]\n", call);
			update_stat( stg_onhold_calls, -1);
			update_stat( call->flow->st_onhold_calls, -1);
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
			call->agent->location.len, call->agent->location.s);
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
		update_stat( call->flow->st_onhold_calls, -1);
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

	LM_DBG("call %p moving to %.*s , state %d\n", call,
		new_leg->len, new_leg->s, call->state);

	if (call->b2bua_id.len==0) {
		/* b2b instance not initialized yet =>
		 * create new b2bua instance */
		call->ref_cnt++;
		id = b2b_api.init( msg, &b2b_scenario, &new_leg, b2bl_callback_customer,
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
		if(b2b_api.bridge( &call->b2bua_id, new_leg, &call->caller_dn, 0) < 0) {
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


static int w_handle_call(struct sip_msg *msg, char *flow_var)
{
	struct cc_flow *flow;
	struct cc_call *call;
	str leg = {NULL,0};
	str *dn;
	str val;
	int dec;
	int ret = -1;

	call = NULL;
	dec = 0;

	/* get the flow name */
	if (fixup_get_svalue(msg, (gparam_p)flow_var, &val)!=0) {
		LM_ERR("failed to evaluate the flow name variable\n");
		return -1;
	}

	/* parse FROM URI */
	if (parse_from_uri(msg)==NULL) {
		LM_ERR("failed to parse from hdr\n");
		return -2;
	}

	lock_get( data->lock );

	/* get the flow ID */
	flow = get_flow_by_name(data, &val);
	if (flow==NULL) {
		LM_ERR("flow <%.*s> does not exists\n", val.len, val.s);
		ret = -3;
		goto error;
	}
	LM_DBG("using call flow %p\n", flow);

	if (flow->logged_agents==0 /* no logged agents */ ) {
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

	call = new_cc_call(data, flow, dn, &get_from(msg)->parsed_uri.user);
	if (call==NULL) {
		LM_ERR("failed to create new call\n");
		ret = -5;
		goto error;
	}
	call->fst_flags |= FSTAT_INCALL;

	/* get estimated wait time */
	call->eta = (unsigned int) (( flow->avg_call_duration *
		(float)get_stat_val(flow->st_queued_calls) ) /
		(float)flow->logged_agents);
	
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
	if (call) { free_cc_call( data, call); flow->ongoing_calls--; }
	return ret;
}


static int w_agent_login(struct sip_msg *req, char *agent_v, char *state_v)
{
	struct cc_agent *agent, *prev_agent;
	str agent_s;
	int state;
	unsigned int flags;


	/* get state */
	if (fixup_get_isvalue( req, (gparam_p)state_v, &state, &agent_s,
	&flags)!=0 || ((flags|GPARAM_INT_VALUE_FLAG)==0) ) {
		LM_ERR("unable to evaluate state spec \n");
		return -1;
	}
	/* get agent */
	if (fixup_get_svalue( req, (gparam_p)agent_v, &agent_s)!=0) {
		LM_ERR("unable to evaluate agent spec \n");
		return -2;
	}

	/* block access to data */
	lock_get( data->lock );

	/* name of the agent */
	agent = get_agent_by_name( data, &agent_s, &prev_agent);
	if (agent==NULL) {
		lock_release( data->lock );
		LM_DBG("agent <%.*s> not found\n",agent_s.len,agent_s.s);
		return -3;
	}

	if (agent->loged_in != state) {

		if(state && (agent->state==CC_AGENT_WRAPUP) &&
			(get_ticks() - agent->last_call_end > wrapup_time))
			agent->state = CC_AGENT_FREE;

		if(state && data->agents[CC_AG_ONLINE] == NULL)
			data->last_online_agent = agent;

		agent_switch_login(data, agent, prev_agent);

		if(state) {
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
	struct cc_agent *agent, *prev_agent, *tmp_ag;
	struct cc_call  *call;
	str out;
	str dest;

	if (data==NULL || data->agents[CC_AG_ONLINE]==NULL)
		return;

	do {

		lock_get( data->lock );

		prev_agent = data->agents[CC_AG_ONLINE];
		agent = data->agents[CC_AG_ONLINE];
		call = NULL;

		/* iterate all agents*/
		do {

			//LM_DBG("%.*s , state=%d, last_call_end=%u, ticks=%u, wrapup=%u\n",
			//		agent->id.len, agent->id.s, agent->state, agent->last_call_end, ticks, wrapup_time);
			/* for agents in WRAPUP time, check if expired */
			if ( (agent->state==CC_AGENT_WRAPUP) &&
					(ticks - agent->last_call_end > wrapup_time)) {
				agent->state = CC_AGENT_FREE;
				/* move it to the end of the list*/
				if(data->last_online_agent != agent) {
					remove_cc_agent(data, agent, prev_agent);
					if(!data->last_online_agent) {
						LM_CRIT("last_online_agent NULL\n");
						if(data->agents[CC_AG_ONLINE] == NULL)
							data->agents[CC_AG_ONLINE] = agent;
						else {
							for (tmp_ag = data->agents[CC_AG_ONLINE]; tmp_ag; tmp_ag= tmp_ag->next)
							{
								prev_agent = tmp_ag;
							}
							prev_agent->next = agent;
							agent->next = NULL;
							data->last_online_agent = agent;
						}
					}
					else {
							data->last_online_agent->next = agent;
							agent->next = NULL;
							data->last_online_agent = agent;
					}
					goto next_ag;
				}
			}

			/* for free agents -> check for calls */
			if ( (data->queue.calls_no!=0) && (agent->state==CC_AGENT_FREE) ) {
				call = cc_queue_pop_call_for_agent( data, agent);
				if (call) {
					/* found a call for the agent */
					break;
				}
			}
next_ag:
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

			dest = agent->location;

			/* make a copy for destination to agent */
			out.len = OUT_BUF_LEN(dest.len);
			out.s = out_buf;
			memcpy( out.s, dest.s, out.len);
			
			call->prev_state = call->state;
			call->state = CC_CALL_TOAGENT;
			/* call no longer on wait */
			LM_DBG("** onhold-- Took out of the queue [%p]\n", call);
			update_stat( stg_onhold_calls, -1);
			update_stat( call->flow->st_onhold_calls, -1);

			/* mark agent as used */
			agent->state = CC_AGENT_INCALL;
			call->agent = agent;
			call->agent->ref_cnt++;
			update_stat( stg_dist_incalls, 1);
			update_stat( call->flow->st_dist_incalls, 1);
			call->fst_flags |= FSTAT_DIST;
			update_stat( call->agent->st_dist_incalls, +1);

			/* unlock data */
			lock_release( data->lock );

			/* send call to selected agent */
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

static struct mi_root* mi_cc_reload(struct mi_root *cmd_tree, void *param)
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
		return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	else
		return init_mi_tree( 500, "Failed to reload",16);
}


static struct mi_root* mi_cc_list_flows(struct mi_root *cmd, void *param)
{
	struct cc_flow *flow;
	struct mi_root *rpl_tree;
	struct mi_node *node;
	struct mi_node *rpl;
	struct mi_attr *attr;
	int len;
	char *p;

	rpl_tree = init_mi_tree( 200, MI_SSTR("OK") );
	if ( rpl_tree==NULL)
		return NULL;
	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;

	/* block access to data */
	lock_get( data->lock );

	for( flow=data->flows; flow ; flow=flow->next ) {

		node = add_mi_node_child( rpl, MI_DUP_VALUE, MI_SSTR("Flow"),
				flow->id.s, flow->id.len );
		if (node==NULL)
				goto error;

		p = int2str( (unsigned long)(flow->avg_call_duration), &len);
		attr = add_mi_attr( node, MI_DUP_VALUE, MI_SSTR("Avg Call Duration"), p, len);
		if (attr==NULL)
				goto error;

		p = int2str( (unsigned long)(flow->processed_calls), &len);
		attr = add_mi_attr( node, MI_DUP_VALUE, MI_SSTR("Processed Calls"), p, len);
		if (attr==NULL)
				goto error;

		p = int2str( (unsigned long)(flow->logged_agents), &len);
		attr = add_mi_attr( node, MI_DUP_VALUE, MI_SSTR("Logged Agents"), p, len);
		if (attr==NULL)
				goto error;

		p = int2str( (unsigned long)(flow->ongoing_calls), &len);
		attr = add_mi_attr( node, MI_DUP_VALUE, MI_SSTR("Ongoing Calls"), p, len);
		if (attr==NULL)
				goto error;

		p = int2str( (unsigned long)(flow->ref_cnt), &len);
		attr = add_mi_attr( node, MI_DUP_VALUE, MI_SSTR("Ref"), p, len);
		if (attr==NULL)
				goto error;

	}

	lock_release( data->lock );

	return rpl_tree;

error:
	lock_release( data->lock );
	return 0;
}


static struct mi_root* mi_cc_list_agents(struct mi_root *cmd_tree, void *param)
{
	struct cc_agent *agent;
	struct mi_root *rpl_tree;
	struct mi_node *node;
	struct mi_node *rpl;
	struct mi_attr *attr;
	str state;
	static str s_free={"free", 4};
	static str s_wrapup={"wrapup", 6};
	static str s_incall={"incall", 6};
	char *p;
	int len;
	int i;

	rpl_tree = init_mi_tree( 200, MI_SSTR("OK") );
	if ( rpl_tree==NULL)
		return NULL;
	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;

	/* block access to data */
	lock_get( data->lock );

	for(i=0; i< 2; i++) {
		for( agent=data->agents[i] ; agent ; agent=agent->next ) {
			node = add_mi_node_child( rpl, MI_DUP_VALUE, "Agent", 5,
					agent->id.s, agent->id.len );
			if (node==NULL)
					goto error;

			p = int2str( (unsigned long)(agent->ref_cnt), &len);
			attr = add_mi_attr( node, MI_DUP_VALUE, MI_SSTR("Ref"), p, len);
			if (attr==NULL)
					goto error;

			if(!agent->loged_in)
				attr = add_mi_attr( node, MI_DUP_VALUE, "Loged in", 8, "NO", 2);
			else {
				attr = add_mi_attr( node, MI_DUP_VALUE, "Loged in", 8, "YES", 3);
				if (attr==NULL)
					goto error;
				
				switch ( agent->state ) {
					case CC_AGENT_FREE:   state = s_free;   break;
					case CC_AGENT_WRAPUP: state = s_wrapup; break;
					case CC_AGENT_INCALL: state = s_incall; break;
					default: state.s =0;  state.len = 0;
				}
				attr = add_mi_attr( node, MI_DUP_VALUE, "State", 5,
						state.s, state.len );
			
			}
			if (attr==NULL)
					goto error;
		}
	}
	lock_release( data->lock );

	return rpl_tree;

error:
	lock_release( data->lock );
	return 0;
}


static struct mi_root* mi_cc_list_calls(struct mi_root *cmd_tree, void *param)
{
	struct cc_call *call;
	struct cc_agent *agent;
	struct mi_root *rpl_tree;
	struct mi_node *node;
	struct mi_node *rpl;
	struct mi_attr *attr;
	char *p;
	int len;
	static str call_state[12]= {{"none", 4},
			{"welcome", 7},
			{"queued", 6},
			{"toagent", 7},
			{"ended", 5}};

	rpl_tree = init_mi_tree( 200, MI_SSTR("OK") );
	if ( rpl_tree==NULL)
		return NULL;
	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;

	/* block access to data */
	lock_get( data->lock );

	for( call=data->list.first ; call ; call=call->next_list ) {

		node = add_mi_node_child( rpl, MI_DUP_VALUE, "Call", 4,
				call->b2bua_id.s, call->b2bua_id.len);
		if (node==NULL)
				goto error;

		p = int2str( (unsigned long)(call->ref_cnt), &len);
		attr = add_mi_attr( node, MI_DUP_VALUE, MI_SSTR("Ref"), p, len);
		if (attr==NULL)
				goto error;
		if(call->ign_cback)
			attr = add_mi_attr( node, MI_DUP_VALUE, MI_SSTR("State"), MI_SSTR("ignored"));
		else
			attr = add_mi_attr( node, MI_DUP_VALUE, MI_SSTR("State"), call_state[call->state].s, call_state[call->state].len);
		if (attr==NULL)
				goto error;

		LM_DBG("call->recv_time= %d, ticks= %d\n", call->recv_time, get_ticks());
		if(call->state != CC_CALL_ENDED)
		{
			p = int2str( (unsigned long)(call->recv_time?(get_ticks() - call->recv_time):0), &len);
			attr = add_mi_attr( node, MI_DUP_VALUE, MI_SSTR("Call Time"), p, len);
			if (attr==NULL)
				goto error;

			if(call->flow) {
				attr = add_mi_attr( node, MI_DUP_VALUE, MI_SSTR("Flow"), call->flow->id.s, call->flow->id.len);
				if (attr==NULL)
					goto error;
			}
		}
		if(call->agent) {
				agent = call->agent;
				attr = add_mi_attr( node, MI_DUP_VALUE, MI_SSTR("Agent"), agent->id.s, agent->id.len);
				if (attr==NULL)
					goto error;	
		}

	}
	
	lock_release( data->lock );

	return rpl_tree;

error:
	lock_release( data->lock );
	return 0;
}


/* FORMAT :  agent_id  log_state */
static struct mi_root* mi_agent_login(struct mi_root *cmd_tree, void *param)
{
	struct mi_node *node;
	struct cc_agent *agent;
	unsigned int loged_in;
	struct cc_agent* prev_agent= 0;

	node = cmd_tree->node.kids;

	if (node==NULL || node->next==NULL || node->next->next!=NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	/* block access to data */
	lock_get( data->lock );

	/* name of the agent */
	agent = get_agent_by_name( data, &node->value, &prev_agent);
	if (agent==NULL) {
		lock_release( data->lock );
		return init_mi_tree( 404, MI_SSTR("Agent not found") );
	}

	/* login state */
	node = node->next;
	if (str2int( &node->value , &loged_in)!=0 ) {
		lock_release( data->lock );
		return init_mi_tree( 400, MI_SSTR("Bad loged_in state") );
	}

	if (agent->loged_in != loged_in) {

		if(loged_in && (agent->state==CC_AGENT_WRAPUP) &&
			(get_ticks() - agent->last_call_end > wrapup_time))
			agent->state = CC_AGENT_FREE;

		if(loged_in && data->agents[CC_AG_ONLINE] == NULL)
			data->last_online_agent = agent;

		agent_switch_login(data, agent, prev_agent);
		
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

	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
}


static struct mi_root* mi_reset_stats(struct mi_root *cmd_tree, void *param)
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
	reset_stat( stg_aban_incalls );

	/* block access to data */
	lock_get( data->lock );

	/* reset flow stats */
	for ( flow = data->flows ; flow ; flow = flow->next ) {
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
	for(i = 0; i< 2; i++) {
		for ( agent = data->agents[i] ; agent ; agent = agent->next ) {
			reset_stat( agent->st_dist_incalls );
			reset_stat( agent->st_answ_incalls );
			reset_stat( agent->st_aban_incalls );
			agent->avg_talktime = 0;
			agent->avg_talktime_no = 0;
		}
	}

	/* release the readers */
	lock_release( data->lock );

	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
}


static struct mi_root* mi_cc_list_queue(struct mi_root *cmd_tree, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *node;
	struct mi_attr *attr;
	struct mi_node *rpl;
	struct cc_call *call;
	unsigned int n, now;
	char *p;
	int len;
	str *s;

	rpl_tree = init_mi_tree( 200, MI_SSTR("OK") );
	if ( rpl_tree==NULL)
		return NULL;
	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;

	n = 0;
	now = get_ticks();

	/* block access to data */
	lock_get( data->lock );

	for ( call=data->queue.first ; call ; call=call->lower_in_queue, n++) {

		p = int2str( (unsigned long)n, &len);
		node = add_mi_node_child( rpl, MI_DUP_VALUE, "Call", 4, p, len);
		if (node==NULL)
				goto error;

		p = int2str( (unsigned long)(now-call->last_start), &len);
		attr = add_mi_attr( node, MI_DUP_VALUE, "Waiting for", 11, p, len);
		if (attr==NULL)
				goto error;

		p = int2str( (unsigned long)(call->eta), &len);
		attr = add_mi_attr( node, MI_DUP_VALUE, "ETW", 3, p, len);
		if (attr==NULL)
				goto error;

		/* flow data */
		node = add_mi_node_child( node, MI_DUP_VALUE, "Flow", 4,
				call->flow->id.s, call->flow->id.len);
		if (node==NULL)
				goto error;

		p = int2str( (unsigned long)(call->flow->priority), &len);
		attr = add_mi_attr( node, MI_DUP_VALUE, "Priority", 8, p, len);
		if (attr==NULL)
				goto error;

		s = get_skill_by_id(data,call->flow->skill);
		if (s) {
			attr = add_mi_attr( node, MI_DUP_VALUE, "Skill", 5, s->s, s->len);
			if (attr==NULL)
					goto error;
		}
	}

	/* release the readers */
	lock_release( data->lock );

	return rpl_tree;
error:
	lock_release( data->lock );
	free_mi_tree(rpl_tree);
	return NULL;
}


