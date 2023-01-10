/*
 * call center module - call queuing and distributio
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



#include <stdio.h>

#include "../../mem/shm_mem.h"
#include "../../parser/parse_uri.h"
#include "../../locking.h"
#include "../../ut.h"
#include "../../trim.h"
#include "../../timer.h"
#include "../../evi/evi.h"
#include "../b2b_logic/b2b_load.h"
#include "cc_data.h"


/* b2b logic API */
extern b2bl_api_t b2b_api;

extern unsigned int wrapup_time;

/* events */
static str agent_event = str_init("E_CALLCENTER_AGENT_REPORT");
static event_id_t agent_evi_id;

static void free_cc_flow( void *ptr);
static void free_cc_agent( void *ptr);
unsigned long cc_flow_free_agents( void *flow);
static void free_cc_rel(void *ptr);


struct cc_data* init_cc_data(void)
{
	struct cc_data *data;

	data = (struct cc_data*) shm_malloc( sizeof(struct cc_data) );
	if (data==NULL) {
		LM_ERR("failed to allocate shm mem\n");
		return NULL;
	}
	memset( data, 0, sizeof(struct cc_data));

	/* create & init lock */
	if ( (data->lock=lock_alloc())==0) {
		LM_CRIT("failed to alloc lock\n");
		goto error;
	}
	if (lock_init(data->lock)==0 ) {
		LM_CRIT("failed to init lock\n");
		goto error;
	}

	/* set of locks for calls */
	if ( (data->call_locks=lock_set_alloc(512))==0) {
		LM_CRIT("failed to alloc set of call locks\n");
		goto error;
	}
	if (lock_set_init(data->call_locks)==0 ) {
		LM_CRIT("failed to init set of call locks\n");
		goto error;
	}

	agent_evi_id = evi_publish_event(agent_event);
	if (agent_evi_id == EVI_ERROR) {
		LM_ERR("cannot register %.*s event\n", agent_event.len, agent_event.s);
		goto error;
	}
    
    data->flows = map_create(AVLMAP_SHARED);
    data->agents = map_create(AVLMAP_SHARED);

	return data;
error:
	free_cc_data(data);
	return NULL;
}


void free_cc_data(struct cc_data *data)
{
	if (data) {
		/* lock */
		if (data->lock) {
			lock_destroy( data->lock );
			lock_dealloc( data->lock );
		}
		if (data->call_locks) {
			lock_set_destroy( data->call_locks );
			lock_set_dealloc( data->call_locks );
		}
		/* flows */
        map_destroy(data->flows, free_cc_flow);
		/* agents */
        map_destroy(data->agents, free_cc_agent);
		shm_free(data);
	}
}


struct cc_flow *get_flow_by_name(struct cc_data *data, str *name)
{
	void** ptr = map_find(data->flows, *name);
    
    if (ptr) {
        return (struct cc_flow*)*ptr;
    }
    
    return NULL;
}


struct cc_agent* get_agent_by_name(struct cc_data *data, str *name)
{
	void** ptr = map_find(data->agents, *name);
    
    if (ptr) {
        return (struct cc_agent*)*ptr;
    }
	return NULL;
}


void update_cc_flow_awt(struct cc_flow *flow, unsigned long duration)
{
	flow->avg_waittime_no ++;
	flow->avg_waittime =
		( ((float)duration + (flow->avg_waittime * (float)(flow->avg_waittime_no-1))) ) /
		(float)flow->avg_waittime_no;
}

#ifdef STATISTICS
static unsigned long cc_flow_get_etw( void *flow_p)
{
	struct cc_flow *flow = (struct cc_flow*)flow_p;

	return flow->logged_agents? (unsigned long)(( flow->avg_call_duration * get_stat_val(flow->st_queued_calls) ) /
		(float)flow->logged_agents):0;
}


static unsigned long cc_flow_get_awt( void *flow_p)
{
	return (unsigned long)((struct cc_flow*)flow_p)->avg_waittime;
}


static unsigned long cc_flow_get_load( void *flow_p)
{
	struct cc_flow *flow = (struct cc_flow*)flow_p;

	return (flow->logged_agents==0) ? 0 :
	(100*(get_stat_val(flow->st_onhold_calls)+flow->logged_agents-cc_flow_free_agents(flow))/flow->logged_agents);
}
#endif


int add_cc_flow( struct cc_data *data, str *id, int priority, str *skill,
		str *cid, int max_wrapup, int diss_hangup, int diss_ewt_th, 
		int diss_qsize_th, int diss_onhold_th, str *recordings )
{
	struct cc_flow *flow, *dup_flow;
	unsigned int i;
#ifdef STATISTICS
	char *name;
	str s;
#endif

    /* new flow -> create and populate one */
    flow = (struct cc_flow*)shm_malloc(sizeof(struct cc_flow) + id->len);
    if (flow==NULL) {
        LM_ERR("not enough shmem for a new flow\n");
        goto error;
    }
    memset( flow, 0, sizeof(struct cc_flow) );
    /* id */
    flow->id.s = (char*)(flow+1);
    memcpy( flow->id.s, id->s, id->len);
    flow->id.len = id->len;
    /* priority */
    flow->priority = priority;
    /* max wrapup time */
    flow->max_wrapup = max_wrapup;
    /* dissuading related options */
    flow->diss_hangup = diss_hangup;
    flow->diss_ewt_th = diss_ewt_th;
    flow->diss_qsize_th = diss_qsize_th;
    flow->diss_onhold_th = diss_onhold_th;
    /* skill */
    flow->skill.s = (char*)shm_malloc(skill->len);
    if (flow->skill.s == NULL) {
        LM_ERR("not enough shmem for the skill of the flow\n");
        goto error;
    }
    memcpy(flow->skill.s, skill->s, skill->len);
    flow->skill.len = skill->len;
    /* cid */
    if (cid && cid->s && cid->len) {
        flow->cid.s = (char*)shm_malloc(cid->len);
        if (flow->cid.s==NULL) {
            LM_ERR("not enough shmem for the cid of the flow\n");
            goto error;
        }
        memcpy( flow->cid.s, cid->s, cid->len);
        flow->cid.len = cid->len;
    }
    /* audio messages */
    for( i=0 ; i<MAX_AUDIO ; i++ ) {
        if (recordings[i].s && recordings[i].len) {
            flow->recordings[i].s = (char*)shm_malloc(recordings[i].len);
            if (flow->recordings[i].s==NULL) {
                LM_ERR("not enough shmem for the message %d of the flow\n",
                    i);
                goto error;
            }
            memcpy( flow->recordings[i].s, recordings[i].s,
                recordings[i].len);
            flow->recordings[i].len = recordings[i].len;
        }
    }
    
    flow->online_agents = NULL;
    flow->agents = map_create(AVLMAP_SHARED);
    
#ifdef STATISTICS
    /* statistics */
    s.s = "ccf_incalls";s.len = 11 ;
    if ( (name=build_stat_name( &s, id->s))==0 || register_stat("call_center",
    name, &flow->st_incalls, STAT_SHM_NAME)!=0 ) {
        LM_ERR("failed to add stat variable\n");
        goto error;
    }
    s.s = "ccf_dist_incalls";s.len = 15 ;
    if ( (name=build_stat_name( &s, id->s))==0 || register_stat("call_center",
    name, &flow->st_dist_incalls, STAT_SHM_NAME)!=0 ) {
        LM_ERR("failed to add stat variable\n");
        goto error;
    }
    s.s = "ccf_answ_incalls";s.len = 15 ;
    if ( (name=build_stat_name( &s, id->s))==0 || register_stat("call_center",
    name, &flow->st_answ_incalls, STAT_SHM_NAME)!=0 ) {
        LM_ERR("failed to add stat variable\n");
        goto error;
    }
    s.s = "ccf_aban_incalls";s.len = 15 ;
    if ( (name=build_stat_name( &s, id->s))==0 || register_stat("call_center",
    name, &flow->st_aban_incalls, STAT_SHM_NAME)!=0 ) {
        LM_ERR("failed to add stat variable\n");
        goto error;
    }
    s.s = "ccf_onhold_calls";s.len = 15 ;
    if ( (name=build_stat_name( &s, id->s))==0 || register_stat("call_center",
    name, &flow->st_onhold_calls, STAT_SHM_NAME)!=0 ) {
        LM_ERR("failed to add stat variable\n");
        goto error;
    }
    s.s = "ccf_queued_calls";s.len = 16 ;
    if ( (name=build_stat_name( &s, id->s))==0 || register_stat("call_center",
    name, &flow->st_queued_calls, STAT_SHM_NAME|STAT_NO_RESET)!=0 ) {
        LM_ERR("failed to add stat variable\n");
        goto error;
    }
    s.s = "ccf_etw";s.len = 7 ;
    if ( (name=build_stat_name( &s, id->s))==0 || register_stat2("call_center",
    name, (stat_var **)cc_flow_get_etw, STAT_SHM_NAME|STAT_IS_FUNC,
    (void*)flow, 0)!=0) {
        LM_ERR("failed to add stat variable\n");
        goto error;
    }
    s.s = "ccf_awt";s.len = 7 ;
    if ( (name=build_stat_name( &s, id->s))==0 || register_stat2("call_center",
    name, (stat_var **)cc_flow_get_awt, STAT_SHM_NAME|STAT_IS_FUNC,
    (void*)flow, 0)!=0) {
        LM_ERR("failed to add stat variable\n");
        goto error;
    }
    s.s = "ccf_load";s.len = 8 ;
    if ( (name=build_stat_name( &s, id->s))==0 || register_stat2("call_center",
    name, (stat_var **)cc_flow_get_load, STAT_SHM_NAME|STAT_IS_FUNC,
    (void*)flow, 0)!=0) {
        LM_ERR("failed to add stat variable\n");
        goto error;
    }
    s.s = "ccf_free_agents";s.len = 15 ;
    if ( (name=build_stat_name( &s, id->s))==0 || register_stat2("call_center",
    name, (stat_var **)cc_flow_free_agents, STAT_SHM_NAME|STAT_IS_FUNC,
    (void*)flow, 0)!=0) {
        LM_ERR("failed to add stat variable\n");
        goto error;
    }
#endif

    if ((dup_flow = map_put(data->flows, flow->id, flow))) {
        free_cc_flow(dup_flow);
    }

	return 0;

error:
	if (flow)
		free_cc_flow(flow);
	return -1;
}

static void free_cc_flow( void *ptr)
{
	int i;
    struct cc_flow *flow = (struct cc_flow*)ptr;

	if (flow->cid.s)
		shm_free(flow->cid.s);
    if (flow->skill.s) {
        shm_free(flow->skill.s);
    }
	for( i=0 ; i<MAX_AUDIO ; i++ ) {
		if (flow->recordings[i].s)
			shm_free(flow->recordings[i].s);
	}
    
    //free the agent AVL
    map_destroy(flow->agents, free_cc_rel);
	shm_free(flow);
}


void update_cc_agent_att(struct cc_agent *agent, unsigned long duration)
{
	agent->avg_talktime_no ++;
	agent->avg_talktime =
		( ((float)duration + (agent->avg_talktime * (float)(agent->avg_talktime_no-1))) ) /
		(float)agent->avg_talktime_no;
}


#ifdef STATISTICS
static unsigned long cc_agent_get_att( void *agent_p)
{
	return (unsigned long)((struct cc_agent*)agent_p)->avg_talktime;
}
#endif

int add_cc_agent( struct cc_data *data, str *id, str *location,
				unsigned int logstate, unsigned int own_wrapup,
												unsigned int wrapup_end_time)
{
	struct cc_agent *agent, *dup_agent;
	struct sip_uri uri;
#ifdef STATISTICS
	char *name;
	str s;
#endif

    /* new agent -> create and populate one */
    agent = (struct cc_agent*)shm_malloc(sizeof(struct cc_agent)+id->len);
    if (agent==NULL) {
        LM_ERR("not enough shmem for a new agent\n");
        goto error;
    }
    memset( agent, 0, sizeof(struct cc_agent) );
    /* id */
    agent->id.s = (char*)(agent+1);
    memcpy( agent->id.s, id->s, id->len);
    agent->id.len = id->len;
    /* location */
    agent->location.s = (char*)shm_malloc(location->len);
    if (agent->location.s==NULL) {
        LM_ERR("not enough shmem for the location of the agent\n");
        goto error;
    }
    memcpy( agent->location.s, location->s, location->len);
    agent->location.len = location->len;
    if (parse_uri( agent->location.s, agent->location.len, &uri)<0) {
        LM_ERR("location of the agent is not a SIP URI\n");
        goto error;
    }
    agent->did = uri.user;
    /* LOG STATE */
    agent->loged_in = logstate;
    /* WRAPUP TIME */
    agent->wrapup_time = (own_wrapup==0)? wrapup_time : own_wrapup;
    
    agent->flows = NULL;
    
    /* statistics */
#ifdef STATISTICS
    s.s = "cca_dist_incalls";s.len = 16 ;
    if ( (name=build_stat_name( &s, id->s))==0 || register_stat("call_center",
    name, &agent->st_dist_incalls, STAT_SHM_NAME)!=0 ) {
        LM_ERR("failed to add stat variable\n");
        goto error;
    }
    s.s = "cca_answ_incalls";s.len = 16 ;
    if ( (name=build_stat_name( &s, id->s))==0 || register_stat("call_center",
    name, &agent->st_answ_incalls, STAT_SHM_NAME)!=0 ) {
        LM_ERR("failed to add stat variable\n");
        goto error;
    }
    s.s = "cca_aban_incalls";s.len = 16 ;
    if ( (name=build_stat_name( &s, id->s))==0 || register_stat("call_center",
    name, &agent->st_aban_incalls, STAT_SHM_NAME)!=0 ) {
        LM_ERR("failed to add stat variable\n");
        goto error;
    }
    s.s = "cca_att";s.len = 7 ;
    if ( (name=build_stat_name( &s, id->s))==0 || register_stat2("call_center",
    name, (stat_var **)cc_agent_get_att, STAT_SHM_NAME|STAT_IS_FUNC,
    (void*)agent, 0)!=0) {
        LM_ERR("failed to add stat variable\n");
        goto error;
    }
#endif
    if (wrapup_end_time && (wrapup_end_time > (int)time(NULL))) {
        agent->state = CC_AGENT_WRAPUP;
        agent->wrapup_end_time = wrapup_end_time - startup_time;
    }    
    
    if ((dup_agent = map_put(data->agents, agent->id, agent))) {
        free_cc_agent(dup_agent);
    }
    else {
        data->totalnr_agents++;
    }

	return 0;
error:
	if (agent)
		free_cc_agent(agent);
	return 0;
}


static void free_cc_agent( void *ptr)
{
    struct cc_agent *agent = (struct cc_agent *)ptr;
    struct cc_rel *rel, *tmp_rel;
	if (agent->location.s)
		shm_free(agent->location.s);
    
    rel = agent->flows;
    while (rel) {
        tmp_rel = rel->next;
        shm_free(rel);
        rel = tmp_rel;
    }
    
	shm_free(agent);
}


void print_call_list(struct cc_data *data)
{
	struct cc_call *call;
	
	for( call=data->list.first ; call ; call=call->next_list )
		LM_DBG("[%.*s] - %p\n", call->b2bua_id.len, call->b2bua_id.s, call);
}

void cc_list_insert_call(struct cc_data *data, struct cc_call *call)
{
	if(data->list.first)
		data->list.first->prev_list = call;
	call->next_list= data->list.first;
	data->list.first = call;
	call->prev_list = NULL;
	data->list.calls_no++;
	call->id = data->list.lid++;
	print_call_list(data);
}

void cc_list_remove_call(struct cc_data *data, struct cc_call *call)
{
	if(call->prev_list)
		call->prev_list->next_list = call->next_list;
	else
		data->list.first = call->next_list;

	if(call->next_list)
		call->next_list->prev_list = call->prev_list;
	
	data->list.calls_no--;
	print_call_list(data);
}

struct cc_call* new_cc_call(struct cc_data *data, struct cc_flow *flow,
		str *dn, str *un, str *param)
{
	struct cc_call *call;
	char *p;

	/* new call structure */
	call = (struct cc_call*)shm_malloc( sizeof(struct cc_call) +
		(dn?dn->len:0) + (un?un->len:0) + (param?param->len:0) +
        flow->id.len);
	if (call==NULL) {
		LM_ERR("no more shm mem for a new call\n");
		return NULL;
	}
	memset( call, 0, sizeof(struct cc_call) );
	p = (char*)(call+1);

	/*copy DisplayName and UserName */
	if (dn && dn->s) {
		call->caller_dn.s = p;
		call->caller_dn.len = dn->len;
		memcpy( p, dn->s, dn->len );
		p += dn->len;
	}
	if (un && un->s) {
		call->caller_un.s = p;
		call->caller_un.len = un->len;
		memcpy( p, un->s, un->len );
		p += un->len;
	}
	if (param && param->s && param->len) {
		call->script_param.s = p;
		call->script_param.len = param->len;
		memcpy( p, param->s, param->len );
		p += param->len;
	}

	call->recv_time = get_ticks();

	call->setup_time = -1;

	/* attache to flow */
    call->flow.s = p;
    call->flow.len = flow->id.len;
    memcpy(p, flow->id.s, flow->id.len);
    p += flow->id.len;
    
    call->priority = flow->priority;
    
	LM_DBG("created call %p\n", call);

	/* attache a lock */
	call->lock_idx = data->next_lock_to_use++;
	if (data->next_lock_to_use==512)
		data->next_lock_to_use = 0;

	cc_list_insert_call( data, call );

	return call;
}


void free_cc_call(struct cc_data * data, struct cc_call *call)
{
	lock_get( data->lock );

	cc_list_remove_call( data, call );

	lock_release( data->lock );

	LM_DBG("free call %p, [%.*s]\n", call, call->b2bua_id.len, call->b2bua_id.s);
	free_cc_call_agent(data, call);

	if(call->b2bua_id.s)
		shm_free(call->b2bua_id.s);

	if (call->b2bua_agent_id.s)
		shm_free(call->b2bua_agent_id.s);

	shm_free(call);
}


struct cc_agent* get_free_agent(struct cc_data *data, struct cc_flow *flow)
{
	struct cc_agent *agent;
    struct cc_rel *rel;

	if (flow->last_selected_agent == NULL) {
        flow->last_selected_agent = flow->online_agents;
    } else {
        agent = get_agent_by_name(data, &flow->last_selected_agent->id);
        if (!agent || !agent->loged_in) {
            flow->last_selected_agent = flow->online_agents;
        }
    }
	if (flow->last_selected_agent == NULL) return NULL;

	/* iterate from cursor the end of agent list*/
    for(rel = flow->last_selected_agent->next; rel; rel = rel->next) {
        agent = get_agent_by_name(data, &(rel->id));
		if (agent && agent->state == CC_AGENT_FREE) {
			flow->last_selected_agent = rel;
            return agent;
		}
	}
    
    /* iterate from start of agent list to cursor */
    for(rel = flow->online_agents; rel && rel != flow->last_selected_agent->next; rel = rel->next) {
        agent = get_agent_by_name(data, &(rel->id));
		if (agent && agent->state==CC_AGENT_FREE) {
			flow->last_selected_agent = rel;
			return agent;
		}
	};

	return NULL;
}


void log_agent_to_flow(struct cc_data *data, struct cc_agent *agent, struct cc_flow *flow, int login) {
    struct cc_rel *rel;
    void ** ptr;
    
    flow->logged_agents = flow->logged_agents + (login?1:-1);
    
    ptr = map_find(flow->agents, agent->id);
    if (!ptr) {
        LM_ERR("Agent %.*s is not linked to flow %.*s\n", agent->id.len, agent->id.s, flow->id.len, flow->id.s);
        return;
    }
    rel = (struct cc_rel*)*ptr;
            
    if (login) {
        if (rel->next || rel->prev) {
            LM_DBG("Agent %.*s is already logged in to flow %.*s, ignore duplication login", agent->id.len, agent->id.s, flow->id.len, flow->id.s);
        }
        else {
            rel->next = flow->online_agents;
            if (flow->online_agents) flow->online_agents->prev = &(rel->next);
            flow->online_agents = rel;
            rel->prev = &(flow->online_agents);
        }
    }
    else {
        //remove agent from online list of the flow
        *rel->prev = rel->next;
        if (flow->last_selected_agent == rel) {
            flow->last_selected_agent = rel->next;
        }        
        rel->prev = NULL;
        rel->next = NULL;
    }
}


void log_agent_to_flows(struct cc_data *data, struct cc_agent *agent, int login)
{
	struct cc_flow *flow;
    struct cc_rel *rel;

	LM_DBG("login %d agent %.*s\n", login, agent->id.len, agent->id.s);
	
    for( rel=agent->flows ; rel ; rel=rel->next ) {
        //LM_DBG("chekcing flow %.*s with skill %d\n", flow->id.len, flow->id.s, flow->skill);
        flow = get_flow_by_name(data, &(rel->id));
        if (flow) {
            log_agent_to_flow(data, agent, flow, login);
        }
    }
}

int link_agent_to_flow(struct cc_data *data, struct cc_agent *agent, struct cc_flow *flow) {
    struct cc_rel *rel;
    
    if (flow && agent) {
        // allocate a single relation for a single agent,
        // this will be added to online list if agent is online
        rel = (struct cc_rel*)shm_malloc(sizeof(struct cc_rel) + agent->id.len);
        rel->id.s = (char*)(rel + 1);
        memcpy(rel->id.s, agent->id.s, agent->id.len);
        rel->id.len = agent->id.len;
        rel->next = NULL;
        rel->prev = NULL;
        
        // add agent to flow AVL
        map_put(flow->agents, agent->id, rel);
        
        // add flow relation to agent object
        rel = (struct cc_rel*)shm_malloc(sizeof(struct cc_rel) + flow->id.len);
        rel->id.s = (char*)(rel + 1);
        memcpy(rel->id.s, flow->id.s, flow->id.len);
        rel->id.len = flow->id.len;
        rel->next = agent->flows;
        agent->flows = rel;
        
        // log agent in
        if (agent->loged_in) {
            log_agent_to_flow(data, agent, flow, 1);
        }
        
        return 0;
    }
    
    return -1;
}

void unlink_agent_from_flows(struct cc_data *data, struct cc_agent *agent) {
    struct cc_rel *rel, *tmp_rel;
    struct cc_flow *flow;
    
    rel = agent->flows;
    while (rel) {
        flow = get_flow_by_name(data, &(rel->id));
        
        // log out
        if (agent->loged_in) {
            log_agent_to_flow(data, agent, flow, 0);
        }
        
        // unlink
        if (flow) {
            map_remove(flow->agents, agent->id);
        }
        
        tmp_rel = rel->next;
        shm_free(rel);
        rel = tmp_rel;
    }
}


void clean_cc_unref_data(struct cc_data *data)
{
    //not useful anymore
	return;
}

void clean_cc_data(struct cc_data *data) {
    map_destroy(data->flows, free_cc_flow);
    map_destroy(data->agents, free_cc_agent);
    
    data->flows = map_create(AVLMAP_SHARED);
    data->agents = map_create(AVLMAP_SHARED);
}


void print_queue(struct cc_data *data)
{
	struct cc_call *call_it;
	LM_DBG("QUEUE:\n");
	for(call_it=data->queue.first ; call_it ; call_it=call_it->lower_in_queue)
		LM_DBG("[%p] ->\n", call_it);
	LM_DBG("0\n");
}


int cc_queue_push_call(struct cc_data *data, struct cc_call *call, int top)
{
	struct cc_call *call_it;
	int n = 0;
    struct cc_flow *flow;

	LM_DBG(" QUEUE - adding call %p \n",call);
	if ( is_call_in_queue(data, call) ) {
		LM_CRIT(" QUEUE - call already in queue \n");
		abort();
	}

	if (top) {
		/* add the call in the very top of the queue */
		call_it = NULL;
	} else {
		/* search (priority based) the place in queue */
		for(call_it=data->queue.last ; call_it ; call_it=call_it->higher_in_queue){
			if (call_it->priority <= call->priority)
				break;
			n++;
		}
	}


	if (call_it) {
		/* add before it */
		if (call_it->lower_in_queue) {
			call_it->lower_in_queue->higher_in_queue = call;
		} else {
			data->queue.last = call;
		}
		call->lower_in_queue = call_it->lower_in_queue;
		call->higher_in_queue = call_it;
		call_it->lower_in_queue = call;
	} else {
		/* add in top of the queue */
		call->lower_in_queue = data->queue.first;
		if (data->queue.first) {
			data->queue.first->higher_in_queue = call;
		}
		else {
			data->queue.last = call;
		}
		call->higher_in_queue = NULL;
		data->queue.first = call;
	}
	data->queue.calls_no++;
    
    flow = get_flow_by_name(data, &(call->flow));
    
	if (flow) update_stat( flow->st_queued_calls, +1 );
	
	LM_DBG("adding call on pos %d (already %d calls), l=%p h=%p\n",
		n, data->queue.calls_no,
		call->lower_in_queue, call->higher_in_queue);
	call->ref_cnt++;

	if (call->queue_start==0)
		call->queue_start = get_ticks();

	return data->queue.calls_no-1-n;
}



void cc_queue_rmv_call( struct cc_data *data, struct cc_call *call)
{
    struct cc_flow *flow;
    
	LM_DBG(" QUEUE - removing call %p \n",call);
	if ( !is_call_in_queue(data, call) ) { 
		LM_CRIT(" QUEUE - call not in queue l=%p, h=%p\n",
				call->lower_in_queue, call->higher_in_queue);
		abort();
	}

	if (call->lower_in_queue) {
		call->lower_in_queue->higher_in_queue =
			call->higher_in_queue;
	} else {
		data->queue.last = call->higher_in_queue;
	}
	if (call->higher_in_queue) {
		call->higher_in_queue->lower_in_queue =
			call->lower_in_queue;
	} else {
		data->queue.first = call->lower_in_queue;
	}
	call->lower_in_queue = call->higher_in_queue = NULL;
	data->queue.calls_no--;
    
    flow = get_flow_by_name(data, &(call->flow));
    if (flow==NULL) {
        LM_ERR("flow <%.*s> does not exists, it may be deleted\n", call->flow.len, call->flow.s);
    }
    else {
        update_stat( flow->st_queued_calls, -1 );
    }
}



struct cc_call *cc_queue_pop_call_for_agent(struct cc_data *data,
													struct cc_agent *agent)
{
	struct cc_call *call_it;
    struct cc_flow *flow;

	/* interate all the queued calls and see *
	 * if they mathe the agent (as skills)*/
	for(call_it=data->queue.first ; call_it ; call_it=call_it->lower_in_queue){
        /* before taking a call out, be sure that call is fully initialized 
         * from b2bua point of view (to avoid races) -> check the b2bua id */
        flow = get_flow_by_name(data, &(call_it->flow));
        if (call_it->b2bua_id.len!=0 && flow && map_find(flow->agents, agent->id)) {
            LM_DBG("found call %p for agent %p(%.*s) \n",
                call_it, agent, agent->id.len, agent->id.s);
            // remove the call from queue
            cc_queue_rmv_call( data, call_it);
            return call_it;
        }
	}

	return NULL;
}


void agent_raise_event(struct cc_agent *agent, struct cc_call *call)
{
	static str agent_id_str = str_init("agent_id");
	static str status_str = str_init("status");
	static str status_offline_str = str_init("offline");
	static str status_free_str = str_init("free");
	static str status_incall_str = str_init("incall");
	static str status_wrapup_str = str_init("wrapup");
	static str wrapup_ends_str = str_init("wrapup_ends");
	static str flow_id_str = str_init("flow_id");

	evi_params_p list;
	str *txt = NULL;
	int ts;

	if (agent_evi_id == EVI_ERROR || !evi_probe_event(agent_evi_id))
		return;

	list = evi_get_params();
	if (!list) {
		LM_ERR("cannot create event params\n");
		return;
	}

	if (evi_param_add_str(list, &agent_id_str, &agent->id) < 0) {
		LM_ERR("cannot add agent_id\n");
		goto error;
	}

	if (!agent->loged_in) {
		txt = &status_offline_str;
	} else {
		switch (agent->state) {
			case CC_AGENT_FREE:
				txt = &status_free_str;
				break;
			case CC_AGENT_INCALL:
				txt = &status_incall_str;
				break;
			case CC_AGENT_WRAPUP:
				txt = &status_wrapup_str;
				break;
		}
	}

	if (evi_param_add_str(list, &status_str, txt) < 0) {
		LM_ERR("cannot add state\n");
		goto error;
	}

	if (agent->state==CC_AGENT_WRAPUP) {
		ts = (int)time(NULL)+agent->wrapup_end_time-get_ticks();
		if (evi_param_add_int(list, &wrapup_ends_str, &ts) < 0) {
			LM_ERR("cannot add wrapup time\n");
			goto error;
		}
	}

	if (agent->state==CC_AGENT_INCALL && call) {
		if (evi_param_add_str(list, &flow_id_str, &call->flow) < 0) {
			LM_ERR("cannot add wrapup time\n");
			goto error;
		}
	}


	if (evi_raise_event(agent_evi_id, list)) {
		LM_ERR("unable to send agent report event\n");
	}
	return;

error:
	evi_free_params(list);
}

void free_cc_call_agent(struct cc_data *data, struct cc_call* call) {
    if (call->agent.s) {
        shm_free(call->agent.s);
        call->agent.s = NULL;
        call->agent.len = 0;
    }
}

int cc_set_call_agent(struct cc_data *data, struct cc_call* call, struct cc_agent* agent) {
    if (call->agent.len < agent->id.len) {
        free_cc_call_agent(data, call);
        call->agent.s = (char*)shm_malloc(agent->id.len);
        if (!call->agent.s) {
            return -1;
        }
        call->agent.len = agent->id.len;
        memcpy(call->agent.s, agent->id.s, agent->id.len);
    }
    else {
        memcpy(call->agent.s, agent->id.s, agent->id.len);
        call->agent.len = agent->id.len;
    }
    
    return 0;
}

void free_cc_rel(void *ptr) {
    shm_free(ptr);
}

