/*
 * call center module - call queuing and distributio
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
 */



#ifndef CC_CC_DATA_H_
#define CC_CC_DATA_H_

#include "../../str.h"
#include "../../locking.h"
#include "../../hash_func.h"
#include "../../parser/msg_parser.h"
#include "../../map.h"


#define CC_SKILL_MAX_SIZE 65 //it is 64 in db designed

typedef enum {
	AUDIO_WELCOME,
	AUDIO_QUEUE,
	AUDIO_DISSUADING,
	AUDIO_FLOW_ID,
	MAX_AUDIO
} audio_files;

struct cc_rel {
    str id; // can be flowid or agentid
    struct cc_rel* next;
    struct cc_rel** prev; // 2 direction linked list to help remove item in O(1)
};

struct cc_flow {
	str id;
	unsigned int is_new;
	/* configuration data */
	unsigned int priority;
	str skill;
	unsigned int max_wrapup;
	unsigned int diss_hangup;
	unsigned int diss_ewt_th;
	unsigned int diss_qsize_th;
	unsigned int diss_onhold_th;
	str recordings[MAX_AUDIO];
	str cid;
	/* runtime data */
	int ref_cnt;
	float avg_call_duration;
	unsigned long processed_calls;
	unsigned int logged_agents;
	unsigned int ongoing_calls;
    struct cc_rel *last_selected_agent; //round-robin cursor to pick an agent for a call
	/* statistics */
	stat_var *st_incalls;
	stat_var *st_dist_incalls;
	stat_var *st_answ_incalls;
	stat_var *st_aban_incalls;
	stat_var *st_onhold_calls;
	stat_var *st_queued_calls;
	float avg_waittime;
	unsigned long avg_waittime_no;
    struct cc_rel *online_agents; //linked list of online agent relationship
    map_t agents; //AVL tree of all agent relationship (cc_rel)

	struct cc_flow *next;
};


typedef enum {
	CC_AGENT_FREE,
	CC_AGENT_WRAPUP,
	CC_AGENT_INCALL
}agent_state;

struct cc_agent {
	str id;
	unsigned int is_new;
	/* configuration data */
	str location; /* sip address*/
	str did;  /* shorcut for username in sips address */
	unsigned int wrapup_time;
	/* runtime data */
	int ref_cnt;
	agent_state state;
	unsigned int loged_in;
	/* seconds to the end of wrap up (relative to internal time)*/
	int wrapup_end_time;
	/* statistics */
	stat_var *st_dist_incalls;
	stat_var *st_answ_incalls;
	stat_var *st_aban_incalls;
	float avg_talktime;
	unsigned long avg_talktime_no;
    struct cc_rel *flows;

	struct cc_agent *next;
};


struct cc_list {
	unsigned int lid;
	unsigned int calls_no;
	struct cc_call *first;
	struct cc_call *last;
};


#define CC_AG_OFFLINE 0
#define CC_AG_ONLINE  1

struct cc_data {
	gen_lock_t *lock;
	map_t flows; //flows AVL
	map_t agents; //agents AVL
	struct cc_list queue;
	struct cc_list list;
	/* call related data */
	gen_lock_set_t *call_locks;
	unsigned int next_lock_to_use;
	struct cc_call *calls;
	/* tracking data */
	unsigned int logedin_agents;
	float avt_waittime;
	unsigned long avt_waittime_no;
	unsigned long totalnr_agents;
};


typedef enum {
	CC_CALL_NONE,
	CC_CALL_WELCOME,
	CC_CALL_DISSUADING1,
	CC_CALL_DISSUADING2,
	CC_CALL_QUEUED,
	CC_CALL_PRE_TOAGENT,
	CC_CALL_TOAGENT,
	CC_CALL_ENDED
} call_state;

static inline str *call_state_str(call_state state)
{
	static str call_state_s[] = {
		str_init("none"),
		str_init("welcome"),
		str_init("dissuading1"),
		str_init("dissuading2"),
		str_init("queued"),
		str_init("preagent"),
		str_init("toagent"),
		str_init("ended"),
		/* unused */
		str_init("unknown"),
	};
	int size = (sizeof(call_state_s)/sizeof(call_state_s[0]));
	return &call_state_s[(state < size - 1)?state:size - 1];
}

#define FSTAT_INCALL  (1<<0)
#define FSTAT_DIST    (1<<1)
#define FSTAT_ANSW    (1<<2)
#define FSTAT_ABAN    (1<<3)

struct cc_call {
	unsigned int id;
	unsigned int lock_idx;
	char ign_cback; /* ignore callbacks because agent_free was called */
	int fst_flags;  /* flow stats flags */
	call_state state; /* call state */
	call_state prev_state;
	short ref_cnt; 
	short no_rejections;
	short setup_time;
	unsigned int eta;
	unsigned int last_start;
	unsigned int queue_start;
	unsigned int recv_time;
	str caller_dn;
	str caller_un;
	str script_param;
	/* b2b id */
	str b2bua_id;
	/* b2b agent id */
	str b2bua_agent_id;
	/* flow the call belong to */
	//struct cc_flow *flow;
    str flow;
    unsigned int priority;
	/* agent taking this call  */
	//struct cc_agent *agent;
    str agent;
	/* queue-ing link */
	struct cc_call *higher_in_queue;
	struct cc_call *lower_in_queue;
	struct cc_call *next_list;
	struct cc_call *prev_list;
};

#define is_call_in_queue(_data, _call)  ((_call)->lower_in_queue || (_call)->higher_in_queue || \
		(_data->queue.first==_call && _data->queue.last==_call))

struct cc_data* init_cc_data(void);

void free_cc_data(struct cc_data *data);

int add_cc_flow( struct cc_data *data, str *id, int priority, str *skill,
		str *cid, int max_wrapup, int diss_hangup, int diss_ewt_th,
		int diss_qsize_th, int diss_onhold_th, str *recordings );

void update_cc_agent_att(struct cc_agent *agent, unsigned long duration);

int add_cc_agent( struct cc_data *data, str *id, str *location,
		unsigned int logstate, unsigned int wrapup_time,
		unsigned int wrapup_end_time);

void update_cc_flow_awt(struct cc_flow *flow, unsigned long duration);

struct cc_agent* get_agent_by_name(struct cc_data *data, str *name);

struct cc_flow *get_flow_by_name(struct cc_data *data, str *name);

struct cc_call* new_cc_call(struct cc_data *data, struct cc_flow *flow,
		str *dn, str *un, str *param);

void free_cc_call(struct cc_data *data, struct cc_call *call);

struct cc_agent* get_free_agent(struct cc_data *data,
		struct cc_flow *flow);

int link_agent_to_flow(struct cc_data *data, struct cc_agent *agent, struct cc_flow *flow);

void unlink_agent_from_flows(struct cc_data *data, struct cc_agent *agent);

void log_agent_to_flow(struct cc_data *data, struct cc_agent *agent,
		struct cc_flow* flow, int login);

void log_agent_to_flows(struct cc_data *data, struct cc_agent *agent,
		int login);

void agent_raise_event(struct cc_agent *agent, struct cc_call *call);

void clean_cc_unref_data(struct cc_data *data);

void clean_cc_data(struct cc_data *data);

int cc_queue_push_call(struct cc_data *data, struct cc_call *call, int top);

struct cc_call *cc_queue_pop_call_for_agent(struct cc_data *data,
		struct cc_agent *agent);

void cc_queue_rmv_call( struct cc_data *data, struct cc_call *call);

static inline void agent_switch_login(struct cc_data* data, struct cc_agent* agent)
{
	agent->loged_in ^= 1;
	agent_raise_event( agent, NULL);
}

int cc_set_call_agent(struct cc_data *data, struct cc_call* call, struct cc_agent* agent);

void free_cc_call_agent(struct cc_data *data, struct cc_call* call);
#endif
