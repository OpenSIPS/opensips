---
title: "Call-Center Module"
description: "The Call Center module implements an inbound call center system with call flows (for queuing the received calls) and agents (for answering the calls)."
---

## Admin Guide


### Overview


The Call Center module implements an inbound call center system with call 
	flows (for queuing the received calls) and agents (for answering the 
	calls).


The module implements the queuing system, the call distribution 
	to agents, agents managements, CDRs for the calls, statistics on 
	call distribution and agent's activity - basically everything 
	except the media playback (for the queue). This part must be provided via 
	a third party media server (FreeSwitch, Asterisk or others).


This is actually a Contact Center and it is able to handle both
	RTP/audio calls and (multiple) MSRP/chat calls, in the same time.


The module provides an internal buit-in dispatching logic (for sending the
	calls/chats to the agents), but also offers the possibility to use an
	external logic to do the dispatching
	(see [mi dispatch call to agent](#mi_dispatch_call_to_agent) MI command).


### How it works


The main entities in the modules are the flows (queues) and agents.


#### DB tables


Each entity has a corresponding table in the database, for 
		provisioning purposes - the *cc_flows* and 
		*cc_agents* tables, see
		[DB schema](https://opensips.org/Documentation/Install-DBSchema--3-3#AEN2656).
		Data is loaded at startup and cached into memory ; runtime reload is 
		possible via the MI commands (see the *call_center:reload* 
		command in [exported mi functions](#exported_mi_functions)).


Additionally there is a table *cc_cdrs* for writing 
		the CDRs - this operation is done in realtime, after the call in 
		completed, covering all possible cases: call was dropped while in 
		queue, call was rejected by agent, call was accepted by agent, call 
		terminated with error - NOTE that a call may generate more than one 
		CDR (like call rejected by agent A, and redistributed and accepted by 
		agent B).


The *cc_calls* table is used to store ongoing calls,
		regardless it's state (in queue, to the agent, ended). It is populated
		at runtime by the module and queried at startup. This table should not
		be manually provisioned.


#### Call Flows


A flow is defined by a unique alphanumerical ID - the main attribute 
		of a flow is the *skill* - the skill is a 
		capability required by the flow for an agent to be able to answer the 
		call ; the concept of *skills* is the link between 
		the flows and the agents - telling what agents are serving what flows 
		- the flows require a skill, while the agents provide a set of skills. 
		Agents matching the required skill of a flow will automatically 
		receive calls from that flow.


Additional, the flow has a *priority* - as agents 
		may server multiple flows in the same time (based on skills), you can
		define priorities between the flows - if the flows has a higher 
		priority, its calls will be pushed (in deliver to agents and queuing) in
		front of the calls from flows with a lower priority.


Configurable per flow, the module may do per-flow call dissuading; this
		means to redirect a call to another destination, if the queue/flow 
		is overloaded:


- if the number of calls already in the queue exceeds the diss_qsize_th threshold
- if the estimated time to wait of the queue exceeds the diss_ewt_th threshold
- if the call was waiting in the queue for longer than diss_onhold_th threshold


Optionally, the flow may define a *prependcid* - a
		prefix to be added to the CLI (Caller ID) when the call is delivered to
		the agents - as an agent may receive call from multiple flows, it is 
		important for the user to see which was the queue a call was received.


In terms of media announcements, the flow defines the 
		*message_welcome* (optional, to be played in the 
		call, before doing anything with the call) and 
		*message_queue* (mandatory, the looping message
		providing infinite on hold media IMPORTANT - this message must cycle 
		and media server must never hung up on it. Both announcements are 
		provided as SIP URIs (where the call has to be sent in order to get
		the playback).


The flow also has an optional *max_wrapup time*,
		which acts as an upper limit for the per-agent/global value (the flow 
		forces a ceiling of the wrapup value for all its calls).


#### Agents


An agent is defined by a unique alphanumerical ID - the main attribute 
		of an agent is its the set of *skills*. This set of
		skills will tell what calls to be received (from which flows, based on
		the skill matching).


The agent may provide support for different optional media types, like
		RTP/audio or MSRP/chat. Each supported media type comes with the 
		maximum supported number of sessions. Of course, for audio the `1` 
		value is hardocded. On the SIP side, each media type comes with a
		*locations*. The location is a SIP URI where to 
		calls must be sent in order to be answered by the agent. At least one 
		media type should be defined. To specify which media the agent
		support, just define the corresponding SIP location in his profile.


So, at a certain time, an agent may handle either a single call,
		either several chat sessions.


Additionally, the agent has a initial *logstate* - 
		if he is logged in or not (being logged in is a must in order to
		receive calls). The log state may be changed at runtime via a 
		dedicated MI command *call_center:agent_login*, see 
		[exported mi functions](#exported_mi_functions).


There is an optional per-agent *wrapup_time*
		defined, saying the time interval for an agent before getting a new 
		call from the system (after he finished a call). If no value is defined
		for the agent, the global *wrapup_time* will be 
		used. Note that the resulting value may be upper limited by the
		per-flow *max_wrapup_time* if defined.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *b2b_logic* - B2bUA module
- *database* - one of the SQL DB modules


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### db_url (string)


SQL address to the DB server -- database specific. This must be
		the Database holding the provisioning tables (cc_flows, cc_agents
		and cc_calls tables).


```opensips title="Set db_url parameter"
...
modparam("call_center", "db_url", 
	"mysql://opensips:opensipsrw@localhost/opensips")
...
```


#### acc_db_url (string)


SQL address to the DB server -- database specific. This must be
		the Database where the CDRs table (cc_cdrs) is located.


```opensips title="Set acc_db_url parameter"
...
modparam("call_center", "acc_db_url", 
	"mysql://opensips:opensipsrw@localhost/opensips_cdrs")
...
```


#### rt_db_url (string)


SQL address/URL of the DB server (database specific) where the
		runtime tables (non provisioning tables) are located. The
		runtime tables are the tables populated by OpenSIPS with data
		learned during runtime. To be more specific, the only runtime
		table we have so far is the "cc_calls" table.


```opensips title="Set rt_db_url parameter"
...
modparam("call_center", "rt_db_url", 
	"mysql://opensips:opensipsrw@localhost/opensips_runtime")
...
```


#### wrapup_time (integer)


Time for an agent between finishing a call and receiving the next
		call from the system. Even if there are queued calls, the module
		will not deliver call to agent during this wrapup interval.


This value may be overwritten by the per-agent value (if defined)
		and furher more, by the per-flow value (if defined).


*Default value is "30 seconds".*


```opensips title="Set wrapup_time parameter"
...
modparam("call_center", "wrapup_time", 45)
...
```


#### queue_pos_param (string)


The name of an SIP URI parameter to be used to report the position
		in the waiting queue when sending the call to media server for
		onwait/queue playback. The position 0 means it is the next call
		to be delivered to an agent.


*Default value is "empty(none)".*


```opensips title="Set queue_pos_param parameter"
...
modparam("call_center", "queue_pos_param", "cc_pos")
...
```


#### reject_on_no_agents (int)


A parameter to tell if an incoming call should be rejected or
		quueued if there are no logged in agents. Basically this allows
		call queueing on flows with no agents yet.


*Default value is "1 (true)".*


```opensips title="Set reject_on_no_agents parameter"
...
modparam("call_center", "reject_on_no_agents", 0)
...
```


#### chat_dispatch_policy (int)


A parameter to tell what should be the policy on dispatching the
		chat/MSRP sessions to the agents, considering that an agent may
		handle multiple such sessions/chats in the same time.


Options are:


- **balancing** - the distribution
			will try to be even across the agents, but by doing this you may 
			end up waisting chat sessions on agents and call starvation -
			agents are partially used by chat sessions, so they cannot take
			calls (of course, if you have mixed agetns with audio/chat)
- **full-load** - the distribution
			will try to make usage of an agent in the best possible way when
			comes to chat sessions - once the agent take a chat, all the
			following chats will be assigned ot him - the idea is to try to 
			be efficient in using the resource/sessions of an agents, to leave
			as much room as possible for calls. Of course, this may lead to an
			un-even loading of chat agents - some will be full, others empty.


*Default value is "balancing".*


```opensips title="Set chat_dispatch_policy parameter"
...
modparam("call_center", "chat_dispatch_policy", "balancing")
...
```


#### internal_call_dispatching (int)


A parameter to tell if the internal/buit-in call dispatching to agent
		should be used or not. If enabled, the module will automatically
		dispatch (by itself) the queued/incoming calls to the available agents.
		If disabled, the module will not do such dispaching by itself and it
		is expected to use the  [mi dispatch call to agent](#mi_dispatch_call_to_agent)
		MI command to dispatch the queued calls to agents. This allows the
		implementation of an external, custom dispatching logic. The value of
		this setting may be changed during runtime via the 
		[mi internal call dispatching](#mi_internal_call_dispatching) MI command.


*Default value is "1" (enabled).*


```opensips title="Set internal_call_dispatching parameter"
...
modparam("call_center", "internal_call_dispatching", 0)
...
```


#### cc_agents_table (string)


Name to be used for the table holding the agents.


*Default value is "cc_agents".*


```opensips title="Set cc_agents_table parameter"
...
modparam("call_center", "cc_agents_table", "my_agents")
...
```


#### cca_agentid_column (string)


Name to be used for the "agent id" (unique DB id) column in the
		agents table.


*Default value is "agentid".*


```opensips title="Set cca_agentid_column parameter"
...
modparam("call_center", "cca_agentid_column", "cid")
...
```


#### cca_location_column (string)


Name to be used for the calling/audio "location" (SIP URI) column in 
		the agents table.


*Default value is "location".*


```opensips title="Set cca_location_column parameter"
...
modparam("call_center", "cca_location_column", "sip_uri")
...
```


#### cca_msrp_location_column (string)


Name to be used for the msrp/chat "location" (SIP URI) column in the
		agents table.


*Default value is "msrp_location".*


```opensips title="Set cca_msrp_location_column parameter"
...
modparam("call_center", "cca_msrp_location_column", "sip_uri")
...
```


#### cca_msrp_max_sessions_column (string)


Name to be used for the column (in the agents table) holding the 
		maximum number of chat sessions that can be handled by the agent.


*Default value is "msrp_max_sessions".*


```opensips title="Set cca_msrp_max_sessions_column parameter"
...
modparam("call_center", "cca_msrp_max_sessions_column", "max_chats")
...
```


#### cca_skills_column (string)


Name to be used for the "skills" (list of skills) column in the
		agents table.


*Default value is "skills".*


```opensips title="Set cca_skills_column parameter"
...
modparam("call_center", "cca_skills_column", "skills")
...
```


#### cca_logstate_column (string)


Name to be used for the "logstate" (original login state) column in the
		agents table.


*Default value is "logstate".*


```opensips title="Set cca_logstate_column parameter"
...
modparam("call_center", "cca_logstate_column", "log_state")
...
```


#### cca_wrapuptime_column (string)


Name to be used for the "wrapuptime" (per-agent wrapup time) column 
		in the agents table.


*Default value is "wrapup_time".*


```opensips title="Set cca_wrapuptime_column parameter"
...
modparam("call_center", "cca_wrapuptime_column", "wtime")
...
```


#### cca_wrapupend_column (string)


Name to be used for the "wrapupend" (timestamp when the wrapup ends) 
		column in the agents table.


*Default value is "wrapup_end_time".*


```opensips title="Set cca_wrapupend_column parameter"
...
modparam("call_center", "cca_wrapupend_column", "wrapup_ends")
...
```


#### cc_flows_table (string)


Name to be used for the table holding the definition of the
		flows/queues.


*Default value is "cc_flows".*


```opensips title="Set cc_flows_table parameter"
...
modparam("call_center", "cc_flows_table", "queues")
...
```


#### ccf_flowid_column (string)


Name to be used for the "flow id" (unique DB id) column in the
		flows table.


*Default value is "flowid".*


```opensips title="Set ccf_flowid_column parameter"
...
modparam("call_center", "ccf_flowid_column", "queue_id")
...
```


#### ccf_priority_column (string)


Name to be used for the "priority" column in the
		flows table.


*Default value is "priority".*


```opensips title="Set ccf_priority_column parameter"
...
modparam("call_center", "ccf_priority_column", "queue_prio")
...
```


#### ccf_skill_column (string)


Name to be used for the "skill" column in the
		flows table.


*Default value is "skill".*


```opensips title="Set ccf_skill_column parameter"
...
modparam("call_center", "ccf_skill_column", "queue_skill")
...
```


#### ccf_cid_column (string)


Name to be used for the "caller ID prefix" column in the
		flows table.


*Default value is "prependcid".*


```opensips title="Set ccf_cid_column parameter"
...
modparam("call_center", "ccf_cid_column", "queue_cli_prefix")
...
```


#### ccf_max_wrapup_column (string)


Name to be used for the "max limit for wrapup time" column in the
		flows table.


*Default value is "max_wrapup_time".*


```opensips title="Set ccf_max_wrapup_column parameter"
...
modparam("call_center", "ccf_max_wrapup_column", "queue_wrapup")
...
```


#### ccf_dissuading_hangup_column (string)


Name to be used for the "hangup after dissuading" column in the
		flows table.


*Default value is "dissuading_hangup".*


```opensips title="Set ccf_dissuading_hangup_column parameter"
...
modparam("call_center", "ccf_dissuading_hangup_column", "hangup_on_dissuading")
...
```


#### ccf_dissuading_onhold_th_column (string)


Name to be used for the "on-hold dissuading threshold" column in the
		flows table.


*Default value is "dissuading_onhold_th".*


```opensips title="Set ccf_dissuading_onhold_th_column parameter"
...
modparam("call_center", "ccf_dissuading_onhold_th_column", "th_diss_onhold")
...
```


#### ccf_dissuading_ewt_th_column (string)


Name to be used for the "EWT dissuading threshold" column in the
		flows table.


*Default value is "dissuading_ewt_th".*


```opensips title="Set ccf_dissuading_ewt_th_column parameter"
...
modparam("call_center", "ccf_dissuading_ewt_th_column", "th_diss_ewt")
...
```


#### ccf_dissuading_qsize_th_column (string)


Name to be used for the "queue size dissuading threshold" column in the
		flows table.


*Default value is "dissuading_qsize_th".*


```opensips title="Set ccf_dissuading_qsize_th_column parameter"
...
modparam("call_center", "ccf_dissuading_qsize_th_column", "th_diss_qsize")
...
```


#### ccf_m_welcome_column (string)


Name to be used for the "audio message on welcome" column in the
		flows table.


*Default value is "message_welcome".*


```opensips title="Set ccf_m_welcome_column parameter"
...
modparam("call_center", "ccf_m_welcome_column", "audio_welcome")
...
```


#### ccf_m_queue_column (string)


Name to be used for the "audio message on queueing" column in the
		flows table.


*Default value is "message_queue".*


```opensips title="Set ccf_m_queue_column parameter"
...
modparam("call_center", "ccf_m_queue_column", "audio_queue")
...
```


#### ccf_m_dissuading_column (string)


Name to be used for the "audio message on dissuading" column in the
		flows table.


*Default value is "message_dissuading".*


```opensips title="Set ccf_m_dissuading_column parameter"
...
modparam("call_center", "ccf_m_dissuading_column", "audio_dissuading")
...
```


#### ccf_m_flow_id_column (string)


Name to be used for the "audio message on identifying the flow" column
		in the flows table.


*Default value is "message_flow_id".*


```opensips title="Set ccf_m_flow_id_column parameter"
...
modparam("call_center", "ccf_m_flow_id_column", "audio_flow_id")
...
```


#### b2b_logic_ctx_param (string)


The name of the *$b2b_logic.ctx* variable that can be
		used to retrieve the value of the parameter passed to
		the [cc handle call](#func_cc_handle_call) function.


This parameter will be copied throughout all the B2B scenarios started
		by the call_center module. NOTE that you can change the value of the current
		scenario by writing into it, but the change will not be reflected in a
		different scenario.


*Default value is "call_center".*


```opensips title="Set b2b_logic_ctx_param parameter"
...
modparam("call_center", "b2b_logic_ctx_param", "b2b_callid")
...
route[handle_call_center] {
    ...
    cc_handle_call("flow", $ci);
    ...
}
...
route[b2b_handle_request] {
    ...
    xlog("Initial Callid is $b2b_logic.ctx(b2b_callid)\n");
    ...
}
```


### Exported Functions


#### cc_handle_call( flowID [,param])


This must be used only for initial INVITE requests - the function
		pushes the call to be handled by the call center module (via a certain
		flow/queue).


This function can be used from REQUEST_ROUTE.


Parameters:


- *flowID (string)* - the ID of the flow to
				handle this call (push the call to that flow).
- *param (string, optional)* - an opaque
				string to be passed as parameter to the "callcenter" and 
				"agent" B2B scenarios. It is
				intended for custom integration of the call center module and 
				it is 100% up to the script writer about the value and purpose
				of this parameter, OpenSIPS will not touch or interpret it.
				You can retrieve the value of this parameter using the
				*$b2b_logic.ctx* variable with the name
				defined in the [b2b logic ctx param](#param_b2b_logic_ctx_param)
				parameter.


The function returns TRUE back to the script if the call was 
		successfully pushed and handled by the Call Center engine. IMPORTANT: 
		you must not do any signaling on the call (reply, relay) after this
		point.


In case of error, FALSE is returned to the script with the following 
		return codes:


- **-1** - unable to get the flow ID
			from the parameter;
- **-2** - unable to parse the FROM URI;
- **-3** - flow with FlowID not found;
- **-4** - no agents logged in the flow;
- **-5** - internal error;


```opensips title="cc_handle_call usage"
...
if (is_method("INVITE") and !has_totag()) {
	if (!cc_handle_call("tech_support")) {
		send_reply(403,"Cannot handle call");
		exit;
	}
}
...
```


#### cc_agent_login(agentID, state)


This function sets the login (on or off) state for an agent.


This function can be used from REQUEST_ROUTE.


Parameters:


- *agentID (string)* - the ID of the agent
- *state (int)* - an integer value giving
				the new state - 0 means logged off, anything else means logged in.


```opensips title="cc_agent_login usage"
...
# log off the 'agentX' agent
cc_agent_login("agentX",0);
...
```


### Exported Statistics


#### Global statistics


##### ccg_incalls


Total number of received calls. (counter type)


##### ccg_awt


Global avg. waiting time for calls. (realtime type)


##### ccg_load


Global load (across all flows). (realtime type)


##### ccg_distributed_incalls


Total number of distributed calls. (counter type)


##### ccg_answered_incalls


Total number of calls (audio/RTP and chat/MSRP) answered by agents. (counter type)


##### ccg_answered_inchats


Total number of chat/MSRP only calls answered by agents. (counter type)


##### ccg_abandonned_incalls


Total number of calls terminated by caller before being
			answered by agents. (counter type)


##### ccg_onhold_calls


Total number of calls (audio/RTP and chat/MSRP) in the queues (onhold). (realtime type)


##### ccg_onhold_chats


Total number of chat/MSRP only calls in the queues (onhold). (realtime type)


##### ccg_free_agents


Total number of free agents (across all flows). (realtime type)


#### Per-flow statistics (one set for each flow)


##### ccf_incalls_flowID


Number of received calls for the flow. (counter type)


##### ccf_dist_incalls_flowID


Number of distributed calls in this flow. (counter type)


##### ccf_answ_incalls_flowID


Nnumber of calls (audio/RTP and chat/MSRP) from the flow answered by agents. (counter type)


##### ccf_answ_incalls_flowID


Nnumber of chat/MSRP only calls from the flow answered by agents. (counter type)


##### ccf_aban_incalls_flowID


Number of calls (from the flow) terminated by caller before being
			answered by agents. (counter type)


##### ccf_onhold_incalls_flowID


Number of calls (audio/RTP and chat/MSRP) -from the flow- which are onhold.
			 (realtime type)


##### ccf_onhold_inchats_flowID


Number of chat/MSRP only calls -from the flow- which are onhold.
			 (realtime type)


##### ccf_queued_calls_flowID


Number of calls which are queued for this flow. (realtime type)


##### ccf_free_agents_flowID


Number of free agents serving this flow. (realtime type)


##### ccf_etw_flowID


Estimated Time to Wait for this flow. (realtime type)


##### ccf_awt_flowID


Avg. Wating Time for this flow. (realtime type)


##### ccg_load_flowID


The load on the flow (number of queued calls versus number of
			logged agents). (realtime type)


#### Per-agent statistics (one set for each agent)


##### cca_dist_incalls_agnetID


Number of distributed calls to this agent. (counter type)


##### cca_answ_incalls_agentID


Number of calls (audio/RTP and chat/MSRP) answered by the agent. (counter type)


##### cca_answ_inchats_agentID


Number of chat/MSRP only calls answered by the agent. (counter type)


##### cca_aban_incalls_agentID


Number of calls (sent to this agent) terminated by caller before 
			being answered by agents. (counter type)


##### cca_att_agentID


Avg. Talk Time for this agent (realtime type)


### Exported MI Functions


#### call_center:reload


Replaces obsolete MI command: *cc_reload*.


Command to reload flows and agents definition from database.


It takes no parameter.


MI FIFO Command usage:


```bash
opensips-cli -x mi call_center:reload
```


#### call_center:agent_login


Replaces obsolete MI command: *cc_agent_login*.


Command to login an agent into the Call Center engine.


Parameters:


- *agent_id* - ID of the agent
- *state* - the new login state (0 - log off, 1 - log in)


MI FIFO Command usage:


```bash
opensips-cli -x mi call_center:agent_login agentX 0
```


#### call_center:list_queue


Replaces obsolete MI command: *cc_list_queue*.


Command to list all the calls in queuing - for each call, the 
		following attributes will be printed: the call id, the calling
		user info, the flow of the call, for how
		long the call is in the queue, the ETW for the call, call priority 
		and the call skill (inherited from the flow).


It takes no parameter.


MI FIFO Command usage:


```bash
opensips-cli -x mi call_center:list_queue
```


#### call_center:list_flows


Replaces obsolete MI command: *cc_list_flows*.


Command to list all the flows - for each flow, the 
		following attributes will be printed: the flow ID, the avg. call 
		duration, how many calls were processed, how many agents are logged, 
		and how many onging calls are.


It takes no parameter.


MI FIFO Command usage:


```bash
opensips-cli -x mi call_center:list_flows
```


#### call_center:list_agents


Replaces obsolete MI command: *cc_list_agents*.


Command to list all the agents - for each agent, the 
		following attributes will be printed: agent ID, agent login state,
		agent state (free, wrapup, incall) and info on ongoing sessions.


It takes no parameter.


MI FIFO Command usage:


```bash
opensips-cli -x mi call_center:list_agents
```


#### call_center:list_calls


Replaces obsolete MI command: *cc_list_calls*.


Command to list all the ongoing calls - for each call, the 
		following attributes will be printed: call ID, call state 
		(welcome, queued, toagent, ended), call duration, flow it belongs to,
		agent serving the call (if any).


It takes no parameter.


MI FIFO Command usage:


```bash
opensips-cli -x mi call_center:list_agents
```


#### call_center:dispatch_call_to_agent


Replaces obsolete MI command: *cc_dispatch_call_to_agent*.


This function sends a given call (from the queue) to a given agent. For
		the operation to succeed, several conditions must be met:


- the call must be in the queue
- the agent must be logged in
- the agent must support the skill required by the call
- the agent must support the media (RTP/MSRP) requiref by the call
- the agent must have available sessions for the requested media


It takes two parameters.


- *call_id* - the ID of the call, as provided by
			the queue listing MI command [mi list queue](#mi_list_queue)
- *agent_id* - the ID of the call, as provided by
			the agents listing MI command [mi list agents](#mi_list_agents)


IMPORTANT: in order to be used, you need to be sure that the internal
		call dispatching is DISABLED via the
		[internal call dispatching](#param_internal_call_dispatching) module parameter
		or the [mi internal call dispatching](#mi_internal_call_dispatching) MI command.


MI FIFO Command usage:


```bash
opensips-cli -x mi call_center:dispatch_call_to_agent B2B452.dee2.33 agentX
```


#### call_center:internal_call_dispatching


Replaces obsolete MI command: *cc_internal_call_dispatching*.


Command to inspect and/or change the 
		[internal call dispatching](#param_internal_call_dispatching) setting


It takes one optional parameter `dispatching` if the
		value of the setting should be changed. A 0 value means disabling
		the internal dispatching, a non zero means to enable it.


MI FIFO Command usage:


```bash
opensips-cli -x mi call_center:internal_call_dispatching 0
```


#### call_center:reset_stats


Replaces obsolete MI command: *cc_reset_stats*.


Command to reset all counter-like statistics.


It takes no parameter.


MI FIFO Command usage:


```bash
opensips-cli -x mi call_center:reset_stats
```


### Exported Events


#### E_CALLCENTER_AGENT_REPORT


This event is raised when the status of an agent changes.


Parameters:


- *agent_id* - the id of the agent.
- *state* - the status of the agent:
				
					offline
					free
					incall
					wrapup
- *wrapup_ends* - the timestamp when the 
				wrapup state will end; published only if the state is 
				"wrapup"
- *flow_id* - the flow ID that delivered the
				call for this agent; published only if the state is "incall"


### Exported Pseudo-Variables


`$cc_state`
			Returns the state of a call.
			Possible values returned are:
				*welcome* - the welcome message is played.
					*dissuading1* - the first dissuading message is played.
					*dissuading2* - the second dissuading message is played.
					*queue* - the call is in queue.
					*preagent* - the agent is being called.
					*toagent* - the agent is in call.

		
		$rtpquery Usage
		
```opensips

...
	$json(reply) := $rtpquery;
	xlog("Total RTP Stats: $json(reply/totals)\n");
...
```

		
		
	NONE


## Developer Guide


### Available Functions


NONE


## Frequently Asked Questions


**Q: Where can I find more about OpenSIPS?**


Take a look at [https://opensips.org/](https://opensips.org/).


**Q: Where can I post a question about this module?**


First at all check if your question was already answered on one of
			our mailing lists:

E-mails regarding any stable OpenSIPS release should be sent to 
			users@lists.opensips.org and e-mails regarding development versions
			should be sent to devel@lists.opensips.org.

If you want to keep the mail private, send it to 
			users@lists.opensips.org.


**Q: How can I report a bug?**


Please follow the guidelines provided at:
			[https://github.com/OpenSIPS/opensips/issues](https://github.com/OpenSIPS/opensips/issues).
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
