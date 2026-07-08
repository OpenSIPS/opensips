---
title: "Call-Center Module"
description: "The Call Center module implements an inbound call center system with call flows (for queueing the received calls) and agents (for answering the calls)."
---

## Admin Guide


### Overview


The Call Center module implements an inbound call center system with call 
	flows (for queueing the received calls) and agents (for answering the 
	calls).


The module implements the queueing system, the call distribution 
	to agents, agents managements, CDRs for the calls, statistics on 
	call distribution and agent's activity - basically everything 
	except the media playback (for the queue). This part must be provided via 
	a third party media server (FreeSwitch, Asterisk or others).


### How it works


The main entities in the modules are the flows (queues) and agents.


#### DB tables


Each entity has a corresponding table in the database, for 
		provisioning purposes - the *cc_flows* and 
		*cc_agents* tables, see
		[DB schema](https://docs.opensips.org/manual/1-11/install-dbschema#AEN2361).
		Data is loaded at startup and cached into memory ; runtime reload is 
		possible via the MI commands (see the *cc_reload* 
		command in [cc mi commands](#exported_mi_functions)).


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


A flow is defined by a unique alhanumerical ID - the main attribute 
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
		priority, its calls will be pushed (in deliver to agents and queing) in
		front of the calls from flows with a lower priority.


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


#### Agents


An agent is defined by a unique alhanumerical ID - the main attribute 
		of an agent is its the set of *skills* and its SIP
		*location*. The set of skills will tell what calls
		to be received (from which flows, based on the skill matching); the 
		location is a SIP URI where to call must be sent in order to be 
		answered by the agent.


Additionally, the agent has a initial *logstate* - 
		if he is logged in or not (being logged in is a must in order to
		receive calls). The log state may be changed at runtime via a 
		dedicated MI command *cc_agent_login*, see 
		[cc mi commands](#exported_mi_functions).


There is a *wrapup_time* defined, saying the 
		time interval for an agent before getting a new call from the system 
		(after he finished a call).


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


#### b2b_scenario (string)


The name of the B2B scenario that is used by the module for handling
		the calls in the queue. This is an advanced options and you should
		not change it unless you really understand what you are doing.


The module provides an B2B scenario file 
		*scenario_callcenter.xml* located in the module
		directory. The name of this scenario from this file (which must be
		loaded via the b2b_logic module) must match the 
		*b2b_scenario* parameter.


*Default value is "call center".*


```opensips title="Set b2b_scenario parameter"
...
modparam("b2b_logic", "script_scenario", "/etc/opensips/scenario_callcenter.xml")
modparam("call_center", "b2b_scenario", "call center")
...
```


#### wrapup_time (integer)


Time for an agent between finishing a call and receiving the next
		call from the system. Even if there are queued calls, the module
		will not deliver call to agent during this wrapup interval.


*Default value is "30 seconds".*


```opensips title="Set wrapup_time parameter"
...
modparam("call_center", "wrapup_time", 45)
...
```


### Exported Functions


#### cc_handle_call(flowID)


This must be used only for initial INVITE requests - the function
		pushs the call to be handled by the call center module (via a certain
		flow/queue).


This function can be used from REQUEST_ROUTE.


The **flowID** mandatory parameter is
		the ID of the flow to handle this call (push the call to that flow).
		This can be a variable or a static string.


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
		send_reply("403","Cannot handle call");
		exit;
	}
}
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


Total number of calls answered by agents. (counter type)


##### ccg_abandonned_incalls


Total number of calls terminated by caller before being
			answered by agents. (counter type)


##### ccg_onhold_calls


Total number of calls in the queues (onhold). (realtime type)


##### ccg_free_agents


Total number of free agents (across all flows). (realtime type)


#### Per-flow statistics (one set for each flow)


##### ccf_incalls_flowID


Number of received calls for the flow. (counter type)


##### ccf_dist_incalls_flowID


Number of distributed calls in this flow. (counter type)


##### ccf_answ_incalls_flowID


Nnumber of calls from the flow answered by agents. (counter type)


##### ccf_aban_incalls_flowID


Number of calls (from the flow) terminated by caller before being
			answered by agents. (counter type)


##### ccf_onhold_incalls_flowID


Number of calls (from the flow) which were put onhold.
			 (counter type)


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


Nnumber of calls answered by the agent. (counter type)


##### cca_aban_incalls_agentID


Number of calls (sent to this agent) terminated by caller before 
			being answered by agents. (counter type)


##### cca_att_agentID


Avg. Talk Time for this agent (realtime type)


### Exported MI Functions


#### cc_reload


Command to reload flows and agents definition from database.


It takes no parameter.


MI FIFO Command usage:


```bash
opensipsctl fifo cc_reload
```


#### cc_agent_login


Command to login an agent into the Call Center engine.


It takes two mandatory parameters, the ID of the agent and the 
		new login state (0 - log off, 1 - log in)


MI FIFO Command usage:


```bash
opensipsctl fifo cc_agent_login agentX 0
```


#### cc_list_queue


Command to list all the calls in queuing - for each call, the 
		following attributes will be printed: the flow of the call, for how
		long the call is in the queue, the ETW for the call, call priority 
		and the call skill (inherited from the flow).


It takes no parameter.


MI FIFO Command usage:


```bash
opensipsctl fifo cc_list_queue
```


#### cc_list_flows


Command to list all the flows - for each flow, the 
		following attributes will be printed: the flow ID, the avg. call 
		duration, how many calls were processed, how many agents are logged, 
		and how many onging calls are.


It takes no parameter.


MI FIFO Command usage:


```bash
opensipsctl fifo cc_list_flows
```


#### cc_list_agents


Command to list all the agents - for each agent, the 
		following attributes will be printed: agent ID, agent login state and
		agent state (free, wrapup, incall).


It takes no parameter.


MI FIFO Command usage:


```bash
opensipsctl fifo cc_list_agents
```


#### cc_list_calls


Command to list all the ongoing calls - for each call, the 
		following attributes will be printed: call ID, call state 
		(welcome, queued, toagent, ended), call duration, flow it belongs to,
		agent serving the call (if any).


It takes no parameter.


MI FIFO Command usage:


```bash
opensipsctl fifo cc_list_agents
```


#### cc_reset_stats


Command to reset all counter-like statistics.


It takes no parameter.


MI FIFO Command usage:


```bash
opensipsctl fifo cc_reset_stats
```


### Exported Pseudo-Variables


NONE


## Developer Guide


### Available Functions


NONE


## Frequently Asked Questions


**Q: Where can I find more about OpenSIPS?**


Take a look at [http://www.opensips.org/](http://www.opensips.org/).


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
