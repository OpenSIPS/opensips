---
title: "B2B_LOGIC"
description: "The B2BUA implementation in OpenSIPS is separated in two layers: a lower one(coded in b2b_entities module)- which implements the basic functions of a UAS and UAC an upper one - which represents the logic engine of B2BUA, responsible of actually implementing the B2BUA servic..."
---

## Admin Guide


### Overview


The B2BUA implementation in OpenSIPS is separated in two layers:


- a lower one(coded in b2b_entities module)- which implements the basic functions of a UAS and UAC
- an upper one - which represents the logic engine of B2BUA, responsible of actually
implementing the B2BUA services using the functions offered by the low level.


This module is a B2BUA upper level implementation that can be used with b2b_entities
module to have B2BUA that can be configured to provide some PBX services.
The B2B services are coded in an XML scenario document. The b2b_logic module
examines this document and uses the functions provided by the b2b_entities
module to achieve the actions specified in the document and enable the service.


A scenario can be instantiated in two ways:


- from the script - at the receipt of a initial message
- with a extern command (MI) command - the server will connect two 
end points in a session(Third Party Call Control).


### Dependencies


#### OpenSIPS Modules


- *b2b_entities, a db module*


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *libxml2-dev*


### Exported Parameters


#### hash_size (int)


The size of the hash table that stores the scenario instatiation entities.


*Default value is "9"*
(512 records).


```opensips title="Set server_hsize parameter"
...
modparam("b2b_logic", "hash_size", 10)
...
	
```


#### script_scenario (str)


This parameter should be set with the path of a document
that contains a scenario that can be instantiated from the
script at the receipt of an initial message.


This parameter can be set more than once.


```opensips title="Set script_scenario parameter"
...
modparam("b2b_logic", "script_scenario", "/usr/local/opensips/scripts/b2b_prepaid.xml")
...
	
```


#### extern_scenario (str)


This parameter should be set with the path of a document
that contains a scenario that can be instantiated with an MI command.


This parameter can be set more than once.


```opensips title="Set script_scenario parameter"
...
modparam("b2b_logic", "extern_scenario", "/usr/local/opensips/scripts/b2b_marketing.xml")
...
	
```


#### cleanup_period (int)


The time interval at which to search for an hanged b2b context.
A scenario is considered expired if the duration of a session exceeds the
lifetime specified in the scenario.
At that moment, BYE is sent in all the dialogs from that context and the
context is deleted.


*Default value is "100".*


```opensips title="Set cleanup_period parameter"
...
modparam("b2b_logic", "cleanup_period", 60)
...
	
```


#### custom_headers_regexp (str)


Regexp to search SIP header by names that should be passed
from the dialog of one side to the other side. There are a number
of headers that are passed by default. They are:


- Content-Type
- Supported
- Allow
- Proxy-Require
- Session-Expires
- Min-SE
- Require
- RSeq


If you wish some other headers to be passed also you should define them
by setting this parameter.


It can be in forms like "regexp", "/regexp/" and "/regexp/flags".


Meaning of the flags is as follows:


- *i* - Case insensitive search.
- *e* - Use extended regexp.


*Default value is "NULL".*


```opensips title="Set parameter"
...
modparam("b2b_logic", "custom_headers_regexp", "/^x-/i")
...
	
```


#### custom_headers (str)


A list of SIP header names delimited by ';' that should be passed
from the dialog of one side to the other side. There are a number
of headers that are passed by default. They are:


- Max-Forwards (it is decreased by 1)
- Content-Type
- Supported
- Allow
- Proxy-Require
- Session-Expires
- Min-SE
- Require
- RSeq


If you wish some other headers to be passed also you should define them
by setting this parameter.


*Default value is "NULL".*


```opensips title="Set parameter"
...
modparam("b2b_logic", "custom_headers", "User-Agent;Date")
...
	
```


#### use_init_sdp (int)


This parameter modifies the behaviour of the B2BUA when bridging
and a provisional media uri is set. For playing media while the callee
answers (that is connecting the caller to a media server), the bridging
with the callee must start by sending an Invite to it. The correct way
is to send an Invite without a body in this case, but it has been observed
that not many gateways support this. So, the solution is to use the sdp
received in the first Invite from the caller and put it as the body for this
invite. By setting this parameter, this behavior is enabled.
You can also set use_init_sdp per scenario and overwrite this global value.


*Default value is "0".*


```opensips title="Set parameter"
...
modparam("b2b_logic", "use_init_sdp", 1)
...
	
```


#### db_url (str)


Database URL.


```opensips title="Set db_url parameter"
...
modparam("b2b_logic", "db_url", "mysql://opensips:opensipsrw@127.0.0.1/opensips")
...
	
```


#### update_period (int)


The time interval at which to update the info in database.


*Default value is "100".*


```opensips title="Set update_period parameter"
...
modparam("b2b_logic", "update_period", 60)
...
	
```


#### max_duration (int)


The maximum duration of a call.


*Default value is "12 * 3600 (12 hours)".*


If you set it to 0, there will be no limitation.


```opensips title="Set max_duration parameter"
...
modparam("b2b_logic", "max_duration", 7200)
...
	
```


#### b2bl_from_spec_param (string)


The name of the pseudo variable for storing the new
"From" header.
The PV must be set before calling "b2b_init_request".


*Default value is "NULL" (disabled).*


```opensips title="Set b2bl_from_spec_param parameter"
...
modparam("b2b_logic", "b2bl_from_spec_param", "$var(b2bl_from)")
...
route{
	...
	# setting the From header
	$var(b2bl_from) = "\"Call ID\" <sip:user@opensips.org>";
	...
	b2b_init_request("top hiding");
	...
}
	
```


#### server_address (str)


The IP address of the machine that will be used as Contact in
the generated messages. This is compulsory only when using external
scenarios. For the script scenarios, if it is not set, it is constructed
dynamically from the socket where the initiating request was received.
This socket will be used to send all the requests, replies for that
scenario instantiation.


```opensips title="Set server_address parameter"
...
modparam("b2b_logic", "server_address", "sip:sa@10.10.10.10:5060")
...
	
```


#### init_callid_hdr (str)


The module offers the possibility to insert the original callid in a header
in the generated Invites. If you want this, set this parameter to the name
of the header in which to insert the original callid.


```opensips title="Set init_callid_hdr parameter"
...
modparam("b2b_logic", "init_callid_hdr", "Init-CallID")
...
	
```


#### db_mode (int)


The B2B modules have support for the 3 type of database storage


- NO DB STORAGE - set this parameter to 0
- WRITE THROUGH (synchronous write in database) - set this parameter to 1
- WRITE BACK (update in db from time to time) - set this parameter to 2


*Default value is "2" (WRITE BACK).*


```opensips title="Set db_mode parameter"
...
modparam("b2b_logic", "db_mode", 1)
...
	
```


#### db_table (str)


Name of the database table to be used


*Default value is "b2b_logic"*


```opensips title="Set db_table parameter"
...
modparam("b2b_logic", "db_table", "some_table_name")
...
	
```


#### b2bl_th_init_timeout (int)


Call setup timeout for topology hiding scenario.


*Default value is "60"*


```opensips title="Set b2bl_th_init_timeout parameter"
...
modparam("b2b_logic", "b2bl_th_init_timeout", 60)
...
	
```


### Exported Functions


#### b2b_init_request(flags, [scenario_param1], [scenario_param2], [scenario_param3], [scenario_param4])


This is the function that must be called by the script writer
on an initial INVITE for which a B2B scenario must be instantiated.
It is up to the script writer to decide which are the criteria to decide
for which messages certain scenarios must be instantiated.


The first parameter is the identifier for the scenario and possible flags.
This is defined in the XML document as an attribute of the root node
or "top hiding" for internal topology hiding scenario.
It can be passed as "scenario" or "scenario_name/flags".
Then it can take at most 4 other parameters that represent the parameters for
the xml scenario. The expected number of parameters is also specified as an attribute
in the root node of the XML scenario.


Parameters:


- *flags (string)* - meaning of the flags is as follows:

					*t[nn]* -  Call setup timeout for topology hiding scenario.
					Example: t300.
					*a* -  Transparent authentication. In this mode b2b passes your 401
					or 407 authentication request to destination server.
					*p* -  Preserve To: header.
- *scenario_param1 (string, optional)*
- *scenario_param2 (string, optional)*
- *scenario_param3 (string, optional)*
- *scenario_param4 (string, optional)*


> [!NOTE]
> If you have a multi interface setup and want to chance the outbound interface,
it is mandatory to use the "force_send_socket()" core function before passing
control to b2b function. If you do not do it, the requests may be correctly routed,
but the SIP pacakge may be invalid (as Contact, Via, etc).


```opensips title="b2b_init_request usage"
...
if(is_method("INVITE") && !has_totag() && prepaid_user())
   b2b_init_request("prepaid", "sip:320@opensips.org:5070",
      "sip:321@opensips.org:5070"));
...
	
```


#### b2b_bridge_request(b2bl_key,entity_no)


This function will bridge an initial INVITE with one of the
particapnts from an existing b2b dialog.


Parameters:


- *b2bl_key (string)* - a string that
contains the b2b_logic key. The key can also be in the form
of *callid;from-tag;to-tag*.
- *entity_no (int)* - an integer that
holds the entity of the entity/participant to bridge.


```opensips title="b2b_bridge_request usage"
...
modparam("b2b_entities", "script_req_route", "b2b_request")
...
route[b2b_request]
{
   # incoming requests from the B2B entities
   ...
   if ($ci~="^B2B") { #keep this aligned with b2b_key_prefix
      # request coming from the UAC side;
      # the Call-ID carries the B2B key ID
      if (is_method("BYE") {
         $var(entity) = 1;
         b2b_bridge_request($ci,$var(entity));
      }
   }
   ...
}
...
		
```


### Exported MI Functions


#### b2b_trigger_scenario


This command instantiates a B2B scenario.


Name: *b2b_trigger_scenario*


Parameters:


- *senario_id* : the id of the scenario to be instantiated.
- *scenario_params* - array of at least 2 scenario parameters


MI FIFO Command Format:


```bash
	opensips-cli -x mi b2b_trigger_scenario marketing sip:bob@opensips.org sip:322@opensips.org:5070 sip:alice@opensips.org
		
```


#### b2b_bridge


This command can be used by an external application to tell B2BUA to bridge a
call party from an on going dialog to another destination. By default the caller
is bridged to the new uri and BYE is set to the callee. You can instead bridge
the callee if you send 1 as the third parameter.


Name: *b2b_bridge*


Parameters:


- *dialog_id* : the *b2b_logic key*, or the
*callid;from-tag;to-tag* of the ongoing dialog.
- *new_uri* - the uri of the new destination
- *flag* (optional) - used to specify that the callee must be bridged to the new destination. If not present the caller will be bridged. Possible values are
'0' or '1'.
- *prov_media_uri* (optional) - the uri of a media server able to play 
provisional media starting from the beginning of the bridging scenario
to the end of it. It is optional. If not present, no other entity will be
envolved in the bridging scenario


MI FIFO Command Format:


```bash
	opensips-cli -x mi b2b_bridge 1020.30 sip:alice@opensips.org
	
```


opensips-cli Command Format:


```bash
	opensips-cli -x mi b2b_bridge 1020.30 sip:alice@opensips.org
	
```


#### b2b_list


This command can be used to list the internals of b2b_logic entities.


Name: *b2b_list*


Parameters: *none*


MI FIFO Command Format:


```bash
	opensips-cli -x mi b2b_list
	
```


## Developer Guide


The module provides an API that can be used from other OpenSIPS
modules. The API offers the functions for instantiating b2b
scenarios from other modules (this comes as an addition to the
other two means of instantiating b2b scenarios - from script
and with an MI command). Also the instantiations can be
dynamically controlled, by commanding the bridging of an entity
involved in a call to another entity or the termination of the
call or even bridging two existing calls.


### b2b_logic_bind(b2bl_api_t* api)


This function binds the b2b_entities modules and fills the
structure the exported functions that will be described in
detail.


```c title="b2bl_api_t structure"
...
typedef struct b2bl_api
{
	b2bl_init_f init;
	b2bl_bridge_f bridge;
	b2bl_bridge_extern_f bridge_extern;
	b2bl_bridge_2calls_t bridge_2calls;
	b2bl_terminate_call_t terminate_call;
	b2bl_set_state_f set_state;
	b2bl_bridge_msg_t bridge_msg;
}b2bl_api_t;
...
```


### init


Field type:


```opensips
...
typedef str* (*b2bl_init_f)(struct sip_msg* msg, str* name, str* args[5],
		b2bl_cback_f, void* param);
...
```


Initializing a b2b scenario. The last two parameters are the
callback function and the parameter to be called in 3
situations that will be listed below. The callback function has
the following definition:


```c
...
typedef int (*b2b_notify_t)(struct sip_msg* msg, str* id, int type, void* param);
...
```


The first argument is the callback given in the init function.


The second argument is a structure with some statistics about
the call -start time, setup time, call time.


The third argument is the current state of the scenario
instantiation.


The last argument is the event that triggered the callback.
There are 3 events when the callback is called:


- *when a BYE is received from either side- event parameter
will also show from which side the BYE is received, so it
can be B2B_BYE_E1 or B2B_BYE_E2*
- *If while bridging, a negative reply is received from the
second entity - the event is B2B_REJECT_E2.*
- *When the b2b logic entity is deleted- the evnet is
B2B_DESTROY*


The return code controls what will happen with the
request/reply that caused the event (except for the last event,
when the return code does not matter)


- *-1 - error*
- *0 - drop the BYE or reply*
- *1 - send the BYE or reply on the other side*
- *2 - do what the scenario tells, if no rule defined send the
BYE or reply on the other side*


### bridge


Field type:


```c
...
typedef int (*b2bl_bridge_f)(str* key, str* new_uri, str* new_from_dname,int entity_type);
...
```


This function allows bridging an entity that is in a call
handled by b2b_logic to another entity.


### bridge_extern


Field type:


```c
...
typedef str* (*b2bl_bridge_extern_f)(str* scenario_name, str* args[5],
                b2bl_cback_f cbf, void* cb_param);
...
```


This function allows initiating an extern scenario, when the
B2BUA starts a call from the middle.


### bridge_2calls


Field type:


```c
...
typedef int (*b2bl_bridge_2calls_t)(str* key1, str* key2);
...
```


With this function it is possible to bridge two existing calls.
The first entity from the two calls will be connected and BYE
will be sent to their peers.


### terminate_call


Field type:


```c
...
typedef int (*b2bl_terminate_call_t)(str* key);
...
```


Terminate a call.


### set_state


Field type:


```c
...
typedef int (*b2bl_set_state_f)(str* key, int state);
...
```


Set the scenario state.


### bridge_msg


Field type:


```c
...
typedef int (*b2bl_bridge_msg_t)(struct sip_msg* msg, str* key, int entity_no);
...
```


This function allows bridging an incoming call to an entity from an
existing call.


The first argument is the INVITE message of the current incoming call.


The second argument is the b2bl_key of an existing call.


The third argument is the entity identifier.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
