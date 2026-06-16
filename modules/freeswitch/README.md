---
title: "freeswitch Module"
description: "The *\"freeswitch\"* module is a C driver for the FreeSWITCH Event Socket Layer interface. It can interact with one or more FreeSWITCH servers either by issuing commands to them, or by receiving events from them."
---

## Admin Guide


### Overview


The *"freeswitch"* module is a C driver for the
	FreeSWITCH Event Socket Layer interface. It can interact with one or more
	FreeSWITCH servers either by issuing commands to them, or by receiving
	events from them.


This driver can be seen as a centralized FreeSWITCH ESL connection manager.
	OpenSIPS modules may use its API in order to easily establish, reference
	and reuse ESL connections.


A FreeSWITCH ESL URL is of the form:
	**fs://[username]:password@host[:port]**.
	The default ESL port is 8021.


### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *None*


### Exported Parameters


#### event_heartbeat_interval (integer)


The expected interval between FreeSWITCH HEARTBEAT event arrivals.


*Default value is "1" (second).*


```c title="Setting the event_heartbeat_interval parameter"
...
modparam("freeswitch", "event_heartbeat_interval", 20)
...
```


#### esl_connect_timeout (integer)


The maximally allowed duration for the establishment of an ESL connection.


*Default value is "5000" (milliseconds).*


```c title="Setting the esl_connect_timeout parameter"
...
modparam("freeswitch", "esl_connect_timeout", 3000)
...
```


#### esl_cmd_timeout (integer)


The maximally allowed duration for the execution of an ESL command.
		This interval does not include the connect duration.


*Default value is "5000" (milliseconds).*


```c title="Setting the esl_cmd_timeout parameter"
...
modparam("freeswitch", "esl_cmd_timeout", 3000)
...
```


#### esl_cmd_polling_itv (integer)


The sleep interval used when polling for an ESL command response. Since the
		value of this parameter imposes a minimal duration for any ESL command,
		you should run OpenSIPS in debug mode in order to first determine an expected
		response time for an arbitrary ESL command, then tune this parameter accordingly.


*Default value is "1000" (microseconds).*


```c title="Setting the esl_cmd_polling_itv parameter"
...
modparam("freeswitch", "esl_cmd_polling_itv", 3000)
...
```


### Exported Functions
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
