---
title: "event_virtual Module"
description: "The *event_virtual* module provides the possibility to have multiple external applications, using different transport protocols, subscribed to the OpenSIPS Event Interface as a single virtual subscriber, for a specific event. When an event is triggered, the event_virtual module notifies the spe..."
---

## Admin Guide


### Overview


The *event_virtual*
		module provides the possibility to have multiple external applications, using different transport protocols, subscribed to the OpenSIPS Event Interface as a single virtual subscriber, for a specific event. When an event is triggered, the event_virtual module notifies the specified transport modules using one of the following policies:


- *PARALLEL* - all subscribers (applications) are notified at once
- *FAILOVER* - for every event raised, try to
				notify the subscribers, in the order in which they are given,
				until the first successful notification. A failed subscriber is
				skipped for further notifications until the
				[failover timeout](#param_failover_timeout) passes.
- *ROUND-ROBIN* - for every event raised, notify the subscribers alternatively, in the order in which they are given (for each raised event notify a different subscriber)


Only one expire value can be used (for the whole virtual subscription), and not one for each individual subscriber.


### Virtual socket syntax


*virtual:policy subscriber_1 [[subscriber_2] ...]*


Meanings:


- *virtual:* - informs the Event Interface that the
					events sent to this subscriber should be handled by the
					*event_virtual* module
- *policy* - subscriber notification policy, can have one of the following values: 'PARALLEL', 'FAILOVER', 'ROUND-ROBIN' (with the behaviour described above)
				
				
					*!! Important: Policies must always be specified as
							uppercase strings!*
- *subscriber_1* - use the socket syntax for this specific subscriber (eg. "rabbitmq:guest:guest@127.0.0.1:5672/pike")


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:
			*The OpenSIPS event modules which implement the transport protocols used by the subscribers*.


### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *none*


### Exported Parameters


#### failover_timeout (integer)


The minimum duration in seconds that a failed subscriber is
			skipped for further notifications. This parameter only affects
			the *FAILOVER* policy.


*Default value is "30".*


```c title="Setting the failover_timeout parameter"
...
modparam("event_virtual", "failover_timeout", 5)
...
	
```


### Exported Functions


No exported functions to be used in the configuration file.


### Example


The sockets of the subscribers may be separated by any number of spaces or tabs:


```c title="Virtual socket"
	virtual:PARALLEL rabbitmq:guest:guest@127.0.0.1:5672/pike flatstore:/var/log/opensips_proxy.log
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
