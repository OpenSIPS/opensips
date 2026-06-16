---
title: "sl Module"
description: "The SL module allows OpenSIPS to act as a stateless UA server and generate replies to SIP requests without keeping state. That is beneficial in many scenarios, in which you wish not to burden server's memory and scale well."
---

## Admin Guide


### Overview


The SL module allows OpenSIPS to act as a stateless 
		UA server and generate replies to SIP requests without keeping 
		state. That is beneficial in many scenarios, in which you wish not to 
		burden server's memory and scale well.


The SL module needs to filter ACKs sent after a 
		local stateless reply to an INVITE was generated. To recognize such 
		ACKs, OpenSIPS adds a special "signature" in to-tags. This signature is 
		sought for in incoming ACKs, and if included, the ACKs are absorbed.


To speed up the filtering process, the module uses a timeout 
		mechanism. When a reply is sent, a timer is set. As time as the timeout 
		didn't hit, the incoming ACK requests will be checked using TO tag 
		value. Once the timer expires, all the ACK are let through - a long
		time passed till it sent a reply, so it does not expect any ACK that 
		have to be blocked.


The ACK filtering may fail in some rare cases. If you think these 
		matter to you, better use stateful processing (tm module) for INVITE 
		processing. Particularly, the problem happens when a UA sends an 
		INVITE which already has a to-tag in it (e.g., a re-INVITE)
		and OpenSIPS want to reply to it. Than, it will keep the current to-tag, 
		which will be mirrored in ACK. OpenSIPS will not see its signature and 
		forward the ACK downstream. Caused harm is not bad--just a useless 
		ACK is forwarded.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### enable_stats (integer)


If the module should generate and export statistics to the core
		manager. A zero value means disabled.


SL module provides statistics about how many replies were sent (
		splitted per code classes) and how many local ACKs were filtered out.


Default value is 1 (enabled).


```c title="enable_stats example"
modparam("sl", "enable_stats", 0)
```


### Exported Functions


#### sl_send_reply(code, reason)


For the current request, a reply is sent back having the given code 
		and text reason. The reply is sent stateless, totally independent of 
		the Transaction module and with no retransmission for the INVITE's 
		replies. 'code' and 'reason' can contain pseudo-variables that are
		replaced at runtime.


Meaning of the parameters is as follows:


- *code (int)* - Return code.
- *reason (string)* - Reason phrase.


This function can be used from REQUEST_ROUTE, ERROR_ROUTE.


```c title="sl_send_reply usage"
...
sl_send_reply(404, "Not found");
...
sl_send_reply($err.rcode, $err.rreason);
...
```


#### sl_reply_error()


Sends back an error reply describing the nature of the last internal 
		error.  Usually this function should be used after a script function 
		that returned an error code.


This function can be used from REQUEST_ROUTE.


```c title="sl_reply_error usage"
...
sl_reply_error();
...
```


### Exported Statistics


#### 1xx_replies


The number of 1xx_replies.


#### 2xx_replies


The number of 2xx_replies.


#### 3xx_replies


The number of 3xx_replies.


#### 4xx_replies


The number of 4xx_replies.


#### 5xx_replies


The number of 5xx_replies.


#### 6xx_replies


The number of 6xx_replies.


#### sent_replies


The number of sent_replies.


#### sent_err_replies


The number of sent_err_replies.


#### received_ACKs


The number of received_ACKs.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
