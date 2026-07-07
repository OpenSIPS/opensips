---
title: "signaling Module"
description: "The SIGNALING module comes as a wrapper over tm and sl modules and offers one function to be called by the modules that want to send a reply."
---

## Admin Guide


### Overview


The SIGNALING module comes as a wrapper over 
		tm and sl modules and offers one function to be called by the modules
		that want to send a reply.


The logic behind the module is to first search if a transaction is
		created and if so, send a state full reply, using tm module, otherwise
		send a stateless reply with the function exported by sl.
		In this way, the script writer still has the call on how the transaction 
		should be handled, state full or stateless and the reply is send 
		accordingly to his choice.


For example, if you do a t_newtran() in the script before doing save() 
		(for registration), the function will automatically send the reply in 
		stateful mode as a transaction is available. If no transaction is done, 
		the reply will be sent in stateless way (as now).


By doing this, we have the possibility to have same module sending 
		either stateful either stateless replies, by just controlling this from 
		the script (if we create or not a transaction).
		So, the signalling will be more coherent as the replies will be sent 
		according to the transaction presence (or not).


Moreover, this module offers the possibility of loading only one 
	of the module, sl or tm, and send reply using only the module that is 
	loaded. This is useful as not in all cases a user desires to send 
	stateful or stateless replies and he should not be forced to load the 
	module only because the send reply interface requires it.


### Dependencies


#### OpenSIPS Modules


At least one of the following modules must be loaded before this module:


- *sl*.
- *tm*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


- *None*.


### Exported Functions


#### send_reply(code, reason)


For the current request, a reply is sent back having the given code 
		and text reason. The reply is sent stateless or statefull depending 
		on which module is loaded and if a transaction was created, as 
		explained above.


Meaning of the parameters is as follows:


- *code (int)* - Return code.
- *reason (string)* - Reason phrase.


This function can be used from REQUEST_ROUTE, ERROR_ROUTE.


```opensips title="sl_send_reply usage"
...
send_reply(404, "Not found");
...
send_reply($err.rcode, $err.rreason);
...
		
```


### Exported Variables


#### $sig_local_totag


This variable returns the local To-tag that will be used
		by OpenSIPS for locally sending replies to the current SIP request.
		Yes, this variable should be used only in the context of a SIP
		request and it should be used only in conjunction with the 
		using [send reply](#func_send_reply).


Whenever you use it, be sure that the function is used in the same
		stateful / stateless SIP mode as the following replying function.
		Otherwise you may get different values for the To-tag!!


NOTE: the variable returns the To-Tag that will be used by OpenSIPS
		in the locally generated reply. This may be completly different from
		the To-tag in the replies received and forwarded by OpenSIPS.


```opensips title="Usage of $sig_local_totag variable"
...
# stateful handling
t_newtran();
xlog("the To-tag to be used is $sig_local_totag \n");
send_reply();  # or t_reply();
...
# stateless handling
xlog("the To-tag to be used is $sig_local_totag \n");
send_reply(); # or sl_send_reply();
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
