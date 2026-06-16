---
title: "QOS Module"
description: "The qos module provides a way to keep track of per dialog SDP session(s)."
---

## Admin Guide


### Overview


The qos module provides a way to keep track of
		per dialog SDP session(s).


### How it works


The qos module uses the dialog module to be notified of
	any new or updated dialogs.  It will then look for and extract
	the SDP session (if present) from SIP requests and replies and
	keep track of it for the entire life of a dialog.


All of this happens with a properly configured dialog
	and qos module and setting the dialog flag and the qos flag at
	the time any INVITE sip message is seen.  There is no
	config script function call required to set the SDP session
	tracking mechanism.  See the dialog module users guide for
	more information.


A dialog can have one or more SDP sessions active in one
	of the following states:


- *pending* - only one end point of the
	SDP session is known.
- *negotiated* - both end points of the
	SDP session are known.


An SDP session can be established in one of the following
	scenarios:


- *INVITE/200ok* - typical "INVITE" and
	"200 OK" SDP exchange.
- *200ok/ACK* - "200 OK" and  "ACK" SDP
	exchange (for calls starting with an empty INVITE).
- *183/PRACK* - early media via "183
	Session Progress" and "PRACK" (see rfc3959 for more information) -
	not implemented yet.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded
		before this module:


- *dialog* - dialog module and
		its decencies (tm).


#### External Libraries or Applications


The following libraries or applications must be installed before
	running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### qos_flag (string)


Keeping with OpenSIPS, the module will not do
		anything to any message unless instructed to do so via
		the config script. You must set the qos_flag
		value in the setflag() call of the INVITE you want the
		qos module to process. But before you can do that, you
		need to tell the qos module which flag value you are
		assigning to qos.


In most cases when ever you create a new dialog
		via create_dialog() function,you will want to set the qos flag. 
		If create_dialog() is not called and the qos flag is set, 
		it will not have any effect.


This parameter must be set of the module will
		not load.


*Default value is "Not set!".*


```c title="Set qos_flag parameter"
...
modparam("qos", "qos_flag", "QOS_FLAG")
...
route {
  ...
  if ($rm=="INVITE") {
    setflag(QOS_FLAG); # Set the qos flag
	create_dialog(); # create the dialog
  }
  ...
}
```


### Exported Functions


There are no exported functions that could be used in scripts.


### Exported Statistics


There are no exported statistics for the qos module.


### Exported MI Functions


There are no exported MI functions for the qos module.
	Check the dialog MI functions for a way to inspect the internals
	of a dialog.


### Exported Pseudo-Variables


There are no exported pseudo-variables for the qos module.


### Installation and Running


Just load the module and remember to set the flag.


## Developer Guide


### Available Functions


#### register_qoscb (qos, type, cb, param)


Register a new callback to the qos.


Meaning of the parameters is as follows:


- *struct qos_ctx_st* qos* - qos to 
			register callback to. If maybe NULL only for QOSCB_CREATED callback
			type, which is not a per qos type.
- *int type* - types of callbacks; more
			types may be register for the same callback function; only 
			QOSCB_CREATED must be register alone. Possible types:
			
			
				*QOSCB_CREATED* - called when a new 
				qos context is created - it's a global type (not associated to 
				any qos).
			
			
				*QOSCB_ADD_SDP* - called when a new SDP
				was added to the qos context - it's a per qos type.
			
			
				*QOSCB_UPDATE_SDP* - called when an
				existing SDP is updated - it's a per qos type.
			
			
				*QOSCB_REMOVE_SDP* - called when an 
				existing SDP is removed - it's a per qos type.
			
			
				*QOSCB_TERMINATED* - called when the 
				qos is terminated.
- *qos_cb cb* - callback function to be 
			called. Prototype is: "void (qos_cb) 
			(struct qos_ctx_st *qos, int type, struct qos_cb_params *params);
			"
- *void *param* - parameter to be passed to
			the callback function.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
