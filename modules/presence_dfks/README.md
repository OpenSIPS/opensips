---
title: "presence_dfks Module"
description: "The module enables the handling of the \"as-feature-event\" event package (as defined by Broadsoft's [Device Feature Key Synchronization](https://h30434.www3.hp.com/psg/attachments/psg/Desk_IP_Conference_Phones/1740/1/DeviceFeatureKeySynchronizationFD.pdf) protocol) by the presence m..."
---

## Admin Guide


### Overview


The module enables the handling of the "as-feature-event" event package (as
	    defined by Broadsoft's
	    [Device Feature Key Synchronization](https://h30434.www3.hp.com/psg/attachments/psg/Desk_IP_Conference_Phones/1740/1/DeviceFeatureKeySynchronizationFD.pdf)
	    protocol) by the presence module. This can be used to synchronize the status of
	    features such as Do Not Disturb and different forwarding types between a SIP
	    phone and a SIP server.


The module supports synchronization for the following features: Do Not Disturb,
	    Call Forwarding Always, Call Forwarding Busy and Call Forwarding No Answer.
	    Feature status can be changed either from the SIP phone or the OpenSIPS Server(
	    by running an MI command).


When handling a SUBSCRIBE message without a body, the module will run a script
	    route for each feature, that will be used to retrieve the current status of that
	    feature. Conversely, a SUBSCRIBE with a body will trigger a script route where the
	    updated status of a specific feature is available. This route might also be run
	    if the feature update was triggered from OpenSIPS via MI.


Note that the module does not automatically cache or persist any feature information
	    as this is left for the script writer to implement in the routes triggered by the module.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *presence*.


#### External Libraries or Applications


- *libxml2-dev*.


### Exported Parameters


#### get_route (string)


The name of the script route to be run in order to retrieve the status
		of a feature.


*Default value is "dfks_get".*


```c title="Set parameter"
...
modparam("presence_dfks", "get_route", "dfks_get")
...
```


#### set_route (string)


The name of the script route to be run when a feature status update
		from a SIP phone is received.


*Default value is "dfks_get".*


```c title="Set parameter"
...
modparam("presence_dfks", "set_route", "dfks_set")
...
```


### Exported Functions


None.


### Exported MI Functions


#### presence_dfks:set_feature


Replaces obsolete MI command: *dfks_set_feature*.


Triggers the sending of NOTIFY messages containing a feature status update
		to all watchers.


*Note:* calling this MI function also triggers the
			*set_route* run. One can determine if the route is
			triggered by an MI function by checking the existence of the
			*$dfks(param)* variable.


Name: *presence_dfks:set_feature*


Parameters:


- *presentity*: the URI of the user whose feature status
				should be updated
- *feature*: The name of the feature to update. Takes one
				of the following values:

  - *DoNotDisturb*
  - *CallForwardingAlways*
  - *CallForwardingBusy*
  - *CallForwardingNoAnswer*
- *status*: the new status of the feature:
				*0* - disabled, *1* - enabled
- *route_param*: optional string parameter
				passed to the *$dfks(param)* variable in
				*set_route*.
- *values*: an array of extra values that can be updated
				for a feature. The format of an array element is:
				*field*/*value*. Supported fields are:
				
				
					*forwardTo* - for all forwarding types
				
				
					*ringCount* - for *CallForwardingNoAnswer*


MI FIFO Command Format:


```c
opensips-cli -x mi presence_dfks:set_feature sip:alice@10.0.0.11 CallForwardingNoAnswer 1 1 \
ringCount/4 forwardTo/sip:bob@10.0.0.11
```


### Exported Pseudo-Variables


#### $dfks(field)


This pseudo-variable can be used in the routes triggered by the module
		to handle the feature information through the following subnames:


- *assigned* - inform the SIP phone that a
		feature is unassigned by setting this to *0* (the NOTIFY response
		will contain no XML data for the corresponding feature) By default, features are assigned.
- *notify* - suppress the sending of the NOTIFY
		message by setting this to *0*. By default, the NOTIFY is sent.
- *presentity* - read-only, returns the current presentity URI.
- *feature* - read-only, returns the current feature name.
		Possible values are:

  - *DoNotDisturb*
  - *CallForwardingAlways*
  - *CallForwardingBusy*
  - *CallForwardingNoAnswer*
- *status* - read or write the feature status. A value of
		*1* means enabled and *0* disabled.
- *param* - returns the parameter passed by the
		*mi_dfks_set_feature* MI function. This field will be
		*NULL* if the parameter was not specified, or if the
		*set_route* is not triggered by an MI command, but by
		SIP signalling.
- *value/field* - read or write extra feature values.
		*field* can be one of:
		
		
			*forwardTo* - for all forwarding types
		
		
			*ringCount* - for *CallForwardingNoAnswer*


```c title="dfks usage"
...
route[dfks_set] {
    # CallForwardingAlways is not allowed
    if ($dfks(feature) == "CallForwardingAlways")
        $dfks(status) = 0;

    xlog("New status: $dfks(status) for feature '$dfks(feature)' of user '$dfks(presentity)'\n");
}
route[dfks_get] {
    if ($dfks(feature) == "CallForwardingNoAnswer") {
        $dfks(status) = 1;
        $dfks(value/forwardTo) = "sip:bob@10.0.0.11";
        $dfks(value/ringCount) = "3";
    } else if ($dfks(feature) == "CallForwardingAlways")
        $dfks(assigned) = 0;
    } else {
        ...
    }
}
...
	
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
