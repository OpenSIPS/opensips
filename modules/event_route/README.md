---
title: "event_route Module"
description: "This module provides a simple way for handling different events, triggered through the OpenSIPS Event Interface, directly from the OpenSIPS script. For a specific event, a special route (*event_route*) has to be declared in the script, and should contain the code that handles the event. T..."
---

## Admin Guide


### Overview


This module provides a simple way for handling different events,
triggered through the OpenSIPS Event Interface, directly from the OpenSIPS
script. For a specific event, a special route
(*event_route*) has to be declared in the script, and
should contain the code that handles the event. The route is executed by
the module when the corresponding event is raised by the OpenSIPS Event
Interface.Since version 1.12, the way an event is handlend (sync/async)
should be specified from the configuration script with the desired keyword
following the name of the event (*event_route[e, sync]*).


### ROUTE events parameters


In order to retrieve the parameters of an event, the 
*fetch_event_params(pvar_list)* function is used. It
receives a single parameter, that consists of a list of parameters names
(optional) and the pseudo-variable where the values will be stored. The
grammar is:
*[ param_name= ] pvar [; [ param_name= ] pvar ]**

		Example:


```opensips
fetch_event_params("$avp(first_param)");
fetch_event_params("ip=$avp(pike_ip)");
fetch_event_params("source=$avp(src);destination=$avp(dst)");
```


If the name of the parameter is not specified, the avp will be populated
according to the order of the parameters, as exported by the event. The
following code will populate the *$avp(first)* avp
with the first parameter of the event, *$avp(second)*
with the second one and so on.

		fetch_event_params("$avp(first);$avp(second);$avp(third)");

		*NOTE:* An event may be triggered within a different event, leading
		to nested processing. This function will retrieve the parameters of the currently processed
		event.


The event name can contain any non-quoted string character, but
it is recommended to follow the syntax:
E_*MODULE_NAME*_*EXTRA_NAME*


### EVENT_ROUTE usage


In order to handle the *E_PIKE_BLOCKED* event,
the following snippet can be used:

			EVENT_ROUTE usage

```opensips

	event_route[E_PIKE_BLOCKED] {
		fetch_event_params("ip=$avp(pike-ip)");
		xlog("IP $avp(pike-ip) has been blocked\n");
	}
```


### EVENT_ROUTE socket syntax


As the OpenSIPS Event Interface requires, the *event_route*
module uses a specific socket syntax:
*'route:' event_name*


Example:
*route:E_PIKE_BLOCKED*


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
running OpenSIPS with this module loaded:


- *none*


### Exported Parameters


The module does not export parameters to be used in configuration script.


### Exported Functions


#### fetch_event_params(pvar_list)


Retrieves the parameters of the event. For more information, please 
read [event route parameters](#route_events_parameters).


The the pseudo variables list as described in [event route parameters](#route_events_parameters).


This function can be used from REQUEST_ROUTE and EVENT_ROUTE.


```opensips title="fetch_event_params usage"
...
fetch_event_params("$avp(first_param)"); # fetch the first parameter of an event
fetch_event_params("ip=$avp(pike_ip)");  # fetch the ip parameter
fetch_event_params("source=$avp(src);destination=$avp(dst)"); # fetch the source and destination parameters
...
```


## Frequently Asked Questions


**Q: Can I declare more routes for handling the same event?**


No, only a single *event_route* can be used for a
particular event.


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
