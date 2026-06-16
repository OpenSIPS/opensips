---
title: "event_route Module"
description: "This module provides a simple way for capturing and handling directly in the OpenSIPS script of different events triggered through the OpenSIPS Event Interface"
---

## Admin Guide


### Overview


This module provides a simple way for capturing and handling 
		directly in the OpenSIPS script of different events triggered through
		the OpenSIPS Event Interface


If you want to capture and handle a certian event, you need to
		define a dedicated route (*event_route*) into the
		OpenSIPS script, route having as name the name/code of the
		desired event. The route is triggered (and executed) by
		the module when the corresponding event is raised by the OpenSIPS


NOTE that there is the triggered *event_route* is
		run asyncronus (and in a differen process) in regards to the code or 
		process that generated the actual event.


NOTE that inside the *event_route* you should
		NOT rely on anything more than the content provide by the event itself
		(see below variable). DO NOT assume to have access to any other
		variable or context, not even to a SIP message.


### ROUTE events parameters


In order to retrieve the parameters of an event, the
		*$param(name)* variable has to be used. It's
			name can be the parameter's name, or, if an integer is specified, its
			index inside the parameter's list.

		Example:


```c
xlog("first parameters is $param(1)\n");
xlog("Pike Blocking IP is $param(ip)\n");
```


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
					
```c

	event_route[E_PIKE_BLOCKED] {
		xlog("IP $param(ip) has been blocked\n");
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


The function does not export any function.


## Frequently Asked Questions


**Q: Can I declare more routes for handling the same event?**


No, only a single *event_route* can be used for a
			particular event.


**Q: What happened with the "fetch_event_params()" function?**


This function has been dropped starting with OpenSIPS 3.0. Its functionality
			has been replaced by the "$param(name)" variable.


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
