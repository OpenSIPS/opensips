---
title: "Script Helper Module"
description: "The purpose of the **Script Helper module** is to simplify the scripting process in OpenSIPS when doing basic scenarios. At the same time, it is useful to script writers as it contains basic SIP routing logic, and thus it allows them to focus more on the particular aspects of their OpenSIPS r..."
---

## Admin Guide


### Overview


The purpose of the **Script Helper module**
	is to simplify the scripting process in OpenSIPS when doing basic scenarios.
	At the same time, it is useful to script writers as it contains basic SIP
	routing logic, and thus it allows them to focus more on the particular aspects
	of their OpenSIPS routing code.


### How it works


By simply loading the module, the following
	**default logic** will be embedded:


- for initial SIP requests, the module will perform *record routing*
	before running the main *request* route
- sequential SIP requests will be transparently handled - the module will perform
	*loose routing*, and the request route will not be run at all


Currently, the module may be further configured to embed the following
	**optional logic**:


- *dialog* support (dialog module dependency - must be loaded before this module)
- an additional route to be run before relaying sequential requests


### Dependencies


#### OpenSIPS Modules


The following  modules must be loaded before this module:


- *dialog* (only if **[use dialog](#param_use_dialog)** is enabled).


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### use_dialog (integer)


Enables dialog support. Note that the dialog module must be loaded before
		this module when setting this parameter.


Default value is 0 (disabled)


```opensips title="Setting use_dialog"
...
modparam("script_helper", "use_dialog", 1)
...
```


#### create_dialog_flags (string)


Flags used when creating dialogs. For details on these flags, please refer
		to the *create_dialog()* function of the dialog module.


Default value is "" (no flags are set)


```opensips title="Setting create_dialog_flags"
...
modparam("script_helper", "create_dialog_flags", "options-ping-caller,options-ping-callee,bye-on-timeout")
...
```


#### sequential_route (string)


Optional route to be run just before sequential requests are relayed.
		If the *exit* script statement is used inside this route,
		the module assumes that the relaying logic has been handled.


By default, this parameter is not set


```opensips title="Setting sequential_route"
...
modparam("script_helper", "sequential_route", "sequential_handling")
...
route [sequential_handling]
{
...
}
...
```


### Known Issues


The Max-Forwards header is currently not handled at all.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
