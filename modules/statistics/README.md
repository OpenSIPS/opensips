---
title: "Statistics Module"
description: "The Statistics module is a wrapper over the internal statistics manager, allowing the script writer to dynamically define and use of statistic variables."
---

## Admin Guide


### Overview


The Statistics module is a wrapper over the internal
		statistics manager, allowing the script writer to dynamically define and
		use of statistic variables.


By bringing the statistics support into the script, it takes advantage
		of the script flexibility in defining logics, making possible 
		implementation of any kind of statistic scenario.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### variable (string)


Name of a new statistic variable. The name may be followed by additional
		flag which describe the variable behavior:


- *no_reset* : variable cannot be reset.


```opensips title="variable example"
modparam("statistics", "variable", "register_counter")
modparam("statistics", "variable", "active_calls/no_reset")
```


### Exported Functions


#### update_stat(variable,value)


Updates the value of the statistic variable with the new value.


Meaning of the parameters is as follows:


- *variable* - variable to be updated
			(it can be a string or a pseudovariable);
- *value* - value to update with; it may be
			also negative.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE, 
		FAILURE_ROUTE and ONREPLY_ROUTE.


```opensips title="update_stat usage"
...
update_stat("register_counter", "+1");
...
$var(a_calls) = "active_calls";
update_stat("$var(a_calls)", "-1");
...
```


#### reset_stat(variable)


Resets to zero the value of the statistic variable.


Meaning of the parameters is as follows:


- *variable* - variable to be reset-ed
			(it can be a string or a pseudovariable).


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE, 
		FAILURE_ROUTE and ONREPLY_ROUTE.


```opensips title="reset_stat usage"
...
reset_stat("register_counter");
...
$var(reg_counter) = "register_counter";
update_stat("$var(reg_counter)");
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
