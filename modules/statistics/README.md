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


### Statistic Groups


Starting with OpenSIPS 2.3, statistics may be grouped by prefixing
their names with the name of the desired group, along with a colon
separator (e.g. **$stat(method:invite)** or
**update_stat("packets:$var(ptype)", "+1")**).
In order for this to work, the groups must be defined prior to OpenSIPS startup
using the **[stat groups](#param_stat_groups)**
module parameter.


The module allows easy iteration over the statistics of a group using
the **[stat iter init](#func_stat_iter_init)**
and **[stat iter next](#func_stat_iter_next)**
functions.


By default, all statistics belong to the
**"dynamic"** group.


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


#### stat_groups (string)


A comma-separated values string, specifying the statistic groups that
may be used throughout the OpenSIPS script. Groups cannot contain leading or
trailing whitespace characters.


```opensips title="setting the stat_groups parameter"
modparam("statistics", "stat_groups", "method, packet, response")
```


### Exported Functions


#### update_stat(variable, value)


Updates the value of the statistic variable with the new value.


Meaning of the parameters is as follows:


- *variable* (string) - variable to be updated;
- *value* (int) - value to update with; it may be
also negative.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE, 
FAILURE_ROUTE and ONREPLY_ROUTE.


```opensips title="update_stat usage"
...
update_stat("register_counter", 1);
...
$var(a_calls) = "active_calls";
update_stat($var(a_calls), -1);
...
```


#### reset_stat(variable)


Resets to zero the value of the statistic variable.


Meaning of the parameters is as follows:


- *variable* (string) - variable to be reset-ed


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE, 
FAILURE_ROUTE and ONREPLY_ROUTE.


```opensips title="reset_stat usage"
...
reset_stat("register_counter");
...
$var(reg_counter) = "register_counter";
update_stat($var(reg_counter));
...
```


#### stat_iter_init(group, iter)


Re-initializes "iter" in order to begin iterating through all
statistics belonging to the given "group".


Meaning of the parameters is as follows:


- *group* (string)
- *iter* (string) - internally matched
to a corresponding iterator


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE, 
FAILURE_ROUTE and ONREPLY_ROUTE.


```opensips title="stat_iter_init usage"
...
stat_iter_init("packet", "iter");
...
```


#### stat_iter_next(name, val, iter)


Attempts to fetch the current statistic to which "iter" points.
If successful, the relevant data will be written to "name" and "val",
while also advancing "iter". Returns negative when reaching the end of iteration.


Meaning of the parameters is as follows:


- *name* (var)
- *val* (var)
- *iter* (string) - internally matched
to a corresponding iterator


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE, 
FAILURE_ROUTE and ONREPLY_ROUTE.


```opensips title="stat_iter_next usage"
...
# periodically clear packet-related data
timer_route [clear_packet_stats, 7200] {
	stat_iter_init("packet", "iter");
	while (stat_iter_next($var(stat), $var(val), "iter"))
		reset_stat("packet:$var(stat)");
}
...
```


### Exported Pseudo-Variables


#### $stat


Allows "get" or "reset" operations on the given statistics.


The name of a statistic may be optionally prefixed with a searching
group, along with a colon separator.


If a searching group is not provided, the statistic is first
searched for in the core groups. If not found, search continues with
the "dynamic" group which, by default, holds all non-explicitly
grouped statistics which are not exported by the OpenSIPS core.


```opensips title="$stat usage"
...
xlog("SHM used size = $stat(used_size), no_invites = $stat(method:invite)\n");
...
$stat(err_requests) = 0;
...
			
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
