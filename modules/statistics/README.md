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


### Statistic Series


Statistic series provide the ability to accumulate statistical data
		over a pre-defined time window. Data is stored in a circular buffer, pushing
		new data on top, and removing stale values (values outside the timeframe) from
		the bottom. These statistics can be used to provide per-time stats, such as
		ACD, ASR, AST, etc, that can be read using the classic statistics interface,
		through the *$stat()* variable.


Statistic series profile describe the timeframe used to store the data, as
		well as how the data is be accumulated and interpreted. There are several
		types a statistic series can be used, depending on the provisioned algorithm:


- *accumulate* - accumulates the specified values in a
			counter; works similar to clasical statistics, except that they reset
			after the specified timeframe
- *average* - returns an average of all the data fed
			within the timeframe; can be useful when computing PDD, AST, ACD stats.
- *percentage* - indicates the percentage of a set of
			values out of the total amount of values fed; can be useful when computing
			ASR, NER, CCR stats.


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


#### stat_series_profile (string)


Used to define a statistic series profile. Has the following format:
		*name: [attr=value]**, where *name*
		represents the name of the profile, and *attr=value*
		contains multiple settings of the defined profile. Possible attributes
		and their values are:


- *algorithm* - indicates the way data should be
			stored and accumulated over the specified timeframe. Possible values are:
			*accumulate*, *average* and
			*percentage*, as described in the
			**[section stat series](#statistic_series)**
			paragraph (default is *accumulate*)
- *hash_size* - each statistic defined/used is stored in
			a hash map attached to the profile; this setting tunes the size of the hash
			(default is: 8)
- *group* - indicates the group where the statistics
			beloging to this profile are grouped (as described in
			**[stat groups](#param_stat_groups)**
			(default is to use the same group as the profile)
- *window* - the number of seconds a timeframe has;
			all older values (out of the specified window) are discarded
			(default is *60* seconds)
- *slots* - the number of slots per window; used to tune
			the granularity of the circular buffer; the higher the number of slots is,
			the more accurate the resulted statistic;
			(default is the same value of the *window* parameter)
- *percentage_factor* - used for
			*percentage* algorithm profiles to specify the
			percentage factor to be used (defaults to *100*)


This parameter can be set multiple times, for each profile needed.


```opensips title="setting the stat_series_profile parameter"
...
# define a statistic that accumulates average values in the last minute
modparam("statistics", "stat_series_profile", "avg: algorithm=average")
...
# define a statistic that accumulates average values in the 10 minutes
# with 1 minute granularity (10 slots out of the 600s window)
modparam("statistics", "stat_series_profile", "avg_10m: algorithm=average window=600 slots=10")
...
# define a statistic that computes the percentage of values in the last hour
# with 10 minutes granularity (6 slots out of the 3600s window)
modparam("statistics", "stat_series_profile", "perc_1h: algorithm=percentage window=3600 slots=6")
...
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


#### update_stat_series(profile, variable, value)


Updates the value of a series statistic.


Meaning of the parameters is as follows:


- *profile* (string) - the profile as defined in
			**[stat series profile](#param_stat_series_profile)**
- *variable* (string) - variable to be updated;
- *value* (int) - value to update with; it may be
			also negative; when using *percentage* algorithm, the
			resulted value represents the percentage of positive values out of the
			total number of values (positive + negative)


This function can be used from any route.


```opensips title="update_stat_series usage"
...
# account failed calls
update_stat_series("perc_1h", "ASR_1h", -1);

# account successful calls
update_stat_series("perc_1h", "ASR_1h", 1);

# compute average PDD
update_stat_series("avg", "PDD", $var(pdd_ms));
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
