---
title: "ratelimit Module"
description: "This module implements rate limiting for SIP requests. In contrast to the PIKE module this limits the flow based on a per SIP request type basis and not per source IP. The latest sources allow you to dynamically group several messages into some entities and limit the traffic based on them..."
---

## Admin Guide


### Overview


This module implements rate limiting for SIP requests. In contrast to
		the PIKE module this limits the flow based on a per SIP request type
		basis and not per source IP. The latest sources allow you to
		dynamically group several messages into some entities and limit the
		traffic based on them. The MI interface can be used to change
		tunables while running OpenSIPS.


This module is integrated with the OpenSIPS Key-Value Interface,
		providing support for distributed rate limiting using Redis or Memcached
		CacheDB backends. The internal limiting data will no longer be kept on each
		OpenSIPS instance. It will be stored in the distributed Key-Value database
		and queried by each instance before deciding if a SIP message should be
		blocked or not.


To achieve a distributed ratelimit feature, the module can also replicate
		its pipes counters to different OpenSIPS instances using the clusterer module.
		To do that, define the *pipe_replication_cluster* parameter
		in your configuration script.


Starting with OpenSIPS 3.2, choosing whether to replicate a pipe over
		CacheDB backends or bin replication is triggered by the flags specified
		when the pipe is created: adding the */r* suffix to the
		pipe's name will replicate through CacheDB, and adding */b*
		will replicate through bin/clusterer.


### Use Cases


Limiting the rate messages are processed on a system directly
		influences the load. The ratelimit module can be used to protect a
		single host or to protect an OpenSIPS cluster when run on the
		dispatching box in front.


Distributed limiting is useful when the rate limit should be
		performed not only on a specific node, but on the entire platform.


NOTE: that this behavior only makes sense when the pipe algorithm
		used is TAILDROP or RED.


A sample configuration snippet might look like this:


```opensips
...
	if (!rl_check($rU, 50, "TAILDROP")) {
		sl_send_reply(503, "Server Unavailable");
		exit;
	};
...
	
```


Upon every incoming request listed above rl_check is invoked and
		the entity identified by the R-URI user is checked. It
		returns an OK code if the current per request load is below the
		configured threshold. If the load is exceeded the function returns an
		error and an administrator can discard requests with a stateless
		response.


### Static Rate Limiting Algorithms


The ratelimit module supports two different static algorithms
		to be used by rl_check to determine whether a message should be
		blocked or not.


#### Tail Drop Algorithm (TAILDROP)


This is a trivial algorithm that imposes some risks when used in
		conjunction with long timer intervals. At the start of each interval
		an internal counter is reset and incremented for each incoming
		message. Once the counter hits the configured limit rl_check returns
		an error.


The downside of this algorithm is that it can lead to SIP client
		synchronization. During a relatively long interval only the first
		requests (i.e. REGISTERs) would make it through. Following messages
		(i.e. RE-REGISTERs) will all hit the SIP proxy at the same time when a
		common Expire timer expired. Other requests will be retransmissed
		after given time, the same on all devices with the same firmware/by
		the same vendor.


#### Random Early Detection Algorithm (RED)


Random Early Detection tries to circumvent the synchronization problem
		imposed by the tail drop algorithm by measuring the average load and
		adapting the drop rate dynamically. When running with the RED
		algorithm OpenSIPS will return errors to the OpenSIPS
		routing engine every n'th packet trying to evenly spread the measured
		load of the last timer interval onto the current interval. As a
		negative side effect OpenSIPS might drop messages although the limit might
		not be reached within the interval. Decrease the timer interval if you
		encounter this.


#### Slot Based Taildropping (SBT)


SBT holds a window consisting of one or more slots. You can set the
			*window_size* parameter(seconds) which means for
			how long we should look back to count the calls and
			*slot_period* parameter(miliseconds) which tells
			how granular the algorithm should be. The number of slots will be
			*window_size*/*slot_period*.
			If, for example, you have *window_size*=
			*slot_period*=1 second, then after each second
			you shall lose the call count, but if you set the
			*slot_period* to 100 milliseconds, then when your
			call will be outside the window, the calls in the first 100 milliseconds
			shall be dropped, and the rest in the next 900 shall be kept.


#### Network Algorithm (NETWORK)


This algorithm relies on information provided by network interfaces.
		The total amount of bytes waiting to be consumed on all the network
		interfaces is retrieved once every timer_interval seconds.
		If the returned amount exceeds the limit specified in the modparam,
		rl_check returns an error.


### Dynamic Rate Limiting Algorithms


When running OpenSIPS on different machines, one has to adjust the drop
		rates for the static algorithms to maintain a sub 100% load average or
		packets start getting dropped in the network stack.  While this is not
		in itself difficult, it isn't neither accurate nor trivial: another
		server taking a notable fraction of the cpu time will require re-tuning
		the parameters.


While tuning the drop rates from the outside based on a certain factor
		is possible, having the algorithm run inside ratelimit permits tuning
		the rates based on internal server parameters and is somewhat more
		flexible (or it will be when support for external load factors - as
		opposed to cpu load - is added).


#### Feedback Algorithm (FEEDBACK)


Using the PID Controller model
		(see [Wikipedia page](http://en.wikipedia.org/wiki/PID_controller)),
		the drop rate is adjusted dynamically based on the load factor so that
		the load factor always drifts towards the specified limit (or setpoint,
		in PID terms).


As reading the cpu load average is relatively expensive (opening /proc/stat,
		parsing it, etc), this only happens once every timer_interval seconds and
		consequently the FEEDBACK value is only at these intervals recomputed. This
		in turn makes it difficult for the drop rate to adjust quickly.  Worst case
		scenarios are request rates going up/down instantly by thousands - it takes
		up to 20 seconds for the controller to adapt to the new request rate.


Generally though, as real life request rates drift by less, adapting should
		happen much faster.


IMPORTANT NOTE: as this algorithm is diven by the load factor, the values
		for the limits must be between 0 and 100 (as percentages) and the limits
		for all the checks and pipes must be the same (only one value). Again, this
		limitation are specific to this algorithm and not to the implementation.


### Cluster-Bridge Replication


*(added in OpenSIPS 4.0)*


Cluster-bridge replication can be useful in some specific scenarios
		where you have multiple clusters of OpenSIPS servers, geographically
		spread across the country or beyond.  In this case, as an improvement
		to the standard, full-mesh replication strategy, you can alternatively
		group them into multiple cluster IDs based on geo-location, then define
		the replication "bridges" between them.  Full details in the
		[cluster-bridge replication](../clusterer#bridge_replication)
		chapter of the clusterer module.


At ratelimit level, you only need to enable [bridge replication](#param_bridge_replication),
		after which the CPS pipes should start flowing to remote clusters.  Make
		sure to tweak [bridge repl timer interval](#param_bridge_repl_timer_interval) and
		[bridge repl timer expire](#param_bridge_repl_timer_expire) as needed.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### timer_interval (integer)


The timer interval in seconds when the Network and Feedback algorithms
			run their queries, and the other algorithms reset their counters.


IMPORTANT: A too small value may lead to performance penalties due to
		timer process overloading.


*Default value is 10.*


```opensips title="Set timer_interval parameter"
...
modparam("ratelimit", "timer_interval", 5)
...
```


#### limit_per_interval (integer)


This parameter configures the way that a pipe's limit is specified
			in the *rl_check* function and only affects the
			Taildrop and RED algorithms. A value of 1 means that the limit is
			set per-*timer_interval* while a value of 0 means per-second.


*Default value is 0(limit per-second).*


```opensips title="Set limit_per_interval parameter"
...
modparam("ratelimit", "limit_per_interval", 1)
...
```


#### expire_time (integer)


This parameter specifies how long a pipe should be kept in memory
		after it becomes idle (no more operations are performed on the pipe)
		until deleted.


*Default value is 3600.*


```opensips title="Set expire_time parameter"
...
modparam("ratelimit", "expire_time", 1800)
...
```


#### hash_size (integer)


The size of the hash table internally used to keep the pipes.
		A larger table is much faster but consumes more memory. The hash size
		must be a power of 2 number.


*Default value is 1024.*


```opensips title="Set hash_size parameter"
...
modparam("ratelimit", "hash_size", 512)
...
```


#### default_algorithm (string)


Specifies which algorithm should be assumed in case it isn't
		explicitly specified in the *rl_check* function.


*Default value is "TAILDROP".*


```opensips title="Set default_algorithm parameter"
...
modparam("ratelimit", "default_algorithm", "RED")
...
```


#### cachedb_url (string)


Enables distributed rate limiting and specifies the backend
		that should be used by the CacheDB interface.


*Default value is "disabled".*


```opensips title="Set cachedb_url parameter"
...
modparam("ratelimit", "cachedb_url", "redis://root:root@127.0.0.1/")
...
```


#### db_prefix (string)


Specifies what prefix should be added to the pipe name. This is
		only used when distributed rate limiting is enabled.


*Default value is "rl_pipe_".*


```opensips title="Set db_prefix parameter"
...
modparam("ratelimit", "db_prefix", "ratelimit_")
...
```


#### repl_buffer_threshold (string)


Used to specify the length of the buffer used by the binary
		replication, in bytes, when a flush should be performed - the pipes
		gathered until then should be sent on the network. This is used
		to avoid using large amount of memory for pipes replication.


*Default value is 32767 bytes.*


```opensips title="Set repl_buffer_threshold parameter"
...
modparam("ratelimit", "repl_buffer_threshold", 500)
...
```


#### repl_timer_interval (string)


Timer in milliseconds, used to specify how often the module
		should replicate its counters to the other instances.


*Default value is 200 ms.*


```opensips title="Set repl_timer_interval parameter"
...
modparam("ratelimit", "repl_timer_interval", 100)
...
```


#### repl_timer_expire (string)


Timer in seconds, used to specify when the counter received
		from a different instance should no longer be taken into account.
		This is used to prevent obsolete values, in case an instance stops
		replicating its counters.


*Default value is 10 s.*


```opensips title="Set repl_timer_expire parameter"
...
modparam("ratelimit", "repl_timer_expire", 10)
...
```


#### pipe_replication_cluster (integer)


Specifies the cluster ID where pipes will be replicated to and
			received from.


*Default value is 0. (no replication)*


```opensips title="Set pipe_replication_cluster parameter"
...
modparam("ratelimit", "pipe_replication_cluster", 1)
...
```


#### bridge_replication (boolean)


Enable the [cluster-bridge replication](../clusterer#bridge_replication)
			feature, if applicable (e.g. the current [pipe replication cluster](#param_pipe_replication_cluster) has
			at least one bridge definition to a foreign cluster).


*Default value is *false*. (disabled)*


```opensips title="Set bridge_replication parameter"
...
modparam("ratelimit", "bridge_replication", true)
...
```


#### bridge_repl_timer_interval (string)


Timer in milliseconds, used to specify how often the module
		should replicate its cluster-local counters to remote clusters,
		if [bridged replication](../clusterer#bridge_replication)
		is in use, as long as it holds the required sharing tag(s).


*Default value is 500 ms.*


```opensips title="Set bridge_repl_timer_interval parameter"
...
modparam("ratelimit", "bridge_repl_timer_interval", 500)
...
```


#### bridge_repl_timer_expire (string)


Timer in seconds, used to specify when the counter received
		from a different cluster should no longer be taken into account.
		This is used to prevent obsolete values, in case an entire cluster
		(data center) is down and stops replicating its counters.


*Default value is 20 s.*


```opensips title="Set bridge_repl_timer_expire parameter"
...
modparam("ratelimit", "bridge_repl_timer_expire", 20)
...
```


#### window_size (int)


How long the history in SBT should be in seconds.


*Default value is "10".*


```opensips title="Set window_size parameter"
...
modparam("ratelimit", "window_size", 5)
...
```


#### slot_period (int)


Value of one slot in milliseconds. This parameter determines
		how granular the algorithm should be. The number of slots will be
		determined by window_size/slot_period.


*Default value is "200".*


```opensips title="Set slot_period parameter"
...
modparam("ratelimit", "window_size", 5)
#we will have 50 slots of 100 milliseconds
modparam("ratelimit", "slot_period", 100)
...
```


### Exported Functions


#### rl_check(name, limit[, algorithm])


Check the current request against the pipe identified by name and
		changes/updates the limit. If no pipe is found, then a new one is
		created with the specified limit and algorithm, if specified. If the
		algorithm parameter doesn't exist, the default one is used.


NOTE: A pipe's algorithm cannot be dynamically changed. Only the one
		specified when the pipe was created will be considered.


NOTE: This function increments the pipe's counter every time it is
		called, even if the call should be declined. Therefore If you are using
		ratelimit to limit only successful traffic, you need to explicitely
		decrease the counter for the declined calls using the
		*rl_dec_count()* function.


The method will return an error code if the limit for the
		matched pipe is reached.


Meaning of the parameters is as follows:


- *name* (string) - this is the name that identifies
				the pipe which should be checked. One can also specify the
				*/s* suffix to indicate the pipe
				should be replicated over cached, or */b*
				to replicate over bin/clusterer interface.
- *limit* (int) - this specifies the threshold
				limit of the pipe. It is strongly related to the algorithm
				used. Note that the limit should be specified as per-second, not
				per-timer_interval.
- *algorithm* (string, optional) - this parameter
				reffers to the algorithm used to check the pipe. If it is
				not set, the default value is used.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, ONREPLY_ROUTE,
			BRANCH_ROUTE, ERROR_ROUTE, LOCAL_ROUTE, TIMER_ROUTE and EVENT_ROUTE.


```opensips title="rl_check usage"
...
	# perform a pipe match for all INVITE methods using RED algorithm
	if (is_method("INVITE")) {
		if (!rl_check("pipe_INVITE", 100, "RED")) {
			sl_send_reply(503, "Server Unavailable");
			exit;
		};
	};
...
	# use default algorithm for each different gateway
	$var(limit) = 10;
	if (!rl_check("gw_$ru", $var(limit))) {
		sl_send_reply(503, "Server Unavailable");
		exit;
	};
...
	# count only successful calls
	if (!rl_check("gw_$ru", 100)) {
		rl_dec_count("gw_$ru");
		sl_send_reply(503, "Server Unavailable");
		exit;
	};
...
```


#### rl_dec_count(name)


This function decreases a counter that could have been previously
		increased by *rl_check* function.


Meaning of the parameters is as follows:


- *name* (string) - identifies the name of the pipe.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, ONREPLY_ROUTE,
			BRANCH_ROUTE, ERROR_ROUTE, LOCAL_ROUTE, TIMER_ROUTE and EVENT_ROUTE.


```opensips title="rl_dec_count usage"
...
	if (!rl_check("gw_$ru", 100, "TAILDROP")) {
		exit;
	} else {
		rl_dec_count("gw_$ru");
	};
...
```


#### rl_reset_count(name)


This function resets a counter that could have been previously
		increased by *rl_check* function.


Meaning of the parameters is as follows:


- *name* - identifies the name of the pipe.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, ONREPLY_ROUTE,
			BRANCH_ROUTE, ERROR_ROUTE, LOCAL_ROUTE, TIMER_ROUTE and EVENT_ROUTE.


```opensips title="rl_reset_count usage"
...
	if (!rl_check("gw_$ru", 100, "TAILDROP")) {
		exit;
	} else {
		rl_reset_count("gw_$ru");
	};
...
```


#### rl_values(ret_avp, regexp)


Returns all the available pipes' names in the *ret_avp*
			output variable.


Meaning of the parameters is as follows:


- *ret_avp* (string) - an AVP where the pipes'
				names will be stored.
- *regexp* (regex, optional) - a regular expression
				used to filter the names of the pipes. If missing, all the pipes
				are returned.


This function can be used from any route.


```opensips title="rl_values usage"
...
	rl_values($avp(values));
	for ($var(pipe) in $(avp(values)[*]))
		xlog("RATELIMIT: $var(pipe): $rl_count($var(pipe))\n");
...
```


### Exported MI Functions


#### ratelimit:list


Replaces obsolete MI command: *rl_list*.


Lists the parameters and variabiles in the ratelimit module.


Name: *ratelimit:list*


Parameters:


- *pipe* (optional) - indicates the name of the
			single pipe to be listed.
- *filter* (optional) - a pattern used to filter
			the active pipes to be listed. The filter is a shell wildcard
			pattern (see glob(7)).
- *filter_out* (optional) - a pattern used to 
			filter out the active pipes NOT to be listed.
			The filter is a shell wildcard pattern (see glob(7)).


Note that you cannot combine multiple paramters when calling this
		function. If using parameters, only one is accepted.


If no parameter are passed to the function, all the active pipes
		are listed.


MI FIFO Command Format:


```bash
		opensips-cli -x mi ratelimit:list pipe=gw_10.0.0.1
		opensips-cli -x mi ratelimit:list filter=gw_*
		
```


#### ratelimit:dump_pipe


Replaces obsolete MI command: *rl_dump_pipe*.


Exposes all the details about the current runtime data (specific to the
		pipe's algorithm) of a pipe. Currently make sense for SBT.


Name: *ratelimit:dump_pipe*


Parameters:


- *pipe* - indicates the name of the pipe.


MI FIFO Command Format:


```bash
		opensips-cli -x mi ratelimit:dump_pipe gw_10.0.0.1
		
```


#### ratelimit:reset_pipe


Replaces obsolete MI command: *rl_reset_pipe*.


Resets the counter of a specified pipe.


Name: *ratelimit:reset_pipe*


Parameters:


- *pipe* - indicates the name of the pipe whose
			counter should be reset.


MI FIFO Command Format:


```bash
		opensips-cli -x mi ratelimit:reset_pipe gw_10.0.0.1
		
```


#### ratelimit:set_pid


Replaces obsolete MI command: *rl_set_pid*.


Sets the PID Controller parameters for the Feedback Algorithm.


Name: *ratelimit:set_pid*


Parameters:


- *ki* - the integral parameter.
- *kp* - the proportional parameter.
- *kd* - the derivative parameter.


MI FIFO Command Format:


```bash
		opensips-cli -x mi ratelimit:set_pid 0.5 0.5 0.5
		
```


#### ratelimit:get_pid


Replaces obsolete MI command: *rl_get_pid*.


Gets the list of in use PID Controller parameters.


Name: *ratelimit:get_pid*


Parameters: *none*


MI FIFO Command Format:


```bash
		opensips-cli -x mi ratelimit:get_pid
		
```


#### rl_bin_status


Dumps each destination used for replication, as well as
		the timestamp of the last message received from them.


Name: *rl_bin_status*


Parameters: *none*


MI FIFO Command Format:


```bash
		opensips-cli -x mi rl_bin_status
		
```


### Exported Pseudo-Variables


#### $rl_count(name)


Returns the counter of a pipe. The variable is read-only.


NULL will be returned if the pipe does not exist.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
