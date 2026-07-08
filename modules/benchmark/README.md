---
title: "Benchmark Module"
description: "This module helps developers to benchmark their module functions. By adding this module's functions via the configuration file or through its API, OpenSIPS can log profiling information for every function."
---

## Admin Guide


### Overview


This module helps developers to benchmark their module functions. By adding
		this module's functions via the configuration file or through its API, OpenSIPS
		can log profiling information for every function.


The duration between calls to start_timer and log_timer is stored and logged
		via OpenSIPS's logging facility. Please note that all durations are given as
		microseconds (don't confuse with milliseconds!).


Important note: as this benchmarking is intended to measure the time
		spent in executing different parts/blocks of the script (and not for 
		measuring the time induced by the SIP signaling), the benchmark module
		is to be used within the SAME top route (request route, failure route, 
		branch route, onreply rout, etc). It is not design to be used across 
		different types of top routes (like started in request route and ended in 
		failure route)!!


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### enable (int)


Even when the module is loaded, benchmarking is not enabled
			per default. This variable may have three different values:


- -1 - Globally disable benchmarking
- 0 - Enable per-timer enabling. Single timers are inactive by default
				and can be activated through the MI interface as soon as that feature is
				implemented.
- 1 - Globally enable benchmarking


*Default value is "0".*


```opensips title="Set enable parameter"
...
modparam("benchmark", "enable", 1)
...
```


#### granularity (int)


Logging normally is not done for every reference to the log_timer()
			function, but only every n'th call. n is defined through this variable.
			A sensible granularity seems to be 100.


If granularity is set to 0, then nothing will be logged automatically. Instead benchmark:poll_results MI command can be used to retrieve the results and clean the local values.


*Default value is "100".*


```opensips title="Set granularity parameter"
...
modparam("benchmark", "granularity", 500)
...
```


#### loglevel (int)


Set the log level for the benchmark logs. These levels should be used:


- -3 - L_ALERT
- -2 - L_CRIT
- -1 - L_ERR
- 1 - L_WARN
- 2 - L_NOTICE
- 3 - L_INFO
- 4 - L_DBG


*Default value is "3" (L_INFO).*


```opensips title="Set loglevel parameter"
...
modparam("benchmark", "loglevel", 4)
...
```


This will set the logging level to L_DBG.


### Exported Functions


#### bm_start_timer(name)


Start timer "name". A later call to
		"bm_log_timer()" logs this timer..


```opensips title="bm_start_timer usage"
...
bm_start_timer("test");
...
```


#### bm_log_timer(name)


This function logs the timer with the given ID. The following data are
			logged:


- *Last msgs* is the number of calls in the last logging interval. This equals the granularity variable.


- *Last sum* is the accumulated duration in the current logging interval (i.e. for the last "granularity" calls).


- *Last min* is the minimum duration between start/log_timer calls during the last interval.


- *Last max* - maximum duration.


- *Last average* is the average duration between
					bm_start_timer() and bm_log_timer() since the last logging.


- *Global msgs* number of calls to log_timer.


- *Global sum* total duration in microseconds.


- *Global min*... You get the point. :)


- *Global max* also obvious.


- *Global avg* possibly the most interesting value.


```opensips title="bm_log_timer usage"
...
bm_log_timer("test");
...
```


### Exported Pseudo-Variables


Exported pseudo-variables are listed in the next sections.


#### $BM_time_diff


*$BM_time_diff* - the time difference
			elapsed between calls of bm_start_timer(name) and
			bm_log_timer(name). The value is 0 if no bm_log_timer()
			was called.


### Exported MI Functions


#### benchmark:enable_global


Replaces obsolete MI command: *bm_enable_global*.


Enables/disables the module.


Parameters:


- *enable* - value may be -1, 0 or 1. See
					discription of "enable" parameter.


MI FIFO Command Format:


```bash
			opensips-cli -x mi benchmark:enable_global 1
			
```


#### benchmark:enable_timer


Replaces obsolete MI command: *bm_enable_timer*.


Enable or disable a single timer.


Parameters:


- *timer* - timer name
- *enable* - enable (1) or disable (0) timer


MI FIFO Command Format:


```bash title="Enabling a timer"
...
opensips-cli -x mi benchmark:enable_timer test 1
...
```


#### benchmark:granularity


Replaces obsolete MI command: *bm_granularity*.


Modifies the benchmarking granularity.


Parameters:


- *benchmark:granularity* - See
					discription of "granularity" parameter.


MI FIFO Command Format:


```bash
			opensips-cli -x mi benchmark:granularity 300
			
```


#### benchmark:loglevel


Replaces obsolete MI command: *bm_loglevel*.


Modifies the module log level.


Parameters:


- *log_level* - See
					discription of "loglevel" parameter.


MI FIFO Command Format:


```bash
			opensips-cli -x mi benchmark:loglevel 4
			
```


#### benchmark:poll_results


Replaces obsolete MI command: *bm_poll_results*.


Returns the current and global results for each timer. This command is only available if the "granularity" variable is set to 0. It can be used to get results in stable time intervals instead of every N messages. Each timer will have 2 nodes - the local and the global values. Format of the values is the same as the one normally used in logfile. This way of getting the results allows to interface with external graphing applications like Munin.


If there were no new calls to *bm_log_timer* since last check, then all current values of a timer will be equal 0. Each call to *benchmark:poll_results* will reset current values (but not global ones).


```bash title="Getting the results via FIFO interface"
...
opensips-cli -x mi benchmark:poll_results
register_timer
	3/40/12/14/13.333333
	9/204/12/97/22.666667
security_check_timer
	3/21/7/7/7.000000
	9/98/7/41/10.888889
...
```


### Example of usage


Measure the duration of user location lookup.


```opensips title="benchmark usage"
...
bm_start_timer("usrloc-lookup");
lookup("location");
bm_log_timer("usrloc-lookup");
...
```


## Developer Guide


The benchmark module provides an internal API to be used by 
	other OpenSIPS modules. The available functions are identical to the user exported
	functions.


Please note that this module is intended mainly for developers. It should
	be used with caution in production environments.


### Available Functions


#### bm_register(name, mode, id)


This function register a new timer and/or returns the internal ID
		associated with the timer. mode controls the creation of new timer
		if not found. id is to be used by start and log timer functions.


#### bm_start(id)


This function equals the user-exported function bm_start_timer. The
		id is passed as an integer, though.


#### bm_log(id)


This function equals the user-exported function bm_log_timer. The id
		is passed as an integer, though.


### Benchmark API Example


```c title="Using the benchmark module's API from another module"
...
#include "../benchmark/benchmark.h"
...
struct bm_binds bmb;
...
...
/* load the benchmarking API */
if (load_bm_api( &bmb )!=0) {
    LM_ERR("can't load benchmark API\n");
    goto error;
}
...
...
/* Start/log timers during a (usually user-exported) module function */
bmb.bm_register("test", 1, &id)
bmb.bm_start(id);
do_something();
bmb.bm_log(id);
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
