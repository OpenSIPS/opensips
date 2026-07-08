---
title: "cfgutils Module"
description: "Useful extensions for the server configuration."
---

## Admin Guide


### Overview


Useful extensions for the server configuration.


The cfgutils module can be used to introduce randomness to
	the behaviour of the server. It provides setup functions
	and the "rand_event" function. This function return either
	true or false, depending on a random value and a specified probability.
	E.g. if you set via fifo or script a probability value of 5%, then 5% of
	all calls to rand_event will return false.
	The pseudovariable "$RANDOM" could be used to introduce 
	random values e.g. into a SIP reply.


The benefit of this module is the probability of the decision
	can be manipulated by external applications such as web interface
	or command line tools. The probability must be specified as 
	percent value, ranging from 0 to 100.


The module exports commands to FIFO server that can be used to change
	the global settings via FIFO interface. The FIFO commands are:
	"set_prob", "reset_prob" and
	"get_prob".


This module can be used for simple load-shedding, e.g. reply 5% of
	the Invites with a 503 error and a adequate random Retry-After value.


The module provides as well functions to delay the execution of the
	server. The functions "sleep" and "usleep" could
	be used to let the server wait a specific time interval.


It can also hash the config file used from the server with a (weak)
	cryptographic hash function on startup. This value is saved and can be
	later compared to the actual hash, to detect modifications of this file
	after the server start. This functions are available as the FIFO commands
	"check_config_hash" and "get_config_hash".


### Dependencies


The module depends on the following modules (in the other words the
		listed modules must be loaded before this module):


- *none*


### Exported Parameters


#### initial_probability (string)


The initial value of the probability.


Default value is 
			"10".


```opensips title="initial_probability parameter usage"
   
modparam("cfgutils", "initial_probability", 15)
   
```


#### hash_file (string)


The config file name for that a hash value should be calculated on startup.


There is no default value, is no parameter is given the hash functionality
		is disabled.


```opensips title="hash_file parameter usage"
   
modparam("cfgutils", "hash_file", "/etc/opensips/opensips.cfg")
   
```


#### shvset (string)


Set the value of a shared variable ($shv(name)). The parameter
		can be set many times.


The value of the parameter has the format:
		_name_ '=' _type_ ':' _value_


- _name_: shared variable name
- _type_: type of the value

  - "i": integer value
  - "s": string value
- _value_: value to be set


Default value is "NULL".


```opensips title="shvset parameter usage"
...
modparam("cfgutils", "shvset", "debug=i:1")
modparam("cfgutils", "shvset", "pstngw=s:sip:10.10.10.10")
...
```


#### varset (string)


Set the value of a script variable ($var(name)). The parameter
		can be set many times.


The value of the parameter has the format:
		_name_ '=' _type_ ':' _value_


- _name_: shared variable name
- _type_: type of the value

  - "i": integer value
  - "s": string value
- _value_: value to be set


Default value is "NULL".


```opensips title="varset parameter usage"
...
modparam("cfgutils", "varset", "init=i:1")
modparam("cfgutils", "varset", "gw=s:sip:11.11.11.11;transport=tcp")
...
```


### Exported Functions


#### rand_event([probability])


Return true or false, depending on a random value and a
			probability value. If probability parameter is given, it will
			override the global parameter set by rand_set_prob() function.


```opensips title="rand_event() usage"
...
if (rand_event()) {
  append_to_reply("Retry-After: 120\n");
  sl_send_reply("503", "Try later");
  exit;
};
# normal message processing follows
...
```


#### rand_set_prob(probabiltiy)


Set the "probability" of the decision.


"probability" can have a value from the range 0..99.


```opensips title="rand_set_prob() usage"
...
rand_set_prob("4");
...
```


#### rand_reset_prob()


Reset the probability back to the inital value.


```opensips title="rand_reset_prob() usage"
...
rand_reset_prob();
...
```


#### rand_get_prob()


Return the current probability setting, e.g. for logging purposes.


```opensips title="rand_get_prob() usage"
...
rand_get_prob();
   
```


#### sleep(time)


Waits "time" seconds.


Meaning of the parameters is as follows:


- *time* - Time to wait in seconds.
				String may be a pseudovariable. In case that variable does 
				not contain a numerical value, it is evaluated to zero seconds.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
			FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="sleep usage"
...
sleep("1");
...
$avp(secs)="10";
sleep("$avp(secs)");
...
			
```


#### usleep(time)


Waits "time" micro-seconds.


Meaning of the parameters is as follows:


- *time* - Time to wait in micro-seconds.
				The string may contain a pseudovariable. In case that pseudovar
				does not contain a numerical value, it is evaluated to zero seconds.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
			FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="usleep usage"
...
usleep("500000"); # sleep half of sec
...
			
```


#### abort()


Debugging function that aborts the server. Depending on the
			configuration of the server a core dump will be created.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
			FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="abort usage"
...
abort();
...
			
```


#### pkg_status()


Debugging function that dumps the status for the private (PKG) memory.
			This information is logged to the default log facility, depending on
			the general log level and the memlog setting. You need to compile
			the server with activated memory debugging to get detailed informations.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
			FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="pkg_status usage"
...
pkg_status();
...
			
```


#### shm_status()


Debugging function that dumps the status for the shared (SHM) memory.
			This information is logged to the default log facility, depending on
			the general log level and the memlog setting. You need to compile
			the server with activated memory debugging to get detailed informations.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
			FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="shm_status usage"
...
shm_status();
...
			
```


#### set_count(pvar name, result pvar name)


Function that counts the values of a pseudovariable. It makes sense to 
			call this function only for pseudovariables that can take more values
			(avp, headers).


The result is returned in the second parameter.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
			FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="set_count usage"
...
set_count("$avp(10)", "$avp(result)");
...
			
```


#### set_select_weight(pseudovarible_name)


This function selects an element from a set formed by the values of the
			pseudovariable name given as parameter. It applies the genetic algorithm
			- roulette-wheel selection to choose an element from a set. The probability
			of selecting a certain element is proportionate with its weight. It will
			return the index of that selected element.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
			FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="set_select_weight usage"
...
$avp(21) = set_select_weight("$avp(10)");
...
			
```


#### ts_usec_delta(t1_sec, t1_usec, t2_sec, t2_usec, delta)


This function returns the difference between two timestamps, specified
			in seconds and microseconds. The result is returned in the last
			parameter, expressed in microseconds.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
			FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="ts_usec_delta usage"
...
ts_usec_delta("$avp(10)", "$avp(20)", "10", "300", "$avp(result)");
...
			
```


### Exported MI Functions


#### rand_set_prop


Set the probability value to the given parameter.
				The parameter should be a percent value.


The parameter value must be a number from 0 to 99.


```bash title="rand_set_prob usage"
...
$ opensipsctl fifo rand_set_prob 10
...
```


#### rand_reset_prob


Reset the probability value to the inital start value.


This command don't need a parameter.


```bash title="rand_reset_prob usage"
...
$ opensipsctl fifo rand_reset_prob
...
```


#### rand_get_prob


Return the actual probability setting.


The function return the actual probability value.


```bash title="rand_get_prob usage"
...
$ opensipsctl fifo get_prob
The actual probability is 50 percent.
...
```


#### check_config_hash


Check if the actual config file hash is identical to the stored one.


The function returns 200 OK if the hash values are identical, 400 if
				there are not identical, 404 if no file for hashing has been configured
				and 500 on errors. Additional a short text message is printed.


```bash title="check_config_hash usage"
...
$ opensipsctl fifo check_config_hash
The actual config file hash is identical to the stored one.
...
```


#### get_config_hash


Return the stored config file hash.


The function returns 200 OK and the hash value on success or 404 if no
				file for hashing has been configured.


```bash title="get_config_hash usage"
...
$ opensipsctl fifo get_config_hash
1580a37104eb4de69ab9f31ce8d6e3e0
...
```


#### shv_set


Set the value of a shared variable ($shv(name)).


Parameters:


- _name_: shared variable name
- _type_: type of the value

  - "int": integer value
  - "str": string value
- _value_: value to be set


MI FIFO Command Format:


```bash
		:shv_set:_reply_fifo_file_
		_name_
		_type_
		_value_
		_empty_line_
		
```


```bash title="shv_set usage"
...
$ opensipsctl fifo shv_set debug int 0
...
```


#### shv_get


Get the value of a shared variable ($shv(name)).


Parameters:


- _name_: shared variable name. If this parameter
			is missing, all shared variables are returned.


MI FIFO Command Format:


```bash
		:shv_get:_reply_fifo_file_
		_name_
		_empty_line_
		
```


```bash title="shv_get usage"
...
$ opensipsctl fifo shv_get debug
$ opensipsctl fifo shv_get
...
```


### Exported Pseudo-Variables


#### $env(name)


This PV provides access to the environment variable 'name'.


```opensips title="env(name) pseudo-variable usage"
...
xlog("PATH environment variable is $env(PATH)\n");
...
				 
```


#### $RANDOM


Returns a random value from the [0 - 2^31) range.


```opensips title="RANDOM pseudo-variable usage"
...
  $avp(10) = ($RANDOM / 16777216); # 2^24
  if ($avp(10) < 10) {
     $avp(10) = 10;
  }
  append_to_reply("Retry-After: $avp(10)\n");
  sl_send_reply("503", "Try later");
  exit;
# normal message processing follows
   
				 
```


#### $time(name)


The PV provides access to broken-down time attributes.


The "name" can be:


- *sec* - return seconds (int 0-59)
- *min* - return minutes (int 0-59)
- *hour* - return hours (int 0-23)
- *mday* - return the day of month (int 0-59)
- *mon* - return the month (int 1-12)
- *year* - return the year (int, e.g., 2008)
- *wday* - return the day of week (int, 1=Sunday - 7=Saturday)
- *yday* - return the day of year (int, 1-366)
- *isdst* - return daylight saving time status (int, 0 - DST off, >0 DST on)


```opensips title="time(name) pseudo-variable usage"
...
if ($time(year) == 2008) {
	xlog("request: $rm from $fu to $ru in year 2008\n");
}
...
				 
```


#### $shv(name)


It is a class of pseudo-variables stored in shared memory. The
				value of $shv(name) is visible across all opensips processes.
				Each "shv" has single value and it is initialized
				to integer 0. You can use "shvset" parameter to
				initialize the shared variable. The module exports a set of MI
				functions to get/set the value of shared variables.


```opensips title="shv(name) pseudo-variable usage"
...
modparam("cfgutils", "shvset", "debug=i:1")
...
if ($shv(debug) == 1) {
	xlog("request: $rm from $fu to $ru\n");
}
...
				 
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
