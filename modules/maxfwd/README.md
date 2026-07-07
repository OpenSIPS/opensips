---
title: "maxfwd Module"
description: "The module implements all the operations regarding MaX-Forward header field, like adding it (if not present) or decrementing and checking the value of the existent one."
---

## Admin Guide


### Overview


The module implements all the operations regarding MaX-Forward header 
		field, like adding it (if not present) or decrementing and checking 
		the value of the existent one.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### max_limit (integer)


Set an upper limit for the max-forward value in the outgoing requests.
		If the header is present, the decremented value is not allowed to 
		exceed this max_limits - if it does, the header value will by 
		decreased to "max_limit".


Note: This check is done when calling the 
		mf_process_maxfwd_header() header.


The range of values stretches from 1 to 256, which is the maximum 
		MAX-FORWARDS value allowed by RFC 3261.


*Default value is "256".*


```opensips title="Set max_limit parameter"
...
modparam("maxfwd", "max_limit", 32)
...
```


### Exported Functions


#### mf_process_maxfwd_header(max_value)


If no Max-Forward header is present in the received request, a header 
		will be added having the original value equal with 
		"max_value". If a Max-Forward header is already present,
		its value will be decremented (if not 0).


Retuning codes:


- *2 (true)* - header was not found and
			a new header was successfully added.
- *1 (true)* - header was found and its 
			value was successfully decremented (had a non-0 value).
- *-1 (false)* - the header was found and
			its value is 0 (cannot be decremented).
- *-2 (false)* - error during processing.


The return code may be extensivly tested via script variable 
		"retcode" (or "$?").


Meaning of the parameters is as follows:


- *max_value* (int) - Value to be added if 
			there is no Max-Forwards header field in the message.


This function can be used from REQUEST_ROUTE.


```opensips title="mx_process_maxfwd_header usage"
...
# initial sanity checks -- messages with
# max_forwards==0, or excessively long requests
if (!mf_process_maxfwd_header(10) && $retcode==-1) {
	sl_send_reply(483,"Too Many Hops");
	exit;
};
...
```


#### is_maxfwd_lt(max_value)


Checks if the Max-Forward header value is less then the 
		"max_value" parameter value. It considers also the value
		of the new inserted header (if locally added).


Retuning codes:


- *1 (true)* - header was found or set and 
			its value is strictly less than "max_value".
- *-1 (false)* - the header was found or 
			set and its value is greater or equal to "max_value".
- *-2 (false)* - header was not found or
			not set.
- *-3 (false)* - error during processing.


The return code may be extensivly tested via script variable 
		"retcode" (or "$?").


Meaning of the parameters is as follows:


- *max_value* (int) - value to check the 
			Max-Forward.value against (as less than).


```opensips title="is_maxfwd_lt usage"
...
# next hope is a gateway, so make no sens to
# forward if MF is 0 (after decrement)
if ( is_maxfwd_lt(1) ) {
	sl_send_reply(483,"Too Many Hops");
	exit;
};
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
