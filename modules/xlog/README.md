---
title: "xlog Module"
description: "This module provides the possibility to print user formatted log or debug messages from OpenSIPS scripts, similar to printf function. A C-style printf specifier is replaced with a part of the SIP request or other variables from system. [sec implemented specifiers](#sec-implemented-specif..."
---

## Admin Guide


### Overview


This module provides the possibility to print user formatted log or
debug messages from OpenSIPS scripts, similar to printf function. 
A C-style printf specifier is replaced with a part of the SIP request or other
variables from system.
[sec implemented specifiers](#implemented_specifiers) shows what can be printed
out.


### Implemented Specifiers


In the xlog function, you use pseudo-variables, that are a part
of OpenSIPS core and are used by other modules as well (e.g., avpops
in the function avp_printf())


The most important changes from earlier versions of OpenSIPS are:


- - '%' has been replaced by '$'
- - to print a header, use now $hdr(header_name[index]) instead of
%{header_name[index]}
- - to print an AVP, use now $avp([si]:avp_id[index]) instead of
%{[si]:avp_id[index]} or $avp([$avp_alias[index]) instead of
%{[$avp_alias[index]}


The full list of available pseudo-variables in OpenSIPS is availabe at:
[http://opensips.org/dokuwiki/](http://opensips.org/dokuwiki/)


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### buf_size (integer)


Maximum size of the log message.


*Default value is 4096.*


```opensips title="Set buf_size parameter"
...
modparam("xlog", "buf_size", 8192)
...
```


#### force_color (integer)


When set to 1, forces color printing even if log_stderror=0.


*Default value is 0.*


```opensips title="Set force_color parameter"
...
modparam("xlog", "force_color", 0)
...
```


### Exported Functions


#### xlog([level,] format)


Print a formated message using LOG function.


Meaning of the parameters are as follows:


- *level* - The level that will be used in LOG function. It can be:

  - L_ALERT - log level -3
  - L_CRIT - log level -2
  - L_ERR - log level -1
  - L_WARN - log level 1
  - L_NOTICE - log level 2
  - L_INFO - log level 3
  - L_DBG - log level 4
  - $pv - any valid pseudo-variable, that has an integer value.
See above options for valid log levels.
If it is not a pseudo-variable, then what really matters is the
third letter of the value. If the log level is higher than the
"debug" global parameter, the message is not printed
to syslog.
If this parameter is missing, the implicit log level is 'L_ERR'.
- *format* - The formatted string to be printed.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, ONREPLY_ROUTE, BRANCH_ROUTE.


```opensips title="xlog usage"
...
xlog("L_ERR", "time [$Tf] method ($rm) r-uri ($ru) 2nd via ($hdr(via[1]))\n");
...
xlog("time [$Tf] method ($rm) r-uri ($ru) 2nd via ($hdr(via[1]))\n");
...
$var(loglevel) = 2;
xlog("$var(loglevel)", "time [$Tf] method ($rm) r-uri ($ru)\n");
...
```


#### xdbg(format)


Print a formatted message using DBG function.


Meaning of the parameters is as follows:


- *format* - The formatted string to be printed.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, ONREPLY_ROUTE, BRANCH_ROUTE.


```opensips title="xdbg usage"
...
xdbg("time $Cbx[$Tf]$Cxx method ($rm) r-uri ($ru)\n");
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
