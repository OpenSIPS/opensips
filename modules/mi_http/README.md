---
title: "mi_http Module"
description: "This module provides an HTTP transport layer implementation for OpenSIPS's Management Interface."
---

## Admin Guide


### Overview


This module provides an HTTP transport layer implementation
for OpenSIPS's Management Interface.


### To-do


Features to be added in the future:


- possibility to authenticate connections.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *httpd* module.


### Exported Parameters


#### mi_http_root(string)


Specifies the root path for mi http requests.
The link to the mi web interface must be constructed
using the following patern:
http://[opensips_IP]:[opensips_mi_port]/[mi_http_root]


*The default value is "mi".*


```opensips title="Set mi_http_root parameter"
...
modparam("mi_http", "mi_http_root", "opensips_mi")
...
```


#### mi_http_method(integer)


Specifies the HTTP request method to be used:


- 0 - use GET HTTP request
- 1 - use POST HTTP request


*The default value is 0.*


```opensips title="Set mi_http_method parameter"
...
modparam("mi_http", "mi_http_method", 1)
...
```


#### trace_destination (string)


Trace destination as defined in the tracing module. Currently
the only tracing module is **proto_hep**.
This is where traced mi messages will go.


**WARNING:**A tracing module must be
loaded in order for this parameter to work. (for example
**proto_hep**).


*Default value is none(not defined).*


```opensips title="Set trace_destination parameter"
...
modparam("proto_hep", "trace_destination", "[hep_dest]10.0.0.2;transport=tcp;version=3")

modparam("mi_http", "trace_destination", "hep_dest")
...
```


#### trace_bwlist (string)


Filter traced mi commands based on a blacklist or a whitelist.
**trace_destination** must be defined for
this parameter to have any purpose. Whitelists can be defined using
'w' or 'W', blacklists using 'b' or 'B'. The type is separate by the
actual blacklist by ':'. The mi commands in the list must be separated
by ','.


Defining a blacklists means all the commands that are not blacklisted
will be traced. Defining a whitelist means all the commands that are
not whitelisted will not be traced.
**WARNING:** One can't define both
a whitelist and a blacklist. Only one of them is allowed. Defining
the parameter a second time will just overwrite the first one.


> [!WARNING]
> A tracing module must be
> loaded in order for this parameter to work. (for example
> **proto_hep)**.


*Default value is none(not defined).*


```opensips title="Set trace_destination parameter"
...
## blacklist ps and which mi commands
## all the other commands shall be traced
modparam("mi_http", "trace_bwlist", "b: ps, which")
...
## allow only sip_trace mi command
## all the other commands will not be traced
modparam("mi_http", "trace_bwlist", "w: sip_trace")
...
```


### Exported Functions


No function exported to be used from configuration file.


### Known Issues


Commands with large responses (like ul_dump) will fail if the
configured size of the httpd buffer is to small (or if there isn't
enough pkg memory configured).


Future realeases of the httpd and mi_httpd modules will address this issue.


*doc copyrights:*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
