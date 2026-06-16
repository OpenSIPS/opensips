---
title: "AAA_DIAMETER MODULE"
description: "This module provides a Diameter implementation for the core AAA API interface."
---

## Admin Guide


### Overview


This module provides a Diameter implementation for the core AAA API interface.


Any module that wishes to use it has to do the following:


- *include aaa.h*
- *make a bind call with a proper Diameter-specific URL, e.g. "diameter:freeDiameter-client.conf"*


### Dependencies


#### OpenSIPS Modules


None.


#### External Libraries or Applications


All Diameter message building and parsing, as well as the peer state
		machine and Diameter-related network communication are all powered by
		[the freeDiameter project](http://www.freediameter.net/trac/)
		and C libraries, dynamically linking with the "aaa_diameter" module.


The following libraries must be installed before running
		OpenSIPS with this module loaded:


- *libfdcore* v1.2.1 or higher
- *libfdproto* v1.2.1 or higher


### Exported Parameters


#### fd_log_level (integer)


This parameter measures the *quietness* of the logging
		done by the freeDiameter library. Possible values:


- 0 (ANNOYING)
- 1 (DEBUG)
- 3 (NOTICE, default)
- 5 (ERROR)
- 6 (FATAL)


NOTE: since freeDiameter logs to standard output, you must also enable
		the new core parameter, **log_stdout**,
		before getting any logs from the library.


```c title="Setting the fd_log_level parameter"
modparam("aaa_diameter", "fd_log_level", 0)
```


#### realm (string)


The unique realm to be used by all participating Diameter peers.


Default value is *"diameter.test"*.


```c title="Setting the realm parameter"
modparam("aaa_diameter", "realm", "opensips.org")
```


#### peer_identity (string)


The identity (realm subdomain) of the Diameter server peer, to which
		the OpenSIPS Diameter client peer will connect.


Default value is *"server"*
				(i.e. "server.diameter.test").


```c title="Setting the peer_identity parameter"
modparam("aaa_diameter", "peer_identity", "server")
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
