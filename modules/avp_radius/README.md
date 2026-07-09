---
title: "avp_radius Module"
description: "avp_radius module allows loading of user's attributes into AVPs from Radius. User's name and domain can be based on From URI, Request URI, or authenticated credentials."
---

## Admin Guide


### Overview


avp_radius module allows loading of user's attributes into AVPs from
Radius. User's name and domain can be based on From URI, Request
URI, or authenticated credentials.


The module assumes that Radius returns the AVPs as values of reply
attribute SIP-AVP. Its value must be a string of form:


- *value = SIP_AVP_NAME SIP_AVP_VALUE*
- *SIP_AVP_NAME = STRING_NAME | '#'ID_NUMBER*
- *SIP_AVP_VALUE = ':'STRING_VALUE | '#'NUMBER_VALUE*


```c title="'SIP-AVP' RADIUS AVP exmaples"
....
"email:joe@yahoo.com"
    -> STRING NAME AVP (email) with STRING VALUE (joe@yahoo.com)
"#14:joe@yahoo.com"
    -> ID AVP (14) with STRING VALUE (joe@yahoo.com)
"age#28"
    -> STRING NAME AVP (age) with INTEGER VALUE (28)
"#14#28"
    -> ID AVP (14) with INTEGER VALUE (28)
....
```


For AVP with STRING NAME, the module prefixes each attribute name as 
returned from Radius by string "caller_" or 
"callee_" depending if caller's or callee's attributes 
are loaded.


### Dependencies


#### OpenSIPS Modules


The module depends on the following modules (in the other words 
the listed modules must be loaded before this module):


- *none*


#### External Libraries or Applications


The following libraries or applications must be installed 
before compilling OpenSIPS with this module loaded:


- *radiusclient-ng* 0.5.0 or higher -- 
library and development files. See [http://developer.berlios.de/projects/radiusclient-ng/](http://developer.berlios.de/projects/radiusclient-ng/).


### Exported Parameters


#### radius_config (string)


This is the location of the configuration file of radius client 
libraries.


Default value is 
"/usr/local/etc/radiusclient-ng/radiusclient.conf".


```opensips title="radius_config parameter usage"
modparam("avp_radius", "radius_config", "/etc/radiusclient.conf")
```


#### caller_service_type (integer)


This is the value of the Service-Type radius attribute to be
used, when caller's attributes are loaded.


Default value is dictionary value of "SIP-Caller-AVPs"
Service-Type.


```opensips title="caller_service_type parameter usage"
modparam("avp_radius", "caller_service_type", 18)
```


#### callee_service_type (integer)


This is the value of the Service-Type radius attribute to be
used, when callee's attributes are loaded.


Default value is dictionary value of "SIP-Callee-AVPs"
Service-Type.


```opensips title="callee_service_type parameter usage"
modparam("avp_radius", "callee_service_type", 19)
```


### Exported Functions


#### avp_load_radius(user)


The functions loads user's attributes from radius and stores them
into AVPs.  Parameter "user" is used to indicate,
whose attributes are loaded.  Possible values are:


- *caller* - attributes belong to the user
of the From URI are loaded
- *callee* - attributes belong to the user
of the Request URI are loaded
- *digest* - attributes belong to the
authenticated user are loaded


AVP name returned from Radius is prefixed by string
"caller_", if avp_load_radius parameter is
"caller" or "digest", and by
"callee_", if parameter is "callee".


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="avp_load_radius() usage"
...
avp_load_radius("callee");
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
