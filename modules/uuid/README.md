---
title: "UUID Module"
description: "This module provides a way to generate universally unique identifiers (UUID) as specified in RFC 4122."
---

## Admin Guide


### Overview


This module provides a way to generate universally unique identifiers
(UUID) as specified in RFC 4122. The UUID is provided as a string
representation by reading the [uuid](#pv_uuid)
pseudo-variable or calling the [uuid](#func_uuid)
script function.


### Dependencies


#### OpenSIPS Modules


This module does not depend on other modules.


#### External Libraries or Applications


- *libuuid* - part of the util-linux
package, can be downloaded from:
ftp://ftp.kernel.org/pub/linux/utils/util-linux/


### Exported Parameters


The module does not export any parameters.


### Exported Pseudo-Variables


#### $uuid


The *$uuid* variable returns a newly generated
version 4 UUID based on high-quality randomness from /dev/urandom,
if available. Otherwise, a version 1 UUID (based on
current time and the local ethernet MAC address) will be generated.


```opensips title="$uuid usage"
xlog("generated uuid: $uuid\n");
```


### Exported Functions


#### uuid(out_var, [version])


Generates a new UUID.


- *out_var* - an output variable
to return the generated UUID.
- *version* (optional) - UUID version
number. The supported values are:
    - *0* - a RFC version 4 or
    version 1 UUID will be generated, depending on the
    availability of high-quality randomness from
    /dev/urandom. This is the default behavior, if the
    *version* parameter is missing.
    - *1* - version 1 UUID
    based on current time and the local ethernet MAC
    address
    - *4* - version 4 UUID
    based on a high-quality random number generator. If
    not available, a pseudo-random generator will be
    substituted.


If UUID version 1 is used, the function will return the value
*2* if the UUID was generated in an unsafe
manner. This refers to the posibility of two concurrently
running processes generating the same UUID, in cases where
synchronization mechanisms are not available (more details
can be found in the *uuid_generate* man pages
of *libuuid*).


This function can be used from any route.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
