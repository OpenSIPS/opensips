---
title: "presence_reginfo Module"
description: "The module enables the handling of \"Event: reg\" (as defined in RFC 3680) inside of the presence module. This can be used distribute the registration-info status to the subscribed watchers."
---

## Admin Guide


### Overview


The module enables the handling of "Event: reg" (as defined 
	      in RFC 3680) inside of the presence module. This can be used
	      distribute the registration-info status to the subscribed watchers.


The module does not currently implement any authorization
	      rules.  It assumes that publish requests are only issued by
	      an authorized application and subscribe requests only by
	      authorized users.  Authorization can thus be easily done in 
	      OpenSIPS configuration file before calling handle_publish() 
	      and handle_subscribe() functions.


Note: This module only activates the processing of the "reg" 
	      in the presence module. To send dialog-info to watchers you also 
	      need a source which PUBLISH the reg info to the presence module.
	      For example you can use the pua_reginfo module or any external
	      component. This approach allows to have the presence server and the
	      reg-info aware publisher (e.g. the main proxy) on different 
	      OpenSIPS instances.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *presence*.


#### External Libraries or Applications


None.


### Exported Parameters


#### default_expires (int)


The default expires value used when missing from SUBSCRIBE
               message (in seconds).


*Default value is "3600".*


```opensips title="Set default_expires parameter"
        ...
        modparam("presence_reginfo", "default_expires", 3600)
        ...
        
```


#### aggregate_presentities (int)


Whether to aggregate in a single notify body all registration 
							presentities. Useful to have all registrations on first NOTIFY
							following initial SUBSCRIBE.


*Default value is "0" (disabled).*


```opensips title="Set aggregate_presentities parameter"
					...
					modparam("presence_reginfo", "aggregate_presentities", 1)
					...
					
```


### Exported Functions


None to be used in configuration file.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
