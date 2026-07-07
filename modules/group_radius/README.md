---
title: "group_radius Module"
description: "This module export functions necessary for group membership checking over radius. There is a database table that contains list of users and groups they belong to. The table is used by functions of this module."
---

## Admin Guide


### Overview


This module export functions necessary for group membership checking 
		over radius. There is a database table that contains list of users 
		and groups they belong to. The table is used by functions of this 
		module.


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


Location of the configuration file of the radius client library.


*Default value is 
			"/usr/local/etc/radiusclient-ng/radiusclient.conf".*


```opensips title="Set radius_config parameter"
...
modparam("group_radius", "radius_config", "/etc/radiusclient.conf")
...
```


#### use_domain (integer)


If set to 1 then username@domain will be used for lookup, if set to 0 
		then only username will be used.


*Default value is 0 (no).*


```opensips title="Set use_domain parameter"
...
modparam("group_radius", "use_domain", 1)
...
```


### Exported Functions


#### radius_is_user_in(URI, group)


The function returns true if username in the given URI is member of 
		the given group and false if not.


Meaning of the parameters is as follows:


- *URI* - URI whose username and 
			optionally domain to be used, this can be one of:
			
				
				Request-URI - Use Request-URI username and 
				(optionally) domain.
				
				
				To - Use To username and (optionally) domain.
				
				
				From - Use From username and (optionally) domain.
				
				
				Credentials - Use digest credentials username.
- *group* - Name of the group to check.


This function can be used from REQUEST_ROUTE.


```opensips title="radius_is_user_in usage"
...
if (radius_is_user_in("Request-URI", "ld")) {
	...
};
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
