---
title: "uri_radius Module"
description: "This module implements some URI related Radius based tests."
---

## Admin Guide


### Overview


This module implements some URI related Radius based tests.


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


Radiusclient configuration file.


*Default value is "/usr/local/etc/radiusclient-ng/radiusclient.conf".*


```c title="Set param_name parameter"
...
modparam("uri_radius", "radius_config", "/etc/radiusclient.conf")
...
```


#### service_type (integer)


Radius service type used in
	`radius_does_uri_exist` and `radius_does_uri_user_exist` checks.


*Default value is 10 (Call-Check).*


```c title="Set service_type parameter"
...
modparam("uri_radius", "service_type", 11)
...
```


#### use_sip_uri_host (integer)


If zero, `radius_does_uri_exist`
	sends to RADIUS server Request URI user@host in UserName
	attribute.  If non-zero, `radius_does_uri_exist`
	sends to RADIUS server Request URI user in UserName attribute
	and host in SIP-URI-Host attribute.


*Default value is 0.*


```c title="Set use_sip_uri_host parameter"
...
modparam("uri_radius", "use_sip_uri_host", 1)
...
```


### Exported Functions


#### radius_does_uri_exist([pvar])


Checks from Radius if user@host in Request-URI or in
		URI stored in pseudo variable argument belongs
		to a local user. Can be used to decide if 404 or 480 should
		be returned after lookup has failed.   If yes, loads AVP
		based on SIP-AVP reply items returned from Radius.  Each
		SIP-AVP reply item must have a string value of form:


- *value = SIP_AVP_NAME SIP_AVP_VALUE*
- *SIP_AVP_NAME = STRING_NAME | '#'ID_NUMBER*
- *SIP_AVP_VALUE = ':'STRING_VALUE | '#'NUMBER_VALUE*


Returns 1 if Radius returns Access-Accept, -1 if Radius
		returns Access-Reject, and -2 in case of internal
		error.


This function can be used from REQUEST_ROUTE.


```c title="radius_does_uri_exist usage"
...
if (radius_does_uri_exist()) {
	...
};
...
```


#### radius_does_uri_user_exist([pvar])


Similar to radius_does_uri_exist, but check is done
		based only on Request-URI user part or user stored in
		pseudo variable argument.  User should thus
		be unique among all users, such as an E.164 number.


This function can be used from REQUEST_ROUTE.


```c title="radius_does_uri_user_exist usage"
...
if (radius_does_uri_user_exist()) {
	...
};
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
