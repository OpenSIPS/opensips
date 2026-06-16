---
title: "uri Module"
description: "Various checks related to SIP URI."
---

## Admin Guide


### Overview


Various checks related to SIP URI.


### Dependencies


#### OpenSIPS Modules


None.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


None.


### Exported Functions


#### is_user(username)


Check if the username in credentials matches the given username.


Meaning of the parameters is as follows:


- *username* - Username string.


This function can be used from REQUEST_ROUTE.


```c title="is_user usage"
...
if (is_user("john")) {
	...
};
...
```


#### has_totag()


Check if To header field uri contains tag parameter.


This function can be used from REQUEST_ROUTE.


```c title="has_totag usage"
...
if (has_totag()) {
	...
};
...
```


#### uri_param(param)


Find if Request URI has a given parameter with no value


Meaning of the parameters is as follows:


- *param* - parameter name to look for.


This function can be used from REQUEST_ROUTE.


```c title="uri_param usage"
...
if (uri_param("param1")) {
	...
};
...
```


#### uri_param(param,value)


Find if Request URI has a given parameter with matching value


Meaning of the parameters is as follows:


- *param* - parameter name to look for.
- *value* - parameter value to match.


This function can be used from REQUEST_ROUTE.


```c title="uri_param usage"
...
if (uri_param("param1","value1")) {
	...
};
...
```


#### add_uri_param(param)


Add to RURI a parameter (name=value);


Meaning of the parameters is as follows:


- *param* - parameter to be appended in
			"name=value" format.


This function can be used from REQUEST_ROUTE.


```c title="add_uri_param usage"
...
add_uri_param("nat=yes");
...
```


#### tel2sip()


Converts RURI, if it is tel URI, to SIP URI.  Returns true, only if
		conversion succeeded or if no conversion was needed (like RURI
		was not tel URI.


This function can be used from REQUEST_ROUTE.


```c title="tel2sip usage"
...
tel2sip();
...
```


#### is_uri_user_e164(pseudo-variable)


Checks if userpart of URI stored in pseudo variable is
		E164 number.


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


```c title="is_uri_user_e164 usage"
...
if (is_uri_user_e164("$fu")) {  # Check From header URI user part
   ...
}
if (is_uri_user_e164("$avp(i:705)") {
   # Check user part of URI stored in avp i:705
   ...
};
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
