---
title: "uri Module"
description: "Various checks related to SIP URI."
---

## Admin Guide


### Overview


Various checks related to SIP URI.


This module implements some URI related AAA or DB based tests.


### Dependencies


#### OpenSIPS Modules


At least one of the following modules must be loaded before this module:


- *a OpenSIPS database module*.
- *an aaa protocol module*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### aaa_url (string)


This is the url representing the AAA protocol used and the location of the configuration file of this protocol.


```opensips title="Set aaa_url parameter"
...
modparam("uri", "aaa_url", "radius:/etc/radiusclient-ng/radiusclient.conf")
...
```


#### service_type (integer)


AAA service type used in
`aaa_does_uri_exist` and `aaa_does_uri_user_exist` checks.


*Default value is 10 (Call-Check).*


```opensips title="Set service_type parameter"
...
modparam("uri", "service_type", 11)
...
```


#### use_sip_uri_host (integer)


If zero, `aaa_does_uri_exist`
sends to AAA server Request URI user@host in UserName
attribute.  If non-zero, `aaa_does_uri_exist`
sends to AAA server Request URI user in UserName attribute
and host in SIP-URI-Host attribute.


*Default value is 0.*


```opensips title="Set use_sip_uri_host parameter"
...
modparam("uri", "use_sip_uri_host", 1)
...
```


#### db_url (string)


URL of the database to be used.


If the db_url string is not set, you will not be able to use
the DB related functions.


*Default value is ">NULL".*


```opensips title="Set db_url parameter"
...
modparam("uri", "db_url", "mysql://username:password@localhost/opensips")
...
```


#### db_table (string)


The DB table that should be used. Its possible to use the
"subscriber" and "uri" table. If the
"uri" table should be used, an additional parameter
([use uri table](#param_use_uri_table)) must be set.


*Default value is "subscriber".*


```opensips title="Set uri_table parameter"
...
modparam("uri", "db_table", "uri")
...
```


#### user_column (string)


Column holding usernames in the table.


*Default value is "username".*


```opensips title="Set user_column parameter"
...
modparam("uri", "user_column", "username")
...
```


#### domain_column (string)


Column holding domain in the table.


*Default value is "domain".*


```opensips title="Set domain_column parameter"
...
modparam("uri", "domain_column", "domain")
...
```


#### uriuser_column (string)


Column holding URI username in the table.


*Default value is "uri_user".*


```opensips title="Set uriuser_column parameter"
...
modparam("uri", "uriuser_column", "uri_user")
...
```


#### use_uri_table (integer)


Specify if the "uri" table should be used for checkings
instead of "subscriber" table. A non-zero value means true.


*Default value is "0 (false)".*


```opensips title="Set use_uri_table parameter"
...
modparam("uri", "use_uri_table", 1)
...
```


#### use_domain (integer)


Specify if the domain part of the URI should be used to identify the
users (along with username). This is useful in multi domain setups, a
non-zero value means true.


This parameter is only evaluated for calls to "does_uri_exist",
all other functions checks the digest username and realm against the
given username, if the "uri" table is used.


*Default value is "0 (false)".*


```opensips title="Set use_domain parameter"
...
modparam("uri", "use_domain", 1)
...
```


### Exported Functions


#### db_check_to()


Check To username against URI table (if use_uri_table is set) or
digest credentials (no DB backend required).


This function can be used from REQUEST_ROUTE.


```opensips title="db_check_to usage"
...
if (db_check_to()) {
	...
};
...
```


#### db_check_from()


Check From username against URI table (if use_uri_table is set) or
digest credentials (no DB backend required).


This function can be used from REQUEST_ROUTE.


```opensips title="db_check_from usage"
...
if (db_check_from()) {
	...
};
...
```


#### db_does_uri_exist()


Check if username in the request URI belongs to an existing user.


Matching is done against the URI table (if
**use_uri_table** is set)
or the *subscriber* table.


This function can be used from REQUEST_ROUTE.


```opensips title="db_does_uri_exist usage"
...
if (db_does_uri_exist()) {
	...
};
...
```


#### db_get_auth_id(string, var, var)


Checks given uri-string username against URI table (if use_uri_table is set) or
subscriber table (database backend required).
Returns true if the user exists in the database, and sets the given variables to
the authentication id and realm corresponding to the given uri.


This function can be used from REQUEST_ROUTE.


```opensips title="db_get_auth_id usage"
...
if (db_get_auth_id("$ru", "$avp(auth_id)", "$avp(auth_realm)")) {
	...
};
...
```


#### aaa_does_uri_exist([pvar])


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


```opensips title="aaa_does_uri_exist usage"
...
if (aaa_does_uri_exist()) {
	...
};
...
```


#### aaa_does_uri_user_exist([pvar])


Similar to aaa_does_uri_exist, but check is done
based only on Request-URI user part or user stored in
pseudo variable argument.  User should thus
be unique among all users, such as an E.164 number.


This function can be used from REQUEST_ROUTE.


```opensips title="aaa_does_uri_user_exist usage"
...
if (aaa_does_uri_user_exist()) {
	...
};
...
```


#### is_user(username)


Check if the username in credentials matches the given username.


Meaning of the parameters is as follows:


- *username* - Username string.


This function can be used from REQUEST_ROUTE.


```opensips title="is_user usage"
...
if (is_user("john")) {
	...
};
...
```


#### has_totag()


Check if To header field uri contains tag parameter.


This function can be used from REQUEST_ROUTE.


```opensips title="has_totag usage"
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


```opensips title="uri_param usage"
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


```opensips title="uri_param usage"
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


```opensips title="add_uri_param usage"
...
add_uri_param("nat=yes");
...
```


#### del_uri_param(param)


Delete a parameter from the RURI being given the key(key=value);


Meaning of the parameters is as follows:


- *param* - key of the parameter to be removed/


This function can be used from REQUEST_ROUTE.


```opensips title="del_uri_param usage"
...
del_uri_param("name");
...
```


#### tel2sip()


Converts RURI, if it is tel URI, to SIP URI.  Returns true, only if
conversion succeeded or if no conversion was needed (like RURI
was not tel URI.


This function can be used from REQUEST_ROUTE.


```opensips title="tel2sip usage"
...
tel2sip();
...
```


#### is_uri_user_e164(pseudo-variable)


Checks if userpart of URI stored in pseudo variable is
E164 number.


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


```opensips title="is_uri_user_e164 usage"
...
if (is_uri_user_e164("$fu")) {  # Check From header URI user part
   ...
}
if (is_uri_user_e164("$avp(uri)") {
   # Check user part of URI stored in avp uri
   ...
};
...
```


*doc copyrights:*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
