---
title: "SpeedDial Module"
description: "This module provides on-server speed dial facilities. An user can store records consisting of pairs short numbers (2 digits) and SIP addresses into a table of OpenSIPS. Then it can dial the two digits whenever it wants to call the SIP address associated with them."
---

## Admin Guide


### Overview


This module provides on-server speed dial facilities. An user can store
		records consisting of pairs short numbers (2 digits) and SIP addresses
		into a table of OpenSIPS. Then it can dial the two digits whenever it
		wants to call the SIP address associated with them.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *database module (mysql, dbtext, ...)*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### db_url (string)


The URL of database where the table containing speed dial records.


*Default value is mysql://opensipsro:opensipsro@localhost/opensips.*


```c title="Set db_url parameter"
...
modparam("speeddial", "db_url", "mysql://user:xxx@localhost/db_name")
...
```


#### user_column (string)


The name of column storing the user name of the owner of the speed dial
		record.


*Default value is "username".*


```c title="Set user_column parameter"
...
modparam("speeddial", "user_column", "userid")
...
```


#### domain_column (string)


The name of column storing the domain of the owner of the speed dial
		record.


*Default value is  "domain".*


```c title="Set domain_column parameter"
...
modparam("speeddial", "domain_column", "userdomain")
...
```


#### sd_user_column (string)


The name of the column storing the user part of the short dial address.


*Default value is  "sd_username".*


```c title="Set sd_user_column parameter"
...
modparam("speeddial", "sd_user_column", "short_user")
...
```


#### sd_domain_column (string)


The name of the column storing the domain of the short dial address.


*Default value is  "sd_domain".*


```c title="Set sd_domain_column parameter"
...
modparam("speeddial", "sd_domain_column", "short_domain")
...
```


#### new_uri_column (string)


The name of the column containing the URI that will be use to replace
		the short dial URI.


*Default value is "new_uri".*


```c title="Set new_uri_column parameter"
...
modparam("speeddial", "new_uri_column", "real_uri")
...
```


#### domain_prefix (string)


If the domain of the owner (From URI) starts with the value of this parameter, then
		it is stripped before performing the lookup of the short number.


*Default value is NULL.*


```c title="Set domain_prefix parameter"
...
modparam("speeddial", "domain_prefix", "tel.")
...
```


#### use_domain (int)


The parameter specifies wheter or not to use the domain when searching a
		speed dial record (0 - no domain, 1 - use domain from From URI,
		2 - use both domains, from From URI and from request URI).


*Default value is 0.*


```c title="Set use_domain parameter"
...
modparam("speeddial", "use_domain", 1)
...
```


### Exported Functions


#### sd_lookup(table [, owner])


The function lookups the short dial number from R-URI in 'table' and replaces the R-URI with associated address.


Meaning of the parameters is as follows:


- *table* (string) - The name of the table storing the
			speed dial records.
- *owner* (string) - The SIP URI of the owner of
			short dialing codes. If not pressent, URI of From header is used.


This function can be used from REQUEST_ROUTE.


```c title="sd_lookup usage"
...
# 'speed_dial' is the default table name created by opensips db script
if($ru=~"sip:[0-9]{2}@.*")
	sd_lookup("speed_dial");
# use auth username
if($ru=~"sip:[0-9]{2}@.*")
	sd_lookup("speed_dial", "sip:$au@$fd");
...
```


### Installation and Running


#### OpenSIPS config file


Next picture displays a sample usage of speeddial.


[OpenSIPS config script - sample speeddial usage](./samples.md "include")
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
