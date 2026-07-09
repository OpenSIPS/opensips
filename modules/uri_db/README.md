---
title: "uri_db Module"
description: "Various checks related to SIP URI."
---

## Admin Guide


### Overview


Various checks related to SIP URI.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *a OpenSIPS database module*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### db_url (string)


URL of the database to be used.


If the db_url string is empty, the default database URL
will be used.


*Default value is "mysql://opensipsro:opensipsro@localhost/opensips".*


```opensips title="Set db_url parameter"
...
modparam("uri_db", "db_url", "mysql://username:password@localhost/opensips")
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
modparam("uri_db", "db_table", "uri")
...
```


#### user_column (string)


Column holding usernames in the table.


*Default value is "username".*


```opensips title="Set user_column parameter"
...
modparam("uri_db", "user_column", "username")
...
```


#### domain_column (string)


Column holding domain in the table.


*Default value is "domain".*


```opensips title="Set domain_column parameter"
...
modparam("uri_db", "domain_column", "domain")
...
```


#### uriuser_column (string)


Column holding URI username in the table.


*Default value is "uri_user".*


```opensips title="Set uriuser_column parameter"
...
modparam("uri_db", "uriuser_column", "uri_user")
...
```


#### use_uri_table (integer)


Specify if the "uri" table should be used for checkings
instead of "subscriber" table. A non-zero value means true.


*Default value is "0 (false)".*


```opensips title="Set use_uri_table parameter"
...
modparam("uri_db", "use_uri_table", 1)
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
modparam("uri_db", "use_domain", 1)
...
```


### Exported Functions


#### check_to()


Check To username against URI table (if use_uri_table is set) or
digest credentials (no DB backend required).


This function can be used from REQUEST_ROUTE.


```opensips title="check_to usage"
...
if (check_to()) {
	...
};
...
```


#### check_from()


Check From username against URI table (if use_uri_table is set) or
digest credentials (no DB backend required).


This function can be used from REQUEST_ROUTE.


```opensips title="check_from usage"
...
if (check_from()) {
	...
};
...
```


#### does_uri_exist()


Check if username in the request URI belongs to an existing user.


As the checking is done against URI table (if use_uri_table is set) 
or subscriber table.


This function can be used from REQUEST_ROUTE.


```opensips title="does_uri_exist usage"
...
if (does_uri_exist()) {
	...
};
...
```


### Exported Statistics


Exported statistics are listed in the next sections.


#### positive_checks


Number of tests executed for which a positive match is returned.


#### negative_checks


Number of tests executed for which a negative match is returned. This includes no credentials found, or not match found in database.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
