---
title: "ALIAS_DB Module"
description: "ALIAS_DB module can be used as an alternative for user aliases via usrloc. The main feature is that it does not store all adjacent data as for user location and always uses database for search (no memory caching)."
---

## Admin Guide


### Overview


ALIAS_DB module can be used as an alternative for user aliases
via usrloc. The main feature is that it does not store all adjacent
data as for user location and always uses database for search (no
memory caching).


Having no memory caching, search speed might decrease but 
provisioning is easier. With very fast databases like MySQL, speed
penalty can be lowered. Also, the search can be performed on different
tables in the same script.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *database module* (mysql, dbtext, ...).


#### External Libraries or Applications


The following libraries or applications must be installed before 
running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### db_url (str)


Database URL.


*Default value is "mysql://opensipsro:opensipsro@localhost/opensips".*


```opensips title="Set db_url parameter"
...
modparam("alias_db", "db_url", "dbdriver://username:password@dbhost/dbname")
...
```


#### user_column (str)


Name of the column storing username.


*Default value is "username".*


```opensips title="Set user_column parameter"
...
modparam("alias_db", "user_column", "susername")
...
```


#### domain_column (str)


Name of the column storing user's domain.


*Default value is "domain".*


```opensips title="Set domain_column parameter"
...
modparam("alias_db", "domain_column", "sdomain")
...
```


#### alias_user_column (str)


Name of the column storing alias username.


*Default value is "alias_username".*


```opensips title="Set alias_user_column parameter"
...
modparam("alias_db", "alias_user_column", "auser")
...
```


#### alias_domain_column (str)


Name of the column storing alias domain.


*Default value is "alias_domain".*


```opensips title="Set alias_domain_column parameter"
...
modparam("alias_db", "alias_domain_column", "adomain")
...
```


#### use_domain (int)


Specifies whether to use or not the domain from R-URI when searching
for alias. If set to 0, the domain from R-URI is not used, if set to
1 the domain from R-URI is used.


*Default value is "0".*


```opensips title="Set use_domain parameter"
...
modparam("alias_db", "use_domain", 1)
...
```


#### domain_prefix (str)


Specifies the prefix to be stripped from the domain in R-URI before
doing the search.


*Default value is "NULL".*


```opensips title="Set domain_prefix parameter"
...
modparam("alias_db", "domain_prefix", "sip.")
...
```


#### append_branches (int)


If the alias resolves to many SIP IDs, the first is replacing
the R-URI, the rest are added as branches.


*Default value is "0" (0 - don't add branches;
1 - add branches).*


```opensips title="Set append_branches parameter"
...
modparam("alias_db", "append_branches", 1)
...
```


### Exported Functions


#### alias_db_lookup(table_name)


The function takes the R-URI and search to see whether it is an alias
or not. If it is an alias for a local user, the R-URI is replaced with
user's SIP uri.


The function returns TRUE if R-URI is alias and it was replaced by
user's SIP uri.


Meaning of the parameters is as follows:


- *table_name* - the name of the table
where to search for alias. It can include pseudo-variables.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="alias_db_lookup() usage"
...
alias_db_lookup("dbaliases");
alias_db_lookup("dba_$(rU{s.substr,0,1})");
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
