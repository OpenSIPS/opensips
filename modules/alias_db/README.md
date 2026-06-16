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
	penalty can be lowered. Also, search can be performed on different
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


```c title="Set db_url parameter"
...
modparam("alias_db", "db_url", "dbdriver://username:password@dbhost/dbname")
...
```


#### user_column (str)


Name of the column storing username.


*Default value is "username".*


```c title="Set user_column parameter"
...
modparam("alias_db", "user_column", "susername")
...
```


#### domain_column (str)


Name of the column storing user's domain.


*Default value is "domain".*


```c title="Set domain_column parameter"
...
modparam("alias_db", "domain_column", "sdomain")
...
```


#### alias_user_column (str)


Name of the column storing alias username.


*Default value is "alias_username".*


```c title="Set alias_user_column parameter"
...
modparam("alias_db", "alias_user_column", "auser")
...
```


#### alias_domain_column (str)


Name of the column storing alias domain.


*Default value is "alias_domain".*


```c title="Set alias_domain_column parameter"
...
modparam("alias_db", "alias_domain_column", "adomain")
...
```


#### domain_prefix (str)


Specifies the prefix to be stripped from the domain in R-URI before
		doing the search.


*Default value is "NULL".*


```c title="Set domain_prefix parameter"
...
modparam("alias_db", "domain_prefix", "sip.")
...
```


#### append_branches (int)


If the alias resolves to many SIP IDs, the first is replacing
			the R-URI, the rest are added as branches.


*Default value is "0" (0 - don't add branches;
			1 - add branches).*


```c title="Set append_branches parameter"
...
modparam("alias_db", "append_branches", 1)
...
```


### Exported Functions


#### alias_db_lookup(table_name, [flags])


The function takes the R-URI and search to see whether it is an alias
		or not. If it is an alias for a local user, the R-URI is replaced with
		user's SIP uri.


The function returns TRUE if R-URI is alias and it was replaced by
		user's SIP uri.


Meaning of the parameters is as follows:


- *table_name (string)* - the name of the
				table to search for the alias
- *flags (string, optional)* - set of
			character flags to control the alias lookup process:

  - **d** - do not use domain URI part in
				the alias lookup query (use only a username-based lookup). By
				default, both username and domain are used.
  - **r** - do reverse alias lookup - lookup
				for the alias mapped to the current URI (URI 2 alias 
				translation); normally, the function looks up for the URI 
				mapped to the alias (alias 2 URI translation).


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```c title="alias_db_lookup() usage"
...
alias_db_lookup("dbaliases", "rd");
alias_db_lookup("dba_$(rU{s.substr,0,1})");
...
```


#### alias_db_find(table_name, input_uri, output_var, [flags])


The function is very similar to `alias_db_lookup()`,
		but instead of using fixed input (RURI) and output (RURI) is able to
		get the input SIP URI from a pseudo-variable and place the result back
		also in a pseudo-variable.


The function is useful as the alias lookup does not affect the request
		itself (no RURI changes), can be used in a reply context (as it does 
		not work with RURI only) and can be used for others URI than the RURI
		(To URI, From URI, custom URI).


The function returns TRUE if any alias mapping was found and returned.


Meaning of the parameters is as follows:


- *table_name (string)* - the name of the table to
				search for the alias
- *input_uri (string)* - a SIP URI to look up
- *output_var (var)* - a variable to hold
				the SIP URI result
- *flags (string, optional)* (optional) - set of flags 
			(char based flags) to control the alias lookup process:

  - *d* - do not use domain URI part in
				the alias lookup query (use only a username-based lookup). By
				default, both username and domain are used.
  - *r* - do revers alias lookup - lookup
				for the alias mapped to the current URI (URI 2 alias 
				translation); normally, the function looks up for the URI 
				mapped to the alias (alias 2 URI translation).


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
			LOCAL_ROUTE, STARTUP_ROUTE, FAILURE_ROUTE and ONREPLY_ROUTE.


```c title="alias_db_find() usage"
...
# do revers alias lookup and find the alias for the FROM URI
alias_db_find("dbaliases", $fu, $avp(from_alias), "r");
...
```


## Frequently Asked Questions


**Q: What happened with old use_domain parameter**


The global parameter (affecting the entire module) was replaced 
			with a per lookup parameter (affecting only current lookup).
			See the "d" (do not used domain part) flag in the db_alias_lookup()
			and db_alias_find() functions.


**Q: How can I report a bug?**


Please follow the guidelines provided at:
			[https://github.com/OpenSIPS/opensips/issues](https://github.com/OpenSIPS/opensips/issues).
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
