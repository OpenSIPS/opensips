---
title: "group Module"
description: "This module provides functionalities for different methods of group membership checking."
---

## Admin Guide


### Overview


This module provides functionalities for different methods of group
		membership checking.


#### Strict membership checking


There is a database table that contains list of users and groups
			they belong to. The module provides the possibility to check if a
			specific user belongs to a specific group.


There is no DB caching support, each check involving a DB query.


#### Regular Expression based checking


Another database table contains list of regular expressions and
			group IDs. A matching occurs if the user URI match the regular
			expression. This type of matching may be used to fetch the
			group ID(s) the user belongs to (via RE matching) .


Due performance reasons (regular expression evaluation), DB cache
			support is available: the table content is loaded into memory at
			startup and all regular expressions are compiled.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- A database module, like mysql, postgres or dbtext.
- An AAA module, like radius or diameter.


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### db_url (string)


URL of the database table to be used.


```c title="Set db_url parameter"
...
modparam("group", "db_url", "mysql://username:password@dbhost/opensips")
...
```


#### table (string)


Name of the table holding strict definitions of groups and
		their members.


*Default value is "grp".*


```c title="Set table parameter"
...
modparam("group", "table", "grp_table")
...
```


#### user_column (string)


Name of the "table" column holding usernames.


*Default value is "username".*


```c title="Set user_column parameter"
...
modparam("group", "user_column", "user")
...
```


#### domain_column (string)


Name of the "table" column holding domains.


*Default value is "domain".*


```c title="Set domain_column parameter"
...
modparam("group", "domain_column", "realm")
...
```


#### group_column (string)


Name of the "table" column holding groups.


*Default value is "grp".*


```c title="Set group_column parameter"
...
modparam("group", "group_column", "grp")
...
```


#### use_domain (boolean)


If enabled, the domain part of the URI will also be used in the lookup,
		for a stricter group matching.  Otherwise, only the username part
		will be used.


*Default value is *true* (enabled).*


```c title="Set use_domain parameter"
...
modparam("group", "use_domain", 1)
...
```


#### re_table (string)


Name of the table holding definitions for regular-expression
		based groups. If no table is defined, the regular-expression
		support is disabled.


*Default value is "NULL".*


```c title="Set re_table parameter"
...
modparam("group", "re_table", "re_grp")
...
```


#### re_exp_column (string)


Name of the "re_table" column holding the regular
		expression used for user matching.


*Default value is "reg_exp".*


```c title="Set re_exp_column parameter"
...
modparam("group", "re_exp_column", "re")
...
```


#### re_gid_column (string)


Name of the "re_table" column holding the group IDs.


*Default value is "group_id".*


```c title="Set re_gid_column parameter"
...
modparam("group", "re_gid_column", "grp_id")
...
```


#### multiple_gid (integer)


If enabled (non zero value) the regular-expression matching will
		return all group IDs that match the user; otherwise only the first
		will be returned.


*Default value is "1".*


```c title="Set multiple_gid parameter"
...
modparam("group", "multiple_gid", 0)
...
```


#### aaa_url (string)


This is the url representing the AAA protocol used and the location of the configuration file of this protocol.


```c title="Set aaa_url parameter"
...
modparam("group", "aaa_url", "radius:/etc/radiusclient-ng/radiusclient.conf")
...
```


### Exported Functions


#### db_is_user_in(uri, group)


This function is to be used for script group membership. The function
		returns true if username in the given URI is member of the given
		group and false if not.


Meaning of the parameters is as follows:


- *uri (string)* - a SIP URI whose
				username and optionally domain to be used.  Possible values:
			
				
				"Request-URI" - Use Request-URI username and
				(optionally) domain.
				
				
				"To" - Use To username and (optionally) domain.
				
				
				"From" - Use From username and (optionally) domain.
				
				
				"Credentials" - Use digest credentials username.
				
				
				(default) - parse the given input as a SIP URI
- *group (string)* - the group to check


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


```c title="db_is_user_in usage"
...
if (db_is_user_in("Request-URI", "ld")) {
	...
}
...
$avp(grouptocheck)="offline";

if (db_is_user_in("Credentials", $avp(grouptocheck))) {
	...
}
...
```


#### db_get_user_group(uri, output_avp)


This function is to be used for regular expression based group
		membership, using DB support.  The function returns true if the username in
		the given "uri" belongs to at least one group.


All matching group IDs
		shall be returned in "output_avp" if [multiple gid](#param_multiple_gid)
		is enabled, otherwise only the first one to match (the records are
		attempted in reversed order of the results returned by the RDBMS).


Meaning of the parameters is as follows:


- *uri (string)* - a SIP URI to be matched
				against the regular expressions:
			
				
				"Request-URI" - Use Request-URI
				
				
				"To" - Use To URI.
				
				
				"From" - Use From URI
				
				
				"Credentials" - Use digest credentials username
				and realm.
				
				
				(default) - parse the given input as a SIP URI
- *output_avp (var)* - a list of matched
				group IDs


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


```c title="db_get_user_group usage"
...
if (db_get_user_group("Request-URI", $avp(10))) {
    xdbg("User $ru belongs to the following groups: $(avp(10)[*])\n");
    ....
};
...
```


#### aaa_is_user_in(uri, group)


This function checks group membership, using AAA support.
		The function returns true if username in the given "uri" is member of
		the given group and false if not.


Meaning of the parameters is as follows:


- *uri (string)* - a SIP URI whose
				username and optionally domain to be used, this can be one of:
			
				
				"Request-URI" - Use Request-URI username and
				(optionally) domain.
				
				
				"To" - Use To username and (optionally) domain.
				
				
				"From" - Use From username and (optionally) domain.
				
				
				"Credentials" - Use digest credentials username.
- *group (string)* - Name of the group to check.


This function can be used from REQUEST_ROUTE.


```c title="aaa_is_user_in usage"
...
if (aaa_is_user_in("Request-URI", "ld")) {
	...
};
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
