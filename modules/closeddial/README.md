---
title: "closeddial Module"
description: "This module provides functionality which allows to group users using a common field, in such a way that a particular group defines abbreviated codes for users, allowing closed dialing within the group, locating users by their abbreviated code, besides their full identification. This modu..."
---

## Admin Guide


### Overview


This module provides functionality which allows to group users
		using a common field, in such a way that a particular group defines
		abbreviated codes for users, allowing closed dialing within the group,
		locating users by their abbreviated code, besides their 
		full identification. This module offers a functionality similar to
		Centrex.
		The relationship between users and their abbreviated codes, and their
		grouping is defined in a database table (see below).


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- A database module, like mysql, postgres or dbtext


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### db_url (string)


URL of the database table to be used.


*Default value is 
			"mysql://opensips:opensipsrw@localhost/opensips".*


```c title="Set db_url parameter"
...
modparam("closeddial", "db_url", "mysql://username:password@dbhost/opensips")
...
```


#### user_column (string)


Column of the table which stores the username


*Default value is "username".*


```c title="Set user_column parameter"
...
modparam("closeddial", "user_column", "user")
...
```


#### domain_column (string)


Column of the table which stores the domain associated to 
		usernames.


*Default value is "domain".*


```c title="Set domain_column parameter"
...
modparam("closeddial", "domain_column", "domain")
...
```


#### group_id_column (string)


Column of the table which stores the group_id which groups
		the usernames.


*Default value is "group_id".*


```c title="Set group_id_column parameter"
...
modparam("closeddial", "group_id_column", "groupid")
...
```


#### cd_user_column (string)


Column of the table which stores the closed dial code associated
		to a username.


*Default value is "cd_username".*


```c title="Set user_column parameter"
...
modparam("closeddial", "cd_user_column", "cd_user")
...
```


#### cd_domain_column (string)


Column of the table which stores the domain associated to closed dial
		usernames.


*Default value is "cd_domain".*


```c title="Set cd_domain_column parameter"
...
modparam("closeddial", "cd_domain_column", "cddomain")
...
```


#### new_uri_column (string)


Column of the table which stores the new URI which will be used
		to rewrite the request, in case a possitive match be found.


*Default value is "new_uri".*


```c title="Set new_uri_column parameter"
...
modparam("closeddial", "new_uri_column", "new_uri")
...
```


#### use_domain (integer)


If enabled (set to non zero value) then domain will be used
		also used for searching new uri; otherwise only the
		username part will be used.


*Default value is "0 (no)".*


```c title="Set use_domain parameter"
...
modparam("closeddial", "use_domain", 1)
...
```


### Exported Functions


#### cd_lookup(domain [, group])


This function is used to lookup in the database the corresponding URI
		for an abbreviated code dialed, according to group which From user
		belongs to. After finding the group for From user, the dialed code
		and found group are used to look for the new URI to rewrite the request.

		If a positive match is found, R-URI is rewritten; if no match is found,
		R-URI is not changed.


Meaning of the parameters is as follows:


- *domain*  
			Table where searching is going to be perfomed on.
- *group* 
			Optional parameter which can be used to store the group to
			be used in searching. This group must be associated to From user.


Both of the parameters can contain pseudovariables.


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


```c title="cd_lookup usage"
...

# Abbreviated code of two digits
if($(rU{s.len}) == 2)
{
        # Group AVP could be loaded at register time.
        $avp(s:group)="companyA";
        cd_lookup("closeddial", "$avp(s:group)");
};
...

# Abbreviated code of three digits
if($(rU{s.len}) == 3)
{
        # Group is searched on database, by using
        # From username.
        cd_lookup("closeddial");
};
...
```


### Installation


A table needs to be created on the database to store relationship between
		usernames, their corresponding abbreviated codes and their grouping using
		group attribute.

		The SQL syntax to create the table can be found in closeddial-create.sql
		script at opensips/scripts folder.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
