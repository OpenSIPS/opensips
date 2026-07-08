---
title: "userblacklist Module"
description: "The userblacklist module allows OpenSIPS to handle blacklists on a per user basis. This information is stored in a database table, which is queried to decide if the number (more exactly, the request URI user) is blacklisted or not."
---

## Admin Guide


### Overview


The userblacklist module allows OpenSIPS to handle blacklists
	on a per user basis. This information is stored in a database
	table, which is queried to decide if the number (more exactly,
	the request URI user) is blacklisted or not.


An additional functionality that this module provides is the ability
	to handle global blacklists. This lists are loaded on startup into
	memory, thus providing a better performance then in the userblacklist
	case. This global blacklists are useful to only allow calls to certain 
	international destinations, i.e. block all not whitelisted numbers.
	They could also used to prevent the blacklisting of important	
	numbers, as whitelisting is supported too. This is useful for example
	to prevent the customer from blocking emergency call number or service
	hotlines.


The module exports two functions, *check_blacklist*
	and *check_user_blacklist* for usage in the config
	file. Furthermore its provide a FIFO function to reload the global
	blacklist cache.


### Dependencies


#### OpenSIPS Modules


The module depends on the following modules (in the other words 
			the listed modules must be loaded before this module):


- *database* -- Any database module


#### External Libraries or Applications


The following libraries or applications must be installed 
			before running OpenSIPS with this module loaded:


- *none*


### Exported Parameters


#### db_url (string)


Url to the database containing the routing data.


*Default value is "mysql://opensipsro:opensipsro@localhost/opensips".*


```opensips title="Set db_url parameter"
...
modparam("userblacklist", "db_url", "dbdriver://username:password@dbhost/dbname")
...
		
```


#### db_table (string)


Name of the table where the user blacklist data is stored.


*Default value is "userblacklist".*


```opensips title="Set db_table parameter"
...
modparam("userblacklist", "db_table", "userblacklist")
...
		    
```


#### use_domain (boolean)


If enabled, the "domain" column will also be
			matched in the table lookup, for a stricter match.


*Default value is *true* (enabled).*


```opensips title="Set use_domain parameter"
...
modparam("userblacklist", "use_domain", true)
...
		    
```


### Exported Functions


#### check_user_blacklist (user, domain, [number], [table])


Finds the longest prefix that matches the request URI user (or the number
		parameter) for the given user and domain name in the database.
		If a match is found and it is not set to whitelist, false is returned.
		Otherwise, true is returned. The number parameter can be used to check
		for example against the from URI user.


Parameters:


- *user* (string) - description
- *domain* (string) - description
- *number* (string, optional) - If ommited,
	    		the defalut is used.
- *table* (string, optional) - If ommited,
	    		the defalut is used.


```opensips title="check_user_blacklist usage"
...
if (!check_user_blacklist("user", "domain.com"))
	sl_send_reply(403, "Forbidden");
	exit;
}
...
		
```


#### check_blacklist (table)


Finds the longest prefix that matches the request URI for the
		given table. If a match is found and it is not set to whitelist,
		false is returned. Otherwise, true is returned.


Parameters:


- *table* (string)


```opensips title="check_blacklist usage"
...
if (!check_blacklist("global_blacklist")))
	sl_send_reply(403, "Forbidden");
	exit;
}
...
		
```


### Exported MI Functions


#### userblacklist:reload


Replaces obsolete MI command: *reload_blacklist*.


Reload the internal global blacklist cache. This is necessary after
		the database tables for the global blacklist have been changed.


```bash title="reload_blacklists usage"
...
opensips-cli -x mi userblacklist:reload
...
		
```


### Installation and Running


#### Database setup


Before running OpenSIPS with userblacklist, you have to setup the database 
			table where the module will read the blacklist data. For that, if 
			the table was not created by the installation script or you choose
			to install everything by yourself you can use the userblacklist-create.sql
			SQL script in the database directories in the 
			opensips/scripts folder as template. 
			Database and table name can be set with module parameters so they 
			can be changed, but the name of the columns must be as they are 
			in the SQL script.
			You can also find the complete database documentation on the
			project webpage, https://opensips.org/docs/db/db-schema-devel.html.


```c title="Example database content - globalblacklist table"
...
+----+-----------+-----------+
| id | prefix    | whitelist |
+----+-----------+-----------+
|  1 |           |         0 |
|  2 | 1         |         1 |
|  3 | 123456    |         0 |
|  4 | 123455787 |         0 |
+----+-----------+-----------+
...
		
```


This table will setup a global blacklist for all numbers, only allowing calls
		starting with "1". Numbers that starting with "123456"
		and "123455787" are also blacklisted, because the longest prefix
		will be matched.


```c title="Example database content - userblacklist table"
...
+----+----------------+-------------+-----------+-----------+
| id | username       | domain      | prefix    | whitelist |
+----+----------------+-------------+-----------+-----------+
| 23 | 49721123456788 |             | 1234      |         0 |
| 22 | 49721123456788 |             | 123456788 |         1 |
| 21 | 49721123456789 |             | 12345     |         0 |
| 20 | 494675231      |             | 499034133 |         1 |
| 19 | 494675231      | test        | 499034132 |         0 |
| 18 | 494675453      | test.domain | 49901     |         0 |
| 17 | 494675454      |             | 49900     |         0 |
+----+----------------+-------------+-----------+-----------+
...
		
```


This table will setup user specific blacklists for certain usernames. For example
		for user "49721123456788" the prefix "1234" will be not
		allowed, but the number "123456788" is allowed. Additionally a domain
		could be specified that is used for username matching if the "use_domain"
		parameter is set.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
