---
title: "cachedb_sql Module"
description: "This module is an implementation of a cache system designed to work with a regular SQL-based server. It uses the internal DB interface to connect to the back-end, and also implements the Key-Value interface exported from the core."
---

## Admin Guide


### Overview


This module is an implementation of a cache system designed to work with a 
		regular SQL-based server. It uses the internal DB interface to connect
		to the back-end, and also implements the Key-Value interface exported from the core.


### Advantages


- *memory costs are no longer on the server*
- *the cache is 100% persistent. A restart
					of OpenSIPS server will not affect the DB. The DB is also
				persistent so it can also be restarted without loss of information.*
- *Multiple OpenSIPS instances can easily share key-value information
				via a regular SQL-based database*


### Limitations


- *The module's counter operations ( ADD and SUB ) are currently only 
				supported by MySQL*


### Dependencies


#### OpenSIPS Modules


None.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *none:*


### Exported Parameters


#### db_url (string)


The url of the Database  that OpenSIPS will connect to in order
			to use the from script cache_store,cache_fetch, etc operations.


```c title="Set db_url parameter"
...
modparam("cachedb_sql", "db_url","mysql://localhost/my_database");
...
	
```


```c title="Usage example"
...
cache_store("sql","key","$ru value");
cache_add("sql","counter",10);
...
	
```


#### db_table (string)


The table of the Database  that OpenSIPS will connect to in order
			to use the from script cache_store,cache_fetch, etc operations.


```c title="Set db_url parameter"
...
modparam("cachedb_sql", "db_table","my_table");
...
	
```


#### key_column (string)


The column where the key will be stored


```c title="Set key_column parameter"
...
modparam("cachedb_sql", "key_column","some_name");
...
	
```


#### value_column (string)


The column where the value will be stored


```c title="Set value_column parameter"
...
modparam("cachedb_sql", "value_column","some_name");
...
	
```


#### counter_column (string)


The column where the counter value will be stored


```c title="Set counter_column parameter"
...
modparam("cachedb_sql", "counter_column","some_name");
...
	
```


#### expires_column (string)


The column where the expires will be stored


```c title="Set expires_column parameter"
...
modparam("cachedb_sql", "expires_column","some_name");
...
	
```


#### cache_clean_period (int)


The interval in seconds at which the expired keys will be removed from
			the database. Default value is 60 ( seconds )


```c title="Set cache_clean_period parameter"
...
modparam("cachedb_sql", "cache_clean_period",10);
...
	
```


#### Exported Functions


The module does not export functions to be used
		in configuration script.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
